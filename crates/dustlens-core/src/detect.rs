//! 检测器：把扫描结果变成 `Finding`。
//!
//! 四类判据（形式属性，不含价值判断 —— P1）：
//! - `Large`：体积异常（只对**目录**判定）
//! - `NonCompliant`：规范违规（主语是**应用**，只登记、不产出删除建议）
//! - `OddLocation`：位置异常（构建产物出现在不该出现的地方）
//! - `Unclear`：判定失败（「说不清」），独立分区
//!
//! 注意：`NonCompliant` **绝不**产出「建议删除」——
//! `.minecraft` / `.cargo` / `.rustup` 全都违反 XDG 且全都正常（见设计共识 §3.2）。

use crate::dangling;
use crate::duplicates::{self, DuplicateSet};
use crate::refs::{self, ProcessIndex, ReferenceIndex};
use crate::scan::{DirTotal, LooseFile, RawScan};
use crate::types::{
    display_path, Evidence, Finding, FindingKind, LinkStrength, ScanConfig, SharePolicy,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// 产物目录名 → (生成器, 触发重建所需的项目文件)。
///
/// 这张表是**判据**而非建议：它回答「这个产物是谁生成的、还能不能重建」，
/// 不回答「该不该删」（P1）。
const GENERATOR_TABLE: &[(&str, &str, &str)] = &[
    ("target", "cargo", "Cargo.toml"),
    ("node_modules", "npm", "package.json"),
    ("__pycache__", "python", "pyproject.toml"),
    (".pytest_cache", "pytest", "pyproject.toml"),
    (".mypy_cache", "mypy", "pyproject.toml"),
    ("dist", "构建工具", "package.json"),
    ("build", "构建工具", "CMakeLists.txt"),
    ("out", "构建工具", "CMakeLists.txt"),
    (".gradle", "gradle", "build.gradle"),
    (".next", "next", "package.json"),
    (".nuxt", "nuxt", "package.json"),
];

/// 若目录名对应已知产物，返回生成器证据。
///
/// `tool_available` 只查 `PATH`（不执行生成器，保持只读与无副作用）。
fn generator_evidence(path: &Path) -> Option<Evidence> {
    let name = path.file_name()?.to_str()?;
    let (_, tool, manifest) = GENERATOR_TABLE.iter().find(|(n, _, _)| *n == name)?;

    // 项目描述文件通常在产物目录的父目录
    let manifest_present = path
        .parent()
        .map(|p| p.join(manifest).exists())
        .unwrap_or(false);

    // 生成器是否在 PATH 中
    let tool_available = which(tool);

    let note = if name == "target" {
        "cargo 的构建产物（debug/release 与增量编译缓存）".to_string()
    } else {
        format!("`{name}` 通常由 {tool} 生成")
    };

    Some(Evidence::Generator {
        artifact: name.to_string(),
        tool: tool.to_string(),
        tool_available,
        manifest_present,
        note,
    })
}

/// 在 `PATH` 中查找可执行文件（不执行它）。
fn which(tool: &str) -> bool {
    // 非真实工具名（如「构建工具」）不查
    if tool.contains(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_') {
        return false;
    }
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    path.split(':').any(|dir| {
        let p = Path::new(dir).join(tool);
        p.is_file()
    })
}

/// 判定门槛。抽成结构体是为了可测试、可配置（硬编码常量无法写单测）。
#[derive(Debug, Clone, Copy)]
pub struct Thresholds {
    /// 进入「体积异常」
    pub large_bytes: u64,
    /// 进入「说不清」
    pub unclear_bytes: u64,
    /// 进入「顶层散落物」
    pub loose_bytes: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            large_bytes: LARGE_MIN_BYTES,
            unclear_bytes: UNCLEAR_MIN_BYTES,
            loose_bytes: LOOSE_MIN_BYTES,
        }
    }
}

/// 进入「体积异常」的默认最低门槛。
pub const LARGE_MIN_BYTES: u64 = 100 * 1024 * 1024; // 100 MiB

/// 顶层散落物里值得点名的体积门槛。
pub const LOOSE_MIN_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB

/// 「说不清」的最小体积门槛（再小就不值得占用用户注意力）。
pub const UNCLEAR_MIN_BYTES: u64 = 50 * 1024 * 1024; // 50 MiB

/// 构建产物的目录名（出现在非项目语境即为「位置异常」）。
const ARTIFACT_DIR_NAMES: &[&str] = &[
    "node_modules",
    "target",
    "build",
    "dist",
    "out",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".pytest_cache",
    ".mypy_cache",
    ".gradle",
    ".next",
    ".nuxt",
    ".parcel-cache",
    ".cache-loader",
];

/// 判断某目录是否位于「项目语境」内。
///
/// 项目语境 = 路径中包含 `Projects` / `projects` / `src` / `code` / `dev` 这类组件，
/// 或目录内存在 `.git`。在项目语境里出现 `target/`、`node_modules/` 是**正常**的。
fn in_project_context(path: &Path) -> bool {
    const MARKERS: &[&str] = &[
        "Projects",
        "projects",
        ".git",
        "src",
        "code",
        "dev",
        "workspace",
        "repos",
    ];
    let comps: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    if comps
        .iter()
        .any(|c| MARKERS.iter().any(|m| c.eq_ignore_ascii_case(m)))
    {
        return true;
    }
    // 祖先里存在 .git
    let mut cur = path.parent();
    while let Some(p) = cur {
        if p.join(".git").exists() {
            return true;
        }
        cur = p.parent();
    }
    // 或同级的父目录里存在构建描述文件 —— 那就说明「这是某个项目的一部分」，
    // 它不是「位置异常」，只是「没被 git 管理的项目」。
    if let Some(parent) = path.parent() {
        const MANIFESTS: &[&str] = &[
            "Cargo.toml",
            "package.json",
            "pyproject.toml",
            "setup.py",
            "CMakeLists.txt",
            "meson.build",
            "Makefile",
            "go.mod",
            "pom.xml",
            "build.gradle",
        ];
        if MANIFESTS.iter().any(|m| parent.join(m).exists()) {
            return true;
        }
    }
    false
}

/// 检测结果（含未成为 `Finding` 的聚合信息）。
#[derive(Debug, Default)]
pub struct Detection {
    /// 体积异常（已按体积降序）
    pub large: Vec<Finding>,
    /// 位置异常
    pub odd_location: Vec<Finding>,
    /// 「说不清」分区（按体积降序）
    pub unclear: Vec<Finding>,
    /// 规范违规（主语是应用，按体积降序）
    pub non_compliant: Vec<AppViolation>,
    /// 顶层散落物（体积降序）
    pub loose: Vec<LooseFile>,
    /// 失效引用（P1）：某配置指向的目标已不存在
    pub dangling: Vec<Finding>,
    /// 引用检查汇总统计
    pub stats: DetectionStats,
    /// 归属探测（P0）统计
    pub provenance: ProvenanceStats,
    /// 冗余副本（M4）：内容完全相同的文件组（明细，最多 MAX_SETS 组）
    pub duplicates: Vec<DuplicateSet>,
    /// 真实组数（不受明细上限影响）
    pub duplicate_total_sets: usize,
    /// 真实可回收字节（不受明细上限影响）
    pub duplicate_total_reclaimable: u64,
    /// 按区域分布：(区域, 组数, 可回收字节)
    pub duplicate_by_area: Vec<(String, usize, u64)>,
}

/// 归属探测的统计（供报告说明「这一轮问过谁、有没有问不到」）。
#[derive(Debug, Default, Clone)]
pub struct ProvenanceStats {
    /// 本机可用的包管理器
    pub managers: Vec<&'static str>,
    /// 成功给出归属结论的条目数
    pub resolved: u64,
    /// 结论是「不属于任何包」
    pub untracked: u64,
    /// 执行失败（命令异常）次数
    pub failures: u64,
}

#[derive(Debug, Default, Clone)]
pub struct DetectionStats {
    pub candidates_checked: u64,
    pub in_use: u64,
    pub will_use: u64,
    pub unclaimed: u64,
}

impl DetectionStats {
    fn tally(&mut self, s: LinkStrength) {
        self.candidates_checked += 1;
        match s {
            LinkStrength::InUse => self.in_use += 1,
            LinkStrength::WillUse => self.will_use += 1,
            LinkStrength::Unclaimed => self.unclaimed += 1,
        }
    }
}

/// 一个「应用」层面的规范违规。
///
/// **这不是一个可删除的对象** —— 它是对一个应用的**行为记录**。
#[derive(Debug, Clone)]
pub struct AppViolation {
    /// 推断出的应用名（取自路径组件）
    pub app: String,
    /// 涉及的路径
    pub paths: Vec<PathBuf>,
    pub bytes: u64,
    /// XDG 规范建议的位置（用于科普，不用于 remediation）
    pub suggestion: String,
    /// 能否在菜单/桌面项里找到它（用于判断「它还活着吗」）
    pub has_desktop_entry: Option<bool>,
    pub link: LinkStrength,
    pub evidence: Vec<Evidence>,
}

/// 执行检测（使用默认门槛）。
pub fn detect(
    scan: &RawScan,
    procs: &ProcessIndex,
    refs: &ReferenceIndex,
    cfg: &ScanConfig,
) -> Detection {
    detect_with(scan, procs, refs, cfg, Thresholds::default())
}

/// 执行检测（可指定门槛）。
pub fn detect_with(
    scan: &RawScan,
    procs: &ProcessIndex,
    refs: &ReferenceIndex,
    cfg: &ScanConfig,
    th: Thresholds,
) -> Detection {
    let home = cfg.home.as_deref();
    let mut det = Detection::default();

    // ---- 体积异常 ----
    //
    // 只看「扫描根的直接子目录」会漏掉深层的大户：
    // 例如 `~/Projects/MemStack/target`（22 GiB）在第 3 层。
    // 因此下探到两层，再按「是否已被更上层条目包含」去重 ——
    // 保留最上层的具体目录，避免 `Projects` 把 `MemStack/target` 吞掉。
    for root in &scan.roots {
        let Ok(root) = root.canonicalize() else {
            continue;
        };
        let mut candidates: Vec<DirTotal> = scan
            .dirs
            .iter()
            .filter(|d| d.path == root)
            .cloned()
            .collect();
        candidates.extend(
            scan.dirs
                .iter()
                .filter(|d| {
                    // 直接子目录
                    d.path.parent() == Some(root.as_path())
                // 二层子目录
                || d.path.parent().and_then(|p| p.parent()) == Some(root.as_path())
                })
                .cloned(),
        );
        // 深层优先保留：若候选 A 包含候选 B 且两者都在榜，去掉 A（保留更具体的 B）
        candidates.sort_by_key(|d| std::cmp::Reverse(d.path.components().count()));
        for d in candidates {
            if d.bytes < th.large_bytes {
                continue;
            }
            let Some(f) = make_finding(
                &d.path,
                FindingKind::Large,
                d.bytes,
                d.files,
                procs,
                refs,
                home,
                &mut det.stats,
            ) else {
                continue;
            };
            det.large.push(f);
        }
    }
    det.large.sort_by_key(|b| std::cmp::Reverse(b.bytes));

    // ---- 位置异常 ----
    det.odd_location = detect_odd_locations(scan, procs, refs, cfg, th);
    det.odd_location.sort_by_key(|b| std::cmp::Reverse(b.bytes));

    // ---- 说不清 ----
    det.unclear = detect_unclear(scan, procs, refs, cfg, th, &det);
    det.unclear.sort_by_key(|b| std::cmp::Reverse(b.bytes));

    // ---- 规范违规（按应用聚合）----
    det.non_compliant = detect_non_compliant(scan, procs, refs, cfg);
    det.non_compliant
        .sort_by_key(|b| std::cmp::Reverse(b.bytes));

    // ---- 顶层散落物 ----
    det.loose = scan
        .loose_files
        .iter()
        .filter(|l| l.bytes >= th.loose_bytes)
        .cloned()
        .collect();
    det.loose.sort_by_key(|b| std::cmp::Reverse(b.bytes));

    // ---- M4：冗余副本 ----
    if cfg.duplicates {
        let rep = duplicates::find(&scan.big_files, procs, refs, home);
        det.duplicates = rep.sets;
        det.duplicate_total_sets = rep.total_sets;
        det.duplicate_total_reclaimable = rep.total_reclaimable;
        det.duplicate_by_area = rep.by_area;
    }

    // ---- P1：失效引用 ----
    if cfg.dangling {
        det.dangling = dangling::find(refs, home, &scan.roots)
            .into_iter()
            .map(|d| Finding {
                display_path: display_path(&d.missing, home),
                path: d.missing,
                kind: FindingKind::DanglingRef,
                bytes: 0,
                files: 0,
                link: LinkStrength::Unclaimed,
                evidence: vec![Evidence::DanglingReference {
                    file: d.referrer,
                    note: d.note,
                }],
                share: SharePolicy::OutsideHome, // 目标不存在，无内容可送；保守处理
                inaccessible: None,
            })
            .collect();
    }

    // ---- P0：归属（放在最后，因为它要 fork 外部命令）----
    if cfg.provenance {
        let mut prober = crate::provenance::Prober::new(home);
        det.provenance.managers = prober.managers().labels();

        // 只把**有信息量**的归属挂到条目上：
        // - 查到所属包 → 挂上（「这是包管理器装的，动它要小心」）
        // - 查不到     → 只统计，不逐条挂。「不属于任何包」在扫描家目录时
        //                几乎对所有条目都成立，逐条打印等于 63 行噪音。
        let mut attach = |f: &mut Finding| {
            if let Some(ev) = prober.probe(&f.path) {
                if let Evidence::Provenance { package, .. } = &ev {
                    if package.is_some() {
                        det.provenance.resolved += 1;
                        f.evidence.push(ev);
                    } else {
                        det.provenance.untracked += 1;
                    }
                }
            }
        };
        for f in det
            .large
            .iter_mut()
            .chain(det.odd_location.iter_mut())
            .chain(det.unclear.iter_mut())
        {
            attach(f);
        }
        det.provenance.failures = prober.failures() as u64;
    }

    det
}

/// 构造一个 `Finding` 并完成引用检查。
#[allow(clippy::too_many_arguments)]
fn make_finding(
    path: &Path,
    kind: FindingKind,
    bytes: u64,
    files: u64,
    procs: &ProcessIndex,
    refs: &ReferenceIndex,
    home: Option<&Path>,
    stats: &mut DetectionStats,
) -> Option<Finding> {
    let rf = refs::check(path, procs, refs, home);
    stats.tally(rf.strength);

    let mut evidence = vec![Evidence::Body { bytes, files }];
    // 若目录名对应已知产物，补上「生成器还在不在」这条证据
    if let Some(ev) = generator_evidence(path) {
        evidence.push(ev);
    }
    evidence.extend(rf.evidence.iter().cloned());

    let share = SharePolicy::derive(path, home);
    Some(Finding {
        path: path.to_path_buf(),
        display_path: display_path(path, home),
        kind,
        bytes,
        files,
        link: rf.strength,
        evidence,
        share,
        inaccessible: None,
    })
}

/// 位置异常：构建产物出现在没有项目语境的地方。
fn detect_odd_locations(
    scan: &RawScan,
    procs: &ProcessIndex,
    refs: &ReferenceIndex,
    cfg: &ScanConfig,
    _th: Thresholds,
) -> Vec<Finding> {
    let home = cfg.home.as_deref();
    let mut out = Vec::new();
    let mut stats = DetectionStats::default();

    // 「位置异常」的判据必须**窄**。早期版本把任何非项目语境的
    // `__pycache__` / `node_modules` 都算进来，结果在真实机器上报出 1344 条 ——
    // 其中绝大多数是 `site-packages/__pycache__`、嵌套 `node_modules`
    // 这类**完全正常**的产物。噪音会淹没真正的问题。
    //
    // 现在的定义收窄为「**随手留下的产物**」：产物目录直接位于
    //   · 扫描根之下，或
    //   · 下载 / 桌面 / 模板 这三个「用户随手放东西」的目录之下。
    // 更深的位置说明用户是**有意组织**的，不构成异常。
    const CARELESS_PARENTS: &[&str] =
        &["Downloads", "Desktop", "Templates", "下载", "桌面", "模板"];

    let roots: Vec<PathBuf> = scan
        .roots
        .iter()
        .filter_map(|r| r.canonicalize().ok())
        .collect();

    for d in &scan.dirs {
        let Some(name) = d.path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !ARTIFACT_DIR_NAMES.contains(&name) {
            continue;
        }
        // 在项目语境里是正常的，不算位置异常
        if in_project_context(&d.path) {
            continue;
        }
        // 自身或子树没有体积就跳过
        if d.bytes == 0 {
            continue;
        }
        // 必须在「随手区域」：产物目录的**父目录**就是扫描根或随手目录
        let Some(parent) = d.path.parent() else {
            continue;
        };
        let parent_is_root = roots.iter().any(|r| r == parent);
        let parent_is_careless = parent
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| CARELESS_PARENTS.contains(&n))
            .unwrap_or(false);
        if !parent_is_root && !parent_is_careless {
            continue;
        }
        if let Some(f) = make_finding(
            &d.path,
            FindingKind::OddLocation,
            d.bytes,
            d.files,
            procs,
            refs,
            home,
            &mut stats,
        ) {
            out.push(f);
        }
    }

    // 说明：这里**刻意不做**「按目录名猜这是不是应用目录」的判据。
    //
    // 早期版本用一张词表（含 games / downloads / data / cache …）去猜，
    // 结果把 `$HOME/Games`（94.9 GiB）与 `$HOME/Downloads` 报成了「位置异常」。
    // 那是把**用户的资产**说成「异常」，违背 P1（工具不评判价值）。
    //
    // 「位置异常」现在只保留一条**客观、可验证**的判据：
    // **没有项目语境的构建产物目录**。用户自己的大目录由「体积异常」如实呈现，
    // 名字里有什么词不构成任何判断依据。

    // 去重（同一路径可能两种规则都命中）
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out.dedup_by(|a, b| a.path == b.path);
    out
}

/// 「说不清」：不认识、无引用、但占据可观体积的顶层目录。
///
/// **判定逻辑**：不属于任何已知类别（已知类别已被前面几类认领），
/// 且体积可观。这是「判定失败」而非「一种脏」。
fn detect_unclear(
    scan: &RawScan,
    procs: &ProcessIndex,
    refs: &ReferenceIndex,
    cfg: &ScanConfig,
    th: Thresholds,
    det: &Detection,
) -> Vec<Finding> {
    let home = cfg.home.as_deref();
    let mut claimed: Vec<PathBuf> = Vec::new();
    claimed.extend(det.large.iter().map(|f| f.path.clone()));
    claimed.extend(det.odd_location.iter().map(|f| f.path.clone()));

    let mut out = Vec::new();
    let mut stats = DetectionStats::default();

    for root in &scan.roots {
        let Ok(root) = root.canonicalize() else {
            continue;
        };
        for d in &scan.dirs {
            if d.path.parent() != Some(root.as_path()) {
                continue;
            }
            if claimed.contains(&d.path) {
                continue;
            }
            if d.bytes < th.unclear_bytes {
                continue;
            }
            // 已经能说清它是什么的，不算「说不清」
            let name = d
                .path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if ARTIFACT_DIR_NAMES.contains(&name.as_str()) && in_project_context(&d.path) {
                continue;
            }
            if let Some(f) = make_finding(
                &d.path,
                FindingKind::Unclear,
                d.bytes,
                d.files,
                procs,
                refs,
                home,
                &mut stats,
            ) {
                // 「说不清」必须是无人认领的；有引用就说明能说清「谁在用」
                if f.link == LinkStrength::Unclaimed {
                    out.push(f);
                }
            }
        }
    }
    out
}

/// 规范违规：应用把数据写在了 XDG 之外的位置。
fn detect_non_compliant(
    scan: &RawScan,
    procs: &ProcessIndex,
    refs: &ReferenceIndex,
    cfg: &ScanConfig,
) -> Vec<AppViolation> {
    let home = cfg.home.as_deref();
    let Some(home) = home else {
        return Vec::new();
    };

    // 只在扫描根就是家目录时才做这项检查（否则无法判断「相对家目录」的位置）
    let home_scan = scan
        .roots
        .iter()
        .any(|r| r.canonicalize().map(|c| c == home).unwrap_or(false));
    if !home_scan {
        return Vec::new();
    }

    // 收集家目录根下的非隐藏目录 + 隐藏但不符合 XDG 的目录
    let mut by_app: BTreeMap<String, (Vec<PathBuf>, u64)> = BTreeMap::new();

    for d in &scan.dirs {
        if d.path.parent() != Some(home) {
            continue;
        }
        let Some(name) = d.path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // ---- 白名单 ----
        //
        // 1) XDG 规定的隐藏目录与 shell rc 文件
        // 2) **家目录标准用户目录**（XDG user dirs）—— Pictures / Documents /
        //    Downloads / Music / Videos / Desktop 等。它们**本来就该在 $HOME 下**，
        //    把它们算作「规范违规」是纯假阳性（实测曾把 Pictures 4.4 GiB 报成违规）。
        const XDG_OK: &[&str] = &[
            ".config",
            ".local",
            ".cache",
            ".bashrc",
            ".zshrc",
            ".profile",
            ".bash_profile",
            ".bash_history",
            ".zsh_history",
            ".Xauthority",
            ".xsession-errors",
            ".gitconfig",
            ".gitignore",
        ];
        const USER_DIRS: &[&str] = &[
            "Desktop",
            "Documents",
            "Downloads",
            "Music",
            "Pictures",
            "Public",
            "Templates",
            "Videos",
        ];
        // 桌面环境本地化目录名（中文环境常见）
        const USER_DIRS_ZH: &[&str] = &[
            "桌面", "文档", "下载", "音乐", "图片", "公共", "模板", "视频",
        ];
        if XDG_OK.contains(&name) {
            continue;
        }
        if USER_DIRS.iter().any(|u| name.eq_ignore_ascii_case(u)) || USER_DIRS_ZH.contains(&name) {
            continue;
        }
        // 只看**隐藏目录**（以 . 开头）——那才是「应用把数据丢在家目录根」的特征。
        // 非隐藏目录多半是用户自己建的（Games / Desktop 之外的任意命名），
        // 归入「位置异常」而不是「规范违规」，避免把用户资产说成应用的错。
        if !name.starts_with('.') {
            continue;
        }
        let app_name = name.trim_start_matches('.').to_string();
        if app_name.is_empty() {
            continue;
        }
        let entry = by_app.entry(app_name).or_insert_with(|| (Vec::new(), 0));
        entry.0.push(d.path.clone());
        entry.1 += d.bytes;
    }

    let desktop_dir = home.join(".local/share/applications");
    let system_desktop = Path::new("/usr/share/applications");

    let mut out = Vec::new();
    for (app, (paths, bytes)) in by_app {
        if bytes == 0 {
            continue;
        }
        let mut stats = DetectionStats::default();
        let anchor = paths
            .iter()
            .max_by_key(|p| {
                scan.dirs
                    .iter()
                    .find(|d| &d.path == *p)
                    .map(|d| d.bytes)
                    .unwrap_or(0)
            })
            .cloned()
            .unwrap_or_else(|| home.join(&app));
        let rf = refs::check(&anchor, procs, refs, Some(home));
        stats.tally(rf.strength);

        let has_desktop = has_desktop_entry(&app, &desktop_dir, system_desktop);

        let mut evidence = vec![Evidence::Body { bytes, files: 0 }];
        evidence.extend(rf.evidence.iter().cloned());
        evidence.push(Evidence::Content {
            note: format!(
                "XDG 建议：配置 → ~/.config/{}，数据 → ~/.local/share/{}",
                app, app
            ),
        });

        let suggestion = format!("~/.config/{app} 与 ~/.local/share/{app}");
        out.push(AppViolation {
            app,
            paths,
            bytes,
            suggestion,
            has_desktop_entry: has_desktop,
            link: rf.strength,
            evidence,
        });
    }
    out
}

/// 粗判某应用是否存在桌面项（不追求完备，用于「它还活着吗」的参考）。
fn has_desktop_entry(app: &str, user_dir: &Path, system_dir: &Path) -> Option<bool> {
    let needle = app.to_lowercase();
    for dir in [user_dir, system_dir] {
        let Ok(rd) = std::fs::read_dir(dir) else {
            continue;
        };
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().to_lowercase();
            if name.ends_with(".desktop") && name.contains(&needle) {
                return Some(true);
            }
        }
    }
    // 系统目录都读不到时返回 None（表示「无法判断」，而不是「没有」）
    if !system_dir.exists() || !user_dir.exists() {
        None
    } else {
        Some(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{LooseFile, ScanStats};
    use std::fs;

    fn config_for(home: &Path) -> ScanConfig {
        ScanConfig::new(vec![home.to_path_buf()], Some(home.to_path_buf()))
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("dl_det_{tag}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn artifact_in_project_context_is_not_odd() {
        let home = tmpdir("proj");
        let t = home.join("Projects/x/target");
        fs::create_dir_all(&t).unwrap();
        fs::write(t.join("f"), [0u8; 16]).unwrap();

        let cfg = config_for(&home);
        let scan = crate::scan::scan(&cfg);
        let det = detect(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
        );
        assert!(
            !det.odd_location
                .iter()
                .any(|f| f.path == t.canonicalize().unwrap()),
            "项目内的 target/ 不应被判为位置异常"
        );
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn artifact_without_project_context_is_odd() {
        // 「位置异常」= 随手区域（下载/桌面/模板）下的构建产物
        let home = tmpdir("noproj");
        let t = home.join("Downloads/node_modules");
        fs::create_dir_all(&t).unwrap();
        fs::write(t.join("f"), [0u8; 16]).unwrap();

        let cfg = config_for(&home);
        let scan = crate::scan::scan(&cfg);
        let det = detect(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
        );
        assert!(
            det.odd_location
                .iter()
                .any(|f| f.path.file_name().unwrap() == "node_modules"),
            "随手区域（Downloads）下的 node_modules 应被判为位置异常"
        );
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn deep_artifacts_are_not_odd_locations() {
        // 回归：真实机器上曾报出 1344 条「位置异常」，绝大多数是
        // `site-packages/__pycache__`、嵌套 `node_modules` 这类正常产物。
        let home = tmpdir("deep");
        let p = home.join(".local/share/app/lib/python3/site-packages/__pycache__");
        fs::create_dir_all(&p).unwrap();
        fs::write(p.join("x.pyc"), vec![0u8; 64]).unwrap();
        let n = home.join("Downloads/proj/node_modules/pkg/node_modules");
        fs::create_dir_all(&n).unwrap();
        fs::write(n.join("i.js"), vec![0u8; 64]).unwrap();

        let cfg = config_for(&home);
        let scan = crate::scan::scan(&cfg);
        let det = detect(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
        );
        assert!(
            det.odd_location.is_empty(),
            "深层产物不应被判为位置异常，实际: {:?}",
            det.odd_location.iter().map(|f| &f.path).collect::<Vec<_>>()
        );
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn user_content_dirs_are_never_odd_locations() {
        // 回归：早期用词表猜「应用目录」，把 $HOME/Games 与 $HOME/Downloads
        // 报成了「位置异常」—— 那是把用户的资产说成异常（违背 P1）。
        let home = tmpdir("assets");
        for name in ["Games", "Downloads", "Pictures", "Documents", "Videos"] {
            let p = home.join(name);
            fs::create_dir_all(&p).unwrap();
            fs::write(p.join("f.bin"), vec![0u8; 64]).unwrap();
        }
        let cfg = config_for(&home);
        let scan = crate::scan::scan(&cfg);
        let th = Thresholds {
            unclear_bytes: 16, // 让体积门槛不挡住
            ..Thresholds::default()
        };
        let det = detect_with(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
            th,
        );
        let offenders: Vec<&PathBuf> = det.odd_location.iter().map(|f| &f.path).collect();
        assert!(
            offenders.is_empty(),
            "用户自己的大目录不得被判为位置异常，实际: {offenders:?}"
        );
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn non_compliant_groups_by_app_and_never_suggests_deletion() {
        let home = tmpdir("nc");
        let mc = home.join(".minecraft");
        fs::create_dir_all(mc.join("saves")).unwrap();
        fs::write(mc.join("options.txt"), [0u8; 128]).unwrap();

        let cfg = config_for(&home);
        let scan = crate::scan::scan(&cfg);
        let det = detect(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
        );

        let v = det
            .non_compliant
            .iter()
            .find(|v| v.app == "minecraft")
            .expect("应识别出 minecraft 为规范违规");
        // 关键断言：违规条目里不得含「删除」建议
        for e in &v.evidence {
            let s = e.summary(None);
            assert!(!s.contains("删除"), "规范违规不得含删除建议: {s}");
        }
        assert!(v.suggestion.contains("XDG") || v.suggestion.contains("~/.config"));
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn xdg_compliant_dirs_are_not_violations() {
        let home = tmpdir("xdg");
        for d in [".config/app", ".local/share/app", ".cache/app"] {
            let p = home.join(d);
            fs::create_dir_all(&p).unwrap();
            fs::write(p.join("f"), [0u8; 8]).unwrap();
        }
        let cfg = config_for(&home);
        let scan = crate::scan::scan(&cfg);
        let det = detect(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
        );
        assert!(
            det.non_compliant.is_empty(),
            "XDG 合规目录不应被登记为违规，实际: {:?}",
            det.non_compliant.iter().map(|v| &v.app).collect::<Vec<_>>()
        );
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn standard_user_dirs_are_never_non_compliant() {
        // 回归：实测曾把 Pictures(4.4 GiB)/Downloads/Documents 报成「规范违规」。
        // 它们本来就该在 $HOME 下（XDG user dirs），属纯假阳性。
        let home = tmpdir("userdirs");
        for d in [
            "Pictures",
            "Documents",
            "Downloads",
            "Music",
            "Videos",
            "Desktop",
            "图片",
            "文档",
            "下载",
        ] {
            let p = home.join(d);
            fs::create_dir_all(&p).unwrap();
            fs::write(p.join("f.bin"), vec![0u8; 64]).unwrap();
        }
        let cfg = config_for(&home);
        let scan = crate::scan::scan(&cfg);
        let det = detect(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
        );
        let offenders: Vec<&String> = det.non_compliant.iter().map(|v| &v.app).collect();
        assert!(
            offenders.is_empty(),
            "标准用户目录不得被判为规范违规，实际: {offenders:?}"
        );
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn non_hidden_home_dirs_are_not_flagged_as_app_violations() {
        // 非隐藏目录多半是用户自己建的（Games / 任意命名），
        // 不能把「用户的资产」说成「应用的错」。
        let home = tmpdir("nonhidden");
        let p = home.join("Games");
        fs::create_dir_all(&p).unwrap();
        fs::write(p.join("f.bin"), vec![0u8; 64]).unwrap();
        let cfg = config_for(&home);
        let scan = crate::scan::scan(&cfg);
        let det = detect(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
        );
        assert!(
            !det.non_compliant.iter().any(|v| v.app == "Games"),
            "非隐藏目录不应进规范违规"
        );
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn hidden_violation_is_detected_without_deletion_advice() {
        let home = tmpdir("hidden");
        let p = home.join(".someapp");
        fs::create_dir_all(&p).unwrap();
        fs::write(p.join("f.bin"), vec![0u8; 64]).unwrap();
        let cfg = config_for(&home);
        let scan = crate::scan::scan(&cfg);
        let det = detect(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
        );
        assert!(det.non_compliant.iter().any(|v| v.app == "someapp"));
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn generator_evidence_is_attached_to_artifacts() {
        let home = tmpdir("gen");
        let proj = home.join("proj");
        fs::create_dir_all(proj.join("target/debug")).unwrap();
        fs::write(proj.join("Cargo.toml"), b"[package]\nname=\"x\"\n").unwrap();
        fs::write(proj.join("target/debug/bin"), vec![0u8; 1024]).unwrap();

        let cfg = config_for(&home);
        let scan = crate::scan::scan(&cfg);
        let th = Thresholds {
            large_bytes: 16,
            ..Thresholds::default()
        };
        let det = detect_with(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
            th,
        );
        let f = det
            .large
            .iter()
            .find(|f| f.path.file_name().unwrap() == "target")
            .expect("target 应进体积异常");
        let gen = f
            .evidence
            .iter()
            .find_map(|e| match e {
                Evidence::Generator {
                    tool,
                    manifest_present,
                    ..
                } => Some((tool.clone(), *manifest_present)),
                _ => None,
            })
            .expect("应带生成器证据");
        assert_eq!(gen.0, "cargo");
        assert!(gen.1, "Cargo.toml 存在时 manifest_present 应为 true");
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn unclear_requires_unclaimed_and_size() {
        let home = tmpdir("unclear");
        let small = home.join("tinydir");
        fs::create_dir_all(&small).unwrap();
        fs::write(small.join("f"), [0u8; 8]).unwrap(); // 远小于阈值

        let cfg = config_for(&home);
        let scan = crate::scan::scan(&cfg);
        let det = detect(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
        );
        assert!(det.unclear.is_empty(), "小目录不应进「说不清」");
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn odd_and_unclear_are_mutually_exclusive_on_same_path() {
        let home = tmpdir("excl");
        let nm = home.join("Downloads/node_modules");
        fs::create_dir_all(&nm).unwrap();

        let cfg = config_for(&home);
        let mut scan = crate::scan::scan(&cfg);
        // 伪造一个大体积，触发两边的门槛
        let canon = nm.canonicalize().unwrap();
        for d in scan.dirs.iter_mut() {
            if d.path == canon || canon.starts_with(&d.path) {
                d.bytes += UNCLEAR_MIN_BYTES * 2;
            }
        }
        scan.dirs.sort_by_key(|b| std::cmp::Reverse(b.bytes));
        let det = detect(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
        );

        let in_odd = det.odd_location.iter().any(|f| f.path == canon);
        let in_unclear = det.unclear.iter().any(|f| f.path == canon);
        assert!(in_odd, "应进入位置异常");
        assert!(!in_unclear, "同一条目不应同时进入「说不清」");
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn loose_files_filtered_by_threshold() {
        let home = tmpdir("loose");
        fs::write(home.join("tiny.bin"), [0u8; 32]).unwrap();
        let cfg = config_for(&home);
        let scan = crate::scan::scan(&cfg);
        let det = detect(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
        );
        assert!(det.loose.is_empty(), "小文件不进散落物榜");
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn detection_stats_tally_three_states() {
        let mut s = DetectionStats::default();
        s.tally(LinkStrength::InUse);
        s.tally(LinkStrength::WillUse);
        s.tally(LinkStrength::Unclaimed);
        s.tally(LinkStrength::Unclaimed);
        assert_eq!(s.candidates_checked, 4);
        assert_eq!(s.in_use, 1);
        assert_eq!(s.will_use, 1);
        assert_eq!(s.unclaimed, 2);
    }

    #[test]
    fn empty_scan_produces_empty_detection() {
        let scan = RawScan {
            roots: vec![],
            dirs: vec![],
            loose_files: Vec::<LooseFile>::new(),
            excluded: vec![],
            gaps: vec![],
            stats: ScanStats::default(),
            big_files: vec![],
        };
        let cfg = ScanConfig::new(vec![], None);
        let det = detect(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
        );
        assert!(det.large.is_empty());
        assert!(det.unclear.is_empty());
    }
}
