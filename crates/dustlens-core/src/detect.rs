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
use crate::types::{display_path, Evidence, Finding, LinkStrength, ScanConfig, SharePolicy, Tag};
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
    /// 进入「顶层散落物」
    pub loose_bytes: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            large_bytes: LARGE_MIN_BYTES,
            loose_bytes: LOOSE_MIN_BYTES,
        }
    }
}

/// 进入「体积异常」的默认最低门槛。
pub const LARGE_MIN_BYTES: u64 = 100 * 1024 * 1024; // 100 MiB

/// 顶层散落物里值得点名的体积门槛。
pub const LOOSE_MIN_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB

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
    /// 所有「路径条目」——**同一个路径只出现一次**，形式属性以 `tags` 表达。
    ///
    /// 这是本轮「tag 化」的核心：早先每个分区各一个 Vec（large / odd_location /
    /// dangling / 派生出来的 unclear），同一条目可能在多个分区里重复出现，
    /// 还要靠「谁先认领」的排除逻辑避免打架 —— 而体积本就是**属性**不是类别。
    ///
    /// 全程按体积降序（`bytes` desc），标签只用于筛选与分组，**不决定排序**。
    pub items: Vec<Finding>,
    /// 规范违规（主语是**应用**，不是路径，故不进 items）
    pub non_compliant: Vec<AppViolation>,
    /// 顶层散落物（主语是根目录下的**散文件**）
    pub loose: Vec<LooseFile>,
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
    /// 被内容鉴定出「这是什么」的条目数（M5）
    pub identified: usize,
}

impl Detection {
    /// 带某标签的全部条目（保持 items 的原顺序 = 体积降序）。
    pub fn tagged(&self, tag: Tag) -> impl Iterator<Item = &Finding> {
        self.items.iter().filter(move |f| f.tags.contains(&tag))
    }

    /// 方便测试与报告使用：收集成 Vec。
    pub fn tagged_vec(&self, tag: Tag) -> Vec<&Finding> {
        self.tagged(tag).collect()
    }

    pub fn count_tag(&self, tag: Tag) -> usize {
        self.tagged(tag).count()
    }

    pub fn has_tag(&self, tag: Tag) -> bool {
        self.tagged(tag).next().is_some()
    }
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
    // 先在局部构建，最后打标签合并成 items
    let mut large: Vec<Finding> = Vec::new();
    let mut odd: Vec<Finding>;
    let mut dangling_findings: Vec<Finding> = Vec::new();

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
                Tag::Large,
                d.bytes,
                d.files,
                procs,
                refs,
                home,
                &mut det.stats,
            ) else {
                continue;
            };
            large.push(f);
        }
    }
    large.sort_by_key(|b| std::cmp::Reverse(b.bytes));

    // ---- 位置异常 ----
    odd = detect_odd_locations(scan, procs, refs, cfg, th);
    odd.sort_by_key(|b| std::cmp::Reverse(b.bytes));

    // ---- 说不清 ----

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
        dangling_findings = dangling::find(refs, home, &scan.roots)
            .into_iter()
            .map(|d| Finding {
                display_path: display_path(&d.missing, home),
                path: d.missing,
                tags: std::iter::once(Tag::DanglingRef).collect(),
                bytes: 0,
                files: 0,
                link: LinkStrength::Unclaimed,
                evidence: vec![Evidence::DanglingReference {
                    display_file: display_path(&d.referrer, home),
                    note: d.note,
                }],
                share: SharePolicy::OutsideHome, // 目标不存在，无内容可送；保守处理
                inaccessible: None,
            })
            .collect();
    }

    // ---- M5：内容鉴定 ----
    if cfg.identify {
        for f in large.iter_mut().chain(odd.iter_mut()) {
            attach_identification(f, &scan.roots, home);
            if f.evidence.iter().any(|e| {
                matches!(
                    e,
                    Evidence::Identification {
                        confident: true,
                        ..
                    }
                )
            }) {
                det.identified += 1;
            }
        }

        // ---- 「说不清」= 判定失败的**标签** ----
        //
        // 它就是「这条条目无法被确定性识别」，与体积无关；作为标签挂在条目上，
        // 不再需要单独的 Vec，也不会与其它分区互斥（早先的实现因此长期为空）。
        for f in large.iter_mut().chain(odd.iter_mut()) {
            let is_root = scan.roots.iter().any(|r| r == &f.path);
            let confident = f.evidence.iter().any(|e| {
                matches!(
                    e,
                    Evidence::Identification {
                        confident: true,
                        ..
                    }
                )
            });
            if !is_root && !confident {
                f.tags.insert(Tag::Unclear);
            }
        }
    }

    // ---- 死符号链接（并入「失效引用」）----
    //
    // 符号链接本身是一个**存在的对象**；它「失效」是指**指向的目标**不在了。
    // 交给用户的事实有两层：这是个链接 + 链接指向的东西已经没了。
    if cfg.dangling {
        // 用 take(budget) 而不是手工计数器：clippy 的 explicit_counter_loop 会拦
        let budget = crate::dangling::MAX_DANGLING.saturating_sub(dangling_findings.len());
        for link in scan
            .symlinks
            .iter()
            .filter(|l| !l.target_exists && !is_transient_symlink(l))
            .take(budget)
        {
            let rf = refs::check(&link.path, procs, refs, home);
            // 目标是相对路径时原样展示（相对路径本身不含家目录，无需脱敏）
            let shown_target = if link.target.is_absolute() {
                display_path(&link.target, home)
            } else {
                link.target.display().to_string()
            };
            dangling_findings.push(Finding {
                path: link.path.clone(),
                display_path: display_path(&link.path, home),
                tags: std::iter::once(Tag::DanglingRef).collect(),
                bytes: 0,
                files: 1,
                link: rf.strength,
                evidence: vec![
                    Evidence::Symlink {
                        display_target: shown_target,
                    },
                    Evidence::Content {
                        note: "符号链接指向的目标不存在".into(),
                    },
                ],
                share: SharePolicy::derive(&link.path, home),
                inaccessible: None,
            });
        }
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
        for f in large.iter_mut().chain(odd.iter_mut()) {
            attach(f);
        }
        det.provenance.failures = prober.failures() as u64;
    }

    // ---- 合并成统一条目表 ----
    //
    // 同一路径若在多个来源里出现（理论上 large 与 odd 可能同时命中），
    // 合并成一条并取并集标签，避免报告里出现两个一模一样的路径。
    let all = large
        .into_iter()
        .chain(odd)
        .chain(dangling_findings)
        .collect::<Vec<_>>();
    let mut merged: std::collections::BTreeMap<PathBuf, Finding> =
        std::collections::BTreeMap::new();
    for f in all {
        match merged.get_mut(&f.path) {
            Some(existing) => {
                existing.tags.extend(f.tags);
                if f.bytes > existing.bytes {
                    existing.bytes = f.bytes;
                    existing.files = f.files;
                }
                existing.evidence.extend(f.evidence);
            }
            None => {
                merged.insert(f.path.clone(), f);
            }
        }
    }
    det.items = merged.into_values().collect();
    det.items.sort_by_key(|f| std::cmp::Reverse(f.bytes));

    det
}

/// 是否属于「不该报」的临时符号链接。
///
/// 两类噪音，都是实跑打出来的：
///
/// 1. **目标不是路径**：Chromium 的 `SingletonLock` 指向 `hostname-pid`、
///    `SingletonCookie` 指向一个整数。它们不是「路径消失」，而是进程间锁令牌。
/// 2. **运行时锁/socket 的文件名**：`SingletonLock` / `SingletonCookie` /
///    `SingletonSocket` / `SS` / `Socket` —— 这些本来就该在进程退出后失效。
///
/// 排除它们之后剩下的，才是「真的有一份数据不在原位了」。
fn is_transient_symlink(link: &crate::scan::SymlinkEntry) -> bool {
    if !link.target.is_absolute() {
        return true;
    }
    let name = link.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    const TRANSIENT: &[&str] = &[
        "SingletonLock",
        "SingletonCookie",
        "SingletonSocket",
        "SingletonSocket",
        "SS",
        "Socket",
    ];
    TRANSIENT.contains(&name)
}

/// 构造一个 `Finding` 并完成引用检查。
/// 对一条 finding 做内容鉴定并挂上证据。
///
/// 只对目录走结构鉴定；文件走魔数 + 头部特征。
/// 鉴定不出来就不挂 —— 不猜。
///
/// `roots` 用来跳过**扫描根本身**：对 `$HOME` 或 `/opt` 说「这是什么」没有意义，
/// 而且会误判（例：家目录里恰好有 `.dsh/`，就被说成「DSH 工作区」）。
fn attach_identification(
    f: &mut Finding,
    roots: &[std::path::PathBuf],
    home: Option<&std::path::Path>,
) {
    if roots.iter().any(|r| r == &f.path) {
        return;
    }
    let id = if f.path.is_dir() {
        crate::identify::identify_dir_with_home(&f.path, home)
    } else {
        crate::identify::identify_file(&f.path)
    };
    if let Some(id) = id {
        f.evidence.push(Evidence::Identification {
            what: id.what,
            basis: id.basis,
            confident: id.confident,
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn make_finding(
    path: &Path,
    tag: Tag,
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
        tags: std::iter::once(tag).collect(),
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
            Tag::OddLocation,
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
            !det.tagged_vec(Tag::OddLocation)
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
            det.tagged_vec(Tag::OddLocation)
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
            det.tagged_vec(Tag::OddLocation).is_empty(),
            "深层产物不应被判为位置异常，实际: {:?}",
            det.tagged_vec(Tag::OddLocation)
                .iter()
                .map(|f| &f.path)
                .collect::<Vec<_>>()
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
            large_bytes: 1, // 让它们都进入「体积异常」
            ..Thresholds::default()
        };
        let det = detect_with(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
            th,
        );
        let offenders: Vec<&PathBuf> = det
            .tagged_vec(Tag::OddLocation)
            .iter()
            .map(|f| &f.path)
            .collect();
        assert!(
            offenders.is_empty(),
            "用户自己的大目录不得被判为位置异常，实际: {offenders:?}"
        );
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn dead_symlink_becomes_dangling_ref_with_symlink_evidence() {
        #[cfg(unix)]
        {
            let home = tmpdir("deadlink");
            fs::write(home.join("real.txt"), b"x").unwrap();
            std::os::unix::fs::symlink(home.join("gone-target"), home.join("dead.link")).unwrap();
            std::os::unix::fs::symlink(home.join("real.txt"), home.join("good.link")).unwrap();

            let cfg = config_for(&home);
            let scan = crate::scan::scan(&cfg);
            let det = detect(
                &scan,
                &ProcessIndex::default(),
                &ReferenceIndex::default(),
                &cfg,
            );

            let link_finding = det
                .tagged_vec(Tag::DanglingRef)
                .into_iter()
                .find(|f| f.display_path.ends_with("dead.link"))
                .expect("死符号链接应进入失效引用分区");
            assert!(link_finding.tags.contains(&Tag::DanglingRef));
            assert!(
                link_finding
                    .evidence
                    .iter()
                    .any(|e| matches!(e, Evidence::Symlink { .. })),
                "必须带 Symlink 证据"
            );
            // 目标已脱敏
            let t = link_finding
                .evidence
                .iter()
                .find_map(|e| match e {
                    Evidence::Symlink { display_target } => Some(display_target.clone()),
                    _ => None,
                })
                .unwrap();
            assert!(t.starts_with("$HOME"), "链接目标也应脱敏，实际: {t}");

            // 好链接不应进失效引用
            assert!(!det
                .tagged_vec(Tag::DanglingRef)
                .into_iter()
                .any(|f| f.display_path.ends_with("good.link")));

            let _ = fs::remove_dir_all(&home);
        }
    }

    #[test]
    fn confidently_identified_dirs_leave_the_unclear_partition() {
        let home = tmpdir("m5");
        // ① 可确定性识别：Minecraft 结构
        let mc = home.join("mcdata");
        fs::create_dir_all(mc.join("saves")).unwrap();
        fs::write(
            mc.join("options.txt"),
            b"fov:70
",
        )
        .unwrap();
        // ② 认不出来
        let odd = home.join("mystery");
        fs::create_dir_all(&odd).unwrap();
        fs::write(odd.join("a.bin"), b"\x00\x01\x02").unwrap();

        let cfg = config_for(&home);
        let scan = crate::scan::scan(&cfg);
        let th = Thresholds {
            large_bytes: 1,
            ..Thresholds::default()
        };
        let det = detect_with(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
            th,
        );

        let unclear_names: Vec<String> = det
            .tagged_vec(Tag::Unclear)
            .iter()
            .map(|f| f.display_path.clone())
            .collect();
        assert!(
            !unclear_names.iter().any(|p| p.contains("mcdata")),
            "已能确定性识别的目录不应留在「说不清」: {unclear_names:?}"
        );
        assert!(
            unclear_names.iter().any(|p| p.contains("mystery")),
            "认不出来的仍应在「说不清」: {unclear_names:?}"
        );
        assert!(det.identified >= 1, "应至少识别出 1 项");

        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn identification_is_attached_as_evidence_with_basis() {
        let home = tmpdir("m5ev");
        let mc = home.join("mcdata");
        fs::create_dir_all(mc.join("saves")).unwrap();
        fs::write(mc.join("options.txt"), b"x").unwrap();

        let cfg = config_for(&home);
        let scan = crate::scan::scan(&cfg);
        let th = Thresholds {
            large_bytes: 1,
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
            .tagged_vec(Tag::Large)
            .into_iter()
            .find(|f| f.display_path.contains("mcdata"))
            .expect("应在体积异常里");
        let id = f
            .evidence
            .iter()
            .find_map(|e| match e {
                Evidence::Identification {
                    what,
                    basis,
                    confident,
                } => Some((what.clone(), basis.clone(), *confident)),
                _ => None,
            })
            .expect("应带 Identification 证据");
        assert!(id.0.contains("Minecraft"), "{id:?}");
        assert!(id.1.contains("特征项"), "依据应描述结构: {id:?}");
        assert!(id.2, "结构证据应标为确定");

        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn transient_symlinks_are_not_reported_as_dangling() {
        #[cfg(unix)]
        {
            let home = tmpdir("transient");
            fs::create_dir_all(home.join(".config/app")).unwrap();
            // Chromium 风格：目标不是路径
            std::os::unix::fs::symlink("fedora-1234", home.join(".config/app/SingletonLock"))
                .unwrap();
            // 运行时 socket：绝对但属瞬时
            std::os::unix::fs::symlink(
                "/tmp/whatever/SingletonSocket",
                home.join(".config/app/SingletonSocket"),
            )
            .unwrap();
            // 真正该报的
            std::os::unix::fs::symlink(home.join("missing-data"), home.join("real-dead.link"))
                .unwrap();

            let cfg = config_for(&home);
            let scan = crate::scan::scan(&cfg);
            let det = detect(
                &scan,
                &ProcessIndex::default(),
                &ReferenceIndex::default(),
                &cfg,
            );

            let links: Vec<&str> = det
                .tagged_vec(Tag::DanglingRef)
                .into_iter()
                .filter(|f| {
                    f.evidence
                        .iter()
                        .any(|e| matches!(e, Evidence::Symlink { .. }))
                })
                .map(|f| f.display_path.as_str())
                .collect();
            assert!(
                links.iter().any(|p| p.ends_with("real-dead.link")),
                "真正的死链接必须报出: {links:?}"
            );
            assert!(
                !links.iter().any(|p| p.contains("Singleton")),
                "运行时锁不得报出: {links:?}"
            );

            let _ = fs::remove_dir_all(&home);
        }
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
            .tagged_vec(Tag::Large)
            .into_iter()
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
        assert!(
            det.tagged_vec(Tag::Unclear).is_empty(),
            "小目录不应进「说不清」"
        );
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn one_item_can_carry_multiple_tags() {
        // tag 化的核心收益：同一条目可以同时「很大」且「说不出是什么」
        let home = tmpdir("multitag");
        let mystery = home.join("mystery");
        fs::create_dir_all(&mystery).unwrap();
        fs::write(mystery.join("blob.bin"), vec![0u8; 64]).unwrap();

        let cfg = config_for(&home);
        let scan = crate::scan::scan(&cfg);
        let th = Thresholds {
            large_bytes: 1,
            ..Thresholds::default()
        };
        let det = detect_with(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
            th,
        );

        let item = det
            .items
            .iter()
            .find(|f| f.display_path.contains("mystery"))
            .expect("应有 mystery 条目");
        assert!(item.tags.contains(&Tag::Large), "应带体积异常标签");
        assert!(
            item.tags.contains(&Tag::Unclear),
            "认不出来时同时带「说不清」标签"
        );
        // 同一条目在两张视图里都出现，但底层只有一份
        assert_eq!(
            det.tagged_vec(Tag::Large)
                .iter()
                .filter(|f| f.display_path.contains("mystery"))
                .count(),
            1
        );

        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn items_are_sorted_by_bytes_regardless_of_tags() {
        let home = tmpdir("tagorder");
        fs::write(home.join("a.bin"), vec![0u8; 4096]).unwrap();
        let small = home.join("small-dir");
        fs::create_dir_all(&small).unwrap();
        fs::write(small.join("x.bin"), vec![0u8; 64]).unwrap();
        let big = home.join("big-dir");
        fs::create_dir_all(&big).unwrap();
        fs::write(big.join("y.bin"), vec![0u8; 65536]).unwrap();

        let cfg = config_for(&home);
        let scan = crate::scan::scan(&cfg);
        let th = Thresholds {
            large_bytes: 1,
            ..Thresholds::default()
        };
        let det = detect_with(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
            th,
        );

        let sizes: Vec<u64> = det.items.iter().map(|f| f.bytes).collect();
        assert!(
            sizes.windows(2).all(|w| w[0] >= w[1]),
            "items 必须按体积降序，标签不得影响排序: {sizes:?}"
        );

        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn unclear_is_a_derived_view_over_unidentified_findings() {
        // 新语义：untclear 不再是一条独立的「体积窄带」，而是
        // 「体积异常 / 位置异常里无法确定性识别的条目」的派生视图。
        let home = tmpdir("unclearview");
        // ① 大且能识别（Minecraft 结构）→ 不应进 unclear
        let mc = home.join("mcdata");
        fs::create_dir_all(mc.join("saves")).unwrap();
        fs::write(mc.join("options.txt"), b"x").unwrap();
        // ② 大且认不出来 → 应进 unclear
        let odd = home.join("mystery-data");
        fs::create_dir_all(&odd).unwrap();
        fs::write(odd.join("blob.bin"), vec![0u8; 64]).unwrap();

        let cfg = config_for(&home);
        let scan = crate::scan::scan(&cfg);
        let th = Thresholds {
            large_bytes: 1, // 都算「大」
            ..Thresholds::default()
        };
        let det = detect_with(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
            th,
        );

        let paths: Vec<&str> = det
            .tagged_vec(Tag::Unclear)
            .into_iter()
            .map(|u| u.display_path.as_str())
            .collect();
        assert!(
            !paths.iter().any(|p| p.contains("mcdata")),
            "能确定性识别的条目不应出现在「说不清」: {paths:?}"
        );
        assert!(
            paths.iter().any(|p| p.contains("mystery-data")),
            "认不出来的大条目必须出现在「说不清」: {paths:?}"
        );
        // 排序：按体积降序
        let sizes: Vec<u64> = det
            .tagged_vec(Tag::Unclear)
            .iter()
            .map(|u| u.bytes)
            .collect();
        assert!(sizes.windows(2).all(|w| w[0] >= w[1]), "应按体积降序");

        let one = det
            .tagged_vec(Tag::Unclear)
            .into_iter()
            .find(|u| u.display_path.contains("mystery-data"))
            .unwrap();
        // 「线索」现在从证据里取（Identification 的 basis）
        let hint = one
            .evidence
            .iter()
            .find_map(|e| match e {
                Evidence::Identification { basis, .. } => Some(basis.clone()),
                _ => None,
            })
            .unwrap_or_default();
        assert!(!hint.is_empty(), "必须给出「已掌握的线索」");
        assert!(one.tags.contains(&Tag::Large), "应带体积异常标签");

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
            symlinks: vec![],
        };
        let cfg = ScanConfig::new(vec![], None);
        let det = detect(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
        );
        assert!(det.tagged_vec(Tag::Large).is_empty());
        assert!(det.tagged_vec(Tag::Unclear).is_empty());
    }
}
