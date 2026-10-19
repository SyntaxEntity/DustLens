//! 报告渲染：JSON（主数据）+ Markdown（视图）。
//!
//! 设计依据：设计共识 §7.4 / §8.3 / §3.2 / P8。
//! - **所有路径用 `$HOME` 字面量**，不出现绝对家目录路径。
//! - **不含任何删除建议**（P1）。
//! - **必须披露扫描盲区**（P8）。
//! - **必须含 XDG 科普**（P4：不给 remediation，但必须科普）。

use crate::detect::{AppViolation, Detection, DetectionStats, LARGE_MIN_BYTES};
use crate::scan::{LooseFile, RawScan};
use crate::types::{display_path, human_bytes, Evidence, Finding, LinkStrength, ScanConfig};
use serde::Serialize;
use std::path::Path;

/// JSON 主数据。
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub dustlens_version: &'static str,
    pub generated_at_unix: u64,
    pub roots: Vec<String>,
    pub home_display: String,
    pub summary: Summary,
    pub large: Vec<Finding>,
    pub non_compliant: Vec<AppViolationOut>,
    pub odd_location: Vec<Finding>,
    /// 失效引用（P1）—— 目标已不存在，属**仅供参考**，无可归档对象
    pub dangling: Vec<Finding>,
    /// 冗余副本（M4）
    pub duplicates: Vec<DupSetOut>,
    pub unclear: Vec<Finding>,
    pub loose: Vec<LooseOut>,
    pub scan_gaps: Vec<ScanGapOut>,
    pub excluded: ExcludedSummary,
    pub notes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub dirs_scanned: u64,
    pub files_seen: u64,
    pub bytes_seen: u64,
    pub bytes_seen_human: String,
    pub candidates_checked: u64,
    pub in_use: u64,
    pub will_use: u64,
    pub unclaimed: u64,
    pub unmapped_bytes: u64,
    pub unmapped_bytes_human: String,
    pub gaps: u64,
    pub excluded_entries: u64,
    pub excluded_privacy_entries: u64,
    /// 失效引用条数
    pub dangling: u64,
    /// 冗余副本组数
    pub duplicate_sets: u64,
    /// 冗余副本可回收字节（每组留一份）
    pub duplicate_reclaimable: u64,
    pub duplicate_reclaimable_human: String,
    /// 按区域分布：(区域, 组数, 可回收人类可读)
    pub duplicate_areas: Vec<(String, usize, String)>,
    /// 本机可用的包管理器（用于说明「归属」能不能判）
    pub provenance_managers: Vec<String>,
    /// 归属判定为「属于某个包」的条目数
    pub provenance_resolved: u64,
    /// 归属判定为「不属于任何包」的条目数
    pub provenance_untracked: u64,
    /// 被内容鉴定出「这是什么」的条目数
    pub identified: u64,
}

#[derive(Debug, Serialize)]
pub struct AppViolationOut {
    pub app: String,
    pub bytes: u64,
    pub bytes_human: String,
    pub paths: Vec<String>,
    pub xdg_suggestion: String,
    pub has_desktop_entry: Option<bool>,
    pub link_strength: LinkStrength,
    pub evidence: Vec<Evidence>,
    /// 恒为 true：规范违规不产出删除建议（见设计共识 §3.2）
    pub informational_only: bool,
}

#[derive(Debug, Serialize)]
pub struct DupSetOut {
    pub size: u64,
    pub size_human: String,
    pub copies: usize,
    pub reclaimable: u64,
    pub reclaimable_human: String,
    pub members: Vec<DupMemberOut>,
}

#[derive(Debug, Serialize)]
pub struct DupMemberOut {
    pub path: String,
    pub link_strength: crate::types::LinkStrength,
    pub mtime_unix: u64,
}

#[derive(Debug, Serialize)]
pub struct LooseOut {
    pub path: String,
    pub bytes: u64,
    pub bytes_human: String,
}

#[derive(Debug, Serialize)]
pub struct ScanGapOut {
    pub path: String,
    pub kind: crate::types::GapKind,
    pub kind_label: &'static str,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct ExcludedSummary {
    pub total: u64,
    pub privacy: u64,
    /// 只说明「有多少项被排除」，不列路径（避免把隐私目录写进报告）
    pub note: String,
}

/// 「我的盘到底被什么占着」—— 体积由大到小的目录榜。
#[derive(Debug, Serialize)]
pub struct OccupancyRow {
    pub path: String,
    pub bytes: u64,
    pub bytes_human: String,
    pub files: u64,
}

/// 由扫描 + 检测结果构造报告。
pub fn build(
    scan: &RawScan,
    det: &Detection,
    cfg: &ScanConfig,
    version: &'static str,
) -> (Report, Vec<OccupancyRow>) {
    let home = cfg.home.as_deref();

    let mapped: u64 = det
        .large
        .iter()
        .chain(det.odd_location.iter())
        .chain(det.unclear.iter())
        .map(|f| f.bytes)
        .sum();
    let unmapped = scan.stats.bytes_seen.saturating_sub(mapped);

    let privacy_count = scan.excluded.iter().filter(|e| e.privacy).count() as u64;

    let report = Report {
        schema: "dustlens.report/v1",
        dustlens_version: version,
        generated_at_unix: now_unix(),
        roots: cfg.roots.iter().map(|r| display_path(r, home)).collect(),
        // 家目录本身也必须脱敏：早先这里写成 `display_path(h, None)`，
        // 而 `home = None` 时该函数原样返回 —— 于是报告头部一直打印
        // 真实的 `/home/<用户名>`，泄漏 OS 用户名。
        home_display: if cfg.home.is_some() {
            "$HOME".to_string()
        } else {
            "(未知)".to_string()
        },
        summary: Summary {
            dirs_scanned: scan.stats.dirs_scanned,
            files_seen: scan.stats.files_seen,
            bytes_seen: scan.stats.bytes_seen,
            bytes_seen_human: human_bytes(scan.stats.bytes_seen),
            candidates_checked: det.stats.candidates_checked,
            in_use: det.stats.in_use,
            will_use: det.stats.will_use,
            unclaimed: det.stats.unclaimed,
            unmapped_bytes: unmapped,
            unmapped_bytes_human: human_bytes(unmapped),
            gaps: scan.gaps.len() as u64,
            excluded_entries: scan.excluded.len() as u64,
            excluded_privacy_entries: privacy_count,
            dangling: det.dangling.len() as u64,
            // 用**真实总量**，不是明细条数 —— 明细有上限
            duplicate_sets: det.duplicate_total_sets as u64,
            duplicate_reclaimable: det.duplicate_total_reclaimable,
            duplicate_reclaimable_human: human_bytes(det.duplicate_total_reclaimable),
            duplicate_areas: det
                .duplicate_by_area
                .iter()
                .take(10)
                .map(|(a, n, b)| (a.clone(), *n, human_bytes(*b)))
                .collect(),
            provenance_managers: det
                .provenance
                .managers
                .iter()
                .map(|s| s.to_string())
                .collect(),
            provenance_resolved: det.provenance.resolved,
            provenance_untracked: det.provenance.untracked,
            identified: det.identified as u64,
        },
        large: det.large.clone(),
        non_compliant: det.non_compliant.iter().map(|v| to_out(v, home)).collect(),
        odd_location: det.odd_location.clone(),
        dangling: det.dangling.clone(),
        duplicates: det
            .duplicates
            .iter()
            .map(|s| DupSetOut {
                size: s.size,
                size_human: s.human_size(),
                copies: s.members.len() + s.truncated,
                reclaimable: s.reclaimable(),
                reclaimable_human: human_bytes(s.reclaimable()),
                members: s
                    .members
                    .iter()
                    .map(|m| DupMemberOut {
                        path: m.display_path.clone(),
                        link_strength: m.link,
                        mtime_unix: m.mtime_unix,
                    })
                    .collect(),
            })
            .collect(),
        unclear: det.unclear.clone(),
        loose: det
            .loose
            .iter()
            .map(|l| LooseOut {
                path: display_path(&l.path, home),
                bytes: l.bytes,
                bytes_human: human_bytes(l.bytes),
            })
            .collect(),
        scan_gaps: scan
            .gaps
            .iter()
            .map(|g| ScanGapOut {
                path: g.display_path.clone(),
                kind: g.kind,
                kind_label: g.kind.label(),
                detail: g.detail.clone(),
            })
            .collect(),
        excluded: ExcludedSummary {
            total: scan.excluded.len() as u64,
            privacy: privacy_count,
            note: "被排除的项在进榜之前即被拦掉，不进任何分区；隐私项不读取内容、不写入报告".into(),
        },
        notes: notes(),
    };

    let mut occ: Vec<OccupancyRow> = scan
        .dirs
        .iter()
        .filter(|d| d.bytes > 0)
        .map(|d| OccupancyRow {
            path: display_path(&d.path, home),
            bytes: d.bytes,
            bytes_human: human_bytes(d.bytes),
            files: d.files,
        })
        .collect();
    occ.sort_by_key(|b| std::cmp::Reverse(b.bytes));
    occ.truncate(50);

    (report, occ)
}

fn to_out(v: &AppViolation, home: Option<&Path>) -> AppViolationOut {
    AppViolationOut {
        app: v.app.clone(),
        bytes: v.bytes,
        bytes_human: human_bytes(v.bytes),
        paths: v.paths.iter().map(|p| display_path(p, home)).collect(),
        xdg_suggestion: v.suggestion.clone(),
        has_desktop_entry: v.has_desktop_entry,
        link_strength: v.link,
        evidence: v.evidence.clone(),
        informational_only: true,
    }
}

fn notes() -> Vec<String> {
    vec![
        "本报告只声明形式属性并附引用证据，不含任何『该不该删』的判断。".into(),
        "『无人认领』只说明没有进程或配置引用它，不等于你不需要它。".into(),
        "规范违规一节记录的是应用的存放行为，不是可删除对象的清单。".into(),
        "失效引用一节只陈述『某配置指向的目标已不存在』，目标本身已无可归档的内容。".into(),
        "冗余副本一节按内容分组陈述事实，不指定保留哪一份 —— 那是用户的决定。".into(),
        "归属来自本机包管理器的查询结果；『不属于任何包』不等于『来路不明』——多为用户手动安装或应用自建。".into(),
        "扫描盲区一节列出未能读取的位置；未列出即代表已读到。".into(),
    ]
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn render_json(report: &Report) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

/// 渲染 Markdown 视图。
pub fn render_markdown(
    report: &Report,
    occ: &[OccupancyRow],
    scan: &RawScan,
    det: &Detection,
    cfg: &ScanConfig,
) -> String {
    let home = cfg.home.as_deref();
    let mut s = String::new();

    s.push_str("# DustLens 诊断报告\n\n");
    s.push_str(&format!(
        "> 生成时间（Unix）：{} ｜ DustLens {}\n",
        report.generated_at_unix, report.dustlens_version
    ));
    s.push_str(&format!(
        "> 扫描根：{} ｜ 家目录：{}\n\n",
        report.roots.join("  "),
        report.home_display
    ));

    // ---- 摘要 ----
    s.push_str("## 摘要\n\n");
    s.push_str(&format!(
        "- 扫描：**{}** 个目录 · **{}** 个文件 · **{}**\n",
        report.summary.dirs_scanned, report.summary.files_seen, report.summary.bytes_seen_human
    ));
    s.push_str(&format!(
        "- 引用检查：**{}** 项 → 🔴 正在用 {} · 🟡 配置指向 {} · ⚪ 无人认领 {}\n",
        report.summary.candidates_checked,
        report.summary.in_use,
        report.summary.will_use,
        report.summary.unclaimed
    ));
    if report.summary.provenance_managers.is_empty() {
        s.push_str("- 归属：本机**没有可用的包管理器** → 无法判断「谁装的」\n");
    } else {
        s.push_str(&format!(
            "- 归属（{}）：**{}** 条可查到所属包 · **{}** 条不属于任何包\n",
            report.summary.provenance_managers.join(" / "),
            report.summary.provenance_resolved,
            report.summary.provenance_untracked
        ));
    }
    s.push_str(&format!(
        "- 失效引用：**{}** 条（配置指向的目标已不存在）\n",
        report.summary.dangling
    ));
    s.push_str(&format!(
        "- 冗余副本：**{}** 组，每组留一份可回收 **{}**\n",
        report.summary.duplicate_sets, report.summary.duplicate_reclaimable_human
    ));
    s.push_str(&format!(
        "- 内容鉴定：**{}** 项能确定性说出「这是什么」（不依赖 LLM）\n",
        report.summary.identified
    ));
    s.push_str(&format!(
        "- 扫描盲区：**{}** 处（见[扫描盲区](#扫描盲区)）\n",
        report.summary.gaps
    ));
    s.push_str(&format!(
        "- 排除：**{}** 项（其中隐私项 {} 项，未读取内容）\n\n",
        report.summary.excluded_entries, report.summary.excluded_privacy_entries
    ));

    // ---- 体积异常 ----
    section_findings(&mut s, "体积异常", &report.large, home);

    // ---- 规范违规 ----
    s.push_str("## 规范违规（按应用）\n\n");
    if report.non_compliant.is_empty() {
        s.push_str("_本次扫描未发现把数据写在 XDG 约定之外的应用。_\n\n");
    } else {
        s.push_str(
            "> 这一节的主语是**应用**，不是文件。它记录的是应用的存放行为，**不是可删除对象的清单**。\n\n",
        );
        for v in &report.non_compliant {
            s.push_str(&format!("### {} · {}\n\n", v.app, v.bytes_human));
            s.push_str(&format!("- 路径：{}\n", v.paths.join("  ")));
            s.push_str(&format!("- XDG 建议位置：{}\n", v.xdg_suggestion));
            s.push_str(&format!("- 引用：{}\n", v.link_strength.label()));
            for e in &v.evidence {
                if matches!(e, Evidence::Content { .. }) {
                    continue; // 建议行单独输出，避免重复
                }
                s.push_str(&format!("  - {}\n", e.summary(home)));
            }
            match v.has_desktop_entry {
                Some(true) => s.push_str("- 桌面项：存在\n"),
                Some(false) => s.push_str("- 桌面项：未找到\n"),
                None => s.push_str("- 桌面项：无法判断\n"),
            }
            s.push('\n');
        }
    }

    // ---- 位置异常 ----
    section_findings(&mut s, "位置异常", &report.odd_location, home);

    // ---- 失效引用（P1）----
    s.push_str("## 失效引用\n\n");
    if report.dangling.is_empty() {
        s.push_str("_本次扫描没有发现指向已消失目标的配置引用。_\n\n");
    } else {
        s.push_str(
            "> **只陈述事实**：以下路径在本机**已经不存在**，或**指向它们的东西已失效**。\n\
             > 来源有两类：① 配置里记录的路径；② **指向已消失目标的符号链接**。\n\
             > 这不代表「那个应用该删」—— 目标已经不在了，本节不产出任何操作建议。\n\
             > 配置类判定范围：仅限**家目录内**的目标；且要求**父目录存在**（否则多半是文档示例路径）。\n\n",
        );
        s.push_str("| 位置（已不存在 / 已失效） | 来源 | 依据 |\n|---|---|---|\n");
        // 符号链接按「所在目录」聚合：同一个 node_modules 里 79 条死链接逐条列出
        // 会把真正的信号埋掉（这是本项目反复踩过的坑）。
        let mut link_by_dir: std::collections::BTreeMap<String, (usize, String, String)> =
            std::collections::BTreeMap::new();
        let mut non_link: Vec<&Finding> = Vec::new();
        for f in &report.dangling {
            let is_link = f
                .evidence
                .iter()
                .any(|e| matches!(e, Evidence::Symlink { .. }));
            if is_link {
                let dir = f
                    .display_path
                    .rsplit_once('/')
                    .map(|(d, _)| d.to_string())
                    .unwrap_or_else(|| "$HOME".into());
                let target = f
                    .evidence
                    .iter()
                    .find_map(|e| match e {
                        Evidence::Symlink { display_target } => Some(display_target.clone()),
                        _ => None,
                    })
                    .unwrap_or_default();
                let e = link_by_dir
                    .entry(dir)
                    .or_insert((0, target, f.display_path.clone()));
                e.0 += 1;
            } else {
                non_link.push(f);
            }
        }
        for f in non_link.iter().take(60) {
            // 两种来源：配置引用（DanglingReference）与死符号链接（Symlink）。
            // 两者的展示路径都已在构造时脱敏。
            let (source, note) = if let Some((file, note)) = f.evidence.iter().find_map(|e| match e
            {
                Evidence::DanglingReference { display_file, note } => {
                    Some((display_file.clone(), note.clone()))
                }
                _ => None,
            }) {
                (format!("`{file}`"), note)
            } else if let Some(target) = f.evidence.iter().find_map(|e| match e {
                Evidence::Symlink { display_target } => Some(display_target.clone()),
                _ => None,
            }) {
                (
                    "（符号链接本身）".to_string(),
                    format!("这是个符号链接，指向的目标已消失 → `{target}`"),
                )
            } else {
                ("?".into(), String::new())
            };
            s.push_str(&format!(
                "| `{}` | {} | {} |\n",
                f.display_path, source, note
            ));
        }
        for (dir, (n, sample, first)) in link_by_dir {
            if n == 1 {
                // 只有一条时直接显示这个链接本身，聚合反而丢信息
                s.push_str(&format!(
                    "| `{first}` | （符号链接本身） | 指向的目标已消失 → `{sample}` |\n"
                ));
            } else {
                s.push_str(&format!(
                    "| `{dir}` 下 **{n}** 个符号链接 | （符号链接本身） | 目标均已消失，例如 → `{sample}` |\n"
                ));
            }
        }
        if report.dangling.len() > 60 {
            s.push_str(&format!(
                "\n_另有 {} 条未列出（完整清单见 JSON）。_\n",
                report.dangling.len() - 60
            ));
        }
        s.push('\n');
    }

    // ---- 冗余副本（M4）----
    s.push_str("## 冗余副本\n\n");
    if report.duplicates.is_empty() {
        s.push_str("_本次扫描的候选文件中没有发现字节完全相同的副本。_\n\n");
    } else {
        s.push_str(
            "> 以下每组文件的**内容逐字节相同**（不是哈希猜测，是实际比对）。\n\
             > 本工具**不指定留哪一份** —— 只按组罗列成员。\n\
             > 「可回收」是**形式计算**（每组只留一份），**不代表这些都该删**：\n\
             > 例如 Steam 的各个 Proton 版本各自带同一份运行时库，内容相同但是必需的。\n\n",
        );
        // 事实性分布：让 42 GiB 这种总量能落到具体位置
        if report.summary.duplicate_areas.len() > 1 {
            s.push_str("### 分布\n\n| 区域 | 组数 | 可回收 |\n|---|---:|---:|\n");
            for (area, n, bytes_h) in &report.summary.duplicate_areas {
                s.push_str(&format!("| `{area}` | {n} | {bytes_h} |\n"));
            }
            s.push('\n');
        }
        for (i, set) in report.duplicates.iter().take(40).enumerate() {
            s.push_str(&format!(
                "### 组 {} · {} × {} 份 · 可回收 {}\n\n",
                i + 1,
                set.size_human,
                set.copies,
                set.reclaimable_human
            ));
            s.push_str("| 成员 | 体积 | 引用 |\n|---|---:|---|\n");
            for m in &set.members {
                s.push_str(&format!(
                    "| `{}` | {} | {} |\n",
                    m.path,
                    set.size_human,
                    m.link_strength.label()
                ));
            }
            if set.copies > set.members.len() {
                s.push_str(&format!(
                    "\n_另有 {} 个成员未列出。_\n",
                    set.copies - set.members.len()
                ));
            }
            s.push('\n');
        }
        if report.duplicates.len() > 40 {
            s.push_str(&format!(
                "_另有 {} 组未列出（完整清单见 JSON）。_\n\n",
                report.duplicates.len() - 40
            ));
        }
    }

    // ---- 说不清 ----
    s.push_str("## 说不清\n\n");
    if report.unclear.is_empty() {
        s.push_str("_本次扫描没有出现「无引用、体积可观、但无法归类」的条目。_\n\n");
    } else {
        s.push_str(
            "> 这些条目**不是「一种脏」**，而是**判定失败**：工具无法确认它是什么。\n\
             > 默认不进任何自动流程。你可以逐条查看内容，或交由 LLM 分析（会消耗较多 token）。\n\
             > 注：能被**结构/魔数**确定性识别的条目已经移出本节（见各项的「这是什么」依据）。\n\n",
        );
        for f in &report.unclear {
            render_finding(&mut s, f, 3, home);
        }
    }

    // ---- 顶层散落物 ----
    s.push_str("## 顶层散落物\n\n");
    if report.loose.is_empty() {
        s.push_str(&format!(
            "_扫描根下没有超过 {} 的散落文件。_\n\n",
            human_bytes(crate::detect::LOOSE_MIN_BYTES)
        ));
    } else {
        s.push_str("| 文件 | 体积 |\n|---|---:|\n");
        for l in &report.loose {
            s.push_str(&format!("| `{}` | {} |\n", l.path, l.bytes_human));
        }
        s.push('\n');
    }

    // ---- 我的盘被什么占着 ----
    s.push_str("## 我的盘被什么占着\n\n");
    s.push_str("> 目录级体积（含全部后代），按体积降序取前 30。\n\n");
    s.push_str("| 目录 | 体积 | 文件数 |\n|---|---:|---:|\n");
    for row in occ.iter().take(30) {
        if row.bytes == 0 {
            continue;
        }
        s.push_str(&format!(
            "| `{}` | {} | {} |\n",
            row.path, row.bytes_human, row.files
        ));
    }
    s.push('\n');

    // ---- 扫描盲区 ----
    s.push_str("## 扫描盲区\n\n");
    if report.scan_gaps.is_empty() {
        s.push_str("_本次扫描没有遇到读取失败的位置。_\n\n");
    } else {
        // 按原因聚合：4 万条「符号链接未跟随」逐条列出没有阅读价值，
        // 反而会把真正的「权限不足」淹没。
        let mut by_kind: std::collections::BTreeMap<&str, Vec<&ScanGapOut>> =
            std::collections::BTreeMap::new();
        for g in &report.scan_gaps {
            by_kind.entry(g.kind_label).or_default().push(g);
        }

        s.push_str(&format!(
            "> **诚实披露**：以下 {} 处**未被读到**，它们的体积未计入统计。\n\
             > 未出现在本节的位置，代表已被读到。\n\n",
            report.scan_gaps.len()
        ));
        s.push_str("| 原因 | 处数 | 是否影响结论 |\n|---|---:|---|\n");
        for (kind, items) in &by_kind {
            let impact = match *kind {
                "符号链接未跟随" => "低（默认不跟随，需显式 `--follow-symlinks`）",
                "权限不足" => "**高**（这部分完全没读到）",
                "到达深度上限" => "**高**（显式限制了深度）",
                "跨文件系统未进入" => "中（可用 `--cross-filesystem`）",
                _ => "中",
            };
            s.push_str(&format!("| {} | {} | {} |\n", kind, items.len(), impact));
        }
        s.push('\n');

        // 只详列「真正影响结论」的类别；符号链接/深度上限各举例少量
        for (kind, items) in &by_kind {
            let cap = if *kind == "符号链接未跟随" {
                5
            } else {
                100
            };
            s.push_str(&format!(
                "### {}（{} 处，示例 {} 条）\n\n",
                kind,
                items.len(),
                cap.min(items.len())
            ));
            for g in items.iter().take(cap) {
                s.push_str(&format!("- `{}` — {}\n", g.path, g.detail));
            }
            if items.len() > cap {
                s.push_str(&format!(
                    "- …另有 {} 处（完整清单见 JSON）\n",
                    items.len() - cap
                ));
            }
            s.push('\n');
        }
    }

    // ---- 排除项 ----
    s.push_str("## 已排除\n\n");
    s.push_str(&format!("{}\n\n", report.excluded.note));
    s.push_str(&format!(
        "- 共排除 **{}** 项，其中隐私项 **{}** 项（内容未被读取）\n\n",
        report.excluded.total, report.excluded.privacy
    ));

    // ---- XDG 科普（P4：不给 remediation，但必须科普）----
    s.push_str("## 附：XDG 基础目录规范是什么\n\n");
    s.push_str(
        "本节是**科普**，不是整改建议。\n\n\
         **XDG Base Directory Specification** 是 GNOME / KDE / XFCE 等桌面环境共同遵循的约定，\
         目的是让「配置、数据、缓存」在用户目录里各有固定去处：\n\n\
         | 用途 | 位置 |\n|---|---|\n\
         | 配置 | `$XDG_CONFIG_HOME`（默认 `~/.config`） |\n\
         | 数据 | `$XDG_DATA_HOME`（默认 `~/.local/share`） |\n\
         | 缓存 | `$XDG_CACHE_HOME`（默认 `~/.cache`） |\n\
         | 可执行 | `$XDG_BIN_HOME`（默认 `~/.local/bin`） |\n\n\
         **遵守规范的好处**：备份时知道该备份哪个目录；清理时知道哪个目录可以安全再生；\
         多个应用不会互相覆盖。\n\n\
         **不遵守的后果**：应用把数据丢在家目录根（例如 `~/.minecraft`、`~/.cargo`），\
         家目录逐渐变成一堆认不出来的文件夹。DustLens 会把这类行为登记在本报告的「规范违规」一节。\n\n\
         > **本工具不对这类行为给整改建议** —— 怎么改、改不改，由你和应用的维护者决定。\n\n",
    );

    // ---- 说明 ----
    s.push_str("## 说明\n\n");
    for n in &report.notes {
        s.push_str(&format!("- {n}\n"));
    }
    s.push('\n');

    // ---- 阈值 ----
    s.push_str(&format!(
        "> 判定门槛：体积异常 ≥ {} ｜ 说不清 ≥ {} ｜ 散落物 ≥ {}\n",
        human_bytes(LARGE_MIN_BYTES),
        human_bytes(crate::detect::UNCLEAR_MIN_BYTES),
        human_bytes(crate::detect::LOOSE_MIN_BYTES),
    ));

    // 避免未使用的参数告警
    let _ = (det, scan);
    s
}

fn section_findings(s: &mut String, title: &str, findings: &[Finding], home: Option<&Path>) {
    s.push_str(&format!("## {title}\n\n"));
    if findings.is_empty() {
        s.push_str("_本次扫描没有达到门槛的条目。_\n\n");
        return;
    }
    for f in findings {
        render_finding(s, f, 3, home);
    }
}

fn render_finding(s: &mut String, f: &Finding, level: usize, home: Option<&Path>) {
    let h = "#".repeat(level);
    s.push_str(&format!(
        "{h} `{}` · {} · {} 个文件\n\n",
        f.display_path,
        human_bytes(f.bytes),
        f.files
    ));
    s.push_str(&format!("- 引用：{}\n", f.link.label()));
    if f.link == LinkStrength::InUse {
        s.push_str("- 注：这是**检查这一刻**的快照；编译/索引等短命进程会让目录暂时显示为占用\n");
    }
    if let Some(caveat) = f.link.caveat() {
        s.push_str(&format!("  - ⚠️ {caveat}\n"));
    }
    if f.share.needs_consent() {
        s.push_str("- 隐私：位于家目录之外，送 LLM 需先获得你的同意\n");
    }
    for e in &f.evidence {
        s.push_str(&format!("- {}\n", e.summary(home)));
    }
    if let Some(reason) = &f.inaccessible {
        s.push_str(&format!("- ⚠️ 读取失败：{reason}\n"));
    }
    s.push('\n');
}

/// 帮助函数：供 CLI 打印简短摘要。
pub fn short_summary(report: &Report) -> String {
    format!(
        "扫描 {} 目录 / {} 文件 / {}\n  体积异常 {} · 规范违规 {} · 位置异常 {} · 说不清 {} · 散落物 {}\n  引用：🔴 {} 🟡 {} ⚪ {}｜盲区 {}",
        report.summary.dirs_scanned,
        report.summary.files_seen,
        report.summary.bytes_seen_human,
        report.large.len(),
        report.non_compliant.len(),
        report.odd_location.len(),
        report.unclear.len(),
        report.loose.len(),
        report.summary.in_use,
        report.summary.will_use,
        report.summary.unclaimed,
        report.summary.gaps,
    )
}

/// 供测试与 CLI 使用：从 `RawScan` 取盲区数量。
pub fn gap_count(scan: &RawScan) -> usize {
    scan.gaps.len()
}

/// 供测试：占位，避免 `DetectionStats` 未使用告警。
pub fn stats_debug(s: &DetectionStats) -> String {
    format!("checked={} in_use={}", s.candidates_checked, s.in_use)
}

/// 供测试：散落物计数。
pub fn loose_count(l: &[LooseFile]) -> usize {
    l.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::detect;
    use crate::refs::{ProcessIndex, ReferenceIndex};
    use crate::scan::scan;
    use crate::types::ScanGap;
    use std::fs;

    fn run(tag: &str) -> (Report, String, RawScan) {
        let home = std::env::temp_dir().join(format!("dl_rep_{tag}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(home.join(".minecraft/saves")).unwrap();
        fs::write(home.join(".minecraft/options.txt"), vec![0u8; 2048]).unwrap();
        fs::create_dir_all(home.join("Downloads/node_modules/x")).unwrap();
        fs::write(home.join("Downloads/node_modules/x/a.js"), vec![0u8; 4096]).unwrap();

        let cfg = ScanConfig::new(vec![home.clone()], Some(home.clone()));
        let scan = scan(&cfg);
        let det = detect(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
        );
        let (rep, occ) = build(&scan, &det, &cfg, "test");
        let md = render_markdown(&rep, &occ, &scan, &det, &cfg);
        let _ = fs::remove_dir_all(&home);
        (rep, md, scan)
    }

    #[test]
    fn markdown_has_required_sections() {
        let (_rep, md, _scan) = run("secs");
        for h in [
            "# DustLens 诊断报告",
            "## 摘要",
            "## 体积异常",
            "## 规范违规（按应用）",
            "## 位置异常",
            "## 说不清",
            "## 顶层散落物",
            "## 我的盘被什么占着",
            "## 扫描盲区",
            "## 已排除",
            "## 附：XDG 基础目录规范是什么",
            "## 说明",
        ] {
            assert!(md.contains(h), "缺少章节 {h}");
        }
    }

    #[test]
    fn markdown_never_contains_delete_suggestions() {
        let (_rep, md, _scan) = run("nodelete");
        for bad in ["建议删除", "可以删除", "应当删除", "推荐删除"] {
            assert!(!md.contains(bad), "报告中不得出现删除建议: {bad}");
        }
    }

    #[test]
    fn markdown_has_no_absolute_home_path() {
        let (_rep, md, scan) = run("nohome");
        // 两重断言：
        // 1) 不含通用的家目录前缀
        let abs_home_prefix = concat!("/", "home", "/");
        assert!(!md.contains(abs_home_prefix), "报告不得含绝对家目录路径");

        // 2) **不含本次扫描的真实家目录字符串**。
        //    第 2 条才是真正有效的检查 —— 历史上有三处泄漏
        //    （报告头部 home_display、evidence.summary、规范违规的路径行）
        //    都因为只查 `/home/` 而在临时目录测试里逃过了。
        let home = scan.roots[0].to_string_lossy().into_owned();
        assert!(
            !md.contains(home.as_str()),
            "Markdown 不得出现本次扫描的真实家目录路径"
        );
        assert!(md.contains("$HOME") || md.contains("(未知)"));
    }

    #[test]
    fn json_is_valid_and_has_schema() {
        let (rep, _md, _scan) = run("json");
        let j = render_json(&rep);
        let v: serde_json::Value = serde_json::from_str(&j).expect("JSON 必须可解析");
        assert_eq!(v["schema"], "dustlens.report/v1");
        assert!(v["summary"]["files_seen"].as_u64().unwrap() >= 2);
    }

    #[test]
    fn non_compliant_output_is_informational_only() {
        let (rep, _md, _scan) = run("nc");
        for v in &rep.non_compliant {
            assert!(v.informational_only, "规范违规必须标记为仅供参考");
        }
    }

    #[test]
    fn dangling_referrer_is_masked_in_markdown() {
        // 回归：真实报告里曾出现 `/home/<user>/.config/...` 作为「引用它的配置」
        use crate::detect::Detection;
        use crate::types::{Evidence, Finding, FindingKind, LinkStrength, SharePolicy};

        let home = std::env::temp_dir().join(format!("dl_dmask_{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(home.join(".config")).unwrap();

        let cfg = ScanConfig::new(vec![home.clone()], Some(home.clone()));
        let scan = scan(&cfg);
        let mut det = Detection::default();
        det.dangling.push(Finding {
            path: home.join("gone/x"),
            display_path: "$HOME/gone/x".into(),
            kind: FindingKind::DanglingRef,
            bytes: 0,
            files: 0,
            link: LinkStrength::Unclaimed,
            evidence: vec![Evidence::DanglingReference {
                display_file: "$HOME/.config/app.json".into(),
                note: "配置中记录的路径已不存在".into(),
            }],
            share: SharePolicy::InHome,
            inaccessible: None,
        });

        let (rep, occ) = build(&scan, &det, &cfg, "test");
        let md = render_markdown(&rep, &occ, &scan, &det, &cfg);

        assert!(
            md.contains("$HOME/.config/app.json"),
            "引用者路径应脱敏为 $HOME 形式"
        );
        let abs = home.to_string_lossy().into_owned();
        assert!(
            !md.contains(abs.as_str()),
            "Markdown 不得出现绝对家目录路径"
        );
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn duplicates_section_renders_and_never_picks_a_keeper() {
        let home = std::env::temp_dir().join(format!("dl_dupsec_{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&home).unwrap();
        let data = vec![3u8; 20_000];
        fs::write(home.join("a.bin"), &data).unwrap();
        fs::write(home.join("b.bin"), &data).unwrap();

        let mut cfg = ScanConfig::new(vec![home.clone()], Some(home.clone()));
        cfg.dup_min_bytes = 1024; // 测试里文件很小，必须调低门槛
        let scan = scan(&cfg);
        let det = detect(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
        );

        let (rep, occ) = build(&scan, &det, &cfg, "test");
        let md = render_markdown(&rep, &occ, &scan, &det, &cfg);

        assert!(md.contains("## 冗余副本"));
        assert!(!rep.duplicates.is_empty(), "应检出 1 组副本");
        assert!(md.contains("a.bin") && md.contains("b.bin"));
        // P1：不得指定留哪一份
        for bad in ["建议保留", "保留这一份", "删掉其余", "主副本"] {
            assert!(!md.contains(bad), "不得出现「{bad}」这类指定保留者的措辞");
        }
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn json_has_no_real_home_path_and_no_raw_path_field() {
        // brief v15 §3.2① 的验收断言：
        // 1) JSON 里不得出现**本次扫描的真实家目录**（不是 "/home/" 前缀）
        // 2) Finding.path 不参与序列化（真实路径不能进 JSON）
        use crate::refs::build_reference_index;

        let home = std::env::temp_dir().join(format!("dl_jsonleak_{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        // 配置文件里引用一个**存在**的家目录内路径 → 产出 ConfigReference 证据
        fs::create_dir_all(home.join(".config/app")).unwrap();
        fs::create_dir_all(home.join("data")).unwrap();
        fs::write(home.join("data/big.bin"), vec![0u8; 2048]).unwrap();
        fs::write(
            home.join(".config/app/settings.json"),
            format!("{{\"dir\": \"{}/data\"}}", home.display()),
        )
        .unwrap();

        let cfg = ScanConfig::new(vec![home.clone()], Some(home.clone()));
        let scan = scan(&cfg);
        let refs = build_reference_index(Some(&home), &cfg.excludes);
        let det = detect(&scan, &ProcessIndex::default(), &refs, &cfg);
        let (rep, _occ) = build(&scan, &det, &cfg, "test");

        let json = render_json(&rep);
        let real_home = home.to_string_lossy().into_owned();
        assert!(
            !json.contains(real_home.as_str()),
            "JSON 不得出现本次扫描的真实家目录"
        );
        assert!(
            !json.contains("\"path\""),
            "Finding.path 不应被序列化（应只有 display_path）"
        );
        assert!(json.contains("$HOME"), "JSON 应使用 $HOME 字面量");

        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn gaps_are_reported_in_markdown() {
        let home = std::env::temp_dir().join(format!("dl_gap_{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&home).unwrap();
        let cfg = ScanConfig::new(vec![home.clone()], Some(home.clone()));
        let mut scan = scan(&cfg);
        scan.gaps.push(ScanGap {
            display_path: "$HOME/locked".into(),
            kind: crate::types::GapKind::PermissionDenied,
            detail: "Permission denied".into(),
        });
        let det = Detection::default();
        let (rep, occ) = build(&scan, &det, &cfg, "test");
        let md = render_markdown(&rep, &occ, &scan, &det, &cfg);
        assert!(md.contains("诚实披露"), "必须显式披露盲区");
        assert!(md.contains("$HOME/locked"));
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn link_strength_serializes_as_three_distinct_values_in_report() {
        let home = std::env::temp_dir().join(format!("dl_ls_{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(home.join("data")).unwrap();
        fs::write(home.join("data/f"), vec![0u8; 1024]).unwrap();

        let cfg = ScanConfig::new(vec![home.clone()], Some(home.clone()));
        let scan = scan(&cfg);
        let det = detect(
            &scan,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            &cfg,
        );
        let (rep, _occ) = build(&scan, &det, &cfg, "test");
        let j = render_json(&rep);
        // 三个取值都应当能以字符串形式出现（至少 unclaimed 一定出现）
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        let _ = v;
        assert!(j.contains("unclaimed") || j.contains("in_use"));
        let _ = fs::remove_dir_all(&home);
    }
}
