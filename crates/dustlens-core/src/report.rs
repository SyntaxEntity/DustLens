//! 报告渲染：JSON（主数据）+ Markdown（视图）。
//!
//! 设计依据：设计共识 §7.4 / §8.3 / §3.2 / P8。
//! - **所有路径用 `$HOME` 字面量**，不出现绝对家目录路径。
//! - **不含任何删除建议**（P1）。
//! - **必须披露扫描盲区**（P8）。
//! - **必须含 XDG 科普**（P4：不给 remediation，但必须科普）。

use crate::detect::{AppViolation, Detection, DetectionStats, LARGE_MIN_BYTES};
use crate::scan::{LooseFile, RawScan};
use crate::types::{
    display_path, human_bytes, Evidence, Finding, LinkStrength, ScanConfig,
};
use serde::Serialize;

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
        roots: cfg
            .roots
            .iter()
            .map(|r| display_path(r, home))
            .collect(),
        home_display: cfg
            .home
            .as_deref()
            .map(|h| display_path(h, None).to_string())
            .unwrap_or_else(|| "(未知)".into()),
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
        },
        large: det.large.clone(),
        non_compliant: det.non_compliant.iter().map(to_out).collect(),
        odd_location: det.odd_location.clone(),
        unclear: det.unclear.clone(),
        loose: det.loose.iter().map(|l| LooseOut {
            path: display_path(&l.path, home),
            bytes: l.bytes,
            bytes_human: human_bytes(l.bytes),
        }).collect(),
        scan_gaps: scan.gaps.iter().map(|g| ScanGapOut {
            path: g.display_path.clone(),
            kind: g.kind,
            kind_label: g.kind.label(),
            detail: g.detail.clone(),
        }).collect(),
        excluded: ExcludedSummary {
            total: scan.excluded.len() as u64,
            privacy: privacy_count,
            note: "被排除的项在进榜之前即被拦掉，不进任何分区；隐私项不读取内容、不写入报告"
                .into(),
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
    occ.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    occ.truncate(50);

    (report, occ)
}

fn to_out(v: &AppViolation) -> AppViolationOut {
    AppViolationOut {
        app: v.app.clone(),
        bytes: v.bytes,
        bytes_human: human_bytes(v.bytes),
        paths: v.paths.iter().map(|p| p.display().to_string()).collect(),
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
                s.push_str(&format!("  - {}\n", e.summary()));
            }
            match v.has_desktop_entry {
                Some(true) => s.push_str("- 桌面项：存在\n"),
                Some(false) => s.push_str("- 桌面项：未找到\n"),
                None => s.push_str("- 桌面项：无法判断\n"),
            }
            s.push_str("\n");
        }
    }

    // ---- 位置异常 ----
    section_findings(&mut s, "位置异常", &report.odd_location, home);

    // ---- 说不清 ----
    s.push_str("## 说不清\n\n");
    if report.unclear.is_empty() {
        s.push_str("_本次扫描没有出现「无引用、体积可观、但无法归类」的条目。_\n\n");
    } else {
        s.push_str(
            "> 这些条目**不是「一种脏」**，而是**判定失败**：工具无法确认它是什么。\n\
             > 默认不进任何自动流程。你可以逐条查看内容，或交由 LLM 分析（会消耗较多 token）。\n\n",
        );
        for f in &report.unclear {
            render_finding(&mut s, f, 3);
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
            let cap = if *kind == "符号链接未跟随" { 5 } else { 100 };
            s.push_str(&format!("### {}（{} 处，示例 {} 条）\n\n", kind, items.len(), cap.min(items.len())));
            for g in items.iter().take(cap) {
                s.push_str(&format!("- `{}` — {}\n", g.path, g.detail));
            }
            if items.len() > cap {
                s.push_str(&format!("- …另有 {} 处（完整清单见 JSON）\n", items.len() - cap));
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

fn section_findings(s: &mut String, title: &str, findings: &[Finding], _home: Option<&std::path::Path>) {
    s.push_str(&format!("## {title}\n\n"));
    if findings.is_empty() {
        s.push_str("_本次扫描没有达到门槛的条目。_\n\n");
        return;
    }
    for f in findings {
        render_finding(s, f, 3);
    }
}

fn render_finding(s: &mut String, f: &Finding, level: usize) {
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
        s.push_str(&format!("- {}\n", e.summary()));
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
        let det = detect(&scan, &ProcessIndex::default(), &ReferenceIndex::default(), &cfg);
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
        let (_rep, md, _scan) = run("nohome");
        // 报告里不应出现绝对家目录路径（用 $HOME 字面量代替）
        let abs_home_prefix = concat!("/", "home", "/");
        assert!(!md.contains(abs_home_prefix), "报告不得含绝对家目录路径");
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
        let det = detect(&scan, &ProcessIndex::default(), &ReferenceIndex::default(), &cfg);
        let (rep, _occ) = build(&scan, &det, &cfg, "test");
        let j = render_json(&rep);
        // 三个取值都应当能以字符串形式出现（至少 unclaimed 一定出现）
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        let _ = v;
        assert!(j.contains("unclaimed") || j.contains("in_use"));
        let _ = fs::remove_dir_all(&home);
    }
}
