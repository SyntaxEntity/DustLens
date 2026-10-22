//! DustLens 核心：扫描 → 引用证据 → 检测 → 报告。
//!
//! **不包含**：GUI、LLM 调用、任何删除操作。
//!
//! 设计红线（见 `DustLens-设计共识.md`）：
//! - P1 只声明形式属性 + 引用证据，不做价值判断
//! - P5 不自动外发任何数据（本 crate 完全不联网）
//! - P8 扫描盲区必须如实记录并报告
//!
//! 入口见 [`run`]。

pub mod archive;
pub mod dangling;
pub mod detect;
pub mod duplicates;
pub mod identify;
pub mod presets;
pub mod provenance;
pub mod refs;
pub mod report;
pub mod scan;
pub mod types;

use std::path::PathBuf;

pub use detect::{detect_with, Detection, DetectionStats, Thresholds};
pub use duplicates::{DupMember, DuplicateSet};
pub use provenance::Prober;
pub use refs::{load_processes, ProcessIndex, ReferenceIndex};
pub use report::{OccupancyRow, Report};
pub use scan::{RawScan, ScanStats};
pub use types::{
    display_path, human_bytes, Evidence, ExcludeRule, Finding, GapKind, LinkStrength, ScanConfig,
    ScanGap, SharePolicy, Tag,
};

/// 当前核心版本（与 `Cargo.toml` 保持一致）。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 报告 schema 标识。
pub const SCHEMA: &str = "dustlens.report/v1";

/// 一次完整诊断的产物。
#[derive(Debug)]
pub struct Diagnosis {
    pub report: Report,
    pub occupancy: Vec<OccupancyRow>,
    pub markdown: String,
    /// JSON 主数据（惰性渲染，避免 CLI 只要 markdown 时也付序列化代价）
    pub json: Option<String>,
}

/// 执行一次完整诊断。
///
/// 这是本 crate 的**唯一**入口：调用方负责（按 P7）先取得用户对扫描范围的确认。
pub fn run(cfg: &ScanConfig, want_json: bool) -> Diagnosis {
    let raw = scan::scan(cfg);
    let procs = refs::load_processes();
    let refs = refs::build_reference_index(cfg.home.as_deref(), &cfg.excludes);
    let det = detect::detect(&raw, &procs, &refs, cfg);
    let (report, occupancy) = report::build(&raw, &det, cfg, VERSION);
    let markdown = report::render_markdown(&report, &occupancy, &raw, &det, cfg);
    let json = if want_json {
        Some(report::render_json(&report))
    } else {
        None
    };
    Diagnosis {
        report,
        occupancy,
        markdown,
        json,
    }
}

/// 解析用户传入的扫描根：保证至少一个，且全部是绝对路径（P7）。
pub fn normalize_roots(roots: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    if roots.is_empty() {
        return Err("至少需要一个扫描根（P7：扫描必须由用户显式指定并确认）".into());
    }
    let mut out = Vec::new();
    for r in roots {
        let abs = if r.is_absolute() {
            r.clone()
        } else {
            std::env::current_dir()
                .map_err(|e| format!("无法取得当前目录：{e}"))?
                .join(r)
        };
        if !abs.exists() {
            return Err(format!("扫描根不存在：{}", abs.display()));
        }
        out.push(abs);
    }
    Ok(out)
}

/// 从环境推导家目录（供 `$HOME` 脱敏与 `SharePolicy` 使用）。
pub fn home_from_env() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_end_to_end_on_temp_dir() {
        use std::fs;
        let home = std::env::temp_dir().join(format!("dl_e2e_{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(home.join("stuff")).unwrap();
        fs::write(home.join("stuff/a.bin"), vec![0u8; 100]).unwrap();

        let cfg = ScanConfig::new(vec![home.clone()], Some(home.clone()));
        let d = run(&cfg, true);

        assert!(d.markdown.contains("# DustLens 诊断报告"));
        let json = d.json.expect("应生成 JSON");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["schema"], SCHEMA);
        assert_eq!(v["summary"]["files_seen"], 1);
        assert!(!d.occupancy.is_empty());
        let abs_home_prefix = concat!("/", "home", "/");
        assert!(!d.markdown.contains(abs_home_prefix));

        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn normalize_roots_rejects_empty() {
        let e = normalize_roots(&[]).unwrap_err();
        assert!(e.contains("至少需要一个扫描根"));
    }

    #[test]
    fn normalize_roots_rejects_missing() {
        let e = normalize_roots(&[PathBuf::from("/definitely/not/here")]).unwrap_err();
        assert!(e.contains("不存在"));
    }

    #[test]
    fn normalize_roots_makes_absolute() {
        let out = normalize_roots(&[PathBuf::from(".")]).unwrap();
        assert!(out[0].is_absolute());
    }

    #[test]
    fn version_matches_cargo() {
        assert!(!VERSION.is_empty());
        assert_eq!(SCHEMA, "dustlens.report/v1");
    }
}
