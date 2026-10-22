//! 配置文件（M7）：把「每次都要敲一长串参数」变成「写一次」。
//!
//! # 位置与优先级
//!
//! 默认位置：`$XDG_CONFIG_HOME/dustlens/config.toml`（通常是 `~/.config/dustlens/config.toml`）。
//!
//! **优先级：命令行 > 配置文件 > 内置默认值。**
//! 命令行永远赢 —— 否则「我明明加了 `--no-duplicates` 为什么还在跑」会变成玄学。
//!
//! # 这个文件**不**能做什么
//!
//! - 不能开「自动删除」：本项目没有这个能力，也不打算有（P3 / P6）。
//! - 不能关掉脱敏：脱敏不是配置项，是输出通道的固有性质（CONVENTIONS §6.6）。
//! - 不能把扫描范围设成 `/`：会给出警告但仍允许（配置是给懂的人用的，见 `[scan] roots`）。

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::detect::Thresholds;
use crate::types::{ExcludeRule, ScanConfig};

/// 配置读取/解析失败。
#[derive(Debug)]
pub enum ConfigError {
    /// 文件读不了（不存在另算，见 `load` 的 `Option` 语义）
    Read(std::io::Error),
    /// TOML 语法或字段类型错误
    Parse(toml::de::Error),
    /// 体积写法无法解析（如 `"100 MB"` 里的单位不认识）
    Size(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Read(e) => write!(f, "读取配置文件失败：{e}"),
            ConfigError::Parse(e) => write!(f, "配置文件格式有误：{e}"),
            ConfigError::Size(s) => write!(f, "无法解析的体积写法：{s}（支持 B/KiB/MiB/GiB/TiB）"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// 配置文件的内存表示。所有字段都是可选的 —— 没写就用默认值。
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    #[serde(default)]
    pub scan: ScanSection,
    #[serde(default)]
    pub thresholds: ThresholdsSection,
    #[serde(default)]
    pub features: FeaturesSection,
    #[serde(default)]
    pub exclude: ExcludeSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanSection {
    /// 扫描根。支持 `$HOME` 字面量；相对路径按当前目录解析。
    pub roots: Option<Vec<String>>,
    /// 是否跟随符号链接（默认 false）
    pub follow_symlinks: Option<bool>,
    /// 是否只跨一个文件系统（默认 false）
    pub one_filesystem: Option<bool>,
    /// 预定义「重灾区」（tmp / opt / srv / varcache …）
    pub presets: Option<Vec<String>>,
    /// 并行线程数（0 = 自动）
    pub threads: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdsSection {
    /// 「体积异常」门槛，如 `"100 MiB"`
    pub large: Option<String>,
    /// 「散落物」门槛，如 `"10 MiB"`
    pub loose: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeaturesSection {
    pub provenance: Option<bool>,
    pub dangling: Option<bool>,
    pub duplicates: Option<bool>,
    pub identify: Option<bool>,
    /// 参与去重比对的最小体积，如 `"1 MiB"`
    pub dup_min_bytes: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExcludeSection {
    /// 排除规则（glob）。追加到内置规则之后。
    pub patterns: Option<Vec<String>>,
}

/// 解析人读体积：`"100 MiB"` / `"1.5 GiB"` / `"512 KiB"` / `"1024"`。
///
/// 单位用二进制（KiB = 1024），与 `df`/`ls -h` 的常见直觉一致；
/// 也接受 `KB/MB/GB` 写法，但**仍按 1024 解释** —— 并在帮助文本里写明，避免歧义。
pub fn parse_size(s: &str) -> Result<u64, ConfigError> {
    let t = s.trim();
    if t.is_empty() {
        return Err(ConfigError::Size(s.into()));
    }
    let (num, unit) = t.split_at(
        t.find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(t.len()),
    );
    let value: f64 = num.parse().map_err(|_| ConfigError::Size(s.to_string()))?;
    if value < 0.0 {
        return Err(ConfigError::Size(s.into()));
    }
    let mult: f64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "k" | "kb" | "kib" => 1024.0,
        "m" | "mb" | "mib" => 1024.0 * 1024.0,
        "g" | "gb" | "gib" => 1024.0 * 1024.0 * 1024.0,
        "t" | "tb" | "tib" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return Err(ConfigError::Size(s.into())),
    };
    Ok((value * mult) as u64)
}

impl FileConfig {
    /// 把配置合并进 `ScanConfig`（在命令行覆盖**之前**调用）。
    ///
    /// 只覆盖配置里显式写了的字段；没写的保持默认值。
    pub fn apply_to(&self, cfg: &mut ScanConfig) -> Result<(), ConfigError> {
        let scan = &self.scan;
        if let Some(roots) = &scan.roots {
            let expanded: Vec<std::path::PathBuf> = roots.iter().map(|r| expand_home(r)).collect();
            if !expanded.is_empty() {
                cfg.roots = expanded;
            }
        }
        if let Some(v) = scan.follow_symlinks {
            cfg.follow_symlinks = v;
        }
        if let Some(v) = scan.one_filesystem {
            cfg.one_filesystem = v;
        }
        if let Some(v) = scan.threads {
            cfg.threads = v;
        }
        if let Some(spec) = &scan.presets {
            let joined = spec.join(",");
            match crate::presets::parse(&joined) {
                Ok(list) => {
                    let (mut proots, _skipped) = crate::presets::resolve(&list);
                    cfg.roots.append(&mut proots);
                }
                Err(e) => return Err(ConfigError::Size(e)),
            }
        }

        let f = &self.features;
        if let Some(v) = f.provenance {
            cfg.provenance = v;
        }
        if let Some(v) = f.dangling {
            cfg.dangling = v;
        }
        if let Some(v) = f.duplicates {
            cfg.duplicates = v;
        }
        if let Some(v) = f.identify {
            cfg.identify = v;
        }
        if let Some(s) = &f.dup_min_bytes {
            cfg.dup_min_bytes = parse_size(s)?;
        }

        if let Some(pats) = &self.exclude.patterns {
            for p in pats {
                let comps: Vec<String> = p
                    .split('/')
                    .filter(|c| !c.is_empty())
                    .map(|c| c.to_string())
                    .collect();
                if comps.is_empty() {
                    continue;
                }
                cfg.excludes.push(ExcludeRule {
                    components: comps,
                    reason: "配置：用户自定义排除",
                });
            }
        }
        Ok(())
    }

    /// 由配置得到的阈值（未写则用传入的默认值）。
    pub fn thresholds(&self, mut base: Thresholds) -> Result<Thresholds, ConfigError> {
        if let Some(s) = &self.thresholds.large {
            base.large_bytes = parse_size(s)?;
        }
        if let Some(s) = &self.thresholds.loose {
            base.loose_bytes = parse_size(s)?;
        }
        Ok(base)
    }
}

/// 展开配置里的 `$HOME` 字面量。
pub fn expand_home(s: &str) -> std::path::PathBuf {
    let t = s.trim();
    if t == "$HOME" || t == "~" {
        return std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(t));
    }
    if let Some(rest) = t.strip_prefix("$HOME/").or_else(|| t.strip_prefix("~/")) {
        if let Some(home) = std::env::var_os("HOME") {
            return std::path::PathBuf::from(home).join(rest);
        }
    }
    std::path::PathBuf::from(t)
}

/// 默认配置文件路径：`$XDG_CONFIG_HOME/dustlens/config.toml`。
pub fn default_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from(".config"));
    base.join("dustlens").join("config.toml")
}

/// 读取配置。
///
/// - 文件不存在 → `Ok(None)`（不是错误：没配置就该用默认值）
/// - 文件存在但语法错 → `Err`，**绝不静默忽略**
pub fn load(path: &Path) -> Result<Option<FileConfig>, ConfigError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(ConfigError::Read(e)),
    };
    toml::from_str(&text).map(Some).map_err(ConfigError::Parse)
}

/// 把配置渲染成可写出的文本（`dustlens config --init` 用）。
pub fn template() -> &'static str {
    r#"# DustLens 配置文件
#
# 优先级：命令行 > 本文件 > 内置默认值。
# 本文件不能开启任何「自动删除」能力 —— 本项目只做诊断，不做处置。

[scan]
# 扫描根。支持 $HOME 字面量；不写则默认 $HOME。
# roots = ["$HOME", "/var/tmp"]
#
# 预定义「重灾区」：tmp / vartmp / opt / srv / varcache / varlog / varlibflatpak
# presets = ["tmp", "opt"]

# 跟随符号链接（默认 false）。打开后可能跨进其它挂载点，慎用。
follow_symlinks = false
# 只统计同一文件系统（默认 false）
one_filesystem = false
# 并行线程数（0 = 按 CPU 自动）
threads = 0

[thresholds]
# 「体积异常」门槛（二进制单位：KiB = 1024）
large = "100 MiB"
# 「顶层散落物」门槛
loose = "10 MiB"

[features]
# 归属（rpm/dpkg/pacman/flatpak 查「谁装的」）
provenance = true
# 失效引用（配置/符号链接指向不存在的东西）
dangling = true
# 冗余副本（会读文件内容，家目录级约多花 1–2 分钟）
duplicates = true
# 内容鉴定（只读文件头与目录项名字，不读全文、不联网）
identify = true
# 参与去重比对的最小体积
dup_min_bytes = "1 MiB"

[exclude]
# 追加到内置排除规则之后的路径片段（不是通配符）：
# 每个条目按 / 分段，出现在路径的任意连续位置即命中。
# patterns = ["node_modules", ".git", "steamapps/common"]
"#
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_toml(text: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "dl_cfg_{}_{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("config.toml");
        std::fs::write(&p, text).unwrap();
        (dir, p)
    }

    #[test]
    fn parses_human_sizes() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("512 KiB").unwrap(), 512 * 1024);
        assert_eq!(parse_size("1.5 MiB").unwrap(), 1024 * 1024 * 3 / 2);
        assert_eq!(parse_size("2 GiB").unwrap(), 2 * 1024 * 1024 * 1024);
        assert!(parse_size("100 lightyears").is_err());
        assert!(parse_size("").is_err());
    }

    #[test]
    fn missing_file_is_not_an_error() {
        let p = std::env::temp_dir().join("dl_cfg_definitely_missing/config.toml");
        assert!(matches!(load(&p), Ok(None)));
    }

    #[test]
    fn parses_full_config() {
        let (dir, p) = write_toml(
            r#"
[scan]
roots = ["$HOME", "/var/tmp"]
follow_symlinks = true
presets = ["tmp"]

[thresholds]
large = "50 MiB"

[features]
duplicates = false
dup_min_bytes = "2 MiB"

[exclude]
patterns = ["*.iso"]
"#,
        );
        let c = load(&p).unwrap().expect("应读到配置");
        assert_eq!(c.scan.roots.as_deref().unwrap(), ["$HOME", "/var/tmp"]);
        assert_eq!(c.scan.follow_symlinks, Some(true));
        assert_eq!(c.thresholds.large.as_deref(), Some("50 MiB"));
        assert_eq!(c.features.duplicates, Some(false));
        assert_eq!(c.exclude.patterns.as_deref().unwrap(), ["*.iso"]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn syntax_error_is_reported_not_ignored() {
        let (dir, p) = write_toml("[scan\nroots = 1");
        assert!(load(&p).is_err(), "语法错误必须报出来，不能静默忽略");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unknown_field_is_rejected() {
        // deny_unknown_fields：拼错的键不能悄悄失效
        let (dir, p) = write_toml("[features]\nduplicat = false\n");
        assert!(load(&p).is_err(), "拼错的字段名必须报错");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn template_is_valid_toml() {
        let parsed: Result<FileConfig, _> = toml::from_str(template());
        assert!(parsed.is_ok(), "自带模板必须能被自己解析");
    }

    #[test]
    fn default_path_ends_with_dustlens_config() {
        let p = default_path();
        assert!(p.ends_with("dustlens/config.toml"), "实际: {}", p.display());
    }
}
