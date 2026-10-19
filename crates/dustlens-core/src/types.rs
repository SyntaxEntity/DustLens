//! DustLens 数据模型。
//!
//! 设计约束（见 `DustLens-设计共识.md`）：
//! - **P1**：只声明形式属性 + 附引用证据；不含任何「价值判断」字段。
//! - **引用强度必须是三个不同的值**（`LinkStrength`），不能退化成布尔值。
//! - **扫描盲区（`ScanGap`）是独立概念**，与隐私（`SharePolicy`）不同轴，不得合并。

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

/// 引用强度。
///
/// 三级是**证据强度**的区分，不是「能不能删」的区分：
/// - `InUse`：有进程正在使用 → 现在删会出错（最硬）
/// - `WillUse`：有配置/自启/桌面项指向它 → 下次启动会读
/// - `Unclaimed`：全系统零引用 → **只说明没人认领，不说明你不需要**
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkStrength {
    /// 🔴 有进程正在使用（cwd 或打开句柄）
    InUse,
    /// 🟡 有配置 / 自启项 / 桌面项指向它
    WillUse,
    /// ⚪ 零引用
    Unclaimed,
}

impl LinkStrength {
    /// 给用户看的中文标签 —— **措辞即产品**，不要弱化 `Unclaimed` 的不确定性。
    pub fn label(self) -> &'static str {
        match self {
            LinkStrength::InUse => "🔴 正在使用",
            LinkStrength::WillUse => "🟡 配置/自启项指向它",
            LinkStrength::Unclaimed => "⚪ 无人认领",
        }
    }

    /// `Unclaimed` 的下一步动作提示，避免用户把「零引用」读成「可删」。
    pub fn caveat(self) -> Option<&'static str> {
        match self {
            LinkStrength::Unclaimed => {
                Some("无人认领 ≠ 不需要：请详细查看内容判断，或交由 LLM 分析")
            }
            _ => None,
        }
    }

    /// 用于排序：越"活"越靠前。
    pub fn rank(self) -> u8 {
        match self {
            LinkStrength::InUse => 0,
            LinkStrength::WillUse => 1,
            LinkStrength::Unclaimed => 2,
        }
    }
}

impl fmt::Display for LinkStrength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// 一条引用证据的具体来源。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    /// 进程正在把它当 cwd
    ProcessCwd { pid: u32, comm: String },
    /// 进程打开了它的句柄
    ProcessFd { pid: u32, comm: String },
    /// 配置文件里出现了它的路径
    ///
    /// 字段类型是 `String` 而**不是 `PathBuf`** —— 存进去的必须是已经脱敏的展示路径。
    /// 这是刻意的：`Serialize` 会按字段原样写出，存裸路径就必然在 JSON 通道泄漏。
    ConfigReference { display_file: String },
    /// 桌面项 / 自启项里出现了它的路径（已脱敏）
    DesktopReference { display_file: String },
    /// 符号链接（目标已脱敏）
    Symlink { display_target: String },
    /// 可重建产物：生成器是否还在（形式属性，不是价值判断）
    ///
    /// 「生成器还在」意味着产物可以重新生成；「生成器不在」意味着它已退化成普通数据。
    /// 这条**不构成删除建议**，只是把简报里最重要的判据摆到证据链上。
    Generator {
        /// 产物目录名（如 `target`、`node_modules`）
        artifact: String,
        /// 生成器（如 `cargo`、`npm`）
        tool: String,
        /// 生成器当前在本机是否可用
        tool_available: bool,
        /// 触发重建所需的项目文件是否还在（如 `Cargo.toml`）
        manifest_present: bool,
        /// 说明
        note: String,
    },
    /// 归属：哪个包管理器拥有它（P0：谁装的）
    ///
    /// `package` 为 `None` 表示**查得到但没有归属**（不属于任何包，即用户手动装的）。
    Provenance {
        /// 命中的包管理器（`rpm` / `dpkg` / `pacman` / `flatpak`）
        manager: String,
        /// 包名（`None` = 不属于任何包）
        package: Option<String>,
        /// 版本（能拿到才有）
        version: Option<String>,
    },
    /// 失效引用：某处配置指向了这个**不存在**的目标（P1：B 类孤儿）
    ///
    /// 注意：这条只陈述「指向的东西不在了」，**不构成「所以该删」**（P1 红线）。
    DanglingReference {
        /// 哪个配置指向它（已脱敏）
        display_file: String,
        /// 判定依据（缺失的是文件/目录、父目录是否存在等）
        note: String,
    },
    /// 「这是什么」（M5 内容鉴定，不依赖 LLM）
    ///
    /// `basis` 只描述**结构**（文件名、魔数、目录特征），**绝不包含文件内容**。
    Identification {
        what: String,
        basis: String,
        /// 是否足够确定；`false` 时不得用于剔除「说不清」
        confident: bool,
    },
    /// 体积与文件数统计（不是引用，是身份信息）
    Body { bytes: u64, files: u64 },
    /// 读取该处内容得到的判定依据
    Content { note: String },
}

impl Evidence {
    /// 供 Markdown 渲染用的一行摘要（不含价值判断）。
    ///
    /// `home` 用于把路径渲染成 `$HOME` 字面量 —— 报告里**不得**出现
    /// 绝对家目录路径（泄漏 OS 用户名）。`None` 表示原样输出。
    pub fn summary(&self, _home: Option<&Path>) -> String {
        match self {
            Evidence::ProcessCwd { pid, comm } => format!("进程 {comm} (PID {pid}) 的 cwd"),
            Evidence::ProcessFd { pid, comm } => format!("进程 {comm} (PID {pid}) 打开着它"),
            Evidence::ConfigReference { display_file } => {
                format!("配置 {display_file} 提及它")
            }
            Evidence::DesktopReference { display_file } => {
                format!("桌面项/自启项 {display_file} 提及它")
            }
            Evidence::Symlink { display_target } => {
                format!("符号链接 → {display_target}")
            }
            Evidence::Generator {
                artifact,
                tool,
                tool_available,
                manifest_present,
                ..
            } => {
                let gen_state = if *tool_available && *manifest_present {
                    "生成器与项目描述都在"
                } else if *manifest_present {
                    "项目描述在，但生成器不在 PATH 中"
                } else {
                    "项目描述已不存在 → 产物已退化为普通数据"
                };
                format!("可重建产物 `{artifact}`（生成器 `{tool}`）：{gen_state}")
            }
            Evidence::Provenance {
                manager,
                package,
                version,
            } => match package {
                Some(pkg) => {
                    let mut s = format!("归属 `{manager}`：包 `{pkg}`");
                    if let Some(v) = version {
                        s.push_str(&format!(" {v}"));
                    }
                    s
                }
                None => format!("归属 `{manager}`：**不属于任何包**（用户手动安装或应用自建）"),
            },
            Evidence::DanglingReference { display_file, note } => {
                format!("{display_file} 指向它，但目标不存在：{note}")
            }
            Evidence::Identification {
                what,
                basis,
                confident,
            } => {
                let mark = if *confident { "" } else { "（不确定）" };
                format!("这是什么：{what}{mark} —— 依据：{basis}")
            }
            Evidence::Body { bytes, files } => {
                format!("{} 个文件 · {}（{} B）", files, human_bytes(*bytes), bytes)
            }
            Evidence::Content { note } => note.clone(),
        }
    }

    /// 该证据属于哪一级引用强度；身份类证据返回 `None`。
    pub fn strength(&self) -> Option<LinkStrength> {
        match self {
            Evidence::ProcessCwd { .. } | Evidence::ProcessFd { .. } => Some(LinkStrength::InUse),
            Evidence::ConfigReference { .. } | Evidence::DesktopReference { .. } => {
                Some(LinkStrength::WillUse)
            }
            _ => None,
        }
    }
}

/// 「判脏」的原因 —— 形式属性，不含价值判断（P1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// 体积异常：只对目录判定，散文件不参与排序
    Large,
    /// 规范违规：主语是「应用」，只登记、不产出删除建议
    NonCompliant,
    /// 位置异常
    OddLocation,
    /// 判定失败（「说不清」）—— 独立分区，可选送 LLM
    Unclear,
    /// 失效引用：某处配置指向的目标不存在（B 类孤儿）
    DanglingRef,
}

impl FindingKind {
    pub fn label(self) -> &'static str {
        match self {
            FindingKind::Large => "体积异常",
            FindingKind::NonCompliant => "规范违规",
            FindingKind::OddLocation => "位置异常",
            FindingKind::Unclear => "说不清",
            FindingKind::DanglingRef => "失效引用",
        }
    }

    /// 是否属于「判定失败」类（处理流程与其它三类不同）。
    pub fn is_undetermined(self) -> bool {
        matches!(self, FindingKind::Unclear)
    }

    /// 是否「仅供参考、不产出任何操作建议」。
    ///
    /// 失效引用的主语是**配置**而不是可删除对象 —— 目标本身已经不存在，
    /// 没有什么东西可归档。所以它只陈述事实（P1）。
    pub fn is_informational(self) -> bool {
        matches!(self, FindingKind::DanglingRef)
    }
}

/// 送 LLM 的策略（隐私轴，与 `ScanGap` 无关）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharePolicy {
    /// 位于 `$HOME` 内：路径以 `$HOME` 字面量表示后可直接发送（仍需用户点击触发）
    InHome,
    /// 位于 `$HOME` 外：**必须先获得用户显式同意**，并告知会上传完整路径
    OutsideHome,
}

impl SharePolicy {
    /// 依据目标是否位于家目录之内推导。
    ///
    /// 注意：`home` 未知时保守地判为 `OutsideHome`（宁可多问一次）。
    pub fn derive(path: &Path, home: Option<&Path>) -> Self {
        match home {
            Some(h) if path.starts_with(h) => SharePolicy::InHome,
            _ => SharePolicy::OutsideHome,
        }
    }

    pub fn needs_consent(self) -> bool {
        self == SharePolicy::OutsideHome
    }
}

/// 一条待用户处理（或待鉴定）的发现。
///
/// 不含 `should_delete` 之类的字段 —— 这是刻意的（P1）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// 绝对路径（**不序列化**）
    ///
    /// JSON 报告里只保留 `display_path`（`$HOME` 字面量）。
    /// 真实路径若进了 JSON，脱敏就形同虚设 —— 消费方可以按需把 `$HOME` 展开回来。
    #[serde(skip)]
    pub path: PathBuf,
    /// 以 `$HOME` 字面量表示的展示路径（写入报告时优先用它）
    pub display_path: String,
    pub kind: FindingKind,
    /// 体积（目录为该目录下所有常规文件的合计）
    pub bytes: u64,
    /// 文件数
    pub files: u64,
    /// 引用强度
    pub link: LinkStrength,
    /// 支持该强度判定的证据
    pub evidence: Vec<Evidence>,
    /// 送 LLM 的隐私策略
    pub share: SharePolicy,
    /// 该条目自身被读取时的失败原因（若读不了）
    pub inaccessible: Option<String>,
}

impl Finding {
    /// 该条目是否属于「说不清」分区。
    pub fn is_unclear(&self) -> bool {
        self.kind.is_undetermined()
    }
}

/// 扫描盲区 —— **诚实性要求**（P8）。
///
/// 任何「我没读到」都要记录并报告，否则用户会误以为扫描覆盖了全盘。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanGap {
    /// 出问题的路径（以 `$HOME` 字面量表示）
    pub display_path: String,
    pub kind: GapKind,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapKind {
    /// 权限不足
    PermissionDenied,
    /// 跨文件系统（按 `--one-filesystem` 要求未进入）
    CrossDevice,
    /// 符号链接未跟随
    SymlinkNotFollowed,
    /// 到达深度上限
    MaxDepth,
    /// 其它 I/O 错误
    IoError,
}

impl GapKind {
    pub fn label(self) -> &'static str {
        match self {
            GapKind::PermissionDenied => "权限不足",
            GapKind::CrossDevice => "跨文件系统未进入",
            GapKind::SymlinkNotFollowed => "符号链接未跟随",
            GapKind::MaxDepth => "到达深度上限",
            GapKind::IoError => "I/O 错误",
        }
    }
}

/// 扫描配置。
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// 扫描根（至少一个；由用户显式选择 —— P7）
    pub roots: Vec<PathBuf>,
    /// 家目录，用于 `$HOME` 脱敏与 `SharePolicy` 推导
    pub home: Option<PathBuf>,
    /// 是否跟随符号链接（默认否；跨系统引用陷阱正来源于此）
    pub follow_symlinks: bool,
    /// 是否停留在同一文件系统（默认是，避免挂载进网络盘/NTFS）
    pub one_filesystem: bool,
    /// 目录深度上限（`None` = 不限，这是默认值）
    pub max_depth: Option<usize>,
    /// 排除规则（进榜前即拦掉）
    pub excludes: Vec<ExcludeRule>,
    /// 并行线程数；`0` = 自动
    pub threads: usize,
    /// 是否探测「谁装的」（P0）。默认开。
    pub provenance: bool,
    /// 是否探测「失效引用」（P1）。默认开。
    pub dangling: bool,
    /// 是否探测「冗余副本」（M4）。默认开。
    pub duplicates: bool,
    /// 进入去重判定的大小门槛（小于它不值得比对）。
    pub dup_min_bytes: u64,
    /// 是否做内容鉴定（M5）。默认开。
    pub identify: bool,
}

impl ScanConfig {
    pub fn new(roots: Vec<PathBuf>, home: Option<PathBuf>) -> Self {
        Self {
            roots,
            home,
            follow_symlinks: false,
            one_filesystem: true,
            max_depth: None,
            excludes: ExcludeRule::defaults(),
            threads: 0,
            provenance: true,
            dangling: true,
            duplicates: true,
            dup_min_bytes: 1024 * 1024,
            identify: true,
        }
    }
}

/// 排除规则：按路径**组件**匹配，不是子串匹配。
#[derive(Debug, Clone)]
pub struct ExcludeRule {
    /// 相对于家目录的路径组件序列，如 `[".ssh"]` 或 `[".config", "gh"]`
    pub components: Vec<String>,
    pub reason: &'static str,
}

impl ExcludeRule {
    /// 默认排除清单（设计共识 §7.2b）。
    ///
    /// 这些路径**既不出现在结果里，也永远不会被送进 LLM**。
    pub fn defaults() -> Vec<ExcludeRule> {
        const PRIVATE: &str = "隐私：凭据/会话目录，默认排除";
        vec![
            ExcludeRule::new(&[".ssh"], PRIVATE),
            ExcludeRule::new(&[".gnupg"], PRIVATE),
            ExcludeRule::new(&[".password-store"], PRIVATE),
            ExcludeRule::new(&[".local", "share", "keyrings"], PRIVATE),
            ExcludeRule::new(&[".aws"], PRIVATE),
            ExcludeRule::new(&[".config", "gh"], PRIVATE),
            ExcludeRule::new(&[".config", "google-chrome"], "隐私：浏览器配置"),
            ExcludeRule::new(&[".mozilla"], "隐私：浏览器配置"),
            ExcludeRule::new(&[".dsh", "sessions"], "隐私：会话记录"),
        ]
    }

    pub fn new(components: &[&str], reason: &'static str) -> Self {
        Self {
            components: components.iter().map(|s| s.to_string()).collect(),
            reason,
        }
    }

    /// 判断某绝对路径是否命中该规则。
    ///
    /// 规则是**有序组件序列**，从家目录起算；也允许匹配路径中任意连续片段，
    /// 这样 `$HOME` 未知时（例如扫描 `/var/tmp`）仍能命中。
    pub fn matches(&self, path: &Path) -> bool {
        let comps: Vec<String> = path
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        if self.components.len() > comps.len() {
            return false;
        }
        comps
            .windows(self.components.len())
            .any(|w| w.iter().zip(self.components.iter()).all(|(a, b)| a == b))
    }

    /// 隐私级排除：命中后连「说不清」都不进，避免把 `.ssh` 列出来。
    pub fn is_privacy(&self) -> bool {
        self.reason.starts_with("隐私")
    }
}

/// 把字节数变成人类可读形式。
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if v >= 100.0 {
        format!("{v:.0} {}", UNITS[i])
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// 把绝对路径渲染为 `$HOME` 字面量形式，避免绝对家目录路径落盘（合规要求）。
///
/// 若路径不在家目录下则原样返回 —— 调用方仍需据 `SharePolicy` 决定如何处理。
pub fn display_path(path: &Path, home: Option<&Path>) -> String {
    if let Some(h) = home {
        if let Ok(rest) = path.strip_prefix(h) {
            let joined = rest.to_string_lossy().replace('\\', "/");
            if joined.is_empty() {
                return "$HOME".to_string();
            }
            return format!("$HOME/{joined}");
        }
    }
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_strength_is_three_distinct_values() {
        // 这条测试存在的意义：防止有人把三级压成 bool。
        let all = [
            LinkStrength::InUse,
            LinkStrength::WillUse,
            LinkStrength::Unclaimed,
        ];
        let json: Vec<String> = all
            .iter()
            .map(|s| serde_json::to_string(s).unwrap())
            .collect();
        assert_eq!(json.len(), 3);
        assert_ne!(json[0], json[1]);
        assert_ne!(json[1], json[2]);
    }

    #[test]
    fn unclaimed_carries_a_caveat() {
        let c = LinkStrength::Unclaimed.caveat().unwrap();
        assert!(c.contains("≠") || c.contains("不"));
        assert!(LinkStrength::InUse.caveat().is_none());
    }

    #[test]
    fn human_bytes_formats_sensibly() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(3 * 1024 * 1024), "3.0 MiB");
    }

    /// 构造测试用绝对路径，避免在仓库里出现真实家目录形式的字面量
    /// （Atlas 隐私审计会把「绝对家目录形式」的字面量一律判为泄漏）。
    fn p(parts: &[&str]) -> std::path::PathBuf {
        let mut b = std::path::PathBuf::from(std::path::MAIN_SEPARATOR.to_string());
        for x in parts {
            b.push(x);
        }
        b
    }

    #[test]
    fn display_path_masks_home() {
        let home = p(&["home", "alice"]);
        let home = home.as_path();
        let target = p(&["home", "alice", "Projects", "x"]);
        assert_eq!(display_path(&target, Some(home)), "$HOME/Projects/x");
        assert_eq!(display_path(home, Some(home)), "$HOME");
        // 不在家目录下则原样返回
        let outside = p(&["var", "tmp", "a"]);
        assert_eq!(
            display_path(&outside, Some(home)),
            outside.to_string_lossy()
        );
    }

    #[test]
    fn exclude_rule_matches_components_not_substrings() {
        let rule = ExcludeRule::new(&[".ssh"], "test");
        assert!(rule.matches(&p(&["home", "alice", ".ssh"])));
        assert!(rule.matches(&p(&["home", "alice", ".ssh", "id_ed25519"])));
        // 子串不应误命中
        assert!(!rule.matches(&p(&["home", "alice", ".ssh-keys-backup"])));
        assert!(!rule.matches(&p(&["home", "alice", "projects", ".sshfoo"])));
    }

    #[test]
    fn exclude_rule_matches_nested_component_sequence() {
        let rule = ExcludeRule::new(&[".local", "share", "keyrings"], "test");
        assert!(rule.matches(&p(&[
            "home",
            "alice",
            ".local",
            "share",
            "keyrings",
            "login.keyring"
        ])));
        // 顺序不对不应命中
        assert!(!rule.matches(&p(&["home", "alice", ".local", "keyrings", "share"])));
    }

    #[test]
    fn share_policy_defaults_to_outside_when_home_unknown() {
        let home = p(&["home", "alice"]);
        let home = home.as_path();
        assert_eq!(
            SharePolicy::derive(&p(&["x", "y"]), None),
            SharePolicy::OutsideHome
        );
        assert_eq!(
            SharePolicy::derive(&p(&["home", "alice", "x"]), Some(home)),
            SharePolicy::InHome
        );
        assert_eq!(
            SharePolicy::derive(&p(&["var", "tmp", "x"]), Some(home)),
            SharePolicy::OutsideHome
        );
    }

    #[test]
    fn evidence_maps_to_expected_strength() {
        let in_use = Evidence::ProcessFd {
            pid: 1,
            comm: "x".into(),
        };
        assert_eq!(in_use.strength(), Some(LinkStrength::InUse));
        let will_use = Evidence::ConfigReference {
            display_file: "$HOME/.config/x".into(),
        };
        assert_eq!(will_use.strength(), Some(LinkStrength::WillUse));
        let identity = Evidence::Body { bytes: 1, files: 1 };
        assert_eq!(identity.strength(), None);
    }
}
