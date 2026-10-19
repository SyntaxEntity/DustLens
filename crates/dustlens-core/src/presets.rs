//! 内置「重灾区」热点目录预设。
//!
//! # 为什么需要
//!
//! 简报里最贵的那两项都不在 `$HOME` 下：
//! - 一个 4.31 GB 的 `/var/tmp/cc_mod*`（临时工作目录）
//! - 一个 `/srv` 下的空目录（删了造成唯一一次事故）
//!
//! 默认只扫 `$HOME` 会让工具**系统性漏掉**这些位置。但反过来，
//! 默认扫描 `$HOME` 之外又会违背 P7（扫描必须由用户确认范围）。
//!
//! # 折中
//!
//! 预设**不默认启用**，只是把「常见拉屎位置」整理成一份可勾选清单：
//! CLI 的 `--presets all` 或 `--presets tmp,opt` 才纳入扫描；
//! `dustlens presets` 可查看完整清单与权限要求。
//!
//! 每种预设都标注 `min_privilege`：有些目录普通用户读不了，
//! 扫描时会进 `ScanGap` 并在报告里如实披露（P8）。

use std::path::PathBuf;

/// 单个预设。
#[derive(Debug, Clone, Copy)]
pub struct Preset {
    /// 稳定标识（CLI 里用）
    pub id: &'static str,
    /// 展示名
    pub name: &'static str,
    /// 绝对路径
    pub path: &'static str,
    /// 需要什么权限才能完整读取
    pub min_privilege: Privilege,
    /// 为什么把它列进来
    pub why: &'static str,
}

/// 读取所需的权限级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    /// 普通用户即可完整读取
    User,
    /// 普通用户可读，但部分子目录可能无权
    UserPartial,
    /// 通常需要 root 才能完整读取
    RootLikely,
}

impl Privilege {
    pub fn label(self) -> &'static str {
        match self {
            Privilege::User => "普通用户可读",
            Privilege::UserPartial => "可能部分无权限",
            Privilege::RootLikely => "多半需要 root",
        }
    }
}

/// 全部预设。
///
/// 排序原则：**越常常堆积垃圾的位置越靠前**。
pub const PRESETS: &[Preset] = &[
    Preset {
        id: "tmp",
        name: "临时目录",
        path: "/tmp",
        min_privilege: Privilege::UserPartial,
        why: "程序运行时的临时文件；多数会被清理，但一次性工具常留下大块残留",
    },
    Preset {
        id: "vartmp",
        name: "持久临时目录",
        path: "/var/tmp",
        min_privilege: Privilege::UserPartial,
        why: "重启后仍保留的临时空间；最容易堆积「没人记得的一次性工作目录」",
    },
    Preset {
        id: "opt",
        name: "第三方软件安装区",
        path: "/opt",
        min_privilege: Privilege::UserPartial,
        why: "手动解压安装的软件常驻这里；卸载后目录常被遗忘",
    },
    Preset {
        id: "srv",
        name: "服务数据区",
        path: "/srv",
        min_privilege: Privilege::UserPartial,
        why: "服务/编排系统的工作目录；可能是运行目录而非垃圾（参考简报的事故案例）",
    },
    Preset {
        id: "varcache",
        name: "系统缓存",
        path: "/var/cache",
        min_privilege: Privilege::RootLikely,
        why: "包管理器与系统服务的缓存，通常可重建；普通用户读不全",
    },
    Preset {
        id: "varlog",
        name: "系统日志",
        path: "/var/log",
        min_privilege: Privilege::RootLikely,
        why: "日志会持续增长；普通用户读不全，且删除需 root",
    },
    Preset {
        id: "varlibflatpak",
        name: "Flatpak 运行时",
        path: "/var/lib/flatpak",
        min_privilege: Privilege::UserPartial,
        why: "系统级 Flatpak 安装与运行时；卸载发行版后可能遗留",
    },
];

/// 按 id 查找。
pub fn find(id: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.id == id)
}

/// 解析 `--presets` 的取值。
///
/// - `"all"` → 全部预设
/// - 逗号分隔的 id 列表，如 `"tmp,opt"`
///
/// 未知 id 返回错误（**不静默忽略** —— 用户以为扫了却没扫是最坏的体验）。
pub fn parse(spec: &str) -> Result<Vec<&'static Preset>, String> {
    if spec.trim().is_empty() {
        return Ok(Vec::new());
    }
    if spec.eq_ignore_ascii_case("all") {
        return Ok(PRESETS.iter().collect());
    }
    let mut out = Vec::new();
    for raw in spec.split(',') {
        let id = raw.trim();
        if id.is_empty() {
            continue;
        }
        match find(id) {
            Some(p) => {
                if !out.iter().any(|x: &&Preset| x.id == p.id) {
                    out.push(p);
                }
            }
            None => {
                let known: Vec<&str> = PRESETS.iter().map(|p| p.id).collect();
                return Err(format!(
                    "未知预设 `{id}`。可用：{}（或 `all`）",
                    known.join(", ")
                ));
            }
        }
    }
    Ok(out)
}

/// 把预设展开成实际存在的扫描根；不存在的会被跳过并返回说明。
pub fn resolve(presets: &[&'static Preset]) -> (Vec<PathBuf>, Vec<String>) {
    let mut roots = Vec::new();
    let mut skipped = Vec::new();
    for p in presets {
        let path = PathBuf::from(p.path);
        if path.exists() {
            roots.push(path);
        } else {
            skipped.push(format!("{}（{}）：本机不存在", p.name, p.path));
        }
    }
    (roots, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_presets_have_unique_ids_and_absolute_paths() {
        let mut ids: Vec<&str> = PRESETS.iter().map(|p| p.id).collect();
        ids.sort();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "预设 id 必须唯一");
        for p in PRESETS {
            assert!(
                p.path.starts_with('/'),
                "预设路径必须是绝对路径: {}",
                p.path
            );
            assert!(!p.why.is_empty(), "每个预设都要说明为什么: {}", p.id);
        }
    }

    #[test]
    fn parse_all_returns_everything() {
        let v = parse("all").unwrap();
        assert_eq!(v.len(), PRESETS.len());
    }

    #[test]
    fn parse_specific_ids() {
        let v = parse("tmp,opt").unwrap();
        let ids: Vec<&str> = v.iter().map(|p| p.id).collect();
        assert_eq!(ids, vec!["tmp", "opt"]);
    }

    #[test]
    fn parse_dedups() {
        let v = parse("tmp,tmp").unwrap();
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn parse_unknown_is_an_error_not_silent() {
        // 用户以为扫了却没扫，是最坏的体验 —— 必须报错
        let e = parse("tmp,doesnotexist").unwrap_err();
        assert!(e.contains("doesnotexist"));
        assert!(e.contains("tmp"));
    }

    #[test]
    fn parse_empty_is_empty() {
        assert!(parse("").unwrap().is_empty());
        assert!(parse("  ").unwrap().is_empty());
    }

    #[test]
    fn resolve_skips_missing_but_reports() {
        // 用一个必然不存在的路径构造 Preset 无法做到（PRESETS 是常量），
        // 这里只验证「存在的预设会被纳入」这一半行为。
        let (roots, skipped) = resolve(&[&PRESETS[0]]);
        if PathBuf::from(PRESETS[0].path).exists() {
            assert_eq!(roots.len(), 1);
            assert!(skipped.is_empty());
        } else {
            assert!(roots.is_empty());
            assert_eq!(skipped.len(), 1);
        }
    }

    #[test]
    fn privilege_labels_are_nonempty() {
        for pr in [
            Privilege::User,
            Privilege::UserPartial,
            Privilege::RootLikely,
        ] {
            assert!(!pr.label().is_empty());
        }
    }
}
