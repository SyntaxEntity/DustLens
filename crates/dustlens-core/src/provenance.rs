//! 归属（P0）：这个路径**是谁装的**。
//!
//! 这是设计共识里「三层价值」的朴素实现：**「谁装的」是可查询的客观事实，不需要猜。**
//! 查不到就如实说「查不到」，**绝不编造**。
//!
//! # 支持的来源
//!
//! | 来源 | 查询方式 | 备注 |
//! |---|---|---|
//! | rpm | `rpm -qf --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'` | Fedora / RHEL / openSUSE |
//! | dpkg | `dpkg -S` | Debian / Ubuntu |
//! | pacman | `pacman -Qo` | Arch |
//! | flatpak | **纯路径推导**（不走命令） | `~/.local/share/flatpak/app/<id>/…` |
//!
//! # 两个刻意的设计
//!
//! 1. **命令全都带 `LC_ALL=C`** —— 本机实测 rpm 的中文输出是
//!    `文件 /x 不属于任何软件包`。按英文解析会在中文环境下静默失效。
//! 2. **「不属于任何包」是一个结论，不是失败** —— 它意味着用户手动安装或应用自建，
//!    这跟「没查到」是两件事，报告里必须区分。

use crate::types::Evidence;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// 本机有哪些可用的包管理器。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Managers {
    pub rpm: bool,
    pub dpkg: bool,
    pub pacman: bool,
}

impl Managers {
    /// 通过 `PATH` 探测（不执行命令，只找可执行文件）。
    pub fn detect() -> Self {
        Self {
            rpm: which("rpm"),
            dpkg: which("dpkg"),
            pacman: which("pacman"),
        }
    }

    /// 一个都没有时，归属探测应整体跳过（而不是逐个报「查不到」）。
    pub fn any(&self) -> bool {
        self.rpm || self.dpkg || self.pacman
    }

    pub fn labels(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.rpm {
            v.push("rpm");
        }
        if self.dpkg {
            v.push("dpkg");
        }
        if self.pacman {
            v.push("pacman");
        }
        v
    }
}

/// 归属探测器（带缓存）。
///
/// 每条 finding 都要问一次，而 findings 可能几十条 —— 缓存按路径去重，
/// 避免对同一路径反复 fork `rpm`。
pub struct Prober {
    managers: Managers,
    home: Option<PathBuf>,
    cache: HashMap<PathBuf, Option<Evidence>>,
    /// 实际执行过的外部命令次数（供报告说明开销）
    calls: usize,
    /// 探测失败次数（命令不存在 / 执行错误）
    failures: usize,
}

impl Prober {
    pub fn new(home: Option<&Path>) -> Self {
        Self {
            managers: Managers::detect(),
            home: home.map(|h| h.to_path_buf()),
            cache: HashMap::new(),
            calls: 0,
            failures: 0,
        }
    }

    pub fn managers(&self) -> Managers {
        self.managers
    }

    pub fn calls(&self) -> usize {
        self.calls
    }

    pub fn failures(&self) -> usize {
        self.failures
    }

    /// 查询一个路径的归属。
    ///
    /// 返回 `None` 表示**本机没有可用的包管理器**（无法判断），
    /// 而不是「不属于任何包」—— 后者会返回 `Some(Provenance { package: None, .. })`。
    pub fn probe(&mut self, path: &Path) -> Option<Evidence> {
        if let Some(hit) = self.cache.get(path) {
            return hit.clone();
        }
        let result = self.probe_uncached(path);
        self.cache.insert(path.to_path_buf(), result.clone());
        result
    }

    fn probe_uncached(&mut self, path: &Path) -> Option<Evidence> {
        // flatpak 先走路径推导：它没有「文件属于哪个包」的通用查询，
        // 但安装布局是固定的，路径前缀就能定性，且零进程开销。
        if let Some(id) = flatpak_app_id(path, self.home.as_deref()) {
            return Some(Evidence::Provenance {
                manager: "flatpak".into(),
                package: Some(id),
                version: None,
            });
        }

        if !self.managers.any() {
            return None;
        }

        let path_str = path.to_string_lossy();

        if self.managers.rpm {
            self.calls += 1;
            match run(
                "rpm",
                &["-qf", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n", &path_str],
            ) {
                Some(out) => {
                    let (pkg, ver) = parse_rpm(&out);
                    return Some(Evidence::Provenance {
                        manager: "rpm".into(),
                        package: pkg,
                        version: ver,
                    });
                }
                None => self.failures += 1,
            }
        }

        if self.managers.dpkg {
            self.calls += 1;
            match run("dpkg", &["-S", &path_str]) {
                Some(out) => {
                    let pkg = parse_dpkg(&out);
                    return Some(Evidence::Provenance {
                        manager: "dpkg".into(),
                        package: pkg,
                        version: None,
                    });
                }
                None => self.failures += 1,
            }
        }

        if self.managers.pacman {
            self.calls += 1;
            match run("pacman", &["-Qo", &path_str]) {
                Some(out) => {
                    let (pkg, ver) = parse_pacman(&out);
                    return Some(Evidence::Provenance {
                        manager: "pacman".into(),
                        package: pkg,
                        version: ver,
                    });
                }
                None => self.failures += 1,
            }
        }

        None
    }
}

/// 执行命令，返回 stdout+stderr（不因非零退出码而失败 —— 各包管理器语义不同）。
fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd)
        .args(args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .output()
        .ok()?;
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push('\n');
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Some(s)
}

/// 解析 `rpm -qf --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'` 的输出。
///
/// 返回 `(package, version)`；`package == None` 表示「不属于任何包」。
pub fn parse_rpm(out: &str) -> (Option<String>, Option<String>) {
    // 未归属（LC_ALL=C）：`error: file /x is not owned by any package`
    if out.contains("is not owned by any package") {
        return (None, None);
    }
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("error:") {
            continue;
        }
        // 形如 `bash\t5.3.9-3.fc44` 或（无 --qf 时）`bash-5.3.9-3.fc44.x86_64`
        if let Some((name, ver)) = line.split_once('\t') {
            let name = name.trim();
            let ver = ver.trim();
            if !name.is_empty() {
                return (
                    Some(name.to_string()),
                    if ver.is_empty() {
                        None
                    } else {
                        Some(ver.to_string())
                    },
                );
            }
        }
    }
    (None, None)
}

/// 解析 `dpkg -S`：`pkg: /path` → `Some("pkg")`。
pub fn parse_dpkg(out: &str) -> Option<String> {
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("dpkg-query:") || line.starts_with("error:") {
            continue;
        }
        if let Some((pkg, _path)) = line.split_once(':') {
            let pkg = pkg.trim();
            // `dpkg -S` 对多包会输出 `pkg1, pkg2: /path`
            if !pkg.is_empty() {
                return Some(pkg.to_string());
            }
        }
    }
    None
}

/// 解析 `pacman -Qo`：`/path is owned by pkg 1.2.3` → `(pkg, version)`。
pub fn parse_pacman(out: &str) -> (Option<String>, Option<String>) {
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("error:") {
            continue;
        }
        if let Some(rest) = line.split_once(" is owned by ").map(|(_, r)| r) {
            let mut it = rest.split_whitespace();
            let pkg = it.next().unwrap_or("").to_string();
            let ver = it.next().map(|s| s.to_string());
            if !pkg.is_empty() {
                return (Some(pkg), ver);
            }
        }
    }
    (None, None)
}

/// 从 flatpak 的固定安装布局里推导应用 id（零进程开销）。
///
/// 支持：
/// - `~/.local/share/flatpak/app/<id>/…`（用户级）
/// - `~/.local/share/flatpak/runtime/<id>/…`
/// - `/var/lib/flatpak/app/<id>/…`（系统级）
pub fn flatpak_app_id(path: &Path, home: Option<&Path>) -> Option<String> {
    // 注意：`components()` 会包含 `RootDir`（映射成 "/"）。
    // 前缀是相对根写的，所以两边都必须先剥掉根组件，否则系统级
    // `/var/lib/flatpak/...` 永远匹配不上。
    let comps = normal_components(path);

    let mut prefixes: Vec<Vec<String>> = vec![vec!["var".into(), "lib".into(), "flatpak".into()]];
    if let Some(h) = home {
        let mut p = normal_components(h);
        p.extend([".local".into(), "share".into(), "flatpak".into()]);
        prefixes.push(p);
    }

    for prefix in prefixes {
        if comps.len() <= prefix.len() + 1 {
            continue;
        }
        let matches_prefix = comps.iter().zip(prefix.iter()).all(|(a, b)| a == b);
        if !matches_prefix {
            continue;
        }
        // prefix 之后是 `app` / `runtime`，再之后才是 id
        let kind = comps[prefix.len()].as_str();
        if kind != "app" && kind != "runtime" {
            continue;
        }
        let id = &comps[prefix.len() + 1];
        if id.is_empty() {
            continue;
        }
        return Some(id.clone());
    }
    None
}

/// 取路径的普通组件（剥掉根、`.`、`..` 等非名字组件）。
fn normal_components(p: &Path) -> Vec<String> {
    p.components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

/// 在 `PATH` 中查找可执行文件（不执行它）。
fn which(tool: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    path.split(':').any(|dir| {
        let p = Path::new(dir).join(tool);
        p.is_file()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rpm_owned_with_qf() {
        let (pkg, ver) = parse_rpm("bash\t5.3.9-3.fc44\n");
        assert_eq!(pkg.as_deref(), Some("bash"));
        assert_eq!(ver.as_deref(), Some("5.3.9-3.fc44"));
    }

    #[test]
    fn parses_rpm_not_owned_english() {
        let (pkg, ver) =
            parse_rpm("error: file /home/someone/.bashrc is not owned by any package\n");
        assert_eq!(pkg, None);
        assert_eq!(ver, None);
    }

    #[test]
    fn parses_dpkg_output() {
        assert_eq!(parse_dpkg("bash: /usr/bin/bash\n").as_deref(), Some("bash"));
        assert_eq!(
            parse_dpkg("pkg1, pkg2: /usr/bin/x\n").as_deref(),
            Some("pkg1, pkg2")
        );
        assert_eq!(
            parse_dpkg("dpkg-query: no path found matching pattern /x\n"),
            None
        );
    }

    #[test]
    fn parses_pacman_output() {
        let (pkg, ver) = parse_pacman("/usr/bin/bash is owned by bash 5.2.021-1\n");
        assert_eq!(pkg.as_deref(), Some("bash"));
        assert_eq!(ver.as_deref(), Some("5.2.021-1"));
        assert_eq!(parse_pacman("error: No package owns /x\n").0, None);
    }

    #[test]
    fn flatpak_ids_from_layout() {
        let home = Path::new("/h/u");
        assert_eq!(
            flatpak_app_id(
                Path::new("/h/u/.local/share/flatpak/app/com.spotify.Client/x/y"),
                Some(home)
            )
            .as_deref(),
            Some("com.spotify.Client")
        );
        assert_eq!(
            flatpak_app_id(
                Path::new("/var/lib/flatpak/runtime/org.gnome.Platform/x/y"),
                Some(home)
            )
            .as_deref(),
            Some("org.gnome.Platform")
        );
        // 不是 flatpak 布局
        assert_eq!(
            flatpak_app_id(Path::new("/h/u/Projects/x"), Some(home)),
            None
        );
        // 布局太浅
        assert_eq!(
            flatpak_app_id(Path::new("/var/lib/flatpak/app"), Some(home)),
            None
        );
        // 未知子类
        assert_eq!(
            flatpak_app_id(Path::new("/var/lib/flatpak/other/x/y"), Some(home)),
            None
        );
    }

    #[test]
    fn prober_returns_none_when_no_manager() {
        // 构造一个「没有任何包管理器」的探测器，验证它会明确返回 None（无法判断）
        let mut p = Prober {
            managers: Managers {
                rpm: false,
                dpkg: false,
                pacman: false,
            },
            home: None,
            cache: HashMap::new(),
            calls: 0,
            failures: 0,
        };
        assert_eq!(p.probe(Path::new("/tmp/definitely-not-flatpak")), None);
        assert_eq!(p.calls, 0, "没有包管理器时不应执行任何命令");
    }

    #[test]
    fn cache_avoids_repeat_calls() {
        let mut p = Prober {
            managers: Managers {
                rpm: false,
                dpkg: false,
                pacman: false,
            },
            home: None,
            cache: HashMap::new(),
            calls: 0,
            failures: 0,
        };
        let path = Path::new("/tmp/x-cache-test");
        let _ = p.probe(path);
        let _ = p.probe(path);
        assert_eq!(p.calls, 0);
        assert_eq!(p.cache.len(), 1, "同一路径只探测一次");
    }

    #[test]
    fn managers_detect_is_stable_shape() {
        // 只验证结构可用，不断言本机具体装了哪些（那会让测试依赖环境）
        let m = Managers::detect();
        let labels = m.labels();
        assert_eq!(
            labels.len(),
            [m.rpm, m.dpkg, m.pacman].iter().filter(|b| **b).count()
        );
    }
}
