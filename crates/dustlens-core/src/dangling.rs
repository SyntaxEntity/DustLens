//! 失效引用（P1）：某处配置指向的东西**已经不在了**。
//!
//! # 这条判据为什么值得做
//!
//! 设计共识里把它归为「B 类：失效引用 —— 最容易自动化」。
//! 简报案例 C（2.21 GiB 的 `llauncher`）的判据链就是：
//! 配置里的 `game_dir` 不存在 + 启动器二进制不存在 → 三项都失效 → 孤儿。
//!
//! # 但「失效」不等于「可以删」（P1 红线）
//!
//! 本模块**只输出事实**：`某配置 → 指向的路径不存在`。
//! 它不推断「所以这个应用该删」，也不产出任何操作建议。
//!
//! # 噪音控制（本模块最重要的设计）
//!
//! 上一轮做过「位置异常」，宽判据在真实机器上产出 1345 条噪音，
//! 最终被迫收窄到 0 条 —— 教训是：**判据松一点，信号就被埋掉。**
//! 所以这里用了七道过滤器，宁可漏报也不刷屏：
//!
//! 1. 只看**非注释行**（`#` / `;` 开头的行整行跳过）
//! 2. 只认**绝对路径**或 `~/` / `$HOME/` 开头的 token
//! 3. 跳过通配符、URL、未解析的 `$VAR`、省略号、含空白的 token
//! 4. 目标必须**不存在**
//! 5. **父目录必须存在** —— 这条最关键：它把「某个具体文件/目录不见了」
//!    和「文档里随手写的示例路径」区分开
//! 6. 只判定**家目录之内**的目标（系统路径不在本工具职责内，见文档说明）
//! 7. 总量封顶，避免刷屏

use crate::refs::ReferenceIndex;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// 单次扫描最多报多少条（超出只报计数，防止刷屏）。
pub const MAX_DANGLING: usize = 200;

/// 一条失效引用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DanglingRef {
    /// 指向的目标（**不存在**）
    pub missing: PathBuf,
    /// 哪个配置文件指向它
    pub referrer: PathBuf,
    /// 判定依据
    pub note: String,
}

/// 扫描配置索引，找出失效引用。
///
/// `home` 为 `None` 时返回空 —— 没有家目录就无法做 `~/` 展开与「家目录内」判定。
///
/// `roots` 用于把结果**对齐到本次扫描范围**：只报告目标落在某个扫描根之内的条目。
/// 否则扫描 `/opt` 时会顺带报出 `$HOME` 里的失效引用 —— 用户会困惑
/// 「我明明只扫了 /opt，为什么报告里有家目录的东西」。
pub fn find(index: &ReferenceIndex, home: Option<&Path>, roots: &[PathBuf]) -> Vec<DanglingRef> {
    let Some(home) = home else {
        return Vec::new();
    };
    let roots_abs: Vec<PathBuf> = roots
        .iter()
        .filter_map(|r| r.canonicalize().ok().or_else(|| Some(r.clone())))
        .collect();
    let in_scope = |p: &Path| roots_abs.iter().any(|r| p.starts_with(r));

    let mut out: Vec<DanglingRef> = Vec::new();
    let mut seen: HashSet<(PathBuf, PathBuf)> = HashSet::new();

    for rf in &index.files {
        // **只判定配置文件。**
        // 早期版本把 `.config` 下的一切都算进来，结果 leveldb 的 `LOG` / `MANIFEST-*`
        // 这类运行期日志被当成配置：它们里面是含空格的路径（如 `Local Storage/…`），
        // 分词后变成 `…/Local` —— 一次扫描就产出 116 条假阳性。
        if !is_config_like(&rf.path) {
            continue;
        }

        // ---- 桌面项：单独走 Exec/TryExec 判据 ----
        if rf.path.extension().map(|e| e == "desktop").unwrap_or(false) {
            // 桌面项的判定方向与配置值相反：
            //   · 配置值：**目标**必须落在扫描根内（否则扫 /opt 会报家目录的事）
            //   · 桌面项：**引用者**在扫描根内即可，目标允许在家目录之外
            //     （`Exec=/usr/bin/xxx` 本来就是系统路径；简报案例 C 的
            //      `/usr/bin/llauncher` 不存在正是这一条）
            if !in_scope(&rf.path) {
                continue;
            }
            for d in desktop_dangling(&rf.path, &rf.raw, home) {
                if seen.insert((d.referrer.clone(), d.missing.clone())) {
                    out.push(d);
                }
            }
            continue;
        }

        for line in rf.raw.lines() {
            let t = line.trim_start();
            if t.starts_with('#') || t.starts_with(';') {
                continue;
            }
            for tok in candidate_tokens(line) {
                if let Some(missing) = resolve_missing(&tok, home) {
                    if !in_scope(&missing) {
                        continue;
                    }
                    let key = (rf.path.clone(), missing.clone());
                    if seen.insert(key) {
                        out.push(DanglingRef {
                            missing,
                            referrer: rf.path.clone(),
                            note: "配置中记录的路径已不存在".into(),
                        });
                        if out.len() >= MAX_DANGLING {
                            return out;
                        }
                    }
                }
            }
        }
    }

    out
}

/// 从一行里切出「可能是路径」的 token。
///
/// 分两步，**顺序很重要**：
/// 1. 先取**引号内**的完整内容 —— 这是路径允许含空格的地方
/// 2. 再把剩余部分按分隔符切开 —— 未加引号的值通常不含空格
///
/// 早期实现只做第 2 步（且把空白也算分隔符），于是
/// `~/Library/Application Support/…` 被切成 `~/Library/Application`，
/// 进而被判成「失效引用」。**含空格的路径是这条判据的头号假阳性来源。**
fn candidate_tokens(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = String::new();
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '"' || c == '\'' {
            // 取到配对的引号为止
            let quote = c;
            let mut buf = String::new();
            for inner in chars.by_ref() {
                if inner == quote {
                    break;
                }
                buf.push(inner);
            }
            push_if_path(&mut out, &buf);
            rest.push(' '); // 保持分隔
        } else {
            rest.push(c);
        }
    }

    for tok in rest.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '`' | '=' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | ':'
            )
    }) {
        push_if_path(&mut out, tok);
    }

    out
}

fn push_if_path(out: &mut Vec<String>, t: &str) {
    let t = t.trim();
    if t.starts_with('/') || t.starts_with("~/") || t.starts_with("$HOME/") {
        out.push(t.to_string());
    }
}

/// 这个文件像不像「配置」（而不是运行期日志/数据库/缓存）。
fn is_config_like(path: &Path) -> bool {
    const EXTS: &[&str] = &[
        "json",
        "toml",
        "ini",
        "conf",
        "cfg",
        "yaml",
        "yml",
        "desktop",
        "service",
        "xml",
        "properties",
        "rc",
        "env",
        "jsonc",
        "json5",
    ];
    const NAMES: &[&str] = &[
        ".bashrc",
        ".zshrc",
        ".profile",
        ".bash_profile",
        ".zprofile",
        ".config",
        "config",
        "settings",
    ];
    // 明显的非配置（日志 / leveldb / 数据库）
    const DENY_EXTS: &[&str] = &[
        "log", "ldb", "sst", "db", "sqlite", "sqlite3", "lock", "tmp",
    ];
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let e = ext.to_ascii_lowercase();
        if DENY_EXTS.contains(&e.as_str()) {
            return false;
        }
        if EXTS.contains(&e.as_str()) {
            return true;
        }
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name.starts_with("manifest-") || name == "log" || name == "log.old" || name == "current" {
        return false;
    }
    NAMES.iter().any(|n| name == *n)
}

/// 判定一个 token 是否「指向一个不存在的家目录内目标」。
///
/// 返回 `Some(missing_path)` 表示命中。
fn resolve_missing(tok: &str, home: &Path) -> Option<PathBuf> {
    // ---- 噪声过滤 ----
    if tok.contains("://") {
        return None; // URL
    }
    if tok.contains('*') || tok.contains('?') || tok.contains('…') || tok.contains("...") {
        return None; // 通配符 / 省略号
    }
    if tok.contains('{') || tok.contains('}') || tok.contains('[') || tok.contains(']') {
        return None;
    }
    if tok.contains(' ') {
        return None;
    }
    // 未解析的变量（`$HOME` 已在调用前展开，其余一律跳过）
    if tok.contains('$') && !tok.starts_with("/") {
        return None;
    }
    if tok.matches('$').count() > 0 && !tok.starts_with("/") {
        return None;
    }

    // ---- 展开 ----
    let path: PathBuf = if let Some(rest) = tok.strip_prefix("~/") {
        home.join(rest)
    } else if let Some(rest) = tok.strip_prefix("$HOME/") {
        home.join(rest)
    } else if tok.starts_with('/') {
        PathBuf::from(tok)
    } else {
        return None;
    };

    // ---- 只判定家目录之内（v1 范围，见模块文档）----
    if !path.starts_with(home) {
        return None;
    }
    if path == home {
        return None;
    }
    // 至少两级（`~/x` 之外的要求：`~/a/b` 更像具体条目）
    let depth = path
        .strip_prefix(home)
        .map(|r| r.components().count())
        .unwrap_or(0);
    if depth < 2 {
        return None;
    }

    // ---- 目标必须不存在，但父目录必须存在 ----
    if path.symlink_metadata().is_ok() {
        return None; // 存在 → 不是失效引用
    }
    let parent = path.parent()?;
    if parent.symlink_metadata().is_err() {
        return None; // 父目录也不在 → 多半是示例路径，不是「某个具体东西丢了」
    }

    Some(path)
}

/// 桌面项 / 自启项的 `Exec=` / `TryExec=` 判据。
///
/// 这是简报案例 C 里「`/usr/bin/llauncher` 不存在」那一条的自动化版本：
/// 桌面项声称能启动某个程序，但那个程序不在本机。
fn desktop_dangling(desktop_file: &Path, raw: &str, home: &Path) -> Vec<DanglingRef> {
    let mut out = Vec::new();

    for line in raw.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key != "Exec" && key != "TryExec" {
            continue;
        }

        // 取第一个 token（程序本身），去掉 field codes 与引号
        let Some(prog) = value.split_whitespace().next() else {
            continue;
        };
        let prog = prog.trim_matches('"').trim();
        if prog.is_empty() {
            continue;
        }
        // 带参数占位符（如 `%u`）不影响程序本身，上面已取第一个 token

        let resolved: Option<PathBuf> = if prog.starts_with('/') {
            Some(PathBuf::from(prog))
        } else if let Some(rest) = prog.strip_prefix("~/") {
            Some(home.join(rest))
        } else {
            // 裸命令名：走 PATH 解析；找不到才算失效
            if in_path(prog) {
                None
            } else {
                return vec![DanglingRef {
                    missing: PathBuf::from(prog),
                    referrer: desktop_file.to_path_buf(),
                    note: format!("{key} 指定的程序 `{prog}` 不在 PATH 中"),
                }];
            }
        };

        if let Some(p) = resolved {
            if p.symlink_metadata().is_err() {
                out.push(DanglingRef {
                    missing: p,
                    referrer: desktop_file.to_path_buf(),
                    note: format!("{key} 指定的程序不存在"),
                });
            }
        }
    }

    // 去重（同一桌面项可能 Exec 与 TryExec 都是同一个程序）
    out.sort_by(|a, b| a.missing.cmp(&b.missing));
    out.dedup_by(|a, b| a.missing == b.missing);
    out
}

fn in_path(prog: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    path.split(':')
        .any(|dir| Path::new(dir).join(prog).is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refs::{RefFile, ReferenceIndex};
    use std::collections::HashSet;
    use std::fs;

    struct Case {
        home: PathBuf,
    }

    impl Case {
        fn new(tag: &str) -> Self {
            let home = std::env::temp_dir().join(format!(
                "dl_dangle_{tag}_{}_{:x}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let _ = fs::remove_dir_all(&home);
            fs::create_dir_all(home.join(".config")).unwrap();
            Self { home }
        }
        fn ref_file(&self, name: &str, text: &str) -> RefFile {
            RefFile {
                path: self.home.join(".config").join(name),
                tokens: HashSet::new(),
                raw: text.to_string(),
            }
        }
    }

    impl Drop for Case {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.home);
        }
    }

    fn index(files: Vec<RefFile>) -> ReferenceIndex {
        ReferenceIndex {
            files,
            skipped: vec![],
        }
    }

    #[test]
    fn detects_missing_game_dir_like_brief_case_c() {
        // 复现简报案例 C：配置里的 game_dir 指向一个不存在的目录，但父目录存在
        let c = Case::new("casec");
        fs::create_dir_all(c.home.join("Games")).unwrap();
        let rf = c.ref_file(
            "llauncher/settings.json",
            r#"{ "game_dir": "~/Games/ArknightsEndfield" }"#,
        );
        let found = find(
            &index(vec![rf]),
            Some(&c.home),
            std::slice::from_ref(&c.home),
        );
        assert_eq!(found.len(), 1, "应命中 1 条，实际: {found:?}");
        assert_eq!(found[0].missing, c.home.join("Games/ArknightsEndfield"));
        assert!(found[0].note.contains("不存在"));
    }

    #[test]
    fn ignores_existing_targets() {
        let c = Case::new("exists");
        fs::create_dir_all(c.home.join("Games/Real")).unwrap();
        let rf = c.ref_file("a.json", r#"{"dir": "~/Games/Real"}"#);
        assert!(find(
            &index(vec![rf]),
            Some(&c.home),
            std::slice::from_ref(&c.home)
        )
        .is_empty());
    }

    #[test]
    fn ignores_missing_parent_dir() {
        // 父目录不存在 → 多半是示例路径，不报
        let c = Case::new("noparent");
        let rf = c.ref_file("a.json", r#"{"dir": "~/NoSuchApp/whatever"}"#);
        assert!(find(
            &index(vec![rf]),
            Some(&c.home),
            std::slice::from_ref(&c.home)
        )
        .is_empty());
    }

    #[test]
    fn path_with_spaces_inside_quotes_is_not_split() {
        // 回归：`Local Storage/…` 曾被空白切成 `Local`，产生大批假阳性
        let c = Case::new("spaces");
        fs::create_dir_all(c.home.join("Library/Application Support/App")).unwrap();
        fs::write(
            c.home.join("Library/Application Support/App/real.txt"),
            b"x",
        )
        .unwrap();
        let rf = c.ref_file(
            "a.json",
            r#"{ "dir": "~/Library/Application Support/App/real.txt" }"#,
        );
        assert!(
            find(
                &index(vec![rf]),
                Some(&c.home),
                std::slice::from_ref(&c.home)
            )
            .is_empty(),
            "引号内的含空格路径必须整体识别，且目标存在 → 不应报"
        );
    }

    #[test]
    fn runtime_log_files_are_not_treated_as_config() {
        // 回归：leveldb 的 LOG / MANIFEST-* 里全是含空格路径，曾被当成配置
        let c = Case::new("logs");
        fs::create_dir_all(c.home.join("Games")).unwrap();
        let log = c.ref_file(
            "Local Storage/leveldb/LOG",
            "Reusing: ~/Games/Not There/whatever\n",
        );
        assert!(
            find(
                &index(vec![log]),
                Some(&c.home),
                std::slice::from_ref(&c.home)
            )
            .is_empty(),
            "运行期日志不应参与失效引用判定"
        );
    }

    #[test]
    fn ignores_comment_lines() {
        let c = Case::new("comment");
        fs::create_dir_all(c.home.join("Games")).unwrap();
        let rf = c.ref_file("a.conf", "# example: ~/Games/NotThere\n");
        assert!(find(
            &index(vec![rf]),
            Some(&c.home),
            std::slice::from_ref(&c.home)
        )
        .is_empty());
    }

    #[test]
    fn ignores_urls_wildcards_and_vars() {
        let c = Case::new("noise");
        fs::create_dir_all(c.home.join("Games")).unwrap();
        let rf = c.ref_file(
            "a.conf",
            "url=https://example.com/~Games/x\npat=~/Games/*.bin\nv=$OTHER/~/Games/x\n",
        );
        assert!(find(
            &index(vec![rf]),
            Some(&c.home),
            std::slice::from_ref(&c.home)
        )
        .is_empty());
    }

    #[test]
    fn ignores_system_paths_outside_home() {
        let c = Case::new("syspath");
        let rf = c.ref_file("a.conf", "bin=/usr/lib/definitely-missing-abc/x\n");
        assert!(
            find(
                &index(vec![rf]),
                Some(&c.home),
                std::slice::from_ref(&c.home)
            )
            .is_empty(),
            "家目录之外的目标不在 v1 判定范围内"
        );
    }

    #[test]
    fn ignores_single_component_paths() {
        let c = Case::new("shallow");
        let rf = c.ref_file("a.conf", "p=~/OnlyOne\n");
        assert!(find(
            &index(vec![rf]),
            Some(&c.home),
            std::slice::from_ref(&c.home)
        )
        .is_empty());
    }

    #[test]
    fn desktop_exec_absolute_missing() {
        let c = Case::new("deskexec");
        let rf = c.ref_file(
            "x.desktop",
            "[Desktop Entry]\nExec=/usr/bin/definitely-not-a-real-binary %U\n",
        );
        let found = find(
            &index(vec![rf]),
            Some(&c.home),
            std::slice::from_ref(&c.home),
        );
        assert_eq!(found.len(), 1);
        assert!(found[0].missing.ends_with("definitely-not-a-real-binary"));
        assert!(found[0].note.contains("Exec"));
    }

    #[test]
    fn desktop_exec_bare_name_missing_from_path() {
        let c = Case::new("deskname");
        let rf = c.ref_file(
            "y.desktop",
            "[Desktop Entry]\nExec=zzz-not-a-real-command-xyz\n",
        );
        let found = find(
            &index(vec![rf]),
            Some(&c.home),
            std::slice::from_ref(&c.home),
        );
        assert_eq!(found.len(), 1);
        assert!(found[0].note.contains("PATH"));
    }

    #[test]
    fn desktop_exec_existing_is_ignored() {
        let c = Case::new("deskok");
        let bin = c.home.join("mytool");
        fs::write(&bin, b"#!/bin/sh\n").unwrap();
        let rf = c.ref_file(
            "z.desktop",
            &format!("[Desktop Entry]\nExec={} %U\n", bin.display()),
        );
        assert!(find(
            &index(vec![rf]),
            Some(&c.home),
            std::slice::from_ref(&c.home)
        )
        .is_empty());
    }

    #[test]
    fn no_home_means_no_findings() {
        let c = Case::new("nohome");
        fs::create_dir_all(c.home.join("Games")).unwrap();
        let rf = c.ref_file("a.json", r#"{"d": "~/Games/X"}"#);
        assert!(find(&index(vec![rf]), None, &[]).is_empty());
    }

    #[test]
    fn dedups_same_referrer_and_target() {
        let c = Case::new("dedup");
        fs::create_dir_all(c.home.join("Games")).unwrap();
        let rf = c.ref_file(
            "a.json",
            "{\"a\": \"~/Games/Missing\", \"b\": \"~/Games/Missing\"}",
        );
        let found = find(
            &index(vec![rf]),
            Some(&c.home),
            std::slice::from_ref(&c.home),
        );
        assert_eq!(found.len(), 1, "同一文件同一目标只报一次");
    }

    #[test]
    fn caps_at_max_dangling() {
        let c = Case::new("cap");
        fs::create_dir_all(c.home.join("Games")).unwrap();
        let mut text = String::new();
        for i in 0..(MAX_DANGLING + 20) {
            text.push_str(&format!("p{i}=~/Games/missing{i}\n"));
        }
        let rf = c.ref_file("a.conf", &text);
        let found = find(
            &index(vec![rf]),
            Some(&c.home),
            std::slice::from_ref(&c.home),
        );
        assert!(found.len() <= MAX_DANGLING);
    }
}
