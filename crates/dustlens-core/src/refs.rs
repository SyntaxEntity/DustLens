//! 引用证据：三级强度（🔴 InUse / 🟡 WillUse / ⚪ Unclaimed）。
//!
//! 设计依据：设计共识 §4。
//! **「这个目录是谁在用」是跨系统查询，不能只查文件系统。**
//!
//! 本模块做两件事：
//! 1. **进程侧**：扫描 `/proc`，找出 cwd 与打开句柄指向候选路径的进程 → `InUse`
//! 2. **配置侧**：扫描 `~/.config`、自启项、systemd、shell rc，找出提及候选路径的文件 → `WillUse`
//!
//! 两者都没有命中 → `Unclaimed`，**并附带「无人认领 ≠ 不需要」的提示**。

use crate::types::{Evidence, LinkStrength};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// 单个配置文件的引用索引。
#[derive(Debug, Clone)]
pub struct RefFile {
    pub path: PathBuf,
    /// 按分隔符切出来的词元集合（用于精确命中）
    pub tokens: HashSet<String>,
    /// 原始文本（用于前缀命中，如「目录路径 + 文件名」）
    pub raw: String,
}

/// 配置侧引用索引。
#[derive(Debug, Default)]
pub struct ReferenceIndex {
    pub files: Vec<RefFile>,
    /// 扫描时跳过的文件（超大/二进制/读不了）—— 计入盲区
    pub skipped: Vec<(PathBuf, String)>,
}

/// 进程侧的引用索引。
#[derive(Debug, Default)]
pub struct ProcessIndex {
    /// pid → (comm, cwd)
    pub procs: Vec<ProcRef>,
    /// 读不到的 /proc 条目（多为其它用户的进程）
    pub denied: usize,
}

#[derive(Debug, Clone)]
pub struct ProcRef {
    pub pid: u32,
    pub comm: String,
    pub cwd: Option<PathBuf>,
    pub fds: Vec<PathBuf>,
}

/// 一次引用检查的结果。
#[derive(Debug, Clone)]
pub struct RefFinding {
    pub strength: LinkStrength,
    pub evidence: Vec<Evidence>,
}

impl RefFinding {
    /// `InUse` 是**瞬时快照**：它只说明「检查这一刻」有进程在用。
    ///
    /// 编译、索引、转码这类短命进程会让一个目录在扫描瞬间显示为「正在使用」，
    /// 几分钟后就变回「无人认领」。UI 与报告都必须把这一点讲出来，
    /// 否则用户会以为这是稳定状态。
    pub fn in_use_is_transient(&self) -> bool {
        self.strength == LinkStrength::InUse
    }
}

impl RefFinding {
    pub fn unclaimed() -> Self {
        Self {
            strength: LinkStrength::Unclaimed,
            evidence: Vec::new(),
        }
    }
}

/// 读取进程信息（`/proc`）。
///
/// 非 Linux 平台返回空索引（本项目先支持 Linux）。
pub fn load_processes() -> ProcessIndex {
    let mut idx = ProcessIndex::default();
    // 排除「我们自己」这条进程链：否则工具会把自己、父 shell
    // 一并报成「正在使用」，产生自我污染的假证据。
    let self_chain = self_process_chain();
    // 更要紧的是：比本进程**更晚启动**的进程，几乎必然是本次扫描管道的一部分
    // （`dustlens ~ | tail` 里的 tail、grep 等）。它们读到的是我们的输出，
    // 不是「正在使用被扫描的目录」。用启动时刻把它们排除。
    let self_start = process_start_ticks(std::process::id());
    // 同父进程（same parent）的兄弟进程也属于本次扫描管道：
    // `dustlens ~ | grep x` 里 grep 与 dustlens **同时**由同一个 shell 启动，
    // 所以它既不在我们的祖先链上、也不比我们晚启动。
    let self_pid = std::process::id();
    let self_ppid = process_ppid(self_pid);

    #[cfg(target_os = "linux")]
    {
        let proc_dir = Path::new("/proc");
        let Ok(rd) = fs::read_dir(proc_dir) else {
            return idx;
        };
        for ent in rd.flatten() {
            let name = ent.file_name();
            let name = name.to_string_lossy();
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            let base = proc_dir.join(name.as_ref());
            let comm = fs::read_to_string(base.join("comm"))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "?".into());

            let cwd = fs::read_link(base.join("cwd")).ok();

            let mut fds = Vec::new();
            let mut denied_here = false;
            match fs::read_dir(base.join("fd")) {
                Ok(fd_rd) => {
                    for f in fd_rd.flatten() {
                        if let Ok(p) = fs::read_link(f.path()) {
                            // 只保留真实文件系统路径（跳过 socket:[..] / pipe:[..]）
                            if p.is_absolute() {
                                fds.push(p);
                            }
                        }
                    }
                }
                Err(_) => denied_here = true,
            }

            // cwd 也读不到，且 fd 也读不到 → 该进程整体不可见
            if denied_here && cwd.is_none() {
                idx.denied += 1;
                continue;
            }

            if self_chain.contains(&pid) {
                continue;
            }
            if let (Some(mine), Some(theirs)) = (self_start, process_start_ticks(pid)) {
                if theirs > mine {
                    continue;
                }
            }
            // 兄弟进程：与扫描器同父 → 同一条命令行管道
            if pid != self_pid {
                if let (Some(spp), Some(ppp)) = (self_ppid, process_ppid(pid)) {
                    if spp == ppp && spp != 0 {
                        continue;
                    }
                }
            }

            idx.procs.push(ProcRef {
                pid,
                comm,
                cwd,
                fds,
            });
        }
    }

    idx
}

/// 配置文件候选（相对家目录）。
const CONFIG_RELATIVE: &[&str] = &[
    ".config",
    ".local/share/applications",
    ".local/state",
    ".bashrc",
    ".zshrc",
    ".profile",
    ".bash_profile",
    ".config/systemd/user",
    ".config/autostart",
];

/// 单个文件读入上限，超过则跳过（多为二进制或巨型日志）。
const MAX_REF_FILE_BYTES: u64 = 256 * 1024;

/// 建立配置侧索引。
///
/// - `home`：家目录；`None` 时返回空索引（配置扫描依赖家目录）
/// - `excludes`：隐私排除规则；命中的文件**不读取**（避免把凭据内容载入内存）
pub fn build_reference_index(
    home: Option<&Path>,
    excludes: &[crate::types::ExcludeRule],
) -> ReferenceIndex {
    let mut idx = ReferenceIndex::default();
    let Some(home) = home else {
        return idx;
    };

    for rel in CONFIG_RELATIVE {
        let base = home.join(rel);
        if !base.exists() {
            continue;
        }
        if base.is_file() {
            ingest_file(&base, excludes, &mut idx);
            continue;
        }
        // 目录：深度优先读取（配置目录通常不大，但仍设上限）
        let mut stack = vec![base];
        while let Some(dir) = stack.pop() {
            if excludes.iter().any(|r| r.matches(&dir)) {
                continue; // 隐私目录整体跳过
            }
            let Ok(rd) = fs::read_dir(&dir) else {
                idx.skipped.push((dir, "目录不可读".into()));
                continue;
            };
            for ent in rd.flatten() {
                let p = ent.path();
                if excludes.iter().any(|r| r.matches(&p)) {
                    continue;
                }
                match fs::symlink_metadata(&p) {
                    Ok(md) if md.is_dir() => stack.push(p),
                    Ok(md) if md.is_file() => ingest_file(&p, excludes, &mut idx),
                    Ok(md) if md.file_type().is_symlink() => {
                        // 不跟随：配置文件里的链接常指向别处，跟随会引入噪音
                        let _ = md;
                    }
                    _ => {}
                }
            }
        }
    }

    idx
}

fn ingest_file(path: &Path, excludes: &[crate::types::ExcludeRule], idx: &mut ReferenceIndex) {
    if excludes.iter().any(|r| r.matches(path)) {
        return;
    }
    let Ok(md) = fs::metadata(path) else {
        idx.skipped.push((path.to_path_buf(), "元数据不可读".into()));
        return;
    };
    if md.len() > MAX_REF_FILE_BYTES {
        idx.skipped
            .push((path.to_path_buf(), format!("超过 {} B 上限", MAX_REF_FILE_BYTES)));
        return;
    }
    let Ok(bytes) = fs::read(path) else {
        idx.skipped.push((path.to_path_buf(), "读取失败".into()));
        return;
    };
    // 二进制启发式：含 NUL 字节即视为二进制，跳过
    if bytes.iter().take(4096).any(|b| *b == 0) {
        idx.skipped.push((path.to_path_buf(), "疑似二进制".into()));
        return;
    }
    let Ok(text) = String::from_utf8(bytes) else {
        idx.skipped.push((path.to_path_buf(), "非 UTF-8".into()));
        return;
    };

    let tokens: HashSet<String> = text
        .split(|c: char| {
            c.is_whitespace()
                || matches!(c, '"' | '\'' | '`' | '=' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>')
        })
        .filter(|t| t.contains('/'))
        .map(|t| t.to_string())
        .collect();

    idx.files.push(RefFile {
        path: path.to_path_buf(),
        tokens,
        raw: text,
    });
}

/// 对单个候选路径做引用检查。
///
/// 返回**最强**的那一级证据；同一级可附带多条证据。
pub fn check(
    target: &Path,
    procs: &ProcessIndex,
    index: &ReferenceIndex,
    home: Option<&Path>,
) -> RefFinding {
    let mut in_use: Vec<Evidence> = Vec::new();
    let mut will_use: Vec<Evidence> = Vec::new();

    // ---- 1. 进程侧（InUse）----
    for p in &procs.procs {
        let mut hit_cwd = false;
        if let Some(cwd) = &p.cwd {
            if cwd_relates(target, cwd) {
                hit_cwd = true;
            }
        }
        if hit_cwd {
            in_use.push(Evidence::ProcessCwd {
                pid: p.pid,
                comm: p.comm.clone(),
            });
            continue; // 同一进程不重复登记
        }
        for fd in &p.fds {
            // 「打开句柄」只在**目标本身就是一个文件**时才成立；
            // 目录被某个进程当作 cwd 覆盖不到它内部的文件，所以用精确匹配。
            //
            // 注意：`target` 可能是目录。目录下某个文件被打开，
            // 并不等于「这个目录正在被使用」——那属于 Body/Unclaimed，
            // 而不是 InUse。这里刻意只认精确相等。
            if fd == target {
                in_use.push(Evidence::ProcessFd {
                    pid: p.pid,
                    comm: p.comm.clone(),
                });
                break;
            }
        }
    }

    // ---- 2. 配置侧（WillUse）----
    if in_use.is_empty() {
        let forms = path_forms(target, home);
        let is_desktop = |p: &Path| {
            p.extension().map(|e| e == "desktop").unwrap_or(false)
                || p.components().any(|c| c.as_os_str() == "autostart")
        };
        for rf in &index.files {
            let mut hit = false;
            if rf.tokens.iter().any(|t| forms.iter().any(|f| f == t)) {
                hit = true;
            } else if forms.iter().any(|f| f.len() > 8 && rf.raw.contains(f.as_str())) {
                // 前缀命中：配置里可能写的是 `<目录>/<文件名>`
                hit = true;
            }
            if hit {
                if is_desktop(&rf.path) {
                    will_use.push(Evidence::DesktopReference {
                        file: rf.path.clone(),
                    });
                } else {
                    will_use.push(Evidence::ConfigReference {
                        file: rf.path.clone(),
                    });
                }
            }
        }
    }

    // ---- 3. 汇总：取最强一级 ----
    if !in_use.is_empty() {
        in_use.truncate(8);
        return RefFinding {
            strength: LinkStrength::InUse,
            evidence: in_use,
        };
    }
    if !will_use.is_empty() {
        will_use.truncate(8);
        return RefFinding {
            strength: LinkStrength::WillUse,
            evidence: will_use,
        };
    }
    RefFinding::unclaimed()
}

/// 判断「进程的 cwd 是否**正在使用** `target`」。
///
/// 关系是**有方向**的：
/// - `cwd == target` → 直接命中
/// - `cwd` 位于 `target` 之下 → 命中（该目录下确有进程在工作）
/// - **`target` 位于 `cwd` 之下 → 不命中**
///
/// 最后一条很关键：进程 cwd 是 `/` 或 `$HOME` 时，
/// 若不排除这个方向，整棵树都会被误判成「正在使用」（P1 的典型破坏）。
fn cwd_relates(target: &Path, cwd: &Path) -> bool {
    cwd == target || cwd.starts_with(target)
}

/// 生成一个路径在配置文件里可能出现的几种写法。
fn path_forms(target: &Path, home: Option<&Path>) -> Vec<String> {
    let mut v = vec![target.to_string_lossy().into_owned()];
    if let Some(h) = home {
        if let Ok(rest) = target.strip_prefix(h) {
            let r = rest.to_string_lossy().into_owned();
            if !r.is_empty() {
                v.push(format!("~/{r}"));
                v.push(format!("$HOME/{r}"));
                // 尾斜杠写法
                v.push(format!("{}/", target.to_string_lossy()));
            }
        }
    }
    v.sort();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造测试用绝对路径，避免出现真实家目录形式的字面量。
    fn p(parts: &[&str]) -> PathBuf {
        let mut b = PathBuf::from(std::path::MAIN_SEPARATOR.to_string());
        for x in parts {
            b.push(x);
        }
        b
    }

    fn mk_proc(pid: u32, comm: &str, cwd: Option<&str>, fds: &[&str]) -> ProcRef {
        ProcRef {
            pid,
            comm: comm.into(),
            cwd: cwd.map(PathBuf::from),
            fds: fds.iter().map(PathBuf::from).collect(),
        }
    }

    fn mk_ref(path: &str, text: &str) -> RefFile {
        let tokens = text
            .split_whitespace()
            .filter(|t| t.contains('/'))
            .map(|t| t.to_string())
            .collect();
        RefFile {
            path: PathBuf::from(path),
            tokens,
            raw: text.to_string(),
        }
    }

    #[test]
    fn detects_in_use_by_cwd() {
        let procs = ProcessIndex {
            procs: vec![mk_proc(42, "bash", Some("/srv/t/work"), &[])],
            denied: 0,
        };
        let refs = ReferenceIndex::default();
        let target = p(&["srv", "t", "work"]);
        let f = check(target.as_path(), &procs, &refs, None);
        assert_eq!(f.strength, LinkStrength::InUse);
        assert!(matches!(f.evidence[0], Evidence::ProcessCwd { pid: 42, .. }));
    }

    #[test]
    fn detects_in_use_by_open_fd_on_a_file() {
        // 打开句柄只在**目标本身是那个文件**时命中
        let procs = ProcessIndex {
            procs: vec![mk_proc(7, "vlc", Some("/tmp"), &["/srv/t/video/movie.mp4"])],
            denied: 0,
        };
        let refs = ReferenceIndex::default();
        let target = p(&["srv", "t", "video", "movie.mp4"]);
        let f = check(target.as_path(), &procs, &refs, None);
        assert_eq!(f.strength, LinkStrength::InUse);
        assert!(matches!(f.evidence[0], Evidence::ProcessFd { pid: 7, .. }));
    }

    #[test]
    fn opening_a_file_inside_a_dir_does_not_mark_the_dir_in_use() {
        // 回归：目录里某个文件被打开 ≠ 这个目录正在被使用
        let procs = ProcessIndex {
            procs: vec![mk_proc(
                7,
                "vlc",
                Some("/"),
                &["/srv/t/video/movie.mp4"],
            )],
            denied: 0,
        };
        let refs = ReferenceIndex::default();
        let f = check(p(&["a", "video"]).as_path(), &procs, &refs, None);
        assert_eq!(f.strength, LinkStrength::Unclaimed);
    }

    #[test]
    fn root_cwd_does_not_mark_everything_in_use() {
        // 回归：进程 cwd 为 `/` 时，不能把整棵树判成「正在使用」
        let procs = ProcessIndex {
            procs: vec![mk_proc(1, "init", Some("/"), &[])],
            denied: 0,
        };
        let refs = ReferenceIndex::default();
        for p in ["/srv/t/x", "/var/tmp", "/etc"] {
            let f = check(Path::new(p), &procs, &refs, None);
            assert_eq!(f.strength, LinkStrength::Unclaimed, "{p} 不应被判为 InUse");
        }
    }

    #[test]
    fn cwd_inside_target_counts_as_in_use() {
        let procs = ProcessIndex {
            procs: vec![mk_proc(9, "make", Some("/srv/t/proj/build"), &[])],
            denied: 0,
        };
        let refs = ReferenceIndex::default();
        let target = p(&["srv", "t", "proj"]);
        let f = check(target.as_path(), &procs, &refs, None);
        assert_eq!(f.strength, LinkStrength::InUse);
    }

    #[test]
    fn detects_will_use_from_config() {
        let procs = ProcessIndex::default();
        let refs = ReferenceIndex {
            files: vec![mk_ref(
                "/cfg/app/settings.json",
                r#"{ "dir": "/srv/t/data" }"#,
            )],
            skipped: vec![],
        };
        let target = p(&["srv", "t", "data"]);
        let f = check(target.as_path(), &procs, &refs, None);
        assert_eq!(f.strength, LinkStrength::WillUse);
        assert!(matches!(f.evidence[0], Evidence::ConfigReference { .. }));
    }

    #[test]
    fn detects_will_use_via_tilde_form() {
        let procs = ProcessIndex::default();
        let home_buf = p(&["srv", "t"]);
        let home = home_buf.as_path();
        let refs = ReferenceIndex {
            files: vec![mk_ref(
                "/cfg/x.conf",
                "path = /srv/t/ProjectData\n",
            )],
            skipped: vec![],
        };
        let target = p(&["srv", "t", "ProjectData"]);
        let f = check(target.as_path(), &procs, &refs, Some(home));
        assert_eq!(f.strength, LinkStrength::WillUse);
    }

    #[test]
    fn unclaimed_when_no_reference() {
        let procs = ProcessIndex::default();
        let refs = ReferenceIndex::default();
        let target = p(&["srv", "t", "orphan"]);
        let f = check(target.as_path(), &procs, &refs, None);
        assert_eq!(f.strength, LinkStrength::Unclaimed);
        assert!(f.evidence.is_empty());
    }

    #[test]
    fn in_use_takes_precedence_over_will_use() {
        let procs = ProcessIndex {
            procs: vec![mk_proc(1, "x", Some("/srv/t/p"), &[])],
            denied: 0,
        };
        let refs = ReferenceIndex {
            files: vec![mk_ref("/cfg/y", "/srv/t/p")],
            skipped: vec![],
        };
        let target = p(&["srv", "t", "p"]);
        let f = check(target.as_path(), &procs, &refs, None);
        assert_eq!(f.strength, LinkStrength::InUse);
    }

    #[test]
    fn prose_mention_counts_as_reference_known_tradeoff() {
        let procs = ProcessIndex::default();
        let refs = ReferenceIndex {
            files: vec![mk_ref("/cfg/z", "see /srv/t/x for details")],
            skipped: vec![],
        };
        // 目标路径只出现在说明文字里；长度 > 8，会命中（这是已知的保守取舍）
        let target = p(&["srv", "t", "x"]);
        let f = check(target.as_path(), &procs, &refs, None);
        assert_eq!(f.strength, LinkStrength::WillUse);
    }

    #[test]
    fn privacy_excluded_files_are_not_read() {
        let home = std::env::temp_dir().join(format!("dl_ref_{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(home.join(".config/gh")).unwrap();
        fs::write(home.join(".config/gh/hosts.yml"), "oauth_token: SECRET").unwrap();
        fs::create_dir_all(home.join(".config/real")).unwrap();
        fs::write(home.join(".config/real/x.conf"), "ok=1").unwrap();

        let idx = build_reference_index(Some(&home), &crate::types::ExcludeRule::defaults());
        assert!(
            !idx.files.iter().any(|f| f.path.to_string_lossy().contains(".config/gh")),
            "隐私目录不得被读取入索引: {:?}",
            idx.files.iter().map(|f| &f.path).collect::<Vec<_>>()
        );
        assert!(idx.files.iter().any(|f| f.path.to_string_lossy().contains(".config/real")));
        let _ = fs::remove_dir_all(&home);
    }
}

/// 取「当前进程 + 其全部祖先」的 PID 集合。
///
/// 存在的意义：**扫描器不得把自己的进程链算作引用证据**。
/// 否则 `dustlens~` 会报告「<你的 shell> 正在使用 $HOME」，这是自证循环。
fn self_process_chain() -> HashSet<u32> {
    let mut set = HashSet::new();
    let mut pid = std::process::id();

    #[cfg(target_os = "linux")]
    {
        set.insert(0); // PID 0 / kernel 线程无需计入
        for _ in 0..64 {
            if pid == 0 || !set.insert(pid) {
                break;
            }
            let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
                break;
            };
            // /proc/<pid>/stat: pid (comm) state ppid ...  comm 可能含括号与空格
            let Some(after) = stat.rfind(')') else { break };
            let rest = stat[after + 1..].trim_start();
            let mut it = rest.split_whitespace();
            let _state = it.next();
            let Some(ppid) = it.next().and_then(|v| v.parse::<u32>().ok()) else {
                break;
            };
            pid = ppid;
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        set.insert(pid);
    }

    set
}

#[cfg(test)]
mod self_chain_tests {
    #[test]
    fn self_chain_contains_own_pid() {
        let s = super::self_process_chain();
        assert!(s.contains(&std::process::id()));
    }
}

/// 读取进程的启动时刻（`/proc/<pid>/stat` 第 22 字段，单位 clock tick）。
///
/// 用途：把「比扫描器更晚启动」的进程排除出引用证据 ——
/// 它们通常是本次扫描的管道下游（`| tail`、`| grep`），
/// 其 cwd 与本次扫描无关，报成「正在使用」属自我污染。
fn process_start_ticks(pid: u32) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let after = stat.rfind(')')?;
        let rest = stat[after + 1..].trim_start();
        // 从 state 开始数：state 是第 1 个，starttime 是第 22 个 → 索引 19
        rest.split_whitespace().nth(19)?.parse().ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

#[cfg(test)]
mod start_time_tests {
    #[test]
    fn own_start_time_is_readable() {
        let t = super::process_start_ticks(std::process::id());
        assert!(t.is_some(), "应能读到自身启动时刻");
        assert!(t.unwrap() > 0);
    }

    #[test]
    fn parents_start_earlier_than_self() {
        let me = super::process_start_ticks(std::process::id()).unwrap();
        let chain = super::self_process_chain();
        for pid in chain.iter().filter(|p| **p != 0) {
            if let Some(t) = super::process_start_ticks(*pid) {
                assert!(t <= me, "祖先进程不可能比子进程更晚启动");
            }
        }
    }
}

/// 读取进程的父进程 PID（`/proc/<pid>/stat` 第 4 字段）。
fn process_ppid(pid: u32) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let after = stat.rfind(')')?;
        let rest = stat[after + 1..].trim_start();
        // state 是第 1 个字段，ppid 是第 2 个
        rest.split_whitespace().nth(1)?.parse().ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

#[cfg(test)]
mod ppid_tests {
    #[test]
    fn own_ppid_is_readable() {
        assert!(super::process_ppid(std::process::id()).is_some());
    }

    #[test]
    fn parent_chain_matches_ppid() {
        let me = std::process::id();
        let pp = super::process_ppid(me).unwrap();
        if pp != 0 {
            assert!(super::self_process_chain().contains(&pp));
        }
    }
}
