//! 文件系统扫描：广度优先、并行、且**如实记录盲区**（P8）。
//!
//! 关键决策：
//! - **默认不限深度** —— 之前 `-maxdepth 4` 导致「0 命中」的教训。
//! - **默认不跟随符号链接** —— 跨系统引用陷阱正来源于对链接的误判。
//! - **默认停留在同一文件系统** —— 避免把网络盘/NTFS 挂载算进体积。
//! - **任何读取失败都进 `ScanGap`**，不允许静默跳过。

use crate::types::{display_path, Evidence, GapKind, ScanConfig, ScanGap};
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// 扫描统计的累计结果。
#[derive(Debug, Default)]
pub struct ScanStats {
    pub dirs_scanned: u64,
    pub files_seen: u64,
    pub bytes_seen: u64,
}

/// 扫描结果（尚未变成 `Finding`）。
#[derive(Debug)]
pub struct RawScan {
    /// 扫描根
    pub roots: Vec<PathBuf>,
    /// 每个**目录**的累计体积（不含自身，仅其后代常规文件）
    pub dirs: Vec<DirTotal>,
    /// 顶层散落文件（扫描根的直接子文件，未进入任何子目录）
    pub loose_files: Vec<LooseFile>,
    /// 被排除的路径（按规则聚合，不逐条列出以免泄漏）
    pub excluded: Vec<ExcludedHit>,
    /// 盲区
    pub gaps: Vec<ScanGap>,
    pub stats: ScanStats,
    /// 候选去重文件（体积 ≥ `dup_min_bytes` 的常规文件；仅在开启去重时收集）
    pub big_files: Vec<BigFile>,
}

/// 一个候选去重文件。
#[derive(Debug, Clone)]
pub struct BigFile {
    pub path: PathBuf,
    pub len: u64,
}

/// 一个目录的累计体积。
#[derive(Debug, Clone)]
pub struct DirTotal {
    pub path: PathBuf,
    pub bytes: u64,
    pub files: u64,
    /// 该目录的直接子项数量（用于判断「说不清」时是否有结构）
    pub direct_children: u64,
}

/// 扫描根下的散落文件（P7 的相关产物：顶层散落物统计）。
#[derive(Debug, Clone)]
pub struct LooseFile {
    pub path: PathBuf,
    pub bytes: u64,
}

/// 命中的排除规则（只记规则与位置，不记内容）。
#[derive(Debug, Clone)]
pub struct ExcludedHit {
    pub display_path: String,
    pub reason: &'static str,
    pub privacy: bool,
}

/// 执行扫描。
pub fn scan(cfg: &ScanConfig) -> RawScan {
    let mut gaps: Vec<ScanGap> = Vec::new();
    let mut excluded: Vec<ExcludedHit> = Vec::new();
    let mut loose_files: Vec<LooseFile> = Vec::new();
    let mut big_files: Vec<BigFile> = Vec::new();
    let mut dirs: Vec<DirTotal> = Vec::new();
    let stats = Arc::new(Mutex::new(ScanStats::default()));

    let threads = if cfg.threads == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .min(16)
    } else {
        cfg.threads.max(1)
    };

    for root in &cfg.roots {
        let root = match root.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                gaps.push(ScanGap {
                    display_path: display_path(root, cfg.home.as_deref()),
                    kind: GapKind::IoError,
                    detail: format!("无法解析扫描根：{e}"),
                });
                continue;
            }
        };

        // 根本身是否被排除
        if let Some(rule) = cfg.excludes.iter().find(|r| r.matches(&root)) {
            excluded.push(ExcludedHit {
                display_path: display_path(&root, cfg.home.as_deref()),
                reason: rule.reason,
                privacy: rule.is_privacy(),
            });
            continue;
        }

        if !root.is_dir() {
            // 单个文件作为根：直接算散落物
            if let Ok(md) = fs::symlink_metadata(&root) {
                loose_files.push(LooseFile {
                    path: root.clone(),
                    bytes: md.len(),
                });
            }
            continue;
        }

        let root_dev = dev_of(&root);

        // 目录树：BFS + 工作线程
        let queue: Arc<Mutex<VecDeque<(PathBuf, usize)>>> =
            Arc::new(Mutex::new(VecDeque::from([(root.clone(), 0)])));
        let results: Arc<Mutex<Vec<DirTotal>>> = Arc::new(Mutex::new(Vec::new()));
        let gaps_m: Arc<Mutex<Vec<ScanGap>>> = Arc::new(Mutex::new(Vec::new()));
        let excl_m: Arc<Mutex<Vec<ExcludedHit>>> = Arc::new(Mutex::new(Vec::new()));
        let loose_m: Arc<Mutex<Vec<LooseFile>>> = Arc::new(Mutex::new(Vec::new()));
        let big_m: Arc<Mutex<Vec<BigFile>>> = Arc::new(Mutex::new(Vec::new()));
        let active = Arc::new(AtomicUsize::new(0));

        std::thread::scope(|s| {
            for _ in 0..threads {
                let queue = Arc::clone(&queue);
                let results = Arc::clone(&results);
                let gaps_m = Arc::clone(&gaps_m);
                let excl_m = Arc::clone(&excl_m);
                let loose_m = Arc::clone(&loose_m);
                let big_m = Arc::clone(&big_m);
                let stats = Arc::clone(&stats);
                let active = Arc::clone(&active);
                let root = root.clone();
                let home = cfg.home.clone();
                let excludes = cfg.excludes.clone();
                let cfg = cfg.clone();

                s.spawn(move || loop {
                    // 取任务；队列空且无活动工作线程则退出
                    let task = {
                        let mut q = queue.lock().unwrap();
                        match q.pop_front() {
                            Some(t) => Some(t),
                            None => {
                                drop(q);
                                if active.load(Ordering::SeqCst) == 0 {
                                    None
                                } else {
                                    // 别的线程可能在处理时会产出新目录，稍等重试
                                    std::thread::yield_now();
                                    continue;
                                }
                            }
                        }
                    };
                    let Some((dir, depth)) = task else { break };
                    active.fetch_add(1, Ordering::SeqCst);

                    let mut total_bytes = 0u64;
                    let mut total_files = 0u64;
                    let mut direct_children = 0u64;
                    let mut subdirs: Vec<(PathBuf, usize)> = Vec::new();

                    match fs::read_dir(&dir) {
                        Ok(rd) => {
                            for ent in rd {
                                let ent = match ent {
                                    Ok(e) => e,
                                    Err(e) => {
                                        gaps_m.lock().unwrap().push(ScanGap {
                                            display_path: display_path(&dir, home.as_deref()),
                                            kind: GapKind::IoError,
                                            detail: format!("读取目录项失败：{e}"),
                                        });
                                        continue;
                                    }
                                };
                                let path = ent.path();
                                direct_children += 1;

                                if let Some(rule) = excludes.iter().find(|r| r.matches(&path)) {
                                    excl_m.lock().unwrap().push(ExcludedHit {
                                        display_path: display_path(&path, home.as_deref()),
                                        reason: rule.reason,
                                        privacy: rule.is_privacy(),
                                    });
                                    continue;
                                }

                                let md = match fs::symlink_metadata(&path) {
                                    Ok(m) => m,
                                    Err(e) => {
                                        gaps_m.lock().unwrap().push(ScanGap {
                                            display_path: display_path(&path, home.as_deref()),
                                            kind: GapKind::IoError,
                                            detail: format!("读取元数据失败：{e}"),
                                        });
                                        continue;
                                    }
                                };

                                let ft = md.file_type();
                                if ft.is_symlink() {
                                    if !cfg.follow_symlinks {
                                        // 符号链接不跟随，但要登记（可能是跨系统引用）
                                        gaps_m.lock().unwrap().push(ScanGap {
                                            display_path: display_path(&path, home.as_deref()),
                                            kind: GapKind::SymlinkNotFollowed,
                                            detail: "未跟随（默认）；如需跟随请显式开启".into(),
                                        });
                                        continue;
                                    }
                                    // 跟随：按目标类型处理
                                    match fs::metadata(&path) {
                                        Ok(tm) if tm.is_dir() => {
                                            if cfg.one_filesystem && dev_of(&path) != root_dev {
                                                gaps_m.lock().unwrap().push(ScanGap {
                                                    display_path: display_path(
                                                        &path,
                                                        home.as_deref(),
                                                    ),
                                                    kind: GapKind::CrossDevice,
                                                    detail: "链接指向其它文件系统，已跳过".into(),
                                                });
                                                continue;
                                            }
                                            subdirs.push((path.clone(), depth + 1));
                                        }
                                        Ok(tm) => {
                                            total_bytes += tm.len();
                                            total_files += 1;
                                        }
                                        Err(e) => gaps_m.lock().unwrap().push(ScanGap {
                                            display_path: display_path(&path, home.as_deref()),
                                            kind: GapKind::IoError,
                                            detail: format!("跟随符号链接失败：{e}"),
                                        }),
                                    }
                                    continue;
                                }

                                if ft.is_dir() {
                                    if cfg.one_filesystem && dev_of(&path) != root_dev {
                                        gaps_m.lock().unwrap().push(ScanGap {
                                            display_path: display_path(&path, home.as_deref()),
                                            kind: GapKind::CrossDevice,
                                            detail: "位于其它文件系统，已跳过".into(),
                                        });
                                        continue;
                                    }
                                    match cfg.max_depth {
                                        Some(max) if depth + 1 > max => {
                                            gaps_m.lock().unwrap().push(ScanGap {
                                                display_path: display_path(&path, home.as_deref()),
                                                kind: GapKind::MaxDepth,
                                                detail: format!("超过深度上限 {max}"),
                                            });
                                        }
                                        _ => subdirs.push((path.clone(), depth + 1)),
                                    }
                                } else if ft.is_file() {
                                    total_bytes += md.len();
                                    total_files += 1;
                                    // 顶层散落文件（深度 0 的直接子文件）
                                    if depth == 0 {
                                        loose_m.lock().unwrap().push(LooseFile {
                                            path: path.clone(),
                                            bytes: md.len(),
                                        });
                                    }
                                    // 去重候选：只收够大的文件，避免把几十万小文件塞进内存
                                    if cfg.duplicates && md.len() >= cfg.dup_min_bytes {
                                        big_m.lock().unwrap().push(BigFile {
                                            path: path.clone(),
                                            len: md.len(),
                                        });
                                    }
                                }
                                // 其它类型（socket/fifo/device）忽略
                            }
                        }
                        Err(e) => {
                            let kind = if e.kind() == std::io::ErrorKind::PermissionDenied {
                                GapKind::PermissionDenied
                            } else {
                                GapKind::IoError
                            };
                            gaps_m.lock().unwrap().push(ScanGap {
                                display_path: display_path(&dir, home.as_deref()),
                                kind,
                                detail: e.to_string(),
                            });
                        }
                    }

                    if !subdirs.is_empty() {
                        let mut q = queue.lock().unwrap();
                        q.extend(subdirs);
                    }

                    let _ = root;
                    results.lock().unwrap().push(DirTotal {
                        path: dir,
                        bytes: total_bytes,
                        files: total_files,
                        direct_children,
                    });
                    {
                        let mut st = stats.lock().unwrap();
                        st.dirs_scanned += 1;
                        st.files_seen += total_files;
                        st.bytes_seen += total_bytes;
                    }
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });

        // 自底向上累加，得到每个目录的完整（含后代）体积
        let mut nodes = Arc::try_unwrap(results).unwrap().into_inner().unwrap();
        accumulate_upward(&mut nodes);
        dirs.extend(nodes);
        gaps.extend(Arc::try_unwrap(gaps_m).unwrap().into_inner().unwrap());
        excluded.extend(Arc::try_unwrap(excl_m).unwrap().into_inner().unwrap());
        loose_files.extend(Arc::try_unwrap(loose_m).unwrap().into_inner().unwrap());
        big_files.extend(Arc::try_unwrap(big_m).unwrap().into_inner().unwrap());
    }

    // 散落物与目录去重排序
    loose_files.sort_by_key(|b| std::cmp::Reverse(b.bytes));
    dirs.sort_by_key(|b| std::cmp::Reverse(b.bytes));

    // 盲区去重（同一路径可能被多个线程记录）
    gaps.sort_by(|a, b| a.display_path.cmp(&b.display_path));
    gaps.dedup_by(|a, b| a.display_path == b.display_path && a.kind == b.kind);

    let stats = Arc::try_unwrap(stats).unwrap().into_inner().unwrap();
    RawScan {
        roots: cfg.roots.clone(),
        dirs,
        loose_files,
        excluded,
        gaps,
        stats,
        big_files,
    }
}

/// 把每个目录的体积向上累加到其父目录，使 `DirTotal.bytes` 含全部后代。
///
/// 实现方式：先按路径字典序建索引，再从最深路径往上加。
fn accumulate_upward(nodes: &mut [DirTotal]) {
    use std::collections::HashMap;
    // 收集 (路径 → 索引)
    let mut idx: HashMap<PathBuf, usize> = HashMap::with_capacity(nodes.len());
    for (i, n) in nodes.iter().enumerate() {
        idx.insert(n.path.clone(), i);
    }
    // 按深度降序处理，保证子节点先加满
    let mut order: Vec<usize> = (0..nodes.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(nodes[i].path.components().count()));
    // 按深度降序处理：处理某个节点时，它的所有后代**已经**累加完毕，
    // 所以直接把它「当前的累计值」加到父节点即可。
    //
    // 曾经在这里额外保留了一份「自身体积」副本 —— 那是错的：
    // 父节点会同时收到「自身」与「子节点带上的自身」，导致重复计数。
    for &i in &order {
        let (b, f) = (nodes[i].bytes, nodes[i].files);
        if b == 0 && f == 0 {
            continue;
        }
        if let Some(parent) = nodes[i].path.parent() {
            if let Some(&pi) = idx.get(parent) {
                if pi != i {
                    nodes[pi].bytes += b;
                    nodes[pi].files += f;
                }
            }
        }
    }
}

/// 取设备号，用于 `one_filesystem` 判定。
#[cfg(unix)]
fn dev_of(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).map(|m| m.dev()).unwrap_or(0)
}

#[cfg(not(unix))]
fn dev_of(_path: &Path) -> u64 {
    0
}

/// 从目录统计里挑出「扫描根的直接子目录」，作为体积排序的展示粒度。
pub fn top_level_dirs(scan: &RawScan, root: &Path) -> Vec<DirTotal> {
    scan.dirs
        .iter()
        .filter(|d| d.path.parent() == Some(root))
        .cloned()
        .collect()
}

/// 把目录统计变成身份类证据。
pub fn body_evidence(d: &DirTotal) -> Evidence {
    Evidence::Body {
        bytes: d.bytes,
        files: d.files,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulate_upward_sums_descendants() {
        let mut nodes = vec![
            DirTotal {
                path: PathBuf::from("/r"),
                bytes: 10,
                files: 1,
                direct_children: 3,
            },
            DirTotal {
                path: PathBuf::from("/r/a"),
                bytes: 20,
                files: 2,
                direct_children: 1,
            },
            DirTotal {
                path: PathBuf::from("/r/a/b"),
                bytes: 30,
                files: 3,
                direct_children: 0,
            },
        ];
        accumulate_upward(&mut nodes);
        let by = |p: &str| nodes.iter().find(|n| n.path == *p).unwrap().clone();
        assert_eq!(by("/r/a/b").bytes, 30);
        // /r/a 自身 20 + 子 30
        assert_eq!(by("/r/a").bytes, 50);
        assert_eq!(by("/r/a").files, 5);
        // /r 自身 10 + /r/a 的 50
        assert_eq!(by("/r").bytes, 60);
        assert_eq!(by("/r").files, 6);
    }

    #[test]
    fn scan_counts_files_and_detects_top_level() {
        let tmp = std::env::temp_dir().join(format!("dl_scan_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("sub/deep")).unwrap();
        fs::write(tmp.join("a.txt"), b"hello").unwrap(); // 5 B
        fs::write(tmp.join("sub/b.txt"), b"world!!").unwrap(); // 7 B
        fs::write(tmp.join("sub/deep/c.txt"), b"x").unwrap(); // 1 B

        let cfg = ScanConfig::new(vec![tmp.clone()], None);
        let raw = scan(&cfg);

        assert_eq!(raw.stats.files_seen, 3);
        assert_eq!(raw.stats.bytes_seen, 13);
        assert!(raw.gaps.is_empty(), "gaps: {:?}", raw.gaps);

        // 顶层散落文件只有 a.txt
        assert_eq!(raw.loose_files.len(), 1);
        assert_eq!(raw.loose_files[0].bytes, 5);

        let top = top_level_dirs(&raw, &tmp.canonicalize().unwrap());
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].bytes, 8); // sub 下 7+1

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn default_scan_is_unbounded_depth() {
        // 回归测试：曾因 maxdepth 导致「0 命中」
        let tmp = std::env::temp_dir().join(format!("dl_deep_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let mut p = tmp.clone();
        for i in 0..12 {
            p = p.join(format!("d{i}"));
        }
        fs::create_dir_all(&p).unwrap();
        fs::write(p.join("deep.bin"), [0u8; 64]).unwrap();

        let cfg = ScanConfig::new(vec![tmp.clone()], None);
        let raw = scan(&cfg);
        assert_eq!(raw.stats.files_seen, 1, "深层文件必须被扫到");
        assert_eq!(raw.stats.bytes_seen, 64);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn privacy_excludes_are_not_reported_as_dirs() {
        let tmp = std::env::temp_dir().join(format!("dl_excl_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join(".ssh")).unwrap();
        fs::write(tmp.join(".ssh/id_ed25519"), b"secret").unwrap();
        fs::create_dir_all(tmp.join(".ssh-keys-backup")).unwrap();
        fs::write(tmp.join(".ssh-keys-backup/keep.txt"), b"keep").unwrap();

        let cfg = ScanConfig::new(vec![tmp.clone()], Some(tmp.clone()));
        let raw = scan(&cfg);

        // .ssh 被排除；.ssh-keys-backup 是子串相近但不同目录，必须保留
        assert!(raw.excluded.iter().any(|e| e.display_path.contains(".ssh")));
        assert!(raw
            .excluded
            .iter()
            .any(|e| e.privacy && e.display_path.ends_with(".ssh")));
        assert_eq!(raw.stats.files_seen, 1, "只应扫到 keep.txt");
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn permission_denied_is_recorded_as_gap() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let tmp = std::env::temp_dir().join(format!("dl_perm_{}", std::process::id()));
            let _ = fs::remove_dir_all(&tmp);
            let locked = tmp.join("locked");
            fs::create_dir_all(&locked).unwrap();
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

            let cfg = ScanConfig::new(vec![tmp.clone()], None);
            let raw = scan(&cfg);

            // root 用户运行时会读得到，此时不强制断言有 gap
            if unsafe { libc_geteuid() } != 0 {
                assert!(
                    raw.gaps.iter().any(|g| g.kind == GapKind::PermissionDenied),
                    "权限不足必须进 ScanGap，gaps={:?}",
                    raw.gaps
                );
            }
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
            let _ = fs::remove_dir_all(&tmp);
        }
    }

    #[cfg(unix)]
    extern "C" {
        #[link_name = "geteuid"]
        fn libc_geteuid() -> u32;
    }
}
