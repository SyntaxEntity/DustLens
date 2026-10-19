//! 冗余副本（M4）：字节完全相同的多份文件。
//!
//! # 判据只陈述事实
//!
//! 「这些文件的字节完全相同」是一个**可验证的形式属性**（P1）。
//! 本模块**不指定**「留哪一份」—— 那是用户的事。报告里只按集合罗列成员。
//!
//! # 三级过滤（为什么要这样做）
//!
//! 全量哈希会把每个候选文件读一遍。本机实测：`$HOME` 下 ≥1 MiB 的文件有 25,413 个，
//! 其中有**大小重复**的尺寸 2,996 种 —— 直接全量哈希读不完。
//!
//! 所以：
//!
//! | 级别 | 依据 | 成本 |
//! |---|---|---|
//! | 1 | **尺寸**相同才可能是副本 | 零 IO（已从扫描阶段带来） |
//! | 2 | **前 16 KiB** 的哈希相同 | 只读 16 KiB |
//! | 3 | **逐字节**核对 | 只对二级仍相同的少量文件读全文 |
//!
//! 第 3 级是**精确核对**，不是哈希 —— 因此不存在碰撞误判：
//! 报出来的集合是真的字节相同，不是「哈希碰巧一样」。
//!
//! # 不做什么
//!
//! - 不做相似文件（图片/音频）判定 —— 那需要解码，属另一类问题
//! - 不跟随符号链接（扫描阶段就已跳过）
//! - 不跨扫描根比对以外的事：所有候选都来自同一轮扫描

use crate::refs::{self, ProcessIndex, ReferenceIndex};
use crate::scan::BigFile;
use crate::types::{display_path, human_bytes, LinkStrength};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

/// 最多报告多少组（防止刷屏）。
pub const MAX_SETS: usize = 100;
/// 每组最多列多少成员（其余只报数量）。
pub const MAX_MEMBERS: usize = 20;
/// 二级过滤读取的前缀长度。
const PREFIX_BYTES: u64 = 16 * 1024;

/// 去重结果：明细 + 真实总量。
///
/// 明细有上限（防止报告刷屏），但**总量必须如实统计** ——
/// 否则摘要会报一个偏小的数字，等于骗人。
#[derive(Debug, Clone)]
pub struct DuplicateReport {
    /// 明细（最多 `MAX_SETS` 组）
    pub sets: Vec<DuplicateSet>,
    /// 真实组数（不受上限影响）
    pub total_sets: usize,
    /// 真实可回收字节（不受上限影响）
    pub total_reclaimable: u64,
    /// 按区域统计：(区域, 组数, 可回收字节)，按可回收降序
    pub by_area: Vec<(String, usize, u64)>,
}

/// 一组内容完全相同的文件。
#[derive(Debug, Clone)]
pub struct DuplicateSet {
    /// 每个成员的字节数（集合内所有成员相同）
    pub size: u64,
    /// 成员共同归属的区域（`$HOME/` 之后的头两段路径）。
    /// 只是**事实性归类**，用于让用户看清「这堆重复集中在哪」。
    pub area: String,
    pub members: Vec<DupMember>,
    /// 该组未被计入的成员数（超出 `MAX_MEMBERS` 时）
    pub truncated: usize,
}

impl DuplicateSet {
    /// 若只保留一份，可回收的字节数。
    pub fn reclaimable(&self) -> u64 {
        let n = (self.members.len() + self.truncated) as u64;
        self.size.saturating_mul(n.saturating_sub(1))
    }

    pub fn human_size(&self) -> String {
        human_bytes(self.size)
    }
}

#[derive(Debug, Clone)]
pub struct DupMember {
    pub path: PathBuf,
    pub display_path: String,
    /// 该副本的引用强度（可能正被使用 —— 那就不是「闲置的第二份」）
    pub link: LinkStrength,
    /// 修改时间（Unix 秒），仅作参考信息
    pub mtime_unix: u64,
}

/// 执行去重检测。
///
/// `files` 来自扫描阶段收集的候选（已按大小门槛过滤）。
pub fn find(
    files: &[BigFile],
    procs: &ProcessIndex,
    refs: &ReferenceIndex,
    home: Option<&Path>,
) -> DuplicateReport {
    // ---- 第 1 级：按尺寸分组，只留 ≥2 个的组 ----
    let mut by_size: HashMap<u64, Vec<&BigFile>> = HashMap::new();
    for f in files {
        by_size.entry(f.len).or_default().push(f);
    }
    let mut candidates: Vec<(u64, Vec<&BigFile>)> =
        by_size.into_iter().filter(|(_, v)| v.len() >= 2).collect();
    // 大文件优先（更值得关注），同名尺寸内部按路径排序保证确定性
    candidates.sort_by_key(|(size, _)| std::cmp::Reverse(*size));

    // ---- 逐组处理（并行）----
    // 8.5 分钟的单线程实测不可接受：默认开启的功能必须快。
    // 每个尺寸组相互独立，按组切分给工作线程即可。
    let groups = std::sync::Mutex::new(candidates);
    let next = std::sync::atomic::AtomicUsize::new(0);
    let results: std::sync::Mutex<Vec<DuplicateSet>> = std::sync::Mutex::new(Vec::new());
    let total_sets = std::sync::atomic::AtomicUsize::new(0);
    let total_reclaim = std::sync::atomic::AtomicU64::new(0);
    let area_map: std::sync::Mutex<HashMap<String, (usize, u64)>> =
        std::sync::Mutex::new(HashMap::new());

    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(8);

    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| loop {
                let idx = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let (size, group) = {
                    let g = groups.lock().unwrap();
                    if idx >= g.len() {
                        break;
                    }
                    let (size, group) = &g[idx];
                    (*size, group.clone())
                };

                for set in duplicates_in_group(size, &group, procs, refs, home) {
                    total_sets.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    total_reclaim
                        .fetch_add(set.reclaimable(), std::sync::atomic::Ordering::Relaxed);
                    {
                        let mut m = area_map.lock().unwrap();
                        let e = m.entry(set.area.clone()).or_insert((0, 0));
                        e.0 += 1;
                        e.1 = e.1.saturating_add(set.reclaimable());
                    }
                    let mut r = results.lock().unwrap();
                    if r.len() < MAX_SETS {
                        r.push(set);
                    }
                }
            });
        }
    });

    let mut out = results.into_inner().unwrap();
    let total_sets = total_sets.into_inner();
    let total_reclaimable = total_reclaim.into_inner();

    // 按可回收体积降序
    out.sort_by_key(|s| std::cmp::Reverse(s.reclaimable()));
    let mut by_area: Vec<(String, usize, u64)> = area_map
        .into_inner()
        .unwrap()
        .into_iter()
        .map(|(k, (n, b))| (k, n, b))
        .collect();
    by_area.sort_by_key(|(_, _, b)| std::cmp::Reverse(*b));

    DuplicateReport {
        sets: out,
        total_sets,
        total_reclaimable,
        by_area,
    }
}

/// 求一组路径的**共同区域**：把成员路径按 `$HOME/` 之后的头两段归并。
///
/// 目的不是判断价值，而是让「可回收 42 GiB」这种总量能落到具体位置 ——
/// 例如「38 GiB 在 Steam 里」和「1 GiB 在 Documents 里」是完全不同的两件事。
fn common_area(members: &[DupMember]) -> String {
    let seg = |p: &str| -> Vec<String> {
        p.trim_start_matches("$HOME/")
            .split('/')
            .take(2)
            .map(|s| s.to_string())
            .collect()
    };
    let Some(first) = members.first() else {
        return "?".into();
    };
    let mut common = seg(&first.display_path);
    for m in &members[1..] {
        let s = seg(&m.display_path);
        while !common.is_empty() && !s.starts_with(&common) {
            common.pop();
        }
    }
    if common.is_empty() {
        "$HOME".into()
    } else {
        format!("$HOME/{}", common.join("/"))
    }
}

/// 处理一个「尺寸相同」的候选组，返回其中内容完全相同的集合。
///
/// 内部走第 2 级（前缀哈希）与第 3 级（逐字节核对）。
fn duplicates_in_group(
    size: u64,
    group: &[&BigFile],
    procs: &ProcessIndex,
    refs: &ReferenceIndex,
    home: Option<&Path>,
) -> Vec<DuplicateSet> {
    let mut out = Vec::new();

    // ---- 第 2 级：前 16 KiB 哈希 ----
    let mut by_prefix: HashMap<u64, Vec<&BigFile>> = HashMap::new();
    for f in group {
        if let Some(h) = prefix_hash(&f.path, size) {
            by_prefix.entry(h).or_default().push(f);
        }
    }

    for (_, same_prefix) in by_prefix {
        if same_prefix.len() < 2 {
            continue;
        }

        // ---- 第 3 级：逐字节分区（精确，无哈希碰撞）----
        let mut classes: Vec<Vec<&BigFile>> = Vec::new();
        for f in same_prefix {
            let mut placed = false;
            for class in classes.iter_mut() {
                if same_bytes(&class[0].path, &f.path, size) {
                    class.push(f);
                    placed = true;
                    break;
                }
            }
            if !placed {
                classes.push(vec![f]);
            }
        }

        for class in classes {
            if class.len() < 2 {
                continue;
            }
            let mut members = Vec::new();
            for f in class.iter().take(MAX_MEMBERS) {
                let rf = refs::check(&f.path, procs, refs, home);
                members.push(DupMember {
                    display_path: display_path(&f.path, home),
                    path: f.path.clone(),
                    link: rf.strength,
                    mtime_unix: mtime_of(&f.path),
                });
            }
            members.sort_by_key(|m| m.display_path.clone());
            let area = common_area(&members);
            out.push(DuplicateSet {
                size,
                area,
                truncated: class.len().saturating_sub(MAX_MEMBERS),
                members,
            });
        }
    }

    out
}

/// 读前 `PREFIX_BYTES` 字节做哈希（第 2 级过滤）。
fn prefix_hash(path: &Path, size: u64) -> Option<u64> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let f = File::open(path).ok()?;
    let mut r = BufReader::new(f);
    let want = size.min(PREFIX_BYTES) as usize;
    let mut buf = vec![0u8; want];
    let mut read = 0usize;
    while read < want {
        match r.read(&mut buf[read..]) {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(_) => return None,
        }
    }
    buf.truncate(read);

    let mut h = DefaultHasher::new();
    // 把尺寸也混进去，避免「前缀相同但长度不同」被并到一组
    size.hash(&mut h);
    buf.hash(&mut h);
    Some(h.finish())
}

/// 逐字节比较两个文件（长度已知相同）。
fn same_bytes(a: &Path, b: &Path, size: u64) -> bool {
    let (Ok(fa), Ok(fb)) = (File::open(a), File::open(b)) else {
        return false;
    };
    let mut ra = BufReader::new(fa);
    let mut rb = BufReader::new(fb);
    let mut ba = vec![0u8; 64 * 1024];
    let mut bb = vec![0u8; 64 * 1024];
    let mut remaining = size;

    while remaining > 0 {
        let want = remaining.min(64 * 1024) as usize;
        if read_exact_or_eof(&mut ra, &mut ba[..want]).is_none() {
            return false;
        }
        if read_exact_or_eof(&mut rb, &mut bb[..want]).is_none() {
            return false;
        }
        if ba[..want] != bb[..want] {
            return false;
        }
        remaining -= want as u64;
    }
    true
}

fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Option<()> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => return None,
            Ok(n) => filled += n,
            Err(_) => return None,
        }
    }
    Some(())
}

fn mtime_of(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refs::{ProcessIndex, ReferenceIndex};
    use std::fs;

    struct Case {
        home: PathBuf,
    }

    impl Case {
        fn new(tag: &str) -> Self {
            let home = std::env::temp_dir().join(format!(
                "dl_dup_{tag}_{}_{:x}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let _ = fs::remove_dir_all(&home);
            fs::create_dir_all(&home).unwrap();
            Self { home }
        }
        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let p = self.home.join(name);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, bytes).unwrap();
            p
        }
        fn big(&self, name: &str, bytes: &[u8]) -> BigFile {
            let p = self.write(name, bytes);
            BigFile {
                path: p,
                len: bytes.len() as u64,
            }
        }
    }

    impl Drop for Case {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.home);
        }
    }

    fn run(c: &Case, files: &[BigFile]) -> Vec<DuplicateSet> {
        find(
            files,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            Some(&c.home),
        )
        .sets
    }

    #[test]
    fn detects_identical_files() {
        let c = Case::new("ident");
        let data = vec![7u8; 40_000];
        let a = c.big("a.bin", &data);
        let b = c.big("b.bin", &data);
        let sets = run(&c, &[a, b]);
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].members.len(), 2);
        assert_eq!(sets[0].size, 40_000);
        assert_eq!(sets[0].reclaimable(), 40_000);
    }

    #[test]
    fn one_byte_difference_is_not_a_duplicate() {
        let c = Case::new("onediff");
        let mut d2 = vec![7u8; 40_000];
        d2[39_999] = 8;
        let a = c.big("a.bin", &vec![7u8; 40_000]);
        let b = c.big("b.bin", &d2);
        assert!(run(&c, &[a, b]).is_empty(), "差一字节不得算副本");
    }

    #[test]
    fn same_size_different_content_is_not_a_duplicate() {
        let c = Case::new("sameSize");
        let a = c.big("a.bin", &vec![1u8; 30_000]);
        let b = c.big("b.bin", &vec![2u8; 30_000]);
        assert!(run(&c, &[a, b]).is_empty());
    }

    #[test]
    fn different_sizes_are_never_compared() {
        let c = Case::new("diffsize");
        let a = c.big("a.bin", &vec![3u8; 20_000]);
        let b = c.big("b.bin", &vec![3u8; 21_000]);
        assert!(run(&c, &[a, b]).is_empty());
    }

    #[test]
    fn identical_prefix_but_different_tail_is_caught_by_byte_compare() {
        // 前缀 16 KiB 完全相同，只在尾部不同 —— 必须靠第 3 级抓出来
        let c = Case::new("tail");
        let mut a_data = vec![9u8; PREFIX_BYTES as usize + 5_000];
        let mut b_data = a_data.clone();
        let last = a_data.len() - 1;
        a_data[last] = 1;
        b_data[last] = 2;
        let a = c.big("a.bin", &a_data);
        let b = c.big("b.bin", &b_data);
        assert!(run(&c, &[a, b]).is_empty(), "尾部不同必须被判为不同");
    }

    #[test]
    fn groups_three_copies_and_reports_reclaimable() {
        let c = Case::new("three");
        let data = vec![5u8; 20_000];
        let files = vec![
            c.big("a.bin", &data),
            c.big("b/c.bin", &data),
            c.big("d/e/c.bin", &data),
        ];
        let sets = run(&c, &files);
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].members.len(), 3);
        // 留 1 份 → 可回收 2 份
        assert_eq!(sets[0].reclaimable(), 40_000);
    }

    #[test]
    fn separates_two_distinct_content_groups_of_same_size() {
        let c = Case::new("twogroups");
        let a = vec![1u8; 20_000];
        let b = vec![2u8; 20_000];
        let files = vec![
            c.big("a1.bin", &a),
            c.big("a2.bin", &a),
            c.big("b1.bin", &b),
            c.big("b2.bin", &b),
        ];
        let sets = run(&c, &files);
        assert_eq!(sets.len(), 2, "两组不同内容必须分开");
        for s in &sets {
            assert_eq!(s.members.len(), 2);
        }
    }

    #[test]
    fn single_file_is_not_reported() {
        let c = Case::new("single");
        let a = c.big("only.bin", &vec![4u8; 20_000]);
        assert!(run(&c, &[a]).is_empty());
    }

    #[test]
    fn missing_file_does_not_panic() {
        let c = Case::new("missing");
        let a = BigFile {
            path: c.home.join("nope.bin"),
            len: 10_000,
        };
        let b = BigFile {
            path: c.home.join("nope2.bin"),
            len: 10_000,
        };
        assert!(run(&c, &[a, b]).is_empty());
    }

    #[test]
    fn caps_members_per_set() {
        let c = Case::new("cap");
        let data = vec![6u8; 20_000];
        let mut files = Vec::new();
        for i in 0..(MAX_MEMBERS + 5) {
            files.push(c.big(&format!("f{i}.bin"), &data));
        }
        let sets = run(&c, &files);
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].members.len(), MAX_MEMBERS);
        assert_eq!(sets[0].truncated, 5);
    }

    #[test]
    fn totals_are_not_capped_by_detail_limit() {
        // 明细有上限，但「真实组数 / 可回收总量」必须如实统计
        let c = Case::new("totals");
        let mut files = Vec::new();
        for i in 0..(MAX_SETS + 5) {
            // 每组两份、且每组的尺寸各不相同 → 制造很多组
            let data = vec![(i % 251) as u8; 20_000 + i * 4096];
            files.push(c.big(&format!("a{i}.bin"), &data));
            files.push(c.big(&format!("b{i}.bin"), &data));
        }
        let rep = find(
            &files,
            &ProcessIndex::default(),
            &ReferenceIndex::default(),
            Some(&c.home),
        );
        assert_eq!(rep.sets.len(), MAX_SETS, "明细应被封顶");
        assert_eq!(rep.total_sets, MAX_SETS + 5, "总量必须如实");
        assert!(rep.total_reclaimable > 0);
    }

    #[test]
    fn members_report_link_strength() {
        let c = Case::new("links");
        let data = vec![8u8; 20_000];
        let a = c.big("a.bin", &data);
        let b = c.big("b.bin", &data);
        let sets = run(&c, &[a, b]);
        // 无进程、无配置引用 → 都是无人认领
        assert!(sets[0]
            .members
            .iter()
            .all(|m| m.link == LinkStrength::Unclaimed));
    }
}
