//! 归档（M2）：把条目移入版本化归档区，并支持**整批恢复**。
//!
//! # 为什么是「版本」而不是「条目」
//!
//! 设计共识 §5.2 的硬约束：
//!
//! > **回收站中的归档按版本来管理，不能单个恢复。必须全量恢复、单次操作。**
//!
//! 这不是 UI 层的约定，而是**本模块的 API 形状**：
//! [`restore_version`] 只接受 `version_id`，**不存在任何接受「某个条目」的恢复函数**。
//! 想单条恢复在本 crate 里**无法表达**——把「不要单文件操作」从约定升级成结构性不可能。
//!
//! # 格式
//!
//! 刻意不用 tar（本机无网络、`tar` crate 未缓存），也刻意不用自定义二进制容器：
//!
//! ```text
//! <archive_root>/                       # 默认 $XDG_DATA_HOME/dustlens/archive
//! ├── 1792215203-a1b2c3d4/             # 版本目录
//! │   ├── manifest.json                 # 这个版本的元数据
//! │   └── payload/
//! │       ├── 0/                        # 第 0 个入口的完整内容（保留相对结构）
//! │       └── 1/
//! └── ...
//! ```
//!
//! 好处：**用户可以直接 `ls` 看**，不需要任何专门工具解包；坏处是比 tar 占更多 inode。
//! 对一个「让用户敢删东西」的工具来说，透明性比紧凑更重要。
//!
//! # 不保留的东西（诚实披露）
//!
//! - **硬链接会退化成独立副本**（`std` 没有硬链接计数查询的稳定接口）
//! - **扩展属性 / ACL 不保留**
//! - 所有权（uid/gid）不保留（本工具以普通用户运行；归档区本来就在自己的家目录下）

use crate::types::{display_path, human_bytes};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// 归档格式版本。
pub const ARCHIVE_FORMAT: u32 = 1;

/// 单个版本的元数据。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    /// 版本 id，形如 `1792215203-a1b2c3d4`
    pub version_id: String,
    pub created_at_unix: u64,
    /// 可选的人类可读备注
    pub note: Option<String>,
    /// 本次归档的入口（每个入口是用户点名的一个路径）
    pub entries: Vec<ManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// 入口序号（与 `payload/<n>` 对应）
    pub index: u32,
    /// 原始绝对路径
    pub original: String,
    /// `$HOME` 字面量形式（供展示，避免报告泄漏绝对路径）
    pub display: String,
    pub kind: EntryKind,
    /// 该入口的总体积与文件数
    pub bytes: u64,
    pub files: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
}

impl EntryKind {
    pub fn label(self) -> &'static str {
        match self {
            EntryKind::File => "文件",
            EntryKind::Dir => "目录",
            EntryKind::Symlink => "符号链接",
        }
    }
}

/// 一次归档的结果。
#[derive(Debug)]
pub struct ArchiveOutcome {
    pub version_id: String,
    pub bytes: u64,
    pub entries: usize,
    /// 归档根位于哪个文件系统（用于提示「同盘归档不释放空间」）
    pub archive_root: PathBuf,
    /// 归档是否与源同属一个文件系统
    pub same_filesystem: bool,
}

/// 恢复计划 —— 先校验、再执行（全量、单次）。
#[derive(Debug)]
pub struct RestorePlan {
    pub version_id: String,
    pub entries: Vec<RestoreStep>,
}

#[derive(Debug, Clone)]
pub struct RestoreStep {
    pub archive_path: PathBuf,
    pub original: PathBuf,
    pub display: String,
    pub kind: EntryKind,
    pub bytes: u64,
}

/// 归档存储。把「归档根」显式化，避免在测试里改进程级环境变量
/// （`set_var("XDG_DATA_HOME")` 会与其他并行测试互相污染）。
#[derive(Debug, Clone)]
pub struct Store {
    pub root: PathBuf,
}

impl Store {
    /// 按环境推导归档根。
    ///
    /// 优先 `$XDG_DATA_HOME/dustlens/archive`，其次 `$HOME/.local/share/dustlens/archive`。
    pub fn from_env(home: Option<&Path>) -> Option<Self> {
        archive_root(home).map(|root| Store { root })
    }

    /// 显式指定归档根（测试与嵌入场景用）。
    pub fn at(root: PathBuf) -> Self {
        Store { root }
    }
}

/// 归档根目录。
///
/// 优先 `$XDG_DATA_HOME/dustlens/archive`，其次 `$HOME/.local/share/dustlens/archive`。
pub fn archive_root(home: Option<&Path>) -> Option<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_DATA_HOME") {
        if !x.is_empty() {
            return Some(PathBuf::from(x).join("dustlens").join("archive"));
        }
    }
    home.map(|h| {
        h.join(".local")
            .join("share")
            .join("dustlens")
            .join("archive")
    })
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 生成版本 id：时间戳 + 进程内随机后缀。
fn new_version_id() -> String {
    let t = now_unix();
    let mut seed = t ^ ((std::process::id() as u64) << 32);
    // xorshift，只为避免同一秒内多次归档撞名
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
    format!("{t}-{:08x}", (seed & 0xffff_ffff) as u32)
}

/// 创建归档：把 `paths` 移入归档区。
///
/// # 行为
///
/// - 每个入口整体移动（`rename`；跨文件系统时退化为「复制 + 删除源」）
/// - 写入 `manifest.json`
/// - **不做任何「判断该不该删」的事** —— 调用方（用户）已经决定
///
/// # 失败时
///
/// 已移动的入口会被**尽力回滚**（移回原位），并返回错误。
pub fn create_archive(
    store: &Store,
    paths: &[PathBuf],
    home: Option<&Path>,
    note: Option<String>,
) -> io::Result<ArchiveOutcome> {
    if paths.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "归档至少需要一个条目",
        ));
    }
    let root = store.root.clone();

    // 拒绝对归档区自身或家目录整体做归档（灾难性误操作防线）
    for p in paths {
        let abs = absolutize(p)?;
        if root.starts_with(&abs) || abs.starts_with(&root) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("拒绝归档归档区自身：{}", abs.display()),
            ));
        }
        if let Some(h) = home {
            if abs == h {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "拒绝归档整个家目录",
                ));
            }
        }
        if !abs.symlink_metadata().is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("条目不存在：{}", abs.display()),
            ));
        }
    }

    // 必须先建出归档根，否则下面的 same_device() 拿不到元数据、永远判为「不同盘」
    fs::create_dir_all(&root)?;

    let version_id = new_version_id();
    let ver_dir = root.join(&version_id);
    let payload = ver_dir.join("payload");
    fs::create_dir_all(&payload)?;

    // 必须在**移动任何东西之前**记下源的设备号：
    // 源一旦被移入归档，原路径的 metadata 就不存在了，
    // 那时再比较会恒判为「不同盘」（早期实现的实际 bug）。
    let src_dev = paths
        .first()
        .and_then(|p| absolutize(p).ok())
        .and_then(|p| device_of(&p));

    let mut entries = Vec::new();
    let mut moved: Vec<(PathBuf, PathBuf)> = Vec::new(); // (归档路径, 原路径)
    let mut total_bytes = 0u64;

    let mut result: io::Result<()> = Ok(());
    for (i, p) in paths.iter().enumerate() {
        if result.is_err() {
            break;
        }
        let abs = absolutize(p)?;
        let (bytes, files, kind) = match measure(&abs) {
            Ok(v) => v,
            Err(e) => {
                result = Err(e);
                break;
            }
        };
        let dest = payload.join(i.to_string());
        match move_path(&abs, &dest) {
            Ok(()) => moved.push((dest.clone(), abs.clone())),
            Err(e) => {
                result = Err(e);
                break;
            }
        }
        total_bytes += bytes;
        entries.push(ManifestEntry {
            index: i as u32,
            original: abs.to_string_lossy().into_owned(),
            display: display_path(&abs, home),
            kind,
            bytes,
            files,
        });
    }

    if let Err(e) = result {
        // 尽力回滚
        for (archived, original) in moved.iter().rev() {
            let _ = move_path(archived, original);
        }
        let _ = fs::remove_dir_all(&ver_dir);
        return Err(e);
    }

    let manifest = Manifest {
        format: ARCHIVE_FORMAT,
        version_id: version_id.clone(),
        created_at_unix: now_unix(),
        note,
        entries,
    };
    let mpath = ver_dir.join("manifest.json");
    let json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fs::write(&mpath, json)?;

    let same_fs = match (device_of(&root), src_dev) {
        (Some(a), Some(b)) => a == b,
        // 拿不到设备号时保守地说「不确定」= 不同盘（会提示用户可能占用翻倍）
        _ => false,
    };

    Ok(ArchiveOutcome {
        version_id,
        bytes: total_bytes,
        entries: moved.len(),
        archive_root: root,
        same_filesystem: same_fs,
    })
}

/// 列出全部版本（按创建时间降序）。
pub fn list_versions(store: &Store) -> io::Result<Vec<Manifest>> {
    let root = store.root.clone();
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for ent in fs::read_dir(&root)? {
        let ent = ent?;
        if !ent.file_type()?.is_dir() {
            continue;
        }
        let mpath = ent.path().join("manifest.json");
        if !mpath.exists() {
            continue;
        }
        let Ok(text) = fs::read_to_string(&mpath) else {
            continue;
        };
        if let Ok(m) = serde_json::from_str::<Manifest>(&text) {
            out.push(m);
        }
    }
    out.sort_by_key(|b| std::cmp::Reverse(b.created_at_unix));
    Ok(out)
}

/// 读取单个版本。
pub fn load_manifest(store: &Store, version_id: &str) -> io::Result<Manifest> {
    let mpath = store.root.join(version_id).join("manifest.json");
    let text = fs::read_to_string(&mpath)?;
    serde_json::from_str(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// 构造恢复计划并**做全部前置校验**。
///
/// 只要有任何一条不满足，整个恢复被拒绝 —— 绝不半途而废。
pub fn plan_restore(store: &Store, version_id: &str) -> io::Result<RestorePlan> {
    let root = store.root.clone();
    let manifest = load_manifest(store, version_id)?;
    let ver_dir = root.join(version_id);

    let mut steps = Vec::new();
    let mut conflicts: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();

    for e in &manifest.entries {
        let archive_path = ver_dir.join("payload").join(e.index.to_string());
        if !exists_any(&archive_path) {
            missing.push(e.display.clone());
            continue;
        }
        let original = PathBuf::from(&e.original);
        if exists_any(&original) {
            conflicts.push(e.display.clone());
        }
        steps.push(RestoreStep {
            archive_path,
            original,
            display: e.display.clone(),
            kind: e.kind,
            bytes: e.bytes,
        });
    }

    if !missing.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "归档内容不完整（payload 缺失），拒绝恢复：{}",
                missing.join(", ")
            ),
        ));
    }
    if !conflicts.is_empty() {
        // 设计共识 §5.3：绝不静默覆盖。整批拒绝。
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "目标位置已存在同名内容，整批恢复已拒绝（不会覆盖任何东西）：{}",
                conflicts.join(", ")
            ),
        ));
    }

    Ok(RestorePlan {
        version_id: version_id.to_string(),
        entries: steps,
    })
}

/// 执行整批恢复。
///
/// **复制**语义：恢复 `payload` 的一份副本到原位置，归档本身保留。
/// 这样同一个版本可以被恢复任意多次（例如恢复后用户发现还是不对，可以再来一次），
/// 归档只有通过 [`discard_version`] 才会真正消失。
///
/// 两个不变量：
/// 1. **全量**：只要有一条失败，整批回滚（已写入的目标被删除）。
/// 2. **不覆盖**：任何目标位置已存在内容时，在 [`plan_restore`] 阶段就整批拒绝。
pub fn restore_version(store: &Store, version_id: &str) -> io::Result<usize> {
    let plan = plan_restore(store, version_id)?;
    let mut done: Vec<PathBuf> = Vec::new();

    for step in &plan.entries {
        if let Some(parent) = step.original.parent() {
            fs::create_dir_all(parent)?;
        }
        match copy_tree(&step.archive_path, &step.original) {
            Ok(()) => done.push(step.original.clone()),
            Err(e) => {
                // 回滚：删掉本次已写入的目标（归档内容始终不变）
                for placed in done.iter().rev() {
                    let _ = remove_any(placed);
                }
                return Err(io::Error::new(
                    e.kind(),
                    format!("恢复 {} 失败（已回滚整批）：{e}", step.display),
                ));
            }
        }
    }
    Ok(done.len())
}

/// 永久删除一个已归档版本 —— **这是唯一真正释放空间的操作**。
pub fn discard_version(store: &Store, version_id: &str) -> io::Result<u64> {
    let ver_dir = store.root.join(version_id);
    if !ver_dir.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("版本不存在：{version_id}"),
        ));
    }
    // 口径与 `archive list` 展示的「归档区占用」一致：整个版本目录（含 manifest）
    let bytes = dir_size(&ver_dir).unwrap_or(0);
    fs::remove_dir_all(&ver_dir)?;
    Ok(bytes)
}

/// 归档区占用（供 `archive list` 展示）。
pub fn archive_usage(store: &Store) -> u64 {
    dir_size(&store.root).unwrap_or(0)
}

// ---------------------------------------------------------------- 内部工具

fn absolutize(p: &Path) -> io::Result<PathBuf> {
    if p.is_absolute() {
        Ok(p.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(p))
    }
}

fn exists_any(p: &Path) -> bool {
    p.symlink_metadata().is_ok()
}

/// 统计一个入口的体积、文件数与类型。
fn measure(path: &Path) -> io::Result<(u64, u64, EntryKind)> {
    let md = path.symlink_metadata()?;
    if md.file_type().is_symlink() {
        return Ok((0, 1, EntryKind::Symlink));
    }
    if md.is_file() {
        return Ok((md.len(), 1, EntryKind::File));
    }
    // 目录：递归统计
    let mut bytes = 0u64;
    let mut files = 0u64;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else {
            continue;
        };
        for ent in rd.flatten() {
            let p = ent.path();
            let Ok(md) = p.symlink_metadata() else {
                continue;
            };
            if md.file_type().is_symlink() {
                files += 1;
            } else if md.is_dir() {
                stack.push(p);
            } else if md.is_file() {
                bytes += md.len();
                files += 1;
            }
        }
    }
    Ok((bytes, files, EntryKind::Dir))
}

/// 移动一个路径：优先 `rename`；跨设备时退化为「复制 + 删除源」。
fn move_path(from: &Path, to: &Path) -> io::Result<()> {
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(18) /* EXDEV */ => {
            copy_tree(from, to)?;
            remove_any(from)
        }
        Err(e) => Err(e),
    }
}

fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    let md = from.symlink_metadata()?;
    if md.file_type().is_symlink() {
        let target = fs::read_link(from)?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, to)?;
        #[cfg(not(unix))]
        fs::copy(from, to).map(|_| ())?;
        return Ok(());
    }
    if md.is_file() {
        fs::copy(from, to)?;
        // 保留权限位
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = md.permissions().mode();
            let _ = fs::set_permissions(to, fs::Permissions::from_mode(mode));
        }
        return Ok(());
    }
    fs::create_dir_all(to)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(to, fs::Permissions::from_mode(md.permissions().mode()));
    }
    for ent in fs::read_dir(from)?.flatten() {
        let src = ent.path();
        let name = ent.file_name();
        copy_tree(&src, &to.join(name))?;
    }
    Ok(())
}

fn remove_any(p: &Path) -> io::Result<()> {
    let md = p.symlink_metadata()?;
    if md.is_dir() && !md.file_type().is_symlink() {
        fs::remove_dir_all(p)
    } else {
        fs::remove_file(p)
    }
}

fn dir_size(path: &Path) -> io::Result<u64> {
    let mut total = 0u64;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else {
            continue;
        };
        for ent in rd.flatten() {
            let p = ent.path();
            let Ok(md) = p.symlink_metadata() else {
                continue;
            };
            if md.is_dir() && !md.file_type().is_symlink() {
                stack.push(p);
            } else if md.is_file() {
                total += md.len();
            }
        }
    }
    Ok(total)
}

/// 取路径所在文件系统的设备号。
#[cfg(unix)]
fn device_of(p: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(p).ok().map(|m| m.dev())
}

#[cfg(not(unix))]
fn device_of(_p: &Path) -> Option<u64> {
    None
}

/// 供 CLI 展示的一段人类可读说明。
pub fn describe(o: &ArchiveOutcome) -> String {
    let mut s = format!(
        "已归档 {} 个条目（{}）→ 版本 {}",
        o.entries,
        human_bytes(o.bytes),
        o.version_id
    );
    if !o.same_filesystem {
        s.push_str("\n注意：归档区与源不在同一文件系统，本次是**复制**而非移动，占用约翻倍。");
    } else {
        s.push_str("\n注意：同盘移动不占用额外空间，但**也不释放空间**。");
        s.push_str("\n      真正的空间释放发生在 `dustlens archive discard`。");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct Case {
        home: PathBuf,
        store: Store,
    }

    impl Case {
        fn new(tag: &str) -> Self {
            let home = std::env::temp_dir().join(format!(
                "dl_arch_{tag}_{}_{:x}",
                std::process::id(),
                now_unix()
            ));
            let _ = fs::remove_dir_all(&home);
            fs::create_dir_all(&home).unwrap();
            // 归档根显式落在临时目录内 —— 不碰进程级环境变量
            let store = Store::at(home.join("archive-store"));
            Self { home, store }
        }
    }

    impl Drop for Case {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.home);
        }
    }

    fn mkfile(dir: &Path, name: &str, bytes: usize) -> PathBuf {
        let p = dir.join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, vec![0u8; bytes]).unwrap();
        p
    }

    #[test]
    fn create_moves_entries_and_writes_manifest() {
        let c = Case::new("create");
        let a = mkfile(&c.home, "a.bin", 100);
        let d = c.home.join("dir");
        mkfile(&d, "x/y.bin", 200);

        let out = create_archive(
            &c.store,
            &[a.clone(), d.clone()],
            Some(&c.home),
            Some("t".into()),
        )
        .unwrap();

        assert!(!a.exists(), "源文件应已被移入归档");
        assert!(!d.exists(), "源目录应已被移入归档");
        let m = load_manifest(&c.store, &out.version_id).unwrap();
        assert_eq!(m.entries.len(), 2);
        assert_eq!(m.format, ARCHIVE_FORMAT);
        assert!(m.entries[0].bytes >= 100);
        assert!(m.entries[1].bytes >= 200);
        assert_eq!(out.entries, 2);
        assert!(out.bytes >= 300);
    }

    #[test]
    fn manifest_uses_home_literal_not_absolute_path() {
        let c = Case::new("display");
        let a = mkfile(&c.home, "visible.bin", 10);
        let out = create_archive(&c.store, &[a], Some(&c.home), None).unwrap();
        let m = load_manifest(&c.store, &out.version_id).unwrap();
        assert!(m.entries[0].display.starts_with("$HOME"));
        assert!(m.entries[0].original.contains("visible.bin"));
    }

    #[test]
    fn restore_puts_everything_back() {
        let c = Case::new("restore");
        let a = mkfile(&c.home, "r1.bin", 64);
        let d = c.home.join("rdir");
        mkfile(&d, "sub/r2.bin", 128);
        let before: Vec<Vec<u8>> = [&a, &d.join("sub/r2.bin")]
            .iter()
            .map(|p| fs::read(p).unwrap())
            .collect();

        let out = create_archive(&c.store, &[a.clone(), d.clone()], Some(&c.home), None).unwrap();
        assert!(!a.exists());

        let n = restore_version(&c.store, &out.version_id).unwrap();
        assert_eq!(n, 2);
        assert_eq!(fs::read(&a).unwrap(), before[0]);
        assert_eq!(fs::read(d.join("sub/r2.bin")).unwrap(), before[1]);
    }

    #[test]
    fn restore_is_rejected_when_any_target_exists() {
        // §5.3：绝不静默覆盖 —— 只要有一个冲突，整批拒绝
        let c = Case::new("conflict");
        let a = mkfile(&c.home, "c1.bin", 16);
        let b = mkfile(&c.home, "c2.bin", 16);
        let out = create_archive(&c.store, &[a.clone(), b.clone()], Some(&c.home), None).unwrap();

        fs::write(&a, b"new").unwrap();

        let err = restore_version(&c.store, &out.version_id).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(!b.exists(), "冲突时不应恢复任何条目");
        assert_eq!(fs::read(&a).unwrap(), b"new");
    }

    #[test]
    fn restore_rejects_when_archive_payload_missing() {
        let c = Case::new("missing");
        let a = mkfile(&c.home, "m.bin", 8);
        let out = create_archive(&c.store, &[a], Some(&c.home), None).unwrap();

        fs::remove_dir_all(c.store.root.join(&out.version_id).join("payload")).unwrap();

        let err = restore_version(&c.store, &out.version_id).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn restore_is_repeatable_and_does_not_consume_the_archive() {
        // 回归：早期实现用「移动」做恢复，导致同一个版本只能恢复一次，
        // 且第二次恢复报错信息是「归档内容缺失」（误导）。
        let c = Case::new("repeat");
        let a = mkfile(&c.home, "rep.bin", 32);
        let out = create_archive(&c.store, std::slice::from_ref(&a), Some(&c.home), None).unwrap();

        // 第一次恢复
        restore_version(&c.store, &out.version_id).unwrap();
        assert!(a.exists());
        // 归档仍在
        assert!(c
            .store
            .root
            .join(&out.version_id)
            .join("payload/0")
            .exists());

        // 目标已存在 → 必须先删掉才能再恢复（这是「不覆盖」的体现）
        fs::remove_file(&a).unwrap();
        // 第二次恢复：应成功，证明归档内容未被消耗
        let n = restore_version(&c.store, &out.version_id).unwrap();
        assert_eq!(n, 1);
        assert!(a.exists());
    }

    #[test]
    fn second_restore_without_removing_target_reports_conflict_not_missing() {
        let c = Case::new("conflictmsg");
        let a = mkfile(&c.home, "cm.bin", 8);
        let out = create_archive(&c.store, std::slice::from_ref(&a), Some(&c.home), None).unwrap();
        restore_version(&c.store, &out.version_id).unwrap();

        let e = restore_version(&c.store, &out.version_id).unwrap_err();
        assert_eq!(
            e.kind(),
            io::ErrorKind::AlreadyExists,
            "应是冲突而不是「缺失」"
        );
        assert!(e.to_string().contains("整批恢复已拒绝"));
    }

    #[test]
    fn same_filesystem_is_true_when_archive_lives_on_same_device_as_source() {
        // 临时目录下的归档根与源文件同盘 → 必须是 true。
        // 回归点：早期实现把比较放在「移动之后」，源已不存在，
        // metadata 失败导致恒为 false（并会误导用户以为要额外占一倍空间）。
        let c = Case::new("samefs");
        let a = mkfile(&c.home, "fs.bin", 8);
        let out = create_archive(&c.store, &[a], Some(&c.home), None).unwrap();
        assert!(
            out.same_filesystem,
            "归档根与源同在临时目录下，应判为同一文件系统"
        );
    }

    #[test]
    fn discard_frees_the_version() {
        let c = Case::new("discard");
        let a = mkfile(&c.home, "d.bin", 512);
        let out = create_archive(&c.store, &[a], Some(&c.home), None).unwrap();
        assert_eq!(list_versions(&c.store).unwrap().len(), 1);

        let freed = discard_version(&c.store, &out.version_id).unwrap();
        assert!(freed >= 512);
        assert!(list_versions(&c.store).unwrap().is_empty());
    }

    #[test]
    fn refuses_to_archive_the_archive_itself() {
        let c = Case::new("self");
        fs::create_dir_all(&c.store.root).unwrap();
        let err = create_archive(
            &c.store,
            std::slice::from_ref(&c.store.root),
            Some(&c.home),
            None,
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn refuses_to_archive_whole_home() {
        let c = Case::new("home");
        let err = create_archive(&c.store, std::slice::from_ref(&c.home), Some(&c.home), None)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn archiving_missing_path_is_rejected() {
        let c = Case::new("missingpath");
        let err =
            create_archive(&c.store, &[c.home.join("nope")], Some(&c.home), None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn empty_input_rejected() {
        let c = Case::new("empty");
        let err = create_archive(&c.store, &[], Some(&c.home), None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn symlink_is_preserved_as_symlink() {
        let c = Case::new("symlink");
        let target = mkfile(&c.home, "real.bin", 32);
        let link = c.home.join("link.bin");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let out =
            create_archive(&c.store, std::slice::from_ref(&link), Some(&c.home), None).unwrap();
        let m = load_manifest(&c.store, &out.version_id).unwrap();
        assert_eq!(m.entries[0].kind, EntryKind::Symlink);

        restore_version(&c.store, &out.version_id).unwrap();
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
    }

    #[test]
    fn multiple_versions_are_listed_newest_first() {
        let c = Case::new("multi");
        let a = mkfile(&c.home, "v1.bin", 8);
        let o1 = create_archive(&c.store, &[a], Some(&c.home), None).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let b = mkfile(&c.home, "v2.bin", 8);
        let o2 = create_archive(&c.store, &[b], Some(&c.home), None).unwrap();

        let list = list_versions(&c.store).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].version_id, o2.version_id);
        assert_eq!(list[1].version_id, o1.version_id);
    }

    /// 结构不变式：本模块**不得**出现按单个条目恢复的公开 API。
    #[test]
    fn there_is_no_single_entry_restore_api() {
        // restore_version 只接受 version_id；这条测试是给未来的自己看的。
        let _ = restore_version as fn(&Store, &str) -> io::Result<usize>;
    }
}
