//! 内容鉴定（M5）：**不依赖 LLM** 地回答「这是什么」。
//!
//! # 三层依据，从硬到软
//!
//! | 层 | 依据 | 强度 |
//! |---|---|---|
//! | 1 | **目录结构特征**（`saves/`+`options.txt`、`Cargo.toml`、`.git`…） | 强：结构不是猜的 |
//! | 2 | **文件魔数**（ELF / PNG / PDF / ZIP…） | 强：只看前 16 字节 |
//! | 3 | **前 4 KiB 文本特征**（JSON / 脚本 / Markdown / systemd unit…） | 中：观察头部 |
//!
//! # 三条硬约束
//!
//! 1. **只读、只在本机**（P5）：不联网、不上传，也不把文件内容写进报告 ——
//!    报告里只出现**文件名与结构**，不出现内容。
//! 2. **不确定性要标出来**：`confident = false` 的鉴定结果**不能**用来
//!    把条目从「说不清」里剔除（那等于用猜测消灭不确定性）。
//! 3. **不猜价值**（P1）：只说「这是什么」，不说「该不该留」。

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// 读取用于鉴定的头部长度（文本特征用）。
pub const HEAD_BYTES: usize = 4096;
/// 目录鉴定时最多看多少个直接子项。
pub const MAX_DIR_ENTRIES: usize = 64;
/// 判定「扩展名主导」时的最少样本数。
const MIN_EXT_SAMPLES: usize = 8;

/// 一次鉴定的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identified {
    /// 「这是什么」（一句话）
    pub what: String,
    /// 依据（只含文件名与结构，**绝不含文件内容**）
    pub basis: String,
    /// 是否足够确定 —— `false` 时不得用于剔除「说不清」
    pub confident: bool,
}

impl Identified {
    fn firm(what: impl Into<String>, basis: impl Into<String>) -> Self {
        Self {
            what: what.into(),
            basis: basis.into(),
            confident: true,
        }
    }
    fn weak(what: impl Into<String>, basis: impl Into<String>) -> Self {
        Self {
            what: what.into(),
            basis: basis.into(),
            confident: false,
        }
    }
}

// ------------------------------------------------------------------ 目录

/// 已知的「目录特征」规则。
///
/// 每条规则 = 触发条件（若干必须同时存在的名字）+ 结论。
/// 顺序有意义：越具体的越靠前。
struct DirRule {
    /// 必须出现的名字（任一命中即可，用 `any_of` 表示）
    any_of: &'static [&'static str],
    /// 必须同时出现的名字（全部命中）
    all_of: &'static [&'static str],
    what: &'static str,
}

const DIR_RULES: &[DirRule] = &[
    DirRule {
        any_of: &[],
        all_of: &["saves", "options.txt"],
        what: "Minecraft 游戏数据（含存档与设置）",
    },
    DirRule {
        any_of: &[],
        all_of: &["Cargo.toml", "src"],
        what: "Rust 项目源码",
    },
    DirRule {
        any_of: &["Cargo.toml"],
        all_of: &[],
        what: "Rust 项目（含构建描述）",
    },
    DirRule {
        any_of: &["package.json"],
        all_of: &[],
        what: "Node.js 项目",
    },
    DirRule {
        any_of: &["CMakeLists.txt"],
        all_of: &[],
        what: "CMake 项目",
    },
    DirRule {
        any_of: &["pyproject.toml", "setup.py", "requirements.txt"],
        all_of: &[],
        what: "Python 项目",
    },
    DirRule {
        any_of: &[".git"],
        all_of: &[],
        what: "Git 仓库",
    },
    DirRule {
        any_of: &["compose.yaml", "docker-compose.yml", "Dockerfile"],
        all_of: &[],
        what: "容器编排/镜像构建项目",
    },
    DirRule {
        any_of: &["index.html"],
        all_of: &[],
        what: "网页 / 静态站点",
    },
    DirRule {
        any_of: &["go.mod"],
        all_of: &[],
        what: "Go 项目",
    },
];

/// 按扩展名判定的「媒体/资料集合」。
fn ext_rule(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "mp4" | "mkv" | "avi" | "mov" | "webm" | "flv" | "wmv" => "视频合集",
        "mp3" | "flac" | "wav" | "m4a" | "ogg" | "opus" => "音频合集",
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "heic" | "bmp" | "tiff" => "图片合集",
        "pdf" | "epub" | "mobi" | "djvu" => "电子书 / 文档资料",
        "iso" | "img" | "vmdk" | "qcow2" => "磁盘镜像",
        "blend" => "Blender 工程",
        "psd" | "xcf" => "图像工程文件",
        "zip" | "rar" | "7z" | "tar" | "gz" | "xz" | "zst" => "压缩归档合集",
        _ => return None,
    })
}

/// 目录采样：名字、扩展名计数、文件数、子目录路径。
struct Sample {
    names: Vec<String>,
    ext_counts: HashMap<String, usize>,
    file_count: usize,
    subdirs: Vec<PathBuf>,
}

fn probe(dir: &Path, limit: usize) -> Option<Sample> {
    let rd = fs::read_dir(dir).ok()?;
    let mut sample = Sample {
        names: Vec::new(),
        ext_counts: HashMap::new(),
        file_count: 0,
        subdirs: Vec::new(),
    };
    for ent in rd.flatten().take(limit) {
        let Some(name) = ent.file_name().to_str().map(|s| s.to_string()) else {
            continue;
        };
        let ftype = ent.file_type().ok();
        if let Some(ext) = Path::new(&name)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
        {
            *sample.ext_counts.entry(ext).or_default() += 1;
        }
        if ftype.map(|t| t.is_file()).unwrap_or(false) {
            sample.file_count += 1;
        }
        if ftype.map(|t| t.is_dir()).unwrap_or(false) && sample.subdirs.len() < 8 {
            sample.subdirs.push(dir.join(&name));
        }
        sample.names.push(name);
    }
    Some(sample)
}

/// 把「一层下探」的采样合并进主采样（只取子目录里的名字与扩展名）。
fn merge_one_level(sample: &mut Sample) {
    let subdirs = sample.subdirs.clone();
    for sub in subdirs {
        let Ok(rd) = fs::read_dir(&sub) else {
            continue;
        };
        for ent in rd.flatten().take(32) {
            let Some(name) = ent.file_name().to_str().map(|s| s.to_string()) else {
                continue;
            };
            if let Some(ext) = Path::new(&name)
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_ascii_lowercase())
            {
                *sample.ext_counts.entry(ext).or_default() += 1;
            }
            if ent.file_type().map(|t| t.is_file()).unwrap_or(false) {
                sample.file_count += 1;
            }
            sample.names.push(name);
        }
    }
}

/// 鉴定一个目录。
///
/// 先看直接子项；若结论不确定，再**下探一层**（最多 8 个子目录 × 32 项）——
/// 真实数据里，媒体/资料往往在 `X/视频/`、`X/壁纸/` 这样的一层目录里。
pub fn identify_dir(dir: &Path) -> Option<Identified> {
    let mut sample = probe(dir, MAX_DIR_ENTRIES)?;
    if sample.names.is_empty() {
        return Some(Identified::firm("空目录", "目录下没有任何子项"));
    }

    if let Some(id) = classify(&sample, false) {
        if id.confident {
            return Some(id);
        }
    }

    merge_one_level(&mut sample);
    if let Some(id) = classify(&sample, true) {
        return Some(id);
    }
    classify(&sample, false)
}

/// 对采样做分类。`deep = true` 表示采样包含下一层。
fn classify(sample: &Sample, deep: bool) -> Option<Identified> {
    let names = &sample.names;
    let suffix = if deep {
        "（含一层子目录采样）"
    } else {
        ""
    };

    // ---- 第 1 层：结构规则（**只看直接子项**）----
    //
    // 结构标记说明「这个目录本身是什么」：`~/Projects` 底下有一堆
    // `Cargo.toml`，但那是「一堆项目」，不是「一个 Rust 项目」。
    // 下探采样只用于扩展名主导（下面那条），不用于结构规则。
    for rule in DIR_RULES {
        if deep {
            break;
        }
        let any_ok =
            rule.any_of.is_empty() || rule.any_of.iter().any(|n| names.iter().any(|x| x == n));
        if !any_ok {
            continue;
        }
        if !rule.all_of.iter().all(|n| names.iter().any(|x| x == n)) {
            continue;
        }
        let triggers: Vec<&str> = rule
            .any_of
            .iter()
            .chain(rule.all_of.iter())
            .copied()
            .filter(|n| names.iter().any(|x| x == n))
            .collect();
        return Some(Identified::firm(
            rule.what,
            format!("目录中存在 {} 等特征项{suffix}", triggers.join("、")),
        ));
    }

    // ---- 第 3 层：扩展名主导 ----
    if let Some((ext, count)) = sample.ext_counts.iter().max_by_key(|(_, c)| **c) {
        if *count >= MIN_EXT_SAMPLES {
            let total: usize = sample.ext_counts.values().sum();
            if let Some(what) = ext_rule(ext) {
                let ratio = *count * 100 / total.max(1);
                return Some(Identified {
                    what: format!("{what}（以 .{ext} 为主）"),
                    basis: format!(
                        "{} 个带扩展名的样本中有 {count} 个是 .{ext}（{ratio}%）{suffix}",
                        total
                    ),
                    confident: ratio >= 60,
                });
            }
        }
    }

    // 兜底：说清「看到了什么」，但不给结论
    let dirs = names.len().saturating_sub(sample.file_count);
    Some(Identified::weak(
        "未识别的目录",
        format!(
            "前 {} 个子项中：{} 个文件、{dirs} 个子目录，未匹配到已知结构特征{suffix}",
            names.len().min(MAX_DIR_ENTRIES + 8 * 32),
            sample.file_count
        ),
    ))
}

// ------------------------------------------------------------------ 文件

/// 鉴定一个文件：**先看魔数**，再看前 4 KiB 的文本特征。
pub fn identify_file(path: &Path) -> Option<Identified> {
    let mut f = fs::File::open(path).ok()?;
    let mut buf = vec![0u8; HEAD_BYTES];
    let n = f.read(&mut buf).ok()?;
    buf.truncate(n);
    if buf.is_empty() {
        return Some(Identified::firm("空文件", "长度为 0"));
    }

    // ---- 魔数 ----
    if let Some((what, basis)) = magic(&buf) {
        return Some(Identified::firm(what, basis));
    }

    // ---- 文本特征（必须是文本）----
    if let Some(text) = as_text(&buf) {
        return Some(text_identify(text, &buf));
    }

    Some(Identified::weak(
        "二进制文件",
        "头部既不是已知魔数，也不是可读文本",
    ))
}

/// 魔数表（只需看头部）。
fn magic(b: &[u8]) -> Option<(&'static str, &'static str)> {
    let starts = |p: &[u8]| b.starts_with(p);

    if starts(b"\x7fELF") {
        return Some(("ELF 可执行文件 / 共享库", "魔数 7f 45 4c 46"));
    }
    if starts(b"\x89PNG\r\n\x1a\n") {
        return Some(("PNG 图片", "魔数 89 50 4e 47"));
    }
    if starts(b"\xff\xd8\xff") {
        return Some(("JPEG 图片", "魔数 ff d8 ff"));
    }
    if starts(b"GIF87a") || starts(b"GIF89a") {
        return Some(("GIF 图片", "魔数 GIF8"));
    }
    if starts(b"%PDF") {
        return Some(("PDF 文档", "魔数 25 50 44 46"));
    }
    if starts(b"PK\x03\x04") {
        return Some(("ZIP 归档（可能是文档/安装包/压缩包）", "魔数 50 4b 03 04"));
    }
    if starts(b"Rar!\x1a\x07") {
        return Some(("RAR 压缩包", "魔数 52 61 72 21"));
    }
    if starts(b"7z\xbc\xaf\x27\x1c") {
        return Some(("7z 压缩包", "魔数 37 7a bc af"));
    }
    if starts(b"\x1f\x8b") {
        return Some(("gzip 压缩流", "魔数 1f 8b"));
    }
    if starts(b"\xfd7zXZ\x00") {
        return Some(("xz 压缩流", "魔数 fd 37 7a 58 5a"));
    }
    if starts(b"\x28\xb5\x2f\xfd") {
        return Some(("Zstandard 压缩流", "魔数 28 b5 2f fd"));
    }
    if starts(b"BZh") {
        return Some(("bzip2 压缩流", "魔数 42 5a 68"));
    }
    if b.len() > 262 && &b[257..262] == b"ustar" {
        return Some(("tar 归档", "偏移 257 处为 ustar"));
    }
    if starts(b"SQLite format 3\x00") {
        return Some(("SQLite 数据库", "魔数 SQLite format 3"));
    }
    if b.len() > 12 && &b[4..8] == b"ftyp" {
        return Some(("MP4 / MOV 容器视频", "偏移 4 处为 ftyp"));
    }
    if starts(b"\x1a\x45\xdf\xa3") {
        return Some(("Matroska / WebM 视频", "魔数 1a 45 df a3"));
    }
    if starts(b"OggS") {
        return Some(("Ogg 媒体流", "魔数 4f 67 67 53"));
    }
    if starts(b"fLaC") {
        return Some(("FLAC 无损音频", "魔数 66 4c 61 43"));
    }
    if starts(b"ID3") {
        return Some(("MP3 音频（带 ID3 标签）", "魔数 ID3"));
    }
    if b.len() > 12 && &b[0..4] == b"RIFF" {
        return Some(match &b[8..12] {
            b"WEBP" => ("WebP 图片", "RIFF 容器，类型 WEBP"),
            b"WAVE" => ("WAV 音频", "RIFF 容器，类型 WAVE"),
            b"AVI " => ("AVI 视频", "RIFF 容器，类型 AVI"),
            _ => ("RIFF 容器（音视频/图片）", "魔数 RIFF"),
        });
    }
    if starts(b"II*\x00") || starts(b"MM\x00*") {
        return Some(("TIFF 图片", "魔数 II* 或 MM*"));
    }
    if starts(b"BM") {
        return Some(("BMP 图片", "魔数 42 4d"));
    }
    if starts(b"\x89HDF") {
        return Some(("HDF5 数据文件", "魔数 89 48 44 46"));
    }
    if starts(b"\xed\xab\xee\xdb") {
        return Some(("RPM 安装包", "魔数 ed ab ee db"));
    }
    if starts(b"!<arch>\n") {
        return Some(("ar 归档（常为 .deb 安装包）", "魔数 !<arch>"));
    }
    if starts(b"\xca\xfe\xba\xbe") {
        return Some(("Java class / Mach-O 通用二进制", "魔数 ca fe ba be"));
    }
    if starts(b"wOFF") || starts(b"wOF2") {
        return Some(("WOFF 字体", "魔数 wOFF/wOF2"));
    }
    if starts(b"OTTO") {
        return Some(("OpenType 字体", "魔数 OTTO"));
    }
    if starts(b"\x00\x01\x00\x00") {
        return Some(("TrueType 字体", "魔数 00 01 00 00"));
    }
    None
}

/// 尝试把头部按 UTF-8 文本解读（要求几乎没有控制字符）。
fn as_text(buf: &[u8]) -> Option<&str> {
    if buf.contains(&0) {
        return None;
    }
    let s = std::str::from_utf8(buf).ok()?;
    let total = s.chars().count().max(1);
    let control = s
        .chars()
        .filter(|c| c.is_control() && *c != '\n' && *c != '\r' && *c != '\t')
        .count();
    if control * 100 / total > 2 {
        return None;
    }
    Some(s)
}

/// 取首行的 INI 段名（`[Section]` 形式）。
fn ini_section(t: &str) -> Option<String> {
    let line = t.lines().next()?.trim();
    let inner = line.strip_prefix('[')?.strip_suffix(']')?;
    if inner.is_empty() || !inner.chars().any(|c| c.is_alphabetic()) {
        return None;
    }
    // 段名里不该出现引号/冒号（那更像 JSON 数组里的字符串）
    if inner.contains('"') || inner.contains(':') {
        return None;
    }
    Some(inner.to_string())
}

/// 像不像 JSON：`{...}` 或以 `[` 开头的数组（`["…"`、`[{…`、`[]`、`[ 1, 2]`）。
fn is_json_like(t: &str) -> bool {
    if t.starts_with('{') {
        return true;
    }
    let Some(rest) = t.strip_prefix('[') else {
        return false;
    };
    match rest.trim_start().chars().next() {
        None => true,
        Some(c) => matches!(c, '"' | '{' | ']' | '-') || c.is_ascii_digit(),
    }
}

/// 文本文件的进一步分类。
fn text_identify(text: &str, buf: &[u8]) -> Identified {
    let t = text.trim_start();

    if t.starts_with("<!DOCTYPE html") || t.starts_with("<html") {
        return Identified::firm("HTML 文档", "头部为 <!DOCTYPE html> / <html>");
    }
    if t.starts_with("<?xml") || t.starts_with("<svg") {
        return Identified::firm("XML / SVG 文档", "头部为 XML 声明或 <svg>");
    }
    // ⚠️ 顺序很关键：INI 的段头 `[Desktop Entry]` 也以 `[` 开头，
    // 若先判 JSON 就会把桌面项/服务单元全部误判成 JSON。
    if let Some(section) = ini_section(t) {
        if section == "Desktop Entry" {
            return Identified::firm("桌面项（.desktop）", "首行为 [Desktop Entry] 段");
        }
        if t.contains("ExecStart") || t.contains("[Unit]") {
            return Identified::firm("systemd 单元", "首行为 %SECTION% 段且含 ExecStart");
        }
        if section == "package" && t.contains("name") {
            return Identified::firm("Rust 包描述（Cargo.toml）", "首行为 [package] 段");
        }
        return Identified::weak("INI 风格配置（带 [段]）", format!("首行为 [{section}] 段"));
    }
    if is_json_like(t) {
        return Identified::firm("JSON 数据", "头部为 { 或以 [ 开头的数组");
    }
    if t.starts_with("---\n") || t.starts_with("# ") || t.starts_with("## ") {
        return Identified::firm("Markdown 文档", "头部为 Markdown 标题或 front matter");
    }
    if t.starts_with("#!") {
        let first = t.lines().next().unwrap_or("");
        return Identified::firm("脚本（带 shebang）", format!("首行：{first}"));
    }

    // 行结构与标点密度只能给出弱判断
    let lines = t.lines().take(20).count().max(1);
    let weighted = t
        .lines()
        .take(20)
        .filter(|l| l.contains('=') || l.contains(':'))
        .count();
    if weighted * 2 >= lines {
        return Identified::weak(
            "文本配置（键值形式）",
            format!("前 {lines} 行中有 {weighted} 行是键值/键值对形式"),
        );
    }
    Identified::weak(
        "纯文本文件",
        format!("前 {} 字节可读且无已知结构", buf.len()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct Case {
        dir: PathBuf,
    }

    impl Case {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "dl_ident_{tag}_{}_{:x}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }
        fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let p = self.dir.join(name);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, bytes).unwrap();
            p
        }
    }

    impl Drop for Case {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    // ---- 魔数 ----

    #[test]
    fn identifies_png_and_elf_by_magic() {
        let c = Case::new("magic");
        let png = c.file("a.png", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR");
        let id = identify_file(&png).unwrap();
        assert!(id.what.contains("PNG"), "{:?}", id);
        assert!(id.confident);

        let elf = c.file("a.out", b"\x7fELF\x02\x01\x01\x00");
        assert!(identify_file(&elf).unwrap().what.contains("ELF"));
    }

    #[test]
    fn identifies_pdf_and_zip() {
        let c = Case::new("pdfzip");
        assert!(identify_file(&c.file("a.pdf", b"%PDF-1.7\n"))
            .unwrap()
            .what
            .contains("PDF"));
        assert!(identify_file(&c.file("a.zip", b"PK\x03\x04"))
            .unwrap()
            .what
            .contains("ZIP"));
    }

    #[test]
    fn empty_file_is_identified() {
        let c = Case::new("empty");
        let p = c.file("empty.txt", b"");
        let id = identify_file(&p).unwrap();
        assert!(id.what.contains("空文件"));
        assert!(id.confident);
    }

    // ---- 文本 ----

    #[test]
    fn identifies_json_and_shebang_script() {
        let c = Case::new("text");
        let j = c.file("a.json", br#"{"k": 1}"#);
        assert!(identify_file(&j).unwrap().what.contains("JSON"));

        let sh = c.file("run.sh", b"#!/bin/bash\necho hi\n");
        let id = identify_file(&sh).unwrap();
        assert!(id.what.contains("shebang"), "{:?}", id);
    }

    #[test]
    fn identifies_desktop_entry_and_systemd_unit() {
        let c = Case::new("struct");
        let d = c.file("x.desktop", b"[Desktop Entry]\nName=X\nExec=/bin/x\n");
        assert!(identify_file(&d).unwrap().what.contains("桌面项"));
        let u = c.file("x.service", b"[Unit]\nDescription=x\nExecStart=/bin/x\n");
        assert!(identify_file(&u).unwrap().what.contains("systemd"));
    }

    #[test]
    fn json_identification_does_not_leak_file_content() {
        // 依据里只能出现结构描述，绝不能出现文件内容
        let c = Case::new("noleak");
        let secret = br#"{"password": "hunter2-secret-value"}"#;
        let p = c.file("conf.json", secret);
        let id = identify_file(&p).unwrap();
        assert!(!id.basis.contains("hunter2"), "依据不得包含文件内容");
        assert!(!id.what.contains("hunter2"));
    }

    // ---- 目录 ----

    #[test]
    fn identifies_minecraft_dir_by_structure() {
        let c = Case::new("mc");
        let d = c.dir.join("mc");
        fs::create_dir_all(d.join("saves")).unwrap();
        c.file("mc/options.txt", b"fov:70\n");
        let id = identify_dir(&d).unwrap();
        assert!(id.what.contains("Minecraft"), "{:?}", id);
        assert!(id.confident);
    }

    #[test]
    fn identifies_rust_project_and_git_repo() {
        let c = Case::new("rust");
        let d = c.dir.join("proj");
        fs::create_dir_all(d.join("src")).unwrap();
        c.file("proj/Cargo.toml", b"[package]\nname=\"x\"\n");
        assert!(identify_dir(&d).unwrap().what.contains("Rust"));

        let g = c.dir.join("repo");
        fs::create_dir_all(g.join(".git")).unwrap();
        assert!(identify_dir(&g).unwrap().what.contains("Git 仓库"));
    }

    #[test]
    fn identifies_media_collection_by_extension_majority() {
        let c = Case::new("media");
        let d = c.dir.join("videos");
        for i in 0..10 {
            c.file(&format!("videos/v{i}.mp4"), b"x");
        }
        let id = identify_dir(&d).unwrap();
        assert!(id.what.contains("视频合集"), "{:?}", id);
        assert!(id.confident);
    }

    #[test]
    fn structure_markers_only_count_on_direct_children() {
        // 目录里只有一个子目录含 Cargo.toml → 不能说「我是 Rust 项目」
        let c = Case::new("markerdeep");
        let outer = c.dir.join("container");
        c.file("container/inner/Cargo.toml", b"[package]\nname=\"x\"\n");
        c.file("container/inner/src/main.rs", b"fn main(){}");
        let id = identify_dir(&outer).unwrap();
        assert!(!id.what.contains("Rust"), "结构标记不得由下探触发: {id:?}");
    }

    #[test]
    fn extension_majority_can_use_one_level_down() {
        // 但媒体合集藏在一层目录里时应当能识别
        let c = Case::new("extdeep");
        let outer = c.dir.join("album");
        fs::create_dir_all(outer.join("photos")).unwrap();
        for i in 0..10 {
            c.file(&format!("album/photos/p{i}.jpg"), b"x");
        }
        let id = identify_dir(&outer).unwrap();
        assert!(id.what.contains("图片合集"), "{id:?}");
        assert!(id.confident);
        assert!(id.basis.contains("一层子目录"), "依据应说明下探: {id:?}");
    }

    #[test]
    fn mixed_extensions_are_not_confident() {
        let c = Case::new("mixed");
        let d = c.dir.join("mix");
        for i in 0..5 {
            c.file(&format!("mix/a{i}.mp4"), b"x");
        }
        for i in 0..5 {
            c.file(&format!("mix/b{i}.txt"), b"x");
        }
        let id = identify_dir(&d).unwrap();
        assert!(!id.confident, "五五开时不应给出确信结论: {id:?}");
    }

    #[test]
    fn empty_dir_is_identified_as_empty() {
        let c = Case::new("emptydir");
        let d = c.dir.join("nothing");
        fs::create_dir_all(&d).unwrap();
        let id = identify_dir(&d).unwrap();
        assert!(id.what.contains("空目录"));
        assert!(id.confident);
    }

    #[test]
    fn unknown_dir_is_weak_not_firm() {
        let c = Case::new("unknown");
        let d = c.dir.join("mystery");
        for i in 0..3 {
            c.file(&format!("mystery/a{i}.bin"), b"\x00\x01\x02");
        }
        let id = identify_dir(&d).unwrap();
        assert!(!id.confident, "认不出来就必须标为不确定: {id:?}");
    }

    #[test]
    fn basis_never_contains_file_contents_from_directory_scan() {
        let c = Case::new("dirnoleak");
        let d = c.dir.join("files");
        c.file("files/secret-name-with-password.txt", b"hunter2");
        let id = identify_dir(&d).unwrap();
        assert!(!id.basis.contains("hunter2"));
        // 文件名可以出现（那是结构，不是内容）
        assert!(id.basis.contains("特征项") || id.basis.contains("子项"));
    }
}
