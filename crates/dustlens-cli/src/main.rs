//! DustLens CLI —— 目录整洁度诊断器。
//!
//! **只读**：本程序不做任何删除、移动或写入被扫描目录的动作。
//! 唯一写出的文件是诊断报告（Markdown + JSON），写在仓库的 `diagnostics/` 下（已 gitignore）。

use clap::{Parser, Subcommand};
use dustlens_core as core;
use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "dustlens",
    version,
    about = "目录整洁度诊断器 —— 只声明形式属性并附引用证据，价值判断交给你",
    long_about = "DustLens 只读扫描指定目录，输出一份诊断报告：\n\
                  · 体积异常（目录级，正确聚合文件夹体积）\n\
                  · 规范违规（哪个应用没按 XDG 放东西）\n\
                  · 位置异常（构建产物出现在不该出现的地方）\n\
                  · 说不清（无法归类、无引用的条目）\n\
                  · 引用证据（谁在用 —— 正在用 / 配置指向它 / 无人认领）\n\
                  · 扫描盲区（哪些位置没读到）\n\n\
                  本工具不判断「该不该删」，也不会删除任何东西。"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// 报告输出目录（缺省 ./diagnostics）
    #[arg(short, long, global = true, default_value = "diagnostics")]
    out: PathBuf,

    /// 跳过交互确认（用于脚本；请自行确认扫描范围 —— 设计共识 P7）
    #[arg(short = 'y', long, global = true)]
    yes: bool,

    /// 跟随符号链接（默认不跟随 —— 跨系统引用的常见陷阱）
    #[arg(long, global = true)]
    follow_symlinks: bool,

    /// 允许跨文件系统（默认停留在同一文件系统）
    #[arg(long, global = true)]
    cross_filesystem: bool,

    /// 最大目录深度（默认不限 —— 曾因限制深度导致「0 命中」）
    #[arg(long, global = true)]
    max_depth: Option<usize>,

    /// 并行线程数（0 = 自动）
    #[arg(long, global = true, default_value_t = 0)]
    threads: usize,

    /// 只打印 Markdown 到 stdout，不写文件
    #[arg(long, global = true)]
    stdout_only: bool,

    /// 只打印摘要，不写文件
    #[arg(long, global = true)]
    quiet: bool,

    /// 纳入内置「重灾区」预设（`all` 或逗号分隔的 id，如 `tmp,vartmp,opt`）。
    /// 用 `dustlens presets` 查看清单。
    #[arg(long, global = true, value_name = "SPEC")]
    presets: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// 扫描并生成诊断报告（默认子命令）
    Scan {
        /// 扫描根（可多个；缺省为 $HOME）
        #[arg(value_name = "PATH")]
        roots: Vec<PathBuf>,
    },
    /// 打印默认排除清单（隐私项）
    Excludes,
    /// 打印内置「重灾区」预设清单
    Presets,
    /// 打印可复现的环境信息
    Doctor,
    /// 归档：按版本管理，只能整批恢复
    Archive {
        #[command(subcommand)]
        action: ArchiveAction,
    },
}

#[derive(Subcommand, Debug)]
enum ArchiveAction {
    /// 把条目移入归档（不删除，可整批恢复）
    Create {
        /// 要归档的路径（至少一个）
        #[arg(required = true, value_name = "PATH")]
        paths: Vec<PathBuf>,
        /// 备注（写进 manifest）
        #[arg(long)]
        note: Option<String>,
    },
    /// 列出全部归档版本
    List,
    /// 查看某个版本的明细
    Show {
        #[arg(value_name = "VERSION")]
        version: String,
    },
    /// 整批恢复某个版本（若目标已存在则整批拒绝，绝不覆盖）
    Restore {
        #[arg(value_name = "VERSION")]
        version: String,
    },
    /// 永久销毁某个版本 —— 这是唯一真正释放空间的操作
    Discard {
        #[arg(value_name = "VERSION")]
        version: String,
    },
}

fn main() -> ExitCode {
    let mut cli = Cli::parse();
    let command = cli.command.take();

    match command {
        Some(Command::Excludes) => {
            print_excludes();
            ExitCode::SUCCESS
        }
        Some(Command::Presets) => {
            print_presets();
            ExitCode::SUCCESS
        }
        Some(Command::Doctor) => {
            print_doctor();
            ExitCode::SUCCESS
        }
        Some(Command::Archive { action }) => run_archive(action, &cli),
        Some(Command::Scan { roots }) => run_scan(cli, roots),
        None => run_scan(cli, Vec::new()),
    }
}

fn print_excludes() {
    println!("默认排除清单（这些路径既不进榜，也永远不会被送进 LLM）：\n");
    for rule in core::ExcludeRule::defaults() {
        let shown = rule
            .components
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>()
            .join("/");
        println!("  ~/{shown:<40} {}", rule.reason);
    }
    println!("\n清单可从 `ScanConfig::excludes` 增删（未来会提供 CLI 参数）。");
}

fn print_presets() {
    println!("内置「重灾区」预设 —— 这些目录**不默认扫描**，需显式 `--presets` 才纳入。\n");
    // 中文是双宽字符，`{:<20}` 按 char 补空格会错位 —— 改成逐项成行，不依赖列对齐
    for p in core::presets::PRESETS {
        println!("· {}", p.id);
        println!("    路径   {}", p.path);
        println!("    权限   {}", p.min_privilege.label());
        println!("    为什么 {}", p.why);
        println!();
    }
    println!();
    println!("用法：");
    println!("  dustlens scan --presets all             # 全部预设 + $HOME");
    println!("  dustlens scan ~/x --presets tmp,vartmp   # 指定目录 + 指定预设");
    println!();
    println!("提示：标「多半需要 root」的目录，普通用户读不全；");
    println!("      读不到的部分会在报告的「扫描盲区」里如实列出（不会假装扫过）。");
}

fn print_doctor() {
    let home = core::home_from_env();
    println!("DustLens 环境自检");
    println!("──────────────────────────────");
    println!("版本          {}", core::VERSION);
    println!("报告 schema   {}", core::SCHEMA);
    println!(
        "家目录        {}",
        home.as_deref()
            .map(|h| core::display_path(h, None))
            .unwrap_or_else(|| "(未设置 HOME)".into())
    );
    println!(
        "并行度        {}",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    );
    println!(
        "进程可见性    {} 个 /proc 条目可读",
        core::load_processes().procs.len()
    );
    println!("平台          {}", std::env::consts::OS);
    println!("\n本程序只读：不会删除、移动或修改被扫描的目录。");
}

fn run_scan(cli: Cli, cli_roots: Vec<PathBuf>) -> ExitCode {
    let home = core::home_from_env();

    // 扫描根：缺省为 $HOME（P7：默认值可接受，但必须显式确认）
    let raw_roots: Vec<PathBuf> = if cli_roots.is_empty() {
        match &home {
            Some(h) => vec![h.clone()],
            None => {
                eprintln!("错误：未指定扫描根，且环境变量 HOME 未设置。");
                eprintln!("请显式指定目录，例如： dustlens ~/Projects");
                return ExitCode::FAILURE;
            }
        }
    } else {
        cli_roots
    };

    // ---- 重灾区预设：显式启用才纳入（P7：不擅自扩大扫描范围）----
    let mut raw_roots = raw_roots;
    if let Some(spec) = &cli.presets {
        match core::presets::parse(spec) {
            Ok(list) => {
                let (mut proots, skipped) = core::presets::resolve(&list);
                for s in &skipped {
                    eprintln!("跳过预设 {s}");
                }
                // 用户在 `--presets` 之外没给目录时，不要退化成「只扫预设」之外的空集
                raw_roots.append(&mut proots);
            }
            Err(e) => {
                eprintln!("错误：{e}");
                return ExitCode::FAILURE;
            }
        }
    }

    let roots = match core::normalize_roots(&raw_roots) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("错误：{e}");
            return ExitCode::FAILURE;
        }
    };

    // ---- P7：扫描必须由用户确认 ----
    if !cli.yes {
        if !std::io::stdin().is_terminal() {
            eprintln!("拒绝执行：当前不是交互终端，且未传 --yes。");
            eprintln!("（设计共识 P7 要求扫描前确认扫描范围。脚本场景请显式传 --yes。）");
            return ExitCode::FAILURE;
        }
        if !confirm(&roots, home.as_deref()) {
            println!("已取消。未扫描任何内容。");
            return ExitCode::SUCCESS;
        }
    }

    let mut cfg = core::ScanConfig::new(roots.clone(), home.clone());
    cfg.follow_symlinks = cli.follow_symlinks;
    cfg.one_filesystem = !cli.cross_filesystem;
    cfg.max_depth = cli.max_depth;
    cfg.threads = cli.threads;

    eprintln!("扫描中…（只读，不会修改任何文件）");
    let t0 = std::time::Instant::now();
    let diag = core::run(&cfg, true);
    let elapsed = t0.elapsed();

    if cli.quiet {
        println!("{}", core::report::short_summary(&diag.report));
        eprintln!("用时 {:.2?}", elapsed);
        return ExitCode::SUCCESS;
    }

    if cli.stdout_only {
        print!("{}", diag.markdown);
        return ExitCode::SUCCESS;
    }

    // ---- 写报告 ----
    let stamp = diag.report.generated_at_unix;
    let md_path = cli.out.join(format!("dustlens-{stamp}.md"));
    let json_path = cli.out.join(format!("dustlens-{stamp}.json"));

    if let Err(e) = std::fs::create_dir_all(&cli.out) {
        eprintln!("错误：无法创建输出目录 {}：{e}", cli.out.display());
        return ExitCode::FAILURE;
    }
    if let Err(e) = std::fs::write(&md_path, &diag.markdown) {
        eprintln!("错误：写入 Markdown 失败：{e}");
        return ExitCode::FAILURE;
    }
    if let Some(json) = &diag.json {
        if let Err(e) = std::fs::write(&json_path, json) {
            eprintln!("错误：写入 JSON 失败：{e}");
            return ExitCode::FAILURE;
        }
    }

    println!("{}", core::report::short_summary(&diag.report));
    println!("\n报告已写出：");
    println!("  Markdown  {}", md_path.display());
    println!("  JSON      {}", json_path.display());
    eprintln!("用时 {:.2?}", elapsed);
    ExitCode::SUCCESS
}

/// 交互确认：把「即将扫描什么、不会被外发」讲清楚。
fn confirm(roots: &[PathBuf], home: Option<&std::path::Path>) -> bool {
    println!("即将扫描以下位置（只读）：");
    for r in roots {
        let shown = core::display_path(r, home);
        let tag = if shown.starts_with("$HOME") { "" } else { "   [预设/家目录外]" };
        println!("  {shown}{tag}");
    }
    println!();
    println!("说明：");
    println!("  · 扫描全程在本机进行，不联网、不上传任何内容。");
    println!("  · 默认排除凭据/会话目录（`dustlens excludes` 查看清单）。");
    println!("  · 报告里的路径以 $HOME 字面量表示。");
    println!();
    print!("确认开始扫描？[y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn archive_store(home: Option<&std::path::Path>) -> core::archive::Store {
    // 理论上总能推导出来（有 HOME 即可）；没有则退化为当前目录下的 .dustlens/archive
    core::archive::Store::from_env(home).unwrap_or_else(|| {
        core::archive::Store::at(PathBuf::from(".dustlens").join("archive"))
    })
}

fn run_archive(action: ArchiveAction, cli: &Cli) -> ExitCode {
    let home = core::home_from_env();
    let store = archive_store(home.as_deref());

    match action {
        ArchiveAction::Create { paths, note } => {
            if !cli.yes {
                println!("即将**归档**（可恢复，不是删除）：");
                for p in &paths {
                    println!("  {}", core::display_path(p, home.as_deref()));
                }
                println!();
                println!("归档 = 把这些条目移入版本化归档区。");
                println!("  · 同盘移动：瞬间完成，不占额外空间，但**也不释放空间**");
                println!("  · 之后可用 `dustlens archive restore <版本>` 整批恢复");
                println!("  · 真正释放空间需要 `dustlens archive discard <版本>`");
                println!();
                if !confirm_yes("确认归档？") {
                    println!("已取消。");
                    return ExitCode::SUCCESS;
                }
            }
            match core::archive::create_archive(&store, &paths, home.as_deref(), note) {
                Ok(out) => {
                    println!("{}", core::archive::describe(&out));
                    println!("归档区：{}", out.archive_root.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("归档失败：{e}");
                    ExitCode::FAILURE
                }
            }
        }
        ArchiveAction::List => match core::archive::list_versions(&store) {
            Ok(list) => {
                if list.is_empty() {
                    println!("归档区为空：{}", store.root.display());
                    return ExitCode::SUCCESS;
                }
                println!(
                    "{:<22} {:<12} {:<10} {}",
                    "版本", "条目", "体积", "备注"
                );
                println!("{}", "─".repeat(80));
                for m in &list {
                    let bytes: u64 = m.entries.iter().map(|e| e.bytes).sum();
                    println!(
                        "{:<22} {:<12} {:<10} {}",
                        m.version_id,
                        m.entries.len(),
                        core::human_bytes(bytes),
                        m.note.clone().unwrap_or_default()
                    );
                }
                println!();
                println!("归档区占用：{}", core::human_bytes(core::archive::archive_usage(&store)));
                println!("（归档区占用 ≠ 已释放空间；`discard` 之后才真正释放）");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("读取归档失败：{e}");
                ExitCode::FAILURE
            }
        },
        ArchiveAction::Show { version } => match core::archive::load_manifest(&store, &version) {
            Ok(m) => {
                println!("版本 {}", m.version_id);
                println!("创建于 {}", m.created_at_unix);
                if let Some(n) = &m.note {
                    println!("备注   {n}");
                }
                println!();
                println!("{:<40} {:<8} {:<10}", "路径", "类型", "体积");
                println!("{}", "─".repeat(66));
                for e in &m.entries {
                    println!(
                        "{:<40} {:<8} {:<10}",
                        e.display,
                        e.kind.label(),
                        core::human_bytes(e.bytes)
                    );
                }
                println!();
                println!("恢复：dustlens archive restore {}   （整批，不可单条）", m.version_id);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("找不到版本 {version}：{e}");
                ExitCode::FAILURE
            }
        },
        ArchiveAction::Restore { version } => {
            // 先做完整校验，再执行 —— 全量、单次
            match core::archive::plan_restore(&store, &version) {
                Ok(plan) => {
                    println!("即将**整批恢复**版本 {}：", plan.version_id);
                    for s in &plan.entries {
                        println!("  {}  ({}，{})", s.display, s.kind.label(), core::human_bytes(s.bytes));
                    }
                    println!();
                    println!("说明：若其中任意一个目标位置已存在内容，整批恢复会被拒绝（不会覆盖任何东西）。");
                    println!("      本工具**不支持**按单个条目恢复。");
                    println!();
                    if !cli.yes && !confirm_yes("确认整批恢复？") {
                        println!("已取消。");
                        return ExitCode::SUCCESS;
                    }
                    match core::archive::restore_version(&store, &version) {
                        Ok(n) => {
                            println!("已整批恢复 {n} 个条目。");
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("恢复失败：{e}");
                            ExitCode::FAILURE
                        }
                    }
                }
                Err(e) => {
                    eprintln!("拒绝恢复：{e}");
                    ExitCode::FAILURE
                }
            }
        }
        ArchiveAction::Discard { version } => {
            println!("⚠️  即将**永久销毁**版本 {version} 的全部归档内容。");
            println!("这是不可撤销操作，也是唯一真正释放空间的动作。");
            if !cli.yes && !confirm_yes("确认永久销毁？") {
                println!("已取消。");
                return ExitCode::SUCCESS;
            }
            match core::archive::discard_version(&store, &version) {
                Ok(freed) => {
                    println!("已销毁版本 {version}，释放约 {}。", core::human_bytes(freed));
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("销毁失败：{e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

fn confirm_yes(prompt: &str) -> bool {
    print!("{prompt} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}
