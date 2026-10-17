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

    /// 扫描根（可多次指定；缺省为 $HOME）
    #[arg(value_name = "PATH", global = true)]
    roots: Vec<PathBuf>,

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
}

#[derive(Subcommand, Debug)]
enum Command {
    /// 扫描并生成诊断报告（默认子命令）
    Scan,
    /// 打印默认排除清单（隐私项）
    Excludes,
    /// 打印可复现的环境信息
    Doctor,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Excludes) => {
            print_excludes();
            ExitCode::SUCCESS
        }
        Some(Command::Doctor) => {
            print_doctor();
            ExitCode::SUCCESS
        }
        Some(Command::Scan) | None => run_scan(cli),
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

fn run_scan(cli: Cli) -> ExitCode {
    let home = core::home_from_env();

    // 扫描根：缺省为 $HOME（P7：默认值可接受，但必须显式确认）
    let raw_roots: Vec<PathBuf> = if cli.roots.is_empty() {
        match &home {
            Some(h) => vec![h.clone()],
            None => {
                eprintln!("错误：未指定扫描根，且环境变量 HOME 未设置。");
                eprintln!("请显式指定目录，例如： dustlens ~/Projects");
                return ExitCode::FAILURE;
            }
        }
    } else {
        cli.roots.clone()
    };

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
        println!("  {}", core::display_path(r, home));
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
