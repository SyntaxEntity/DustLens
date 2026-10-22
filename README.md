# DustLens

![Rust](https://img.shields.io/badge/Rust-1.94%2B-blue?style=for-the-badge&logo=rust)
![status](https://img.shields.io/badge/status-M5%20identify%20ready-blue?style=for-the-badge)
![license](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)
![DeepSeek Assisted Development](https://img.shields.io/badge/DeepSeek%20Assisted-Development-brightgreen?style=for-the-badge&logo=deepseek)

> 目录整洁度诊断器 —— 只声明形式属性、附上引用证据，把「需不需要」的判断权完整交给用户。

> 版本 `0.1.0`（与 `Cargo.toml` 一致）｜ 状态：**M5 可用**（诊断 + 内容鉴定 + 归属 + 失效引用 + 冗余副本 + 归档）｜ 已知限制见 [已知限制](#已知限制)

---

## 功能

现有工具回答「**哪些是垃圾**」；DustLens 回答「**这东西是什么、谁在用、删了会怎样**」。

它不替你判断价值，只做三件事：

1. **找出让目录看上去不干净的东西** —— 规范不符的存放、奇怪的位置、异常的体积、无人认领的残留
2. **为每一项附上可复算的引用证据** —— 谁在用它、谁生成它、删了会怎样
3. **把判断权交还给你**

> **判定原则：工具只声明形式属性，并附上引用证据；价值判断永远由用户完成，工具不代劳、也不暗示。**

### 隐私边界

**本工具会扫描你的文件系统。请先读完这一节再决定是否使用。**

#### 扫描与上传是两件事

| | 是否离开本机 | 说明 |
|---|---|---|
| **扫描** | ❌ **不出本机** | 纯本地只读。路径、体积、时间戳都在本机处理 |
| **送 LLM** | ✅ **仅在用户主动触发时** | 只有当你点击某一条的「交由 LLM 分析」时才发送 |

**扫描范围可以开得很宽，因为它不涉及隐私；真正受约束的是「送出去」这一步。**

#### 送出去的是什么

| 维度 | 内容 |
|---|---|
| **获取什么** | 送 LLM 的只有：**脱敏元数据**（路径以 `$HOME` 字面量表示）+ **系统上下文**。<br>**绝不发送文件内容**（唯一例外：你手动点击分析的单个小文本文件） |
| **什么时候** | **仅当你触发 LLM 时**。不触发就不发送 |
| **干什么用** | 生成「这是什么」的一句话说明。**不用于任何自动操作** |
| **给谁** | **你自己配置的 API 端点**。本工具不做中转、不留副本 |

送出的系统上下文（用于让模型判断目录结构约定，避免瞎猜）：

```
发行版      Fedora / UOS / ...
桌面环境    GNOME / KDE / XFCE     ← 决定 XDG 遵守程度
包管理器    rpm / dpkg / pacman     ← 决定溯源查询方式
家目录      $HOME（脱敏为字面量）
```

> **光知道发行版不够**：目录结构约定主要由**桌面环境**和**包管理器**决定。

#### 三条硬边界

1. **默认排除清单**：`~/.ssh`、`~/.gnupg`、`~/.local/share/keyrings`、浏览器配置、云凭据（`~/.aws`、`~/.config/gh`）等
   **既不出现在结果里，也永远不会被送进 LLM**。被排除的项**在进榜之前就被拦掉**，不属于任何分区。
   清单可见、可增删。
2. **`$HOME` 之外需显式同意**：目标位于家目录之外时，会明确提示「需要上传完整路径，请注意隐私」并等你确认。
3. **不配置 LLM 也能用**：基础层（体积排序 + 引用证据 + 规范审计）**完全不依赖 LLM**，是完整可用的产品。

#### 定位是诚实优先

**它就是靠 LLM 做鉴定的工具。** 担心隐私，你有三个选择：
把敏感目录放进排除清单、干脆不配 LLM、或者**自己部署**一个本地模型端点。

### 条目与标签：属性不是类别

工具产出一张**统一条目表**，每条路径只出现一次，形式属性以**标签**表达：

| 标签 | 含义 |
|---|---|
| `large` | 体积异常（≥ 门槛） |
| `odd_location` | 位置异常（构建产物出现在不该出现的地方） |
| `dangling_ref` | 失效引用（配置或符号链接指向的目标不存在） |
| `unclear` | 判定失败：说不出「这是什么」 |

**一条路径可以同时有多个标签** —— 一个 92 GiB 又认不出来的目录既是 `large` 也是 `unclear`。
早先用「互斥分区」表达，导致 `large` 与 `unclear` 互相抢条目、「说不清」长期为空。

> **标签只用于筛选与分组，不决定排序** —— 排序永远按体积降序。

### 内容鉴定：这是什么（M5）

**不依赖 LLM** 地回答「这是什么」，三层依据从硬到软：

| 层 | 依据 | 强度 |
|---|---|---|
| 1 | **目录结构**（`saves/`+`options.txt`、`Cargo.toml`、`.git`…） | 强：结构不是猜的 |
| 2 | **文件魔数**（ELF / PNG / PDF / ZIP / SQLite…） | 强：只看前 16 字节 |
| 3 | **前 4 KiB 文本特征**（JSON / 脚本 / Markdown / systemd unit…） | 中：观察头部 |

```
$HOME/Pictures         → 图片合集（以 .png 为主）
$HOME/Projects/MemStack → Rust 项目（含构建描述）
/opt/wechat            → ELF 可执行文件 / 共享库
```

三条硬约束：

- **只读、只在本机**：不联网、不上传，报告里只出现**文件名与结构**，不出现文件内容
- **不确定性要标出来**：标为「不确定」的结论**不会**用来把条目移出「说不清」——
  用猜测消灭不确定性等于自欺
- **不猜价值**：只说「这是什么」，不说「该不该留」

能被确定性识别的条目会自动移出「说不清」分区。

**「说不清」的定义是「判定失败」，与体积无关**：它列出所有工具无法确定性说出
「这是什么」的条目（可能很大，也可能是小目录）。每条会附上「已掌握的线索」，
让你知道工具看到了什么、缺的是什么。

### 归属：谁装的（P0）

对每条结果查一次「这个路径属于哪个软件包」——这是**可查询的客观事实**，不是猜测：

| 来源 | 查询方式 |
|---|---|
| rpm | `rpm -qf`（Fedora / RHEL / openSUSE） |
| dpkg | `dpkg -S`（Debian / Ubuntu） |
| pacman | `pacman -Qo`（Arch） |
| flatpak | 按安装布局的路径推导（零进程开销） |

```
/opt/wechat       归属 rpm：包 wechat 4.1.13.5-1
/opt/QQ           归属 rpm：不属于任何包（用户手动安装或应用自建）
```

**「不属于任何包」是一个结论，不是失败。** 它和「没查到」是两件事：
本机没有可用包管理器时会明说「无法判断」，绝不会猜。

### 失效引用（P1）

两类「B 类孤儿」，都是**最容易自动化**的判据：

```
① 配置里记录的路径已不存在
$HOME/Downloads/xxx.zip   ← $HOME/.config/JetBrains/CLion2026.2/options/project.default.xml

② 符号链接指向的目标已消失
$HOME/.steampath       → $HOME/.steam/sdk32/steam
$HOME/.dsh/profiles/node_modules 下 74 个符号链接 → 目标已移除的全局安装
```

**只陈述事实**：不推断「所以那个应用该删」。目标本身已经不在了，没有可归档的内容。

为了不刷屏，这条判据有多道过滤器（见 `## 已知限制`）：
配置类只读「像配置」的文件、要求父目录存在；符号链接类跳过非路径目标
（Chromium 的 `SingletonLock` 指向 `hostname-pid`）与运行时锁，并在报告中按目录聚合。

### 终端界面（M7）

`dustlens tui` 打开一个**只读**的交互界面：左边按体积列出条目，右边给出它为什么在这里。

```
┌ DustLens ｜筛选：全部｜3/63 条｜扫描根：$HOME ────────────────────┐
│ ▸    92.7 GiB  $HOME/Games/arknights   │ 路径  $HOME/Games/...   │
│       79.6 GiB  $HOME/Documents/A408   │ 体积  92.7 GiB · ...    │
│       43.1 GiB  $HOME/Projects         │ 引用  ⚪ 无人认领        │
│                                        │ 标签  体积异常 · 说不清   │
│                                        │ 证据                    │
│                                        │ · 这是什么：游戏安装目录  │
└ 按键：j/k 移动 · 1-5 筛选 · ? 帮助 · q 退出 ──────────────────┘
```

**界面里没有任何处置动作** —— 没有删除、没有移动、没有归档按钮。
P1/P3/P6 三条都不允许：工具只负责把证据排好，判断由你完成。

按键：`j/k`（或 ↑↓）移动 · `PgUp/PgDn` 翻页 · `g/G` 首尾 ·
`1` 全部 / `2` 体积异常 / `3` 位置异常 / `4` 失效引用 / `5` 说不清 · `?` 帮助 · `q` 退出。

### 配置文件（M7）

`~/.config/dustlens/config.toml`，写一次即可，不用每次敲一长串参数。

```toml
[scan]
roots = ["$HOME", "/var/tmp"]
presets = ["tmp", "opt"]

[thresholds]
large = "100 MiB"        # 二进制单位：KiB = 1024
loose = "10 MiB"

[features]
provenance = true
dangling = true
duplicates = true
identify = true
dup_min_bytes = "1 MiB"

[exclude]
patterns = ["node_modules", ".git"]   # 路径片段，不是通配符
```

**优先级：命令行 > 配置文件 > 内置默认值** —— 命令行永远赢。

配置文件**不能**：开启任何自动删除、关闭脱敏、或改变「只诊断不处置」的定位。

### 冗余副本（M4）

内容**逐字节相同**的多份文件，按组列出：

```
组 1 · 499 MiB × 2 份 · 可回收 499 MiB
  $HOME/Documents/A408/…/01.高数基础01.mp4
  $HOME/Documents/A408/…/01.高数基础01【务必关注公众号…】.mp4
```

**不指定留哪一份** —— 只按组罗列成员（P1）。

判定用三级过滤，最后一级是**实际逐字节比对**，不是哈希猜测：

| 级别 | 依据 | 成本 |
|---|---|---|
| 1 | 尺寸相同 | 零 IO |
| 2 | 前 16 KiB 相同 | 每文件读 16 KiB |
| 3 | 逐字节相同 | 只对少量幸存者读全文 |

报告里还给出**按区域的分布**（例如「38 GiB 在 Steam 里、509 MiB 在 Documents 里」），
因为「可回收 42 GiB」这个总量本身很容易被误读 —— Steam 的各个 Proton 版本各自带同一份运行时库，
内容相同但是必需的。

### 版本化归档（M2）

诊断之外，DustLens 可以把条目**移出视野**而不销毁：

```bash
dustlens archive create ~/scratch/old build-tmp      # 移入版本化归档
dustlens archive list                                # 列出全部版本
dustlens archive show <版本>                          # 看某版本明细
dustlens archive restore <版本>                       # 整批恢复
dustlens archive discard <版本>                       # 永久销毁（真正释放空间）
```

**两条硬约束**（不是 UI 约定，是 API 形状）：

- **只能按版本整批恢复** —— 本工具**没有**「恢复某个条目」的能力。想单独取回某个文件，
  请自己在文件管理器里从归档目录拿。
- **恢复绝不覆盖** —— 只要有一个目标位置已存在内容，**整批恢复被拒绝**，不会动任何文件。

归档格式是可读目录（`~/.local/share/dustlens/archive/<版本>/payload/`），
你可以直接用 `ls` 查看，不需要任何专门工具解包。

> **注意**：归档是**移动**，不是删除。同盘移动不占额外空间，但**也不释放空间** ——
> 真正的空间释放发生在 `archive discard`。

### 重灾区预设

默认只扫家目录。**家目录之外最容易堆垃圾的地方**整理成了可选预设：

```bash
dustlens presets                                  # 查看清单
dustlens scan --presets all                       # 全部预设 + 家目录
dustlens scan ~/x --presets tmp,vartmp            # 指定预设 + 指定目录
```

预设**不默认启用**（扫描范围必须由你确认）。清单：
`/tmp` · `/var/tmp` · `/opt` · `/srv` · `/var/cache` · `/var/log` · `/var/lib/flatpak`。

### 能力分层

| 层 | 能力 | 需要 LLM |
|---|---|---|
| **基础层** | 目录级体积正确排序 · 引用证据 · 规范审计 | ❌ |
| **鉴定层** | 「这是什么」的自然语言说明 | ✅ |

**基础层不是阉割版**。文件管理器按大小排序时**不会把文件夹大小算进去** ——
仅仅「正确的目录级体积排序 + 引用证据」就已经是别处拿不到的东西。
对于本来就认识自己文件的人，不配 LLM 也够用。

---

## 安装

**尚无发布产物**（无二进制包、无包管理器分发）。当前唯一方式是[从源码构建](#构建开发)。

```bash
git clone git@github.com:SyntaxEntity/DustLens.git
cd DustLens
cargo build --release --offline
# 产物：target/release/dustlens
```

> `--offline` 仅在依赖已缓存于本地时可用；正常情况下去掉它即可。

---

## 使用

```bash
# 环境自检
dustlens doctor

# 查看默认隐私排除清单
dustlens excludes

# 扫描家目录（默认值；会先投影范围并要求确认）
dustlens

# 扫描指定目录，把报告写到 diagnostics/
dustlens ~/Projects -o diagnostics

# 只打印 Markdown 到 stdout
dustlens ~/Projects --stdout-only

# 只看摘要
dustlens ~/Projects --quiet

# 脚本场景跳过交互确认（自行承担责任：扫什么由你指定）
dustlens scan ~/Projects --yes

# 纳入「重灾区」预设
dustlens scan --presets all

# 关闭某个探测（默认都开）
dustlens scan ~/x --no-provenance     # 不 fork 包管理器
dustlens scan ~/x --no-dangling       # 不查失效引用
dustlens scan ~/x --no-duplicates     # 不查冗余副本（最省时间）
dustlens scan ~/x --no-identify       # 不做内容鉴定

# 配置文件（写一次，不用每次敲一长串）
dustlens tui                          # 只读终端界面：浏览、筛选、看证据
dustlens config --init                # 生成 ~/.config/dustlens/config.toml
dustlens config                       # 查看实际生效的配置
dustlens --config /path/to.toml scan  # 指定配置文件
dustlens scan ~/x --dup-min-bytes 10485760   # 只比对 ≥10 MiB 的文件

# 归档（可恢复，不是删除）
dustlens archive create ~/old-stuff --note "旧项目"
dustlens archive list
dustlens archive restore <版本>
dustlens archive discard <版本>
```

**常用选项**：

| 选项 | 作用 |
|---|---|
| `--max-depth N` | 限制深度（默认**不限**；限制会在报告里留下「盲区」记录） |
| `--follow-symlinks` | 跟随符号链接（默认不跟随） |
| `--cross-filesystem` | 允许跨文件系统（默认停留同一文件系统） |
| `--threads N` | 并行线程数（0 = 自动） |
| `-o DIR` | 报告输出目录（默认 `diagnostics/`，已 gitignore） |

产物：`diagnostics/dustlens-<unix>.md` + `.json`（JSON 为主数据，Markdown 为视图）。

**本程序只读** —— 不删除、不移动、不修改被扫描目录中的任何文件。

## 构建（开发）

```bash
cargo build --release    # 构建 CLI
cargo test               # 单元测试（54 项）
cargo build --offline    # 依赖已缓存时可用
```

依赖来自 crates.io（`serde` / `serde_json` / `walkdir` / `clap`）。

---

## 项目结构

```
DustLens/
├── Cargo.toml                     # workspace
├── crates/
│   ├── dustlens-cli/
│   │   ├── tui.rs                 # 只读终端界面（无任何处置动作）
│   ├── dustlens-core/             # 核心库（无 GUI、不联网）
│   │   └── src/
│   │       ├── types.rs           # 数据模型（引用强度三级、Finding、ScanGap）
│   │       ├── scan.rs            # BFS 并行扫描 + 盲区记录
│   │       ├── refs.rs            # 引用证据（/proc + 配置）
│   │       ├── detect.rs          # 四类检测器
│   │       ├── archive.rs         # 版本化归档（整批恢复，禁止单条）
│   │       ├── provenance.rs      # 归属：rpm / dpkg / pacman / flatpak
│   │       ├── dangling.rs        # 失效引用（七道噪音过滤）
│   │       ├── duplicates.rs      # 冗余副本（三级过滤 + 逐字节核对）
│   │       ├── identify.rs        # 内容鉴定（结构 / 魔数 / 头部文本，不依赖 LLM）
│   │       ├── config.rs          # 配置文件（TOML；命令行 > 配置 > 默认值）
│   │       ├── presets.rs         # 重灾区预设
│   │       └── report.rs          # JSON + Markdown 渲染
│   └── dustlens-cli/              # 命令行（clap）
├── README.md                      # 本文件：面向用户
├── LICENSE                        # MIT
├── AGENTS.md                      # 面向 AI 协作者
├── docs/
│   ├── DustLens-设计共识.md        # 设计决策（唯一权威）
│   ├── DustLens-思路提炼.md        # 方法论抽象层
│   └── DustLens-M5后测量.md        # M5 后的残差量化
└── diagnostics/                   # 报告输出（gitignore）
```

> 另有两份第一手素材文档（真实清理台账）**保留在本地、不随本仓库发布**。

---

## 技术栈

| 项 | 值 |
|---|---|
| 语言 | Rust 1.94+（MSRV，`cargo +1.94.0 build --offline` 实测通过） |
| 依赖 | `serde` / `serde_json` / `walkdir` / `clap` |
| 平台 | 先 Linux；之后可能 Windows；**macOS 明确不做** |
| 界面 | 暂缓。**先验证 core**；倾向 core 与 UI 解耦 |
| LLM | 用户自配 API 端点（工具不做中转） |

---

## 已知限制

- **只在 Fedora + btrfs + GNOME + Wayland 上跑过**；其它发行版/桌面环境/文件系统**未验证**。
- **平台**：只实现 Linux（`/proc` 依赖在此）。Windows **未构建、未运行**；macOS **明确不做**。
- **没有「永久删除」命令**：DustLens 只提供「归档」与「销毁归档」两步。删除永远先经过归档区。
- **无 GUI、无 LLM**：全部交互在命令行；「这是什么」的自然语言说明尚未实现。
- **不含权限审计**：`/etc/hosts` 权限异常那类问题本版本不检查。
- **「正在使用」是瞬时快照**：编译/索引等短命进程会让目录暂时显示为占用，几分钟后就变回「无人认领」。
  报告里会注明这一点。
- **规范违规只覆盖家目录根下的隐藏目录**；非隐藏目录（用户自己的文件夹）刻意不判为应用的错。
- **归属只覆盖 rpm / dpkg / pacman / flatpak**；其它包管理器（snap / nix / Gentoo / AppImage）
  会如实报「无法判断」，**不会猜**。扫描家目录时绝大多数条目会是「不属于任何包」——
  这很正常，家目录里的东西本来就不是包管理器装的。
- **失效引用只判定家目录内的目标**，且只读「像配置」的文件（`.json/.toml/.ini/.conf/.desktop/…`）。
  运行期日志与数据库（leveldb 的 `LOG`、`MANIFEST-*`）被排除在外 ——
  否则它们里面含空格的路径会产生成批假阳性。
- **死符号链接的判定**：只报「目标为绝对路径且目标不存在」的链接；
  `Singleton*` / `SS` / `Socket` 这类运行时锁与 socket 不报（它们本来就该失效）；
  同一目录下有多条时在报告里聚合为一行。
- **冗余副本会读文件内容**：家目录级扫描（25k 个 ≥1 MiB 文件）约多花 **1–2 分钟**。
  不想付这个成本就加 `--no-duplicates`，或把 `--dup-min-bytes` 调高。
- **去重默认门槛 1 MiB**：更小的文件不参与比对（否则 IO 成本失控）。
- **明细有上限**：报告最多列 100 组、每组最多 20 个成员；
  但摘要里的「组数 / 可回收」是**全量真实统计**，不是截断值。
- **内容鉴定是启发式**：结构规则只看直接子项；扩展名主导向最多下探一层。
  认不出来就标「未识别」，**不会**用猜测把条目移出「说不清」。
- **鉴定只读头部 4 KiB 与目录项名字**，不读文件全文；报告里不出现文件内容。
- **「位置异常」判据很窄**：只认**随手区域**（`Downloads` / `Desktop` / `Templates`）与扫描根之下的构建产物。
  更深的位置视为用户有意组织，不做判定。
- **归档不保留**：硬链接会退化成独立副本；扩展属性 / ACL / 所有权（uid/gid）不保留。
- **扫描盲区会计入报告但不会自动重试**：`--max-depth`、跨文件系统、未跟随的符号链接、权限不足
  都会如实列出，且**这些位置的体积未计入统计**。
- **`will_use`（配置指向它）是文本匹配**：配置文件里出现的路径字符串即算命中，
  注释或示例里的提及也会算进去（偏保守，宁可多报「有人指向它」）。
- **徽章依赖外部服务**：徽章图片来自 shields.io，离线环境不显示。

---

## 路线图

| 阶段 | 内容 | 状态 |
|---|---|---|
| M0 | 设计冻结：定位、八条不定项、引用证据三级、隐私模型 | ✅ 完成 |
| **M1** | **core**：BFS 扫描 + 目录级体积聚合 + 引用证据三级 + 四类检测 + 盲区披露 + JSON/Markdown | ✅ **完成**（v0.1.0） |
| **M2** | **归档与恢复**：按版本整批恢复、冲突整批拒绝、`discard` 真正释放空间 | ✅ **完成** |
| **M4** | **冗余副本**：尺寸 → 前 16 KiB → 逐字节三级过滤 + 区域分布 | ✅ **完成** |
| **M5** | **内容鉴定**：目录结构 / 魔数 / 前 4 KiB 文本，**不依赖 LLM** | ✅ **完成** |
| M6 | LLM 鉴定层（用户自配端点，默认关闭） | ⏳ 未开始 |
| M7 | 可配置（`~/.config/dustlens/config.toml`）+ TUI | ⏳ 未开始 |
| M8 | GUI | ⏳ 暂缓，待 M1–M6 有真实使用数据 |

**明确不做**：`macOS` · 系统监控仪表盘 · 启动项管理 · 一键清理 · 多许可证布局

## 项目文档

| 文件 | 内容 |
|---|---|
| [`DustLens-设计共识.md`](docs/DustLens-设计共识.md) | **当前唯一权威**：全部设计决策 + 理由 + 变更记录 |
| [`DustLens-思路提炼.md`](docs/DustLens-思路提炼.md) | 方法论抽象层：六个推理模式、七个可复用信号 |
| [`DustLens-M5后测量.md`](docs/DustLens-M5后测量.md) | M5 之后的残差量化：LLM 还有多少事可做 |
| [`AGENTS.md`](AGENTS.md) | 面向 AI 协作者：红线、不定项、文档地图 |

---

## 反馈

本项目处于设计冻结、代码未开工阶段。**此时反馈设计本身最有价值** ——
尤其是：你希望它回答哪些「这是什么」的问题、哪些目录你觉得最该被点名。

请通过 [Issues](https://github.com/SyntaxEntity/DustLens/issues) 提出。

---

## 许可证

**MIT** ｜ SPDX：`MIT` ｜ 全文见 [`LICENSE`](LICENSE)

Copyright (c) 2026 DustLens contributors

可自由使用、修改、分发，包括商业用途；条件是保留版权声明与许可声明。
软件按「原样」提供，不附带任何担保。

---

## DeepSeek Assisted Development

![DeepSeek Assisted Development](https://img.shields.io/badge/DeepSeek%20Assisted-Development-brightgreen?style=for-the-badge&logo=deepseek)

本仓库代码由 **DeepSeek** 辅助编写（vibecoding）。AI 生成的代码可能包含缺陷、过时用法或不完整实现，
请自行评估后使用与集成。
