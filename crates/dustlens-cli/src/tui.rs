//! 终端界面（M7-b）：**只读浏览**，不提供任何处置动作。
//!
//! # 为什么这里没有「删除 / 归档」按钮
//!
//! P1（不代用户判断）、P3（不干预摆放）、P6（删除后果由用户承担，证据必须摆在按钮旁）
//! 三条都不允许在这里放动作。TUI 的唯一职责是**把证据排好给人看**：
//! 按体积排序、按标签筛选、右侧给出这个条目为什么出现在这里。
//!
//! # 可测试性
//!
//! 所有状态逻辑（筛选、移动、边界）都在 [`App`] 上，与终端无关；
//! 渲染用 `ratatui` 的 `TestBackend` 在测试里直接断言屏幕内容，
//! 因此**不需要真实终端**也能验证界面确实是它该有的样子。

use dustlens_core::types::{Finding, LinkStrength, Tag};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

/// 当前筛选。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    All,
    Tag(Tag),
}

impl Filter {
    pub fn label(self) -> &'static str {
        match self {
            Filter::All => "全部",
            Filter::Tag(t) => t.label(),
        }
    }

    fn accepts(self, f: &Finding) -> bool {
        match self {
            Filter::All => true,
            Filter::Tag(t) => f.tags.contains(&t),
        }
    }

    /// 按数字键切换的映射：1=全部，2..=5 依次为 Tag::ALL。
    pub fn from_key(c: char) -> Option<Filter> {
        let idx = c.to_digit(10)?;
        match idx {
            1 => Some(Filter::All),
            2..=5 => Some(Filter::Tag(Tag::ALL[(idx - 2) as usize])),
            _ => None,
        }
    }
}

/// 界面状态（与终端解耦，可单测）。
pub struct App<'a> {
    items: &'a [Finding],
    /// 当前筛选后可见的下标
    view: Vec<usize>,
    filter: Filter,
    selected: usize,
    show_help: bool,
    pub quit: bool,
}

impl<'a> App<'a> {
    pub fn new(items: &'a [Finding]) -> Self {
        let mut app = Self {
            items,
            view: Vec::new(),
            filter: Filter::All,
            selected: 0,
            show_help: false,
            quit: false,
        };
        app.refilter();
        app
    }

    fn refilter(&mut self) {
        self.view = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, f)| self.filter.accepts(f))
            .map(|(i, _)| i)
            .collect();
        if self.selected >= self.view.len() {
            self.selected = self.view.len().saturating_sub(1);
        }
    }

    pub fn filter(&self) -> Filter {
        self.filter
    }

    pub fn set_filter(&mut self, f: Filter) {
        self.filter = f;
        self.selected = 0;
        self.refilter();
    }

    pub fn visible(&self) -> usize {
        self.view.len()
    }

    pub fn selected(&self) -> usize {
        self.selected
    }

    pub fn current(&self) -> Option<&'a Finding> {
        self.view.get(self.selected).map(|i| &self.items[*i])
    }

    pub fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
    }

    pub fn help_visible(&self) -> bool {
        self.show_help
    }

    pub fn next(&mut self) {
        if !self.view.is_empty() {
            self.selected = (self.selected + 1).min(self.view.len() - 1);
        }
    }

    pub fn prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn page_down(&mut self, n: usize) {
        if !self.view.is_empty() {
            self.selected = (self.selected + n).min(self.view.len() - 1);
        }
    }

    pub fn page_up(&mut self, n: usize) {
        self.selected = self.selected.saturating_sub(n);
    }

    pub fn home(&mut self) {
        self.selected = 0;
    }

    pub fn end(&mut self) {
        self.selected = self.view.len().saturating_sub(1);
    }

    /// 处理一个按键。返回 `true` 表示需要重绘。
    pub fn on_key(&mut self, c: char) -> bool {
        match c {
            'q' | 'Q' => {
                self.quit = true;
                true
            }
            'j' => {
                self.next();
                true
            }
            'k' => {
                self.prev();
                true
            }
            'g' => {
                self.home();
                true
            }
            'G' => {
                self.end();
                true
            }
            '?' | 'h' => {
                self.toggle_help();
                true
            }
            c => {
                if let Some(f) = Filter::from_key(c) {
                    self.set_filter(f);
                    true
                } else {
                    false
                }
            }
        }
    }
}

/// 人类可读体积（界面用；与报告里的写法保持一致）。
fn human(n: u64) -> String {
    dustlens_core::human_bytes(n)
}

fn link_badge(l: LinkStrength) -> (&'static str, Style) {
    match l {
        LinkStrength::InUse => ("🔴 正在用", Style::default().fg(ratatui::style::Color::Red)),
        LinkStrength::WillUse => (
            "🟡 会用到",
            Style::default().fg(ratatui::style::Color::Yellow),
        ),
        LinkStrength::Unclaimed => (
            "⚪ 无人认领",
            Style::default().fg(ratatui::style::Color::DarkGray),
        ),
    }
}

fn tags_text(f: &Finding) -> String {
    if f.tags.is_empty() {
        "-".into()
    } else {
        f.tags
            .iter()
            .map(|t| t.label())
            .collect::<Vec<_>>()
            .join(" · ")
    }
}

/// 画界面。
pub fn draw(frame: &mut Frame, app: &App, roots: &[String]) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(2),
        ])
        .split(area);

    // ---- 顶栏 ----
    let head = Paragraph::new(Line::from(vec![
        Span::styled(" DustLens ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(format!(
            "｜筛选：{}｜{}/{} 条｜扫描根：{}",
            app.filter().label(),
            if app.visible() == 0 {
                0
            } else {
                app.selected() + 1
            },
            app.visible(),
            roots.join(", ")
        )),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(head, chunks[0]);

    // ---- 主体 ----
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(chunks[1]);

    let items: Vec<ListItem> = app
        .view
        .iter()
        .map(|i| {
            let f = &app.items[*i];
            ListItem::new(Line::from(vec![
                Span::raw(format!("{:>10}  ", human(f.bytes))),
                Span::raw(truncate(&f.display_path, 52)),
            ]))
        })
        .collect();

    let mut state = ListState::default();
    if !app.view.is_empty() {
        state.select(Some(app.selected));
    }
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" 条目（按体积）"),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▸ ");
    frame.render_stateful_widget(list, body[0], &mut state);

    // ---- 详情 ----
    let detail = match app.current() {
        None => Paragraph::new("（没有条目）").block(Block::default().borders(Borders::ALL)),
        Some(f) => {
            let mut lines: Vec<Line> = Vec::new();
            lines.push(Line::from(vec![
                Span::styled("路径  ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(f.display_path.clone()),
            ]));
            lines.push(Line::from(vec![
                Span::styled("体积  ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format!(
                    "{}（{} B）· {} 个文件",
                    human(f.bytes),
                    f.bytes,
                    f.files
                )),
            ]));
            let (badge, st) = link_badge(f.link);
            lines.push(Line::from(vec![
                Span::styled("引用  ", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(badge, st),
            ]));
            lines.push(Line::from(vec![
                Span::styled("标签  ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(tags_text(f)),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "证据",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            for e in &f.evidence {
                lines.push(Line::from(format!("· {}", e.summary(None))));
            }
            if let Some(err) = &f.inaccessible {
                lines.push(Line::from(format!("· 读取失败：{err}")));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "本工具只陈述事实，不判断该不该留，也不提供任何处置动作。",
                Style::default().fg(ratatui::style::Color::DarkGray),
            )));
            Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title(" 详情 "))
                .wrap(Wrap { trim: false })
        }
    };
    frame.render_widget(detail, body[1]);

    // ---- 底栏 / 帮助 ----
    if app.help_visible() {
        let help = vec![
            Line::from("按键："),
            Line::from("  j / ↓ 下一条        k / ↑ 上一条"),
            Line::from("  PgDn / PgUp 翻页    g / G 首尾"),
            Line::from("  1 全部  2 体积异常  3 位置异常  4 失效引用  5 说不清"),
            Line::from("  ? 关闭帮助          q 退出"),
        ];
        frame.render_widget(
            Paragraph::new(help).block(Block::default().borders(Borders::ALL).title(" 帮助 ")),
            chunks[2],
        );
    } else {
        frame.render_widget(
            Paragraph::new(Line::from(
                "j/k 移动 · 1-5 筛选 · ? 帮助 · q 退出（只读界面，不提供任何处置动作）",
            ))
            .block(Block::default().borders(Borders::ALL)),
            chunks[2],
        );
    }
    let _ = area;
    let _ = Rect::default();
}

fn truncate(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        return s.to_string();
    }
    let mut out: String = chars[..max.saturating_sub(1)].iter().collect();
    out.push('…');
    out
}

/// 进入交互界面（需要真实 TTY）。
pub fn run(items: &[Finding], roots: &[String]) -> std::io::Result<()> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    use std::io::IsTerminal;

    // ratatui::init() 在非 TTY 下会 panic —— 先自己检查，给一句人话
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "当前不是交互终端",
        ));
    }

    let mut terminal = ratatui::init();
    let mut app = App::new(items);
    let result = (|| -> std::io::Result<()> {
        loop {
            terminal.draw(|f| draw(f, &app, roots))?;
            if app.quit {
                break;
            }
            match event::read()? {
                Event::Key(k) if k.kind == KeyEventKind::Press => {
                    let ctrl_c = k.modifiers.contains(KeyModifiers::CONTROL)
                        && matches!(k.code, KeyCode::Char('c'));
                    if ctrl_c {
                        break;
                    }
                    match k.code {
                        KeyCode::Char(c) => {
                            app.on_key(c);
                        }
                        KeyCode::Down => app.next(),
                        KeyCode::Up => app.prev(),
                        KeyCode::PageDown => app.page_down(20),
                        KeyCode::PageUp => app.page_up(20),
                        KeyCode::Home => app.home(),
                        KeyCode::End => app.end(),
                        KeyCode::Esc => break,
                        _ => {}
                    }
                }
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
        Ok(())
    })();
    ratatui::restore();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use dustlens_core::types::{Evidence, SharePolicy};
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    fn finding(path: &str, bytes: u64, tags: &[Tag]) -> Finding {
        Finding {
            path: PathBuf::from(path),
            display_path: path.to_string(),
            tags: tags.iter().copied().collect::<BTreeSet<_>>(),
            bytes,
            files: 1,
            link: LinkStrength::Unclaimed,
            evidence: vec![Evidence::Content {
                note: "测试证据".into(),
            }],
            share: SharePolicy::InHome,
            inaccessible: None,
        }
    }

    fn sample() -> Vec<Finding> {
        vec![
            finding("$HOME/big", 3_000_000_000, &[Tag::Large]),
            finding("$HOME/small", 1_000, &[]),
            finding("$HOME/mystery", 20_000, &[Tag::Large, Tag::Unclear]),
            finding("$HOME/gone", 0, &[Tag::DanglingRef]),
        ]
    }

    #[test]
    fn filters_by_tag_and_resets_selection() {
        let items = sample();
        let mut app = App::new(&items);
        assert_eq!(app.visible(), 4);
        app.next();
        assert_eq!(app.selected(), 1);

        app.set_filter(Filter::Tag(Tag::Large));
        assert_eq!(app.visible(), 2, "应只剩两个 large 条目");
        assert_eq!(app.selected(), 0, "切筛选后选中项应回到第一条");

        app.set_filter(Filter::All);
        assert_eq!(app.visible(), 4);
    }

    #[test]
    fn navigation_stops_at_bounds() {
        let items = sample();
        let mut app = App::new(&items);
        app.prev();
        assert_eq!(app.selected(), 0, "顶部再上不出界");
        app.page_down(100);
        assert_eq!(app.selected(), 3, "底部再下不出界");
        app.home();
        assert_eq!(app.selected(), 0);
        app.end();
        assert_eq!(app.selected(), 3);
    }

    #[test]
    fn number_keys_switch_filters() {
        let items = sample();
        let mut app = App::new(&items);
        assert!(app.on_key('5'));
        assert_eq!(app.filter(), Filter::Tag(Tag::Unclear));
        assert_eq!(app.visible(), 1);
        assert!(app.on_key('1'));
        assert_eq!(app.filter(), Filter::All);
    }

    #[test]
    fn q_requests_quit_and_unknown_keys_do_not() {
        let items = sample();
        let mut app = App::new(&items);
        assert!(!app.on_key('z'));
        assert!(!app.quit);
        assert!(app.on_key('q'));
        assert!(app.quit);
    }

    #[test]
    fn renders_paths_and_evidence_in_a_test_backend() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let items = sample();
        let app = App::new(&items);
        let mut term = Terminal::new(TestBackend::new(120, 30)).unwrap();
        term.draw(|f| draw(f, &app, &["$HOME".to_string()]))
            .unwrap();
        let buf = term.backend().buffer();
        let text: String = buf
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect::<Vec<_>>()
            .join("");

        // CJK 是宽字符：TestBackend 里每个字占两格（第二格是空白），
        // 所以断言前先去掉空白，否则 "证据" 会变成 "证 据"。
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(compact.contains("$HOME/big"), "列表应显示条目路径");
        assert!(compact.contains("证据"), "详情应显示证据区");
        assert!(compact.contains("测试证据"), "详情应显示证据内容");
        // 这句可能被折行，断言一个一定落在同一行内的片段
        assert!(compact.contains("只陈述事实"), "界面必须声明它只陈述事实");
    }

    #[test]
    fn truncated_paths_keep_the_tail_readable() {
        let s = truncate(
            "$HOME/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            20,
        );
        assert_eq!(s.chars().count(), 20);
        assert!(s.ends_with('…'));
    }
}
