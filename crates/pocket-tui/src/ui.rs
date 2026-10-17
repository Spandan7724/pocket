//! Rendering (STYLES.md). Every frame is drawn from `App` alone.

use pocket_proto::rpc::{PocketState, SessionState, Verdict};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap};

use crate::app::{App, Loaded, Overlay, Row, TABS, Tab, View};
use crate::theme::{self, Theme};

pub fn draw(f: &mut Frame, app: &mut App) {
    let started = std::time::Instant::now();
    let area = f.area();
    let [head, body, foot] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(area);
    header(f, app, head);
    if !app.loaded && app.pockets.is_empty() {
        centered_text(f, body, &app.theme, &["connecting to pocketd…"]);
    } else if app.pockets.is_empty() {
        empty_state(f, app, body);
    } else if app.view == View::Grid {
        grid(f, app, body);
    } else {
        let left_w = (body.width * 38 / 100).clamp(28, 46).min(body.width);
        let [left, right] =
            Layout::horizontal([Constraint::Length(left_w), Constraint::Min(10)]).areas(body);
        tree(f, app, left);
        detail(f, app, right);
    }
    footer(f, app, foot);
    if let Some(o) = &app.overlay {
        overlay(f, app, o, area);
    }
    app.frame_us = started.elapsed().as_micros() as u64;
}

fn human(b: u64) -> String {
    const U: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b}B")
    } else if v < 10.0 {
        format!("{v:.1}{}", U[i])
    } else {
        format!("{v:.0}{}", U[i])
    }
}

fn ago(now_ms: u64, t: u64) -> String {
    let s = now_ms.saturating_sub(t) / 1000;
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m", s / 60),
        3600..=86399 => format!("{}h", s / 3600),
        _ => format!("{}d", s / 86400),
    }
}

fn header(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let sessions: usize = app
        .pockets
        .iter()
        .map(|p| {
            p.sessions
                .iter()
                .filter(|s| s.state != SessionState::Exited)
                .count()
        })
        .sum();
    let waiting: usize = app.pockets.iter().map(|p| p.waiting()).sum();
    let mem: u64 = app
        .pockets
        .iter()
        .filter(|p| matches!(p.info.state, PocketState::Running | PocketState::Paused))
        .map(|p| (p.info.memory_mib as u64) << 20)
        .sum();
    // Most important first; the rest only when it fits.
    let mut parts: Vec<Vec<Span>> = vec![vec![Span::raw(format!(
        "{} pockets · {sessions} sessions",
        app.pockets.len()
    ))]];
    if waiting > 0 {
        parts.push(vec![Span::styled(
            format!("○ {waiting} need input"),
            t.attention(),
        )]);
    }
    parts.push(vec![Span::raw(format!(
        "{} of {} RAM reserved",
        human(mem),
        if app.host_mem > 0 {
            human(app.host_mem)
        } else {
            "?".into()
        }
    ))]);
    parts.push(vec![Span::raw(format!(
        "↑{} req/min",
        app.requests_per_min()
    ))]);
    if !app.connected {
        parts.insert(0, vec![Span::styled("⚠ pocketd unreachable", t.bad())]);
    }
    let budget = area.width.saturating_sub(10) as usize;
    let mut right: Vec<Span> = vec![];
    let mut used = 0;
    for part in parts {
        let w: usize =
            part.iter().map(|s| s.width()).sum::<usize>() + if right.is_empty() { 1 } else { 3 };
        if used + w > budget {
            break;
        }
        if !right.is_empty() {
            right.push(Span::styled(" · ", t.dim()));
        }
        right.extend(part);
        used += w;
    }
    right.push(Span::raw(" "));
    let left = Line::from(vec![
        Span::styled(" pocket ", t.title().add_modifier(Modifier::REVERSED)),
        Span::raw(" "),
    ]);
    let rw: u16 = right.iter().map(|s| s.width() as u16).sum();
    let [l, r] = Layout::horizontal([Constraint::Min(1), Constraint::Length(rw.min(area.width))])
        .areas(area);
    f.render_widget(Paragraph::new(left), l);
    f.render_widget(
        Paragraph::new(Line::from(right)).alignment(Alignment::Right),
        r,
    );
}

fn empty_state(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let lines = vec![
        Line::styled("No pockets yet", t.title()),
        Line::raw(""),
        Line::from(vec![
            Span::raw("Press "),
            Span::styled("n", t.key()),
            Span::raw(" to create your first pocket"),
        ]),
        Line::styled("or run `pocket new` inside a repository", t.dim()),
    ];
    let h = lines.len() as u16;
    let y = area.y + area.height.saturating_sub(h) / 2;
    f.render_widget(
        Paragraph::new(lines).alignment(Alignment::Center),
        Rect::new(area.x, y, area.width, h.min(area.height)),
    );
}

fn centered_text(f: &mut Frame, area: Rect, t: &Theme, lines: &[&str]) {
    let h = lines.len() as u16;
    let y = area.y + area.height.saturating_sub(h) / 2;
    f.render_widget(
        Paragraph::new(
            lines
                .iter()
                .map(|l| Line::styled(*l, t.dim()))
                .collect::<Vec<_>>(),
        )
        .alignment(Alignment::Center),
        Rect::new(area.x, y, area.width, h.min(area.height)),
    );
}

fn block<'a>(t: &Theme, title: impl Into<Line<'a>>, focused: bool) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(t.border(focused))
        .title(title)
}

fn tree(f: &mut Frame, app: &mut App, area: Rect) {
    let t = app.theme;
    let title = if app.filtering || !app.filter.is_empty() {
        Line::from(vec![
            Span::styled(" POCKETS ", t.title()),
            Span::styled(format!("/{}", app.filter), t.accent()),
            Span::raw(if app.filtering { "▏ " } else { " " }),
        ])
    } else {
        Line::styled(" POCKETS ", t.title())
    };
    let b = block(&t, title, !app.interact);
    let inner = b.inner(area);
    f.render_widget(b, area);
    let rows = app.rows();
    let h = inner.height as usize;
    if app.sel < app.tree_offset {
        app.tree_offset = app.sel;
    } else if h > 0 && app.sel >= app.tree_offset + h {
        app.tree_offset = app.sel + 1 - h;
    }
    app.tree_area = inner;
    let name_w = (inner.width as usize).saturating_sub(17).clamp(6, 18);
    let sess_w = name_w.saturating_sub(2).max(4);
    let mut lines = vec![];
    for (n, r) in rows.iter().enumerate().skip(app.tree_offset).take(h) {
        let selected = n == app.sel;
        let line = match *r {
            Row::Pocket(i) => {
                let p = &app.pockets[i];
                let st = &p.info.state;
                let mut spans = vec![
                    Span::raw(if p.expanded && !p.sessions.is_empty() {
                        "▼ "
                    } else {
                        "▶ "
                    }),
                    Span::styled(
                        format!("{:<name_w$}", trunc(&p.info.name, name_w)),
                        t.title(),
                    ),
                    Span::styled(
                        format!(
                            " {} {:<pad$}",
                            theme::pocket_glyph(st),
                            short_state(st, inner.width),
                            pad = if inner.width >= 36 { 10 } else { 0 }
                        ),
                        theme::pocket_style(&t, st),
                    ),
                ];
                if p.waiting() > 0 {
                    spans.push(Span::styled(format!(" ○{}", p.waiting()), t.attention()));
                }
                if p.info.net_mode.as_deref() == Some("full") {
                    spans.push(Span::styled(" ⚠net", t.bad()));
                }
                Line::from(spans)
            }
            Row::Session(i, j) => {
                let p = &app.pockets[i];
                let s = &p.sessions[j];
                let last = j + 1 == p.sessions.len();
                let code = s.info.exited.map(|e| e.code());
                let mut label = if inner.width < 36 && s.state == SessionState::Waiting {
                    "input".to_string()
                } else {
                    theme::session_label(s.state).to_string()
                };
                if let Some(c) = code {
                    label = format!("exit {c}");
                }
                let mut spans = vec![
                    Span::styled(if last { "  └ " } else { "  ├ " }, t.dim()),
                    Span::raw(format!("{:<sess_w$}", trunc(&s.info.name, sess_w))),
                    Span::styled(
                        format!(" {} {label}", theme::session_glyph(s.state, code)),
                        theme::session_style(&t, s.state, code),
                    ),
                ];
                if s.info.attached > 0 {
                    spans.push(Span::styled(format!(" ⇄{}", s.info.attached), t.dim()));
                }
                Line::from(spans)
            }
        };
        lines.push(if selected {
            line.style(t.selected())
        } else {
            line
        });
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn short_state(s: &PocketState, width: u16) -> &str {
    match s {
        PocketState::Hibernated if width < 36 => "hibern.",
        _ => s.label(),
    }
}

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut o: String = s.chars().take(n.saturating_sub(1)).collect();
        o.push('…');
        o
    }
}

fn tabs_line(app: &App, width: u16) -> Line<'static> {
    let t = &app.theme;
    let name = app
        .current_pocket()
        .map(|p| p.info.name.clone())
        .unwrap_or_default();
    let mut spans = vec![
        Span::styled(format!(" {name} "), t.title()),
        Span::raw("─ "),
    ];
    let short = width < 64 + name.chars().count() as u16;
    for (i, tab) in TABS.iter().enumerate() {
        let label = if short {
            format!("{} {}", i + 1, &tab.label()[..3])
        } else {
            format!("{} {}", i + 1, tab.label())
        };
        if *tab == app.tab {
            spans.push(Span::styled(
                format!("[{label}]"),
                t.accent().add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::styled(format!(" {label} "), t.dim()));
        }
        spans.push(Span::raw(" "));
    }
    Line::from(spans)
}

fn detail(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let b = block(t, tabs_line(app, area.width), app.interact);
    let inner = b.inner(area);
    f.render_widget(b, area);
    match app.tab {
        Tab::Session => session_tab(f, app, inner),
        Tab::Diff => diff_tab(f, app, inner),
        Tab::Network => net_tab(f, app, inner),
        Tab::Ports => ports_tab(f, app, inner),
        Tab::Info => info_tab(f, app, inner),
    }
}

fn session_tab(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let Some(p) = app.current_pocket() else {
        return;
    };
    match &p.info.state {
        PocketState::Paused => {
            return centered_text(
                f,
                area,
                t,
                &["‖ paused", "", "⏎ resumes and attaches · p resumes"],
            );
        }
        PocketState::Hibernated => {
            return centered_text(
                f,
                area,
                t,
                &[
                    "◌ hibernated (memory saved to disk)",
                    "",
                    "⏎ resumes and attaches · p resumes",
                ],
            );
        }
        PocketState::Stopped => {
            return centered_text(f, area, t, &["■ stopped", "", "s starts it"]);
        }
        PocketState::Creating => return centered_text(f, area, t, &["◔ creating…"]),
        PocketState::Broken { reason } => {
            let msg = format!("⚠ {reason}");
            return centered_text(
                f,
                area,
                t,
                &[msg.as_str(), "", "s boots it again · x removes it"],
            );
        }
        PocketState::Running => {}
    }
    let Some((p, s)) = app.current_session() else {
        return centered_text(f, area, t, &["no live sessions", "", "t opens a shell"]);
    };
    let [head, body] = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(area);
    let code = s.info.exited.map(|e| e.code());
    let mut spans = vec![
        Span::styled(format!(" {} ", s.info.name), t.title()),
        Span::styled(
            format!(
                "{} {}",
                theme::session_glyph(s.state, code),
                theme::session_label(s.state)
            ),
            theme::session_style(t, s.state, code),
        ),
        Span::styled(
            format!(
                "  {}×{}  {}",
                s.info.size.cols,
                s.info.size.rows,
                trunc(&s.info.argv.join(" "), 40)
            ),
            t.dim(),
        ),
    ];
    if app.interact {
        spans.push(Span::styled("  INTERACT · Ctrl-] leaves", t.attention()));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), head);
    match app.screens.get(&(p.info.name.clone(), s.info.name.clone())) {
        Some(screen) => {
            let parser = screen.lock().unwrap_or_else(|e| e.into_inner());
            crate::pane::draw(parser.screen(), body, f.buffer_mut(), t, app.interact);
        }
        None => centered_text(f, body, t, &["connecting to the session…"]),
    }
}

fn loading<T>(f: &mut Frame, t: &Theme, area: Rect, l: Option<&Loaded<T>>) -> Option<()> {
    match l {
        None | Some(Loaded::Loading) => {
            centered_text(f, area, t, &["loading…"]);
            None
        }
        Some(Loaded::Failed(e)) => {
            f.render_widget(
                Paragraph::new(vec![
                    Line::styled(format!("✗ {e}"), t.bad()),
                    Line::raw(""),
                    Line::styled("r retries", t.dim()),
                ])
                .wrap(Wrap { trim: false }),
                area,
            );
            None
        }
        Some(Loaded::Ready(_)) => Some(()),
    }
}

/// Files and +/- counts of a unified diff.
pub fn diff_files(text: &str) -> Vec<(String, u32, u32)> {
    let mut out: Vec<(String, u32, u32)> = vec![];
    for l in text.lines() {
        if let Some(rest) = l.strip_prefix("diff --git a/") {
            let name = rest.split(" b/").next().unwrap_or(rest).to_string();
            out.push((name, 0, 0));
        } else if let Some(last) = out.last_mut() {
            if l.starts_with('+') && !l.starts_with("+++") {
                last.1 += 1;
            } else if l.starts_with('-') && !l.starts_with("---") {
                last.2 += 1;
            }
        }
    }
    out
}

fn diff_tab(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let Some(p) = app.current_pocket() else {
        return;
    };
    if p.info.repo_path.is_none() {
        return centered_text(f, area, t, &["scratch pocket — no repository to diff"]);
    }
    let d = app.details.get(&p.info.name).and_then(|d| d.diff.as_ref());
    if loading(f, t, area, d).is_none() {
        return;
    }
    let Some(Loaded::Ready(text)) = d else { return };
    if text.trim().is_empty() {
        return centered_text(
            f,
            area,
            t,
            &[
                "✓ no changes yet",
                "",
                "the pocket's branch matches where it started",
            ],
        );
    }
    let files = diff_files(text);
    let (add, del) = files.iter().fold((0, 0), |(a, d), f| (a + f.1, d + f.2));
    let mut lines = vec![Line::from(vec![
        Span::styled(format!(" {} files ", files.len()), t.title()),
        Span::styled(format!("+{add}"), t.added()),
        Span::raw(" "),
        Span::styled(format!("-{del}"), t.removed()),
        Span::styled("   a apply · P pull request · J/K scroll", t.dim()),
    ])];
    for (name, a, d) in files.iter().take(8) {
        lines.push(Line::from(vec![
            Span::raw(format!("  {:<40} ", trunc(name, 40))),
            Span::styled(format!("+{a:<4}"), t.added()),
            Span::styled(format!("-{d}"), t.removed()),
        ]));
    }
    if files.len() > 8 {
        lines.push(Line::styled(
            format!("  … {} more", files.len() - 8),
            t.dim(),
        ));
    }
    lines.push(Line::raw(""));
    for l in text.lines() {
        let style = if l.starts_with("diff --git") {
            t.title()
        } else if l.starts_with("@@") {
            t.hunk()
        } else if l.starts_with("+++") || l.starts_with("---") || l.starts_with("index ") {
            t.dim()
        } else if l.starts_with('+') {
            t.added()
        } else if l.starts_with('-') {
            t.removed()
        } else {
            Style::default()
        };
        lines.push(Line::styled(l.replace('\t', "    "), style));
    }
    f.render_widget(Paragraph::new(lines).scroll((app.detail_scroll, 0)), area);
}

fn net_tab(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let Some(p) = app.current_pocket() else {
        return;
    };
    let mut lines = vec![];
    let pending: Vec<_> = app
        .approvals
        .iter()
        .filter(|a| a.pocket == p.info.name)
        .collect();
    for a in &pending {
        let what = match &a.what {
            pocket_proto::rpc::ApprovalWhat::Network { host, port, reason } => format!(
                "{host}{} — {reason}",
                port.map(|p| format!(":{p}")).unwrap_or_default()
            ),
            pocket_proto::rpc::ApprovalWhat::SshSign { key, comment } => {
                format!("ssh signature with {comment} ({key})")
            }
            pocket_proto::rpc::ApprovalWhat::File { path } => format!("copy host file {path}"),
        };
        lines.push(Line::from(vec![
            Span::styled(" ⚠ wants ", t.attention()),
            Span::raw(what),
        ]));
    }
    if !pending.is_empty() {
        lines.push(Line::from(vec![
            Span::raw("   "),
            Span::styled("o", t.key()),
            Span::raw(" allow once  "),
            Span::styled("A", t.key()),
            Span::raw(" allow for the pocket  "),
            Span::styled("D", t.key()),
            Span::raw(" deny"),
        ]));
        lines.push(Line::raw(""));
    }
    if p.info.net_mode.as_deref() == Some("full") {
        lines.push(Line::styled(
            " ⚠ --net full: this pocket has a real network interface; traffic outside the proxy is not filtered or logged",
            t.bad(),
        ));
        lines.push(Line::raw(""));
    }
    let d = app.details.get(&p.info.name).and_then(|d| d.net.as_ref());
    if loading(
        f,
        t,
        Rect {
            height: area.height,
            ..area
        },
        d,
    )
    .is_none()
        && lines.is_empty()
    {
        return;
    }
    if let Some(Loaded::Ready(entries)) = d {
        lines.push(Line::styled(
            format!(
                " {:<8} {:<10} {:<34} {:<18} {:>4} {:>7} {:>7}",
                "TIME", "VERDICT", "DESTINATION", "REQUEST", "CODE", "UP", "DOWN"
            ),
            t.dim(),
        ));
        if entries.is_empty() {
            lines.push(Line::styled(" no connections yet", t.dim()));
        }
        for e in entries.iter().rev() {
            let secs = e.ts_ms / 1000;
            let (verdict, style) = match e.verdict {
                Verdict::Allowed => ("✓ allowed", t.ok()),
                Verdict::Denied => ("✗ blocked", t.bad()),
            };
            let what = match (&e.method, &e.path) {
                (Some(m), Some(p)) => format!("{m} {p}"),
                (Some(m), None) => m.clone(),
                _ => e.kind.clone(),
            };
            lines.push(Line::from(vec![
                Span::raw(format!(
                    " {:02}:{:02}:{:02} ",
                    (secs / 3600) % 24,
                    (secs / 60) % 60,
                    secs % 60
                )),
                Span::styled(format!("{verdict:<10} "), style),
                Span::raw(format!(
                    "{:<34} ",
                    trunc(&format!("{}:{}", e.host, e.port), 34)
                )),
                Span::raw(format!("{:<18} ", trunc(&what, 18))),
                Span::raw(format!(
                    "{:>4} {:>7} {:>7}",
                    e.status.map(|s| s.to_string()).unwrap_or("-".into()),
                    human(e.bytes_up),
                    human(e.bytes_down)
                )),
                Span::styled(if e.injected { "  ⚿ key" } else { "" }, t.accent()),
            ]));
        }
    }
    f.render_widget(Paragraph::new(lines).scroll((app.detail_scroll, 0)), area);
}

fn ports_tab(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let Some(p) = app.current_pocket() else {
        return;
    };
    let d = app.details.get(&p.info.name).and_then(|d| d.ports.as_ref());
    if loading(f, t, area, d).is_none() {
        return;
    }
    let Some(Loaded::Ready(ports)) = d else {
        return;
    };
    if ports.is_empty() {
        return centered_text(
            f,
            area,
            t,
            &[
                "no forwarded ports",
                "",
                "servers listening in the pocket appear here",
            ],
        );
    }
    let mut lines = vec![Line::styled(
        format!(" {:<8} {:<24} {:<16} {}", "GUEST", "HOST", "PROCESS", "HOW"),
        t.dim(),
    )];
    for (i, f) in ports.iter().enumerate() {
        lines.push(Line::from(vec![
            Span::raw(format!(" {:<8} ", f.guest)),
            Span::styled(
                format!("{:<24} ", format!("127.0.0.1:{}", f.host)),
                t.accent(),
            ),
            Span::raw(format!(
                "{:<16} ",
                f.process.clone().unwrap_or_else(|| "-".into())
            )),
            Span::styled(if f.auto { "auto" } else { "configured" }, t.dim()),
            Span::styled(
                if i == 0 {
                    "   o opens in the browser"
                } else {
                    ""
                },
                t.dim(),
            ),
        ]));
    }
    f.render_widget(Paragraph::new(lines), area);
}

fn info_tab(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let Some(p) = app.current_pocket() else {
        return;
    };
    let i = &p.info;
    let kv = |k: &str, v: String| {
        Line::from(vec![
            Span::styled(format!(" {k:<14}"), t.dim()),
            Span::raw(v),
        ])
    };
    let mut lines = vec![
        kv(
            "state",
            format!("{} {}", theme::pocket_glyph(&i.state), i.state.label()),
        ),
        kv("preset", i.preset.clone()),
        kv("image", trunc(&i.image_digest, 30)),
        kv(
            "resources",
            format!(
                "{} vCPU · {} MiB RAM · {} disk ({} used)",
                i.vcpus,
                i.memory_mib,
                human(i.disk_bytes),
                human(i.disk_used_bytes)
            ),
        ),
        kv(
            "network",
            format!(
                "{} profile · {} mode",
                i.net_profile,
                i.net_mode.clone().unwrap_or_else(|| "proxy".into())
            ),
        ),
        kv(
            "started from",
            i.started_from.clone().unwrap_or_else(|| "-".into()),
        ),
        kv("template", i.template.clone().unwrap_or_else(|| "-".into())),
        kv(
            "repository",
            i.repo_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "none (scratch)".into()),
        ),
        kv("branch", i.branch.clone().unwrap_or_else(|| "-".into())),
        kv(
            "base",
            i.base_ref
                .clone()
                .map(|b| trunc(&b, 12))
                .unwrap_or_else(|| "-".into()),
        ),
        kv("created", format!("{} ago", ago(app.now_ms, i.created_at))),
        kv(
            "last active",
            format!("{} ago", ago(app.now_ms, i.last_active_at)),
        ),
        kv("sessions", format!("{}", p.sessions.len())),
    ];
    if i.net_mode.as_deref() == Some("full") {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            " ⚠ full network access: not filtered by the pocket proxy",
            t.bad(),
        ));
    }
    f.render_widget(Paragraph::new(lines), area);
}

fn grid(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let cells = app.grid();
    if cells.is_empty() {
        return centered_text(
            f,
            area,
            t,
            &["no live sessions to show", "", "g returns to the tree"],
        );
    }
    let shown: Vec<(usize, usize)> = if app.zoom {
        vec![cells[app.grid_focus.min(cells.len() - 1)]]
    } else {
        cells.clone()
    };
    let n = if shown.len() <= 1 {
        1
    } else if shown.len() <= 4 {
        2
    } else {
        3
    };
    let rows = Layout::vertical(vec![Constraint::Ratio(1, n as u32); n]).split(area);
    for (k, &(i, j)) in shown.iter().enumerate() {
        let r = rows[k / n];
        let cols = Layout::horizontal(vec![Constraint::Ratio(1, n as u32); n]).split(r);
        let cell = cols[k % n];
        let p = &app.pockets[i];
        let s = &p.sessions[j];
        let focused = !app.zoom && cells.get(app.grid_focus) == Some(&(i, j)) || app.zoom;
        let code = s.info.exited.map(|e| e.code());
        let title = Line::from(vec![
            Span::styled(format!(" {}:{} ", p.info.name, s.info.name), t.title()),
            Span::styled(
                format!(
                    "{} {} ",
                    theme::session_glyph(s.state, code),
                    theme::session_label(s.state)
                ),
                theme::session_style(t, s.state, code),
            ),
        ]);
        let b = block(t, title, focused);
        let inner = b.inner(cell);
        f.render_widget(b, cell);
        match app.screens.get(&(p.info.name.clone(), s.info.name.clone())) {
            Some(screen) => {
                let parser = screen.lock().unwrap_or_else(|e| e.into_inner());
                crate::pane::draw(parser.screen(), inner, f.buffer_mut(), t, false);
            }
            None => centered_text(f, inner, t, &["connecting…"]),
        }
    }
}

fn hints(app: &App) -> Vec<(&'static str, &'static str)> {
    if app.interact {
        return vec![("Ctrl-]", "back to the dashboard")];
    }
    if app.filtering {
        return vec![("⏎", "keep filter"), ("Esc", "clear")];
    }
    if app.pockets.is_empty() {
        return vec![
            ("n", "new pocket"),
            (":", "commands"),
            ("?", "help"),
            ("q", "quit"),
        ];
    }
    if app.view == View::Grid {
        return vec![
            ("⏎", "attach"),
            ("↑↓", "focus"),
            ("z", "zoom"),
            ("g", "tree"),
            ("?", "help"),
            ("q", "quit"),
        ];
    }
    let mut v = vec![("⏎", "attach"), ("n", "new"), ("t", "shell")];
    match app.tab {
        Tab::Diff => v.extend([("a", "apply"), ("P", "PR")]),
        Tab::Network => v.extend([("o/A/D", "approve")]),
        Tab::Ports => v.push(("o", "open")),
        Tab::Session => v.push(("i", "interact")),
        Tab::Info => {}
    }
    let paused = app
        .current_pocket()
        .is_some_and(|p| matches!(p.info.state, PocketState::Paused | PocketState::Hibernated));
    v.push(("p", if paused { "resume" } else { "pause" }));
    v.extend([
        ("x", "remove"),
        ("g", "grid"),
        ("/", "filter"),
        (":", "commands"),
        ("?", "help"),
    ]);
    v
}

fn footer(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    if let Some((msg, err)) = app.status_line() {
        let style = if err { t.bad() } else { t.accent() };
        f.render_widget(Paragraph::new(Line::styled(format!(" {msg}"), style)), area);
        return;
    }
    let mut h = hints(app);
    let width = |h: &[(&str, &str)]| {
        h.iter()
            .map(|(k, d)| k.chars().count() + d.chars().count() + 4)
            .sum::<usize>()
    };
    // Drop hints from the middle until it fits; `?` (help) and the first stay.
    while h.len() > 2 && width(&h) > area.width as usize {
        h.remove(h.len() - 2);
    }
    let mut spans = vec![Span::raw(" ")];
    for (i, (k, d)) in h.into_iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" · ", t.dim()));
        }
        spans.push(Span::styled(k, t.key()));
        spans.push(Span::raw(format!(" {d}")));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    )
}

pub const HELP: &[(&str, &str)] = &[
    ("↑↓ j k", "move"),
    ("← → h l", "collapse / expand"),
    ("⏎", "attach (full screen; Ctrl-] d returns here)"),
    ("i", "type into the session in the pane (Ctrl-] leaves)"),
    ("Tab 1-5", "Session · Diff · Network · Ports · Info"),
    ("d N P I", "jump to Diff · Network · Ports · Info"),
    ("g / z", "grid of live sessions / zoom one"),
    ("n", "new pocket"),
    ("t", "new shell session"),
    ("p / H", "pause–resume / hibernate"),
    ("s / x", "stop–start / remove (asks first)"),
    ("a / P", "apply / pull request (Diff tab)"),
    (
        "o A D",
        "allow once · allow for pocket · deny (Network tab)",
    ),
    ("o", "open forwarded port (Ports tab)"),
    ("/", "filter"),
    (": Ctrl-P", "command palette"),
    ("T", "theme: dark · light · no colour"),
    ("r", "refresh"),
    ("q", "quit (pockets keep running)"),
];

fn overlay(f: &mut Frame, app: &App, o: &Overlay, area: Rect) {
    let t = &app.theme;
    match o {
        Overlay::Help => {
            let r = centered(area, 70, HELP.len() as u16 + 4);
            f.render_widget(Clear, r);
            let lines: Vec<Line> = HELP
                .iter()
                .map(|(k, d)| {
                    Line::from(vec![
                        Span::styled(format!(" {k:<12}"), t.key()),
                        Span::raw(*d),
                    ])
                })
                .collect();
            let mut lines = lines;
            lines.push(Line::raw(""));
            lines.push(Line::styled(" ● working  ○ input needed  · idle  ‖ paused  ◌ hibernated  ✓ ✗ exited  ⚠ attention", t.dim()));
            f.render_widget(
                Paragraph::new(lines).block(block(t, Line::styled(" keys ", t.title()), true)),
                r,
            );
        }
        Overlay::Palette { query, sel } => {
            let items = App::palette_matches(query);
            let r = centered(area, 60, (items.len() as u16 + 4).min(20));
            f.render_widget(Clear, r);
            let mut lines = vec![Line::from(vec![
                Span::styled(" › ", t.accent()),
                Span::raw(query.clone()),
                Span::raw("▏"),
            ])];
            for (i, it) in items.iter().enumerate() {
                let line = Line::from(vec![
                    Span::raw(format!("   {:<44}", it.label)),
                    Span::styled(it.key, t.key()),
                ]);
                lines.push(if i == *sel {
                    line.style(t.selected())
                } else {
                    line
                });
            }
            if items.is_empty() {
                lines.push(Line::styled("   no matching command", t.dim()));
            }
            f.render_widget(
                Paragraph::new(lines).block(block(t, Line::styled(" commands ", t.title()), true)),
                r,
            );
        }
        Overlay::Wizard(w) => {
            let r = centered(area, 72, w.fields.len() as u16 * 2 + 5);
            f.render_widget(Clear, r);
            let mut lines = vec![];
            for (i, fld) in w.fields.iter().enumerate() {
                let focused = i == w.focus;
                let value = if fld.choices.is_empty() {
                    format!("{}{}", fld.value, if focused { "▏" } else { "" })
                } else {
                    format!("‹ {} ›", fld.value)
                };
                let line = Line::from(vec![
                    Span::styled(
                        format!(" {:<12}", fld.label),
                        if focused { t.accent() } else { t.dim() },
                    ),
                    Span::styled(value, if focused { t.title() } else { Style::default() }),
                ]);
                lines.push(if focused {
                    line.style(t.selected())
                } else {
                    line
                });
                lines.push(Line::styled(format!("             {}", fld.hint), t.dim()));
            }
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                Span::raw(" "),
                Span::styled("⏎", t.key()),
                Span::raw(" create  "),
                Span::styled("↑↓", t.key()),
                Span::raw(" field  "),
                Span::styled("←→", t.key()),
                Span::raw(" choose  "),
                Span::styled("Esc", t.key()),
                Span::raw(" cancel"),
            ]));
            f.render_widget(
                Paragraph::new(lines).block(block(
                    t,
                    Line::styled(" new pocket ", t.title()),
                    true,
                )),
                r,
            );
        }
        Overlay::Confirm {
            title,
            lines,
            stat_for,
            ..
        } => {
            let mut text: Vec<Line> = lines.iter().map(|l| Line::raw(format!(" {l}"))).collect();
            if let Some(p) = stat_for {
                let line = match app.stat.get(p) {
                    None | Some(Loaded::Loading) => {
                        Line::styled(" checking for unapplied work…", t.dim())
                    }
                    Some(Loaded::Failed(e)) => {
                        Line::styled(format!(" could not check for unapplied work: {e}"), t.bad())
                    }
                    Some(Loaded::Ready(s)) if s.trim().is_empty() => {
                        Line::styled(" ✓ no unapplied changes", t.ok())
                    }
                    Some(Loaded::Ready(s)) => Line::styled(
                        format!(" ⚠ unapplied: {}", s.trim().lines().last().unwrap_or("")),
                        t.attention(),
                    ),
                };
                text.insert(0, line);
                text.insert(1, Line::raw(""));
            }
            let r = centered(area, 76, text.len() as u16 + 2);
            f.render_widget(Clear, r);
            f.render_widget(
                Paragraph::new(Text::from(text))
                    .wrap(Wrap { trim: false })
                    .block(block(
                        t,
                        Line::styled(format!(" {title} "), t.attention()),
                        true,
                    )),
                r,
            );
        }
    }
}
