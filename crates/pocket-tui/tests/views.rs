//! Snapshot tests of every dashboard view (the scenes `cargo xtask preview-tui` shows), plus
//! the 50-pocket frame time and the "never blocks on the daemon" property.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use pocket_tui::app::{Cmd, Update};
use pocket_tui::scenes;

fn snap(name: &str, w: u16, h: u16) {
    let mut app = scenes::scene(name).unwrap();
    let buf = scenes::render(&mut app, w, h);
    insta::assert_snapshot!(name, scenes::text(&buf));
}

#[test]
fn every_scene_has_a_snapshot() {
    for name in scenes::SCENES {
        snap(name, 120, 32);
    }
}

#[test]
fn narrow_terminal() {
    let mut app = scenes::scene("session").unwrap();
    let buf = scenes::render(&mut app, 80, 24);
    insta::assert_snapshot!("narrow-80x24", scenes::text(&buf));
}

/// State is never colour-only: the mono theme still shows every glyph and label.
#[test]
fn mono_keeps_glyphs_and_words() {
    let mut app = scenes::scene("mono").unwrap();
    let t = scenes::text(&scenes::render(&mut app, 120, 32));
    for s in [
        "● running",
        "‖ paused",
        "◌ hibernated",
        "○ input needed",
        "· idle",
        "✓ exit 0",
        "⚠net",
    ] {
        assert!(t.contains(s), "{s} missing:\n{t}");
    }
    let buf = scenes::render(&mut app, 120, 32);
    for c in buf.content() {
        assert_eq!(
            c.fg,
            ratatui::style::Color::Reset,
            "mono theme used a colour"
        );
    }
}

#[test]
fn fifty_pockets_render_well_within_a_frame() {
    let mut app = scenes::scene("fifty").unwrap();
    let mut times = vec![];
    for i in 0..60 {
        // Scroll through the list like a user holding ↓.
        app.sel = i % 50;
        let t = Instant::now();
        scenes::render(&mut app, 200, 60);
        times.push(t.elapsed());
    }
    times.sort();
    let p50 = times[times.len() / 2];
    let p95 = times[times.len() * 95 / 100];
    eprintln!("50 pockets, 200×60: frame p50 {p50:?}, p95 {p95:?}");
    // 60 fps budget, with room for an unoptimized test build.
    assert!(p95 < Duration::from_millis(16), "p95 {p95:?}");
}

struct Stuck {
    rx: mpsc::Receiver<Update>,
    sent: std::cell::RefCell<Vec<Cmd>>,
}

impl pocket_tui::Source for Stuck {
    fn send(&self, cmd: Cmd) {
        self.sent.borrow_mut().push(cmd);
    }
    fn try_recv(&self) -> Option<Update> {
        self.rx.try_recv().ok()
    }
}

/// With a worker that never answers, keys and frames keep flowing.
#[test]
fn a_stuck_daemon_never_stalls_the_ui() {
    let (_tx, rx) = mpsc::channel();
    let src = Stuck {
        rx,
        sent: Default::default(),
    };
    let mut app = scenes::scene("session").unwrap();
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let started = Instant::now();
    for i in 0..200 {
        pocket_tui::run::pump(&mut app, &src);
        let code = [
            KeyCode::Down,
            KeyCode::Up,
            KeyCode::Tab,
            KeyCode::Char('d'),
            KeyCode::Char('x'),
            KeyCode::Esc,
        ][i % 6];
        let (cmds, _) = app.key(KeyEvent::new(code, KeyModifiers::NONE));
        for c in cmds {
            pocket_tui::Source::send(&src, c);
        }
        scenes::render(&mut app, 120, 32);
    }
    let took = started.elapsed();
    eprintln!(
        "200 key + frame iterations with an unresponsive daemon: {took:?}; {} requests queued",
        src.sent.borrow().len()
    );
    assert!(took < Duration::from_secs(2));
    assert!(
        !src.sent.borrow().is_empty(),
        "requests were queued, not awaited"
    );
}

#[test]
fn palette_and_wizard_flows() {
    use pocket_tui::app::{Action, Overlay};
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let k = |c| KeyEvent::new(c, KeyModifiers::NONE);
    let mut app = scenes::scene("session").unwrap();
    app.key(k(KeyCode::Char(':')));
    for c in "hiber".chars() {
        app.key(k(KeyCode::Char(c)));
    }
    let (cmds, _) = app.key(k(KeyCode::Enter));
    assert_eq!(
        cmds,
        vec![Cmd::Pocket("webapp-1".into(), Action::Hibernate)]
    );

    app.key(k(KeyCode::Char('n')));
    for c in "demo".chars() {
        app.key(k(KeyCode::Char(c)));
    }
    for _ in 0..5 {
        app.key(k(KeyCode::Down));
    }
    app.key(k(KeyCode::Right));
    let (cmds, _) = app.key(k(KeyCode::Enter));
    let Some(Cmd::New(spec)) = cmds.last() else {
        panic!("{cmds:?}")
    };
    assert_eq!(spec.name.as_deref(), Some("demo"));
    assert_eq!(spec.net, "strict");
    assert!(app.overlay.is_none());

    // Removing asks first and says what is lost.
    let (cmds, _) = app.key(k(KeyCode::Char('x')));
    assert_eq!(cmds, vec![Cmd::LoadStat("webapp-1".into())]);
    assert!(matches!(app.overlay, Some(Overlay::Confirm { .. })));
    let (cmds, _) = app.key(k(KeyCode::Char('n')));
    assert!(cmds.is_empty() && app.overlay.is_none());
}
