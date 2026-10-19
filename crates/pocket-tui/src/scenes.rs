//! Representative dashboard states, for `cargo xtask preview-tui` and the snapshot tests.

use std::sync::{Arc, Mutex};

use pocket_proto::guest::{ExitStatus, PtySize, SessionInfo};
use pocket_proto::rpc::{
    ApprovalInfo, ApprovalWhat, NetEntry, PocketInfo, PocketState, PortInfo, SessionState, Verdict,
};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{App, Details, Loaded, PocketRow, SessionRow, Tab, View};
use crate::theme::{Mode, Theme};

pub const NOW: u64 = 1_792_300_000_000;

pub const SCENES: &[&str] = &[
    "session", "diff", "network", "ports", "info", "grid", "wizard", "palette", "help", "confirm",
    "empty", "interact", "light", "mono", "fifty",
];

fn info(name: &str, state: PocketState, repo: bool) -> PocketInfo {
    PocketInfo {
        id: format!("{name}-id"),
        name: name.into(),
        state,
        preset: "base".into(),
        image_digest: "sha256:cd549319b1741248f0aa".into(),
        repo_path: repo.then(|| "/home/dev/code/webapp".into()),
        base_ref: repo.then(|| "4f2a9c1e0b7d".into()),
        branch: repo.then(|| format!("pocket/{name}")),
        vcpus: 2,
        memory_mib: 2048,
        disk_bytes: 20 << 30,
        disk_used_bytes: 412 << 20,
        net_profile: "dev".into(),
        created_at: NOW - 3_600_000,
        last_active_at: NOW - 40_000,
        started_from: Some("pool".into()),
        template: Some("2ac8b6f87166f04a0603".into()),
        net_mode: Some("proxy".into()),
    }
}

fn session(name: &str, argv: &[&str], state: SessionState, attached: u32) -> SessionRow {
    let exited = (state == SessionState::Exited).then_some(ExitStatus::Code(0));
    SessionRow {
        info: SessionInfo {
            name: name.into(),
            pid: 42,
            argv: argv.iter().map(|a| a.to_string()).collect(),
            created_unix_ms: NOW - 3_000_000,
            size: PtySize {
                rows: 30,
                cols: 100,
            },
            attached,
            exited,
            last_output_unix_ms: NOW - 1_000,
            last_bell_unix_ms: 0,
            tail: String::new(),
        },
        state,
    }
}

fn screen(text: &str) -> crate::app::Screen {
    let mut p = vt100::Parser::new(30, 100, 0);
    p.process(text.as_bytes());
    Arc::new(Mutex::new(p))
}

const CLAUDE: &str = "\x1b[1m\x1b[38;5;208m✻ Claude Code\x1b[0m\r\n\r\n\
\x1b[2m> \x1b[0mAdd rate limiting to the /login route\r\n\r\n\
\x1b[38;5;208m●\x1b[0m I'll add a token bucket in \x1b[1msrc/middleware/ratelimit.ts\x1b[0m.\r\n\r\n\
  \x1b[32m⎿ Wrote 48 lines to src/middleware/ratelimit.ts\x1b[0m\r\n\
  \x1b[32m⎿ Updated src/routes/login.ts (+3 -1)\x1b[0m\r\n\r\n\
\x1b[38;5;208m●\x1b[0m Running the tests…\r\n\
  \x1b[2mnpm test -- login\x1b[0m\r\n\
  \x1b[32m✓ 14 passed\x1b[0m\r\n\r\n\
\x1b[38;5;208m✻ Thinking…\x1b[0m \x1b[2m(12s · esc to interrupt)\x1b[0m\r\n";

const CODEX: &str = "\x1b[1mcodex\x1b[0m  \x1b[2mgpt-5 · /work\x1b[0m\r\n\r\n\
\x1b[36muser\x1b[0m fix the flaky date test\r\n\r\n\
\x1b[35mcodex\x1b[0m The test depends on the local timezone. I want to run:\r\n\r\n\
  \x1b[1mTZ=UTC npm test -- dates\x1b[0m\r\n\r\n\
\x1b[33mAllow this command? [y/n]\x1b[0m ";

const DIFF: &str = "diff --git a/src/middleware/ratelimit.ts b/src/middleware/ratelimit.ts
new file mode 100644
index 0000000..3b18e51
--- /dev/null
+++ b/src/middleware/ratelimit.ts
@@ -0,0 +1,12 @@
+import type { Request, Response, NextFunction } from \"express\";
+
+const buckets = new Map<string, { tokens: number; at: number }>();
+
+export function rateLimit(perMinute = 10) {
+  return (req: Request, res: Response, next: NextFunction) => {
+    const key = req.ip ?? \"anon\";
+    const b = buckets.get(key) ?? { tokens: perMinute, at: Date.now() };
+    if (b.tokens <= 0) return res.status(429).end();
+    b.tokens--; buckets.set(key, b); next();
+  };
+}
diff --git a/src/routes/login.ts b/src/routes/login.ts
index 9a1c0d2..e4b77f0 100644
--- a/src/routes/login.ts
+++ b/src/routes/login.ts
@@ -1,6 +1,8 @@
 import { Router } from \"express\";
+import { rateLimit } from \"../middleware/ratelimit\";

 const r = Router();
-r.post(\"/login\", login);
+r.post(\"/login\", rateLimit(5), login);
 export default r;
";

fn net(
    host: &str,
    port: u16,
    verdict: Verdict,
    method: Option<&str>,
    path: Option<&str>,
    injected: bool,
    t: u64,
) -> NetEntry {
    NetEntry {
        pocket: "webapp-1".into(),
        ts_ms: NOW - t,
        kind: if method.is_some() {
            "http".into()
        } else {
            "connect".into()
        },
        host: host.into(),
        ip: Some("140.82.112.3".into()),
        port,
        method: method.map(String::from),
        path: path.map(String::from),
        status: method.map(|_| 200),
        bytes_up: 2_400,
        bytes_down: 48_000,
        verdict,
        reason: if verdict == Verdict::Denied {
            "not in the dev profile".into()
        } else {
            String::new()
        },
        injected,
    }
}

/// The three-pocket fleet from TUI.md.
pub fn fleet(mode: Mode) -> App {
    let mut a = App::new(Theme::new(mode));
    a.now_ms = NOW;
    a.host_mem = 31 << 30;
    a.loaded = true;
    let mut web = PocketRow {
        info: info("webapp-1", PocketState::Running, true),
        sessions: vec![
            session("claude", &["claude"], SessionState::Working, 0),
            session("codex", &["codex"], SessionState::Waiting, 0),
            session(
                "shell",
                &["/bin/sh", "-c", "exec \"${SHELL:-/bin/sh}\" -l"],
                SessionState::Idle,
                1,
            ),
        ],
        expanded: true,
    };
    web.sessions[1].info.tail = "Allow this command? [y/n]".into();
    let mut api = info("api-fix", PocketState::Paused, true);
    api.started_from = Some("template".into());
    let mut scratch = info("scratch", PocketState::Hibernated, false);
    scratch.started_from = Some("hibernation".into());
    let mut full = info("netlab", PocketState::Running, false);
    full.net_mode = Some("full".into());
    a.pockets = vec![
        PocketRow {
            info: api,
            sessions: vec![session("claude", &["claude"], SessionState::Idle, 0)],
            expanded: false,
        },
        PocketRow {
            info: full,
            sessions: vec![session("build", &["make"], SessionState::Exited, 0)],
            expanded: true,
        },
        PocketRow {
            info: scratch,
            sessions: vec![],
            expanded: false,
        },
        web,
    ];
    a.sel = a
        .rows()
        .iter()
        .position(
            |r| matches!(*r, crate::app::Row::Pocket(i) if a.pockets[i].info.name == "webapp-1"),
        )
        .unwrap_or(0);
    a.screens
        .insert(("webapp-1".into(), "claude".into()), screen(CLAUDE));
    a.screens
        .insert(("webapp-1".into(), "codex".into()), screen(CODEX));
    a.screens.insert(("webapp-1".into(), "shell".into()), screen("dev@webapp-1:/work$ npm run dev\r\n\x1b[32m  VITE v6.2  ready in 312 ms\x1b[0m\r\n  ➜  Local: http://localhost:5173/\r\n"));
    let d = Details {
        diff: Some(Loaded::Ready(DIFF.into())),
        net: Some(Loaded::Ready(vec![
            net(
                "api.anthropic.com",
                443,
                Verdict::Allowed,
                Some("POST"),
                Some("/v1/messages"),
                true,
                4_000,
            ),
            net(
                "registry.npmjs.org",
                443,
                Verdict::Allowed,
                None,
                None,
                false,
                60_000,
            ),
            net(
                "cdn.jsdelivr.net",
                443,
                Verdict::Denied,
                None,
                None,
                false,
                30_000,
            ),
            net(
                "github.com",
                443,
                Verdict::Allowed,
                Some("POST"),
                Some("/o/r.git/git-receive-pack"),
                true,
                9_000,
            ),
        ])),
        ports: Some(Loaded::Ready(vec![
            PortInfo {
                guest: 5173,
                host: 5173,
                process: Some("node".into()),
                auto: true,
            },
            PortInfo {
                guest: 5432,
                host: 15432,
                process: Some("postgres".into()),
                auto: false,
            },
        ])),
    };
    a.details.insert("webapp-1".into(), d);
    a.approvals = vec![ApprovalInfo {
        id: 7,
        pocket: "webapp-1".into(),
        what: ApprovalWhat::Network {
            host: "cdn.jsdelivr.net".into(),
            port: Some(443),
            reason: "not in the dev profile".into(),
        },
        created_ms: NOW - 30_000,
    }];
    for i in 0..37 {
        a.requests.push_back(NOW - i * 1500);
    }
    a
}

pub fn fifty() -> App {
    let mut a = App::new(Theme::new(Mode::Dark));
    a.now_ms = NOW;
    a.host_mem = 31 << 30;
    a.loaded = true;
    let states = [
        PocketState::Running,
        PocketState::Running,
        PocketState::Paused,
        PocketState::Hibernated,
        PocketState::Stopped,
    ];
    for n in 0..50 {
        let st = states[n % states.len()].clone();
        let running = st == PocketState::Running;
        let sessions = if running {
            vec![
                session(
                    "claude",
                    &["claude"],
                    if n % 3 == 0 {
                        SessionState::Waiting
                    } else {
                        SessionState::Working
                    },
                    0,
                ),
                session("shell", &["/bin/sh"], SessionState::Idle, 0),
            ]
        } else {
            vec![]
        };
        a.pockets.push(PocketRow {
            info: info(&format!("agent-{n:02}"), st, true),
            sessions,
            expanded: running,
        });
        if running {
            a.screens
                .insert((format!("agent-{n:02}"), "claude".into()), screen(CLAUDE));
        }
    }
    a
}

pub fn scene(name: &str) -> Option<App> {
    let key = |a: &mut App, c: KeyCode| {
        a.key(KeyEvent::new(c, KeyModifiers::NONE));
        // `key` reads the wall clock; scenes stay pinned to NOW.
        a.now_ms = NOW;
    };
    Some(match name {
        "session" => fleet(Mode::Dark),
        "diff" => {
            let mut a = fleet(Mode::Dark);
            a.tab = Tab::Diff;
            a
        }
        "network" => {
            let mut a = fleet(Mode::Dark);
            a.tab = Tab::Network;
            a
        }
        "ports" => {
            let mut a = fleet(Mode::Dark);
            a.tab = Tab::Ports;
            a
        }
        "info" => {
            let mut a = fleet(Mode::Dark);
            a.tab = Tab::Info;
            a
        }
        "grid" => {
            let mut a = fleet(Mode::Dark);
            a.view = View::Grid;
            a
        }
        "wizard" => {
            let mut a = fleet(Mode::Dark);
            a.cwd_repo = Some("/home/dev/code/webapp".into());
            key(&mut a, KeyCode::Char('n'));
            a
        }
        "palette" => {
            let mut a = fleet(Mode::Dark);
            key(&mut a, KeyCode::Char(':'));
            for c in "pa".chars() {
                key(&mut a, KeyCode::Char(c));
            }
            a
        }
        "help" => {
            let mut a = fleet(Mode::Dark);
            key(&mut a, KeyCode::Char('?'));
            a
        }
        "confirm" => {
            let mut a = fleet(Mode::Dark);
            key(&mut a, KeyCode::Char('x'));
            a.stat.insert(
                "webapp-1".into(),
                Loaded::Ready(" 2 files changed, 15 insertions(+), 1 deletion(-)".into()),
            );
            a
        }
        "empty" => {
            let mut a = App::new(Theme::new(Mode::Dark));
            a.loaded = true;
            a.now_ms = NOW;
            a.host_mem = 31 << 30;
            a
        }
        "interact" => {
            let mut a = fleet(Mode::Dark);
            a.sel += 1;
            key(&mut a, KeyCode::Char('i'));
            a.status = None;
            a
        }
        "light" => fleet(Mode::Light),
        "mono" => fleet(Mode::Mono),
        "fifty" => fifty(),
        _ => return None,
    })
}

pub fn render(app: &mut App, w: u16, h: u16) -> ratatui::buffer::Buffer {
    let mut t = ratatui::Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
    t.draw(|f| crate::ui::draw(f, app)).unwrap();
    t.backend().buffer().clone()
}

/// The buffer as plain text, one line per row (snapshot tests).
pub fn text(buf: &ratatui::buffer::Buffer) -> String {
    let a = buf.area;
    let mut out = String::new();
    for y in 0..a.height {
        let mut line = String::new();
        for x in 0..a.width {
            line.push_str(buf[(x, y)].symbol());
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// The buffer with SGR colours, for showing a scene in a real terminal.
pub fn ansi(buf: &ratatui::buffer::Buffer) -> String {
    use ratatui::style::{Color, Modifier};
    fn sgr(c: Color, fg: bool) -> String {
        let base = if fg { 30 } else { 40 };
        match c {
            Color::Reset => format!("{}", base + 9),
            Color::Black => format!("{base}"),
            Color::Red => format!("{}", base + 1),
            Color::Green => format!("{}", base + 2),
            Color::Yellow => format!("{}", base + 3),
            Color::Blue => format!("{}", base + 4),
            Color::Magenta => format!("{}", base + 5),
            Color::Cyan => format!("{}", base + 6),
            Color::Gray => format!("{}", base + 7),
            Color::DarkGray => format!("{}", base + 60),
            Color::LightRed => format!("{}", base + 61),
            Color::LightGreen => format!("{}", base + 62),
            Color::LightYellow => format!("{}", base + 63),
            Color::LightBlue => format!("{}", base + 64),
            Color::LightMagenta => format!("{}", base + 65),
            Color::LightCyan => format!("{}", base + 66),
            Color::White => format!("{}", base + 67),
            Color::Indexed(i) => format!("{};5;{i}", base + 8),
            Color::Rgb(r, g, b) => format!("{};2;{r};{g};{b}", base + 8),
        }
    }
    let a = buf.area;
    let mut out = String::new();
    for y in 0..a.height {
        for x in 0..a.width {
            let c = &buf[(x, y)];
            let m = c.modifier;
            let mut codes = vec!["0".to_string(), sgr(c.fg, true), sgr(c.bg, false)];
            for (bit, code) in [
                (Modifier::BOLD, "1"),
                (Modifier::DIM, "2"),
                (Modifier::ITALIC, "3"),
                (Modifier::UNDERLINED, "4"),
                (Modifier::REVERSED, "7"),
            ] {
                if m.contains(bit) {
                    codes.push(code.into());
                }
            }
            out.push_str(&format!("\x1b[{}m{}", codes.join(";"), c.symbol()));
        }
        out.push_str("\x1b[0m\n");
    }
    out
}
