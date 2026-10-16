//! `pocket attach` (TUI.md §1): the user's terminal becomes the session's terminal.
//! Bytes pass through unmodified in both directions; only the detach prefix (`Ctrl-]`) is
//! intercepted. Menus draw on the alternate screen (or, if the guest owns it, are followed
//! by a forced repaint), so nothing pocket draws corrupts a guest TUI.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pocket_proto::frame::{recv, send};
use pocket_proto::guest::{AttachIn, AttachOut, ExitStatus, MAX_CHUNK, PtySize, StreamOpen};
use pocket_proto::rpc::{Request, Response};

use crate::client::Client;
use crate::error::{CliError, Result};
use crate::term::{self, AltTracker, GUEST_ALT, RawGuard};
use crate::vsock;

pub const PREFIX: u8 = 0x1d; // Ctrl-]
/// Terminal replies to queries replayed from scrollback arrive as input; such reply
/// sequences are dropped in this window after attaching.
const REPLAY_QUIET: Duration = Duration::from_millis(300);

static WINCH_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_winch(_: libc::c_int) {
    let fd = WINCH_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        // SAFETY: write(2) is async-signal-safe.
        unsafe { libc::write(fd, [1u8].as_ptr().cast(), 1) };
    }
}

fn winch_pipe() -> i32 {
    static PIPE: std::sync::OnceLock<i32> = std::sync::OnceLock::new();
    *PIPE.get_or_init(new_winch_pipe)
}

fn new_winch_pipe() -> i32 {
    let mut fds = [0; 2];
    // SAFETY: pipe2 into a local array; handler installed after the fd is published.
    unsafe {
        libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK);
        WINCH_FD.store(fds[1], Ordering::Relaxed);
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_winch as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGWINCH, &sa, std::ptr::null_mut());
    }
    fds[0]
}

fn out(b: &[u8]) {
    let mut o = std::io::stdout().lock();
    let _ = o.write_all(b);
    let _ = o.flush();
}

enum End {
    Detached,
    Exited(ExitStatus),
    Switch(Option<String>),
    NewShell,
    Lost(String),
}

struct Shared {
    /// Output held back while a pocket overlay is on screen.
    held: Mutex<Option<Vec<u8>>>,
    /// The guest screen as the user sees it, to restore what a notice covered.
    mirror: Mutex<vt100::Parser>,
    /// A clipboard write waiting for Ctrl-] y (`ui.clipboard_osc52 = "ask"`).
    clip: Mutex<Option<Vec<u8>>>,
    notices: std::sync::mpsc::Sender<String>,
    notice_wake: i32,
}

impl Shared {
    fn notify(&self, text: String) {
        if self.notices.send(text).is_ok() {
            // SAFETY: write(2) on our own pipe.
            unsafe { libc::write(self.notice_wake, [1u8].as_ptr().cast(), 1) };
        }
    }
}

struct Session {
    stream: UnixStream,
    wake_r: i32,
    exit: Arc<Mutex<Option<std::result::Result<ExitStatus, String>>>>,
    shared: Arc<Shared>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Session {
    fn open(
        uds: &Path,
        session: &str,
        token: Vec<u8>,
        notices: std::sync::mpsc::Sender<String>,
        notice_wake: i32,
    ) -> Result<Session> {
        let (rows, cols) = term::size();
        let stream = vsock::open(
            uds,
            &StreamOpen::Attach {
                session: session.into(),
                size: PtySize { rows, cols },
                replay_scrollback: true,
                token,
            },
        )?;
        let mut fds = [0; 2];
        // SAFETY: pipe2 into a local array.
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        let (wake_r, wake_w) = (fds[0], fds[1]);
        let exit = Arc::new(Mutex::new(None));
        let shared = Arc::new(Shared {
            held: Mutex::new(None),
            mirror: Mutex::new(vt100::Parser::new(rows, cols, 0)),
            clip: Mutex::new(None),
            notices,
            notice_wake,
        });
        let mut clip = crate::notice::Osc52::new(crate::notice::clipboard_policy());
        let mut rd = stream.try_clone().map_err(|e| CliError::io("attach", e))?;
        let (exit2, shared2) = (exit.clone(), shared.clone());
        let reader = std::thread::spawn(move || {
            let mut alt = AltTracker::default();
            let result = loop {
                match recv::<_, AttachOut>(&mut rd) {
                    Ok(Some(AttachOut::Data(d))) => {
                        let (d, held) = clip.feed(&d);
                        for h in held {
                            match h {
                                crate::notice::Held::Ask(seq) => {
                                    shared2.notify(format!(
                                        "the pocket wants to set your clipboard ({} bytes) — Ctrl-] y to allow",
                                        seq.len()
                                    ));
                                    *shared2.clip.lock().unwrap() = Some(seq);
                                }
                                crate::notice::Held::Blocked(n) => shared2.notify(format!(
                                    "blocked a clipboard write of {n} bytes (ui.clipboard_osc52 = \"deny\")"
                                )),
                            }
                        }
                        if d.is_empty() {
                            continue;
                        }
                        shared2.mirror.lock().unwrap().process(&d);
                        alt.feed(&d);
                        let mut held = shared2.held.lock().unwrap();
                        match held.as_mut() {
                            Some(buf) => buf.extend_from_slice(&d),
                            None => {
                                drop(held);
                                out(&d);
                            }
                        }
                    }
                    Ok(Some(AttachOut::Exited(st))) => break Ok(st),
                    Ok(None) => break Err("the pocket closed the session stream".to_string()),
                    Err(e) => break Err(format!("session stream: {e}")),
                }
            };
            *exit2.lock().unwrap() = Some(result);
            // SAFETY: write(2) on our own pipe.
            unsafe { libc::write(wake_w, [1u8].as_ptr().cast(), 1) };
            unsafe { libc::close(wake_w) };
        });
        Ok(Session {
            stream,
            wake_r,
            exit,
            shared,
            reader: Some(reader),
        })
    }

    fn send(&mut self, m: &AttachIn) -> bool {
        send(&mut self.stream, m).is_ok()
    }

    fn resize(&mut self) {
        let (rows, cols) = term::size();
        self.shared
            .mirror
            .lock()
            .unwrap()
            .screen_mut()
            .set_size(rows, cols);
        self.send(&AttachIn::Resize(PtySize { rows, cols }));
    }

    /// Two size changes make full-screen programs repaint everything.
    fn nudge(&mut self) {
        let (rows, cols) = term::size();
        self.send(&AttachIn::Resize(PtySize {
            rows,
            cols: cols.saturating_sub(1).max(1),
        }));
        std::thread::sleep(Duration::from_millis(20));
        self.send(&AttachIn::Resize(PtySize { rows, cols }));
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        if let Some(r) = self.reader.take() {
            let _ = r.join();
        }
        // SAFETY: closing our pipe end.
        unsafe { libc::close(self.wake_r) };
    }
}

/// Removes terminal reply sequences (cursor position and device attribute reports,
/// OSC colour replies, DCS strings) from `input`; everything else passes unchanged.
fn strip_terminal_replies(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == 0x1b && i + 1 < input.len() {
            let start = i;
            match input[i + 1] {
                b'[' => {
                    let mut j = i + 2;
                    while j < input.len()
                        && matches!(input[j], b'0'..=b'9' | b';' | b'?' | b'>' | b'=')
                    {
                        j += 1;
                    }
                    if j < input.len()
                        && matches!(input[j], b'R' | b'c' | b'n' | b't' | b'y')
                        && j > i + 2
                    {
                        i = j + 1;
                        continue;
                    }
                }
                b']' | b'P' => {
                    let mut j = i + 2;
                    while j < input.len()
                        && input[j] != 0x07
                        && !(input[j] == 0x1b && input.get(j + 1) == Some(&b'\\'))
                    {
                        j += 1;
                    }
                    if j < input.len() {
                        i = if input[j] == 0x07 { j + 1 } else { j + 2 };
                        continue;
                    }
                }
                _ => {}
            }
            out.push(input[start]);
            i = start + 1;
            continue;
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

fn read_key() -> Option<u8> {
    let mut b = [0u8; 1];
    // SAFETY: blocking read of one byte from stdin.
    let n = unsafe { libc::read(0, b.as_mut_ptr().cast(), 1) };
    (n == 1).then_some(b[0])
}

/// Shows `lines` full-screen, waits for a key, then restores the guest's screen.
fn overlay(s: &mut Session, lines: &[String]) -> Option<u8> {
    *s.shared.held.lock().unwrap() = Some(vec![]);
    let guest_alt = GUEST_ALT.load(Ordering::SeqCst);
    let mut screen = Vec::new();
    if !guest_alt {
        screen.extend_from_slice(b"\x1b[?1049h");
    }
    screen.extend_from_slice(b"\x1b[0m\x1b[H\x1b[2J");
    for l in lines {
        screen.extend_from_slice(l.as_bytes());
        screen.extend_from_slice(b"\r\n");
    }
    out(&screen);
    let key = read_key();
    let held = s.shared.held.lock().unwrap().take().unwrap_or_default();
    if guest_alt || GUEST_ALT.load(Ordering::SeqCst) {
        // The guest owns the alternate screen we drew on: let it repaint.
        s.nudge();
    } else {
        out(b"\x1b[?1049l");
        out(&held);
    }
    key
}

/// Draws `text` over the bottom row (cursor and attributes saved and restored).
fn draw_notice(text: &str) {
    let (rows, cols) = term::size();
    let mut line: String = format!(" pocket ▸ {text} ");
    let width = cols as usize;
    if line.chars().count() > width {
        line = line
            .chars()
            .take(width.saturating_sub(1))
            .collect::<String>()
            + "…";
    }
    let pad = width.saturating_sub(line.chars().count());
    out(format!(
        "\x1b7\x1b[{rows};1H\x1b[0m\x1b[7m{line}{}\x1b[0m\x1b8",
        " ".repeat(pad)
    )
    .as_bytes());
}

/// Puts the guest's bottom row back from the mirror.
fn clear_notice(s: &Session) {
    let (rows, _) = term::size();
    let m = s.shared.mirror.lock().unwrap();
    let screen = m.screen();
    let (_, cols) = screen.size();
    let row = screen.rows_formatted(0, cols).last().unwrap_or_default();
    let mut b = format!("\x1b7\x1b[{rows};1H\x1b[0m\x1b[2K").into_bytes();
    b.extend_from_slice(&row);
    b.extend_from_slice(b"\x1b8");
    drop(m);
    out(&b);
}

fn approvals_overlay(s: &mut Session, client: &mut Client, pocket: &str) {
    loop {
        let list = match client.request(Request::Approvals {
            pocket: Some(pocket.into()),
        }) {
            Ok(Response::Approvals(l)) => l,
            _ => vec![],
        };
        let Some(a) = list.first().cloned() else {
            overlay(
                s,
                &[
                    format!("  pocket · {pocket} · requests"),
                    String::new(),
                    "  nothing is waiting for you".into(),
                    String::new(),
                    "  press any key to return".into(),
                ],
            );
            return;
        };
        use pocket_proto::rpc::{ApprovalWhat, Decision};
        let (title, keys) = match &a.what {
            ApprovalWhat::Network { host, port, reason } => (
                format!(
                    "  network access to {host}{} ({reason})",
                    port.map(|p| format!(":{p}")).unwrap_or_default()
                ),
                "  o allow once (2 min) · p allow for this pocket · P allow for the project (pocket.toml) · d deny · Esc back",
            ),
            ApprovalWhat::SshSign { key, comment } => (
                format!("  ssh signature with {key} {comment}"),
                "  o sign this once · d deny · Esc back",
            ),
            ApprovalWhat::File { path } => (
                format!("  copy host file {path} into the pocket (/tmp/pocket-files/)"),
                "  o copy it · d deny · Esc back",
            ),
        };
        let lines = vec![
            format!("  pocket · {pocket} · {} request(s) waiting", list.len()),
            String::new(),
            title,
            String::new(),
            keys.into(),
        ];
        let decision = match overlay(s, &lines) {
            Some(b'o') => Decision::Once,
            Some(b'p') if matches!(a.what, ApprovalWhat::Network { .. }) => Decision::Pocket,
            Some(b'P') => {
                if let ApprovalWhat::Network { host, .. } = &a.what {
                    let _ = crate::project::allow_in_project(
                        client,
                        pocket,
                        std::slice::from_ref(host),
                    );
                }
                Decision::Pocket
            }
            Some(b'd') => Decision::Deny,
            _ => return,
        };
        let _ = client.request(Request::Approve { id: a.id, decision });
    }
}

fn ports_overlay(s: &mut Session, client: &mut Client, pocket: &str) {
    let list = match client.request(Request::Ports {
        pocket: pocket.into(),
    }) {
        Ok(Response::Ports(l)) => l,
        _ => vec![],
    };
    let mut lines = vec![format!("  pocket · {pocket} · ports"), String::new()];
    if list.is_empty() {
        lines.push("  nothing forwarded yet — servers listening in the pocket appear here".into());
    }
    for (i, f) in list.iter().enumerate().take(9) {
        lines.push(format!(
            "  {}  guest :{:<6} → http://127.0.0.1:{:<6} {}",
            i + 1,
            f.guest,
            f.host,
            f.process.clone().unwrap_or_default()
        ));
    }
    lines.push(String::new());
    lines.push("  1-9 open in browser · any other key returns".into());
    if let Some(k @ b'1'..=b'9') = overlay(s, &lines)
        && let Some(f) = list.get((k - b'1') as usize)
    {
        let _ = crate::open_browser(&format!("http://127.0.0.1:{}/", f.host));
    }
}

/// Uploads an image to the pocket; returns its guest path.
fn paste_image(client: &mut Client, pocket: &str, data: Vec<u8>) -> Option<String> {
    match client.request(Request::PasteImage {
        pocket: pocket.into(),
        data,
    }) {
        Ok(Response::Text { text, .. }) => Some(text),
        _ => None,
    }
}

fn help_lines(pocket: &str, session: &str) -> Vec<String> {
    vec![
        format!("  pocket · {pocket}:{session}"),
        String::new(),
        "  Ctrl-] d       detach (the session keeps running)".into(),
        "  Ctrl-] n       new shell session in this pocket".into(),
        "  Ctrl-] s       switch session".into(),
        "  Ctrl-] a       review requests (blocked network, ssh signatures)".into(),
        "  Ctrl-] p       ports forwarded from this pocket".into(),
        "  Ctrl-] y       allow a pending clipboard write".into(),
        "  Ctrl-V         pastes an image from your clipboard (for agents)".into(),
        "  Ctrl-] Ctrl-]  send a literal Ctrl-]".into(),
        "  Ctrl-] ?       this help".into(),
        String::new(),
        "  press any key to return".into(),
    ]
}

fn run(
    s: &mut Session,
    client: &mut Client,
    pocket: &str,
    session: &str,
    notices: &std::sync::mpsc::Receiver<String>,
    notice_r: i32,
) -> End {
    let winch_r = winch_pipe();
    let mut shown: Option<Instant> = None;
    let started = Instant::now();
    let test_panic = std::env::var("POCKET_TEST_PANIC_AFTER_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|ms| started + Duration::from_millis(ms));
    let mut nudged = false;
    let mut prefix = false;
    let mut buf = vec![0u8; MAX_CHUNK];
    loop {
        if let Some(t) = test_panic
            && Instant::now() >= t
        {
            panic!("POCKET_TEST_PANIC_AFTER_MS: simulated crash");
        }
        if !nudged && started.elapsed() > Duration::from_millis(120) {
            nudged = true;
            if GUEST_ALT.load(Ordering::SeqCst) {
                s.nudge();
            }
        }
        if shown.is_some_and(|t| t.elapsed() > Duration::from_secs(5)) {
            shown = None;
            clear_notice(s);
        }
        let mut fds = [
            libc::pollfd {
                fd: notice_r,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: 0,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: s.wake_r,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: winch_r,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: poll on a local array.
        let r = unsafe { libc::poll(fds.as_mut_ptr(), 4, 50) };
        if r < 0 {
            continue;
        }
        if fds[0].revents != 0 {
            let mut junk = [0u8; 64];
            // SAFETY: draining our own pipe.
            unsafe { libc::read(notice_r, junk.as_mut_ptr().cast(), junk.len()) };
            if let Some(text) = notices.try_iter().last()
                && s.shared.held.lock().unwrap().is_none()
            {
                draw_notice(&text);
                shown = Some(Instant::now());
            }
        }
        let fds = &fds[1..];
        if fds[1].revents != 0 {
            return match s.exit.lock().unwrap().take() {
                Some(Ok(st)) => End::Exited(st),
                Some(Err(e)) => End::Lost(e),
                None => End::Lost("session ended".into()),
            };
        }
        if fds[2].revents != 0 {
            let mut junk = [0u8; 64];
            // SAFETY: draining our non-blocking pipe.
            while unsafe { libc::read(winch_r, junk.as_mut_ptr().cast(), junk.len()) } > 0 {}
            s.resize();
        }
        if fds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0
            && fds[0].revents & libc::POLLIN == 0
        {
            return End::Detached;
        }
        if fds[0].revents & libc::POLLIN == 0 {
            continue;
        }
        // SAFETY: read into a local buffer.
        let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            return End::Detached;
        }
        let input = &buf[..n as usize];
        let filtered;
        let input = if started.elapsed() < REPLAY_QUIET {
            filtered = strip_terminal_replies(input);
            &filtered[..]
        } else {
            input
        };
        // A pasted image file path is uploaded and replaced by its path in the pocket.
        let rewritten;
        let input = match (
            input.windows(6).position(|w| w == b"\x1b[200~"),
            input.windows(6).position(|w| w == b"\x1b[201~"),
        ) {
            (Some(a), Some(b)) if b > a + 6 => {
                match crate::notice::pasted_image_path(&input[a + 6..b])
                    .and_then(|data| paste_image(client, pocket, data))
                {
                    Some(path) => {
                        rewritten = [&input[..a + 6], path.as_bytes(), &input[b..]].concat();
                        &rewritten[..]
                    }
                    None => input,
                }
            }
            _ => input,
        };
        let mut pending: Vec<u8> = Vec::with_capacity(input.len());
        for &b in input {
            if prefix {
                prefix = false;
                match b {
                    PREFIX => pending.push(PREFIX),
                    b'd' => {
                        if !pending.is_empty() {
                            s.send(&AttachIn::Data(pending));
                        }
                        return End::Detached;
                    }
                    b'n' => return End::NewShell,
                    b's' => {
                        if !pending.is_empty() {
                            s.send(&AttachIn::Data(std::mem::take(&mut pending)));
                        }
                        let list = match client.request(Request::SessionList {
                            pocket: pocket.into(),
                        }) {
                            Ok(Response::Sessions(l)) => l,
                            _ => vec![],
                        };
                        let mut lines =
                            vec![format!("  pocket · {pocket} · sessions"), String::new()];
                        for (i, x) in list.iter().enumerate().take(9) {
                            let state = match x.exited {
                                Some(st) => format!("exited {}", st.code()),
                                None => "running".into(),
                            };
                            let here = if x.name == session {
                                "  ← attached"
                            } else {
                                ""
                            };
                            lines.push(format!(
                                "  {}  {:<16} {:<10} {}{here}",
                                i + 1,
                                x.name,
                                state,
                                x.argv.join(" ")
                            ));
                        }
                        lines.push(String::new());
                        lines.push("  1-9 switch · n new shell · any other key returns".into());
                        match overlay(s, &lines) {
                            Some(k @ b'1'..=b'9') => {
                                if let Some(x) = list.get((k - b'1') as usize)
                                    && x.name != session
                                {
                                    return End::Switch(Some(x.name.clone()));
                                }
                            }
                            Some(b'n') => return End::NewShell,
                            _ => {}
                        }
                    }
                    b'a' => {
                        if !pending.is_empty() {
                            s.send(&AttachIn::Data(std::mem::take(&mut pending)));
                        }
                        approvals_overlay(s, client, pocket);
                    }
                    b'p' => {
                        if !pending.is_empty() {
                            s.send(&AttachIn::Data(std::mem::take(&mut pending)));
                        }
                        ports_overlay(s, client, pocket);
                    }
                    b'y' => {
                        if let Some(seq) = s.shared.clip.lock().unwrap().take() {
                            out(&seq);
                        }
                    }
                    b'?' | b'h' => {
                        if !pending.is_empty() {
                            s.send(&AttachIn::Data(std::mem::take(&mut pending)));
                        }
                        overlay(s, &help_lines(pocket, session));
                    }
                    _ => {}
                }
            } else if b == PREFIX {
                prefix = true;
            } else if b == 0x16 {
                // Ctrl-V: agents read pasted images from the clipboard (guest xclip shim).
                if let Some(png) = crate::notice::clipboard_image() {
                    paste_image(client, pocket, png);
                }
                pending.push(b);
            } else {
                pending.push(b);
            }
        }
        if !pending.is_empty() && !s.send(&AttachIn::Data(pending)) {
            return End::Lost("the pocket closed the session stream".into());
        }
    }
}

/// Attaches to `pocket` (`session` `None` = most recent) until detach or exit; returns
/// the process exit code.
pub fn attach(client: &mut Client, pocket: &str, mut session: Option<String>) -> Result<u8> {
    if !term::is_tty(0) {
        return Err(CliError::usage("attach needs a terminal on stdin")
            .hint("use `pocket exec` for non-interactive commands"));
    }
    let mut guard: Option<RawGuard> = None;
    let (ntx, nrx) = std::sync::mpsc::channel();
    let mut fds = [0; 2];
    // SAFETY: pipe2 into a local array.
    unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
    let (notice_r, notice_w) = (fds[0], fds[1]);
    crate::notice::subscribe(pocket.to_string(), ntx.clone(), notice_w);
    loop {
        let Response::Attach {
            session: name,
            vsock_uds,
            token,
        } = client.request(Request::AttachAuthorize {
            pocket: pocket.into(),
            session: session.clone(),
        })?
        else {
            return Err(CliError::new(
                "internal",
                70,
                "unexpected reply to AttachAuthorize",
            ));
        };
        let mut s = Session::open(&vsock_uds, &name, token, ntx.clone(), notice_w)?;
        if guard.is_none() {
            guard = Some(RawGuard::enter().map_err(|e| CliError::io("set raw mode", e))?);
        }
        let end = run(&mut s, client, pocket, &name, &nrx, notice_r);
        drop(s);
        match end {
            End::Switch(next) => {
                leave_guest_screen();
                session = next;
            }
            End::NewShell => {
                leave_guest_screen();
                let (rows, cols) = term::size();
                let Response::Session { name } = client.request(Request::SessionCreate {
                    pocket: pocket.into(),
                    name: None,
                    argv: None,
                    rows,
                    cols,
                    term: std::env::var("TERM").ok(),
                })?
                else {
                    return Err(CliError::new(
                        "internal",
                        70,
                        "unexpected reply to SessionCreate",
                    ));
                };
                session = Some(name);
            }
            End::Detached => {
                drop(guard);
                eprintln!(
                    "[detached from {pocket}:{name} · reattach: pocket attach {pocket}:{name}]"
                );
                return Ok(0);
            }
            End::Exited(st) => {
                drop(guard);
                eprintln!("[{pocket}:{name} exited with status {}]", st.code());
                return Ok(st.code().clamp(0, 255) as u8);
            }
            End::Lost(why) => {
                drop(guard);
                return Err(
                    CliError::new("guest", 8, format!("lost the session: {why}")).hint(format!(
                        "check `pocket ls`; reattach with `pocket attach {pocket}:{name}`"
                    )),
                );
            }
        }
    }
}

fn leave_guest_screen() {
    if GUEST_ALT.swap(false, Ordering::SeqCst) {
        out(b"\x1b[?1049l");
    }
    out(term::RESET_MODES);
    out(b"\r\n");
}

#[cfg(test)]
mod tests {
    use super::strip_terminal_replies as s;

    #[test]
    fn only_terminal_replies_are_stripped() {
        assert_eq!(
            s(b"\x1b[12;40R\x1b[?62;22c\x1b]11;rgb:0000/0000/0000\x07ls\r"),
            b"ls\r"
        );
        assert_eq!(s(b"\x1b]10;rgb:ffff/ffff/ffff\x1b\\x"), b"x");
        assert_eq!(s(b"\x1b:q!\r\x1dd"), b"\x1b:q!\r\x1dd");
        assert_eq!(s(b"\x1b[A\x1b[1;5C"), b"\x1b[A\x1b[1;5C");
        assert_eq!(s(b"\x1b"), b"\x1b");
    }
}
