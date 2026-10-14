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
/// Terminal replies to queries replayed from scrollback arrive as input; drop escape
/// sequences typed in this window after attaching.
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
}

struct Session {
    stream: UnixStream,
    wake_r: i32,
    exit: Arc<Mutex<Option<std::result::Result<ExitStatus, String>>>>,
    shared: Arc<Shared>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Session {
    fn open(uds: &Path, session: &str, token: Vec<u8>) -> Result<Session> {
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
        });
        let mut rd = stream.try_clone().map_err(|e| CliError::io("attach", e))?;
        let (exit2, shared2) = (exit.clone(), shared.clone());
        let reader = std::thread::spawn(move || {
            let mut alt = AltTracker::default();
            let result = loop {
                match recv::<_, AttachOut>(&mut rd) {
                    Ok(Some(AttachOut::Data(d))) => {
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

fn help_lines(pocket: &str, session: &str) -> Vec<String> {
    vec![
        format!("  pocket · {pocket}:{session}"),
        String::new(),
        "  Ctrl-] d       detach (the session keeps running)".into(),
        "  Ctrl-] n       new shell session in this pocket".into(),
        "  Ctrl-] s       switch session".into(),
        "  Ctrl-] Ctrl-]  send a literal Ctrl-]".into(),
        "  Ctrl-] ?       this help".into(),
        String::new(),
        "  press any key to return".into(),
    ]
}

fn run(s: &mut Session, client: &mut Client, pocket: &str, session: &str) -> End {
    let winch_r = winch_pipe();
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
        let mut fds = [
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
        let r = unsafe { libc::poll(fds.as_mut_ptr(), 3, 50) };
        if r < 0 {
            continue;
        }
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
        if started.elapsed() < REPLAY_QUIET && input.first() == Some(&0x1b) {
            continue;
        }
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
        let mut s = Session::open(&vsock_uds, &name, token)?;
        if guard.is_none() {
            guard = Some(RawGuard::enter().map_err(|e| CliError::io("set raw mode", e))?);
        }
        let end = run(&mut s, client, pocket, &name);
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
