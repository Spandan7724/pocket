//! Persistent PTY sessions. Output is kept in a scrollback ring and fanned out to every
//! attached client; sessions outlive any host connection (tmux-like).

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard};

use pocket_proto::frame::{recv, send};
use pocket_proto::guest::{
    ATTACH_TOKEN_TTL_MS, AttachIn, AttachOut, ErrorKind, ExitStatus, GuestError, GuestEvent,
    PtySize, SessionInfo, StreamAck,
};

use crate::process::{Stdio3, spawn};
use crate::{control, log, sys};

const SCROLLBACK: usize = 1 << 20;
const CHUNK: usize = 32 * 1024;
/// Output chunks queued per client before a slow client is disconnected.
const CLIENT_QUEUE: usize = 256;

struct State {
    scrollback: VecDeque<u8>,
    clients: Vec<(u64, SyncSender<AttachOut>)>,
    size: PtySize,
    exited: Option<ExitStatus>,
}

pub struct Session {
    name: String,
    pid: u32,
    argv: Vec<String>,
    created_unix_ms: u64,
    master: File,
    state: Mutex<State>,
}

impl Session {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn info(&self) -> SessionInfo {
        let st = self.state();
        SessionInfo {
            name: self.name.clone(),
            pid: self.pid,
            argv: self.argv.clone(),
            created_unix_ms: self.created_unix_ms,
            size: st.size,
            attached: st.clients.len() as u32,
            exited: st.exited,
        }
    }
}

static SESSIONS: Mutex<Option<HashMap<String, Arc<Session>>>> = Mutex::new(None);
static NEXT_CLIENT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn sessions() -> MutexGuard<'static, Option<HashMap<String, Arc<Session>>>> {
    SESSIONS.lock().unwrap_or_else(|e| e.into_inner())
}

fn get(name: &str) -> Result<Arc<Session>, GuestError> {
    sessions()
        .as_ref()
        .and_then(|m| m.get(name).cloned())
        .ok_or_else(|| GuestError::new(ErrorKind::NotFound, format!("no session named {name}")))
}

pub fn create(
    name: &str,
    argv: &[String],
    env: &[(String, String)],
    cwd: &str,
    size: PtySize,
    user: Option<&str>,
) -> Result<u32, GuestError> {
    let mut map = sessions();
    let map = map.get_or_insert_with(HashMap::new);
    if map.contains_key(name) {
        return Err(GuestError::new(
            ErrorKind::AlreadyExists,
            format!("session {name} exists"),
        ));
    }
    let io = |e: std::io::Error| GuestError::new(ErrorKind::Io, format!("pty: {e}"));
    let (master, slave) = sys::openpty(size).map_err(io)?;
    let (child, status) = spawn(argv, env, cwd, Stdio3::Pty(slave), user)?;
    let s = Arc::new(Session {
        name: name.into(),
        pid: child.id(),
        argv: argv.to_vec(),
        created_unix_ms: sys::unix_ms(),
        master,
        state: Mutex::new(State {
            scrollback: VecDeque::new(),
            clients: Vec::new(),
            size,
            exited: None,
        }),
    });
    map.insert(name.into(), s.clone());
    let pid = s.pid;
    std::thread::spawn(move || pump(s, status));
    Ok(pid)
}

/// Reads the pty until every slave fd is closed, then reports the exit status.
fn pump(s: Arc<Session>, status: Receiver<ExitStatus>) {
    let mut buf = vec![0u8; CHUNK];
    let mut master = &s.master;
    loop {
        let n = match master.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break, // EIO: no slave left open
        };
        let data = &buf[..n];
        let mut st = s.state();
        st.scrollback.extend(data);
        let excess = st.scrollback.len().saturating_sub(SCROLLBACK);
        st.scrollback.drain(..excess);
        st.clients.retain(
            |(id, tx)| match tx.try_send(AttachOut::Data(data.to_vec())) {
                Ok(()) => true,
                Err(TrySendError::Full(_)) => {
                    log!("session {}: client {id} too slow, disconnected", s.name);
                    false
                }
                Err(TrySendError::Disconnected(_)) => false,
            },
        );
    }
    let st = status.recv().unwrap_or(ExitStatus::Code(0));
    let clients = {
        let mut state = s.state();
        state.exited = Some(st);
        std::mem::take(&mut state.clients)
    };
    for (_, tx) in clients {
        let _ = tx.send(AttachOut::Exited(st));
    }
    control::broadcast(GuestEvent::SessionExited {
        name: s.name.clone(),
        status: st,
    });
}

pub fn list() -> Vec<SessionInfo> {
    let mut v: Vec<SessionInfo> = sessions()
        .as_ref()
        .map(|m| m.values().map(|s| s.info()).collect())
        .unwrap_or_default();
    v.sort_by(|a, b| {
        a.created_unix_ms
            .cmp(&b.created_unix_ms)
            .then(a.name.cmp(&b.name))
    });
    v
}

pub fn kill(name: &str, signal: i32) -> Result<(), GuestError> {
    let s = get(name)?;
    if signal == 0 {
        if s.state().exited.is_none() {
            return Err(GuestError::new(
                ErrorKind::InvalidRequest,
                format!("session {name} is still running"),
            ));
        }
        sessions().as_mut().map(|m| m.remove(name));
        return Ok(());
    }
    // The session leader's pid is also its process group id.
    sys::kill(-(s.pid as i32), signal)
        .map_err(|e| GuestError::new(ErrorKind::Io, format!("kill: {e}")))
}

struct Token {
    token: Vec<u8>,
    session: String,
    expires_ns: u64,
}

static TOKENS: Mutex<Vec<Token>> = Mutex::new(Vec::new());

pub fn authorize(session: &str, token: Vec<u8>) {
    let now = sys::boottime_ns();
    let mut t = TOKENS.lock().unwrap_or_else(|e| e.into_inner());
    t.retain(|t| t.expires_ns > now);
    if t.len() >= 1024 {
        t.remove(0);
    }
    t.push(Token {
        token,
        session: session.into(),
        expires_ns: now + ATTACH_TOKEN_TTL_MS * 1_000_000,
    });
}

/// Single use: a matching token is removed whether or not the attach then succeeds.
fn consume(session: &str, token: &[u8]) -> bool {
    let now = sys::boottime_ns();
    let mut t = TOKENS.lock().unwrap_or_else(|e| e.into_inner());
    t.retain(|t| t.expires_ns > now);
    match t
        .iter()
        .position(|t| t.session == session && sys::ct_eq(&t.token, token))
    {
        Some(i) => {
            t.remove(i);
            true
        }
        None => false,
    }
}

/// Serves an `Attach` stream. The `StreamAck` has not been sent yet.
pub fn attach(name: &str, size: PtySize, replay: bool, token: &[u8], conn: File) {
    if !consume(name, token) {
        let e = GuestError::new(
            ErrorKind::InvalidRequest,
            "attach token missing, used or expired; ask pocketd to authorize the attach",
        );
        let _ = send(&mut &conn, &StreamAck(Err(e)));
        return;
    }
    let s = match get(name) {
        Ok(s) => s,
        Err(e) => {
            let _ = send(&mut &conn, &StreamAck(Err(e)));
            return;
        }
    };
    let id = NEXT_CLIENT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let rx = {
        let mut st = s.state();
        let backlog = if replay {
            st.scrollback.len().div_ceil(CHUNK)
        } else {
            0
        };
        let (tx, rx) = sync_channel(CLIENT_QUEUE + backlog + 1);
        if replay {
            let (a, b) = st.scrollback.as_slices();
            let all = [a, b].concat();
            for chunk in all.chunks(CHUNK) {
                let _ = tx.try_send(AttachOut::Data(chunk.to_vec()));
            }
        }
        match st.exited {
            Some(status) => {
                let _ = tx.try_send(AttachOut::Exited(status));
            }
            None => {
                if st.size != size {
                    let _ = sys::set_winsize(s.master.as_raw_fd(), size);
                    st.size = size;
                }
                st.clients.push((id, tx));
            }
        }
        rx
    };
    if send(&mut &conn, &StreamAck(Ok(()))).is_err() {
        detach(&s, id);
        return;
    }
    let Ok(out) = conn.try_clone() else { return };
    let writer = std::thread::spawn(move || {
        for msg in rx {
            let exited = matches!(msg, AttachOut::Exited(_));
            if send(&mut &out, &msg).is_err() {
                break;
            }
            if exited {
                sys::shutdown_write(&out);
                break;
            }
        }
    });
    loop {
        match recv::<_, AttachIn>(&mut &conn) {
            Ok(Some(AttachIn::Data(d))) => {
                if (&s.master).write_all(&d).is_err() {
                    break;
                }
            }
            Ok(Some(AttachIn::Resize(sz))) => {
                let _ = sys::set_winsize(s.master.as_raw_fd(), sz);
                s.state().size = sz;
            }
            Ok(None) => break,
            Err(e) => {
                log!("session {name}: bad frame from host: {e}");
                break;
            }
        }
    }
    detach(&s, id);
    sys::shutdown_write(&conn);
    let _ = writer.join();
}

fn detach(s: &Session, id: u64) {
    s.state().clients.retain(|(c, _)| *c != id);
}
