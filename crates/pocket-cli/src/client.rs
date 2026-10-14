//! Blocking RPC client for pocketd; starts the daemon on demand.

use std::io;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use pocket_proto::rpc::{self, ClientMsg, DaemonMsg, Event, RPC_VERSION, Request, Response, Topic};

use crate::error::{CliError, Result};

pub fn runtime_dir() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
        Some(d) => PathBuf::from(d).join("pocket"),
        None => std::env::temp_dir().join(format!("pocket-{}", unsafe { libc::getuid() })),
    }
}

pub fn socket_path() -> PathBuf {
    runtime_dir().join("pocketd.sock")
}

fn pocketd_binary() -> PathBuf {
    if let Some(p) = std::env::var_os("POCKETD").filter(|v| !v.is_empty()) {
        return p.into();
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
        && dir.join("pocketd").exists()
    {
        return dir.join("pocketd");
    }
    "pocketd".into()
}

pub struct Client {
    s: UnixStream,
    next_id: u64,
    pub daemon_version: String,
}

fn send(s: &mut UnixStream, m: &ClientMsg) -> Result<()> {
    rpc::write(s, m).map_err(|e| CliError::daemon(format!("pocketd connection: {e}")))
}

fn recv(s: &mut UnixStream) -> Result<DaemonMsg> {
    match rpc::read(s) {
        Ok(Some(m)) => Ok(m),
        Ok(None) => Err(CliError::daemon("pocketd closed the connection")
            .hint("check $XDG_STATE_HOME/pocket/pocketd.log")),
        Err(e) => Err(CliError::daemon(format!("pocketd connection: {e}"))),
    }
}

impl Client {
    fn handshake(mut s: UnixStream) -> Result<Client> {
        send(
            &mut s,
            &ClientMsg::Hello {
                proto_version: RPC_VERSION,
                client: format!("pocket {}", env!("CARGO_PKG_VERSION")),
            },
        )?;
        match recv(&mut s)? {
            DaemonMsg::Hello { daemon_version, .. } => Ok(Client {
                s,
                next_id: 1,
                daemon_version,
            }),
            DaemonMsg::Response { result: Err(e), .. } => Err(e.into()),
            other => Err(CliError::daemon(format!(
                "unexpected handshake reply {other:?}"
            ))),
        }
    }

    /// Connects, starting pocketd if nothing listens yet.
    pub fn connect() -> Result<Client> {
        let sock = socket_path();
        if let Ok(s) = UnixStream::connect(&sock) {
            return Client::handshake(s);
        }
        let bin = pocketd_binary();
        let mut cmd = Command::new(&bin);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = cmd.spawn().map_err(|e| {
            CliError::daemon(format!("could not start {}: {e}", bin.display()))
                .hint("install pocketd next to pocket, or set POCKETD to its path")
        })?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(s) = UnixStream::connect(&sock) {
                // Reaped by init after we exit; it keeps running.
                std::mem::forget(child);
                return Client::handshake(s);
            }
            if let Ok(Some(st)) = child.try_wait() {
                let mut err = String::new();
                if let Some(mut e) = child.stderr.take() {
                    let _ = io::Read::read_to_string(&mut e, &mut err);
                }
                if st.code() == Some(3)
                    && let Ok(s) = UnixStream::connect(&sock)
                {
                    return Client::handshake(s);
                }
                return Err(
                    CliError::daemon(format!("pocketd exited ({st}): {}", err.trim()))
                        .hint("run `pocket doctor`; details in $XDG_STATE_HOME/pocket/pocketd.log"),
                );
            }
            if Instant::now() > deadline {
                return Err(CliError::daemon("pocketd did not start within 10 s")
                    .hint("check $XDG_STATE_HOME/pocket/pocketd.log"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Connects only if a daemon already runs.
    pub fn connect_existing() -> Option<Client> {
        UnixStream::connect(socket_path())
            .ok()
            .and_then(|s| Client::handshake(s).ok())
    }

    pub fn request_with(
        &mut self,
        req: Request,
        mut progress: impl FnMut(&str),
    ) -> Result<Response> {
        let id = self.next_id;
        self.next_id += 1;
        send(&mut self.s, &ClientMsg::Request { id, req })?;
        loop {
            match recv(&mut self.s)? {
                DaemonMsg::Response { id: rid, result } if rid == id => {
                    return result.map_err(Into::into);
                }
                DaemonMsg::Progress { id: rid, stage, .. } if rid == id => progress(&stage),
                _ => {}
            }
        }
    }

    pub fn request(&mut self, req: Request) -> Result<Response> {
        self.request_with(req, |_| {})
    }

    pub fn subscribe(&mut self, topics: Vec<Topic>) -> Result<()> {
        let id = self.next_id;
        self.next_id += 1;
        send(&mut self.s, &ClientMsg::Subscribe { id, topics })?;
        loop {
            if let DaemonMsg::Response { id: rid, result } = recv(&mut self.s)?
                && rid == id
            {
                return result.map(|_| ()).map_err(Into::into);
            }
        }
    }

    pub fn next_event(&mut self) -> Result<Event> {
        loop {
            if let DaemonMsg::Event { event, .. } = recv(&mut self.s)? {
                return Ok(event);
            }
        }
    }
}
