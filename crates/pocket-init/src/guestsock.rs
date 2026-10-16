//! Guest-local endpoints: `/run/pocket/guest.sock` carries `pocket-guest` requests (open a
//! URL, notify, ask for network access) to pocket-init, which validates and forwards them to
//! the host; `/run/pocket/ssh-agent.sock` (opt-in) relays ssh-agent traffic to the host's
//! filtering agent.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use pocket_proto::frame::recv;
use pocket_proto::guest::{GuestEvent, SSH_AGENT_PORT};

use crate::{control, log, sys};

pub const GUEST_SOCK: &str = "/run/pocket/guest.sock";
pub const AGENT_SOCK: &str = "/run/pocket/ssh-agent.sock";
/// Names the guest helper is reachable under in `/usr/local/bin` (created only when free).
pub const SHIMS: &[&str] = &[
    "pocket-guest",
    "git-remote-pocket",
    "xdg-open",
    "sensible-browser",
    "x-www-browser",
    "xclip",
    "wl-paste",
    "wl-copy",
];

static STARTED: OnceLock<()> = OnceLock::new();
static AGENT: OnceLock<()> = OnceLock::new();

fn listen(path: &str) -> std::io::Result<UnixListener> {
    let _ = std::fs::remove_file(path);
    let l = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    Ok(l)
}

/// At most 20 requests per second from all guest processes together.
fn rate_ok() -> bool {
    static WINDOW: AtomicU64 = AtomicU64::new(0);
    static COUNT: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if WINDOW.swap(now, Ordering::Relaxed) != now {
        COUNT.store(0, Ordering::Relaxed);
    }
    COUNT.fetch_add(1, Ordering::Relaxed) < 20
}

fn serve(mut c: UnixStream) {
    while let Ok(Some(ev)) = recv::<_, GuestEvent>(&mut c) {
        let allowed = matches!(
            ev,
            GuestEvent::OpenUrl { .. }
                | GuestEvent::Notify { .. }
                | GuestEvent::ApprovalRequest { .. }
        );
        if allowed && rate_ok() {
            control::broadcast(ev);
        }
    }
}

pub fn start() {
    if STARTED.set(()).is_err() {
        return;
    }
    match listen(GUEST_SOCK) {
        Ok(l) => {
            std::thread::spawn(move || {
                for c in l.incoming().flatten() {
                    std::thread::spawn(move || serve(c));
                }
            });
        }
        Err(e) => log!("guest socket: {e}"),
    }
}

pub fn start_agent() {
    if AGENT.set(()).is_err() {
        return;
    }
    let l = match listen(AGENT_SOCK) {
        Ok(l) => l,
        Err(e) => {
            log!("ssh-agent socket: {e}");
            return;
        }
    };
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            std::thread::spawn(move || {
                let Ok(host) = sys::vsock_connect(libc::VMADDR_CID_HOST, SSH_AGENT_PORT) else {
                    return;
                };
                let (Ok(mut c2), Ok(mut h2)) = (c.try_clone(), host.try_clone()) else {
                    return;
                };
                let up = std::thread::spawn(move || {
                    let _ = sys::pump(&mut c2, &mut h2);
                    sys::shutdown_write(&h2);
                });
                let _ = sys::pump(&host, &c);
                let _ = c.shutdown(std::net::Shutdown::Write);
                let _ = up.join();
            });
        }
    });
}
