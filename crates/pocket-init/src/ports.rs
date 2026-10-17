//! Port watcher and forwarding (M8): listening TCP sockets are reported to the host as they
//! appear and disappear; the host forwards `127.0.0.1:<port>` on its side through
//! `StreamOpen::PortForward` streams that land here.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::OnceLock;
use std::time::Duration;

use pocket_proto::frame::send;
use pocket_proto::guest::{ErrorKind, GuestError, GuestEvent, Proto, StreamAck};

use crate::{control, log, sys};

static STARTED: OnceLock<()> = OnceLock::new();

/// Listening TCP ports (any local address) → socket inode.
fn listening(skip: &[u16]) -> BTreeSet<(u16, u64)> {
    let mut out = BTreeSet::new();
    for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 || cols[3] != "0A" {
                continue;
            }
            let Some(port) = cols[1]
                .rsplit_once(':')
                .and_then(|(_, p)| u16::from_str_radix(p, 16).ok())
            else {
                continue;
            };
            if port == 0 || skip.contains(&port) {
                continue;
            }
            out.insert((port, cols[9].parse().unwrap_or(0)));
        }
    }
    out
}

/// Command name of the process holding socket `inode`.
fn owner(inode: u64) -> Option<String> {
    let needle = format!("socket:[{inode}]");
    for e in std::fs::read_dir("/proc").ok()?.flatten() {
        let name = e.file_name();
        let Some(pid) = name
            .to_str()
            .filter(|n| n.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path()).is_ok_and(|l| l.as_os_str() == needle.as_str()) {
                let mut comm = String::new();
                File::open(format!("/proc/{pid}/comm"))
                    .and_then(|mut f| f.read_to_string(&mut comm))
                    .ok()?;
                return Some(comm.trim().chars().take(64).collect());
            }
        }
    }
    None
}

/// Set by the restore hook: the host lost its forwards, announce every port again.
pub static REANNOUNCE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Starts the watcher once; `skip` are pocket's own listeners (the proxy shim).
pub fn start_watcher(skip: Vec<u16>) {
    if STARTED.set(()).is_err() {
        return;
    }
    std::thread::spawn(move || {
        let mut known: BTreeSet<u16> = BTreeSet::new();
        loop {
            if REANNOUNCE.swap(false, std::sync::atomic::Ordering::SeqCst) {
                known.clear();
            }
            let now = listening(&skip);
            let ports: BTreeSet<u16> = now.iter().map(|(p, _)| *p).collect();
            for &(port, inode) in now.iter() {
                if known.contains(&port) {
                    continue;
                }
                control::broadcast(GuestEvent::PortOpened {
                    port,
                    proto: Proto::Tcp,
                    process: owner(inode),
                });
                known.insert(port);
            }
            for port in known.difference(&ports).copied().collect::<Vec<_>>() {
                control::broadcast(GuestEvent::PortClosed {
                    port,
                    proto: Proto::Tcp,
                });
                known.remove(&port);
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    });
}

pub fn forward(port: u16, conn: File) {
    let addrs = [
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
    ];
    let tcp = addrs
        .iter()
        .find_map(|a| TcpStream::connect_timeout(a, Duration::from_secs(5)).ok());
    let Some(tcp) = tcp else {
        let e = GuestError::new(
            ErrorKind::NotFound,
            format!("nothing listens on port {port}"),
        );
        let _ = send(&mut &conn, &StreamAck(Err(e)));
        return;
    };
    let _ = tcp.set_nodelay(true);
    if send(&mut &conn, &StreamAck(Ok(()))).is_err() {
        return;
    }
    let (Ok(mut t2), Ok(mut c2)) = (tcp.try_clone(), conn.try_clone()) else {
        return;
    };
    std::thread::spawn(move || {
        let _ = sys::pump(&mut c2, &mut t2);
        let _ = t2.shutdown(std::net::Shutdown::Write);
    });
    if let Err(e) = sys::pump(&tcp, &conn) {
        log!("port {port}: {e}");
    }
    // The server closed: end the whole stream (half-closes don't cross the hybrid vsock).
    // SAFETY: shutdown on an open socket we own.
    unsafe { libc::shutdown(std::os::fd::AsRawFd::as_raw_fd(&conn), libc::SHUT_RDWR) };
    let _ = tcp.shutdown(std::net::Shutdown::Both);
}
