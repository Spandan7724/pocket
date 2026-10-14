//! Process helpers: pid-reuse-safe identity and async exit notification via pidfd.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

/// Start time (field 22 of `/proc/<pid>/stat`, clock ticks since boot).
pub fn start_time(pid: u32) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm may contain spaces and parens; fields resume after the last ')'.
    let rest = &s[s.rfind(')')? + 2..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

pub fn alive(pid: u32, start: u64) -> bool {
    start_time(pid) == Some(start)
}

pub fn exe_name(pid: u32) -> Option<String> {
    let p = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    Some(p.file_name()?.to_string_lossy().into_owned())
}

struct PidFd(OwnedFd);

impl AsRawFd for PidFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

fn pidfd_open(pid: u32) -> io::Result<PidFd> {
    // SAFETY: plain syscall; the returned descriptor is owned below.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh descriptor we own.
    Ok(PidFd(unsafe { OwnedFd::from_raw_fd(fd as RawFd) }))
}

/// Resolves when `pid` exits, and reaps it if it is our child.
pub async fn wait_exit(pid: u32, start: u64) -> io::Result<()> {
    if !alive(pid, start) {
        reap(pid);
        return Ok(());
    }
    match pidfd_open(pid) {
        Ok(fd) => {
            // SAFETY: the AsyncFd owns the pidfd, which stays open until it is dropped.
            let afd = unsafe { AsyncFd::register_with_interest(fd, Interest::READABLE) }
                .map_err(|e| io::Error::other(e.to_string()))?;
            let _guard = afd.readable().await?;
        }
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
        Err(_) => {
            while alive(pid, start) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    reap(pid);
    Ok(())
}

fn reap(pid: u32) {
    let mut status = 0;
    // SAFETY: non-blocking waitpid; ECHILD for adopted processes is fine.
    unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
}

pub fn kill(pid: u32, start: u64, sig: i32) {
    if alive(pid, start) {
        // SAFETY: plain kill(2) on a pid we verified by start time.
        unsafe { libc::kill(pid as libc::pid_t, sig) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_start_time_is_stable() {
        let me = std::process::id();
        let t = start_time(me).unwrap();
        assert!(alive(me, t));
        assert!(!alive(me, t + 1));
    }

    #[tokio::test]
    async fn wait_exit_resolves_for_a_child() {
        let mut child = std::process::Command::new("sleep")
            .arg("0.1")
            .spawn()
            .unwrap();
        let pid = child.id();
        let t = start_time(pid).unwrap();
        tokio::time::timeout(Duration::from_secs(5), wait_exit(pid, t))
            .await
            .unwrap()
            .unwrap();
        assert!(!alive(pid, t));
        assert!(child.wait().is_err(), "wait_exit should have reaped it");
    }
}
