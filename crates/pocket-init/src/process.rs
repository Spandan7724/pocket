//! Building commands for guest processes.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::mpsc::Receiver;

use pocket_proto::guest::{ErrorKind, ExitStatus, GuestError};

use crate::{reaper, sys};

const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Variables from `Configure`, applied to every later process.
pub static GLOBAL_ENV: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

pub enum Stdio3 {
    Pipes,
    /// All three on this pty slave; the child becomes session leader with it as ctty.
    Pty(File),
}

pub fn spawn(
    argv: &[String],
    env: &[(String, String)],
    cwd: &str,
    stdio: Stdio3,
) -> Result<(Child, Receiver<ExitStatus>), GuestError> {
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]).current_dir(cwd).env_clear();
    cmd.env("PATH", DEFAULT_PATH)
        .env("HOME", "/root")
        .env("USER", "root")
        .env("LANG", "C.UTF-8");
    let is_pty = matches!(stdio, Stdio3::Pty(_));
    if is_pty {
        cmd.env("TERM", "xterm-256color");
    }
    for (k, v) in GLOBAL_ENV.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        cmd.env(k, v);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    match stdio {
        Stdio3::Pipes => {
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        }
        Stdio3::Pty(slave) => {
            let clone = |f: &File| f.try_clone().map(Stdio::from);
            let io = |e: std::io::Error| GuestError::new(ErrorKind::Io, format!("pty: {e}"));
            cmd.stdin(clone(&slave).map_err(io)?)
                .stdout(clone(&slave).map_err(io)?)
                .stderr(Stdio::from(slave));
        }
    }
    // SAFETY: only async-signal-safe calls (sigprocmask, setsid, ioctl) run after fork.
    unsafe {
        cmd.pre_exec(move || {
            sys::unblock_all_signals()?;
            sys::cvt(libc::setsid())?;
            if is_pty {
                sys::cvt(libc::ioctl(
                    std::io::stdin().as_raw_fd(),
                    libc::TIOCSCTTY,
                    0,
                ))?;
            }
            Ok(())
        });
    }
    reaper::spawn_tracked(&mut cmd).map_err(|e| {
        let kind = match e.kind() {
            std::io::ErrorKind::NotFound => ErrorKind::NotFound,
            _ => ErrorKind::Io,
        };
        GuestError::new(kind, format!("spawn {}: {e}", argv[0]))
    })
}
