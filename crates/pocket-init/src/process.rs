//! Building commands for guest processes.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::mpsc::Receiver;

use pocket_proto::guest::{ErrorKind, ExitStatus, GuestError};

use crate::{reaper, sys, users};

const DEFAULT_PATH: &str =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/run/pocket/system/bin";

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
    user: Option<&str>,
) -> Result<(Child, Receiver<ExitStatus>), GuestError> {
    let user = match user {
        Some(name) => Some(users::lookup(name).ok_or_else(|| {
            GuestError::new(
                ErrorKind::NotFound,
                format!("no user {name} in /etc/passwd"),
            )
        })?),
        None => None,
    };
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]).current_dir(cwd).env_clear();
    cmd.env("PATH", DEFAULT_PATH).env("LANG", "C.UTF-8");
    match &user {
        Some(u) => cmd
            .env("HOME", &u.home)
            .env("USER", &u.name)
            .env("LOGNAME", &u.name)
            .env("SHELL", &u.shell),
        None => cmd.env("HOME", "/root").env("USER", "root"),
    };
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
            if let Some(u) = &user {
                let _ = sys::fchown(&slave, u.uid, u.gid);
            }
            let clone = |f: &File| f.try_clone().map(Stdio::from);
            let io = |e: std::io::Error| GuestError::new(ErrorKind::Io, format!("pty: {e}"));
            cmd.stdin(clone(&slave).map_err(io)?)
                .stdout(clone(&slave).map_err(io)?)
                .stderr(Stdio::from(slave));
        }
    }
    let ids = user.map(|u| (u.uid, u.gid, u.groups));
    // SAFETY: only async-signal-safe calls (sigprocmask, setsid, ioctl, set*id) run after
    // fork; `ids` was allocated before.
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
            if let Some((uid, gid, groups)) = &ids {
                sys::cvt(libc::setgroups(groups.len(), groups.as_ptr()))?;
                sys::cvt(libc::setgid(*gid))?;
                sys::cvt(libc::setuid(*uid))?;
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
