//! Child reaping for PID 1. Every child — ours and orphans re-parented to us — is reaped
//! here; processes we spawned get their status delivered on a channel.
//!
//! Spawning holds the same lock as reaping, so a child that exits before it is registered
//! cannot be reaped (and its status lost) in between.

use std::collections::HashMap;
use std::io;
use std::process::{Child, Command};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Mutex, MutexGuard};

use pocket_proto::guest::ExitStatus;

static WAITERS: Mutex<Option<HashMap<i32, Sender<ExitStatus>>>> = Mutex::new(None);

fn lock() -> MutexGuard<'static, Option<HashMap<i32, Sender<ExitStatus>>>> {
    WAITERS.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn spawn_tracked(cmd: &mut Command) -> io::Result<(Child, Receiver<ExitStatus>)> {
    let mut w = lock();
    let child = cmd.spawn()?;
    let (tx, rx) = channel();
    w.get_or_insert_with(HashMap::new)
        .insert(child.id() as i32, tx);
    Ok((child, rx))
}

fn decode(status: libc::c_int) -> Option<ExitStatus> {
    if libc::WIFEXITED(status) {
        Some(ExitStatus::Code(libc::WEXITSTATUS(status)))
    } else if libc::WIFSIGNALED(status) {
        Some(ExitStatus::Signal(libc::WTERMSIG(status)))
    } else {
        None
    }
}

/// Reaps every exited child without blocking. Returns how many were reaped.
pub fn reap_all() -> usize {
    let mut w = lock();
    let mut n = 0;
    loop {
        let mut status = 0;
        // SAFETY: waitpid with a valid status pointer.
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG | libc::__WALL) };
        if pid <= 0 {
            return n;
        }
        n += 1;
        if let Some(st) = decode(status)
            && let Some(tx) = w.as_mut().and_then(|m| m.remove(&pid))
        {
            let _ = tx.send(st);
        }
    }
}
