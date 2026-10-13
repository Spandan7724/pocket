//! Clean shutdown: stop every process, then leave the pocket disk consistent (unmounted
//! binds, ext4 remounted read-only so its journal is committed and the fs marked clean).

use std::fs;
use std::time::{Duration, Instant};

use crate::boot::DISK;
use crate::{log, reaper, sys};

const PF_KTHREAD: u64 = 0x0020_0000;

/// Pids of live user-space processes other than ourselves (zombies count as gone).
fn user_processes() -> Vec<i32> {
    let Ok(dir) = fs::read_dir("/proc") else {
        return vec![];
    };
    dir.filter_map(|e| e.ok()?.file_name().to_str()?.parse::<i32>().ok())
        .filter(|&pid| pid != 1)
        .filter(|pid| {
            let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
                return false;
            };
            let Some(rest) = stat.rfind(')').map(|i| &stat[i + 2..]) else {
                return false;
            };
            let f: Vec<&str> = rest.split_whitespace().collect();
            let state = f.first().copied().unwrap_or("Z");
            let flags: u64 = f.get(6).and_then(|v| v.parse().ok()).unwrap_or(PF_KTHREAD);
            state != "Z" && state != "X" && flags & PF_KTHREAD == 0
        })
        .collect()
}

fn wait_gone(deadline: Instant) -> bool {
    loop {
        reaper::reap_all();
        if user_processes().is_empty() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

pub fn shutdown(timeout_ms: u32) -> Result<(), String> {
    let _ = sys::kill(-1, libc::SIGTERM);
    if !wait_gone(Instant::now() + Duration::from_millis(timeout_ms as u64)) {
        log!(
            "shutdown: {} processes ignored SIGTERM, killing",
            user_processes().len()
        );
        let _ = sys::kill(-1, libc::SIGKILL);
        if !wait_gone(Instant::now() + Duration::from_secs(5)) {
            return Err(format!(
                "processes survived SIGKILL: {:?}",
                user_processes()
            ));
        }
    }
    // SAFETY: plain syscall.
    unsafe { libc::sync() };
    let mut errs = vec![];
    for m in ["/tmp", "/home", "/work"] {
        if let Err(e) = sys::umount(m) {
            errs.push(e.to_string());
        }
    }
    let ro = libc::MS_REMOUNT | libc::MS_RDONLY;
    if let Err(e) = sys::mount("", DISK, "", ro, None) {
        errs.push(format!("remount {DISK} read-only: {e}"));
    }
    // SAFETY: plain syscall.
    unsafe { libc::sync() };
    if errs.is_empty() {
        log!("shutdown: clean");
        Ok(())
    } else {
        Err(errs.join("; "))
    }
}
