//! cgroup v2 scope per VMM, created through the systemd user manager (rootless delegation).

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupSpec {
    /// Scope name without `.scope`, e.g. `pocket-web-1`.
    pub unit: String,
    pub slice: String,
    /// 100 = one full CPU.
    pub cpu_quota_pct: u32,
    pub memory_max_bytes: u64,
    pub tasks_max: u32,
}

/// Whether `systemd-run --user --scope` works here (cached).
pub fn systemd_scopes_available() -> bool {
    static OK: OnceLock<bool> = OnceLock::new();
    *OK.get_or_init(|| {
        Command::new("systemd-run")
            .args(["--user", "--scope", "--quiet", "--collect", "true"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

/// Wraps `inner` so it runs in its own scope with the limits applied. `systemd-run
/// --scope` execs the command, so the spawned pid is the VMM itself.
pub fn wrap(spec: &CgroupSpec, inner: &Command) -> Command {
    let mut c = Command::new("systemd-run");
    c.args(["--user", "--scope", "--quiet", "--collect"])
        .arg(format!("--unit={}", spec.unit))
        .arg(format!("--slice={}", spec.slice))
        .arg(format!("--property=CPUQuota={}%", spec.cpu_quota_pct))
        .arg(format!("--property=MemoryMax={}", spec.memory_max_bytes))
        .arg(format!("--property=TasksMax={}", spec.tasks_max))
        .arg("--")
        .arg(inner.get_program())
        .args(inner.get_args());
    c
}

pub fn stop_scope(unit: &str) {
    let _ = Command::new("systemctl")
        .args(["--user", "stop", &format!("{unit}.scope")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// cgroup v2 directory of a process.
pub fn cgroup_dir(pid: u32) -> Option<PathBuf> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let rel = s.lines().find_map(|l| l.strip_prefix("0::"))?;
    Some(PathBuf::from("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
}

/// Delegated controllers available to the user manager (`cpu memory pids …`).
pub fn delegated_controllers() -> Option<String> {
    let uid = unsafe { libc::getuid() };
    std::fs::read_to_string(format!(
        "/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/cgroup.controllers"
    ))
    .ok()
    .map(|s| s.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_puts_limits_before_the_command() {
        let spec = CgroupSpec {
            unit: "pocket-a".into(),
            slice: "pocket.slice".into(),
            cpu_quota_pct: 200,
            memory_max_bytes: 1 << 30,
            tasks_max: 512,
        };
        let mut inner = Command::new("/bin/vmm");
        inner.arg("--x");
        let c = wrap(&spec, &inner);
        let args: Vec<_> = c.get_args().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(
            args,
            [
                "--user",
                "--scope",
                "--quiet",
                "--collect",
                "--unit=pocket-a",
                "--slice=pocket.slice",
                "--property=CPUQuota=200%",
                "--property=MemoryMax=1073741824",
                "--property=TasksMax=512",
                "--",
                "/bin/vmm",
                "--x"
            ]
        );
    }
}
