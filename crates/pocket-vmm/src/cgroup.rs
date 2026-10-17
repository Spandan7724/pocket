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

/// Points systemd user tools at the user manager even when `XDG_RUNTIME_DIR` was
/// redirected (tests, CI isolation): they connect to `$XDG_RUNTIME_DIR/systemd/private`.
fn user_bus(c: &mut Command) -> &mut Command {
    let private = |d: &std::path::Path| d.join("systemd/private").exists();
    let ours = std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from);
    let real = std::path::PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() }));
    if !ours.as_deref().is_some_and(private) && private(&real) {
        c.env("XDG_RUNTIME_DIR", real);
    }
    c
}

/// Whether `systemd-run --user --scope` works here (cached).
pub fn systemd_scopes_available() -> bool {
    static OK: OnceLock<bool> = OnceLock::new();
    *OK.get_or_init(|| {
        user_bus(&mut Command::new("systemd-run"))
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
    user_bus(&mut c);
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

/// Moves the already running `pid` into a new scope with the limits applied: the call
/// `systemd-run --scope` makes, issued with `busctl` so the VMM can start in parallel
/// instead of after it (~15 ms on the start path). The caller waits for the child.
pub fn adopt(spec: &CgroupSpec, pid: u32) -> std::io::Result<std::process::Child> {
    let mut c = Command::new("busctl");
    user_bus(&mut c);
    c.args([
        "--user",
        "call",
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "StartTransientUnit",
        "ssa(sv)a(sa(sv))",
    ])
    .arg(format!("{}.scope", spec.unit))
    .arg("fail")
    .arg("6")
    .args(["PIDs", "au", "1"])
    .arg(pid.to_string())
    .args(["Slice", "s"])
    .arg(&spec.slice)
    .args(["MemoryMax", "t"])
    .arg(spec.memory_max_bytes.to_string())
    .args(["CPUQuotaPerSecUSec", "t"])
    .arg((spec.cpu_quota_pct as u64 * 10_000).to_string())
    .args(["TasksMax", "t"])
    .arg(spec.tasks_max.to_string())
    .args(["CollectMode", "s", "inactive-or-failed"])
    .arg("0")
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::piped())
    .spawn()
}

/// Whether `busctl` can create scopes (cached); otherwise `wrap` is used.
pub fn busctl_available() -> bool {
    static OK: OnceLock<bool> = OnceLock::new();
    *OK.get_or_init(|| {
        user_bus(&mut Command::new("busctl"))
            .args(["--user", "--version"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

pub fn stop_scope(unit: &str) {
    let _ = user_bus(&mut Command::new("systemctl"))
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
