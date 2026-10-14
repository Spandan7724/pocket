use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;

use pocket_tests::cli::Env;
use pocket_tests::kvm_or_skip;

fn uid() -> u32 {
    unsafe { libc::getuid() }
}

fn assets() -> Option<std::path::PathBuf> {
    let a = kvm_or_skip()?;
    Some(a.system.parent().unwrap().to_path_buf())
}

#[test]
fn boot_via_rpc_exec_uname_and_cgroup_limits() {
    let Some(assets) = assets() else { return };
    let env = Env::new("e2e", &assets);
    assert!(!env.socket().exists());
    let name = format!("e2e-{}", std::process::id());
    env.ok(&[
        "new",
        &name,
        "--preset",
        "test",
        "--no-repo",
        "--detach",
        "--cpus",
        "2",
        "--mem",
        "1G",
    ]);
    // The first command auto-started the daemon on a private 0600 socket.
    let mode = std::fs::metadata(env.socket())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    let out = env.ok(&["exec", &name, "--", "uname", "-a"]);
    assert!(out.starts_with("Linux ") && out.contains(&name), "{out}");
    let o = env.pocket(&["exec", &name, "--", "sh", "-c", "echo err >&2; exit 42"]);
    assert_eq!(o.status.code(), Some(42));
    assert_eq!(String::from_utf8_lossy(&o.stderr), "err\n");

    let ls = env.json(&["ls"]);
    assert_eq!(ls[0]["name"], name.as_str());
    assert_eq!(ls[0]["state"], "Running");
    assert!(
        ls[0]["disk_used_bytes"].as_u64().unwrap() < 50 << 20,
        "{ls}"
    );

    if pocket_vmm::cgroup::systemd_scopes_available() {
        let cg = std::path::PathBuf::from(format!(
            "/sys/fs/cgroup/user.slice/user-{0}.slice/user@{0}.service/pocket.slice/pocket-{name}.scope",
            uid()
        ));
        let read = |f: &str| {
            std::fs::read_to_string(cg.join(f))
                .unwrap()
                .trim()
                .to_string()
        };
        eprintln!(
            "{}: memory.max={} cpu.max={} pids.max={}",
            cg.display(),
            read("memory.max"),
            read("cpu.max"),
            read("pids.max")
        );
        assert_eq!(read("memory.max"), ((1024u64 + 512) << 20).to_string());
        assert_eq!(read("cpu.max"), "200000 100000");
        assert_eq!(read("pids.max"), "4096");
        let procs = read("cgroup.procs");
        let pid: u32 = procs.lines().next().unwrap().parse().unwrap();
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).unwrap();
        assert!(
            exe.ends_with("cloud-hypervisor"),
            "{exe:?} in the pocket scope"
        );
    }

    env.ok(&["stop", &name]);
    assert_eq!(env.json(&["ls"])[0]["state"], "Stopped");
    let o = env.pocket(&["exec", &name, "--", "true"]);
    assert_eq!(
        o.status.code(),
        Some(5),
        "exec on a stopped pocket is InvalidState"
    );
    assert!(String::from_utf8_lossy(&o.stderr).contains("pocket start"));
    env.ok(&["start", &name]);
    assert_eq!(env.ok(&["exec", &name, "--", "echo", "again"]), "again\n");
    env.ok(&["rm", "-f", &name]);
    assert!(env.json(&["ls"]).as_array().unwrap().is_empty());
}

#[test]
fn state_survives_daemon_restart_and_dead_vms_are_marked_broken() {
    let Some(assets) = assets() else { return };
    let env = Env::new("readopt", &assets);
    let (a, b) = (
        format!("ra-{}", std::process::id()),
        format!("rb-{}", std::process::id()),
    );
    for n in [&a, &b] {
        env.ok(&["new", n, "--preset", "test", "--no-repo", "--detach"]);
    }
    env.ok(&["exec", &a, "--", "sh", "-c", "echo persisted > /root/mark"]);
    let pid_of = |n: &str| -> u32 {
        let cg = format!(
            "/sys/fs/cgroup/user.slice/user-{0}.slice/user@{0}.service/pocket.slice/pocket-{n}.scope/cgroup.procs",
            uid()
        );
        std::fs::read_to_string(cg)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .parse()
            .unwrap()
    };
    let b_pid = pid_of(&b);
    env.ok(&["daemon", "stop"]);
    // While the daemon is down, one VM dies.
    unsafe { libc::kill(b_pid as i32, libc::SIGKILL) };
    std::thread::sleep(std::time::Duration::from_millis(300));
    let ls = env.json(&["ls"]);
    let state = |n: &str| {
        ls.as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == n)
            .unwrap()["state"]
            .clone()
    };
    assert_eq!(state(&a), "Running", "{ls}");
    let broken = state(&b);
    eprintln!("{b}: {broken}");
    assert!(
        broken["Broken"]["reason"]
            .as_str()
            .unwrap()
            .contains("re-adopt"),
        "{broken}"
    );
    // The surviving VM was re-adopted: exec, sessions and its data still work.
    assert_eq!(
        env.ok(&["exec", &a, "--", "cat", "/root/mark"]),
        "persisted\n"
    );
    assert!(env.ok(&["sessions", &a]).contains("shell"));
    assert!(env.log().contains("re-adopted running VM"));
}

#[test]
fn rpc_handshake_rejects_version_mismatch() {
    let Some(assets) = assets() else { return };
    let env = Env::new("rpc", &assets);
    let _ = env.pocket(&["ls"]);
    let mut s = UnixStream::connect(env.socket()).unwrap();
    let hello = br#"{"Hello":{"proto_version":999,"client":"test"}}"#;
    s.write_all(&(hello.len() as u32).to_be_bytes()).unwrap();
    s.write_all(hello).unwrap();
    let mut len = [0u8; 4];
    s.read_exact(&mut len).unwrap();
    let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut buf).unwrap();
    let reply = String::from_utf8(buf).unwrap();
    eprintln!("{reply}");
    assert!(
        reply.contains("VersionMismatch") && reply.contains("hint"),
        "{reply}"
    );
}
