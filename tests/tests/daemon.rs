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
        assert_eq!(read("memory.max"), ((1024u64 + 1024) << 20).to_string());
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

#[test]
fn daemon_stop_stops_a_daemon_of_another_rpc_version() {
    let env = Env::new("oldrpc", &std::env::temp_dir());
    std::fs::create_dir_all(env.socket().parent().unwrap()).unwrap();
    let path = env.socket();
    let path = path.as_os_str().as_encoded_bytes();
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (d, s) in addr.sun_path.iter_mut().zip(path) {
        *d = *s as libc::c_char;
    }
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    let rc = unsafe {
        libc::bind(
            fd,
            (&raw const addr).cast(),
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0);
    // The stand-in daemon must be its own process, and it must call listen() itself:
    // SO_PEERCRED reports the listening process, which `daemon stop` signals. The child
    // only makes raw syscalls (no allocation after fork).
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe { libc::listen(fd, 8) };
        loop {
            let c = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
            if c >= 0 {
                unsafe { libc::close(c) };
            }
        }
    }
    unsafe { libc::close(fd) };
    // Until the child listens, connects are refused and the CLI would start a real pocketd.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while UnixStream::connect(env.socket()).is_err() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let o = env.pocket(&["daemon", "status"]);
    assert!(
        String::from_utf8_lossy(&o.stdout).contains(&format!("pid {pid}")),
        "status names the unreachable daemon"
    );
    assert!(env.ok(&["daemon", "stop"]).contains("pocketd stopped"));
    let mut st = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut st, 0) }, pid);
    assert!(libc::WIFSIGNALED(st) && libc::WTERMSIG(st) == libc::SIGTERM);
    std::fs::remove_file(env.socket()).unwrap();
}

#[test]
fn doctor_reports_checks_and_fixes() {
    let Some(assets) = assets() else { return };
    let env = Env::new("doctor", &assets);
    let out = env.ok(&["doctor"]);
    for name in [
        "kvm",
        "cgroups",
        "reflink",
        "disk space",
        "assets",
        "versions",
        "mkfs.erofs",
    ] {
        assert!(
            out.lines().any(|l| l
                .split_whitespace()
                .skip(1)
                .collect::<Vec<_>>()
                .join(" ")
                .starts_with(name)),
            "{name} missing:\n{out}"
        );
    }
    assert!(
        out.contains(&format!(
            "guest protocol v{}",
            pocket_proto::guest::PROTO_VERSION
        )) && out.contains("cloud-hypervisor 54"),
        "{out}"
    );
    let checks = env.json(&["doctor"]);
    assert!(
        checks
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["ok"] == true || c["fix"].is_string())
    );

    // Broken host: no KVM device, no assets. Every failure says how to fix it.
    let mut broken = Env::new("doctor-bad", &assets.join("nope"));
    broken
        .extra
        .push(("POCKET_DOCTOR_KVM".into(), "/nonexistent/kvm".into()));
    let o = broken.pocket(&["doctor"]);
    assert_eq!(o.status.code(), Some(1));
    let text = String::from_utf8_lossy(&o.stdout);
    for line in ["✗ kvm", "✗ assets"] {
        let i = text
            .find(line)
            .unwrap_or_else(|| panic!("{line} missing:\n{text}"));
        let next = text[i..].lines().nth(1).unwrap();
        assert!(
            next.trim_start().starts_with("fix:"),
            "no fix after {line}:\n{text}"
        );
    }
}

#[test]
fn errors_say_what_happened_and_how_to_fix_it() {
    let Some(assets) = assets() else { return };
    let env = Env::new("errors", &assets);
    let cases: &[(&[&str], i32, &str, &str)] = &[
        (
            &["exec", "nope", "--", "true"],
            3,
            "no pocket named \"nope\"",
            "pocket ls",
        ),
        (
            &["new", "Bad_Name", "--no-repo", "--preset", "test"],
            2,
            "invalid pocket name",
            "lowercase",
        ),
        (
            &["new", "x", "--no-repo", "--preset", "nosuch"],
            2,
            "unknown preset",
            "available presets",
        ),
        (
            &["new", "x", "--no-repo", "--preset", "test", "--net", "wide"],
            2,
            "unknown network profile",
            "dev, strict, offline",
        ),
        (
            &[
                "new",
                "x",
                "--no-repo",
                "--preset",
                "test",
                "--allow",
                "a*b",
            ],
            2,
            "invalid rule",
            "",
        ),
        (
            &["new", "x", "--repo", "/", "--preset", "test"],
            10,
            "not inside a git work tree",
            "--no-repo",
        ),
        (&["kill", "x"], 2, "name the session", ""),
        (
            &["new", "--mem", "lots", "--preset", "test"],
            2,
            "invalid size",
            "4G",
        ),
    ];
    for (args, code, what, hint) in cases {
        let o = env.pocket(args);
        let err = String::from_utf8_lossy(&o.stderr);
        assert_eq!(o.status.code(), Some(*code), "{args:?}: {err}");
        assert!(err.contains(what), "{args:?}: {err}");
        assert!(err.contains('×'), "miette rendering: {err}");
        if !hint.is_empty() {
            assert!(
                err.contains("help:") && err.contains(hint),
                "{args:?}: {err}"
            );
        }
    }
}

#[test]
fn peer_credentials_are_checked() {
    let Some(assets) = assets() else { return };
    let mut env = Env::new("peercred", &assets);
    env.extra
        .push(("POCKETD_TEST_PEER_UID".into(), (uid() + 1).to_string()));
    let o = env.pocket(&["ls"]);
    assert_eq!(
        o.status.code(),
        Some(11),
        "a client with another uid must be refused"
    );
    assert!(
        env.log()
            .contains(&format!("rejected connection from uid {}", uid()))
    );
}

#[test]
fn events_reach_subscribers_and_kill_ends_sessions() {
    let Some(assets) = assets() else { return };
    let env = Env::new("events", &assets);
    let n = format!("ev-{}", std::process::id());
    env.ok(&["new", &n, "--preset", "test", "--no-repo", "--detach"]);
    let mut follow = env
        .cmd("pocket")
        .args(["--json", "logs", &n, "--net", "--follow"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let _ = env.pocket(&[
        "exec",
        &n,
        "--",
        "wget",
        "-q",
        "-O-",
        "http://blocked.example/",
    ]);
    let mut out = follow.stdout.take().unwrap();
    let mut buf = vec![0u8; 4096];
    let k = out.read(&mut buf).unwrap();
    let line = String::from_utf8_lossy(&buf[..k]);
    eprintln!("follow: {line}");
    assert!(
        line.contains("blocked.example") && line.contains("Denied"),
        "{line}"
    );
    let _ = follow.kill();
    let _ = follow.wait();

    env.ok(&["kill", &format!("{n}:shell")]);
    std::thread::sleep(std::time::Duration::from_millis(300));
    let s = env.json(&["sessions", &n]);
    assert_eq!(s[0]["exited"]["Signal"], libc::SIGHUP, "{s}");
    env.ok(&["kill", &format!("{n}:shell")]);
    assert!(env.json(&["sessions", &n]).as_array().unwrap().is_empty());
}
