//! M9 speed tiers: snapshot templates, the restore hook, the warm pool, pause / hibernate
//! and the idle manager.

use std::time::{Duration, Instant};

use pocket_proto::guest::{HostReq, PtySize, Reply};
use pocket_tests::cli::Env;
use pocket_tests::guest::{Control, argv, sh};
use pocket_tests::{TestVm, VmOpts, kvm_or_skip, make_ext4, scratch_dir};

fn assets() -> Option<std::path::PathBuf> {
    let a = kvm_or_skip()?;
    Some(a.system.parent().unwrap().to_path_buf())
}

fn new_args(name: &str) -> Vec<&str> {
    vec![
        "new",
        name,
        "--preset",
        "test",
        "--no-repo",
        "--detach",
        "--mem",
        "512M",
    ]
}

fn pocket<'a>(ls: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    ls.as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == name)
        .unwrap()
}

fn templates(v: &serde_json::Value) -> Vec<String> {
    v["templates"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|t| t["key"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// The guest refuses sessions, execs, attach tokens and Configure between `Seal` and the
/// restore hook, so a restored VM can run nothing for a user before `Restored`.
#[test]
fn sealed_guest_refuses_everything_until_the_restore_hook() {
    let Some(a) = kvm_or_skip() else { return };
    let dir = scratch_dir("seal");
    let disk = dir.join("disk.raw");
    make_ext4(&disk, 256);
    let vm = TestVm::boot(
        &a,
        "seal",
        VmOpts {
            pocket_disk: Some(disk),
            ..Default::default()
        },
    );
    let u = &vm.vsock_uds;
    let mut ctl = Control::connect(u, Duration::from_secs(10));
    assert_eq!(ctl.request(HostReq::Seal), Ok(Reply::Done));
    let refused = [
        HostReq::SessionCreate {
            name: "s".into(),
            argv: argv(&["/bin/sh"]),
            env: vec![],
            cwd: "/".into(),
            size: PtySize { rows: 24, cols: 80 },
            user: None,
        },
        HostReq::Exec {
            argv: argv(&["/bin/true"]),
            env: vec![],
            cwd: "/".into(),
            pty: None,
            user: None,
        },
        HostReq::AuthorizeAttach {
            session: "s".into(),
            token: vec![1; 32],
        },
        HostReq::Configure {
            hostname: "x".into(),
            rng_seed: vec![0; 64],
            time_unix_nanos: 0,
            env: vec![],
            proxy_port: 0,
            machine_id: "0".repeat(32),
            net_mode: pocket_proto::guest::NetMode::Proxy,
        },
    ];
    for req in refused {
        let what = format!("{req:?}");
        let r = ctl.request(req);
        let e = r.expect_err(&format!("sealed guest accepted {what}"));
        assert!(e.message.contains("restore hook"), "{e}");
    }
    let r = ctl.request(HostReq::Restored {
        generation: 1,
        rng_seed: (0..64).collect(),
        time_unix_nanos: 1_900_000_000_000_000_000,
        hostname: "after-restore".into(),
        machine_id: "ab".repeat(16),
        clone: true,
    });
    assert_eq!(r, Ok(Reply::Done));
    assert_eq!(sh(&mut ctl, u, "hostname").trim(), "after-restore");
    assert_eq!(
        sh(&mut ctl, u, "cat /etc/machine-id").trim(),
        "ab".repeat(16)
    );
    let year: i32 = sh(&mut ctl, u, "date -u +%Y").trim().parse().unwrap();
    assert_eq!(year, 2030);
    eprintln!(
        "sealed guest refused SessionCreate, Exec, AuthorizeAttach, Configure; ran after Restored"
    );
}

/// Template build, restore with the restore hook, clone uniqueness, and an automatic
/// rebuild when the template key changes.
#[test]
fn template_clones_are_unique_and_rebuilt_when_the_key_changes() {
    let Some(assets) = assets() else { return };
    // A private copy of the assets so the key can be changed without touching the real ones.
    let own = scratch_dir("tplassets");
    for f in [
        "bin",
        "kernel",
        "system.erofs",
        "test-base.erofs",
        "test-base.sha256",
    ] {
        let st = std::process::Command::new("cp")
            .args(["-a", "--reflink=auto"])
            .arg(assets.join(f))
            .arg(own.join(f))
            .status()
            .unwrap();
        assert!(st.success(), "copy {f}");
    }
    let env = Env::new("tpl", &own).with_templates(0);
    env.ok(&new_args("tpl-first"));
    let v = env.wait_templates("the first template", Duration::from_secs(60), |v| {
        !templates(v).is_empty()
    });
    let key1 = templates(&v)[0].clone();
    eprintln!("template {key1} built in the background");

    let mut started = vec![];
    for n in ["tpl-c1", "tpl-c2"] {
        let t = Instant::now();
        env.ok(&new_args(n));
        started.push(t.elapsed());
    }
    let ls = env.json(&["ls"]);
    for n in ["tpl-c1", "tpl-c2"] {
        let p = pocket(&ls, n);
        assert_eq!(p["started_from"], "template", "{p}");
        assert_eq!(p["template"], key1.as_str(), "{p}");
    }
    eprintln!("pocket new from the template: {started:?}");
    let ident = |n: &str| {
        env.ok(&[
            "exec",
            n,
            "--",
            "sh",
            "-c",
            "hostname; cat /etc/machine-id; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \\n'; echo",
        ])
    };
    let (a, b) = (ident("tpl-c1"), ident("tpl-c2"));
    eprintln!("tpl-c1:\n{a}tpl-c2:\n{b}");
    let (a, b): (Vec<&str>, Vec<&str>) = (a.lines().collect(), b.lines().collect());
    assert_eq!((a[0], b[0]), ("tpl-c1", "tpl-c2"), "hostnames");
    assert_eq!(a[1].len(), 32);
    assert_ne!(a[1], b[1], "machine-id must differ between clones");
    assert_ne!(a[2], b[2], "RNG output must differ between clones");
    // The restore hook ran before the session: its shell sees the new hostname.
    let shell_host = env.ok(&[
        "exec",
        "tpl-c1",
        "--",
        "sh",
        "-c",
        "cat /proc/$(pgrep -o -x sh)/environ >/dev/null; hostname",
    ]);
    assert_eq!(shell_host.trim(), "tpl-c1");
    assert!(
        env.log().contains("restored: generation") || env.log().contains("disk from template"),
        "{}",
        env.log()
    );

    // Change a key input (the system image): the next pocket boots cold and a new template
    // replaces the old one.
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(own.join("system.erofs"))
            .unwrap();
        f.write_all(&[0u8; 4096]).unwrap();
    }
    env.ok(&new_args("tpl-after"));
    let ls = env.json(&["ls"]);
    assert_eq!(pocket(&ls, "tpl-after")["started_from"], "cold");
    let v = env.wait_templates("the rebuilt template", Duration::from_secs(60), |v| {
        let t = templates(v);
        t.len() == 1 && t[0] != key1
    });
    eprintln!("key changed: {key1} replaced by {}", templates(&v)[0]);
    env.ok(&new_args("tpl-new"));
    let ls = env.json(&["ls"]);
    assert_eq!(pocket(&ls, "tpl-new")["started_from"], "template");
    // Pockets restored from the retired template keep working (their mapping stays valid).
    assert_eq!(env.ok(&["exec", "tpl-c1", "--", "echo", "ok"]).trim(), "ok");
    let _ = std::fs::remove_dir_all(&own);
}

#[test]
fn warm_pool_claims_refills_and_respects_its_memory_cap() {
    let Some(assets) = assets() else { return };
    // Cap fits one 512 MiB VM, not two.
    let env = Env::new("pool", &assets)
        .with_templates(2)
        .set("POCKET_POOL_MAX_MEMORY", "900M");
    env.ok(&new_args("pool-seed"));
    env.wait_templates("a pooled VM", Duration::from_secs(60), |v| {
        v["pool"]["ready"].as_u64() == Some(1)
    });
    std::thread::sleep(Duration::from_secs(6));
    let v = env.json(&["templates"]);
    assert_eq!(v["pool"]["ready"], 1, "memory cap exceeded: {v}");
    assert!(v["pool"]["memory_mib"].as_u64().unwrap() <= 900, "{v}");

    let t = Instant::now();
    env.ok(&new_args("pool-a"));
    let e2e = t.elapsed();
    let ls = env.json(&["ls"]);
    assert_eq!(pocket(&ls, "pool-a")["started_from"], "pool");
    assert_eq!(
        env.ok(&["exec", "pool-a", "--", "hostname"]).trim(),
        "pool-a"
    );
    let claim = env
        .log()
        .lines()
        .filter_map(|l| l.split("pool claim ready in ").nth(1))
        .filter_map(|r| r.split(" ms").next()?.parse::<f64>().ok())
        .next_back()
        .expect("claim latency logged");
    eprintln!("pool claim → ready {claim:.2} ms; pocket new end-to-end {e2e:?}");
    // The latency target (p50 ≤ 5 / p95 ≤ 15 ms) is `pocket bench`'s job and gated on a
    // known machine; one sample on a shared CI runner (nested virtualization) is not a
    // measurement. Here: a claim is a resume, not a restore or boot.
    assert!(claim < 150.0, "pool claim took {claim} ms");
    let v = env.wait_templates("the pool refill", Duration::from_secs(30), |v| {
        v["pool"]["ready"].as_u64() == Some(1) && v["pool"]["claimed"].as_u64() == Some(1)
    });
    eprintln!("refilled: {}", v["pool"]);
}

fn state(env: &Env, n: &str) -> String {
    pocket(&env.json(&["ls"]), n)["state"]
        .as_str()
        .unwrap()
        .to_string()
}

fn wait_state(env: &Env, n: &str, want: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while state(env, n) != want {
        assert!(
            Instant::now() < deadline,
            "{n} did not become {want}\n{}",
            env.log()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn pause_hibernate_resume_keep_state() {
    let Some(assets) = assets() else { return };
    let env = Env::new("hib", &assets).set("POCKET_IDLE_PAUSE", "never");
    env.ok(&new_args("hib"));
    env.ok(&["exec", "hib", "--", "sh", "-c", "echo kept > /tmp/mem-only"]);
    env.ok(&["sessions", "hib"]);
    let out = env.ok(&["pause", "hib"]);
    assert_eq!(state(&env, "hib"), "Paused", "{out}");
    // Any use resumes transparently.
    assert_eq!(
        env.ok(&["exec", "hib", "--", "cat", "/tmp/mem-only"])
            .trim(),
        "kept"
    );
    assert_eq!(state(&env, "hib"), "Running");
    env.ok(&["hibernate", "hib"]);
    assert_eq!(state(&env, "hib"), "Hibernated");
    let t = Instant::now();
    let out = env.ok(&[
        "exec",
        "hib",
        "--",
        "sh",
        "-c",
        "cat /tmp/mem-only; hostname",
    ]);
    eprintln!(
        "exec after hibernation (resume + exec) took {:?}",
        t.elapsed()
    );
    assert_eq!(out, "kept\nhib\n");
    let ls = env.json(&["ls"]);
    assert_eq!(pocket(&ls, "hib")["started_from"], "hibernation");
    // The shell session survived hibernation.
    assert!(env.ok(&["sessions", "hib"]).contains("shell"));
    env.ok(&["stop", "hib"]);
    env.ok(&["start", "hib"]);
    assert_eq!(env.ok(&["exec", "hib", "--", "echo", "up"]).trim(), "up");
}

/// The idle manager pauses then hibernates an idle pocket, and never touches a pocket
/// whose agent is busy (output, or CPU without output) or that has a client attached.
#[test]
fn idle_manager_spares_active_pockets() {
    let Some(assets) = assets() else { return };
    let env = Env::new("idle", &assets)
        .set("POCKET_IDLE_PAUSE", "3s")
        .set("POCKET_IDLE_HIBERNATE", "6s")
        .set("POCKET_IDLE_TICK", "500ms");
    for n in ["idle-quiet", "idle-output", "idle-cpu"] {
        env.ok(&new_args(n));
    }
    // An "agent" printing progress, and one computing silently.
    env.ok(&[
        "run-in",
        "idle-output",
        "--name",
        "agent",
        "--",
        "sh",
        "-c",
        "while :; do date; sleep 0.5; done",
    ]);
    env.ok(&[
        "run-in",
        "idle-cpu",
        "--name",
        "agent",
        "--",
        "sh",
        "-c",
        "while :; do :; done",
    ]);
    wait_state(&env, "idle-quiet", "Paused", Duration::from_secs(10));
    eprintln!("idle-quiet paused while the busy pockets kept running");
    wait_state(&env, "idle-quiet", "Hibernated", Duration::from_secs(15));
    eprintln!("idle-quiet hibernated");
    for n in ["idle-output", "idle-cpu"] {
        assert_eq!(state(&env, n), "Running", "{n} was paused while active");
    }
    let log = env.log();
    for n in ["idle-output", "idle-cpu"] {
        assert!(
            !log.contains(&format!("{n}: idle for")),
            "{n} judged idle:\n{log}"
        );
    }
    // Resumed on use, with its files.
    assert_eq!(
        env.ok(&["exec", "idle-quiet", "--", "hostname"]).trim(),
        "idle-quiet"
    );
}

fn git(repo: &std::path::Path, args: &[&str]) {
    let st = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["-c", "user.name=t", "-c", "user.email=t@t"])
        .args(args)
        .status()
        .unwrap();
    assert!(st.success(), "git {args:?}");
}

/// `sandbox.setup` becomes a snapshot template: later pockets restore it (memory included,
/// shown by a tmpfs file setup wrote), get their own identity and branch, and a committed
/// change to a setup input rebuilds it.
#[test]
fn project_setup_becomes_a_snapshot_template() {
    let Some(assets) = assets() else { return };
    let env = Env::new("psnap", &assets).with_templates(0);
    let repo = env.root.join("app");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    std::fs::write(repo.join("deps.txt"), "left-pad 1\n").unwrap();
    std::fs::write(
        repo.join("pocket.toml"),
        "version = 1\n[sandbox]\npreset = \"base\"\nsetup = \"cp deps.txt .setup-deps; date +%s%N > /dev/shm/setup-mem\"\nsetup_inputs = [\"deps.txt\"]\n",
    )
    .unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-qm", "init"]);
    let r = repo.to_str().unwrap().to_string();
    let new = |n: &str| {
        let o = env.pocket(&["new", n, "--repo", &r, "--detach", "--mem", "512M"]);
        assert!(o.status.success());
        String::from_utf8_lossy(&o.stderr).into_owned()
    };
    let sh = |n: &str, s: &str| env.ok(&["exec", n, "--", "sh", "-c", s]).trim().to_string();
    assert!(new("ps-1").contains("running setup"));
    let mem = sh("ps-1", "cat /dev/shm/setup-mem");
    let v = env.json(&["templates"]);
    let project: Vec<&serde_json::Value> = v["templates"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| t["kind"] == "project")
        .collect();
    assert_eq!(project.len(), 1, "{v}");
    let key1 = project[0]["key"].as_str().unwrap().to_string();
    let t = Instant::now();
    let out = new("ps-2");
    eprintln!(
        "second pocket from the project snapshot in {:?}",
        t.elapsed()
    );
    assert!(!out.contains("running setup"), "{out}");
    let ls = env.json(&["ls"]);
    assert_eq!(pocket(&ls, "ps-2")["started_from"], "template");
    assert_eq!(pocket(&ls, "ps-2")["template"], key1.as_str());
    assert_eq!(
        sh("ps-2", "cat /dev/shm/setup-mem"),
        mem,
        "memory came from the snapshot"
    );
    assert_eq!(sh("ps-2", "hostname"), "ps-2");
    assert_ne!(
        sh("ps-2", "cat /etc/machine-id"),
        sh("ps-1", "cat /etc/machine-id")
    );
    assert_eq!(
        sh("ps-2", "git -C /work branch --show-current"),
        "pocket/ps-2"
    );
    // The original keeps running after its snapshot, with its own identity.
    assert_eq!(sh("ps-1", "hostname"), "ps-1");
    std::fs::write(repo.join("deps.txt"), "left-pad 2\n").unwrap();
    git(&repo, &["commit", "-qam", "deps"]);
    assert!(new("ps-3").contains("running setup"));
    assert_eq!(sh("ps-3", "cat /work/.setup-deps"), "left-pad 2");
    let v = env.json(&["templates"]);
    let keys: Vec<&str> = v["templates"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| t["kind"] == "project")
        .filter_map(|t| t["key"].as_str())
        .collect();
    assert_eq!(keys.len(), 1, "old project template retired: {v}");
    assert_ne!(keys[0], key1);
}

/// Session states from the guest's last output, bell and tail: an agent quiet at a prompt
/// is "waiting" and the daemon notifies the desktop once; a bell is "waiting" at once.
#[test]
fn waiting_for_input_is_detected_and_notified() {
    let Some(assets) = assets() else { return };
    let log = std::env::temp_dir().join(format!("pkt-notify-{}.log", std::process::id()));
    let script = log.with_extension("sh");
    std::fs::write(
        &script,
        format!("#!/bin/sh\necho \"$@\" >> {}\n", log.display()),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let env = Env::new("wait", &assets)
        .set("POCKET_NOTIFY_CMD", script.to_str().unwrap())
        .set("POCKET_IDLE_PAUSE", "never")
        .set("POCKET_IDLE_TICK", "500ms");
    env.ok(&new_args("wait"));
    env.ok(&[
        "run-in",
        "wait",
        "--name",
        "agent",
        "--",
        "sh",
        "-c",
        "echo working; sleep 1; printf 'Apply these edits? [y/n] '; read x; echo got $x; sleep 600",
    ]);
    env.ok(&[
        "run-in",
        "wait",
        "--name",
        "belly",
        "--",
        "sh",
        "-c",
        "sleep 1; printf 'done\\a'; sleep 600",
    ]);
    let deadline = Instant::now() + Duration::from_secs(20);
    let text = loop {
        let t = std::fs::read_to_string(&log).unwrap_or_default();
        if t.contains("agent is waiting for input") && t.contains("belly rang the bell") {
            break t;
        }
        assert!(
            Instant::now() < deadline,
            "notifications so far: {t:?}\n{}",
            env.log()
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    eprintln!("notifications:\n{text}");
    assert!(text.contains("Apply these edits? [y/n]"), "{text}");
    assert_eq!(
        text.matches("agent is waiting").count(),
        1,
        "notified once: {text}"
    );
    let s = env.json(&["sessions", "wait"]);
    let states: Vec<(String, String)> = s
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["name"].as_str().unwrap().to_string(),
                x["state"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    eprintln!("session states: {states:?}");
    for (n, want) in [
        ("agent", "Waiting"),
        ("belly", "Waiting"),
        ("shell", "Idle"),
    ] {
        assert!(
            states.contains(&(n.to_string(), want.to_string())),
            "{n} not {want}: {states:?}"
        );
    }
    let _ = std::fs::remove_file(&log);
    let _ = std::fs::remove_file(&script);
}
