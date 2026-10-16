//! M7.5 + M8: host integrations. Runtime port forwarding, `pocket port/open`, URL opening
//! (http/https only, localhost rewritten), notifications, network approvals (CLI,
//! `pocket-guest allow`, project pocket.toml), `pocket.toml` + `pocket init`, opt-in
//! ssh-agent forwarding with per-signature approval, and the attach-side pieces (inline
//! notices, the approvals overlay, OSC 52 policy, image paste).

use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use pocket_tests::cli::Env;
use pocket_tests::kvm_or_skip;
use pocket_tests::pty::Pty;

const T: Duration = Duration::from_secs(30);

fn until<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + T;
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn recorder(dir: &Path, name: &str) -> (String, std::path::PathBuf) {
    let log = dir.join(format!("{name}.log"));
    let script = dir.join(format!("{name}.sh"));
    std::fs::write(
        &script,
        format!("#!/bin/sh\necho \"$@\" >> {}\n", log.display()),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    (script.to_string_lossy().into_owned(), log)
}

fn git(dir: &Path, args: &[&str]) {
    let o = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

fn http_get(port: u16, path: &str) -> String {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(T)).unwrap();
    write!(s, "GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

#[test]
fn ports_urls_notifications_approvals_and_project_config() {
    let Some(a) = kvm_or_skip() else { return };
    let mut env = Env::new("integr", a.system.parent().unwrap());
    let (open_cmd, open_log) = recorder(&env.root, "open");
    let (notify_cmd, notify_log) = recorder(&env.root, "notify");
    env.extra.push(("POCKET_OPEN_CMD".into(), open_cmd));
    env.extra.push(("POCKET_NOTIFY_CMD".into(), notify_cmd));
    let repo = env.root.join("proj");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    std::fs::write(
        repo.join("pocket.toml"),
        "version = 1\n[sandbox]\npreset = \"base\"\nenv = { FROM_TOML = \"yes\" }\n[network]\nprofile = \"strict\"\nallow = [\"example.net\"]\n",
    )
    .unwrap();
    git(&repo, &["add", "."]);
    git(
        &repo,
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-qm",
            "init",
        ],
    );

    let n = format!("int-{}", std::process::id());
    let o = env.pocket(&[
        "new",
        &n,
        "--repo",
        repo.to_str().unwrap(),
        "--detach",
        "--",
        "sh",
        "-c",
        "sleep 2; printf '\\033]777;notify;Build;done\\007'; sleep 1.5; printf '\\a'; exec sh",
    ]);
    assert!(o.status.success());
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("using"),
        "pocket.toml was used"
    );
    let sh = |s: &str| env.ok(&["exec", &n, "--", "bash", "-c", s]);
    assert_eq!(sh("echo $FROM_TOML").trim(), "yes");
    let info = env.json(&["ls"]);
    assert_eq!(info[0]["net_profile"], "strict");

    // Runtime port forwarding: a server started later is forwarded automatically.
    sh(
        "mkdir -p /tmp/w; echo hello-from-pocket > /tmp/w/index.html; setsid python3 -m http.server 8765 -d /tmp/w >/dev/null 2>&1 &",
    );
    let hp = until("port 8765 forwarded", || {
        let v = env.json(&["port", &n]);
        v.as_array()?
            .iter()
            .find(|p| p["guest"] == 8765)
            .map(|p| p["host"].as_u64().unwrap() as u16)
    });
    eprintln!("{}", env.ok(&["port", &n]));
    let page = http_get(hp, "/");
    assert!(page.contains("hello-from-pocket"), "{page}");
    // A fixed forward added at runtime.
    sh("setsid python3 -m http.server 8766 -d /tmp/w >/dev/null 2>&1 &");
    let free = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    env.ok(&["port", &n, &format!("8766:{free}")]);
    until("fixed forward", || {
        http_get(free, "/")
            .contains("hello-from-pocket")
            .then_some(())
    });
    env.ok(&["open", &n, "8765"]);
    let opened = until("pocket open", || {
        std::fs::read_to_string(&open_log)
            .ok()
            .filter(|l| !l.is_empty())
    });
    assert!(
        opened.contains(&format!("http://127.0.0.1:{hp}/")),
        "{opened}"
    );

    // URL opening from the guest: localhost → the forward; non-http refused.
    std::thread::sleep(Duration::from_millis(1100));
    sh("xdg-open 'http://localhost:8765/cb?code=42'");
    let opened = until("guest URL", || {
        std::fs::read_to_string(&open_log)
            .ok()
            .filter(|l| l.contains("cb?code"))
    });
    assert!(
        opened.contains(&format!("http://127.0.0.1:{hp}/cb?code=42")),
        "{opened}"
    );
    let o = env.pocket(&["exec", &n, "--", "xdg-open", "file:///etc/passwd"]);
    assert!(!o.status.success());
    assert!(
        !std::fs::read_to_string(&open_log)
            .unwrap()
            .contains("passwd")
    );

    // Notifications: OSC 777 from a session, and pocket-guest notify.
    let note = until("OSC 777 notification", || {
        std::fs::read_to_string(&notify_log)
            .ok()
            .filter(|l| l.contains("Build done"))
    });
    eprintln!("notifications:\n{note}");
    until("bell notification", || {
        std::fs::read_to_string(&notify_log)
            .ok()
            .filter(|l| l.contains("rang the bell"))
    });
    sh("pocket-guest notify --title Tests all green");
    until("pocket-guest notify", || {
        std::fs::read_to_string(&notify_log)
            .ok()
            .filter(|l| l.contains("Tests all green"))
    });

    // Network approvals: blocked by the profile → pending request; approve → allowed.
    let o = env.pocket(&[
        "exec",
        &n,
        "--",
        "curl",
        "-fsS",
        "-o",
        "/dev/null",
        "http://example.com/",
    ]);
    assert!(!o.status.success());
    sh("pocket-guest allow foo.example.org");
    let pending = until("two approvals", || {
        let v = env.json(&["approvals", &n]);
        (v.as_array()?.len() >= 2).then_some(v)
    });
    eprintln!("{}", env.ok(&["approvals"]));
    let id = |host: &str| {
        pending
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["what"]["Network"]["host"] == host)
            .unwrap()["id"]
            .as_u64()
            .unwrap()
            .to_string()
    };
    env.ok(&["approve", &id("example.com"), "--pocket"]);
    let code = sh("curl -sS -o /dev/null -w '%{http_code}' http://example.com/");
    assert_eq!(code.trim(), "200");
    env.ok(&["deny", &n, "foo.example.org"]);
    assert_eq!(env.json(&["approvals", &n]), serde_json::json!([]));
    // Allow for the project: written into pocket.toml, which stays valid.
    env.ok(&["allow", &n, "httpbin.org", "--project"]);
    let toml = std::fs::read_to_string(repo.join("pocket.toml")).unwrap();
    assert!(
        toml.contains("\"example.net\", \"httpbin.org\"") && toml.contains("FROM_TOML"),
        "{toml}"
    );
    // allow survives a restart (pocket scope is persisted).
    env.ok(&["stop", &n]);
    env.ok(&["start", &n]);
    assert_eq!(
        sh("curl -sS -o /dev/null -w '%{http_code}' http://example.com/").trim(),
        "200"
    );

    // pocket.toml validation with hints, and `pocket init`.
    let bad = env.root.join("bad");
    std::fs::create_dir_all(&bad).unwrap();
    git(&bad, &["init", "-q"]);
    std::fs::write(
        bad.join("pocket.toml"),
        "version = 1\n[sandbox]\npreest = \"base\"\n",
    )
    .unwrap();
    let o = env.pocket(&["new", "x2", "--repo", bad.to_str().unwrap(), "--detach"]);
    let err = String::from_utf8_lossy(&o.stderr);
    eprintln!("{err}");
    assert_eq!(o.status.code(), Some(2));
    assert!(
        err.contains("unknown key `sandbox.preest`")
            && err.contains("did you mean `sandbox.preset`?")
    );
    std::fs::remove_file(bad.join("pocket.toml")).unwrap();
    std::fs::write(bad.join("package.json"), "{}").unwrap();
    std::fs::write(bad.join("package-lock.json"), "{}").unwrap();
    let o = env
        .cmd("pocket")
        .arg("init")
        .current_dir(&bad)
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&o.stdout);
    eprintln!(
        "{out}{}",
        std::fs::read_to_string(bad.join("pocket.toml")).unwrap()
    );
    assert!(out.contains("detected Node.js"));
    assert!(
        std::fs::read_to_string(bad.join("pocket.toml"))
            .unwrap()
            .contains("setup = \"npm ci\"")
    );
}

#[test]
fn ssh_agent_forwarding_confirms_each_signature() {
    let Some(a) = kvm_or_skip() else { return };
    let mut env = Env::new("sshagent", a.system.parent().unwrap());
    let sock = env.root.join("agent.sock");
    let key = env.root.join("id_test");
    let agent = Command::new("ssh-agent")
        .arg("-D")
        .arg("-a")
        .arg(&sock)
        .spawn()
        .unwrap();
    struct Kill(std::process::Child);
    impl Drop for Kill {
        fn drop(&mut self) {
            let _ = self.0.kill();
        }
    }
    let _agent = Kill(agent);
    until("ssh-agent socket", || sock.exists().then_some(()));
    assert!(
        Command::new("ssh-keygen")
            .args([
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "pocket-test-key",
                "-f"
            ])
            .arg(&key)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("ssh-add")
            .arg(&key)
            .env("SSH_AUTH_SOCK", &sock)
            .output()
            .unwrap()
            .status
            .success()
    );
    env.extra
        .push(("SSH_AUTH_SOCK".into(), sock.to_string_lossy().into_owned()));

    let n = format!("ssh-{}", std::process::id());
    env.ok(&[
        "new",
        &n,
        "--preset",
        "base",
        "--no-repo",
        "--detach",
        "--ssh-agent",
    ]);
    let sh = |s: &str| env.pocket(&["exec", &n, "--", "bash", "-c", s]);
    let ids = sh("ssh-add -l");
    let ids = String::from_utf8_lossy(&ids.stdout).into_owned();
    assert!(ids.contains("pocket-test-key"), "{ids}");
    let pubkey = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    assert!(
        sh(&format!(
            "echo '{}' > /tmp/k.pub && echo data > /tmp/d",
            pubkey.trim()
        ))
        .status
        .success()
    );
    assert!(
        String::from_utf8_lossy(&sh("git config --system --get-regexp url || echo none").stdout)
            .contains("none"),
        "no SSH→HTTPS rewrite with agent forwarding"
    );

    let sign = |answer: &str| {
        let env2 = &env;
        let n2 = n.clone();
        std::thread::scope(|sc| {
            let n3 = n2.clone();
            let h = sc.spawn(move || {
                env2.pocket(&[
                    "exec",
                    &n3,
                    "--",
                    "bash",
                    "-c",
                    "rm -f /tmp/d.sig; ssh-keygen -Y sign -f /tmp/k.pub -n test /tmp/d",
                ])
            });
            let id = until("ssh sign approval", || {
                let v = env2.json(&["approvals", &n2]);
                v.as_array()?
                    .iter()
                    .find(|a| a["what"].get("SshSign").is_some())
                    .map(|a| a["id"].as_u64().unwrap())
            });
            eprintln!("{}", env2.ok(&["approvals"]));
            let mut args = vec!["approve".to_string(), id.to_string()];
            if answer == "deny" {
                args.push("--deny".into());
            }
            env2.ok(&args.iter().map(String::as_str).collect::<Vec<_>>());
            h.join().unwrap()
        })
    };
    let ok = sign("allow");
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert!(sh("test -s /tmp/d.sig").status.success());
    let no = sign("deny");
    assert!(!no.status.success());
    eprintln!("denied: {}", String::from_utf8_lossy(&no.stderr));
    // Adding keys through the forwarded agent is refused.
    let add = sh("ssh-keygen -q -t ed25519 -N '' -f /tmp/k2 && ssh-add /tmp/k2");
    assert!(!add.status.success());
    let ids = Command::new("ssh-add")
        .arg("-l")
        .env("SSH_AUTH_SOCK", &sock)
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&ids.stdout).lines().count(),
        1,
        "the host agent gained no key"
    );
}

#[test]
fn attach_notices_approval_overlay_clipboard_and_image_paste() {
    let Some(a) = kvm_or_skip() else { return };
    let mut env = Env::new("attachint", a.system.parent().unwrap());
    let png: Vec<u8> = [b"\x89PNG\r\n\x1a\n".as_slice(), &[7u8; 300]].concat();
    let img = env.root.join("shot.png");
    std::fs::write(&img, &png).unwrap();
    env.extra.push((
        "POCKET_CLIPBOARD_IMAGE_CMD".into(),
        format!("cat {}", img.display()),
    ));
    let n = format!("att-{}", std::process::id());
    env.ok(&[
        "new",
        &n,
        "--preset",
        "test",
        "--no-repo",
        "--detach",
        "--net",
        "offline",
    ]);
    let mut c = env.cmd("pocket");
    c.args(["attach", &n]);
    let mut p = Pty::spawn(c, 30, 120);
    p.wait_for("# ", 0, T);

    // Inline notice for a blocked request, then the approvals overlay.
    let o = env.pocket(&[
        "exec",
        &n,
        "--",
        "wget",
        "-q",
        "-T",
        "5",
        "-O",
        "/dev/null",
        "http://example.com/",
    ]);
    assert!(!o.status.success());
    let rows = p.wait_rows(
        |r| {
            r.last()
                .is_some_and(|l| l.contains("pocket ▸ blocked example.com — Ctrl-] a to review"))
        },
        T,
    );
    eprintln!("notice: {}", rows.last().unwrap().trim_end());
    p.write(b"\x1da");
    p.wait_screen(|s| s.contains("network access to example.com"), T);
    p.write(b"p");
    p.wait_screen(|s| s.contains("nothing is waiting for you"), T);
    p.write(b"q");
    assert_eq!(env.json(&["approvals", &n]), serde_json::json!([]));
    assert!(
        env.pocket(&[
            "exec",
            &n,
            "--",
            "wget",
            "-q",
            "-T",
            "15",
            "-O",
            "/dev/null",
            "http://example.com/"
        ])
        .status
        .success()
    );

    // Inline notice for a newly forwarded port.
    std::thread::sleep(Duration::from_secs(6));
    let o = env.pocket(&[
        "exec",
        &n,
        "--",
        "sh",
        "-c",
        "nc -lk -p 8780 >/dev/null 2>&1 </dev/null & sleep 0.2; netstat -ltn | grep -q 8780",
    ]);
    assert!(o.status.success(), "nc listener");
    let rows = p.wait_rows(
        |r| {
            r.last()
                .is_some_and(|l| l.contains("pocket ▸ port 8780 forwarded to 127.0.0.1:"))
        },
        T,
    );
    eprintln!("notice: {}", rows.last().unwrap().trim_end());
    // OSC 52: writes pass (default allow), reads never do.
    let m = p.mark();
    p.write(b"printf '\\033]52;c;aGk=\\007'; printf '\\033]52;c;?\\007'; echo osc-done\r");
    p.wait_for("osc-done\r\n", m, T);
    assert!(p.wait_bytes(b"\x1b]52;c;aGk=\x07", m, Duration::from_secs(1)));
    assert!(
        !p.wait_bytes(b"\x1b]52;c;?", m, Duration::from_millis(200)),
        "clipboard read reached the host terminal"
    );

    // Image paste: Ctrl-V uploads the host clipboard image for the guest's xclip shim; a
    // pasted image path becomes the path inside the pocket.
    p.write(b"\x16x\x15");
    let shim = until("pasted image", || {
        let o = env.pocket(&["exec", &n, "--", "sh", "-c", "xclip -selection clipboard -t TARGETS -o && xclip -selection clipboard -t image/png -o | md5sum"]);
        o.status
            .success()
            .then(|| String::from_utf8_lossy(&o.stdout).into_owned())
    });
    let want = Command::new("md5sum").arg(&img).output().unwrap();
    let want = String::from_utf8_lossy(&want.stdout)
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    assert!(
        shim.starts_with("image/png") && shim.contains(&want),
        "{shim}"
    );
    let m = p.mark();
    p.write(b"cat > /tmp/pasted\r");
    p.wait_for("cat > /tmp/pasted", m, T);
    std::thread::sleep(Duration::from_millis(300));
    p.write(format!("\x1b[200~{}\x1b[201~\r", img.display()).as_bytes());
    std::thread::sleep(Duration::from_millis(300));
    p.write(b"\x04");
    let pasted = until("pasted text", || {
        let o = env.pocket(&["exec", &n, "--", "cat", "/tmp/pasted"]);
        let t = String::from_utf8_lossy(&o.stdout).into_owned();
        t.contains("/tmp/pocket-paste/paste-").then_some(t)
    });
    eprintln!("pasted: {pasted:?}");
    assert!(
        !pasted.contains(img.to_str().unwrap()),
        "the host path reached the guest"
    );
    assert!(env.pocket(&["exec", &n, "--", "sh", "-c", "test -s \"$(sed 's/.*\\(\\/tmp\\/pocket-paste\\/paste-[0-9]*\\.png\\).*/\\1/' /tmp/pasted)\""]).status.success());

    // Deny policy (global config) after reattaching.
    p.write(b"\x1dd");
    p.wait_exit(T);
    std::fs::create_dir_all(env.root.join("config/pocket")).unwrap();
    std::fs::write(
        env.root.join("config/pocket/config.toml"),
        "[ui]\nclipboard_osc52 = \"deny\"\n",
    )
    .unwrap();
    let mut c = env.cmd("pocket");
    c.args(["attach", &n]);
    let mut p = Pty::spawn(c, 30, 120);
    std::thread::sleep(Duration::from_millis(500));
    let m = p.mark();
    p.write(b"printf '\\033]52;c;aGk=\\007'; echo osc2-done\r");
    p.wait_for("osc2-done\r\n", m, T);
    assert!(!p.wait_bytes(b"\x1b]52;c;aGk=", m, Duration::from_millis(500)));
    p.wait_rows(
        |r| {
            r.last()
                .is_some_and(|l| l.contains("blocked a clipboard write"))
        },
        T,
    );
    p.write(b"\x1dd");
    p.wait_exit(T);
}

#[test]
fn setup_builds_a_project_template() {
    let Some(a) = kvm_or_skip() else { return };
    let env = Env::new("setup", a.system.parent().unwrap());
    let repo = env.root.join("app");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    std::fs::write(repo.join("deps.txt"), "left-pad 1\n").unwrap();
    std::fs::write(
        repo.join("pocket.toml"),
        "version = 1\n[sandbox]\npreset = \"base\"\nsetup = \"date +%s%N > .setup-stamp; cp deps.txt .setup-deps\"\nsetup_inputs = [\"deps.txt\"]\n",
    )
    .unwrap();
    git(&repo, &["add", "."]);
    git(
        &repo,
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-qm",
            "init",
        ],
    );
    let r = repo.to_str().unwrap();
    let new = |n: &str| {
        let o = env.pocket(&["new", n, "--repo", r, "--detach"]);
        assert!(o.status.success());
        String::from_utf8_lossy(&o.stderr).into_owned()
    };
    let sh = |n: &str, s: &str| {
        env.ok(&["exec", n, "--", "bash", "-c", s])
            .trim()
            .to_string()
    };
    let p = std::process::id();
    let (a1, a2, a3) = (format!("s1-{p}"), format!("s2-{p}"), format!("s3-{p}"));
    let t1 = std::time::Instant::now();
    assert!(new(&a1).contains("running setup"));
    let first = t1.elapsed();
    let stamp = sh(&a1, "cat /work/.setup-stamp");
    let t2 = std::time::Instant::now();
    let out = new(&a2);
    eprintln!(
        "first pocket (setup) {first:.1?}, second (template) {:.1?}",
        t2.elapsed()
    );
    assert!(
        !out.contains("running setup") && out.contains("updating the template"),
        "{out}"
    );
    assert_eq!(
        sh(&a2, "cat /work/.setup-stamp"),
        stamp,
        "setup output came from the template"
    );
    assert_eq!(
        sh(&a2, "git -C /work branch --show-current"),
        format!("pocket/{a2}")
    );
    assert_eq!(
        sh(
            &a2,
            "git -C /work branch --format='%(refname:short)' | grep '^pocket/'"
        ),
        format!("pocket/{a2}")
    );
    let head = Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert_eq!(
        sh(&a2, "git -C /work rev-parse HEAD"),
        String::from_utf8_lossy(&head.stdout).trim()
    );
    // An uncommitted edit doesn't reach the pocket, so the template still applies…
    std::fs::write(repo.join("deps.txt"), "left-pad 2\n").unwrap();
    let a4 = format!("s4-{p}");
    assert!(!new(&a4).contains("running setup"));
    // …a committed change to an input means a new template.
    git(
        &repo,
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-qam",
            "deps",
        ],
    );
    assert!(new(&a3).contains("running setup"));
    assert_eq!(sh(&a3, "cat /work/.setup-deps"), "left-pad 2");
    assert_ne!(sh(&a3, "cat /work/.setup-stamp"), stamp);
}
