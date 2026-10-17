//! M11: SSH over vsock (`pocket ssh-proxy`, `ssh`, `code`), `pocket cp` both ways with path
//! checks, `pocket save --as` templates, transparent networking and `--net full`.

use std::time::{Duration, Instant};

use pocket_tests::cli::{Env, bin_dir};
use pocket_tests::kvm_or_skip;

fn env(tag: &str) -> Option<Env> {
    let a = kvm_or_skip()?;
    Some(Env::new(tag, a.system.parent().unwrap()))
}

fn base(env: &Env, name: &str, extra: &[&str]) {
    let mut a = vec![
        "new",
        name,
        "--preset",
        "base",
        "--no-repo",
        "--detach",
        "--mem",
        "1G",
    ];
    a.extend_from_slice(extra);
    env.ok(&a);
}

#[test]
fn ssh_over_vsock_and_editor_config() {
    let Some(env) = env("ssh") else { return };
    let p = format!("ssh-{}", std::process::id());
    base(&env, &p, &[]);
    // `pocket ssh` creates pocket's key, starts the guest's sshd, pins its host key.
    assert_eq!(env.ok(&["ssh", &p, "--", "id", "-un"]).trim(), "dev");
    // Plain OpenSSH with pocket only as the ProxyCommand (what editors do).
    let key = env.root.join("data/pocket/ssh/id_ed25519");
    let mut c = std::process::Command::new("ssh");
    for (k, v) in [
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_STATE_HOME", "state"),
        ("XDG_RUNTIME_DIR", "run"),
        ("HOME", "home"),
    ] {
        c.env(k, env.root.join(v));
    }
    for (k, v) in &env.extra {
        c.env(k, v);
    }
    c.env("POCKET_ASSETS_DIR", &env.assets);
    let o = c
        .args(["-F", "/dev/null", "-i"])
        .arg(&key)
        .args(["-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no"])
        .args(["-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR"])
        .arg("-o")
        .arg(format!(
            "ProxyCommand={} ssh-proxy {p}",
            bin_dir().join("pocket").display()
        ))
        .arg(format!("dev@pocket-{p}"))
        .args([
            "sh",
            "-c",
            "'echo over-vsock $(hostname) $(cat /proc/sys/kernel/random/boot_id | cut -c1-4)'",
        ])
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&o.stdout);
    eprintln!("ssh: {out}{}", String::from_utf8_lossy(&o.stderr));
    assert!(
        o.status.success() && out.starts_with(&format!("over-vsock {p}")),
        "{out}"
    );
    // The guest has no network device: sshd is reachable only through vsock.
    let ifs = env.ok(&["exec", &p, "--", "ls", "/sys/class/net"]);
    assert_eq!(ifs.split_whitespace().collect::<Vec<_>>(), ["lo"]);
    let printed = env.ok(&["code", &p, "--editor", "code", "--print"]);
    assert!(
        printed.contains(&format!("code --remote ssh-remote+pocket-{p} /work")),
        "{printed}"
    );
    let conf = std::fs::read_to_string(env.root.join("home/.ssh/pocket/config")).unwrap();
    assert!(
        conf.contains(&format!("Host pocket-{p}")) && conf.contains("ssh-proxy"),
        "{conf}"
    );
    let main = std::fs::read_to_string(env.root.join("home/.ssh/config")).unwrap();
    assert!(main.starts_with("Include pocket/config"), "{main}");
    let zed = env.ok(&["code", &p, "--editor", "zed", "--print"]);
    assert!(
        zed.contains(&format!("zed ssh://dev@pocket-{p}/work")),
        "{zed}"
    );
}

#[test]
fn cp_both_ways_with_path_checks() {
    let Some(env) = env("cp") else { return };
    let p = format!("cp-{}", std::process::id());
    env.ok(&[
        "new",
        &p,
        "--preset",
        "test",
        "--no-repo",
        "--detach",
        "--mem",
        "512M",
    ]);
    let src = env.root.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("a.txt"), "alpha\n").unwrap();
    std::fs::write(src.join("sub/b.bin"), vec![7u8; 300_000]).unwrap();
    let r = env.ok(&["cp", src.to_str().unwrap(), &format!("{p}:/tmp")]);
    eprintln!("{r}");
    assert_eq!(
        env.ok(&["exec", &p, "--", "cat", "/tmp/src/a.txt"]),
        "alpha\n"
    );
    assert_eq!(
        env.ok(&["exec", &p, "--", "sh", "-c", "wc -c < /tmp/src/sub/b.bin"])
            .trim(),
        "300000"
    );
    // A file to a new name.
    env.ok(&[
        "cp",
        src.join("a.txt").to_str().unwrap(),
        &format!("{p}:/tmp/renamed.txt"),
    ]);
    assert_eq!(
        env.ok(&["exec", &p, "--", "cat", "/tmp/renamed.txt"]),
        "alpha\n"
    );

    // Out of the pocket: a symlink to a host path, a planted .git with a hook, a setuid
    // file and a device node must not come out as such.
    env.ok(&[
        "exec",
        &p,
        "--root",
        "--",
        "sh",
        "-c",
        "mkdir -p /tmp/out/.git/hooks /tmp/out/d && echo data > /tmp/out/d/f && \
         ln -s /home/spandan /tmp/out/link && echo evil > /tmp/out/.git/hooks/post-checkout && \
         echo s > /tmp/out/suid && chmod 4755 /tmp/out/suid && mknod /tmp/out/dev c 1 3",
    ]);
    let dst = env.root.join("got");
    let r = env.ok(&["cp", &format!("{p}:/tmp/out"), dst.to_str().unwrap()]);
    eprintln!("{r}");
    assert!(r.contains("skipped"), "{r}");
    assert_eq!(std::fs::read_to_string(dst.join("d/f")).unwrap(), "data\n");
    assert!(!dst.join(".git").exists(), "a .git came out of the pocket");
    assert!(
        std::fs::symlink_metadata(dst.join("link")).is_err(),
        "symlink came out"
    );
    assert!(
        std::fs::symlink_metadata(dst.join("dev")).is_err(),
        "device node came out"
    );
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(dst.join("suid"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o7000, 0, "setuid bit came out");
    // Into a .git directory is refused; `..` in a pocket path is refused.
    std::fs::create_dir_all(env.root.join("repo/.git")).unwrap();
    let o = env.pocket(&[
        "cp",
        &format!("{p}:/tmp/out/d"),
        env.root.join("repo/.git/hooks").to_str().unwrap(),
    ]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains(".git"));
    let o = env.pocket(&[
        "cp",
        &format!("{p}:/tmp/../etc/shadow"),
        env.root.join("x").to_str().unwrap(),
    ]);
    assert!(!o.status.success() && String::from_utf8_lossy(&o.stderr).contains(".."));
}

#[test]
fn saved_templates_restore_memory_with_a_new_identity() {
    let Some(env) = env("save") else { return };
    let env = env.with_templates(0);
    let id = std::process::id();
    let (a, b) = (format!("sv-a{id}"), format!("sv-b{id}"));
    env.ok(&[
        "new",
        &a,
        "--preset",
        "test",
        "--no-repo",
        "--detach",
        "--mem",
        "512M",
    ]);
    env.ok(&[
        "exec",
        &a,
        "--",
        "sh",
        "-c",
        "echo configured > /work/state; echo in-memory > /dev/shm/m",
    ]);
    let out = env.ok(&["save", &a, "--as", "mytpl"]);
    eprintln!("{out}");
    let t = env.json(&["templates"]);
    assert!(
        t["templates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "mytpl" && t["kind"] == "saved"),
        "{t}"
    );
    env.ok(&["new", &b, "--template", "mytpl", "--no-repo", "--detach"]);
    let sh = |n: &str, s: &str| env.ok(&["exec", n, "--", "sh", "-c", s]).trim().to_string();
    assert_eq!(
        sh(&b, "cat /work/state /dev/shm/m"),
        "configured\nin-memory"
    );
    assert_eq!(sh(&b, "hostname"), b);
    assert_ne!(sh(&b, "cat /etc/machine-id"), sh(&a, "cat /etc/machine-id"));
    // The original kept running and still works.
    assert_eq!(sh(&a, "cat /dev/shm/m"), "in-memory");
    let o = env.pocket(&["new", "--template", "nosuch", "--no-repo", "--detach"]);
    assert_eq!(o.status.code(), Some(3));
}

fn net_log(env: &Env, n: &str) -> Vec<serde_json::Value> {
    env.json(&["logs", n, "--net", "-n", "500"])
        .as_array()
        .unwrap()
        .clone()
}

/// A tool that ignores proxy settings still goes through policy and logging: names resolve
/// only when allowed, connections are checked like CONNECT, private ranges stay denied.
#[test]
fn transparent_mode_polices_tools_that_ignore_the_proxy() {
    let Some(env) = env("tnet") else { return };
    let p = format!("tn-{}", std::process::id());
    base(&env, &p, &["--transparent"]);
    let sh = |s: &str| env.pocket(&["exec", &p, "--", "bash", "-c", s]);
    let ok = |s: &str| {
        let o = sh(s);
        (
            o.status.success(),
            String::from_utf8_lossy(&o.stdout).into_owned(),
        )
    };
    // No proxy variables at all; curl talks straight to the "internet".
    let noproxy = "env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy -u ALL_PROXY";
    let (ok1, code) = ok(&format!(
        "{noproxy} curl -s -o /dev/null -w '%{{http_code}}' --max-time 20 https://api.anthropic.com/"
    ));
    eprintln!("allowed host: {ok1} {code}");
    assert!(
        ok1 && code.len() == 3 && code != "000",
        "allowed host unreachable: {code}"
    );
    let (resolved, addr) = ok("getent hosts api.anthropic.com | cut -d' ' -f1");
    assert!(resolved && addr.starts_with("198.18."), "{addr}");
    let (denied_dns, _) = ok("getent hosts example.com");
    assert!(!denied_dns, "a denied name resolved");
    let (denied, _) = ok(&format!(
        "{noproxy} curl -s --max-time 10 -o /dev/null http://1.1.1.1/"
    ));
    assert!(!denied, "an IP literal outside the policy got through");
    let (private, _) = ok(&format!(
        "{noproxy} curl -s --max-time 10 -o /dev/null http://10.0.0.1/"
    ));
    assert!(!private, "a private address got through");
    // busybox-style clients that send `GET https://` to proxies are fine here too.
    let deadline = Instant::now() + Duration::from_secs(10);
    let log = loop {
        let l = net_log(&env, &p);
        if l.iter()
            .any(|e| e["kind"] == "direct" && e["host"] == "api.anthropic.com")
            || Instant::now() > deadline
        {
            break l;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let find = |kind: &str, host: &str| {
        log.iter()
            .filter(|e| e["kind"] == kind && e["host"] == host)
            .map(|e| e["verdict"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    eprintln!("{}", env.ok(&["logs", &p, "--net"]));
    assert!(find("dns", "api.anthropic.com").contains(&"Allowed".into()));
    assert!(find("direct", "api.anthropic.com").contains(&"Allowed".into()));
    assert!(find("dns", "example.com").contains(&"Denied".into()));
    assert!(find("direct", "1.1.1.1").contains(&"Denied".into()));
    assert!(find("direct", "10.0.0.1").contains(&"Denied".into()));
    let ls = env.ok(&["ls"]);
    assert!(ls.contains("transparent networking"), "{ls}");
}

#[test]
fn full_network_is_a_real_nic_and_flagged() {
    let Some(env) = env("fnet") else { return };
    // passt comes with the assets (`cargo xtask passt`), like the VMM.
    let p = format!("fn-{}", std::process::id());
    let o = env.pocket(&[
        "new",
        &p,
        "--preset",
        "base",
        "--no-repo",
        "--detach",
        "--mem",
        "1G",
        "--net",
        "full",
    ]);
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("NOT filtered"));
    let ip = env.ok(&["exec", &p, "--", "sh", "-c", "ip -4 -o addr show eth0"]);
    assert!(ip.contains("10.0.2.15/24"), "{ip}");
    // Straight out, no proxy: a public HTTPS endpoint answers.
    let code = env.ok(&[
        "exec", &p, "--", "sh", "-c",
        "env -u HTTPS_PROXY -u https_proxy curl -s -o /dev/null -w '%{http_code}' --max-time 20 https://example.com/",
    ]);
    assert!(code.trim() != "000" && code.trim().len() == 3, "{code}");
    let ls = env.ok(&["ls"]);
    assert!(ls.contains("full network access"), "{ls}");
    let j = env.json(&["ls"]);
    assert_eq!(j[0]["net_mode"], "full");
    let o = env.pocket(&["hibernate", &p]);
    assert!(!o.status.success(), "a pocket with a NIC was hibernated");
}
