//! Egress v1 (M5): no NIC in the guest, env-proxy through the host proxy, profiles, and
//! every connection in `pocket logs --net`.

use pocket_tests::cli::Env;
use pocket_tests::kvm_or_skip;

fn setup(tag: &str) -> Option<Env> {
    let a = kvm_or_skip()?;
    Some(Env::new(tag, a.system.parent().unwrap()))
}

fn net_log(env: &Env, name: &str) -> Vec<serde_json::Value> {
    env.json(&["logs", name, "--net", "-n", "500"])
        .as_array()
        .unwrap()
        .clone()
}

fn verdict_for(log: &[serde_json::Value], host: &str) -> Vec<String> {
    log.iter()
        .filter(|e| e["host"] == host)
        .map(|e| e["verdict"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn no_nic_and_profiles_enforced_through_the_host_proxy() {
    let Some(env) = setup("egress") else { return };
    let id = std::process::id();
    let (dev, strict, off) = (format!("dev-{id}"), format!("strict-{id}"), format!("off-{id}"));
    for (n, p) in [(&dev, "dev"), (&strict, "strict"), (&off, "offline")] {
        env.ok(&["new", n, "--preset", "test", "--no-repo", "--net", p, "--detach"]);
    }
    // No network device but loopback; no default route.
    let ifs = env.ok(&["exec", &dev, "--", "ls", "/sys/class/net"]);
    assert_eq!(ifs.split_whitespace().collect::<Vec<_>>(), ["lo"]);
    assert!(env.ok(&["exec", &dev, "--", "cat", "/proc/net/route"]).lines().count() <= 1);
    let env_vars = env.ok(&["exec", &dev, "--", "sh", "-c", "echo $HTTPS_PROXY $NO_PROXY"]);
    assert_eq!(env_vars.trim(), "http://127.0.0.1:3128 localhost,127.0.0.1,::1");

    // Plain HTTP so busybox wget can be the client; verdicts come from the host log.
    let get = |n: &str, url: &str| {
        let _ = env.pocket(&["exec", n, "--", "wget", "-q", "-T", "15", "-O", "/dev/null", url]);
    };
    for n in [&dev, &strict, &off] {
        get(n, "http://archive.ubuntu.com/ubuntu/");
        get(n, "http://api.anthropic.com/");
        get(n, "http://example.com/");
    }
    let d = net_log(&env, &dev);
    let s = net_log(&env, &strict);
    let o = net_log(&env, &off);
    assert_eq!(verdict_for(&d, "archive.ubuntu.com"), ["Allowed"]);
    assert_eq!(verdict_for(&d, "api.anthropic.com"), ["Allowed"]);
    assert_eq!(verdict_for(&d, "example.com"), ["Denied"]);
    assert_eq!(verdict_for(&s, "archive.ubuntu.com"), ["Denied"], "strict has no package mirrors");
    assert_eq!(verdict_for(&s, "api.anthropic.com"), ["Allowed"]);
    for h in ["archive.ubuntu.com", "api.anthropic.com", "example.com"] {
        assert_eq!(verdict_for(&o, h), ["Denied"], "offline allows nothing ({h})");
    }
    let allowed = d.iter().find(|e| e["host"] == "archive.ubuntu.com").unwrap();
    assert!(allowed["bytes_down"].as_u64().unwrap() > 0 && allowed["status"].as_u64().is_some());
    let text = env.ok(&["logs", &dev, "--net"]);
    eprintln!("{text}");
    assert!(text.contains("✓ allowed") && text.contains("✗ BLOCKED"));
}

#[test]
fn private_ranges_denied_even_when_allowlisted_by_wildcard() {
    let Some(env) = setup("private") else { return };
    let n = format!("wild-{}", std::process::id());
    // A host-side service on loopback that must stay unreachable, explicitly allowlisted.
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    l.set_nonblocking(true).unwrap();
    let any_port = format!("*:{port}");
    env.ok(&[
        "new", &n, "--preset", "test", "--no-repo", "--detach", "--net", "offline", "--allow", "*",
        "--allow", "0.0.0.0/0", "--allow", "[::/0]", "--allow", &any_port,
    ]);
    for url in [
        format!("http://127.0.0.1:{port}/"),
        format!("http://localhost:{port}/"),
        "http://10.0.0.1/".to_string(),
        "http://192.168.1.1/".to_string(),
        "http://172.16.0.1/".to_string(),
        "http://169.254.169.254/latest/meta-data/".to_string(),
        "http://100.100.100.200/".to_string(),
        "http://[::1]/".to_string(),
        "http://[fd00:ec2::254]/".to_string(),
        "http://0x7f000001/".to_string(),
    ] {
        let o = env.pocket(&["exec", &n, "--", "wget", "-q", "-T", "5", "-O-", &url]);
        assert!(!o.status.success(), "{url} was reachable");
    }
    assert!(l.accept().is_err(), "the host loopback service received a connection");
    let log = net_log(&env, &n);
    assert!(log.len() >= 9, "{log:?}");
    for e in &log {
        assert_eq!(e["verdict"], "Denied", "{e}");
        let r = e["reason"].as_str().unwrap();
        assert!(r.contains("always denied") || r.contains("cannot resolve"), "{r}");
    }
    // The wildcard does allow public destinations.
    let o = env.pocket(&["exec", &n, "--", "wget", "-q", "-T", "15", "-O", "/dev/null", "http://example.com/"]);
    assert!(o.status.success());
}

#[test]
fn package_managers_work_through_the_dev_profile() {
    let Some(env) = setup("pkgs") else { return };
    let n = format!("pkgs-{}", std::process::id());
    env.ok(&["new", &n, "--preset", "base", "--no-repo", "--detach"]);
    let sh = |s: &str| env.ok(&["exec", &n, "--", "bash", "-lc", s]);
    sh("cd /tmp && npm install --no-fund --no-audit --prefix /tmp/n is-number@7 && test -f /tmp/n/node_modules/is-number/package.json");
    sh("python3 -m venv /tmp/v && /tmp/v/bin/pip install -q six==1.16.0 && /tmp/v/bin/python -c 'import six'");
    sh("cd /tmp && cargo new -q c && cd c && echo 'itoa = \"=1.0.11\"' >> Cargo.toml && cargo fetch -q && ls ~/.cargo/registry/cache/*/ | grep -q itoa-1.0.11");
    sh("curl -sSf -o /dev/null https://github.com/");
    let o = env.pocket(&["exec", &n, "--", "curl", "-sS", "-o", "/dev/null", "https://example.com/"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("403"), "{}", String::from_utf8_lossy(&o.stderr));
    let log = env.ok(&["logs", &n, "--net", "-n", "200"]);
    for h in ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "index.crates.io", "static.crates.io", "github.com"] {
        assert!(log.contains(&format!("{h}:443")), "{h} missing from the log:\n{log}");
    }
    assert!(log.contains("example.com:443") && log.contains("BLOCKED"));
}
