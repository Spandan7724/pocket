//! M6: host-side secrets, the pocket CA, selective TLS interception and credential
//! injection, against local fake HTTPS upstreams. Proves that real values reach only the
//! bound upstreams and never the guest (grep of the guest disk and a guest memory dump).

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use pocket_tests::cli::Env;
use pocket_tests::fake::{self, Req, Resp};
use pocket_tests::kvm_or_skip;

fn rand_alnum(n: usize) -> String {
    let mut b = vec![0u8; n];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom").unwrap(), &mut b).unwrap();
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    b.into_iter()
        .map(|x| A[x as usize % A.len()] as char)
        .collect()
}

fn b64url(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..=c.len() {
            out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

fn jwt(exp: u64, tag: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!(
        "{}.{}.{}",
        b64url(br#"{"alg":"RS256","typ":"JWT"}"#),
        b64url(
            format!(
                r#"{{"exp":{},"email":"t@example.com","tag":"{tag}","https://api.openai.com/auth":{{"chatgpt_account_id":"acct-1"}}}}"#,
                now + exp
            )
            .as_bytes()
        ),
        rand_alnum(86)
    )
}

/// Occurrences of `needle` in a (possibly huge, sparse) file.
fn grep_count(file: &Path, needle: &str) -> u64 {
    let o = Command::new("grep")
        .args(["-a", "-c", "-F", needle])
        .arg(file)
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stdout)
        .trim()
        .parse()
        .unwrap_or(0)
}

#[test]
fn credentials_are_injected_and_never_enter_the_guest() {
    let Some(a) = kvm_or_skip() else { return };
    let mut env = Env::new("secrets", a.system.parent().unwrap());
    let claude = format!("sk-ant-api03-{}", rand_alnum(48));
    let openai = format!("sk-proj-{}", rand_alnum(48));
    let github = format!("ghp_{}", rand_alnum(36));
    let (access2, id2, rt2) = (
        jwt(86_400, "access2"),
        jwt(86_400, "id2"),
        format!("rt_{}", rand_alnum(40)),
    );
    let (access1, id1, rt1) = (
        jwt(60, "access1"),
        jwt(86_400, "id1"),
        format!("rt_{}", rand_alnum(40)),
    );
    let reply =
        format!(r#"{{"access_token":"{access2}","id_token":"{id2}","refresh_token":"{rt2}"}}"#);
    let handler: fake::Handler = Arc::new(move |r: &Req| {
        if r.sni == "auth.openai.com" && r.path == "/oauth/token" {
            return Resp {
                status: 200,
                content_type: "application/json".into(),
                headers: vec![],
                body: reply.clone().into_bytes(),
            };
        }
        Resp::text(200, "upstream")
    });
    let fk = fake::start(
        &[
            "api.anthropic.com",
            "api.openai.com",
            "api.github.com",
            "chatgpt.com",
            "auth.openai.com",
            "free.example.com",
        ],
        &env.root.join("fake"),
        handler,
    );
    env.extra
        .push(("POCKETD_TEST_UPSTREAM".into(), fk.upstream_env()));
    env.extra.push((
        "SSL_CERT_FILE".into(),
        fk.ca_file.to_string_lossy().into_owned(),
    ));
    // Codex ChatGPT login on the "host" (the test HOME).
    let codex = env.root.join("home/.codex");
    std::fs::create_dir_all(&codex).unwrap();
    std::fs::write(
        codex.join("auth.json"),
        format!(r#"{{"OPENAI_API_KEY":null,"tokens":{{"id_token":"{id1}","access_token":"{access1}","refresh_token":"{rt1}","account_id":"acct-1"}},"last_refresh":"2026-10-01T00:00:00Z"}}"#),
    )
    .unwrap();

    assert!(
        env.pocket_stdin(&["login", "claude"], &claude)
            .status
            .success()
    );
    assert!(
        env.pocket_stdin(&["login", "github"], &github)
            .status
            .success()
    );
    assert!(
        env.pocket_stdin(&["login", "openai", "--name", "openai-key"], &openai)
            .status
            .success()
    );
    assert!(
        env.pocket_stdin(&["login", "openai", "--from-codex", "--name", "codex"], "")
            .status
            .success()
    );
    let ls = env.ok(&["secrets", "ls"]);
    eprintln!("{ls}");
    for s in [&claude, &openai, &github, &rt1] {
        assert!(!ls.contains(s.as_str()), "secrets ls printed a value");
    }
    let listed = env.json(&["secrets", "ls"]);
    assert_eq!(listed.as_array().unwrap().len(), 4);
    assert!(
        listed
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["storage"] == "file")
    );
    let enc = env.root.join("data/pocket/secrets.enc");
    for s in [&claude, &openai, &github, &rt1] {
        assert_eq!(
            grep_count(&enc, s),
            0,
            "secrets.enc holds a plaintext value"
        );
    }
    use std::os::unix::fs::PermissionsExt;
    let ca_key = env.root.join("data/pocket/ca/ca.key");

    let n = format!("sec-{}", std::process::id());
    env.ok(&[
        "new",
        &n,
        "--preset",
        "base",
        "--no-repo",
        "--detach",
        "--mem",
        "1G",
        "--disk",
        "4G",
        "--allow",
        "free.example.com",
        "--allow",
        "chatgpt.com",
        "--allow",
        "auth.openai.com",
    ]);
    assert_eq!(
        std::fs::metadata(&ca_key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let sh = |s: &str| env.ok(&["exec", &n, "--", "bash", "-lc", s]);

    // Placeholders, shaped like the real values.
    let vars = sh("echo $ANTHROPIC_API_KEY $OPENAI_API_KEY $GH_TOKEN");
    let vars: Vec<&str> = vars.split_whitespace().collect();
    assert_eq!(vars.len(), 3, "{vars:?}");
    assert!(vars[0].starts_with("sk-ant-api03-") && vars[0] != claude);
    assert!(vars[1].starts_with("sk-proj-") && vars[1] != openai);
    assert!(vars[2].starts_with("ghp_") && vars[2] != github);

    // curl (system bundle), node (NODE_EXTRA_CA_CERTS) and python (system bundle) all trust
    // the pocket CA for bound hosts.
    let code = sh(
        r#"curl -sS -o /dev/null -w '%{http_code}' https://api.anthropic.com/v1/messages -H "x-api-key: $ANTHROPIC_API_KEY" -d '{}'"#,
    );
    assert_eq!(code.trim(), "200");
    let out = sh(
        r#"node -e "fetch('https://api.openai.com/v1/models',{headers:{authorization:'Bearer '+process.env.OPENAI_API_KEY}}).then(r=>r.text()).then(t=>console.log(t))""#,
    );
    assert_eq!(out.trim(), "upstream");
    let out = sh(
        r#"python3 -c "import os,urllib.request as u; r=u.Request('https://api.github.com/user',headers={'Authorization':'token '+os.environ['GH_TOKEN']}); print(u.urlopen(r).read().decode())""#,
    );
    assert_eq!(out.trim(), "upstream");
    let cred = sh("printf 'protocol=https\\nhost=github.com\\n\\n' | git credential fill");
    assert!(
        cred.contains(&format!("password={}", vars[2])) && cred.contains("username=x-access-token"),
        "{cred}"
    );
    let stores = sh(
        "grep -c 'BEGIN CERTIFICATE' /etc/pocket/ca.crt; key=$(sed -n 2p /etc/pocket/ca.crt); grep -lF \"$key\" /etc/ssl/certs/ca-certificates.crt; python3 -c 'import certifi; print(certifi.where())' 2>/dev/null | xargs -r grep -lF \"$key\" || true",
    );
    eprintln!("trust stores:\n{stores}");
    assert!(stores.contains("/etc/ssl/certs/ca-certificates.crt"));

    // Bound domain → pocket CA leaf; un-bound domain → the upstream's real certificate.
    let issuer = |h: &str| {
        sh(&format!(
            "echo | openssl s_client -proxy 127.0.0.1:3128 -connect {h}:443 -servername {h} 2>/dev/null | openssl x509 -noout -issuer"
        ))
    };
    let bound = issuer("api.anthropic.com");
    let free = issuer("free.example.com");
    eprintln!("bound: {bound}free:  {free}");
    assert!(bound.contains("pocket CA"), "{bound}");
    assert!(free.contains("pocket test fake upstream CA"), "{free}");
    let o = env.pocket(&[
        "exec",
        &n,
        "--",
        "bash",
        "-lc",
        "curl -sS https://free.example.com/",
    ]);
    assert!(
        !o.status.success(),
        "the guest must not trust the fake upstream's CA (proves no interception)"
    );

    // ChatGPT login: placeholder tokens; refresh answered by pocket after a host-side refresh.
    let auth = sh("cat ~/.codex/auth.json");
    let v: serde_json::Value = serde_json::from_str(&auth).unwrap();
    let ph_access = v["tokens"]["access_token"].as_str().unwrap().to_string();
    let ph_refresh = v["tokens"]["refresh_token"].as_str().unwrap().to_string();
    assert!(ph_access != access1 && ph_refresh != rt1 && v["tokens"]["account_id"] == "acct-1");
    assert_eq!(
        ph_access.split('.').nth(1),
        access1.split('.').nth(1),
        "claims preserved"
    );
    sh(&format!(
        r#"curl -sSf -o /dev/null https://chatgpt.com/backend-api/codex/responses -H "Authorization: Bearer {ph_access}" -d '{{}}'"#
    ));
    let refreshed = sh(&format!(
        r#"curl -sSf https://auth.openai.com/oauth/token -H 'Content-Type: application/json' -d '{{"client_id":"x","grant_type":"refresh_token","refresh_token":"{ph_refresh}"}}'"#
    ));
    let r: serde_json::Value = serde_json::from_str(&refreshed).unwrap();
    let ph_access2 = r["access_token"].as_str().unwrap().to_string();
    assert!(
        ph_access2 != access2
            && ph_access2 != ph_access
            && r["refresh_token"] == ph_refresh.as_str()
    );
    assert_eq!(ph_access2.split('.').nth(1), access2.split('.').nth(1));
    sh(&format!(
        r#"curl -sSf -o /dev/null https://chatgpt.com/backend-api/codex/responses -H "Authorization: Bearer {ph_access2}""#
    ));
    let host_auth = std::fs::read_to_string(codex.join("auth.json")).unwrap();
    assert!(
        host_auth.contains(&rt2) && host_auth.contains(&access2),
        "host Codex login kept in step"
    );

    let reqs = fk.requests();
    let find = |sni: &str| {
        reqs.iter()
            .filter(move |r| r.sni == sni)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        find("api.anthropic.com")[0].header("x-api-key").as_deref(),
        Some(claude.as_str())
    );
    assert_eq!(
        find("api.openai.com")[0].header("authorization"),
        Some(format!("Bearer {openai}"))
    );
    assert_eq!(
        find("api.github.com")[0].header("authorization"),
        Some(format!("token {github}"))
    );
    let chat = find("chatgpt.com");
    assert_eq!(
        chat[0].header("authorization"),
        Some(format!("Bearer {access1}"))
    );
    assert_eq!(
        chat[1].header("authorization"),
        Some(format!("Bearer {access2}"))
    );
    let refresh = find("auth.openai.com");
    assert_eq!(
        refresh.len(),
        1,
        "the guest's refresh was answered by pocket"
    );
    let body = String::from_utf8_lossy(&refresh[0].body);
    assert!(
        body.contains(&rt1) && body.contains("app_EMoamEEZ73f0CkXaXp7hrann"),
        "{body}"
    );
    for r in &reqs {
        for ph in [
            vars[0],
            vars[1],
            vars[2],
            &ph_access,
            &ph_refresh,
            &ph_access2,
        ] {
            assert!(
                !r.head.contains(ph),
                "placeholder leaked upstream: {}",
                r.head
            );
        }
    }
    let log = env.json(&["logs", &n, "--net", "-n", "200"]);
    let injected = log
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["injected"] == true)
        .count();
    assert!(injected >= 5, "{log}");
    eprintln!("{}", env.ok(&["logs", &n, "--net"]));

    // No real value anywhere in the guest: disk image and a full memory dump. Positive
    // control: the placeholders are found where the guest put them.
    sh(r#"echo "$ANTHROPIC_API_KEY $GH_TOKEN" > ~/placeholders.txt; sync"#);
    let disk = env.root.join(format!(
        "data/pocket/pockets/{}/disk.raw",
        env.json(&["ls"])
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == n.as_str())
            .unwrap()["id"]
            .as_str()
            .unwrap()
    ));
    let mem = env.memory_dump(
        &n,
        &Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("memdump-{}", std::process::id())),
    );
    eprintln!(
        "disk {} ({} MiB allocated), memory {} ({} MiB)",
        disk.display(),
        std::fs::metadata(&disk)
            .map(|m| (std::os::unix::fs::MetadataExt::blocks(&m) * 512) >> 20)
            .unwrap_or(0),
        mem.display(),
        std::fs::metadata(&mem).unwrap().len() >> 20
    );
    assert!(
        grep_count(&disk, vars[0]) > 0,
        "positive control: placeholder on disk"
    );
    assert!(
        grep_count(&mem, vars[0]) > 0,
        "positive control: placeholder in memory"
    );
    for (what, s) in [
        ("claude", &claude),
        ("openai", &openai),
        ("github", &github),
        ("access1", &access1),
        ("access2", &access2),
        ("rt1", &rt1),
        ("rt2", &rt2),
    ] {
        let (d, m) = (grep_count(&disk, s), grep_count(&mem, s));
        eprintln!("{what}: {d} hits on disk, {m} in memory");
        assert_eq!((d, m), (0, 0), "real {what} found in the guest");
    }
    let _ = std::fs::remove_dir_all(mem.parent().unwrap());
}

#[test]
fn copy_secret_is_an_explicit_opt_in() {
    let Some(a) = kvm_or_skip() else { return };
    let env = Env::new("copysec", a.system.parent().unwrap());
    let value = format!("custom-{}", rand_alnum(32));
    let o = env.pocket_stdin(
        &[
            "secrets",
            "add",
            "svc",
            "--host",
            "api.example.net",
            "--env",
            "SVC_TOKEN",
        ],
        &value,
    );
    assert!(o.status.success());
    let n1 = format!("ph-{}", std::process::id());
    let n2 = format!("cp-{}", std::process::id());
    env.ok(&["new", &n1, "--preset", "test", "--no-repo", "--detach"]);
    let o = env.pocket(&[
        "new",
        &n2,
        "--preset",
        "test",
        "--no-repo",
        "--detach",
        "--copy-secret",
        "svc",
    ]);
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("warning: --copy-secret"));
    let get = |n: &str| {
        env.ok(&["exec", n, "--", "sh", "-c", "echo $SVC_TOKEN"])
            .trim()
            .to_string()
    };
    let ph = get(&n1);
    assert!(ph.starts_with("pocket-") && ph != value);
    assert_eq!(get(&n2), value);
    let bound = env.json(&[
        "secrets",
        "bind",
        "svc",
        "--host",
        "*.example.org",
        "--env",
        "SVC2",
        "--header",
        "X-Api-Key: {}",
    ]);
    assert_eq!(
        bound["hosts"],
        serde_json::json!(["api.example.net", "*.example.org"])
    );
    assert_eq!(bound["env"], serde_json::json!(["SVC_TOKEN", "SVC2"]));
    assert!(
        !env.pocket(&["secrets", "bind", "svc", "--host", "10.0.0.0/8"])
            .status
            .success()
    );
    assert!(
        !env.pocket(&["secrets", "rm", "svc"]).status.success(),
        "rm needs confirmation"
    );
    env.ok(&["secrets", "rm", "-f", "svc"]);
    assert_eq!(env.json(&["secrets", "ls"]), serde_json::json!([]));
    // Unknown secrets are an error, not a silent skip.
    let o = env.pocket(&[
        "new",
        "x1",
        "--preset",
        "test",
        "--no-repo",
        "--detach",
        "--secret",
        "nope",
    ]);
    assert_eq!(o.status.code(), Some(3));
}
