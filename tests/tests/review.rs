//! M7: the review loop (`diff`, `apply`, `pr`, `sync`) against a local bare remote and a
//! fake GitHub (smart HTTP via `git http-backend`, REST API), the git escape tests (planted
//! hooks, core.fsmonitor, filters, malicious .gitmodules must not run on the host), push
//! guardrails at the proxy, and SSH remotes rewritten to HTTPS.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use pocket_tests::cli::Env;
use pocket_tests::fake::{self, Req, Resp};
use pocket_tests::kvm_or_skip;

fn git(dir: &Path, args: &[&str]) -> String {
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
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

/// Smart-HTTP git server: one `git http-backend` CGI run per request.
fn http_backend(root: &Path, r: &Req) -> Resp {
    let (path, query) = r.path.split_once('?').unwrap_or((&r.path, ""));
    let mut c = Command::new("git");
    c.arg("http-backend")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("GIT_PROJECT_ROOT", root)
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env("REQUEST_METHOD", &r.method)
        .env("PATH_INFO", path)
        .env("QUERY_STRING", query)
        .env("REMOTE_USER", "pocket-test")
        .env("REMOTE_ADDR", "127.0.0.1")
        .env("CONTENT_LENGTH", r.body.len().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if let Some(t) = r.header("content-type") {
        c.env("CONTENT_TYPE", t);
    }
    if let Some(e) = r.header("content-encoding") {
        c.env("HTTP_CONTENT_ENCODING", e);
    }
    if let Some(p) = r.header("git-protocol") {
        c.env("GIT_PROTOCOL", p);
    }
    let mut ch = c.spawn().unwrap();
    ch.stdin.take().unwrap().write_all(&r.body).unwrap();
    let out = ch.wait_with_output().unwrap().stdout;
    let split = out
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, 4))
        .or_else(|| out.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2)))
        .unwrap();
    let head = String::from_utf8_lossy(&out[..split.0]).into_owned();
    let mut resp = Resp {
        status: 200,
        content_type: "text/plain".into(),
        headers: vec![],
        body: out[split.0 + split.1..].to_vec(),
    };
    for l in head.lines() {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let v = v.trim().to_string();
        match k.trim().to_ascii_lowercase().as_str() {
            "status" => resp.status = v.split(' ').next().unwrap().parse().unwrap(),
            "content-type" => resp.content_type = v,
            _ => resp.headers.push((k.trim().to_string(), v)),
        }
    }
    resp
}

const HOOKS: &[&str] = &[
    "pre-commit",
    "post-commit",
    "post-checkout",
    "post-merge",
    "pre-push",
    "post-rewrite",
    "reference-transaction",
    "pre-rebase",
    "fsmonitor-watchman",
    "pre-auto-gc",
    "post-index-change",
];

#[test]
fn review_loop_escape_tests_guardrails_and_ssh_rewrite() {
    let Some(a) = kvm_or_skip() else { return };
    let mut env = Env::new("review", a.system.parent().unwrap());
    let root = env.root.clone();
    let remote_root = root.join("remote");
    let bare = remote_root.join("o/r.git");
    let repo = root.join("repo");
    let mark: PathBuf = root.join("ESCAPED");
    std::fs::create_dir_all(&bare).unwrap();
    git(&bare, &["init", "-q", "--bare", "-b", "main"]);
    git(&bare, &["config", "http.receivepack", "true"]);
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    for (k, v) in [
        ("user.name", "Host"),
        ("user.email", "host@example.com"),
        ("commit.gpgsign", "false"),
    ] {
        git(&repo, &["config", k, v]);
    }
    std::fs::write(repo.join("a.txt"), "one\n").unwrap();
    git(&repo, &["add", "a.txt"]);
    git(&repo, &["commit", "-qm", "init"]);
    git(
        &repo,
        &["remote", "add", "origin", "https://github.com/o/r.git"],
    );
    git(
        &repo,
        &[
            "config",
            &format!("url.file://{}/.insteadOf", remote_root.display()),
            "https://github.com/",
        ],
    );
    git(&repo, &["push", "-q", "origin", "main"]);
    git(&repo, &["branch", "m1"]);
    git(&repo, &["branch", "m2"]);
    let hooks_before = git(
        &repo,
        &["ls-files", "--others", "-o", "--directory", ".git/hooks"],
    );
    let config_before = std::fs::read_to_string(repo.join(".git/config")).unwrap();

    let rr = remote_root.clone();
    let prs: Arc<std::sync::Mutex<Vec<String>>> = Default::default();
    let prs2 = prs.clone();
    let fk = fake::start(
        &["github.com", "api.github.com"],
        &root.join("fake"),
        Arc::new(move |r: &Req| {
            if r.sni == "api.github.com" {
                prs2.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&r.body).into_owned());
                return Resp {
                    status: 201,
                    content_type: "application/json".into(),
                    headers: vec![],
                    body: br#"{"number":1,"html_url":"https://github.com/o/r/pull/1"}"#.to_vec(),
                };
            }
            http_backend(&rr, r)
        }),
    );
    env.extra
        .push(("POCKETD_TEST_UPSTREAM".into(), fk.upstream_env()));
    env.extra.push((
        "SSL_CERT_FILE".into(),
        fk.ca_file.to_string_lossy().into_owned(),
    ));
    assert!(
        env.pocket_stdin(
            &["login", "github"],
            "ghp_FAKEGITHUBTOKEN0123456789abcdefghijkl"
        )
        .status
        .success()
    );

    let n = format!("rv-{}", std::process::id());
    env.ok(&[
        "new",
        &n,
        "--preset",
        "base",
        "--repo",
        repo.to_str().unwrap(),
        "--detach",
    ]);
    let sh = |s: &str| env.ok(&["exec", &n, "--", "bash", "-c", s]);
    let m = mark.display();

    // Planted escape vectors. Every one would create a file under MARK if it ran.
    let mut plant = String::from("set -e; cd /work\n");
    for h in HOOKS {
        plant.push_str(&format!(
            "printf '#!/bin/sh\\nmkdir -p {m} && touch {m}/hook-%s\\n' {h} > .git/hooks/{h}; chmod +x .git/hooks/{h}\n"
        ));
    }
    plant.push_str(&format!(
        "git config core.fsmonitor 'mkdir -p {m}; touch {m}/fsmonitor; echo'\n\
         git config filter.evil.clean 'mkdir -p {m}; touch {m}/filter-clean; cat'\n\
         git config filter.evil.smudge 'mkdir -p {m}; touch {m}/filter-smudge; cat'\n\
         git config diff.evil.textconv 'mkdir -p {m}; touch {m}/textconv; cat'\n\
         git config core.sshCommand 'mkdir -p {m}; touch {m}/ssh'\n\
         printf '* filter=evil diff=evil\\n' > .gitattributes\n\
         cat > .gitmodules <<'EOM'\n[submodule \"x\"]\n\tpath = x\n\turl = ext::sh -c mkdir% -p% {m}%;touch% {m}/submodule\nEOM\n\
         git update-index --add --cacheinfo 160000,$(git rev-parse HEAD),x\n\
         echo two > b.txt\n\
         git add .gitattributes .gitmodules b.txt && git commit -qm 'add b'\n\
         echo three > c.txt; echo changed >> a.txt\n"
    ));
    sh(&plant);
    // Positive control: in the pocket the planted config is live.
    let ctl = sh(&format!(
        "cd /work && git status >/dev/null; git checkout -q -b probe && git checkout -q -; ls {m}"
    ));
    eprintln!(
        "ran inside the pocket: {}",
        ctl.split_whitespace().collect::<Vec<_>>().join(" ")
    );
    assert!(ctl.contains("fsmonitor") && ctl.contains("hook-post-checkout"));

    // diff (committed, --stat, --uncommitted)
    let d = env.ok(&["diff", &n]);
    assert!(
        d.contains("+two") && d.contains("b.txt") && !d.contains("c.txt"),
        "{d}"
    );
    let st = env.ok(&["diff", &n, "--stat"]);
    assert!(st.contains("b.txt") && st.contains("changed"), "{st}");
    let du = env.ok(&["diff", &n, "--uncommitted"]);
    assert!(
        du.contains("c.txt") && du.contains("+changed") && du.contains("b.txt"),
        "{du}"
    );
    let refs = git(&repo, &["for-each-ref", "--format=%(refname)"]);
    eprintln!("host refs:\n{refs}");
    for r in refs.lines() {
        assert!(
            r.starts_with(&format!("refs/pocket/{n}/"))
                || [
                    "refs/heads/main",
                    "refs/heads/m1",
                    "refs/heads/m2",
                    "refs/remotes/origin/main"
                ]
                .contains(&r),
            "unexpected ref {r}"
        );
    }
    assert!(
        refs.contains(&format!("refs/pocket/{n}/pocket/{n}"))
            && refs.contains(&format!("refs/pocket/{n}/__uncommitted"))
    );
    assert!(
        !repo.join(".git/FETCH_HEAD").exists(),
        "fetch wrote FETCH_HEAD"
    );
    assert_eq!(
        std::fs::read_to_string(repo.join(".git/config")).unwrap(),
        config_before
    );
    assert_eq!(git(&repo, &["status", "--porcelain"]), "");

    // apply: squash onto main, merge onto m1, cherry-pick onto m2
    let out = env.ok(&["apply", &n]);
    assert!(out.contains("squashed") && out.contains("main"), "{out}");
    assert_eq!(
        std::fs::read_to_string(repo.join("b.txt")).unwrap(),
        "two\n"
    );
    assert!(git(&repo, &["log", "-1", "--format=%B"]).contains("- add b"));
    let out = env.ok(&["apply", &n, "--merge", "--onto", "m1"]);
    assert!(out.contains("merged") && out.contains("m1"), "{out}");
    assert_eq!(git(&repo, &["rev-list", "--count", "--merges", "m1"]), "1");
    let out = env.ok(&["apply", &n, "--cherry-pick", "--onto", "m2"]);
    assert!(out.contains("cherry-picked"), "{out}");
    assert_eq!(git(&repo, &["log", "-1", "--format=%s", "m2"]), "add b");
    git(&repo, &["switch", "-q", "main"]);
    // Dirty host tree: apply refuses.
    std::fs::write(repo.join("a.txt"), "local edit\n").unwrap();
    let o = env.pocket(&["apply", &n]);
    assert_eq!(o.status.code(), Some(5));
    git(&repo, &["checkout", "-q", "a.txt"]);

    // pr: pushed from the host to the bare remote, PR opened on the fake API.
    let out = env.ok(&["pr", &n, "--title", "Pocket work", "--draft"]);
    assert!(out.contains("https://github.com/o/r/pull/1"), "{out}");
    assert_eq!(
        git(&bare, &["rev-parse", &format!("refs/heads/pocket/{n}")]),
        git(
            &repo,
            &["rev-parse", &format!("refs/pocket/{n}/pocket/{n}")]
        )
    );
    let pr: serde_json::Value = serde_json::from_str(&prs.lock().unwrap()[0]).unwrap();
    assert_eq!(
        (
            pr["head"].as_str(),
            pr["base"].as_str(),
            pr["title"].as_str(),
            pr["draft"].as_bool()
        ),
        (
            Some(&*format!("pocket/{n}")),
            Some("main"),
            Some("Pocket work"),
            Some(true)
        )
    );
    let api = fk
        .requests()
        .into_iter()
        .find(|r| r.sni == "api.github.com")
        .unwrap();
    assert_eq!(api.path, "/repos/o/r/pulls");
    assert_eq!(
        api.header("authorization").as_deref(),
        Some("Bearer ghp_FAKEGITHUBTOKEN0123456789abcdefghijkl")
    );

    // sync: new host commit reaches the pocket.
    std::fs::write(repo.join("d.txt"), "from host\n").unwrap();
    git(&repo, &["add", "d.txt"]);
    git(&repo, &["commit", "-qm", "host change"]);
    sh("cd /work && git stash -q -u");
    let out = env.ok(&["sync", &n]);
    eprintln!("{out}");
    assert_eq!(sh("cat /work/d.txt").trim(), "from host");

    // Push guardrails at the proxy (guest git → fake github.com through interception).
    git(&bare, &["update-ref", "refs/heads/release/1", "main"]);
    git(&bare, &["update-ref", "refs/heads/someone-else", "main"]);
    let main_before = git(&bare, &["rev-parse", "main"]);
    let push = |args: &str| {
        env.pocket(&[
            "exec",
            &n,
            "--",
            "bash",
            "-c",
            &format!("cd /work && git push {args} 2>&1"),
        ])
    };
    let ok = push(&format!("origin HEAD:refs/heads/pocket/{n}-guest"));
    assert!(ok.status.success(), "allowed pattern must pass");
    assert_eq!(
        git(
            &bare,
            &["rev-parse", &format!("refs/heads/pocket/{n}-guest")]
        ),
        sh("cd /work && git rev-parse HEAD").trim()
    );
    for (args, why) in [
        ("--force origin HEAD:main", "protected branch"),
        ("origin :release/1", "deleting a protected branch"),
        (
            "origin HEAD:refs/heads/someone-else",
            "not created in this pocket",
        ),
        ("origin HEAD:refs/tags/v9", "only branches"),
    ] {
        let o = push(args);
        let text = String::from_utf8_lossy(&o.stdout);
        eprintln!("git push {args}:\n{text}");
        assert!(!o.status.success() && text.contains(why), "{args}: {text}");
    }
    assert_eq!(git(&bare, &["rev-parse", "main"]), main_before);
    assert!(git(&bare, &["for-each-ref", "refs/heads/release/1"]).contains("release/1"));
    let log = env.ok(&["logs", &n, "--net", "-n", "100"]);
    assert!(
        log.contains("POST /o/r.git/git-rece") && log.contains("push blocked"),
        "{log}"
    );
    // New branch created by the pocket may be pushed again (force included).
    assert!(
        push(&format!(
            "--force origin HEAD~1:refs/heads/pocket/{n}-guest"
        ))
        .status
        .success()
    );

    // SSH remotes go over HTTPS through the proxy.
    let rw = sh("git config --system --get-regexp 'url\\..*insteadof'");
    assert!(
        rw.contains("git@github.com:") && rw.contains("ssh://git@github.com/"),
        "{rw}"
    );
    let ls = sh("git ls-remote git@github.com:o/r.git refs/heads/main");
    assert!(ls.contains(&main_before), "{ls}");

    // Nothing planted ran on the host at any point.
    assert!(
        !mark.exists(),
        "escape: {:?}",
        std::fs::read_dir(&mark).map(|d| d.flatten().map(|e| e.file_name()).collect::<Vec<_>>())
    );
    assert_eq!(
        git(
            &repo,
            &["ls-files", "--others", "-o", "--directory", ".git/hooks"]
        ),
        hooks_before
    );
    assert!(!repo.join("x/.git").exists(), "submodule was cloned");
    eprintln!(
        "escape tests: no planted hook, fsmonitor, filter, textconv, sshCommand or submodule ran on the host"
    );
}
