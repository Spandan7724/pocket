//! Clone-in over the vsock git transport (M5): branch, remotes, carry-over, and the host
//! repository left exactly as it was.

use std::path::Path;
use std::process::Command;

use pocket_tests::cli::Env;
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
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// Everything about the host repo the pocket must not change.
fn snapshot(dir: &Path) -> String {
    let mut s = git(
        dir,
        &[
            "status",
            "--porcelain=v2",
            "--branch",
            "--untracked-files=all",
        ],
    );
    s += &git(dir, &["for-each-ref"]);
    s += &git(dir, &["stash", "list"]);
    s += &std::fs::read_to_string(dir.join(".git/config")).unwrap();
    let mut hooks: Vec<_> = std::fs::read_dir(dir.join(".git/hooks"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    hooks.sort();
    let o = Command::new("sha256sum").args(&hooks).output().unwrap();
    s += &String::from_utf8_lossy(&o.stdout);
    s
}

fn host_repo(root: &Path) -> std::path::PathBuf {
    let d = root.join("webapp");
    std::fs::create_dir_all(&d).unwrap();
    git(&d, &["init", "-q", "-b", "main"]);
    git(&d, &["config", "user.name", "Host User"]);
    git(&d, &["config", "user.email", "host@example.com"]);
    std::fs::write(d.join("README.md"), "hello\n").unwrap();
    std::fs::write(d.join("app.js"), "console.log(1)\n").unwrap();
    git(&d, &["add", "."]);
    git(&d, &["commit", "-qm", "initial"]);
    std::fs::write(d.join("app.js"), "console.log(2)\n").unwrap();
    git(&d, &["commit", "-qam", "second"]);
    git(
        &d,
        &[
            "remote",
            "add",
            "origin",
            "git@github.com:example/webapp.git",
        ],
    );
    std::fs::write(
        d.join(".git/hooks/post-checkout"),
        "#!/bin/sh\ntouch /tmp/pocket-hook-ran\n",
    )
    .unwrap();
    // Uncommitted work: a tracked edit and an untracked file.
    std::fs::write(d.join("README.md"), "hello\nwork in progress\n").unwrap();
    std::fs::write(d.join("notes.txt"), "untracked\n").unwrap();
    d
}

#[test]
fn clone_in_branch_remotes_carry_and_host_untouched() {
    let Some(a) = kvm_or_skip() else { return };
    let env = Env::new("ws", a.system.parent().unwrap());
    let repo = host_repo(&env.root);
    let before = snapshot(&repo);
    let head = git(&repo, &["rev-parse", "HEAD"]).trim().to_string();
    let name = format!("webapp-{}", std::process::id() % 100000);

    let mut c = env.cmd("pocket");
    c.current_dir(&repo)
        .args(["new", &name, "--preset", "base", "--carry", "--detach"]);
    let o = c.output().unwrap();
    eprintln!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(o.status.success());

    let sh = |script: &str| env.ok(&["exec", &name, "--", "sh", "-c", script]);
    assert_eq!(
        sh("git -C /work branch --show-current").trim(),
        format!("pocket/{name}")
    );
    assert_eq!(sh("git -C /work rev-parse HEAD").trim(), head);
    let status = sh("git -C /work status --porcelain");
    assert_eq!(status, " M README.md\n?? notes.txt\n", "carried changes");
    assert_eq!(sh("cat /work/notes.txt"), "untracked\n");
    let remotes = sh("git -C /work remote -v");
    assert!(
        remotes.contains("origin\thttps://github.com/example/webapp.git (fetch)"),
        "{remotes}"
    );
    assert!(remotes.contains("host\tpocket://host (fetch)"), "{remotes}");
    assert_eq!(sh("git -C /work log --format=%s").trim(), "second\ninitial");
    assert_eq!(
        sh("git -C /work config user.email").trim(),
        "host@example.com"
    );
    assert_eq!(sh("stat -c %U /work/README.md").trim(), "dev");

    // The guest can fetch from the host again, but never push to it.
    git(&repo, &["branch", "feature"]);
    sh("git -C /work fetch -q host && git -C /work branch -r | grep -q host/feature");
    let o = env.pocket(&[
        "exec",
        &name,
        "--",
        "git",
        "-C",
        "/work",
        "push",
        "host",
        "HEAD:refs/heads/evil",
    ]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("not possible from inside a pocket"));
    git(&repo, &["branch", "-D", "feature"]);

    // The guest owns its repo, hooks included; none of it reaches the host.
    sh(
        "printf '#!/bin/sh\\ntouch /tmp/x\\n' > /work/.git/hooks/pre-commit; chmod +x /work/.git/hooks/pre-commit; git -C /work config core.fsmonitor 'touch /tmp/pwned'",
    );
    let after = snapshot(&repo);
    assert_eq!(before, after, "host repository changed");
    assert!(
        !Path::new("/tmp/pocket-hook-ran").exists(),
        "a host hook ran"
    );
    eprintln!("host repo unchanged: status, refs, stash, config and hooks hash identical");

    // Without --carry the pocket starts clean at HEAD.
    let clean = format!("clean-{}", std::process::id() % 100000);
    let mut c = env.cmd("pocket");
    c.current_dir(repo.join("."))
        .args(["new", &clean, "--preset", "base", "--detach"]);
    assert!(c.status().unwrap().success());
    assert_eq!(
        env.ok(&[
            "exec",
            &clean,
            "--",
            "git",
            "-C",
            "/work",
            "status",
            "--porcelain"
        ]),
        ""
    );
    assert_eq!(snapshot(&repo), before);
}
