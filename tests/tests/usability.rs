//! SideKernel usability checklist (LANDSCAPE.md, arXiv 2610.02456 Appendix A) — the items
//! not already proven by other tests. Prints a per-item result; docs/LOG.md has the full
//! 23-item scorecard with the test that proves each one.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use pocket_tests::cli::Env;
use pocket_tests::kvm_or_skip;

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

#[test]
fn sidekernel_checklist() {
    let Some(a) = kvm_or_skip() else { return };
    let env = Env::new("usab", a.system.parent().unwrap());
    let mut card: Vec<(&str, bool, String)> = vec![];
    let share = env.root.join("shared");
    let big = env.root.join("big");
    std::fs::create_dir_all(&share).unwrap();
    std::fs::create_dir_all(&big).unwrap();
    std::fs::write(share.join("from-host.txt"), "hello from the host\n").unwrap();
    std::fs::write(share.join("script.sh"), "#!/bin/sh\necho ran\n").unwrap();
    std::fs::set_permissions(
        share.join("script.sh"),
        std::fs::Permissions::from_mode(0o751),
    )
    .unwrap();
    std::os::unix::fs::symlink("from-host.txt", share.join("link")).unwrap();
    // 10 GiB, sparse, with random data at both ends.
    let f = std::fs::File::create(big.join("ten.bin")).unwrap();
    f.set_len(10 << 30).unwrap();
    drop(f);
    for seek in ["0", "10239"] {
        assert!(
            Command::new("dd")
                .args([
                    "if=/dev/urandom",
                    &format!("of={}", big.join("ten.bin").display()),
                    "bs=1M",
                    "count=1",
                    &format!("seek={seek}"),
                    "conv=notrunc",
                    "status=none"
                ])
                .status()
                .unwrap()
                .success()
        );
    }
    let secret_file = env.root.join("outside.txt");
    std::fs::write(&secret_file, "outside the share\n").unwrap();

    let repo = env.root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    std::fs::write(repo.join("a.txt"), "one\n").unwrap();
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
    std::fs::write(repo.join("new-on-host.txt"), "untracked\n").unwrap();
    std::fs::write(repo.join("a.txt"), "two\n").unwrap();

    let n = format!("ux-{}", std::process::id());
    let o = env.pocket(&[
        "new",
        &n,
        "--preset",
        "base",
        "--repo",
        repo.to_str().unwrap(),
        "--carry",
        "--detach",
        "--share-dir",
        &format!("{}:/mnt/shared", share.display()),
        "--share-dir",
        &format!("{}:/mnt/big:ro", big.display()),
    ]);
    assert!(o.status.success());
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("is shared writable"),
        "share is visibly flagged"
    );
    let sh = |s: &str| env.pocket(&["exec", &n, "--", "bash", "-c", s]);
    let out = |s: &str| String::from_utf8_lossy(&sh(s).stdout).trim().to_string();

    // UB-1 T1: both directions, create/read/delete.
    let t1 = out("cat /mnt/shared/from-host.txt") == "hello from the host"
        && sh("echo from-guest > /mnt/shared/g.txt && rm /mnt/shared/from-host.txt")
            .status
            .success()
        && std::fs::read_to_string(share.join("g.txt")).is_ok_and(|t| t == "from-guest\n")
        && !share.join("from-host.txt").exists();
    card.push((
        "UB-1 T1 shared folder read/write/delete both ways",
        t1,
        "--share-dir (virtio-fs)".into(),
    ));
    // T2: permission bits.
    let guest_mode = out("stat -c %a /mnt/shared/script.sh");
    let ran = out("/mnt/shared/script.sh");
    sh("echo x > /mnt/shared/p.txt && chmod 640 /mnt/shared/p.txt");
    let host_mode = std::fs::metadata(share.join("p.txt"))
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0);
    let t2 = guest_mode == "751" && ran == "ran" && host_mode == 0o640;
    card.push((
        "UB-1 T2 permission bits",
        t2,
        format!("host 751 → guest {guest_mode}; guest 640 → host {host_mode:o}"),
    ));
    card.push((
        "UB-1 T3 file watcher sees host edits",
        false,
        "virtio-fs has no host→guest change notifications".into(),
    ));
    // T4: a host file outside the share, on request, with approval, no restart.
    sh(&format!(
        "pocket-guest request-file {}",
        secret_file.display()
    ));
    let deadline = Instant::now() + Duration::from_secs(20);
    let id = loop {
        let v = env.json(&["approvals", &n]);
        if let Some(a) = v
            .as_array()
            .and_then(|a| a.iter().find(|x| x["what"].get("File").is_some()))
        {
            break a["id"].as_u64().unwrap();
        }
        assert!(Instant::now() < deadline, "no file request");
        std::thread::sleep(Duration::from_millis(200));
    };
    env.ok(&["approve", &id.to_string()]);
    let t4 = out("cat /tmp/pocket-files/outside.txt") == "outside the share";
    card.push((
        "UB-1 T4 host file outside the share, with approval",
        t4,
        "pocket-guest request-file + pocket approve".into(),
    ));
    // T7: files created in the pocket belong to the host user.
    let uid = unsafe { libc::getuid() };
    let t7 = std::fs::metadata(share.join("g.txt")).is_ok_and(|m| m.uid() == uid);
    card.push((
        "UB-1 T7 guest-created files owned by the host user",
        t7,
        format!("uid {uid}"),
    ));
    // T8: symlinks.
    std::fs::write(share.join("from-host.txt"), "again\n").unwrap();
    let t8 = out("cat /mnt/shared/link") == "again"
        && out("readlink /mnt/shared/link") == "from-host.txt";
    card.push(("UB-1 T8 symlink in the shared folder", t8, String::new()));
    // T9: a 10 GiB file matches its host checksum.
    let started = Instant::now();
    let host_sum = String::from_utf8_lossy(
        &Command::new("sha256sum")
            .arg(big.join("ten.bin"))
            .output()
            .unwrap()
            .stdout,
    )
    .split_whitespace()
    .next()
    .unwrap()
    .to_string();
    let guest_sum = out("sha256sum /mnt/big/ten.bin | cut -d' ' -f1");
    let t9 = host_sum == guest_sum;
    card.push((
        "UB-1 T9 10 GiB file checksum",
        t9,
        format!("{:.0?} for host+guest sha256", started.elapsed()),
    ));

    // UB-3 T6: a new host file shows up in the pocket's repository.
    let st = out("cd /work && git status --porcelain");
    let df = out("cd /work && git diff --stat");
    let t6 = st.contains("?? new-on-host.txt") && df.contains("a.txt");
    card.push((
        "UB-3 T6 host changes visible to git in the pocket",
        t6,
        "pocket new --carry".into(),
    ));
    // UB-3 T1, T3, T4, T5: agent preinstalled, state across a restart.
    let t1u = sh("claude --version").status.success();
    card.push((
        "UB-3 T1 Claude Code present on first boot",
        t1u,
        out("claude --version"),
    ));
    sh("echo \"alias hi='echo hello-alias'\" >> ~/.bashrc");
    let pip = sh("python3 -m venv ~/venv && ~/venv/bin/pip install -q six==1.16.0");
    env.ok(&["stop", &n]);
    env.ok(&["start", &n]);
    let alias = out("tail -1 ~/.bashrc; bash -ic 'type hi' 2>&1 | tail -1");
    let t4u = alias.contains("aliased to `echo hello-alias'");
    card.push((
        "UB-3 T4 shell alias survives a restart",
        t4u,
        alias.replace('\n', " | "),
    ));
    let t5u = pip.status.success() && sh("~/venv/bin/python -c 'import six'").status.success();
    card.push(("UB-3 T5 pip packages survive a restart", t5u, String::new()));
    let t3u =
        sh("claude --version").status.success() && out("cat /mnt/shared/g.txt") == "from-guest";
    card.push((
        "UB-3 T3 Claude present after a restart (shares remounted)",
        t3u,
        String::new(),
    ));
    card.push((
        "UB-3 T7 live checkpoint of running state",
        false,
        "snapshots/hibernate arrive in M9".into(),
    ));

    eprintln!("\nSideKernel checklist items checked here:");
    for (name, ok, note) in &card {
        eprintln!(
            "  {} {name}{}",
            if *ok { "✓" } else { "✗" },
            if note.is_empty() {
                String::new()
            } else {
                format!(" — {note}")
            }
        );
    }
    let expected_fail = ["UB-1 T3", "UB-3 T7"];
    for (name, ok, _) in &card {
        assert!(
            *ok || expected_fail.iter().any(|f| name.starts_with(f)),
            "{name} failed"
        );
    }
}
