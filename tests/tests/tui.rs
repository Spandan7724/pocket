//! Full-screen programs redraw correctly after reattaching on a different terminal size,
//! and agent CLIs start in their presets (M4, M5).

use std::time::Duration;

use pocket_tests::cli::Env;
use pocket_tests::kvm_or_skip;
use pocket_tests::pty::{Pty, is_cooked};

const T: Duration = Duration::from_secs(60);

fn attach(env: &Env, name: &str, rows: u16, cols: u16) -> Pty {
    let mut c = env.cmd("pocket");
    c.args(["attach", name]);
    Pty::spawn(c, rows, cols)
}

/// Starts `cmd` in a session, checks `ok` at 24×80, detaches, reattaches at 30×100 and
/// checks `ok` again against the new size (the program must have repainted).
fn reattach_redraws(
    env: &Env,
    name: &str,
    session: &str,
    cmd: &str,
    quit: &[u8],
    ok: impl Fn(&[String], usize) -> bool,
) {
    let mut p = attach(env, name, 24, 80);
    p.wait_for("$ ", 0, T);
    p.write(format!("{cmd}\r").as_bytes());
    let first = p.wait_rows(|r| ok(r, 24), T);
    eprintln!("{session} at 24x80:\n{}", first.join("\n"));
    p.write(&[0x1d, b'd']);
    assert!(p.wait_exit(T).success());
    assert!(is_cooked(&p.termios()));

    let mut q = attach(env, name, 30, 100);
    let again = q.wait_rows(|r| ok(r, 30), T);
    eprintln!("{session} after reattach at 30x100:\n{}", again.join("\n"));
    std::thread::sleep(Duration::from_millis(400));
    let m = q.mark();
    q.write(quit);
    q.wait_for("$ ", m, T);
    q.write(&[0x1d, b'd']);
    assert!(q.wait_exit(T).success());
}

#[test]
fn vim_and_htop_redraw_after_reattach() {
    let Some(a) = kvm_or_skip() else { return };
    let env = Env::new("tui", a.system.parent().unwrap());
    let n = format!("tui-{}", std::process::id());
    env.ok(&["new", &n, "--preset", "base", "--no-repo", "--detach"]);
    env.ok(&[
        "exec",
        &n,
        "--",
        "sh",
        "-c",
        "printf 'pocket-vim-marker\\nsecond line\\n' > /tmp/x.txt",
    ]);
    reattach_redraws(
        &env,
        &n,
        "vim",
        "vim /tmp/x.txt",
        b"\x1b:q!\r",
        |r, rows| {
            r.len() == rows
                && r[0].starts_with("pocket-vim-marker")
                && r[2].starts_with('~')
                && r[rows - 2].starts_with('~')
                && r[rows - 1].contains("All")
        },
    );
    reattach_redraws(&env, &n, "htop", "htop", b"q", |r, rows| {
        r.len() == rows
            && r.iter().take(4).any(|l| l.contains("Mem["))
            && r[rows - 1].contains("Quit")
    });
}

#[test]
fn claude_code_and_codex_start_in_their_presets() {
    let Some(a) = kvm_or_skip() else { return };
    let env = Env::new("agents", a.system.parent().unwrap());
    for (preset, bin, needle) in [
        ("claude", "claude", "Claude Code"),
        ("codex", "codex", "codex"),
    ] {
        let n = format!("{preset}-{}", std::process::id());
        env.ok(&["new", &n, "--preset", preset, "--no-repo", "--detach"]);
        let v = env.ok(&["exec", &n, "--", bin, "--version"]);
        eprintln!("{bin} --version: {v}");
        assert!(!v.trim().is_empty());
        let mut p = attach(&env, &n, 30, 110);
        p.wait_for("$ ", 0, T);
        p.write(format!("{bin}\r").as_bytes());
        let screen = p.wait_screen(
            |s| {
                s.to_lowercase().contains(&needle.to_lowercase())
                    && s.lines().filter(|l| !l.trim().is_empty()).count() > 3
            },
            T,
        );
        eprintln!("{bin} TUI at 30x110:\n{screen}");
        p.write(&[0x1d, b'd']);
        assert!(p.wait_exit(T).success());
        // Reattach at another size: the agent TUI repaints for it.
        let q = attach(&env, &n, 40, 140);
        let again = q.wait_screen(|s| s.to_lowercase().contains(&needle.to_lowercase()), T);
        eprintln!("{bin} TUI after reattach at 40x140:\n{again}");
        drop(q);
        env.ok(&["rm", "-f", &n]);
    }
}
