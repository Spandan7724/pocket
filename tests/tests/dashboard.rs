//! The dashboard (`pocket` without arguments) on a real pseudo-terminal: live data, a preview
//! that never resizes or types into a session, no waking of paused pockets, a clean hand-over
//! to a full attach and back, and actions from keys.

use std::time::{Duration, Instant};

use pocket_tests::cli::Env;
use pocket_tests::kvm_or_skip;
use pocket_tests::pty::{Pty, is_cooked};

const T: Duration = Duration::from_secs(20);

fn state(env: &Env, n: &str) -> String {
    env.json(&["ls"])
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == n)
        .map(|p| p["state"].as_str().unwrap().to_string())
        .unwrap_or_default()
}

fn wait_state(env: &Env, n: &str, want: &str) {
    let deadline = Instant::now() + T;
    while state(env, n) != want {
        assert!(Instant::now() < deadline, "{n} never became {want}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn dashboard_previews_attaches_and_acts_without_disturbing_sessions() {
    let Some(a) = kvm_or_skip() else { return };
    let env = Env::new("dash", a.system.parent().unwrap()).set("POCKET_IDLE_PAUSE", "never");
    let p = std::process::id();
    let (live, paused) = (format!("dash-a{p}"), format!("dash-b{p}"));
    for n in [&live, &paused] {
        env.ok(&[
            "new",
            n,
            "--preset",
            "test",
            "--no-repo",
            "--detach",
            "--mem",
            "512M",
        ]);
    }
    env.ok(&["pause", &paused]);

    // Another user is attached at 100×30 and types a marker.
    let mut c = env.cmd("pocket");
    c.args(["attach", &live]);
    let mut other = Pty::spawn(c, 30, 100);
    other.wait_for("# ", 0, T);
    other.write(b"echo MARK-$((6*7))\r");
    other.wait_for("MARK-42", 0, T);
    let other_before = other.text_since(0).len();

    let mut c = env.cmd("pocket");
    c.current_dir(&env.root);
    let mut dash = Pty::spawn(c, 36, 120);
    let screen = dash.wait_screen(
        |s| s.contains("POCKETS") && s.contains(&live) && s.contains("MARK-42"),
        T,
    );
    eprintln!("dashboard:\n{screen}");
    assert!(screen.contains("‖ paused"), "{screen}");
    assert!(screen.contains("● running"), "{screen}");

    // The preview kept the session's size, typed nothing, and the paused pocket slept on.
    std::thread::sleep(Duration::from_secs(3));
    let sessions = env.json(&["sessions", &live]);
    let shell = sessions
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "shell")
        .unwrap();
    assert_eq!(
        (
            shell["size"]["rows"].as_u64(),
            shell["size"]["cols"].as_u64()
        ),
        (Some(30), Some(100)),
        "the preview resized the session: {shell}"
    );
    assert_eq!(
        other.text_since(0).len(),
        other_before,
        "the dashboard's preview wrote into the session"
    );
    assert_eq!(
        state(&env, &paused),
        "Paused",
        "polling woke the paused pocket"
    );

    // ⏎ on the selected pocket: the dashboard leaves the screen and the attach owns it.
    let m = dash.mark();
    dash.write(b"\r");
    let s = dash.wait_screen(|s| s.contains("MARK-42") && !s.contains("POCKETS"), T);
    eprintln!("attached from the dashboard:\n{s}");
    dash.write(b"echo FROM-DASH-$((1+1))\r");
    dash.wait_for("FROM-DASH-2", m, T);
    other.wait_for("FROM-DASH-2", 0, T);
    // Ctrl-] d returns to the dashboard.
    dash.write(b"\x1d");
    dash.write(b"d");
    dash.wait_screen(|s| s.contains("POCKETS") && s.contains(&paused), T);

    // p pauses the selected (running) pocket, p again resumes it.
    dash.write(b"p");
    wait_state(&env, &live, "Paused");
    // Both pockets show as paused once the dashboard has caught up.
    dash.wait_rows(
        |r| {
            r.iter()
                .filter(|l| l.contains("dash-") && l.contains("‖ paused"))
                .count()
                == 2
        },
        T,
    );
    dash.write(b"p");
    wait_state(&env, &live, "Running");

    // n opens the wizard: name, then preset; ⏎ creates.
    let made = format!("dash-c{p}");
    dash.write(b"n");
    dash.wait_screen(|s| s.contains("new pocket"), T);
    dash.write(made.as_bytes());
    dash.write(b"\x1b[B\x1b[B"); // ↓ ↓ to Preset (Repository is empty: scratch)
    dash.write(b"\x7f\x7f\x7f\x7ftest");
    dash.write(b"\x1b[B\x1b[B\x1b[C"); // Memory: 2G → 4G… then back
    dash.write(b"\x1b[D\x1b[D");
    dash.write(b"\r");
    wait_state(&env, &made, "Running");
    dash.wait_screen(|s| s.contains(&made), T);

    dash.write(b"q");
    let st = dash.wait_exit(T);
    assert!(st.success(), "{st:?}");
    assert!(is_cooked(&dash.termios()), "terminal left raw");
    let tail = dash.text_since(0);
    assert!(tail.contains("\x1b[?1049l"), "alternate screen not left");
}
