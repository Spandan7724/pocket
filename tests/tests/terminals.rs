//! Terminal compatibility matrix (ARCHITECTURE.md §9): for each common terminal's `TERM`,
//! a session started from that terminal knows it (terminfo present, copied from the host if
//! the image lacks it), and the features agents use pass through attach unchanged both ways.
//! (All 256 byte values passing through is `attach.rs`; this is the per-terminal view.)

use std::time::Duration;

use pocket_tests::cli::Env;
use pocket_tests::kvm_or_skip;
use pocket_tests::pty::Pty;

const T: Duration = Duration::from_secs(20);

const TERMS: &[&str] = &[
    "xterm-256color",
    "alacritty",
    "xterm-kitty",
    "wezterm",
    "foot",
    "xterm-ghostty",
    "vte-256color",
    "tmux-256color",
    "screen-256color",
];

/// Output features: truecolor, undercurl, OSC 8 link, OSC 52 clipboard write, OSC 2 title,
/// kitty keyboard push, SGR mouse + focus + bracketed paste on, synchronized update.
const OUT: &[u8] = b"\x1b[38;2;255;100;0mrgb\x1b[0m\x1b[4:3mcurl\x1b[0m\
\x1b]8;;https://example.com\x1b\\link\x1b]8;;\x1b\\\x1b]52;c;aGk=\x07\x1b]2;title\x07\
\x1b[>1u\x1b[?1006h\x1b[?1004h\x1b[?2004h\x1b[?2026h\x1b[?2026l\x1b[<u";

/// Input features: kitty CSI-u key, SGR mouse press, focus in, bracketed paste, Alt-x, F5.
const IN: &[u8] = b"\x1b[97;5u\x1b[<0;10;5M\x1b[I\x1b[200~pasted\x1b[201~\x1bx\x1b[15~";

#[test]
fn terminal_matrix() {
    let Some(a) = kvm_or_skip() else { return };
    let env = Env::new("terms", a.system.parent().unwrap());
    let p = format!("terms-{}", std::process::id());
    env.ok(&[
        "new",
        &p,
        "--preset",
        "base",
        "--no-repo",
        "--detach",
        "--mem",
        "1G",
    ]);
    // kitty and Ghostty ship their own terminfo entries and point TERMINFO at them; Ubuntu's
    // image has neither. pocket installs the client's entry (stand-ins compiled here).
    let ti = env.root.join("terminfo");
    std::fs::create_dir_all(&ti).unwrap();
    let src = env.root.join("own.src");
    std::fs::write(
        &src,
        "xterm-ghostty|ghostty (test entry),\n\tuse=xterm-256color,\nxterm-kitty|kitty (test entry),\n\tuse=xterm-256color,\n",
    )
    .unwrap();
    let st = std::process::Command::new("tic")
        .args(["-x", "-o"])
        .arg(&ti)
        .arg(&src)
        .status()
        .expect("tic (ncurses) is needed for the matrix test");
    assert!(st.success());
    let mut rows = vec![];
    for (i, term) in TERMS.iter().enumerate() {
        let s = format!("t{i}");
        let mut c = env.cmd("pocket");
        c.env("TERM", term)
            .env("TERMINFO", &ti)
            .args(["run-in", &p, "--name", &s, "--", "bash", "-l"]);
        let o = c.output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let mut c = env.cmd("pocket");
        c.env("TERM", term).args(["attach", &format!("{p}:{s}")]);
        let mut pty = Pty::spawn(c, 30, 100);
        // Markers built with $((…)) appear only in output, never in readline's echo.
        pty.wait_for("$ ", 0, T);
        pty.write(b"echo \"R$((40+2)) T=$TERM C=$(tput colors) I=$(infocmp \"$TERM\" >/dev/null 2>&1 && echo ok || echo missing) Z$((6*7))Z\"\r");
        let line = pty.wait_for("Z42Z", 0, T);
        let got = line
            .split("R42 ")
            .nth(1)
            .and_then(|r| r.split(" Z42Z").next())
            .unwrap_or("")
            .trim()
            .to_string();
        // Output direction, byte-exact.
        let m = pty.mark();
        let hex: String = OUT.iter().map(|b| format!("\\x{b:02x}")).collect();
        pty.write(format!("printf '{hex}'; echo OUT-$((1+1))-DONE\r").as_bytes());
        pty.wait_for("OUT-2-DONE", m, T);
        let out_ok = pty.wait_bytes(OUT, m, Duration::from_secs(1));
        // Input direction, byte-exact (the guest's `od` shows what arrived).
        let m = pty.mark();
        // Raw mode in the same command: bash restores its own settings between commands.
        pty.write(format!("stty raw -echo; head -c {} | od -An -tx1 | tr -d ' \\n'; stty sane; echo IN-$((2+1))-DONE\r", IN.len()).as_bytes());
        std::thread::sleep(Duration::from_millis(500));
        pty.write(IN);
        let text = pty.wait_for("IN-3-DONE", m, T);
        let want: String = IN.iter().map(|b| format!("{b:02x}")).collect();
        let in_ok = text.contains(&want);
        let terminfo = got.contains(&format!("T={term}")) && got.contains("I=ok");
        eprintln!("{term:<16} {got:<48} out:{out_ok} in:{in_ok}");
        rows.push((term.to_string(), terminfo, out_ok, in_ok, got));
        pty.write(b"\x1d");
        pty.write(b"d");
    }
    eprintln!(
        "\n| TERM | terminfo | colours | output features | input features |\n|---|---|---|---|---|"
    );
    for (t, ti, o, i, got) in &rows {
        let colors = got
            .split_whitespace()
            .find_map(|w| w.strip_prefix("C="))
            .unwrap_or("?");
        let mark = |b: bool| if b { "✓" } else { "✗" };
        eprintln!(
            "| {t} | {} | {colors} | {} | {} |",
            mark(*ti),
            mark(*o),
            mark(*i)
        );
    }
    for (t, ti, o, i, got) in rows {
        assert!(ti && o && i, "{t}: terminfo {ti} out {o} in {i} ({got})");
    }
}
