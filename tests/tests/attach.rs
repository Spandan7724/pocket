//! The interactive loop through the real CLI on a host pseudo-terminal:
//! new → attach → type → detach → reattach → rm, plus byte-exact passthrough, resize,
//! the Ctrl-] menu, terminal restore on exit and crash, and keystroke round-trip time.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use pocket_tests::cli::Env;
use pocket_tests::kvm_or_skip;
use pocket_tests::pty::{Pty, is_cooked};

const T: Duration = Duration::from_secs(20);

fn setup(tag: &str) -> Option<(Env, String)> {
    let a = kvm_or_skip()?;
    let env = Env::new(tag, a.system.parent().unwrap());
    Some((env, format!("{tag}-{}", std::process::id())))
}

fn attach_pty(env: &Env, name: &str, rows: u16, cols: u16) -> Pty {
    let mut c = env.cmd("pocket");
    c.args(["attach", name]);
    Pty::spawn(c, rows, cols)
}

fn exec_stdin(env: &Env, name: &str, script: &str, data: &[u8]) -> Vec<u8> {
    let mut child = env
        .cmd("pocket")
        .args(["exec", "--root", name, "--", "sh", "-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(data).unwrap();
    let o = child.wait_with_output().unwrap();
    assert!(o.status.success());
    o.stdout
}

#[test]
fn new_attach_type_detach_reattach_rm() {
    let Some((env, name)) = setup("loop") else {
        return;
    };
    // `pocket new` attaches to the default shell.
    let mut c = env.cmd("pocket");
    c.args(["new", &name, "--preset", "test", "--no-repo"]);
    let mut p = Pty::spawn(c, 24, 80);
    p.wait_for("# ", 0, T);
    let m = p.mark();
    p.write(b"echo hello-$((40+2))\r");
    p.wait_for("hello-42", m, T);

    // Resize propagates to the guest pty.
    p.resize(30, 100);
    std::thread::sleep(Duration::from_millis(100));
    let m = p.mark();
    p.write(b"stty size\r");
    p.wait_for("30 100", m, T);

    // Output passthrough is byte-exact: all 256 byte values, in order, unmodified.
    let all: Vec<u8> = (0..=255u8).collect();
    exec_stdin(&env, &name, "cat > /tmp/all.bin", &all);
    let m = p.mark();
    p.write(b"stty raw -echo; cat /tmp/all.bin; stty sane\r");
    assert!(
        p.wait_bytes(&all, m, T),
        "output bytes altered:\n{:?}",
        &p.raw.lock().unwrap()[m..]
    );

    // Input passthrough is byte-exact; Ctrl-] Ctrl-] sends one literal Ctrl-].
    let m = p.mark();
    p.write(b"stty raw -echo; head -c 256 > /tmp/in.bin; stty sane; echo got-input\r");
    std::thread::sleep(Duration::from_millis(300));
    let mut typed = vec![];
    for b in 0..=255u8 {
        typed.push(b);
        if b == 0x1d {
            typed.push(0x1d);
        }
    }
    for chunk in typed.chunks(37) {
        p.write(chunk);
        std::thread::sleep(Duration::from_millis(5));
    }
    p.wait_for("got-input", m, T);
    let got = exec_stdin(&env, &name, "cat /tmp/in.bin", b"");
    assert_eq!(got, all, "input bytes altered");

    // Detach: the session keeps running, the terminal is restored.
    let m = p.mark();
    p.write(b"sleep 1000 &\rexport MARK=still-here\r");
    p.wait_for("# ", m, T);
    p.write(&[0x1d, b'd']);
    let st = p.wait_exit(T);
    assert!(st.success(), "{st:?}");
    assert!(
        p.text_since(0).contains("[detached from"),
        "{}",
        p.text_since(0)
    );
    assert!(
        is_cooked(&p.termios()),
        "terminal left in raw mode after detach"
    );
    let sessions = env.ok(&["sessions", &name]);
    assert!(
        sessions.contains("shell") && sessions.contains("running"),
        "{sessions}"
    );

    // Reattach on a different terminal size: history is replayed, state is intact.
    let mut q = attach_pty(&env, &name, 40, 120);
    q.wait_screen(|s| s.contains("hello-42"), T);
    let m = q.mark();
    q.write(b"echo $MARK; stty size\r");
    q.wait_for("still-here", m, T);
    q.wait_for("40 120", m, T);

    // Help overlay draws on the alternate screen and leaves the shell screen untouched.
    let before = q.contents();
    q.write(&[0x1d, b'?']);
    q.wait_screen(|s| s.contains("Ctrl-] d") && s.contains("press any key"), T);
    q.write(b"x");
    q.wait_screen(|s| !s.contains("press any key"), T);
    assert_eq!(q.contents(), before, "overlay corrupted the session screen");

    // Ctrl-] n opens a second shell session; Ctrl-] s switches back to the first.
    q.write(&[0x1d, b'n']);
    std::thread::sleep(Duration::from_millis(500));
    let m = q.mark();
    q.write(b"echo in-$((1+1))nd\r");
    q.wait_for("in-2nd", m, T);
    let list = env.ok(&["sessions", &name]);
    assert!(list.contains("shell-2"), "{list}");
    q.write(&[0x1d, b's']);
    q.wait_screen(
        |s| s.contains("1  shell") && s.contains("2  shell-2") && s.contains("attached"),
        T,
    );
    q.write(b"1");
    std::thread::sleep(Duration::from_millis(500));
    let m = q.mark();
    q.write(b"echo back-in-$MARK\r");
    q.wait_for("back-in-still-here", m, T);

    q.write(&[0x1d, b'd']);
    assert!(q.wait_exit(T).success());
    assert!(is_cooked(&q.termios()));

    env.ok(&["rm", "-f", &name]);
    assert!(env.json(&["ls"]).as_array().unwrap().is_empty());
}

#[test]
fn terminal_restored_on_crash_and_on_signals() {
    let Some((env, name)) = setup("crash") else {
        return;
    };
    env.ok(&["new", &name, "--preset", "test", "--no-repo", "--detach"]);

    let mut c = env.cmd("pocket");
    c.args(["attach", &name])
        .env("POCKET_TEST_PANIC_AFTER_MS", "1500");
    let mut p = Pty::spawn(c, 24, 80);
    p.wait_for("# ", 0, T);
    p.write(b"printf '\\033[?1049h\\033[?1000h\\033[?2004h\\033[?25l'\r");
    let st = p.wait_exit(T);
    assert_eq!(st.code(), Some(101), "expected a panic exit, got {st:?}");
    assert!(is_cooked(&p.termios()), "terminal left raw after a panic");
    let out = p.text_since(0);
    assert!(
        out.contains("\x1b[?1049l") && out.contains("\x1b[?1000l") && out.contains("\x1b[?25h")
    );
    assert!(out.contains("simulated crash"));

    for sig in [libc::SIGTERM, libc::SIGHUP] {
        let mut p = attach_pty(&env, &name, 24, 80);
        p.wait_for("# ", 0, T);
        assert!(
            !is_cooked(&p.termios()),
            "attach should put the terminal in raw mode"
        );
        unsafe { libc::kill(p.child.id() as i32, sig) };
        let st = p.wait_exit(T);
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(st.signal(), Some(sig), "{st:?}");
        assert!(
            is_cooked(&p.termios()),
            "terminal left raw after signal {sig}"
        );
    }
    // The session survived all of it.
    assert!(env.ok(&["sessions", &name]).contains("running"));
}

/// Median and p95 round trip of one byte through `pty` running `stty raw -echo; cat`.
fn rtt(master: &mut std::fs::File, n: usize) -> (f64, f64) {
    let mut v = Vec::with_capacity(n);
    let mut b = [0u8; 1];
    for i in 0..n {
        let c = b'a' + (i % 26) as u8;
        let t = Instant::now();
        master.write_all(&[c]).unwrap();
        loop {
            master.read_exact(&mut b).unwrap();
            if b[0] == c {
                break;
            }
        }
        v.push(t.elapsed().as_secs_f64() * 1e6);
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (v[n / 2], v[n * 95 / 100])
}

fn spawn_on_pty(mut cmd: Command) -> (std::fs::File, std::process::Child) {
    let (mut m, mut s) = (0, 0);
    let ws = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        libc::openpty(&mut m, &mut s, std::ptr::null_mut(), std::ptr::null(), &ws);
    }
    use std::os::fd::FromRawFd;
    use std::os::unix::process::CommandExt;
    let slave = unsafe { std::fs::File::from_raw_fd(s) };
    cmd.stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave));
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            libc::ioctl(0, libc::TIOCSCTTY, 0);
            Ok(())
        });
    }
    let child = cmd.spawn().unwrap();
    (unsafe { std::fs::File::from_raw_fd(m) }, child)
}

fn drain_until(master: &mut std::fs::File, needle: &[u8]) {
    let mut seen = vec![];
    let mut b = [0u8; 4096];
    let deadline = Instant::now() + T;
    while !seen.windows(needle.len()).any(|w| w == needle) {
        assert!(
            Instant::now() < deadline,
            "never saw {needle:?}: {}",
            String::from_utf8_lossy(&seen)
        );
        let n = master.read(&mut b).unwrap();
        seen.extend_from_slice(&b[..n]);
    }
}

#[test]
fn keystroke_round_trip_time() {
    let Some((env, name)) = setup("rtt") else {
        return;
    };
    env.ok(&["new", &name, "--preset", "test", "--no-repo", "--detach"]);
    const N: usize = 2000;

    let mut local = Command::new("sh");
    local.args(["-c", "stty raw -echo; echo READY; exec cat"]);
    let (mut lm, mut lc) = spawn_on_pty(local);
    drain_until(&mut lm, b"READY");
    let (l50, l95) = rtt(&mut lm, N);
    let _ = lc.kill();
    let _ = lc.wait();

    let mut c = env.cmd("pocket");
    c.args(["attach", &name]);
    let (mut pm, mut pc) = spawn_on_pty(c);
    drain_until(&mut pm, b"# ");
    std::thread::sleep(Duration::from_millis(400));
    pm.write_all(b"stty raw -echo; echo REA''DY; exec cat\r")
        .unwrap();
    drain_until(&mut pm, b"READY");
    let (p50, p95) = rtt(&mut pm, N);
    let _ = pc.kill();
    let _ = pc.wait();
    let _ = pm.as_raw_fd();

    eprintln!(
        "keystroke RTT (n={N}): local pty p50 {l50:.1} µs / p95 {l95:.1} µs; \
         pocket attach p50 {p50:.1} µs / p95 {p95:.1} µs; added p50 {:.1} µs / p95 {:.1} µs",
        p50 - l50,
        p95 - l95
    );
    assert!(p50 - l50 < 1000.0, "added p50 RTT over 1 ms");
    assert!(p95 - l95 < 3000.0, "added p95 RTT over 3 ms");
}
