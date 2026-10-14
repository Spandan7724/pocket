//! Runs a command on a fresh host pseudo-terminal, like a user's terminal emulator:
//! everything it writes is recorded raw and fed to a VT model of the screen.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct Pty {
    master: File,
    slave: File,
    pub child: Child,
    pub raw: Arc<Mutex<Vec<u8>>>,
    pub screen: Arc<Mutex<vt100::Parser>>,
}

fn openpty(rows: u16, cols: u16) -> (File, File) {
    let (mut m, mut s) = (0, 0);
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: openpty fills two fds we take ownership of.
    unsafe {
        assert_eq!(
            libc::openpty(&mut m, &mut s, std::ptr::null_mut(), std::ptr::null(), &ws),
            0
        );
        libc::fcntl(m, libc::F_SETFD, libc::FD_CLOEXEC);
        libc::fcntl(s, libc::F_SETFD, libc::FD_CLOEXEC);
        (File::from_raw_fd(m), File::from_raw_fd(s))
    }
}

pub fn termios(f: &File) -> libc::termios {
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::tcgetattr(f.as_raw_fd(), &mut t) }, 0);
    t
}

/// The bits raw mode clears; all set on a fresh (cooked) pty.
pub fn is_cooked(t: &libc::termios) -> bool {
    t.c_lflag & (libc::ICANON | libc::ECHO | libc::ISIG) == (libc::ICANON | libc::ECHO | libc::ISIG)
        && t.c_oflag & libc::OPOST != 0
}

impl Pty {
    pub fn spawn(mut cmd: Command, rows: u16, cols: u16) -> Pty {
        let (master, slave) = openpty(rows, cols);
        let sfd = slave.as_raw_fd();
        cmd.stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave.try_clone().unwrap()))
            .env("TERM", "xterm-256color");
        // SAFETY: setsid + TIOCSCTTY are async-signal-safe.
        unsafe {
            cmd.pre_exec(move || {
                libc::setsid();
                libc::ioctl(0, libc::TIOCSCTTY, 0);
                let _ = sfd;
                Ok(())
            });
        }
        let child = cmd.spawn().unwrap();
        let raw = Arc::new(Mutex::new(Vec::new()));
        let screen = Arc::new(Mutex::new(vt100::Parser::new(rows, cols, 0)));
        let mut rd = master.try_clone().unwrap();
        let (raw2, screen2) = (raw.clone(), screen.clone());
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            while let Ok(n) = rd.read(&mut buf) {
                if n == 0 {
                    break;
                }
                raw2.lock().unwrap().extend_from_slice(&buf[..n]);
                screen2.lock().unwrap().process(&buf[..n]);
            }
        });
        Pty {
            master,
            slave,
            child,
            raw,
            screen,
        }
    }

    pub fn write(&mut self, b: &[u8]) {
        self.master.write_all(b).unwrap();
    }

    pub fn mark(&self) -> usize {
        self.raw.lock().unwrap().len()
    }

    pub fn text_since(&self, mark: usize) -> String {
        String::from_utf8_lossy(&self.raw.lock().unwrap()[mark..]).into_owned()
    }

    pub fn wait_for(&self, needle: &str, mark: usize, timeout: Duration) -> String {
        let deadline = Instant::now() + timeout;
        loop {
            let t = self.text_since(mark);
            if t.contains(needle) {
                return t;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {needle:?}; output:\n{t}\nscreen:\n{}",
                self.contents()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    pub fn wait_bytes(&self, needle: &[u8], mark: usize, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let raw = self.raw.lock().unwrap();
            if raw[mark..].windows(needle.len()).any(|w| w == needle) {
                return true;
            }
            drop(raw);
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }

    /// Screen rows as text.
    pub fn rows(&self) -> Vec<String> {
        let p = self.screen.lock().unwrap();
        let (_, cols) = p.screen().size();
        p.screen().rows(0, cols).collect()
    }

    pub fn contents(&self) -> String {
        self.screen.lock().unwrap().screen().contents()
    }

    pub fn wait_rows(&self, pred: impl Fn(&[String]) -> bool, timeout: Duration) -> Vec<String> {
        let deadline = Instant::now() + timeout;
        loop {
            let r = self.rows();
            if pred(&r) {
                return r;
            }
            assert!(
                Instant::now() < deadline,
                "screen never matched:\n{}",
                r.join("\n")
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn wait_screen(&self, pred: impl Fn(&str) -> bool, timeout: Duration) -> String {
        let deadline = Instant::now() + timeout;
        loop {
            let c = self.contents();
            if pred(&c) {
                return c;
            }
            assert!(Instant::now() < deadline, "screen never matched:\n{c}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn resize(&mut self, rows: u16, cols: u16) {
        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: TIOCSWINSZ on our master; the kernel signals the foreground group.
        unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
        self.screen
            .lock()
            .unwrap()
            .screen_mut()
            .set_size(rows, cols);
    }

    pub fn termios(&self) -> libc::termios {
        termios(&self.slave)
    }

    pub fn wait_exit(&mut self, timeout: Duration) -> ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(st) = self.child.try_wait().unwrap() {
                return st;
            }
            assert!(
                Instant::now() < deadline,
                "process did not exit; output:\n{}",
                self.text_since(0)
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
