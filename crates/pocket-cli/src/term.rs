//! Raw mode for attach, with the terminal restored on every exit path: normal return,
//! panic, and fatal signals (handlers only use async-signal-safe calls).

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

static SAVED: Mutex<Option<libc::termios>> = Mutex::new(None);
/// Copy readable from signal handlers without locking.
static mut SAVED_RAW: libc::termios = unsafe { std::mem::zeroed() };
static HAVE_SAVED: AtomicBool = AtomicBool::new(false);
/// Set while the guest has switched the terminal to the alternate screen.
pub static GUEST_ALT: AtomicBool = AtomicBool::new(false);

/// Undo modes a guest TUI may have enabled: mouse reporting, bracketed paste, focus
/// events, kitty keyboard, application keypad/cursor, hidden cursor, attributes.
pub const RESET_MODES: &[u8] = b"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1015l\x1b[?2004l\x1b[?1004l\x1b[<u\x1b[?1l\x1b>\x1b[?25h\x1b[0m";
const LEAVE_ALT: &[u8] = b"\x1b[?1049l";

pub fn is_tty(fd: i32) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

pub fn size() -> (u16, u16) {
    for fd in [1, 0] {
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        // SAFETY: TIOCGWINSZ writes a local winsize.
        if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0
            && ws.ws_row > 0
            && ws.ws_col > 0
        {
            return (ws.ws_row, ws.ws_col);
        }
    }
    (24, 80)
}

fn write_all_raw(b: &[u8]) {
    let mut off = 0;
    while off < b.len() {
        // SAFETY: write(2) on stdout; async-signal-safe.
        let n = unsafe { libc::write(1, b[off..].as_ptr().cast(), b.len() - off) };
        if n <= 0 {
            return;
        }
        off += n as usize;
    }
}

/// Restores the saved termios and resets guest-enabled modes. Async-signal-safe.
pub fn restore() {
    if !HAVE_SAVED.swap(false, Ordering::SeqCst) {
        return;
    }
    if GUEST_ALT.swap(false, Ordering::SeqCst) {
        write_all_raw(LEAVE_ALT);
    }
    write_all_raw(RESET_MODES);
    // SAFETY: SAVED_RAW was written before HAVE_SAVED was set and is never written again
    // while it is set.
    unsafe {
        libc::tcsetattr(0, libc::TCSAFLUSH, std::ptr::addr_of!(SAVED_RAW));
    }
}

extern "C" fn on_fatal(sig: libc::c_int) {
    restore();
    // SAFETY: reset to default and re-raise so the exit status still says what happened.
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

pub struct RawGuard;

impl RawGuard {
    pub fn enter() -> std::io::Result<RawGuard> {
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: tcgetattr/tcsetattr on stdin with local termios structs.
        unsafe {
            if libc::tcgetattr(0, &mut t) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            SAVED_RAW = t;
        }
        *SAVED.lock().unwrap() = Some(t);
        HAVE_SAVED.store(true, Ordering::SeqCst);
        install_crash_handlers();
        let mut raw = t;
        unsafe {
            libc::cfmakeraw(&mut raw);
            if libc::tcsetattr(0, libc::TCSAFLUSH, &raw) != 0 {
                let e = std::io::Error::last_os_error();
                HAVE_SAVED.store(false, Ordering::SeqCst);
                return Err(e);
            }
        }
        Ok(RawGuard)
    }
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        restore();
    }
}

fn install_crash_handlers() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore();
            prev(info);
        }));
        for sig in [
            libc::SIGTERM,
            libc::SIGHUP,
            libc::SIGQUIT,
            libc::SIGSEGV,
            libc::SIGBUS,
            libc::SIGILL,
            libc::SIGFPE,
            libc::SIGABRT,
            libc::SIGPIPE,
        ] {
            // SAFETY: installing a handler that only calls async-signal-safe functions.
            unsafe {
                let mut sa: libc::sigaction = std::mem::zeroed();
                sa.sa_sigaction = on_fatal as *const () as usize;
                libc::sigemptyset(&mut sa.sa_mask);
                libc::sigaction(sig, &sa, std::ptr::null_mut());
            }
        }
    });
}

/// Tracks whether the guest's output left the terminal on the alternate screen.
#[derive(Default)]
pub struct AltTracker {
    tail: Vec<u8>,
}

impl AltTracker {
    pub fn feed(&mut self, data: &[u8]) {
        const ON: [&[u8]; 3] = [b"\x1b[?1049h", b"\x1b[?1047h", b"\x1b[?47h"];
        const OFF: [&[u8]; 3] = [b"\x1b[?1049l", b"\x1b[?1047l", b"\x1b[?47l"];
        let mut buf = std::mem::take(&mut self.tail);
        buf.extend_from_slice(data);
        let mut last: Option<(usize, bool)> = None;
        for (pats, on) in [(ON, true), (OFF, false)] {
            for p in pats {
                if let Some(i) = buf.windows(p.len()).rposition(|w| w == p)
                    && last.is_none_or(|(j, _)| i > j)
                {
                    last = Some((i, on));
                }
            }
        }
        if let Some((_, on)) = last {
            GUEST_ALT.store(on, Ordering::SeqCst);
        }
        let keep = buf.len().min(8);
        self.tail = buf[buf.len() - keep..].to_vec();
    }
}

pub fn mute_signal_default(sig: libc::c_int) {
    // SAFETY: plain signal(2).
    unsafe {
        libc::signal(sig, libc::SIG_IGN);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alt_screen_tracking_across_chunks() {
        let mut t = AltTracker::default();
        t.feed(b"hello\x1b[?10");
        t.feed(b"49h vim");
        assert!(GUEST_ALT.load(Ordering::SeqCst));
        t.feed(b"\x1b[?1049h...\x1b[?1049l$ ");
        assert!(!GUEST_ALT.load(Ordering::SeqCst));
    }
}
