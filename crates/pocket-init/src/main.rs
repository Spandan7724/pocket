//! pocket-init: PID 1 of every pocket (ARCHITECTURE.md §3.5). Boots the guest, then serves
//! the host protocol (CONTRACTS.md §3) over vsock.

mod boot;
mod control;
mod exec;
mod netshim;
mod process;
mod reaper;
mod session;
mod shutdown;
mod sys;
mod users;

use std::sync::Arc;

use pocket_proto::guest::{CONTROL_PORT, STREAM_PORT};

fn fatal(msg: &str) -> ! {
    sys::log_at(2, &format!("fatal: {msg}; powering off"));
    sys::poweroff()
}

fn signal_loop() {
    loop {
        match sys::wait_signal() {
            libc::SIGCHLD => {
                reaper::reap_all();
            }
            sig => {
                log!("signal {sig}: shutting down");
                if let Err(e) = shutdown::shutdown(2000) {
                    log!("shutdown: {e}");
                }
                sys::poweroff();
            }
        }
    }
}

fn main() {
    let t_start = sys::boottime_ns();
    if sys::getpid() != 1 {
        eprintln!("pocket-init runs only as PID 1 inside a pocket");
        std::process::exit(2);
    }
    // Returning from PID 1 panics the kernel; turn every failure into a power-off.
    std::panic::set_hook(Box::new(|info| fatal(&info.to_string())));
    sys::block_handled_signals();

    let mut phases = boot::Phases::default();
    if let Err(e) = boot::boot(&mut phases) {
        fatal(&format!("boot: {e}"));
    }
    std::thread::spawn(signal_loop);
    reaper::reap_all();

    let control = sys::vsock_listen(CONTROL_PORT)
        .unwrap_or_else(|e| fatal(&format!("listen {CONTROL_PORT}: {e}")));
    let streams = sys::vsock_listen(STREAM_PORT)
        .unwrap_or_else(|e| fatal(&format!("listen {STREAM_PORT}: {e}")));
    let t_ready = sys::boottime_ns();
    let ready = Arc::new(control::ReadyInfo {
        boot_ns: t_ready,
        init_ns: t_ready - t_start,
    });
    log!(
        "ready: {:.2} ms after kernel start, {:.2} ms in pocket-init ({})",
        t_ready as f64 / 1e6,
        ready.init_ns as f64 / 1e6,
        phases.summary(t_start)
    );

    std::thread::spawn(move || {
        loop {
            match sys::accept(&streams) {
                Ok(c) => {
                    std::thread::spawn(move || control::serve_stream(c));
                }
                Err(e) => log!("accept {STREAM_PORT}: {e}"),
            }
        }
    });
    loop {
        match sys::accept(&control) {
            Ok(c) => {
                let ready = ready.clone();
                std::thread::spawn(move || control::serve_control(c, &ready));
            }
            Err(e) => log!("accept {CONTROL_PORT}: {e}"),
        }
    }
}
