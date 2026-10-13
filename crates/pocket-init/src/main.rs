//! M1 placeholder PID 1: powers the VM off so the boot pipeline can be tested end to end.

fn main() {
    // SAFETY: plain syscalls without pointers.
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_POWER_OFF);
    }
}
