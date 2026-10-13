use std::time::Duration;

use pocket_proto::guest::{ErrorKind, ExecIn, ExecOut, ExitStatus, PtySize, StreamOpen};
use pocket_tests::guest::{Control, Exec, exec, open_stream};
use pocket_tests::{TestVm, VmOpts, kvm_or_skip};

fn vm(tag: &str) -> Option<(TestVm, Control)> {
    let a = kvm_or_skip()?;
    let vm = TestVm::boot(&a, tag, VmOpts::default());
    let ctl = Control::connect(&vm.vsock_uds, Duration::from_secs(10));
    Some((vm, ctl))
}

#[test]
fn argv_env_cwd_exit_code_and_both_streams() {
    let Some((vm, mut ctl)) = vm("exec") else {
        return;
    };
    let script =
        r#"echo "args:$#:$1:$2"; echo "env:$GREETING"; echo "cwd:$(pwd)"; echo oops >&2; exit 7"#;
    let e = Exec::start(
        &mut ctl,
        &vm.vsock_uds,
        &["/bin/sh", "-c", script, "sh", "a b", "c"],
        &[("GREETING", "hello world")],
        "/etc",
    )
    .unwrap();
    assert!(e.pid > 1);
    let r = e.finish();
    assert_eq!(r.out(), "args:2:a b:c\nenv:hello world\ncwd:/etc\n");
    assert_eq!(r.stderr, b"oops\n");
    assert_eq!(r.status, ExitStatus::Code(7));
}

#[test]
fn output_streams_before_exit() {
    let Some((vm, mut ctl)) = vm("stream") else {
        return;
    };
    let script = "for i in 1 2 3 4; do echo tick $i; sleep 0.3; done";
    let r = Exec::start(
        &mut ctl,
        &vm.vsock_uds,
        &["/bin/sh", "-c", script],
        &[],
        "/",
    )
    .unwrap()
    .finish();
    assert_eq!(r.out(), "tick 1\ntick 2\ntick 3\ntick 4\n");
    assert!(r.stdout_times.len() >= 4, "chunks: {:?}", r.stdout_times);
    let first = r.stdout_times[0];
    let last = *r.stdout_times.last().unwrap();
    eprintln!("first chunk after {first:?}, last after {last:?}");
    assert!(
        last - first >= Duration::from_millis(800),
        "output was not streamed: {:?}",
        r.stdout_times
    );
}

#[test]
fn stdin_signals_and_large_output() {
    let Some((vm, mut ctl)) = vm("stdin") else {
        return;
    };
    let u = &vm.vsock_uds;

    let mut e = Exec::start(&mut ctl, u, &["/bin/cat"], &[], "/").unwrap();
    e.send(ExecIn::Stdin(b"through stdin\n".to_vec()));
    e.send(ExecIn::CloseStdin);
    let r = e.finish();
    assert_eq!(
        (r.out().as_str(), r.status),
        ("through stdin\n", ExitStatus::Code(0))
    );

    let script = r#"trap 'echo got TERM; exit 3' TERM; echo ready; while :; do sleep 0.05; done"#;
    let mut e = Exec::start(&mut ctl, u, &["/bin/sh", "-c", script], &[], "/").unwrap();
    assert_eq!(e.next_out(), Some(ExecOut::Stdout(b"ready\n".to_vec())));
    e.send(ExecIn::Signal(libc::SIGTERM));
    let r = e.finish();
    assert_eq!(r.out(), "got TERM\n");
    assert_eq!(r.status, ExitStatus::Code(3));

    let mut e = Exec::start(&mut ctl, u, &["/bin/sleep", "100"], &[], "/").unwrap();
    e.send(ExecIn::Signal(libc::SIGKILL));
    let r = e.finish();
    assert_eq!(r.status, ExitStatus::Signal(libc::SIGKILL));
    assert_eq!(r.status.code(), 137);

    // 8 MiB through 64 KiB-limited frames, then a clean exit.
    let r = exec(&mut ctl, u, &["/bin/sh", "-c", "head -c 8388608 /dev/zero"]);
    assert_eq!((r.stdout.len(), r.status), (8 << 20, ExitStatus::Code(0)));
}

#[test]
fn pty_exec_and_errors() {
    let Some((vm, mut ctl)) = vm("ptyexec") else {
        return;
    };
    let u = &vm.vsock_uds;
    let r = Exec::start_with(
        &mut ctl,
        u,
        &["/bin/sh", "-c", "tty; stty size; echo TERM=$TERM"],
        &[],
        "/",
        Some(PtySize {
            rows: 33,
            cols: 101,
        }),
    )
    .unwrap()
    .finish();
    assert!(r.stderr.is_empty(), "pty exec has no separate stderr");
    let (out, status) = (r.stdout, r.status);
    let out = String::from_utf8_lossy(&out);
    assert!(out.contains("/dev/pts/"), "{out}");
    assert!(out.contains("33 101"), "{out}");
    assert!(out.contains("TERM=xterm-256color"), "{out}");
    assert_eq!(status, ExitStatus::Code(0));

    let err = Exec::start(&mut ctl, u, &["/no/such/binary"], &[], "/")
        .err()
        .unwrap();
    assert_eq!(err.kind, ErrorKind::NotFound, "{err}");
    let err = Exec::start(&mut ctl, u, &["/bin/true"], &[], "/no/such/dir")
        .err()
        .unwrap();
    assert_eq!(err.kind, ErrorKind::NotFound, "{err}");
    let err = open_stream(u, StreamOpen::ExecIo { exec_id: 999_999 })
        .err()
        .unwrap();
    assert_eq!(err.kind, ErrorKind::NotFound);
    let err = open_stream(u, StreamOpen::PortForward { port: 80 })
        .err()
        .unwrap();
    assert_eq!(err.kind, ErrorKind::Unsupported);
}
