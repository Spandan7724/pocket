use std::time::Duration;

use pocket_proto::guest::{ErrorKind, ExitStatus, GuestEvent, HostReq, PtySize, Reply};
use pocket_tests::guest::{Attach, Control, argv, new_token};
use pocket_tests::{TestVm, VmOpts, kvm_or_skip};

const T: Duration = Duration::from_secs(10);
const SIZE: PtySize = PtySize {
    rows: 30,
    cols: 100,
};

fn create(
    ctl: &mut Control,
    name: &str,
    cmd: &[&str],
) -> Result<Reply, pocket_proto::guest::GuestError> {
    ctl.request(HostReq::SessionCreate {
        name: name.into(),
        argv: argv(cmd),
        env: vec![("PS1".into(), "$ ".into())],
        cwd: "/work".into(),
        size: SIZE,
        user: None,
    })
}

fn list(ctl: &mut Control) -> Vec<pocket_proto::guest::SessionInfo> {
    match ctl.request(HostReq::SessionList) {
        Ok(Reply::Sessions(s)) => s,
        other => panic!("{other:?}"),
    }
}

#[test]
fn sessions_survive_disconnect_and_replay_scrollback() {
    let Some(a) = kvm_or_skip() else { return };
    let vm = TestVm::boot(&a, "session", VmOpts::default());
    let u = &vm.vsock_uds;
    let mut ctl = Control::connect(u, T);

    assert!(
        matches!(create(&mut ctl, "shell", &["/bin/sh"]), Ok(Reply::SessionCreated { pid }) if pid > 1)
    );
    let err = create(&mut ctl, "shell", &["/bin/sh"]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::AlreadyExists);

    // Every attach needs a fresh daemon-issued token; tokens are single use.
    let err = Attach::open_with_token(u, "shell", SIZE, true, new_token())
        .err()
        .unwrap();
    assert_eq!(err.kind, ErrorKind::InvalidRequest);
    let token = new_token();
    ctl.request(HostReq::AuthorizeAttach {
        session: "shell".into(),
        token: token.clone(),
    })
    .unwrap();
    let mut at = Attach::open_with_token(u, "shell", SIZE, true, token.clone()).unwrap();
    let reuse = Attach::open_with_token(u, "shell", SIZE, true, token)
        .err()
        .unwrap();
    assert_eq!(reuse.kind, ErrorKind::InvalidRequest);
    at.type_str("echo marker-$((40+2)); stty size\n");
    at.wait_for("marker-42", 0, T);
    at.wait_for("30 100", 0, T);
    let s = list(&mut ctl);
    assert_eq!(
        (s.len(), s[0].name.as_str(), s[0].attached, s[0].exited),
        (1, "shell", 1, None)
    );

    // Resize while attached.
    at.resize(PtySize {
        rows: 40,
        cols: 120,
    });
    let mark = at.seen.len();
    at.type_str("stty size\n");
    at.wait_for("40 120", mark, T);

    // Detach, drop the control connection too (as if pocketd restarted), and come back.
    drop(at);
    drop(ctl);
    let mut ctl = Control::connect(u, T);
    let s = list(&mut ctl);
    assert_eq!((s.len(), s[0].attached, s[0].exited), (1, 0, None), "{s:?}");

    let mut at = Attach::open(
        &mut ctl,
        u,
        "shell",
        PtySize {
            rows: 40,
            cols: 120,
        },
        true,
    )
    .unwrap();
    let replay = at.wait_for("marker-42", 0, T);
    assert!(
        replay.contains("40 120"),
        "scrollback replay incomplete:\n{replay}"
    );
    let mark = at.seen.len();
    at.type_str("echo still-$((6*7))\n");
    at.wait_for("still-42", mark, T);

    // A second client sees the same live output; attaching without replay skips history.
    let mut other = Attach::open(
        &mut ctl,
        u,
        "shell",
        PtySize {
            rows: 40,
            cols: 120,
        },
        false,
    )
    .unwrap();
    at.type_str("echo shared-output\n");
    other.wait_for("shared-output", 0, T);
    assert!(!String::from_utf8_lossy(&other.seen).contains("marker-42"));
    assert_eq!(list(&mut ctl)[0].attached, 2);

    // Exit from inside: both clients get Exited, the host gets SessionExited.
    at.type_str("exit 5\n");
    let ev = ctl.wait_event(T, |e| matches!(e, GuestEvent::SessionExited { .. }));
    assert_eq!(
        ev,
        GuestEvent::SessionExited {
            name: "shell".into(),
            status: ExitStatus::Code(5)
        }
    );
    let s = list(&mut ctl);
    assert_eq!((s[0].exited, s[0].attached), (Some(ExitStatus::Code(5)), 0));

    // Attaching to an exited session replays and reports the status.
    let mut late = Attach::open(&mut ctl, u, "shell", SIZE, true).unwrap();
    late.wait_for("shared-output", 0, T);

    assert_eq!(
        ctl.request(HostReq::SessionKill {
            name: "shell".into(),
            signal: 0
        }),
        Ok(Reply::Done)
    );
    assert!(list(&mut ctl).is_empty());
    let err = Attach::open(&mut ctl, u, "shell", SIZE, false)
        .err()
        .unwrap();
    assert_eq!(err.kind, ErrorKind::NotFound);
}

#[test]
fn kill_signals_the_whole_session() {
    let Some(a) = kvm_or_skip() else { return };
    let vm = TestVm::boot(&a, "kill", VmOpts::default());
    let u = &vm.vsock_uds;
    let mut ctl = Control::connect(u, T);
    create(
        &mut ctl,
        "busy",
        &["/bin/sh", "-c", "sleep 1000 & sleep 1000; echo unreachable"],
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let err = ctl
        .request(HostReq::SessionKill {
            name: "busy".into(),
            signal: 0,
        })
        .unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::InvalidRequest,
        "running sessions cannot be forgotten"
    );

    assert_eq!(
        ctl.request(HostReq::SessionKill {
            name: "busy".into(),
            signal: libc::SIGTERM
        }),
        Ok(Reply::Done)
    );
    let ev = ctl.wait_event(T, |e| matches!(e, GuestEvent::SessionExited { .. }));
    assert_eq!(
        ev,
        GuestEvent::SessionExited {
            name: "busy".into(),
            status: ExitStatus::Signal(libc::SIGTERM)
        }
    );
    // The background `sleep` was in the same process group and is gone too.
    let r = pocket_tests::guest::exec(&mut ctl, u, &["/bin/sh", "-c", "pgrep sleep || echo none"]);
    assert_eq!(r.out().trim(), "none");
    let err = ctl
        .request(HostReq::SessionKill {
            name: "nope".into(),
            signal: 15,
        })
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::NotFound);
}
