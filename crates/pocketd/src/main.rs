//! pocketd: the per-user daemon (ARCHITECTURE.md §3.2). Started on demand by `pocket`.

mod agentcfg;
mod daemon;
mod doctor;
mod guard;
mod guest;
mod inject;
mod net;
mod paths;
mod presets;
mod provision;
mod review;
mod rpc;
mod secrets;
mod workspace;

use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::process::ExitCode;
use std::sync::Arc;

fn lock(paths: &paths::Paths) -> std::io::Result<std::fs::File> {
    let f = std::fs::File::create(paths.runtime.join("pocketd.lock"))?;
    // SAFETY: flock on an open descriptor.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "another pocketd is running for this user",
        ));
    }
    Ok(f)
}

/// `pocketd git-bridge <vsock-uds> <repo>`: the `ext::` transport for host fetches from a
/// guest. Speaks git-upload-pack only; anything else (a push) is refused.
fn git_bridge(args: &[String]) -> ExitCode {
    use pocket_proto::guest::{STREAM_PORT, StreamAck, StreamOpen};
    use std::io::{Read, Write};
    let (Some(uds), Some(repo)) = (args.first(), args.get(1)) else {
        eprintln!("usage: pocketd git-bridge VSOCK_UDS REPO");
        return ExitCode::from(2);
    };
    if std::env::var("GIT_EXT_SERVICE").as_deref() != Ok("git-upload-pack") {
        eprintln!("pocketd git-bridge: only git-upload-pack is allowed");
        return ExitCode::from(2);
    }
    let run = || -> std::io::Result<()> {
        let s = pocket_vmm::vsock::connect(std::path::Path::new(uds), STREAM_PORT)?;
        pocket_proto::frame::send(&mut &s, &StreamOpen::GitUploadPack { repo: repo.clone() })
            .map_err(std::io::Error::other)?;
        match pocket_proto::frame::recv::<_, StreamAck>(&mut &s).map_err(std::io::Error::other)? {
            Some(StreamAck(Ok(()))) => {}
            Some(StreamAck(Err(e))) => return Err(std::io::Error::other(e.to_string())),
            None => return Err(std::io::Error::other("pocket closed the stream")),
        }
        let mut up = s.try_clone()?;
        std::thread::spawn(move || {
            let mut stdin = std::io::stdin().lock();
            let mut buf = vec![0u8; 64 * 1024];
            while let Ok(n) = stdin.read(&mut buf) {
                if n == 0 || up.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            let _ = up.shutdown(std::net::Shutdown::Write);
        });
        let mut down = &s;
        let mut out = std::io::stdout().lock();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = down.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            out.flush()?;
        }
        Ok(())
    };
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pocketd git-bridge: {e}");
            ExitCode::from(128)
        }
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some("git-bridge") {
        return git_bridge(&argv[2..]);
    }
    let foreground = std::env::args().any(|a| a == "--foreground");
    if std::env::args().any(|a| a == "--version") {
        println!("pocketd {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let paths = paths::Paths::from_env();
    if let Err(e) = paths.ensure() {
        eprintln!("pocketd: cannot create its directories: {e}");
        return ExitCode::FAILURE;
    }
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths.state.join("pocketd.log"));
    let filter = tracing_subscriber::EnvFilter::try_from_env("POCKET_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    match (foreground, log) {
        (false, Ok(f)) => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(f))
            .init(),
        _ => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .init(),
    }
    let _lock = match lock(&paths) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("pocketd: {e}");
            return ExitCode::from(3);
        }
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(run(paths))
}

async fn run(paths: paths::Paths) -> ExitCode {
    let store = match pocket_store::Store::open(&paths.db()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("{e}");
            eprintln!("pocketd: {e}");
            return ExitCode::FAILURE;
        }
    };
    let backend = match pocket_vmm::default_backend(paths.vmm()) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("{e}");
            eprintln!("pocketd: {e} (run `pocket doctor`)");
            return ExitCode::FAILURE;
        }
    };
    let sock = paths.socket();
    let _ = std::fs::remove_file(&sock);
    let listener = match tokio::net::UnixListener::bind(&sock) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("pocketd: listen on {}: {e}", sock.display());
            return ExitCode::FAILURE;
        }
    };
    let _ = std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600));
    let d = daemon::Daemon::new(paths, store, backend);
    tracing::info!(
        "pocketd {} listening on {} ({} {})",
        env!("CARGO_PKG_VERSION"),
        sock.display(),
        d.backend.name(),
        d.backend.version()
    );
    d.readopt().await;
    let stop = Arc::new(tokio::sync::Notify::new());
    let server = tokio::spawn(rpc::serve(d.clone(), listener, stop.clone()));
    let mut term =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal");
    tokio::select! {
        _ = stop.notified() => {}
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    // VMs keep running in their own scopes; the next pocketd re-adopts them.
    tracing::info!("pocketd stopping; VMs keep running");
    server.abort();
    d.detach_all();
    let _ = std::fs::remove_file(&sock);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    ExitCode::SUCCESS
}
