//! `pocket bench`: the daemon measures VM start paths; this adds `pocket new` → attached
//! and keystroke round trips, prints them against the targets and gates regressions.

use std::path::Path;
use std::time::{Duration, Instant};

use pocket_proto::frame::{recv, send};
use pocket_proto::guest::{AttachIn, AttachOut, PtySize, StreamOpen};
use pocket_proto::rpc::{NewPocket, Request, Response};
use serde_json::{Value, json};

use crate::client::Client;
use crate::error::{CliError, Result};

/// PERFORMANCE.md §1 targets (p50, p95) per metric.
pub const TARGETS: &[(&str, &str, f64, f64)] = &[
    ("cold_boot_ms", "Cold boot → ready (ms)", 200.0, 350.0),
    ("restore_ms", "Template restore → ready (ms)", 40.0, 80.0),
    ("pool_claim_ms", "Pool claim → ready (ms)", 5.0, 15.0),
    (
        "new_e2e_ms",
        "`pocket new` warm, attached (ms)",
        150.0,
        300.0,
    ),
    (
        "hibernate_resume_ms",
        "Hibernated → resumed (ms)",
        80.0,
        200.0,
    ),
    (
        "attach_rtt_added_us",
        "Keystroke RTT added (µs)",
        1000.0,
        3000.0,
    ),
];

/// Below these absolute differences a "regression" is noise.
fn noise_floor(metric: &str) -> f64 {
    if metric.ends_with("_us") { 30.0 } else { 2.0 }
}

fn new_req(name: &str, preset: &str, memory_mib: Option<u32>) -> NewPocket {
    NewPocket {
        name: Some(name.into()),
        preset: Some(preset.into()),
        repo: None,
        carry_changes: false,
        cpus: None,
        memory_mib,
        disk_mib: None,
        net_profile: None,
        allow: vec![],
        deny: vec![],
        command: None,
        term: Some("xterm-256color".into()),
        secrets: Some(vec![]),
        copy_secrets: vec![],
        sync_config: false,
        ssh_agent: false,
        auto_forward: true,
        forward: vec![],
        env: vec![],
        git_protected: vec![],
        git_allow_push: vec![],
        setup: None,
        share: vec![],
        idle_pause_ms: Some(0),
        idle_hibernate_ms: Some(0),
        net_mode: None,
        template: None,
    }
}

fn attach(c: &mut Client, pocket: &str) -> Result<std::os::unix::net::UnixStream> {
    let Response::Attach {
        session,
        vsock_uds,
        token,
    } = c.request(Request::AttachAuthorize {
        pocket: pocket.into(),
        session: None,
    })?
    else {
        return Err(CliError::new("internal", 70, "unexpected reply"));
    };
    crate::vsock::open(
        &vsock_uds,
        &StreamOpen::Attach {
            session,
            size: PtySize { rows: 24, cols: 80 },
            replay_scrollback: true,
            token,
        },
    )
}

fn first_output(s: &mut std::os::unix::net::UnixStream) -> Result<()> {
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    match recv::<_, AttachOut>(s) {
        Ok(Some(AttachOut::Data(_))) => Ok(()),
        other => Err(CliError::new(
            "guest",
            8,
            format!("no output on attach: {other:?}"),
        )),
    }
}

/// `stty raw -echo; cat` in the session, then one byte at a time.
fn rtt_us(s: &mut std::os::unix::net::UnixStream, n: usize) -> Result<Vec<f64>> {
    let io = |e: pocket_proto::ProtoError| CliError::new("guest", 8, e.to_string());
    send(
        s,
        &AttachIn::Data(b"stty raw -echo; echo RE\"\"ADY; exec cat\r".to_vec()),
    )
    .map_err(io)?;
    let mut seen = Vec::new();
    while !String::from_utf8_lossy(&seen).contains("READY") {
        match recv::<_, AttachOut>(s).map_err(io)? {
            Some(AttachOut::Data(d)) => seen.extend(d),
            _ => return Err(CliError::new("guest", 8, "session ended")),
        }
    }
    let mut out = vec![];
    for i in 0..n + 50 {
        let t = Instant::now();
        send(s, &AttachIn::Data(vec![b'a' + (i % 26) as u8])).map_err(io)?;
        loop {
            match recv::<_, AttachOut>(s).map_err(io)? {
                Some(AttachOut::Data(d)) if !d.is_empty() => break,
                Some(AttachOut::Data(_)) => {}
                _ => return Err(CliError::new("guest", 8, "session ended")),
            }
        }
        if i >= 50 {
            out.push(t.elapsed().as_secs_f64() * 1e6);
        }
    }
    Ok(out)
}

/// Same round trip on a local pty (`cat` in raw mode): the baseline the attach path adds to.
fn local_rtt_us(n: usize) -> Vec<f64> {
    let mut master = 0;
    let mut slave = 0;
    // SAFETY: openpty into locals; the fds are owned below.
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    } != 0
    {
        return vec![];
    }
    // SAFETY: termios on the slave we just opened.
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        libc::tcgetattr(slave, &mut t);
        libc::cfmakeraw(&mut t);
        libc::tcsetattr(slave, libc::TCSANOW, &t);
    }
    use std::os::fd::FromRawFd;
    // SAFETY: fresh descriptors from openpty.
    let (mut m, mut sl) = unsafe {
        (
            std::fs::File::from_raw_fd(master),
            std::fs::File::from_raw_fd(slave),
        )
    };
    let echo = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let mut b = [0u8; 64];
        while let Ok(k) = sl.read(&mut b) {
            if k == 0 || sl.write_all(&b[..k]).is_err() {
                break;
            }
        }
    });
    use std::io::{Read, Write};
    let mut out = vec![];
    let mut b = [0u8; 64];
    for i in 0..n + 50 {
        let t = Instant::now();
        if m.write_all(b"x").is_err() || m.read(&mut b).unwrap_or(0) == 0 {
            break;
        }
        if i >= 50 {
            out.push(t.elapsed().as_secs_f64() * 1e6);
        }
    }
    drop(m);
    drop(echo);
    out
}

fn p50(v: &[f64]) -> f64 {
    let mut v = v.to_vec();
    v.sort_by(|a, b| a.total_cmp(b));
    v.get(v.len() / 2).copied().unwrap_or(0.0)
}

pub fn run(
    c: &mut Client,
    runs: u32,
    preset: &str,
    density: u32,
    memory_mib: Option<u32>,
    progress: impl FnMut(&str),
) -> Result<Value> {
    let Response::Json(text) = c.request_with(
        Request::Bench {
            runs,
            preset: preset.into(),
            density,
            memory_mib,
        },
        progress,
    )?
    else {
        return Err(CliError::new("internal", 70, "unexpected reply"));
    };
    let mut report: Value =
        serde_json::from_str(&text).map_err(|e| CliError::new("internal", 70, e.to_string()))?;
    crate::end_progress();
    eprintln!("· pocket new → attached ×{runs}");
    let mut e2e = vec![];
    let mut rtt = vec![];
    let tag = format!("{:x}", std::process::id());
    for i in 0..runs {
        let name = format!("bench-{tag}-{i}");
        let t = Instant::now();
        let r = (|| {
            c.request(Request::NewPocket(new_req(&name, preset, memory_mib)))?;
            let mut s = attach(c, &name)?;
            first_output(&mut s)?;
            e2e.push(t.elapsed().as_secs_f64() * 1e3);
            if i == 0 {
                rtt = rtt_us(&mut s, 1000)?;
            }
            Ok::<_, CliError>(())
        })();
        let _ = c.request(Request::Remove { pocket: name });
        r?;
        // Let the pool refill so every run measures a warm start.
        std::thread::sleep(Duration::from_millis(400));
    }
    let local = local_rtt_us(1000);
    let added: Vec<f64> = {
        let base = p50(&local);
        rtt.iter().map(|x| (x - base).max(0.0)).collect()
    };
    let m = &mut report["metrics"];
    m["new_e2e_ms"] = stats(e2e);
    m["attach_rtt_us"] = stats(rtt);
    m["local_pty_rtt_us"] = stats(local);
    m["attach_rtt_added_us"] = stats(added);
    Ok(report)
}

fn stats(mut v: Vec<f64>) -> Value {
    if v.is_empty() {
        return Value::Null;
    }
    v.sort_by(|a, b| a.total_cmp(b));
    let pct = |p: f64| {
        let k = (v.len() - 1) as f64 * p / 100.0;
        let (lo, hi) = (k.floor() as usize, (k.ceil() as usize).min(v.len() - 1));
        v[lo] + (v[hi] - v[lo]) * (k - lo as f64)
    };
    let r = |x: f64| (x * 100.0).round() / 100.0;
    json!({ "p50": r(pct(50.0)), "p95": r(pct(95.0)), "min": r(v[0]), "max": r(v[v.len() - 1]), "n": v.len() })
}

pub fn print(report: &Value) {
    let m = &report["metrics"];
    println!(
        "pocket bench — preset {}, {} runs, {} vCPU / {} MiB guests",
        report["preset"].as_str().unwrap_or("?"),
        report["runs"],
        report["shape"]["vcpus"],
        report["shape"]["memory_mib"]
    );
    println!(
        "{:<36} {:>9} {:>9}   {:>15}",
        "", "p50", "p95", "target p50/p95"
    );
    for (k, label, t50, t95) in TARGETS {
        let v = &m[*k];
        let (p50, p95) = (v["p50"].as_f64(), v["p95"].as_f64());
        let ok = p50.is_some_and(|x| x <= *t50) && p95.is_some_and(|x| x <= *t95);
        println!(
            "{} {:<34} {:>9} {:>9}   {:>7}/{:<7}",
            if ok { "✓" } else { "✗" },
            label,
            p50.map(|x| format!("{x:.2}")).unwrap_or("-".into()),
            p95.map(|x| format!("{x:.2}")).unwrap_or("-".into()),
            t50,
            t95
        );
    }
    if let Some(d) = m.get("density").filter(|d| !d.is_null()) {
        println!(
            "  density: {} idle pockets → {} MiB total PSS ({} MiB each, {} MiB guests), disk {} MiB each",
            d["vms"],
            d["total_pss_mib"],
            d["per_vm_pss_mib"],
            d["guest_memory_mib"],
            d["disk_per_pocket_mib"]
        );
    }
    println!(
        "  template {} MiB on disk; hibernation image {} MiB, written in {} ms",
        report["template"]["size_mib"],
        m["hibernate_image_mib"]["p50"],
        m["hibernate_write_ms"]["p50"]
    );
}

/// Compares p50s with a baseline report from the same host; a metric regresses when it is
/// more than 10% and more than its noise floor slower.
pub fn regressions(report: &Value, baseline: &Path) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(baseline)
        .map_err(|e| CliError::io(&format!("read {}", baseline.display()), e))?;
    let base: Value = serde_json::from_str(&text)
        .map_err(|e| CliError::usage(format!("{}: {e}", baseline.display())))?;
    if base["host"]["cpu_model"] != report["host"]["cpu_model"] {
        eprintln!(
            "· baseline is from another CPU ({}); comparing against the targets only",
            base["host"]["cpu_model"]
        );
        return Ok(vec![]);
    }
    let mut out = vec![];
    for (k, label, ..) in TARGETS {
        let (Some(now), Some(was)) = (
            report["metrics"][*k]["p50"].as_f64(),
            base["metrics"][*k]["p50"].as_f64(),
        ) else {
            continue;
        };
        if now > was * 1.10 && now - was > noise_floor(k) {
            out.push(format!(
                "{label}: p50 {now:.2} vs baseline {was:.2} (+{:.0}%)",
                (now / was - 1.0) * 100.0
            ));
        }
    }
    Ok(out)
}
