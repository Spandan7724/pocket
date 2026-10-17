//! `cargo xtask ci`: every check, run isolated from the user's real pocket state.
//!
//! The steps run in a child `cargo xtask ci` inside a systemd user scope (process group
//! when systemd is unavailable) with XDG dirs, the runtime dir and HOME pointing at a fresh
//! temp dir. Afterwards — also on failure — the scope is stopped, any process still carrying
//! the temp dir in its environment is killed (VMMs started in other scopes included), and
//! the temp dir is removed.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::util::{Result, fetch, have, out, output, root, run, status, step};
use crate::{assets, bail, kernel, lint};

const ACTIONLINT_VERSION: &str = "1.7.12";
const ACTIONLINT_SHA256: &str = "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8";
const XDG: &[(&str, &str)] = &[
    ("XDG_CONFIG_HOME", "config"),
    ("XDG_DATA_HOME", "data"),
    ("XDG_STATE_HOME", "state"),
    ("XDG_CACHE_HOME", "cache"),
    ("XDG_RUNTIME_DIR", "runtime"),
    ("HOME", "home"),
];

pub fn presets_isolated() -> Result {
    if env::var_os("POCKET_CI_INNER").is_some() {
        return presets();
    }
    let argv: Vec<OsString> = vec![env!("CARGO").into(), "xtask".into(), "presets".into()];
    let (st, _) = isolated(&argv, &[("POCKET_CI_INNER", "1".into())])?;
    if !st.success() {
        bail!("presets failed ({st})");
    }
    Ok(())
}

pub fn ci() -> Result {
    if env::var_os("POCKET_CI_INNER").is_some() {
        return inner();
    }
    let started = Instant::now();
    let argv: Vec<OsString> = vec![env!("CARGO").into(), "xtask".into(), "ci".into()];
    let (st, _) = isolated(&argv, &[("POCKET_CI_INNER", "1".into())])?;
    if !st.success() {
        bail!("ci failed ({st})");
    }
    selftest()?;
    eprintln!("\nci: all steps passed in {:.0?}", started.elapsed());
    Ok(())
}

fn inner() -> Result {
    let cargo = || {
        let mut c = Command::new(env!("CARGO"));
        c.current_dir(root());
        c
    };
    step("fmt");
    run(cargo().args(["fmt", "--all", "--check"]))?;
    step("clippy");
    run(cargo().args([
        "clippy",
        "--workspace",
        "--all-targets",
        "--locked",
        "--",
        "-D",
        "warnings",
    ]))?;
    lint::lint_deps()?;
    step("unit tests");
    run(cargo().args([
        "test",
        "--workspace",
        "--exclude",
        "pocket-tests",
        "--locked",
    ]))?;
    cross_aarch64()?;
    kernel::build(false)?;
    assets::vmm()?;
    assets::passt()?;
    assets::system()?;
    assets::test_base()?;
    presets()?;
    step("integration tests (KVM)");
    run(cargo()
        .env("POCKET_ASSETS_DIR", out())
        .env("POCKET_PRESET_CACHE", out().join("presets"))
        .args(["test", "--package", "pocket-tests", "--locked"]))?;
    bench_gate()?;
    actionlint()?;
    fuzz_smoke(15)?;
    Ok(())
}

pub const PRESETS: &[&str] = &["base"];

/// Builds the CLI and daemon, then the preset images into `<out>/presets` (a cache hit
/// when the preset scripts are unchanged). Expects isolated XDG dirs.
pub fn presets() -> Result {
    step("pocket binaries");
    run(Command::new(env!("CARGO")).current_dir(root()).args([
        "build",
        "--locked",
        "-p",
        "pocket-cli",
        "-p",
        "pocketd",
    ]))?;
    step("preset images");
    if !Path::new("/dev/kvm").exists() {
        eprintln!("SKIPPED: preset images need /dev/kvm");
        return Ok(());
    }
    let bin = root().join("target/debug");
    // The builder pocket's disk and the exported root filesystem are several GB: keep them
    // off a tmpfs /tmp. The runtime dir stays isolated (short UDS paths).
    let data = out().join("preset-build");
    let _ = fs::remove_dir_all(&data);
    fs::create_dir_all(&data)?;
    let pocket = |args: &[&str]| {
        let mut c = Command::new(bin.join("pocket"));
        c.args(args)
            .env("XDG_DATA_HOME", &data)
            .env("POCKET_ASSETS_DIR", out())
            .env("POCKET_PRESET_CACHE", out().join("presets"))
            .env("POCKETD", bin.join("pocketd"));
        c
    };
    let res = PRESETS
        .iter()
        .try_for_each(|p| run(&mut pocket(&["pull", p])));
    let _ = status(&mut pocket(&["daemon", "stop"]));
    res
}

/// Guest binaries must build for aarch64 too; VM tests there need an arm64 KVM host (D14).
fn cross_aarch64() -> Result {
    let target = "aarch64-unknown-linux-musl";
    step(&format!("cross-build guest binaries for {target}"));
    run(Command::new(env!("CARGO"))
        .current_dir(root())
        .env("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER", "rust-lld")
        .args([
            "build",
            "--locked",
            "--profile",
            "release-init",
            "--target",
            target,
        ])
        .args(["--package", "pocket-init", "--package", "pocket-guest"]))?;
    for bin in ["pocket-init", "pocket-guest"] {
        let p = root()
            .join("target")
            .join(target)
            .join("release-init")
            .join(bin);
        assets::check_static(&p)?;
        eprintln!(
            "{bin} ({target}): static, {} bytes",
            fs::metadata(&p)?.len()
        );
    }
    Ok(())
}

fn real_home() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| "/".into())
}

fn systemd_user() -> bool {
    have("systemd-run")
        && Command::new("systemd-run")
            .args(["--user", "--scope", "--quiet", "--collect", "true"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
}

fn make_tmp() -> Result<PathBuf> {
    static N: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.subsec_nanos();
    let tmp = env::temp_dir().join(format!(
        "pocket-ci.{}.{}.{nanos}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&tmp)?;
    for (_, d) in XDG {
        fs::create_dir(tmp.join(d))?;
    }
    fs::set_permissions(tmp.join("runtime"), fs::Permissions::from_mode(0o700))?;
    Ok(tmp)
}

/// Runs `argv` isolated; returns its status and the (already removed) temp dir path.
pub fn isolated(argv: &[OsString], extra: &[(&str, String)]) -> Result<(ExitStatus, PathBuf)> {
    let tmp = make_tmp()?;
    let home = real_home();
    let mut envs: Vec<(String, OsString)> = XDG
        .iter()
        .map(|(k, d)| (k.to_string(), tmp.join(d).into_os_string()))
        .collect();
    envs.push((
        "CARGO_HOME".into(),
        env::var_os("CARGO_HOME").unwrap_or_else(|| home.join(".cargo").into()),
    ));
    envs.push((
        "RUSTUP_HOME".into(),
        env::var_os("RUSTUP_HOME").unwrap_or_else(|| home.join(".rustup").into()),
    ));
    envs.push(("POCKET_CI_TMP".into(), tmp.clone().into_os_string()));
    for (k, v) in extra {
        envs.push((k.to_string(), v.into()));
    }

    let unit = format!("pocket-ci-{}-{}", std::process::id(), tmp_suffix(&tmp));
    let scope = systemd_user();
    let st = if scope {
        eprintln!(
            "isolation: {} in systemd user scope {unit}.scope",
            tmp.display()
        );
        let mut cmd = Command::new("systemd-run");
        cmd.args(["--user", "--scope", "--quiet", "--collect"])
            .arg(format!("--unit={unit}"))
            .arg("--")
            .arg("env");
        for (k, v) in &envs {
            let mut kv = OsString::from(format!("{k}="));
            kv.push(v);
            cmd.arg(kv);
        }
        cmd.args(argv);
        status(&mut cmd)
    } else {
        eprintln!(
            "isolation: {} in a process group (no systemd user manager)",
            tmp.display()
        );
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .envs(envs.iter().map(|(k, v)| (k, v)))
            .process_group(0);
        cmd.spawn()
            .and_then(|mut child| {
                let pgid = child.id();
                let st = child.wait();
                let _ = Command::new("kill")
                    .args(["-KILL", "--", &format!("-{pgid}")])
                    .status();
                st
            })
            .map_err(Into::into)
    };
    cleanup(&tmp, scope.then_some(unit.as_str()))?;
    Ok((st?, tmp))
}

fn tmp_suffix(tmp: &Path) -> String {
    tmp.file_name()
        .unwrap()
        .to_string_lossy()
        .rsplit('.')
        .take(2)
        .collect::<Vec<_>>()
        .join("-")
}

/// Pids of processes whose environment carries `POCKET_CI_TMP=<tmp>`.
fn tagged_processes(tmp: &Path) -> Vec<u32> {
    let mut needle = b"POCKET_CI_TMP=".to_vec();
    needle.extend_from_slice(tmp.as_os_str().as_encoded_bytes());
    needle.push(0);
    let Ok(dir) = fs::read_dir("/proc") else {
        return vec![];
    };
    dir.filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| {
            fs::read(format!("/proc/{pid}/environ"))
                .is_ok_and(|env| env.windows(needle.len()).any(|w| w == needle.as_slice()))
        })
        .collect()
}

fn cleanup(tmp: &Path, unit: Option<&str>) -> Result {
    if let Some(unit) = unit {
        let _ = Command::new("systemctl")
            .args(["--user", "stop", &format!("{unit}.scope")])
            .stderr(Stdio::null())
            .status();
    }
    let leftovers = tagged_processes(tmp);
    for pid in &leftovers {
        if let Ok(cg) = fs::read_to_string(format!("/proc/{pid}/cgroup"))
            && let Some(u) = cg
                .trim()
                .rsplit('/')
                .next()
                .filter(|u| u.starts_with("pocket"))
        {
            let _ = Command::new("systemctl")
                .args(["--user", "stop", u])
                .status();
        }
        let _ = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status();
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while !tagged_processes(tmp).is_empty() {
        if Instant::now() > deadline {
            bail!("cleanup: processes from {} survive SIGKILL", tmp.display());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if let Some(unit) = unit {
        let active = Command::new("systemctl")
            .args(["--user", "is-active", "--quiet", &format!("{unit}.scope")])
            .status()
            .is_ok_and(|s| s.success());
        if active {
            bail!("cleanup: {unit}.scope is still active");
        }
    }
    fs::remove_dir_all(tmp)?;
    eprintln!(
        "cleanup: removed {}, {} stray process(es) killed{}",
        tmp.display(),
        leftovers.len(),
        unit.map(|u| format!(", {u}.scope stopped"))
            .unwrap_or_default()
    );
    Ok(())
}

/// Proves the isolation: an isolated command that leaks a VMM and a sleeper, then fails.
pub fn selftest() -> Result {
    step("isolation self-test");
    let marker = env::temp_dir().join(format!("pocket-ci-selftest-{}", std::process::id()));
    let script = r#"
        env | grep -E '^(XDG_(CONFIG|DATA|STATE|CACHE)_HOME|XDG_RUNTIME_DIR|HOME)=' > "$M.env"
        sleep 600 & echo $! > "$M.pids"
        if [ -x "$CH" ] && [ -f "$K" ] && [ -w /dev/kvm ]; then
            setsid "$CH" --kernel "$K" --cmdline "panic=0 quiet" --memory size=64M \
                --cpus boot=1 --serial off --console off >/dev/null 2>&1 &
            echo $! >> "$M.pids"; echo vmm > "$M.vmm"
        fi
        sleep 1
        exit 1"#;
    let argv: Vec<OsString> = vec!["sh".into(), "-c".into(), script.into()];
    let (st, tmp) = isolated(
        &argv,
        &[
            ("M", marker.display().to_string()),
            ("CH", assets::vmm_binary().display().to_string()),
            ("K", kernel::artifact().display().to_string()),
        ],
    )?;
    let read = |ext: &str| fs::read_to_string(marker.with_extension(ext)).unwrap_or_default();
    let (envs, pids, vmm) = (read("env"), read("pids"), read("vmm"));
    for ext in ["env", "pids", "vmm"] {
        let _ = fs::remove_file(marker.with_extension(ext));
    }
    if st.success() {
        bail!("self-test: the failing command reported success");
    }
    let mut checked = 0;
    for line in envs.lines() {
        let (k, v) = line.split_once('=').unwrap_or((line, ""));
        if !Path::new(v).starts_with(&tmp) {
            bail!(
                "self-test: {k}={v} is not inside the isolation dir {}",
                tmp.display()
            );
        }
        checked += 1;
    }
    if checked != XDG.len() {
        bail!(
            "self-test: expected {} isolated variables, saw {checked}:\n{envs}",
            XDG.len()
        );
    }
    let pids: Vec<&str> = pids.split_whitespace().collect();
    if pids.is_empty() {
        bail!("self-test: the command did not record its leaked processes");
    }
    for pid in &pids {
        if Path::new(&format!("/proc/{pid}")).exists() {
            bail!("self-test: leaked process {pid} still running");
        }
    }
    if tmp.exists() {
        bail!("self-test: {} still exists", tmp.display());
    }
    if vmm.is_empty() && env::var("POCKET_KVM_TESTS").as_deref() == Ok("require") {
        bail!("self-test: no VMM was leaked (assets or /dev/kvm missing)");
    }
    eprintln!(
        "self-test ok: command failed as intended; {checked} XDG/HOME vars were inside the temp dir; \
         leaked processes {pids:?} ({}) are gone; temp dir removed",
        if vmm.is_empty() {
            "sleep only, no VMM"
        } else {
            "sleep + cloud-hypervisor"
        }
    );
    Ok(())
}

/// `pocket bench` against `bench/baseline.json` (PERFORMANCE.md §4): fails on a p50 more
/// than 10% (and more than a noise floor) slower than the baseline from the same CPU.
fn bench_gate() -> Result {
    step("bench gate");
    if !Path::new("/dev/kvm").exists() {
        eprintln!("SKIPPED: the bench needs /dev/kvm");
        return Ok(());
    }
    let bin = root().join("target/debug");
    let report = out().join("bench-latest.json");
    run(Command::new(bin.join("pocket"))
        .env("POCKET_ASSETS_DIR", out())
        .env("POCKET_PRESET_CACHE", out().join("presets"))
        .env("POCKETD", bin.join("pocketd"))
        .args([
            "bench",
            "--preset",
            "test",
            "--runs",
            "10",
            "--density",
            "0",
        ])
        .arg("--baseline")
        .arg(root().join("bench/baseline.json"))
        .arg("--out")
        .arg(&report))?;
    let _ = Command::new(bin.join("pocket"))
        .args(["daemon", "stop"])
        .status();
    Ok(())
}

fn actionlint() -> Result {
    step("actionlint");
    let tools = out().join("tools");
    let bin = tools.join("actionlint");
    if !bin.exists() {
        let tar = out()
            .join("cache")
            .join(format!("actionlint-{ACTIONLINT_VERSION}.tar.gz"));
        fetch(
            &format!(
                "https://github.com/rhysd/actionlint/releases/download/v{ACTIONLINT_VERSION}/actionlint_{ACTIONLINT_VERSION}_linux_amd64.tar.gz"
            ),
            ACTIONLINT_SHA256,
            &tar,
        )?;
        fs::create_dir_all(&tools)?;
        run(Command::new("tar")
            .arg("-C")
            .arg(&tools)
            .arg("-xzf")
            .arg(&tar)
            .arg("actionlint"))?;
    }
    run(Command::new(&bin).current_dir(root()))?;
    eprintln!("actionlint: workflows ok");
    Ok(())
}

pub fn fuzz_smoke(secs: u32) -> Result {
    step(&format!("fuzz smoke ({secs}s per target)"));
    let fuzz_dir = root().join("fuzz");
    if !fuzz_dir.join("Cargo.toml").exists() {
        eprintln!("no fuzz targets yet");
        return Ok(());
    }
    let ok = Command::new("cargo")
        .args(["+nightly", "fuzz", "--version"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        if env::var("POCKET_CI_FUZZ").as_deref() == Ok("require") {
            bail!(
                "fuzzing required but `cargo +nightly fuzz` is unavailable; run `rustup toolchain install nightly && cargo install cargo-fuzz`"
            );
        }
        eprintln!(
            "SKIPPED: `cargo +nightly fuzz` unavailable (set POCKET_CI_FUZZ=require to fail)"
        );
        return Ok(());
    }
    let targets = output(
        Command::new("cargo")
            .current_dir(&fuzz_dir)
            .args(["+nightly", "fuzz", "list"]),
    )?;
    for t in targets.lines().filter(|l| !l.trim().is_empty()) {
        run(Command::new("cargo")
            .current_dir(&fuzz_dir)
            .env_remove("RUSTUP_TOOLCHAIN")
            .args([
                "+nightly",
                "fuzz",
                "run",
                t,
                "--",
                &format!("-max_total_time={secs}"),
            ]))?;
    }
    Ok(())
}
