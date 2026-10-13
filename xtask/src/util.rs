use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

pub type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => { return Err(format!($($arg)*).into()) };
}

pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives in the workspace root")
        .to_path_buf()
}

/// Build artifacts and download caches; repo-local so CI isolation never touches it.
pub fn out() -> PathBuf {
    root().join("target").join("pocket")
}

pub fn step(name: &str) {
    eprintln!("\n==> {name}");
}

fn show(cmd: &Command) -> String {
    let mut s = cmd.get_program().to_string_lossy().into_owned();
    for a in cmd.get_args() {
        s.push(' ');
        s.push_str(&a.to_string_lossy());
    }
    s
}

pub fn status(cmd: &mut Command) -> Result<ExitStatus> {
    eprintln!("$ {}", show(cmd));
    cmd.status()
        .map_err(|e| format!("failed to start `{}`: {e}", show(cmd)).into())
}

pub fn run(cmd: &mut Command) -> Result {
    let st = status(cmd)?;
    if !st.success() {
        bail!("`{}` failed: {st}", show(cmd));
    }
    Ok(())
}

pub fn output(cmd: &mut Command) -> Result<String> {
    let out = cmd
        .output()
        .map_err(|e| format!("failed to start `{}`: {e}", show(cmd)))?;
    if !out.status.success() {
        bail!(
            "`{}` failed: {}\n{}",
            show(cmd),
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8(out.stdout)?)
}

pub fn sha256(path: &Path) -> Result<String> {
    let out = output(Command::new("sha256sum").arg(path))?;
    Ok(out
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string())
}

/// Download `url` to `dest` unless it is already there with the expected hash.
pub fn fetch(url: &str, sha: &str, dest: &Path) -> Result {
    if dest.exists() && sha256(dest)? == sha {
        return Ok(());
    }
    fs::create_dir_all(dest.parent().unwrap())?;
    let tmp = dest.with_extension("part");
    run(Command::new("curl")
        .args(["-fsSL", "--retry", "3", "-o"])
        .arg(&tmp)
        .arg(url))?;
    let got = sha256(&tmp)?;
    if got != sha {
        let _ = fs::remove_file(&tmp);
        bail!("checksum mismatch for {url}: expected {sha}, got {got}");
    }
    fs::rename(&tmp, dest)?;
    Ok(())
}

pub fn fresh_dir(p: &Path) -> Result {
    if p.exists() {
        fs::remove_dir_all(p)?;
    }
    fs::create_dir_all(p)?;
    Ok(())
}

pub fn have(program: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {program} >/dev/null")])
        .status()
        .is_ok_and(|s| s.success())
}

pub fn nproc() -> String {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .to_string()
}
