use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::bail;
use crate::util::{Result, fetch, fresh_dir, nproc, out, root, run, sha256, step};

pub const VERSION: &str = "6.18.56";
const SHA256: &str = "4633bbda2ab95eaf2a7af4041236451d6759c72e6946265531af4b3aacefbf89";

fn tarball() -> Result<PathBuf> {
    let dest = out().join("cache").join(format!("linux-{VERSION}.tar.xz"));
    let url = format!("https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-{VERSION}.tar.xz");
    fetch(&url, SHA256, &dest)?;
    Ok(dest)
}

pub fn artifact() -> PathBuf {
    out().join("kernel").join("vmlinux")
}

/// Builds the guest kernel; with `verify`, builds twice from scratch and compares hashes.
pub fn build(verify: bool) -> Result<PathBuf> {
    step(&format!("kernel {VERSION}"));
    let tar = tarball()?;
    let trees = if verify { vec!["a", "b"] } else { vec!["a"] };
    let mut hashes = Vec::new();
    for t in &trees {
        let dir = out().join("kernel-build").join(t);
        if verify {
            fresh_dir(&dir)?;
        }
        let vmlinux = build_in(&tar, &dir)?;
        hashes.push((vmlinux.clone(), sha256(&vmlinux)?));
    }
    for (p, h) in &hashes {
        eprintln!("sha256 {h}  {}", p.display());
    }
    if verify {
        if hashes[0].1 != hashes[1].1 {
            bail!("kernel build is not reproducible: two clean builds differ");
        }
        eprintln!("reproducible: two clean builds produced identical vmlinux");
    }
    let dest = artifact();
    fs::create_dir_all(dest.parent().unwrap())?;
    fs::copy(&hashes[0].0, &dest)?;
    fs::write(
        dest.with_extension("version"),
        format!("{VERSION}-pocket\n"),
    )?;
    Ok(dest)
}

fn build_in(tar: &Path, dir: &Path) -> Result<PathBuf> {
    let src = dir.join(format!("linux-{VERSION}"));
    if !src.exists() {
        fs::create_dir_all(dir)?;
        run(Command::new("tar").arg("-C").arg(dir).arg("-xf").arg(tar))?;
    }
    let cfg_dir = root().join("guest").join("kernel");
    let fragment = cfg_dir.join("pocket.config");
    fs::copy(cfg_dir.join("base-x86_64.config"), src.join(".config"))?;
    run(Command::new("./scripts/kconfig/merge_config.sh")
        .current_dir(&src)
        .args(["-m", "-Q", ".config"])
        .arg(&fragment))?;
    run(Command::new("make")
        .current_dir(&src)
        .arg("olddefconfig")
        .stdout(std::process::Stdio::null()))?;
    check_config(
        &fs::read_to_string(&fragment)?,
        &fs::read_to_string(src.join(".config"))?,
    )?;
    run(Command::new("make")
        .current_dir(&src)
        .args(["-s", "-j", &nproc(), "vmlinux"])
        .env("KBUILD_BUILD_TIMESTAMP", "2026-01-01 00:00:00 UTC")
        .env("KBUILD_BUILD_USER", "pocket")
        .env("KBUILD_BUILD_HOST", "pocket")
        .env("KBUILD_BUILD_VERSION", "1"))?;
    Ok(src.join("vmlinux"))
}

fn config_value(config: &str, key: &str) -> String {
    for line in config.lines() {
        if line == format!("# {key} is not set") {
            return "n".into();
        }
        if let Some(v) = line.strip_prefix(&format!("{key}=")) {
            return v.into();
        }
    }
    "n".into()
}

/// Every option in the fragment must survive `olddefconfig` (it silently drops unmet ones).
fn check_config(fragment: &str, config: &str) -> Result {
    let mut bad = Vec::new();
    for line in fragment.lines() {
        let (key, want) = if let Some(k) = line
            .strip_prefix("# ")
            .and_then(|l| l.strip_suffix(" is not set"))
        {
            (k.to_string(), "n".to_string())
        } else if let Some((k, v)) = line.split_once('=') {
            if k.starts_with('#') {
                continue;
            }
            (k.to_string(), v.to_string())
        } else {
            continue;
        };
        let got = config_value(config, &key);
        if got != want {
            bad.push(format!("{key}: want {want}, got {got}"));
        }
    }
    if !bad.is_empty() {
        bail!(
            "kernel config fragment not applied:\n  {}",
            bad.join("\n  ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_check_detects_dropped_options() {
        let frag = "# CONFIG_MODULES is not set\nCONFIG_EROFS_FS=y\n# comment\n";
        assert!(check_config(frag, "# CONFIG_MODULES is not set\nCONFIG_EROFS_FS=y\n").is_ok());
        let err = check_config(frag, "CONFIG_MODULES=y\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("CONFIG_MODULES: want n, got y"), "{err}");
        assert!(err.contains("CONFIG_EROFS_FS: want y, got n"), "{err}");
    }
}
