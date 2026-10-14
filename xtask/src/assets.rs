//! System disk, pinned VMM build and the integration-test base image.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::bail;
use crate::util::{Result, fetch, fresh_dir, out, output, root, run, step};

pub const INIT_TARGET: &str = "x86_64-unknown-linux-musl";
const INIT_MAX_BYTES: u64 = 5 * 1024 * 1024;

// D3: copyonwrite restore is on main but not in v53.0; re-pin to v54.0 once released.
const CH_REPO: &str = "https://github.com/cloud-hypervisor/cloud-hypervisor.git";
const CH_COMMIT: &str = "1c7088c0bc4d2a41b9b5d308ed9e8fdf6524f695";

const ALPINE_URL: &str = "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-minirootfs-3.24.2-x86_64.tar.gz";
const ALPINE_SHA256: &str = "c5ca053cfe1d85c5b96dff8b9bc57045f7f184a30ffb6b65776409ca90388677";

pub fn system_image() -> PathBuf {
    out().join("system.erofs")
}

pub fn vmm_binary() -> PathBuf {
    out().join("bin").join("cloud-hypervisor")
}

pub fn test_base_image() -> PathBuf {
    out().join("test-base.erofs")
}

pub fn init_binary() -> Result<PathBuf> {
    run(Command::new(env!("CARGO"))
        .current_dir(root())
        .args([
            "build",
            "--package",
            "pocket-init",
            "--profile",
            "release-init",
        ])
        .args(["--target", INIT_TARGET]))?;
    let bin = root()
        .join("target")
        .join(INIT_TARGET)
        .join("release-init")
        .join("pocket-init");
    check_static(&bin)?;
    let size = fs::metadata(&bin)?.len();
    if size > INIT_MAX_BYTES {
        bail!("pocket-init is {size} bytes, over the {INIT_MAX_BYTES} byte budget");
    }
    eprintln!(
        "pocket-init: static, {size} bytes ({:.2} MiB)",
        size as f64 / 1048576.0
    );
    Ok(bin)
}

pub fn guest_binary() -> Result<PathBuf> {
    run(Command::new(env!("CARGO"))
        .current_dir(root())
        .args([
            "build",
            "--package",
            "pocket-guest",
            "--profile",
            "release-init",
        ])
        .args(["--target", INIT_TARGET]))?;
    let bin = root()
        .join("target")
        .join(INIT_TARGET)
        .join("release-init")
        .join("pocket-guest");
    check_static(&bin)?;
    Ok(bin)
}

/// Fails if the ELF requests a dynamic loader (PT_INTERP).
pub fn check_static(bin: &Path) -> Result {
    let data = fs::read(bin)?;
    if data.len() < 64 || &data[..4] != b"\x7fELF" || data[4] != 2 {
        bail!("{} is not a 64-bit ELF", bin.display());
    }
    let u16_at = |o: usize| u16::from_le_bytes([data[o], data[o + 1]]) as usize;
    let phoff = u64::from_le_bytes(data[0x20..0x28].try_into()?) as usize;
    let (phentsize, phnum) = (u16_at(0x36), u16_at(0x38));
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        let p_type = u32::from_le_bytes(data[off..off + 4].try_into()?);
        if p_type == 3 {
            bail!("{} is dynamically linked (has PT_INTERP)", bin.display());
        }
    }
    Ok(())
}

fn mkfs_erofs(dest: &Path, dir: &Path) -> Result {
    let tmp = dest.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    // -T0/-U fixed: identical inputs give an identical image.
    run(Command::new("mkfs.erofs")
        .stdout(std::process::Stdio::null())
        .args(["--all-root", "-T0"])
        .arg("-Uc1b9d5a2-0000-4000-8000-706f636b6574")
        .arg(&tmp)
        .arg(dir))?;
    // virtio-pmem maps whole 2 MiB pages; erofs ignores the tail.
    let len = fs::metadata(&tmp)?.len();
    let align = 2 << 20;
    fs::File::options()
        .write(true)
        .open(&tmp)?
        .set_len(len.div_ceil(align) * align)?;
    fs::rename(&tmp, dest)?;
    Ok(())
}

pub fn system() -> Result<PathBuf> {
    step("system image");
    let init = init_binary()?;
    let staging = out().join("system-staging");
    fresh_dir(&staging)?;
    for d in ["dev", "proc", "sys", "run", "newroot"] {
        fs::create_dir(staging.join(d))?;
    }
    let dest_init = staging.join("pocket-init");
    fs::copy(&init, &dest_init)?;
    fs::set_permissions(&dest_init, fs::Permissions::from_mode(0o755))?;
    fs::create_dir(staging.join("bin"))?;
    let dest_guest = staging.join("bin/pocket-guest");
    fs::copy(guest_binary()?, &dest_guest)?;
    fs::set_permissions(&dest_guest, fs::Permissions::from_mode(0o755))?;
    std::os::unix::fs::symlink("pocket-guest", staging.join("bin/git-remote-pocket"))?;
    let img = system_image();
    mkfs_erofs(&img, &staging)?;
    let listing = output(
        Command::new("dump.erofs")
            .args(["--ls", "--path=/"])
            .arg(&img),
    )?;
    eprintln!("{} contents:\n{listing}", img.display());
    if !listing.contains("pocket-init") || !listing.contains("bin") {
        bail!("system image does not contain pocket-init");
    }
    Ok(img)
}

pub fn vmm() -> Result<PathBuf> {
    step(&format!("cloud-hypervisor @ {}", &CH_COMMIT[..7]));
    let dest = vmm_binary();
    let stamp = dest.with_extension("commit");
    if dest.exists() && fs::read_to_string(&stamp).is_ok_and(|s| s.trim() == CH_COMMIT) {
        eprintln!("up to date: {}", dest.display());
        return Ok(dest);
    }
    let src = out()
        .join("src")
        .join(format!("cloud-hypervisor-{}", &CH_COMMIT[..12]));
    if !src.join("Cargo.toml").exists() {
        fresh_dir(&src)?;
        let git = |args: &[&str]| run(Command::new("git").current_dir(&src).args(args));
        git(&["init", "-q"])?;
        git(&["fetch", "-q", "--depth", "1", CH_REPO, CH_COMMIT])?;
        git(&["checkout", "-q", "FETCH_HEAD"])?;
    }
    run(Command::new(env!("CARGO"))
        .current_dir(&src)
        .env("CARGO_TARGET_DIR", src.join("target"))
        .args(["build", "--release", "--bin", "cloud-hypervisor"]))?;
    fs::create_dir_all(dest.parent().unwrap())?;
    fs::copy(src.join("target/release/cloud-hypervisor"), &dest)?;
    fs::write(&stamp, CH_COMMIT)?;
    eprintln!("{}", output(Command::new(&dest).arg("--version"))?.trim());
    Ok(dest)
}

pub fn test_base() -> Result<PathBuf> {
    step("test base image (Alpine minirootfs)");
    let tar = out().join("cache").join("alpine-minirootfs.tar.gz");
    fetch(ALPINE_URL, ALPINE_SHA256, &tar)?;
    let img = test_base_image();
    let stamp = img.with_extension("sha256");
    if img.exists() && fs::read_to_string(&stamp).is_ok_and(|s| s.trim() == ALPINE_SHA256) {
        eprintln!("up to date: {}", img.display());
        return Ok(img);
    }
    let staging = out().join("test-base-staging");
    fresh_dir(&staging)?;
    run(Command::new("tar")
        .arg("-C")
        .arg(&staging)
        .args(["--no-same-owner", "-xzf"])
        .arg(&tar))?;
    for d in ["work", "home"] {
        fs::create_dir_all(staging.join(d))?;
    }
    mkfs_erofs(&img, &staging)?;
    fs::write(&stamp, ALPINE_SHA256)?;
    Ok(img)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_static_rejects_dynamic_and_non_elf() {
        assert!(check_static(Path::new("/bin/sh")).is_err());
        assert!(check_static(Path::new(env!("CARGO_MANIFEST_DIR"))).is_err());
    }
}
