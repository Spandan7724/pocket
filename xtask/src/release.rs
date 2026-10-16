//! `cargo xtask release`: builds the release artifacts locally into `target/dist/` —
//! static x86_64 and aarch64 binaries, tarballs (x86_64 with the kernel, system image and
//! VMM bundled), an install script, a PKGBUILD, SHA256SUMS and a signature made with a
//! throwaway test key. Nothing is uploaded or published.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::util::{Result, fetch, out, root, run, sha256, step};
use crate::{assets, bail};

/// musl headers and crt for the C parts (SQLite, ring): Alpine's musl-dev, pinned.
const MUSL_DEV: &[(&str, &str, &str)] = &[
    (
        "x86_64",
        "https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/musl-dev-1.2.6-r2.apk",
        "6831e8b9e4821dae2c9121f0641f81e543f4ac27c03144c4876980ee84e6988f",
    ),
    (
        "aarch64",
        "https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/musl-dev-1.2.6-r2.apk",
        "ca72b84f4eb3c36bbbec04d919eb10159d414c7a43413cc2253841d301fa9486",
    ),
];

fn version() -> String {
    std::env::var("POCKET_VERSION").unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string())
}

fn sysroot(arch: &str) -> Result<PathBuf> {
    let (_, url, sha) = MUSL_DEV.iter().find(|(a, _, _)| *a == arch).unwrap();
    let apk = out().join("cache").join(format!("musl-dev-{arch}.apk"));
    fetch(url, sha, &apk)?;
    let dir = out()
        .join("cache")
        .join(format!("sysroot-{arch}-{}", &sha[..12]));
    if !dir.join("usr/include/stdio.h").exists() {
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        // An apk is concatenated gzip tar streams; GNU tar warns about the signature headers.
        let _ = Command::new("tar")
            .arg("-xzf")
            .arg(&apk)
            .arg("-C")
            .arg(&dir)
            .arg("--warning=no-unknown-keyword")
            .status()?;
        if !dir.join("usr/include/stdio.h").exists() {
            bail!("musl-dev for {arch} did not unpack into {}", dir.display());
        }
    }
    Ok(dir)
}

fn build(arch: &str) -> Result<PathBuf> {
    let target = format!("{arch}-unknown-linux-musl");
    step(&format!("static pocket + pocketd for {target}"));
    let sr = sysroot(arch)?;
    let t = target.replace('-', "_");
    let mut c = Command::new(env!("CARGO"));
    c.current_dir(root())
        .env(format!("CC_{t}"), "clang")
        .env(
            format!("CFLAGS_{t}"),
            format!("--target={arch}-linux-musl --sysroot={}", sr.display()),
        )
        .env(format!("AR_{t}"), "ar")
        .env(
            format!("CARGO_TARGET_{}_LINKER", t.to_ascii_uppercase()),
            "rust-lld",
        )
        .args([
            "build",
            "--release",
            "--locked",
            "--target",
            &target,
            "-p",
            "pocket-cli",
            "-p",
            "pocketd",
        ]);
    run(&mut c)?;
    let dir = root().join("target").join(&target).join("release");
    for b in ["pocket", "pocketd"] {
        assets::check_static(&dir.join(b))?;
        eprintln!(
            "{b} ({target}): static, {} bytes",
            fs::metadata(dir.join(b))?.len()
        );
    }
    Ok(dir)
}

fn copy(src: &Path, dst: &Path, mode: u32) -> Result {
    fs::create_dir_all(dst.parent().unwrap())?;
    fs::copy(src, dst)?;
    fs::set_permissions(dst, fs::Permissions::from_mode(mode))?;
    Ok(())
}

const INSTALL: &str = r#"#!/bin/sh
# pocket installer, no root needed.
#   ./install.sh pocket-VERSION-ARCH-linux.tar.gz   verify against SHA256SUMS (and, with
#                                                 POCKET_ALLOWED_SIGNERS, its signature), install
#   pocket-VERSION-ARCH-linux/install.sh            install an already extracted release
# PREFIX (default ~/.local) receives bin/; assets go to $XDG_DATA_HOME/pocket.
set -eu
fail() { echo "pocket: $*" >&2; exit 1; }
if [ $# -ge 1 ]; then
  tgz=$1
  dir=$(cd "$(dirname "$tgz")" && pwd)
  base=$(basename "$tgz")
  if [ -f "$dir/SHA256SUMS" ]; then
    if [ -n "${POCKET_ALLOWED_SIGNERS:-}" ]; then
      ssh-keygen -Y verify -f "$POCKET_ALLOWED_SIGNERS" -I release@pocket.invalid -n pocket-release \
        -s "$dir/SHA256SUMS.sig" < "$dir/SHA256SUMS" >/dev/null || fail "bad signature on SHA256SUMS"
    fi
    (cd "$dir" && grep "  $base\$" SHA256SUMS | sha256sum -c - >/dev/null) || fail "checksum mismatch for $base"
  else
    echo "pocket: warning: no SHA256SUMS next to $base; not verified" >&2
  fi
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  tar -xzf "$tgz" -C "$tmp"
  here=$(echo "$tmp"/pocket-*-linux)
else
  here=$(cd "$(dirname "$0")" && pwd)
fi
[ -x "$here/bin/pocket" ] || fail "no pocket binaries in $here"
prefix=${PREFIX:-$HOME/.local}
data=${XDG_DATA_HOME:-$HOME/.local/share}/pocket
install -d "$prefix/bin"
install -m 755 "$here/bin/pocket" "$here/bin/pocketd" "$prefix/bin/"
if [ -d "$here/share/pocket" ]; then
  mkdir -p "$data"
  cp -R "$here/share/pocket/." "$data/"
  chmod 700 "$data"
fi
echo "installed pocket $("$prefix/bin/pocket" --version | cut -d' ' -f2) to $prefix/bin"
case ":$PATH:" in *":$prefix/bin:"*) ;; *) echo "add $prefix/bin to PATH" ;; esac
[ -w /dev/kvm ] || echo "note: /dev/kvm is not writable for you; see \`pocket doctor\`"
command -v mkfs.erofs >/dev/null || echo "note: install erofs-utils (mkfs.erofs) to build images"
echo "next: pocket doctor"
"#;

fn pkgbuild(ver: &str, sums: &[(String, String)]) -> String {
    let sum = |a: &str| {
        sums.iter()
            .find(|(n, _)| n == &format!("pocket-{ver}-{a}-linux.tar.gz"))
            .map(|(_, s)| s.clone())
            .unwrap_or_default()
    };
    let pkgver = ver.replace('-', "_");
    format!(
        r#"# Maintainer: pocket contributors
pkgname=pocket-bin
pkgver={pkgver}
pkgrel=1
pkgdesc="Disposable microVM sandboxes for coding agents"
arch=('x86_64' 'aarch64')
url="https://github.com/Spandan7724/pocket"
license=('Apache-2.0')
depends=('erofs-utils' 'e2fsprogs' 'git')
optdepends=('virtiofsd: --share-dir' 'libsecret: Secret Service secret storage' 'openssh: ssh-agent forwarding')
provides=('pocket')
conflicts=('pocket')
source_x86_64=("pocket-{ver}-x86_64-linux.tar.gz")
source_aarch64=("pocket-{ver}-aarch64-linux.tar.gz")
sha256sums_x86_64=('{x}')
sha256sums_aarch64=('{a}')

package() {{
  cd "$srcdir/pocket-{ver}-$CARCH-linux"
  install -Dm755 bin/pocket "$pkgdir/usr/bin/pocket"
  install -Dm755 bin/pocketd "$pkgdir/usr/bin/pocketd"
  if [ -d share/pocket ]; then
    install -d "$pkgdir/usr/share/pocket"
    cp -R share/pocket/. "$pkgdir/usr/share/pocket/"
  fi
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
  install -Dm644 NOTICE "$pkgdir/usr/share/licenses/$pkgname/NOTICE"
}}
"#,
        x = sum("x86_64"),
        a = sum("aarch64")
    )
}

pub fn release() -> Result {
    let ver = version();
    let dist = root().join("target/dist");
    let _ = fs::remove_dir_all(&dist);
    fs::create_dir_all(&dist)?;
    // The guest side of the x86_64 bundle: current kernel, system image and VMM.
    crate::kernel::build(false)?;
    assets::vmm()?;
    assets::system()?;
    let mut tarballs = vec![];
    for arch in ["x86_64", "aarch64"] {
        let bins = build(arch)?;
        let name = format!("pocket-{ver}-{arch}-linux");
        let stage = dist.join(&name);
        copy(&bins.join("pocket"), &stage.join("bin/pocket"), 0o755)?;
        copy(&bins.join("pocketd"), &stage.join("bin/pocketd"), 0o755)?;
        for f in ["LICENSE", "NOTICE"] {
            copy(&root().join(f), &stage.join(f), 0o644)?;
        }
        fs::write(stage.join("install.sh"), INSTALL)?;
        fs::set_permissions(stage.join("install.sh"), fs::Permissions::from_mode(0o755))?;
        if arch == "x86_64" {
            let share = stage.join("share/pocket");
            copy(
                &out().join("kernel/vmlinux"),
                &share.join("kernel/vmlinux"),
                0o644,
            )?;
            copy(&assets::system_image(), &share.join("system.erofs"), 0o644)?;
            copy(
                &out().join("bin/cloud-hypervisor"),
                &share.join("bin/cloud-hypervisor"),
                0o755,
            )?;
            fs::write(
                stage.join("README"),
                format!(
                    "pocket {ver} for x86_64 Linux with KVM. Run ./install.sh, then `pocket doctor`.\n"
                ),
            )?;
        } else {
            fs::write(
                stage.join("README"),
                format!(
                    "pocket {ver} for aarch64 Linux: CLI and daemon only. Build the guest kernel, system image and Cloud Hypervisor on an arm64 host with `cargo xtask assets` and point POCKET_ASSETS_DIR at them.\n"
                ),
            )?;
        }
        let tgz = dist.join(format!("{name}.tar.gz"));
        run(Command::new("tar")
            .arg("--owner=0")
            .arg("--group=0")
            .arg("--sort=name")
            .arg("-czf")
            .arg(&tgz)
            .arg("-C")
            .arg(&dist)
            .arg(&name))?;
        tarballs.push(tgz);
    }
    fs::write(dist.join("install.sh"), INSTALL)?;
    fs::set_permissions(dist.join("install.sh"), fs::Permissions::from_mode(0o755))?;
    let mut sums = vec![];
    for t in &tarballs {
        sums.push((
            t.file_name().unwrap().to_string_lossy().into_owned(),
            sha256(t)?,
        ));
    }
    fs::write(dist.join("PKGBUILD"), pkgbuild(&ver, &sums))?;
    for f in ["install.sh", "PKGBUILD"] {
        sums.push((f.to_string(), sha256(&dist.join(f))?));
    }
    let list: String = sums.iter().map(|(n, s)| format!("{s}  {n}\n")).collect();
    fs::write(dist.join("SHA256SUMS"), &list)?;

    step("sign SHA256SUMS (throwaway test key)");
    let keydir = dist.join("test-signing-key");
    fs::create_dir_all(&keydir)?;
    let key = keydir.join("pocket-test");
    run(Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "pocket test release key (not for distribution)",
            "-f",
        ])
        .arg(&key))?;
    run(Command::new("ssh-keygen")
        .args(["-Y", "sign", "-n", "pocket-release", "-f"])
        .arg(&key)
        .arg(dist.join("SHA256SUMS")))?;
    let pubkey = fs::read_to_string(key.with_extension("pub"))?;
    let signers = keydir.join("allowed_signers");
    fs::write(&signers, format!("release@pocket.invalid {pubkey}"))?;
    let verify = Command::new("ssh-keygen")
        .args([
            "-Y",
            "verify",
            "-I",
            "release@pocket.invalid",
            "-n",
            "pocket-release",
            "-f",
        ])
        .arg(&signers)
        .arg("-s")
        .arg(dist.join("SHA256SUMS.sig"))
        .stdin(fs::File::open(dist.join("SHA256SUMS"))?)
        .output()?;
    eprint!("{}", String::from_utf8_lossy(&verify.stdout));
    if !verify.status.success() {
        bail!(
            "signature verification failed: {}",
            String::from_utf8_lossy(&verify.stderr)
        );
    }

    step("install check (temporary prefix)");
    let tmp = dist.join("install-check");
    let name = format!("pocket-{ver}-x86_64-linux");
    run(Command::new(dist.join("install.sh"))
        .arg(dist.join(format!("{name}.tar.gz")))
        .env("POCKET_ALLOWED_SIGNERS", &signers)
        .env("PREFIX", tmp.join("prefix"))
        .env("XDG_DATA_HOME", tmp.join("data")))?;
    let v = Command::new(tmp.join("prefix/bin/pocket"))
        .arg("--version")
        .output()?;
    eprintln!("installed: {}", String::from_utf8_lossy(&v.stdout).trim());
    if !tmp.join("data/pocket/kernel/vmlinux").exists() {
        bail!("install.sh did not install the assets");
    }
    let _ = fs::remove_dir_all(&tmp);

    eprintln!(
        "\nrelease artifacts in {} (local only, nothing published):",
        dist.display()
    );
    for e in fs::read_dir(&dist)?.flatten() {
        let m = e.metadata()?;
        if m.is_file() {
            eprintln!("  {:>12}  {}", m.len(), e.file_name().to_string_lossy());
        }
    }
    eprint!("{list}");
    Ok(())
}
