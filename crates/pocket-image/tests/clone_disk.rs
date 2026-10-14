mod common;

use std::path::Path;

use common::*;
use pocket_image::disk::{CloneMode, clone_disk};

const TMPFS_MAGIC: i64 = 0x0102_1994;
const BTRFS_MAGIC: i64 = 0x9123_683e;
const XFS_MAGIC: i64 = 0x5846_5342;

#[test]
fn tmpfs_falls_back_to_sparse_copy() {
    let base = ["/tmp", "/dev/shm"]
        .into_iter()
        .map(Path::new)
        .find(|p| fs_magic(p) == TMPFS_MAGIC)
        .expect("neither /tmp nor /dev/shm is tmpfs");
    let d = fresh(base, "tmpfs");
    let src = sparse_source(&d);
    let dst = d.join("dst.raw");
    assert_eq!(clone_disk(&src, &dst).unwrap(), CloneMode::SparseCopy);
    assert_same_and_sparse(&src, &dst);
    eprintln!(
        "{}: sparse copy, contents equal, holes kept",
        base.display()
    );
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn reflink_used_where_supported() {
    let d = fresh(Path::new(env!("CARGO_TARGET_TMPDIR")), "reflink");
    let src = sparse_source(&d);
    let dst = d.join("dst.raw");
    let mode = clone_disk(&src, &dst).unwrap();
    let magic = fs_magic(&d);
    let expect = if [BTRFS_MAGIC, XFS_MAGIC].contains(&magic) {
        CloneMode::Reflink
    } else {
        CloneMode::SparseCopy
    };
    if std::env::var_os("POCKET_NO_REFLINK").is_none() {
        assert_eq!(mode, expect, "fs magic {magic:#x}");
    }
    assert_same_and_sparse(&src, &dst);
    eprintln!("{}: {mode:?} (fs magic {magic:#x})", d.display());
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn existing_destination_is_never_overwritten() {
    let d = fresh(Path::new(env!("CARGO_TARGET_TMPDIR")), "exists");
    let src = sparse_source(&d);
    let dst = d.join("dst.raw");
    std::fs::write(&dst, b"keep").unwrap();
    assert!(clone_disk(&src, &dst).is_err());
    assert_eq!(std::fs::read(&dst).unwrap(), b"keep");
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn copies_across_filesystems() {
    let tmp = Path::new("/tmp");
    let other = Path::new(env!("CARGO_TARGET_TMPDIR"));
    if fs_magic(tmp) == fs_magic(other) {
        eprintln!("skipping: /tmp and the target dir are on the same filesystem type");
        return;
    }
    let a = fresh(tmp, "xfs-src");
    let b = fresh(other, "xfs-dst");
    let src = sparse_source(&a);
    let dst = b.join("dst.raw");
    assert_eq!(clone_disk(&src, &dst).unwrap(), CloneMode::SparseCopy);
    assert_same_and_sparse(&src, &dst);
    std::fs::remove_dir_all(a).unwrap();
    std::fs::remove_dir_all(b).unwrap();
}
