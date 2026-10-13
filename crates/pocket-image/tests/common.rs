#![allow(dead_code)] // shared by several test binaries, each using a subset
use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub const LEN: u64 = 256 << 20;

/// 256 MiB sparse file with 1 MiB of data at the start, middle and end.
pub fn sparse_source(dir: &Path) -> PathBuf {
    let p = dir.join("src.raw");
    let mut f = File::create(&p).unwrap();
    f.set_len(LEN).unwrap();
    for off in [0, LEN / 2, LEN - (1 << 20)] {
        f.seek(SeekFrom::Start(off)).unwrap();
        let chunk: Vec<u8> = (0..1 << 20).map(|i| (i as u64 ^ off) as u8 | 1).collect();
        f.write_all(&chunk).unwrap();
    }
    f.sync_all().unwrap();
    p
}

pub fn assert_same_and_sparse(src: &Path, dst: &Path) {
    assert_eq!(
        fs::read(src).unwrap(),
        fs::read(dst).unwrap(),
        "contents differ"
    );
    let allocated = fs::metadata(dst).unwrap().blocks() * 512;
    assert_eq!(fs::metadata(dst).unwrap().len(), LEN);
    assert!(
        allocated <= 8 << 20,
        "copy is not sparse: {allocated} bytes allocated"
    );
}

pub fn fs_magic(p: &Path) -> i64 {
    let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: statfs fills a zeroed struct for a valid C path.
    unsafe {
        let mut s: libc::statfs = std::mem::zeroed();
        assert_eq!(libc::statfs(c.as_ptr(), &mut s), 0);
        s.f_type as i64
    }
}

pub fn fresh(base: &Path, tag: &str) -> PathBuf {
    let d = base.join(format!("pocket-image-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}
