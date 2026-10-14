use pocket_image::disk::{CloneMode, NO_REFLINK_ENV, allocated_bytes, create_pocket_disk};

#[test]
fn fresh_pocket_disk_is_sparse_ext4_under_50_mb() {
    let base = std::env::var_os("POCKET_TEST_DISK_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap().join("../../target"));
    let dir = base.join(format!("pocket-disk-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let size = 20u64 << 30;
    let a = dir.join("a.raw");
    let mode = create_pocket_disk(&dir.join("templates"), size, &a).unwrap();
    let used = allocated_bytes(&a);
    eprintln!(
        "20 GiB pocket disk via {mode:?}: {:.1} MiB allocated (template {:.1} MiB)",
        used as f64 / 1048576.0,
        allocated_bytes(&dir.join("templates/empty-ext4-20480m.raw")) as f64 / 1048576.0
    );
    assert_eq!(std::fs::metadata(&a).unwrap().len(), size);
    assert!(used < 50 << 20, "fresh disk allocates {used} bytes");
    let fsck = std::process::Command::new("e2fsck")
        .args(["-n", "-f"])
        .arg(&a)
        .output()
        .unwrap();
    assert!(
        fsck.status.success(),
        "{}",
        String::from_utf8_lossy(&fsck.stdout)
    );

    // Same with the copy path forced (filesystems without reflink).
    unsafe { std::env::set_var(NO_REFLINK_ENV, "1") };
    let b = dir.join("b.raw");
    let mode = create_pocket_disk(&dir.join("templates"), size, &b).unwrap();
    assert_eq!(mode, CloneMode::SparseCopy);
    let used = allocated_bytes(&b);
    eprintln!("sparse copy: {:.1} MiB allocated", used as f64 / 1048576.0);
    assert!(used < 50 << 20);
    let _ = std::fs::remove_dir_all(&dir);
}
