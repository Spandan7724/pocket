use std::time::{Duration, Instant};

use pocket_image::oci::ImageStore;
use pocket_tests::guest::{Control, sh};
use pocket_tests::{Assets, TestVm, VmOpts, kvm_or_skip, scratch_dir};

#[test]
fn pull_oci_image_to_erofs_boot_it_and_hit_the_cache() {
    let Some(a) = kvm_or_skip() else { return };
    let dir = scratch_dir("image");
    let store = ImageStore {
        images_dir: dir.join("images"),
        blobs_dir: dir.join("blobs"),
        mkfs_erofs: "mkfs.erofs".into(),
    };
    let t = Instant::now();
    let first = store
        .pull("public.ecr.aws/docker/library/alpine:3.22", &|s| {
            eprintln!("pull: {s}")
        })
        .unwrap();
    eprintln!("first pull {:?}: {first:?}", t.elapsed());
    assert!(!first.cache_hit);
    assert_eq!(std::fs::metadata(&first.path).unwrap().len() % (2 << 20), 0);

    let t = Instant::now();
    let second = store
        .pull("public.ecr.aws/docker/library/alpine:3.22", &|_| {})
        .unwrap();
    eprintln!(
        "second pull by tag {:?}: cache_hit={}",
        t.elapsed(),
        second.cache_hit
    );
    assert!(second.cache_hit);
    assert_eq!(second.digest, first.digest);
    let by_digest = store
        .pull(
            &format!("public.ecr.aws/docker/library/alpine@{}", first.digest),
            &|_| panic!("no network expected"),
        )
        .unwrap();
    assert!(by_digest.cache_hit);

    let assets = Assets {
        base: first.path.clone(),
        ..a
    };
    let vm = TestVm::boot(&assets, "pulled", VmOpts::default());
    let mut ctl = Control::connect(&vm.vsock_uds, Duration::from_secs(10));
    let out = sh(
        &mut ctl,
        &vm.vsock_uds,
        "cat /etc/alpine-release; stat -c '%U %a' /bin/busybox",
    );
    eprintln!("guest: {out}");
    assert!(out.starts_with("3.22."), "{out}");
    assert!(out.contains("root 755"), "{out}");
    drop(vm);
    let _ = std::fs::remove_dir_all(dir);
}
