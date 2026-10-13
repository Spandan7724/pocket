//! Separate test binary: it sets process environment, so it holds exactly one test.

mod common;

use std::path::Path;

use common::*;
use pocket_image::disk::{CloneMode, NO_REFLINK_ENV, clone_disk};

#[test]
fn env_var_forces_sparse_copy_even_where_reflink_works() {
    // SAFETY: the only test in this binary; no other thread reads the environment.
    unsafe { std::env::set_var(NO_REFLINK_ENV, "1") };
    let d = fresh(Path::new(env!("CARGO_TARGET_TMPDIR")), "forced");
    let src = sparse_source(&d);
    let dst = d.join("dst.raw");
    assert_eq!(clone_disk(&src, &dst).unwrap(), CloneMode::SparseCopy);
    assert_same_and_sparse(&src, &dst);
    eprintln!("{NO_REFLINK_ENV}=1 on {}: sparse copy", d.display());
    std::fs::remove_dir_all(d).unwrap();
}
