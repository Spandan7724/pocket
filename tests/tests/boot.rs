use std::time::Duration;

use pocket_tests::{TestVm, VmOpts, kvm_or_skip};

#[test]
fn system_image_boots_and_powers_off() {
    let Some(a) = kvm_or_skip() else { return };
    let mut vm = TestVm::boot(&a, "boot", VmOpts::default());
    let st = vm.wait_exit(Duration::from_secs(20));
    assert!(
        st.is_some_and(|s| s.success()),
        "VM did not power off cleanly: {st:?}\n{}",
        vm.logs()
    );
    eprintln!("powered off after {:?}", vm.started.elapsed());
}
