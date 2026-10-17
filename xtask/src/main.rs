mod assets;
mod ci;
mod kernel;
mod lint;
mod release;
mod util;

use std::process::ExitCode;

const USAGE: &str = "usage: cargo xtask <command>

commands:
  ci                          fmt, clippy, lint-deps, unit + KVM tests, actionlint, fuzz smoke (isolated)
  kernel [--verify-reproducible]   build the guest kernel
  system                      build the system erofs with pocket-init
  vmm                         build the pinned cloud-hypervisor
  test-base                   build the integration-test base image
  assets                      kernel + vmm + system + test-base
  presets                     build the preset images into the assets dir (isolated)
  lint-deps                   check crate dependency directions
  preview-tui [SCENE…]        render dashboard scenes offline (--plain for text)
  fuzz [SECONDS]              run every fuzz target (default 60 s each)
  release                     build release tarballs, install script, PKGBUILD (local only)
  isolation-selftest          prove ci isolation cleans up after a failing, leaking command";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let res = match args.first().map(String::as_str) {
        Some("ci") => ci::ci(),
        Some("kernel") => {
            kernel::build(args.iter().any(|a| a == "--verify-reproducible")).map(|_| ())
        }
        Some("system") => assets::system().map(|_| ()),
        Some("vmm") => assets::vmm().map(|_| ()),
        Some("passt") => assets::passt().map(|_| ()),
        Some("test-base") => assets::test_base().map(|_| ()),
        Some("assets") => (|| {
            kernel::build(false)?;
            assets::vmm()?;
            assets::passt()?;
            assets::system()?;
            assets::test_base()?;
            Ok(())
        })(),
        Some("presets") => ci::presets_isolated(),
        Some("lint-deps") => lint::lint_deps(),
        // Offline dashboard scenes (STYLES.md); no daemon or KVM needed.
        Some("preview-tui") => util::run(
            std::process::Command::new(env!("CARGO"))
                .current_dir(util::root())
                .args([
                    "run",
                    "-q",
                    "-p",
                    "pocket-tui",
                    "--example",
                    "preview",
                    "--",
                ])
                .args(&args[1..]),
        ),
        Some("release") => release::release(),
        Some("fuzz") => ci::fuzz_smoke(args.get(1).and_then(|s| s.parse().ok()).unwrap_or(60)),
        Some("isolation-selftest") => ci::selftest(),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
