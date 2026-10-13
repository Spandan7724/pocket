The system disk is built by `cargo xtask system`: a read-only erofs holding `pocket-init`
at `/pocket-init` plus the empty mount points it needs before `pivot_root`.
