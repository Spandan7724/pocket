`cargo xtask kernel` downloads the pinned Linux release, verifies its sha256, merges
`pocket.config` over `base-x86_64.config` and builds `vmlinux` reproducibly
(`--verify-reproducible` builds twice in separate trees and compares hashes).
