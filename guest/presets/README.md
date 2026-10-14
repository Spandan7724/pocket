Build scripts for the official preset images. `pocket pull <preset>` boots a builder
pocket on the parent image (Ubuntu 24.04 OCI image for `base`, the `base` preset for the
others), runs the script as root with egress through the pocket proxy (`dev` profile),
exports the root filesystem as a tarball and builds the erofs image. The image key hashes
the script and the parent's key, so editing a script rebuilds the preset.
