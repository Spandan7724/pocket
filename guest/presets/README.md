Build script for the built-in preset image (D19: one image, `base`). `pocket pull base`
boots a builder pocket on the Ubuntu 24.04 OCI image, runs `base.sh` as root with egress
through the pocket proxy (`dev` profile), exports the root filesystem as a tarball and
builds the erofs image. The image key hashes the script, so editing it rebuilds the image.
