# pocket preset "base": Ubuntu 24.04 LTS + dev tools + terminfo, user `dev` (uid 1000)
# with passwordless sudo. Runs as root in a builder pocket; egress via the pocket proxy.
set -eux
export DEBIAN_FRONTEND=noninteractive
cat > /etc/apt/apt.conf.d/90pocket-proxy <<'APT'
Acquire::http::Proxy "http://127.0.0.1:3128";
Acquire::https::Proxy "http://127.0.0.1:3128";
APT
rm -f /etc/apt/apt.conf.d/docker-clean
apt-get update
apt-get install -y --no-install-recommends \
    ca-certificates curl wget git sudo less vim htop tmux ncurses-term locales \
    build-essential pkg-config python3 python3-pip python3-venv nodejs npm cargo \
    procps psmisc iproute2 openssh-client unzip zip xz-utils jq ripgrep file \
    bash-completion man-db
userdel -r ubuntu 2>/dev/null || true
useradd -m -u 1000 -s /bin/bash -G sudo dev
echo 'dev ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-dev
echo 'Defaults env_keep += "http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY NODE_USE_ENV_PROXY TERM COLORTERM"' > /etc/sudoers.d/91-pocket
chmod 0440 /etc/sudoers.d/90-dev /etc/sudoers.d/91-pocket
mkdir -p /work
apt-get clean
rm -rf /var/lib/apt/lists/* /var/cache/apt/*.bin /root/.cache /root/.npm
git --version; node --version; python3 --version; cargo --version
