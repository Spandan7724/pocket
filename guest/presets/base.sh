# pocket preset "base" — the one built-in image (D19): Ubuntu 24.04 LTS, the major language
# toolchains and the major coding agents, user `dev` (uid 1000) with passwordless sudo.
# Runs as root in a builder pocket; all downloads go through the pocket proxy (dev profile).
set -eux
export DEBIAN_FRONTEND=noninteractive
ARCH=$(uname -m)

cat > /etc/apt/apt.conf.d/90pocket-proxy <<'APT'
Acquire::http::Proxy "http://127.0.0.1:3128";
Acquire::https::Proxy "http://127.0.0.1:3128";
APT
rm -f /etc/apt/apt.conf.d/docker-clean
apt-get update
apt-get install -y --no-install-recommends \
    ca-certificates curl wget git gh sudo less vim htop tmux tree ncurses-term locales \
    procps psmisc iproute2 openssh-client unzip zip xz-utils jq ripgrep file \
    bash-completion man-db \
    build-essential pkg-config clang cmake ninja-build gdb \
    python3 python3-pip python3-venv python3-dev pipx \
    golang-go \
    openjdk-21-jdk-headless maven \
    ruby-full ruby-bundler \
    php-cli php-mbstring php-xml php-curl php-zip php-sqlite3 php-intl composer \
    dotnet-sdk-8.0

# Node.js 22 LTS from nodejs.org (Ubuntu's 18 is end-of-life; Claude Code and Pi need 22).
case "$ARCH" in x86_64) NODE_ARCH=x64 ;; aarch64) NODE_ARCH=arm64 ;; esac
NODE_DIST=https://nodejs.org/dist/latest-v22.x
NODE_TAR=$(curl -fsSL "$NODE_DIST/SHASUMS256.txt" | awk "/linux-$NODE_ARCH.tar.xz\$/ {print \$2}")
curl -fsSL "$NODE_DIST/SHASUMS256.txt" | grep " $NODE_TAR\$" > /tmp/node.sha
curl -fsSL -o "/tmp/$NODE_TAR" "$NODE_DIST/$NODE_TAR"
(cd /tmp && sha256sum -c node.sha)
tar -xJf "/tmp/$NODE_TAR" -C /usr/local --strip-components=1 --no-same-owner
rm -f "/tmp/$NODE_TAR" /tmp/node.sha
corepack enable

# Rust stable via rustup, system-wide; homes link to the shared toolchain.
export RUSTUP_HOME=/opt/rust/rustup CARGO_HOME=/opt/rust/cargo
curl -fsSL -o /tmp/rustup-init "https://static.rust-lang.org/rustup/dist/$ARCH-unknown-linux-gnu/rustup-init"
chmod +x /tmp/rustup-init
/tmp/rustup-init -y --no-modify-path --profile minimal -c rustfmt,clippy
rm /tmp/rustup-init
for b in /opt/rust/cargo/bin/*; do ln -sf "$b" /usr/local/bin/; done
ln -s /opt/rust/rustup /etc/skel/.rustup
ln -s /opt/rust/rustup /root/.rustup
chmod -R a+rX /opt/rust
unset RUSTUP_HOME CARGO_HOME

# Bun.
curl -fsSL https://bun.sh/install | BUN_INSTALL=/opt/bun bash
ln -sf /opt/bun/bin/bun /opt/bun/bin/bunx /usr/local/bin/

# Agents from npm. npm reads the proxy variables itself; Node 22's experimental env-proxy
# agent is kept out of it, and installs are retried (one build hit EIDLETIMEOUT once).
npm_i() {
    for attempt in 1 2 3; do
        env -u NODE_USE_ENV_PROXY npm install -g --no-fund --no-audit \
            --fetch-retries=5 --fetch-retry-maxtimeout=120000 "$@" && return 0
        echo "npm install failed (attempt $attempt), retrying" >&2
        sleep 10
    done
    return 1
}
npm_i \
    typescript \
    @anthropic-ai/claude-code \
    @openai/codex \
    @google/gemini-cli \
    opencode-ai \
    @ampcode/cli \
    @github/copilot \
    @qwen-code/qwen-code \
    @charmland/crush \
    @kilocode/cli
npm_i --ignore-scripts @earendil-works/pi-coding-agent

# Agents with their own installers, placed system-wide.
if [ "$ARCH" = x86_64 ]; then
    # The installer always uses $HOME/.mu; give it a system-wide HOME.
    mkdir -p /opt/mu
    curl -fsSL https://raw.githubusercontent.com/Spandan7724/mu/main/scripts/install.sh | HOME=/opt/mu bash
    ln -sf /opt/mu/.mu/bin/mu /usr/local/bin/mu
    chmod -R a+rX /opt/mu
fi
mkdir -p /opt/cursor
curl -fsSL https://cursor.com/install | HOME=/opt/cursor bash
ln -sf /opt/cursor/.local/bin/cursor-agent /usr/local/bin/cursor-agent
chmod -R a+rX /opt/cursor
curl -fsSL https://github.com/block/goose/releases/download/stable/download_cli.sh \
    | CONFIGURE=false GOOSE_BIN_DIR=/usr/local/bin bash
PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install aider-chat
chmod -R a+rX /opt/pipx

# Agents are installed as root, so `dev` cannot self-update them: new versions come from
# rebuilding this image. Turn off update checks where the agent has a system-wide switch.
mkdir -p /etc/claude-code /etc/gemini-cli /etc/opencode /etc/skel/.config/amp
cat > /etc/claude-code/managed-settings.json <<'JSON'
{
  "env": {
    "DISABLE_AUTOUPDATER": "1"
  }
}
JSON
cat > /etc/gemini-cli/settings.json <<'JSON'
{
  "general": {
    "enableAutoUpdate": false,
    "enableAutoUpdateNotification": false
  }
}
JSON
echo '{ "autoupdate": false }' > /etc/opencode/opencode.json
echo '{ "amp.updates.mode": "disabled" }' > /etc/skel/.config/amp/settings.json
cat > /etc/profile.d/pocket.sh <<'SH'
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
SH

userdel -r ubuntu 2>/dev/null || true
useradd -m -u 1000 -s /bin/bash -G sudo dev
echo 'dev ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-dev
echo 'Defaults env_keep += "http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY NODE_USE_ENV_PROXY TERM COLORTERM"' > /etc/sudoers.d/91-pocket
chmod 0440 /etc/sudoers.d/90-dev /etc/sudoers.d/91-pocket
mkdir -p /work

apt-get clean
npm cache clean --force
rm -rf /var/lib/apt/lists/* /var/cache/apt/*.bin /root/.cache /root/.npm /tmp/*

for v in "git --version" "gh --version" "gcc --version" "clang --version" "cmake --version" \
    "python3 --version" "node --version" "bun --version" "tsc --version" "rustc --version" \
    "cargo --version" "go version" "java -version" "mvn --version" "ruby --version" \
    "php --version" "composer --version" "dotnet --version" "rg --version" \
    "claude --version" "codex --version" "gemini --version" "opencode --version" \
    "amp --version" "copilot --version" "qwen --version" "crush --version" \
    "kilo --version" "pi --version" "cursor-agent --version" "goose --version" \
    "aider --version"; do
    echo "== $v"; $v 2>&1 | head -1
done
if [ "$ARCH" = x86_64 ]; then mu --version; fi
