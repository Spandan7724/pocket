# pocket preset "claude": base + Claude Code.
set -eux
npm install -g --no-fund --no-audit @anthropic-ai/claude-code
rm -rf /root/.npm
# Installed system-wide as root, so `dev` cannot self-update; new versions come from
# rebuilding the preset. Managed settings reach every launch (sessions, exec, sudo).
mkdir -p /etc/claude-code
cat > /etc/claude-code/managed-settings.json <<'JSON'
{
  "env": {
    "DISABLE_AUTOUPDATER": "1"
  }
}
JSON
claude --version
