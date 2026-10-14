# pocket preset "claude": base + Claude Code.
set -eux
npm install -g --no-fund --no-audit @anthropic-ai/claude-code
rm -rf /root/.npm
claude --version
