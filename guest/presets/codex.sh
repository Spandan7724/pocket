# pocket preset "codex": base + OpenAI Codex CLI.
set -eux
npm install -g --no-fund --no-audit @openai/codex
rm -rf /root/.npm
codex --version
