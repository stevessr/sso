#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "Install wasm-pack 0.13.1 or newer first (https://rustwasm.github.io/wasm-pack/)." >&2
  exit 1
fi
rustup target add wasm32-unknown-unknown
wasm-pack build frontend-crypto --target web --out-dir ../web/wasm --release
echo "Browser crypto module built under web/wasm/"
