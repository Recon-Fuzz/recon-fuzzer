#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# WASM atomics require nightly Rust and specific target features.
# SharedArrayBuffer enables wasm_safe_mutex::RwLock to use Atomics.wait
# instead of spinning — matching the main fuzzer's parking_lot::RwLock behavior.
#
# Required features:
#   +atomics          - Enables Atomics.wait/notify for blocking locks
#   +bulk-memory      - Required by atomics for memory.init/data.drop
#   +mutable-globals  - Required for __stack_pointer in multi-threaded WASM

export RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals -C link-arg=--shared-memory -C link-arg=--import-memory -C link-arg=--max-memory=1073741824 -C link-arg=--export=__wasm_init_tls -C link-arg=--export=__tls_size -C link-arg=--export=__tls_align -C link-arg=--export=__tls_base'

# Build once to pkg/ (canonical output for npm publish)
wasm-pack build . --target web --out-dir pkg -- \
    -Z build-std=panic_abort,std

# Patch package.json: name, version from main Cargo.toml, add snippets to files
MAIN_VERSION=$(grep '^version' ../Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
node -e "
const fs = require('fs');
const pkg = JSON.parse(fs.readFileSync('pkg/package.json', 'utf8'));
pkg.name = 'recon-fuzzer-wasm';
pkg.version = '${MAIN_VERSION}';
if (!pkg.files.includes('snippets')) pkg.files.push('snippets');
fs.writeFileSync('pkg/package.json', JSON.stringify(pkg, null, 2) + '\n');
"

echo "Build complete. Open web/index.html to test."
echo "Publishable package at: pkg/ (npm publish from there)"
echo "Note: Server must send COOP/COEP headers for SharedArrayBuffer support."
