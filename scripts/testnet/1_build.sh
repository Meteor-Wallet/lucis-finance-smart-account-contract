#!/bin/sh

set -e
RUSTFLAGS='-C link-arg=-s' cargo build --target wasm32-unknown-unknown --release
cp target/wasm32-unknown-unknown/release/near_recovery.wasm scripts/testnet/build/near_recovery.wasm


# RUSTFLAGS='-C link-arg=-s' cargo near build reproducible-wasm --help
# cargo near build reproducible-wasm