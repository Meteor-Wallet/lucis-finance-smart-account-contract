#!/bin/sh

set -e
cargo near build reproducible-wasm
cp target/near/near_recovery.wasm scripts/mainnet/build/near_recovery.wasm