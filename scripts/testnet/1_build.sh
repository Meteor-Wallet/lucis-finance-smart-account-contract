#!/bin/sh

set -e
cargo near build non-reproducible-wasm
cp target/near/near_recovery.wasm scripts/testnet/build/near_recovery.wasm