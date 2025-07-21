#!/usr/bin/env bash
set -euo pipefail

# --- config ---
VERSION="v0.0.2"
SCRIPT_DIR=$(dirname "$(realpath "$0")")
CONTRACT_PATH="$SCRIPT_DIR/../build/${VERSION}.wasm"
CONTRACT_ID="meteor-recovery.near"

# --- deploy ---
near contract deploy-as-global \
  use-file "$CONTRACT_PATH" \
  as-global-account-id "$CONTRACT_ID" \
  network-config mainnet \
  sign-with-keychain \
  send