#!/usr/bin/env bash
set -euo pipefail

# near create-account ${SUBACCOUNT_ID}.${ACCOUNT_ID} --masterAccount ${ACCOUNT_ID} --initialBalance ${INITIAL_BALANCE}
# near create-account v1.lurec.near --masterAccount lurec.near --initialBalance 0.05 --networkId mainnet

# --- config ---
VERSION="v0.0.3"
SCRIPT_DIR=$(dirname "$(realpath "$0")")
CONTRACT_PATH="$SCRIPT_DIR/../build/${VERSION}.wasm"
# CONTRACT_ID="meteor-recovery.near"
CONTRACT_ID="v1.lurec.near"

# --- deploy ---
near contract deploy-as-global \
  use-file "$CONTRACT_PATH" \
  as-global-account-id "$CONTRACT_ID" \
  network-config mainnet \
  sign-with-keychain \
  send