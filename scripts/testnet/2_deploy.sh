#!/bin/sh
export CONTRACT_ID="$(cat "$(dirname "$(realpath "$0")")/neardev/dev-account")"

# sh "$(dirname "$(realpath "$0")")/1_build.sh"
# echo "y" | near deploy $CONTRACT_ID "$(dirname "$(realpath "$0")")/build/near_recovery.wasm" 
near deploy $CONTRACT_ID "$(dirname "$(realpath "$0")")/build/near_recovery.wasm" 