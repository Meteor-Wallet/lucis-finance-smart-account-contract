#!/bin/sh
export TEST_ACCOUNT_ID=rektdegen.testnet
export NEAR_ENV=testnet
export CONTRACT_ID="$(cat "$(dirname "$(realpath "$0")")/neardev/dev-account")"

near call "$CONTRACT_ID" get_greeting --accountId $CONTRACT_ID --gas 300000000000000
# near call "$CONTRACT_ID" migrate --accountId $CONTRACT_ID --gas 300000000000000
