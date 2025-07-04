#!/bin/sh
export TEST_ACCOUNT_ID=rektdegen.testnet
export NEAR_ENV=testnet
export CONTRACT_ID="$(cat "$(dirname "$(realpath "$0")")/../neardev/dev-account")"

near view "$CONTRACT_ID" get_recovery_addresses '{"blockchain":"Ethereum"}' 
