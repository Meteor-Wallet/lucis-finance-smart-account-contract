#!/bin/sh
export TEST_ACCOUNT_ID=rektdegen.testnet
export NEAR_ENV=testnet
export CONTRACT_ID="$(cat "$(dirname "$(realpath "$0")")/neardev/dev-account")"

# Link NEAR account 2025-07-25_16-53-01_near_recovery.testnet to Ethereum address 0x950918fe5deb16c90a7071d5f3daff3f2e84e0df with nonce 1
near call "$CONTRACT_ID" add_recovery_address '{"blockchain":"Ethereum","recovery_address":"0x950918fe5deb16c90a7071d5f3daff3f2e84e0df","signature":"0x2fe84221315bba610b1db541443d0ecd9f7a2a2552eaf7a0f202dee8b6ace2eb79bba329697e4f4320fb5325564512e6de9992868fa64b811786c0b5f24bb5921c","nonce":1}' --accountId $CONTRACT_ID --gas 300000000000000
# near call "$CONTRACT_ID" migrate --accountId $CONTRACT_ID --gas 300000000000000
