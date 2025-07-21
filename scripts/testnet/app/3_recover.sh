#!/bin/sh
export TEST_ACCOUNT_ID=rektdegen.testnet
export NEAR_ENV=testnet
export CONTRACT_ID="$(cat "$(dirname "$(realpath "$0")")/../neardev/dev-account")"

# Message:
# Recover NEAR account 2025-07-01_13-51-12_near_recovery.testnet to new public key ed25519:3DBS4ZmGmnPZ4Q15aDML46yfyUFFRKzCuh3NKi5EXErx with nonce 11
near call "$CONTRACT_ID" recover '{"new_public_key":"ed25519:3DBS4ZmGmnPZ4Q15aDML46yfyUFFRKzCuh3NKi5EXErx","old_public_key":"ed25519:zaxVGDALKMCtYd4r4gNyz7M3uwCMMvboYTnRwmHMBXZ","blockchain":"Ethereum","recovery_address":"0x950918fe5deb16c90a7071d5f3daff3f2e84e0df","signature":"0x9df2c2f840a0e21d59d39ccbfab11325dc5dd88ab9646c6ea993af36c10f341f78659587718ad9769095e83fb945424dc4068fe358ad59b383d664c25c524b361c","nonce":11}' --accountId $CONTRACT_ID --gas 300000000000000
