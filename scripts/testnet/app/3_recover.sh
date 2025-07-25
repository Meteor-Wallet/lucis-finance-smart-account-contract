#!/bin/sh
export TEST_ACCOUNT_ID=rektdegen.testnet
export NEAR_ENV=testnet
export CONTRACT_ID="$(cat "$(dirname "$(realpath "$0")")/../neardev/dev-account")"

# Message:
# Recover NEAR account 2025-07-25_16-53-01_near_recovery.testnet to new public key ed25519:3DBS4ZmGmnPZ4Q15aDML46yfyUFFRKzCuh3NKi5EXErx with nonce 2
near call "$CONTRACT_ID" recover '{"new_public_key":"ed25519:3DBS4ZmGmnPZ4Q15aDML46yfyUFFRKzCuh3NKi5EXErx","old_public_key":"ed25519:HVqdPrjCz9vNPYEypQK4UJKBu7EyiJekyxWcMra1rEpZ","blockchain":"Ethereum","recovery_address":"0x950918fe5deb16c90a7071d5f3daff3f2e84e0df","signature":"0x98b72542a72d453c3dc4393eb9990cc194a4d05ff542d6bbabb8bf997f25d909267adc99d425d2117ba3163091447d6eea7286f06d784c1d39c8e26e88481f0d1c","nonce":2}' --accountId $CONTRACT_ID --gas 300000000000000
