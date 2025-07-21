#!/bin/sh
export TEST_ACCOUNT_ID=rektdegen.testnet
export NEAR_ENV=testnet
export CONTRACT_ID="$(cat "$(dirname "$(realpath "$0")")/../neardev/dev-account")"

# Message:
# Recover NEAR account 2025-07-01_13-51-12_near_recovery.testnet to new public key ed25519:3DBS4ZmGmnPZ4Q15aDML46yfyUFFRKzCuh3NKi5EXErx with nonce 2

near view "$CONTRACT_ID" get_message_to_add_recovery_address '{"blockchain":"Solana","recovery_address":"EU3KmyMdBhoNewP2t75a1pkMABcBjvPrmReCrenRyCW","signature":"0xffef16ada34fc0b214c32af13c02d75955808aa051d84b4c1ff71d44d583781e4afe63d38c3ad407d459992d21ce69316f81b509367a3dc75ba267efd58c47cc1c"}' 