#!/bin/sh
export TEST_ACCOUNT_ID=rektdegen.testnet
export NEAR_ENV=testnet
export CONTRACT_ID="$(cat "$(dirname "$(realpath "$0")")/../neardev/dev-account")"

# ETH
# near call "$CONTRACT_ID" add_recovery_address '{"blockchain":"Ethereum","recovery_address":"0x950918fe5deb16c90a7071d5f3daff3f2e84e0df","signature":"0x5c023de5087058663e81a96d178767a16835c20f5ccd0e45272f92f126ed007e5df222919a9110813d4878709bc045552c9bd7e3895de00f975338088883bb7f1b","nonce":2}' --accountId $CONTRACT_ID --gas 300000000000000
# Sol
near call "$CONTRACT_ID" add_recovery_address '{"blockchain":"Solana","recovery_address":"EU3KmyMdBhoNewP2t75a1pkMABcBjvPrmReCrenRyCW","signature":"5X6aqvP2BRiYKzRKev626cSWZsX43VTzYPsL4GfNCRW6j1s93fvM53AmSP7Gtj4STNHii41vV8ndC3ud8yfk1kJz","nonce":7}' --accountId $CONTRACT_ID --gas 300000000000000
