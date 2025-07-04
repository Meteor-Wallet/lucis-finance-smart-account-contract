#!/bin/sh

cargo near build non-reproducible-wasm

near transaction construct-transaction recovery-contract.near recovery-contract.near add-action deploy-global-contract \
    target/near/near_recovery.wasm as-global-account-id skip network-config mainnet sign-with-keychain send

near account create-account fund-myself solana-recovery.stevekok.near '1 NEAR' autogenerate-new-keypair save-to-keychain \
    sign-as stevekok.near network-config mainnet sign-with-keychain send

near transaction construct-transaction solana-recovery.stevekok.near solana-recovery.stevekok.near add-action \
    use-global-contract use-global-account-id recovery-contract.near without-init-call add-action function-call add_recovery_address \
    json-args '{"blockchain":"solana","recovery_address":"7PM7AQpxaERCDDBTi65fkWRQmu4BEEnJwYB7YWatuiQp","signature":"3F2sJwJaV8vxb94XmJB5yxJqwo9qy9Y5chH7GAbRM41pMkRJYVMciRTUouHJwnd54LCVdXon7pD968vxgkTXSHa3","nonce":1}' \
    prepaid-gas '200.0 Tgas' attached-deposit '1 yoctoNEAR' skip network-config mainnet sign-with-keychain send

