use near_sdk::{testing_env, AccountId};

use crate::{blockchain_verifiers::BlockchainVerifier, contract_errors::ContractError, SmartAccountContract};

#[test]
fn test_verify_address() {
    let sol = crate::blockchain_verifiers::Sol;
    sol.verify_address("EU3KmyMdBhoNewP2t75a1pkMABcBjvPrmReCrenRyCW".to_string()).expect("");
    sol.verify_address("123".to_string())
        .expect_err(&ContractError::InvalidAddressFormat.message());
}

#[test]
fn test_add_recovery_address() {
    // 1. set up environment
    let mut builder = super::get_context();
    let caller = AccountId::try_from("bob.testnet".to_string()).unwrap();
    builder.current_account_id(caller.clone());
    let context = builder.build();
    testing_env!(context);
    let mut contract = SmartAccountContract::default();

    // 2. test signature verification success
    let solana_blockchain = "Solana".to_string();
    let solana_address = "7PM7AQpxaERCDDBTi65fkWRQmu4BEEnJwYB7YWatuiQp".to_string();
    let signature =
        "4JaZvLKmvYAW6VbuGAxWyXwVyU7LK12m9oK9J4Nvv575kNmSeeTkcbFEcm6v7gbxWPXvuyAEaW88Y1ZNfJYzUmsW"
            .to_string();
    contract.add_recovery_address(solana_blockchain.clone(), solana_address, signature, 1);

    // Optionally, assert that the mapping is set
    assert!(contract.recovery_address.get(&solana_blockchain).is_some());
}

#[test]
fn test_add_recovery_address_non_private_call() {
    // 1. set up environment
    let mut builder = super::get_context();
    let contract = AccountId::try_from("bob.testnet".to_string()).unwrap();
    builder.current_account_id(contract.clone());
    let caller = AccountId::try_from("alice.testnet".to_string()).unwrap();
    builder.signer_account_id(caller.clone());
    builder.predecessor_account_id(caller.clone());
    let context = builder.build();
    testing_env!(context);
    let mut contract = SmartAccountContract::default();

    // 2. test signature verification success
    let solana_blockchain = "Solana".to_string();
    let solana_address = "7PM7AQpxaERCDDBTi65fkWRQmu4BEEnJwYB7YWatuiQp".to_string();
    let signature =
        "4JaZvLKmvYAW6VbuGAxWyXwVyU7LK12m9oK9J4Nvv575kNmSeeTkcbFEcm6v7gbxWPXvuyAEaW88Y1ZNfJYzUmsW"
            .to_string();
    contract.add_recovery_address(solana_blockchain.clone(), solana_address, signature, 1);

    // Optionally, assert that the mapping is set
    assert!(contract.recovery_address.get(&solana_blockchain).is_some());
}

#[test]
#[should_panic(expected = "E005: invalid signature format")]
fn test_add_recovery_address_invalid_signature() {
    // 1. set up environment
    let mut builder = super::get_context();
    let caller = AccountId::try_from("bob.testnet".to_string()).unwrap();
    builder.current_account_id(caller.clone());
    let context = builder.build();
    testing_env!(context);
    let mut contract = SmartAccountContract::default();

    // 2. test signature verification failure
    let solana_blockchain = "Solana".to_string();
    let solana_address = "7PM7AQpxaERCDDBTi65fkWRQmu4BEEnJwYB7YWatuiQp".to_string();
    // The signature was signed with address 0x86e25e65ae0e54e6bb3c5a3c321710cc56978e8e, original message: Link NEAR account bob.testnet to Ethereum address 0x950918fe5deb16c90a7071d5f3daff3f2e84e0df with nonce 1
    let signature = "hello-world".to_string();
    contract.add_recovery_address(solana_blockchain.clone(), solana_address, signature, 1);
}

#[test]
fn test_recover_success() {
    // 1. set up environment
    let mut builder = super::get_context();
    let caller = AccountId::try_from("bob.testnet".to_string()).unwrap();
    builder.current_account_id(caller.clone());
    let context = builder.build();
    testing_env!(context);
    let mut contract = SmartAccountContract::default();

    // 2. add recovery address
    let solana_blockchain = "Solana".to_string();
    let solana_address = "7PM7AQpxaERCDDBTi65fkWRQmu4BEEnJwYB7YWatuiQp".to_string();
    let signature =
        "4JaZvLKmvYAW6VbuGAxWyXwVyU7LK12m9oK9J4Nvv575kNmSeeTkcbFEcm6v7gbxWPXvuyAEaW88Y1ZNfJYzUmsW"
            .to_string();
    contract.add_recovery_address(
        solana_blockchain.clone(),
        solana_address.clone(),
        signature,
        1,
    );

    // 3. recover with a new public key
    let new_public_key = "ed25519:C2CYqegHwc17kKP16qgzHcoZuREvudc9tSZ663fgV1BJ".to_string();
    let signature2 =
        "JrafPF1V9w6XzpWJk3u4D6N5BXNSgREcLLZudcPP3Hk7Wf8iwTyxDJKUV59GM3gfhVBw9TTyvhFiSBpeK484RT4"
            .to_string();
    contract.recover(
        new_public_key,
        solana_blockchain.clone(),
        solana_address.clone(),
        signature2,
        2,
    );
}
