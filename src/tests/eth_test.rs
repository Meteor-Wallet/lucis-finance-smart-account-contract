use near_sdk::{testing_env, AccountId};

use crate::SmartAccountContract;

#[test]
fn test_add_recovery_address() {
    // 1. set up environment
    let mut builder = super::get_context();
    let caller = AccountId::try_from("rektdegen.testnet".to_string()).unwrap();
    builder.current_account_id(caller.clone());
    let context = builder.build();
    testing_env!(context);
    let mut contract = SmartAccountContract::default();

    // 2. test signature verification success
    let eth_blockchain = "Ethereum".to_string();
    let eth_address = "0x950918fe5deb16c90a7071d5f3daff3f2e84e0df".to_string();
    let signature = "0xfce0288ef179953be8cf0d1eb10b2c8f008c591f89deb3425348e6f520cee12e4392c85ee9e81973af97999b84e88886fe12969c39bd663a2cf20725b8deb2a61c".to_string();
    contract.add_recovery_address(eth_blockchain.clone(), eth_address, signature, 1);

    // Optionally, assert that the mapping is set
    assert!(contract.recovery_address.get(&eth_blockchain).is_some());
}

#[test]
fn test_add_recovery_address_non_private_call() {
    // 1. set up environment
    let mut builder = super::get_context();
    let contract = AccountId::try_from("rektdegen.testnet".to_string()).unwrap();
    builder.current_account_id(contract.clone());
    let caller = AccountId::try_from("notrektdegen.testnet".to_string()).unwrap();
    builder.signer_account_id(caller.clone());
    builder.predecessor_account_id(caller.clone());
    let context = builder.build();
    testing_env!(context);
    let mut contract = SmartAccountContract::default();

    // 2. test signature verification success
    let eth_blockchain = "Ethereum".to_string();
    let eth_address = "0x950918fe5deb16c90a7071d5f3daff3f2e84e0df".to_string();
    let signature = "0xfce0288ef179953be8cf0d1eb10b2c8f008c591f89deb3425348e6f520cee12e4392c85ee9e81973af97999b84e88886fe12969c39bd663a2cf20725b8deb2a61c".to_string();
    contract.add_recovery_address(eth_blockchain.clone(), eth_address, signature, 1);

    // Optionally, assert that the mapping is set
    assert!(contract.recovery_address.get(&eth_blockchain).is_some());
}

#[test]
#[should_panic(expected = "E004: signature verification failed")]
fn test_add_recovery_address_invalid_signature() {
    // 1. set up environment
    let mut builder = super::get_context();
    let caller = AccountId::try_from("rektdegen.testnet".to_string()).unwrap();
    builder.current_account_id(caller.clone());
    let context = builder.build();
    testing_env!(context);
    let mut contract = SmartAccountContract::default();

    // 2. test signature verification failure
    let eth_blockchain = "Ethereum".to_string();
    let eth_address = "0x950918fe5deb16c90a7071d5f3daff3f2e84e0df".to_string();
    // The signature was signed with address 0x86e25e65ae0e54e6bb3c5a3c321710cc56978e8e, original message: Link NEAR account rektdegen.testnet to Ethereum address 0x950918fe5deb16c90a7071d5f3daff3f2e84e0df with nonce 1
    let signature = "0xbf26cea246af7fce1984b1bcf50d5f09948b09fde3eadd77c2895bfa6c1b9d007e825ba033a028ccda816c4e5793f5a38317872aec858fafe652e942c33ae85c1c".to_string();
    contract.add_recovery_address(eth_blockchain.clone(), eth_address, signature, 1);
}

#[test]
fn test_recover_success() {
    // 1. set up environment
    let mut builder = super::get_context();
    let caller = AccountId::try_from("rektdegen.testnet".to_string()).unwrap();
    builder.current_account_id(caller.clone());
    let context = builder.build();
    testing_env!(context);
    let mut contract = SmartAccountContract::default();

    // 2. add recovery address
    let eth_blockchain = "Ethereum".to_string();
    let eth_address = "0x950918fe5deb16c90a7071d5f3daff3f2e84e0df".to_string();
    let signature = "0xfce0288ef179953be8cf0d1eb10b2c8f008c591f89deb3425348e6f520cee12e4392c85ee9e81973af97999b84e88886fe12969c39bd663a2cf20725b8deb2a61c".to_string();
    contract.add_recovery_address(eth_blockchain.clone(), eth_address.clone(), signature, 1);

    // 3. recover with a new public key
    let new_public_key = "ed25519:3DBS4ZmGmnPZ4Q15aDML46yfyUFFRKzCuh3NKi5EXErx".to_string();
    let signature2 = "0x004f7b6bbc107982a11364082964db2c4d69b9b82dc571eb2e9a5c4640e7767126004dc42eca0158a163f4ac96afaad2fefba1289c13cc702795af1b22125d831c".to_string();
    contract.recover(
        new_public_key,
        eth_blockchain.clone(),
        eth_address.clone(),
        signature2,
        2,
    );
}
