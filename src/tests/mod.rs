use near_sdk::test_utils::VMContextBuilder;
use near_sdk::{testing_env, AccountId};
mod eth_test;
mod solana_test;

use crate::SmartAccountContract;

fn get_context() -> VMContextBuilder {
    let mut builder = VMContextBuilder::new();
    let account_id = AccountId::try_from("alice.near".to_string()).unwrap();
    builder.predecessor_account_id(account_id);
    builder
}

#[test]
#[should_panic(expected = "E001: unsupported blockchain")]
fn test_unsupported_blockchain() {
    // 1. set up environment
    let mut builder = get_context();
    let caller = AccountId::try_from("rektdegen.testnet".to_string()).unwrap();
    builder.current_account_id(caller.clone());
    let context = builder.build();
    testing_env!(context);
    let mut contract = SmartAccountContract::default();

    // 2. test signature verification success
    let random_blockchain = "random_chain".to_string();
    let random_address = "0x950918fe5deb16c90a7071d5f3daff3f2e84e0df".to_string();
    let random_signature = "0xfce0288ef179953be8cf0d1eb10b2c8f008c591f89deb3425348e6f520cee12e4392c85ee9e81973af97999b84e88886fe12969c39bd663a2cf20725b8deb2a61c".to_string();
    contract.add_recovery_address(
        random_blockchain.clone(),
        random_address,
        random_signature,
        1,
    );
}
