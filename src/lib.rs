pub mod blockchain_verifiers;
pub mod contract_errors;
pub mod types;

use crate::blockchain_verifiers::get_verifier;
use crate::contract_errors::ContractError;
use crate::types::Blockchain;
use near_sdk::store::LookupMap;
use near_sdk::{env, log, near, Promise, PublicKey};
use std::str::FromStr;

#[near(contract_state)]
pub struct SmartAccountContract {
    /// Reverse mapping from Ethereum address (20 bytes) to NEAR account.
    recovery_address: LookupMap<Blockchain, Vec<String>>,
    nonce: u64, // Nonce for the contract, used to prevent replay attacks
}

impl Default for SmartAccountContract {
    fn default() -> Self {
        Self {
            recovery_address: LookupMap::new(b"eth_to_account".to_vec()),
            nonce: 0, // Initialize nonce to 0
        }
    }
}

#[near]
impl SmartAccountContract {

    #[payable]
    #[private]
    pub fn add_recovery_address(
        &mut self,
        blockchain: Blockchain,
        recovery_address: String,
        signature: String,
        nonce: u64,
    ) {
        // Step 1: Verify the nonce and blockchain support
        self.verify_nonce(nonce)
            .expect("Invalid nonce: expected one greater than the current nonce");

        // Step 2: Get the blockchain verifier and validate the address format
        let blockchain_verifier =
            get_verifier(blockchain.as_str()).unwrap_or_else(|e| panic!("{}", e.message()));
        blockchain_verifier
            .verify_address(recovery_address.clone())
            .unwrap_or_else(|e| panic!("{}", e.message()));

        // Step 3: Construct the expected message for signature verification
        let message = format!(
            "Link NEAR account {} to {} address {} with nonce {}",
            env::current_account_id(),
            blockchain,
            recovery_address,
            nonce
        );

        // Stepxx 4: Verify the signature
        let caller = env::current_account_id();
        let account_id = caller.clone();
        blockchain_verifier
            .verify_signature(recovery_address.clone(), message, signature)
            .unwrap_or_else(|e| panic!("{}", e.message()));

        // Step 4: Check if the Ethereum address is already linked to a NEAR account
        let mut current_recovery_addresses = self
            .recovery_address
            .get(&blockchain)
            .cloned()
            .unwrap_or_default();
        assert!(
            !current_recovery_addresses.contains(&recovery_address),
            "{}",
            ContractError::LinkedAddressAlreadyExists.message()
        );

        // Step 5: Add the new address to the mapping
        current_recovery_addresses.push(recovery_address.clone());
        self.recovery_address
            .insert(blockchain, current_recovery_addresses);

        // Log event
        env::log_str(&format!(
            "Linked NEAR account {} to Ethereum address {}",
            account_id, recovery_address
        ));
    }

    pub fn recover(
        &mut self,
        new_public_key: String,
        blockchain: Blockchain,
        recovery_address: String,
        signature: String,
        nonce: u64,
    ) -> Promise {
        // Step 1: Verify the nonce and blockchain support
        self.verify_nonce(nonce)
            .expect("Invalid nonce: expected one greater than the current nonce");

        // Step 2: Get the blockchain verifier
        let blockchain_verifier =
            get_verifier(blockchain.as_str()).unwrap_or_else(|e| panic!("{}", e.message()));

        // Step 3: Check if the recovery address is registered for the given blockchain
        assert!(
            self.is_address_registered_for_recovery(blockchain.clone(), recovery_address.clone(),),
            "{}",
            ContractError::UnauthorizedRecoveryAddress.message()
        );

        // Step 4: Verify the and parse the new public key
        let parsed_public_key = PublicKey::from_str(&new_public_key)
            .unwrap_or_else(|_| panic!("{}", ContractError::InvalidPublicKeyFormat.message()));

        // Step 5: Build the message to verify the signature
        let message = format!(
            "Recover NEAR account {} to new public key {} with nonce {}",
            env::current_account_id(),
            new_public_key,
            nonce
        );
        log!("message = {}", message);

        // Step 6: Verify the signature
        blockchain_verifier
            .verify_signature(recovery_address.clone(), message.clone(), signature.clone())
            .unwrap_or_else(|e| panic!("{}", e.message()));

        env::log_str(&format!(
            "Account {} recovery: adding new key {} and removing old key",
            env::current_account_id(),
            new_public_key
        ));

        // Step 7: Schedule the actions: add the new full access key and delete the old key
        Promise::new(env::current_account_id()).add_full_access_key(parsed_public_key)
    }

    pub fn get_recovery_addresses(&self, blockchain: Blockchain) -> Vec<String> {
        self.recovery_address
            .get(&blockchain)
            .cloned()
            .unwrap_or_default()
    }

    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }
}

impl SmartAccountContract {
    fn verify_nonce(&mut self, input_nonce: u64) -> Result<(), String> {
        // Assert input nonce is one greater than the stored nonce or throw an error
        let expected_nonce = self.nonce + 1;
        if input_nonce == expected_nonce {
            self.nonce = input_nonce;
            Ok(())
        } else {
            Err(format!(
                "Invalid nonce: expected {}, got {}",
                expected_nonce,
                input_nonce
            ))
        }
    }

    fn is_address_registered_for_recovery(
        &self,
        blockchain: Blockchain,
        recovery_address: String,
    ) -> bool {
        // Check if the address is already linked to the NEAR account
        let linked_accounts = self
            .recovery_address
            .get(&blockchain)
            .cloned()
            .unwrap_or_default();

        return linked_accounts.contains(&recovery_address);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, AccountId};

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
        let eth_blockchain = "random_chain".to_string();
        let eth_address = "0x950918fe5deb16c90a7071d5f3daff3f2e84e0df".to_string();
        let signature = "0xfce0288ef179953be8cf0d1eb10b2c8f008c591f89deb3425348e6f520cee12e4392c85ee9e81973af97999b84e88886fe12969c39bd663a2cf20725b8deb2a61c".to_string();
        contract.add_recovery_address(eth_blockchain.clone(), eth_address, signature, 1);
    }

    #[test]
    fn test_add_recovery_address() {
        // 1. set up environment
        let mut builder = get_context();
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
        let mut builder = get_context();
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
        let mut builder = get_context();
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
        let mut builder = get_context();
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
}
