pub mod blockchain_verifiers;
pub mod contract_errors;
#[cfg(test)]
mod tests;
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
    pub fn get_message_to_add_recovery_address(
        &self,
        blockchain: Blockchain,
        recovery_address: String,
    ) -> String {
        format!(
            "Link NEAR account {} to {} address {} with nonce {}",
            env::current_account_id(),
            blockchain,
            recovery_address,
            self.nonce + 1 // The next nonce to be used
        )
    }

    pub fn get_message_to_recover(&self, new_public_key: String) -> String {
        format!(
            "Recover NEAR account {} to new public key {} with nonce {}",
            env::current_account_id(),
            new_public_key,
            self.nonce + 1 // The next nonce to be used
        )
    }

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
            .insert(blockchain.clone(), current_recovery_addresses);

        // Log event
        env::log_str(&format!(
            "Linked NEAR account {} to {} address {}",
            &account_id, &blockchain, &recovery_address
        ));
    }

    pub fn recover(
        &mut self,
        new_public_key: String,
        blockchain: Blockchain,
        recovery_address: String,
        signature: String,
        nonce: u64,
        old_public_key: Option<String>,
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
        let new_parsed_public_key = PublicKey::from_str(&new_public_key)
            .unwrap_or_else(|_| panic!("{}", ContractError::InvalidNewPublicKeyFormat.message()));
        // Step 4.1: Verify the old public key if provided
        if let Some(ref old_public_key) = old_public_key {
            // If an old public key is provided, verify its format
            let old_parsed_public_key = PublicKey::from_str(old_public_key)
                .unwrap_or_else(|_| panic!("{}", ContractError::InvalidOldPublicKeyFormat.message()));

            // Ensure the old public key is not the same as the new one
            assert!(
                old_parsed_public_key != new_parsed_public_key,
                "{}",
                ContractError::SimilarPublicKey.message()
            );
        } 


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
            "Account {} recovery: adding new key {}",
            env::current_account_id(),
            new_public_key
        ));

        // Step 7: Schedule the actions: add the new full access key and delete the old key if provided
        let mut promise = Promise::new(env::current_account_id())
            .add_full_access_key(new_parsed_public_key);
        if let Some(ref old_public_key) = old_public_key {
            let old_parsed_public_key = PublicKey::from_str(old_public_key)
                .unwrap_or_else(|_| panic!("{}", ContractError::InvalidOldPublicKeyFormat.message()));
            promise = promise.then(Promise::new(env::current_account_id()).delete_key(old_parsed_public_key));
        }
        promise
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
                expected_nonce, input_nonce
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
