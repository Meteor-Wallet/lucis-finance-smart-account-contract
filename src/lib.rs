pub mod blockchain_verifiers;
pub mod contract_errors;
#[cfg(test)]
mod tests;
pub mod types;

use crate::blockchain_verifiers::get_verifier;
use crate::contract_errors::ContractError;
use crate::types::{BlockchainAddress, BlockchainId, Nonce, RecoveryKey};
use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::{BorshStorageKey, Gas, NearToken};
use near_sdk::{env, log, near, store::LookupMap, AccountId, Promise, PublicKey};
use std::str::FromStr;

#[derive(BorshSerialize, BorshDeserialize, BorshStorageKey)]
pub enum StorageKey {
    RecoveryKeys,
}

#[near(contract_state)]
pub struct SmartAccountContract {
    factory: AccountId,
    recovery_keys: LookupMap<(BlockchainId, BlockchainAddress), RecoveryKey>,
}

impl SmartAccountContract {
    pub fn internal_generate_nonce(&self) -> Nonce {
        let seed = env::random_seed();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&seed[..8]);
        u64::from_le_bytes(bytes)
    }
}

#[near]
impl SmartAccountContract {
    #[init]
    pub fn new(blockchain_id: BlockchainId, blockchain_address: BlockchainAddress) -> Self {
        let mut contract = Self {
            factory: env::predecessor_account_id(),
            recovery_keys: LookupMap::new(StorageKey::RecoveryKeys),
        };

        contract.recovery_keys.insert(
            (blockchain_id.clone(), blockchain_address.clone()),
            RecoveryKey {
                blockchain: blockchain_id,
                address: blockchain_address,
                nonce: contract.internal_generate_nonce(),
            },
        );

        contract
    }
}

#[near]
impl SmartAccountContract {
    pub fn get_message_for_function_call(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        contract_id: AccountId,
        function_name: String,
        args: String,
        attached_deposit: NearToken,
        gas: Gas,
    ) -> String {
        assert!(
            contract_id != env::current_account_id(),
            "Cannot call a function on the smart account itself"
        );

        let recovery_key = self
            .recovery_keys
            .get(&(blockchain_id.clone(), blockchain_address.clone()))
            .expect("Recovery key not found");

        format!(
            "Call function {} on contract {} with args {} and attached deposit {} and {} TGas from NEAR account {} linked to {} address {} with nonce {}",
            function_name,  
            contract_id,
            args,
            attached_deposit.exact_amount_display(),
            gas.as_tgas(),
            env::current_account_id(),
            blockchain_id,
            blockchain_address,
            recovery_key.nonce
        )
    }

    pub fn get_message_for_access_key_with_allowance(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        public_key: String,
        contract_id: AccountId,
        function_names: String,
        allowance: NearToken,
    ) -> String {
        assert!(
            contract_id != env::current_account_id(),
            "Cannot grant access key to the smart account itself"
        );

        let recovery_key = self
            .recovery_keys
            .get(&(blockchain_id.clone(), blockchain_address.clone()))
            .expect("Recovery key not found");

        format!(
            "Grant access key {} to contract {} with function names {} and allowance {} from NEAR account {} linked to {} address {} with nonce {}",
            public_key,
            contract_id,
            function_names,
            allowance.exact_amount_display(),
            env::current_account_id(),
            blockchain_id,
            blockchain_address,
            recovery_key.nonce
        )
    }

    #[payable]
    #[private]
    pub fn add_recovery_address(
        &mut self,
        blockchain: BlockchainId,
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
        blockchain: BlockchainId,
        recovery_address: String,
        signature: String,
        nonce: u64,
        old_public_key: String,
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
        let old_parsed_public_key = PublicKey::from_str(&old_public_key)
            .unwrap_or_else(|_| panic!("{}", ContractError::InvalidOldPublicKeyFormat.message()));

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

        // Step 7: Schedule the actions: add the new full access key and delete the old key
        Promise::new(env::current_account_id())
            .add_full_access_key(new_parsed_public_key)
            .then(Promise::new(env::current_account_id()).delete_key(old_parsed_public_key))
    }

    pub fn get_recovery_addresses(&self, blockchain: BlockchainId) -> Vec<String> {
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
        blockchain: BlockchainId,
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
