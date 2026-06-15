pub mod contract_errors;
pub mod internal;
pub mod transaction;
pub mod types;
pub mod upgrade;
pub mod verifier;

use crate::types::{BlockchainAddress, BlockchainId, CrossChainAccessKey, Nonce};
use borsh::{BorshDeserialize, BorshSerialize};
use contract_errors::ContractError;
use near_sdk::json_types::Base64VecU8;
use near_sdk::serde::{Deserialize, Deserializer, Serialize, Serializer};
use near_sdk::serde_json::{self, json, Value};
use near_sdk::{env, near, store::LookupMap, AccountId, Promise, PublicKey};
use near_sdk::{ext_contract, BorshStorageKey, CryptoHash, Gas, NearToken, PromiseResult};
use transaction::{Action, AddKeyPermission, Transaction};

const VERIFY_SIGNATURE_GAS: Gas = Gas::from_tgas(10);

#[derive(BorshSerialize, BorshDeserialize, BorshStorageKey)]
pub enum StorageKey {
    CrossChainAccessKeys,
}

#[near(contract_state)]
pub struct SmartAccountContract {
    factory_contract_id: AccountId,
    current_code_hash: CryptoHash,
    cross_chain_access_keys: LookupMap<(BlockchainId, BlockchainAddress), CrossChainAccessKey>,
}

impl Default for SmartAccountContract {
    fn default() -> Self {
        panic!("{}", ContractError::ContractUninitialized.message());
    }
}

#[near]
impl SmartAccountContract {
    #[init]
    #[private]
    pub fn init(
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        code_hash: CryptoHash,
    ) -> Self {
        let mut contract = Self {
            factory_contract_id: env::predecessor_account_id(),
            current_code_hash: code_hash,
            cross_chain_access_keys: LookupMap::new(StorageKey::CrossChainAccessKeys),
        };

        let initial_nonce = contract.internal_generate_nonce();

        contract.cross_chain_access_keys.insert(
            (blockchain_id.clone(), blockchain_address.clone()),
            CrossChainAccessKey {
                blockchain: blockchain_id,
                address: blockchain_address,
                nonce: initial_nonce,
                // Purposely allow underflow
                // If the initial nonce is 0, the last usable nonce will be u64::MAX
                last_usable_nonce: initial_nonce.wrapping_sub(1),
            },
        );

        contract
    }
}

#[ext_contract(ext_self)]
pub trait ExtSelf {
    fn sign_transaction_execution(&mut self, transaction: Transaction) -> Promise;
}

#[near]
impl SmartAccountContract {
    pub fn message_for_sign_transaction(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        transaction: Transaction,
    ) -> String {
        let cross_chain_access_key = self
            .cross_chain_access_keys
            .get(&(blockchain_id.clone(), blockchain_address.clone()))
            .expect(ContractError::UnauthorizedCrossChainAccessKey.message());

        self.internal_validate_transaction(&transaction);

        serde_json::to_string(&json!({
            "blockchain_id": blockchain_id,
            "blockchain_address": blockchain_address,
            "transaction": transaction,
            "nonce": cross_chain_access_key.nonce.wrapping_add(1),
        }))
        .unwrap()
    }

    pub fn message_for_add_wallet(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        new_wallet_blockchain_id: BlockchainId,
        new_wallet_blockchain_address: BlockchainAddress,
    ) -> String {
        let cross_chain_access_key = self
            .cross_chain_access_keys
            .get(&(blockchain_id.clone(), blockchain_address.clone()))
            .expect(ContractError::UnauthorizedCrossChainAccessKey.message());

        assert!(
            self.cross_chain_access_keys
                .get(&(
                    new_wallet_blockchain_id.clone(),
                    new_wallet_blockchain_address.clone()
                ))
                .is_none(),
            "{}",
            ContractError::WalletAlreadyRegistered.message()
        );

        serde_json::to_string(&json!({
            "blockchain_id": blockchain_id,
            "blockchain_address": blockchain_address,
            "new_wallet_blockchain_id": new_wallet_blockchain_id,
            "new_wallet_blockchain_address": new_wallet_blockchain_address,
            "nonce": cross_chain_access_key.nonce.wrapping_add(1),
        }))
        .unwrap()
    }

    pub fn message_for_remove_wallet(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        wallet_blockchain_id_to_be_removed: BlockchainId,
        wallet_blockchain_address_to_be_removed: BlockchainAddress,
        force: Option<bool>,
    ) -> String {
        let cross_chain_access_key = self
            .cross_chain_access_keys
            .get(&(blockchain_id.clone(), blockchain_address.clone()))
            .expect(ContractError::UnauthorizedCrossChainAccessKey.message());

        self.cross_chain_access_keys
            .get(&(
                wallet_blockchain_id_to_be_removed.clone(),
                wallet_blockchain_address_to_be_removed.clone(),
            ))
            .expect(ContractError::UnauthorizedCrossChainAccessKey.message());

        serde_json::to_string(&json!({
            "blockchain_id": blockchain_id,
            "blockchain_address": blockchain_address,
            "wallet_blockchain_id_to_be_removed": wallet_blockchain_id_to_be_removed,
            "wallet_blockchain_address_to_be_removed": wallet_blockchain_address_to_be_removed,
            "force": force.unwrap_or(false),
            "nonce": cross_chain_access_key.nonce.wrapping_add(1),
        }))
        .unwrap()
    }

    pub fn blind_message_for_sign_transaction(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        transaction: Transaction,
    ) -> String {
        let message = self.message_for_sign_transaction(
            blockchain_id.clone(),
            blockchain_address.clone(),
            transaction,
        );

        let sha256_hash = env::sha256(message.as_bytes());

        bs58::encode(sha256_hash).into_string()
    }

    pub fn blind_message_for_add_wallet(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        new_wallet_blockchain_id: BlockchainId,
        new_wallet_blockchain_address: BlockchainAddress,
    ) -> String {
        let message = self.message_for_add_wallet(
            blockchain_id.clone(),
            blockchain_address.clone(),
            new_wallet_blockchain_id,
            new_wallet_blockchain_address,
        );

        let sha256_hash = env::sha256(message.as_bytes());

        bs58::encode(sha256_hash).into_string()
    }

    pub fn blind_message_for_remove_wallet(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        wallet_blockchain_id_to_be_removed: BlockchainId,
        wallet_blockchain_address_to_be_removed: BlockchainAddress,
        force: Option<bool>,
    ) -> String {
        let message = self.message_for_remove_wallet(
            blockchain_id.clone(),
            blockchain_address.clone(),
            wallet_blockchain_id_to_be_removed,
            wallet_blockchain_address_to_be_removed,
            force,
        );

        let sha256_hash = env::sha256(message.as_bytes());

        bs58::encode(sha256_hash).into_string()
    }

    pub fn sign_transaction(
        &mut self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        transaction: Transaction,
        signature: String,
        blind_message: Option<bool>,
    ) -> Promise {
        let blind_message = blind_message.unwrap_or(false);

        let message = if blind_message {
            self.blind_message_for_sign_transaction(
                blockchain_id.clone(),
                blockchain_address.clone(),
                transaction.clone(),
            )
        } else {
            self.message_for_sign_transaction(
                blockchain_id.clone(),
                blockchain_address.clone(),
                transaction.clone(),
            )
        };

        self.internal_verify_signature(
            blockchain_id.clone(),
            blockchain_address.clone(),
            message,
            signature,
        );

        self.internal_update_nonce(blockchain_id, blockchain_address);

        self.internal_generate_promise(transaction)
    }

    pub fn add_wallet(
        &mut self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        new_wallet_blockchain_id: BlockchainId,
        new_wallet_blockchain_address: BlockchainAddress,
        signature: String,
        blind_message: Option<bool>,
    ) {
        let blind_message = blind_message.unwrap_or(false);

        let message = if blind_message {
            self.blind_message_for_add_wallet(
                blockchain_id.clone(),
                blockchain_address.clone(),
                new_wallet_blockchain_id.clone(),
                new_wallet_blockchain_address.clone(),
            )
        } else {
            self.message_for_add_wallet(
                blockchain_id.clone(),
                blockchain_address.clone(),
                new_wallet_blockchain_id.clone(),
                new_wallet_blockchain_address.clone(),
            )
        };

        assert!(
            self.cross_chain_access_keys
                .get(&(
                    new_wallet_blockchain_id.clone(),
                    new_wallet_blockchain_address.clone()
                ))
                .is_none(),
            "{}",
            ContractError::WalletAlreadyRegistered.message()
        );

        self.internal_verify_signature(
            blockchain_id.clone(),
            blockchain_address.clone(),
            message,
            signature,
        );

        self.internal_update_nonce(blockchain_id, blockchain_address);

        let cross_chain_access_key = CrossChainAccessKey {
            blockchain: new_wallet_blockchain_id.clone(),
            address: new_wallet_blockchain_address.clone(),
            nonce: 0,
            last_usable_nonce: u64::MAX,
        };

        self.cross_chain_access_keys.insert(
            (
                cross_chain_access_key.blockchain.clone(),
                cross_chain_access_key.address.clone(),
            ),
            cross_chain_access_key,
        );

        Promise::new(self.factory_contract_id.clone()).function_call(
            "add_wallet".to_string(),
            serde_json::to_vec(&json!({
                "blockchain_id": new_wallet_blockchain_id,
                "blockchain_address": new_wallet_blockchain_address,
            }))
            .unwrap(),
            NearToken::from_near(0),
            Gas::from_tgas(5),
        );
    }

    pub fn remove_wallet(
        &mut self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        wallet_blockchain_id_to_be_removed: BlockchainId,
        wallet_blockchain_address_to_be_removed: BlockchainAddress,
        force: Option<bool>,
        signature: String,
        blind_message: Option<bool>,
    ) {
        let blind_message = blind_message.unwrap_or(false);

        let message = if blind_message {
            self.blind_message_for_remove_wallet(
                blockchain_id.clone(),
                blockchain_address.clone(),
                wallet_blockchain_id_to_be_removed.clone(),
                wallet_blockchain_address_to_be_removed.clone(),
                force,
            )
        } else {
            self.message_for_remove_wallet(
                blockchain_id.clone(),
                blockchain_address.clone(),
                wallet_blockchain_id_to_be_removed.clone(),
                wallet_blockchain_address_to_be_removed.clone(),
                force,
            )
        };

        self.internal_verify_signature(
            blockchain_id.clone(),
            blockchain_address.clone(),
            message,
            signature,
        );

        self.internal_update_nonce(blockchain_id.clone(), blockchain_address.clone());

        if !force.unwrap_or(false) {
            assert!(
                blockchain_id != wallet_blockchain_id_to_be_removed
                    || blockchain_address != wallet_blockchain_address_to_be_removed,
                "{}",
                ContractError::CanNotRevokeSelf.message()
            );
        }

        self.cross_chain_access_keys.remove(&(
            wallet_blockchain_id_to_be_removed.clone(),
            wallet_blockchain_address_to_be_removed.clone(),
        ));

        Promise::new(self.factory_contract_id.clone()).function_call(
            "remove_wallet".to_string(),
            serde_json::to_vec(&json!({
                "blockchain_id": wallet_blockchain_id_to_be_removed,
                "blockchain_address": wallet_blockchain_address_to_be_removed,
            }))
            .unwrap(),
            NearToken::from_near(0),
            Gas::from_tgas(5),
        );
    }
}
