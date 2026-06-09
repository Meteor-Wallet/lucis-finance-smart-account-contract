use borsh::{BorshDeserialize, BorshSerialize};
use contract_errors::*;
use near_sdk::json_types::{Base64VecU8, U64};
use near_sdk::serde_json::json;
use near_sdk::{env, near, store::LookupMap, AccountId, BorshStorageKey, CryptoHash};
use near_sdk::{Gas, NearToken, Promise};
use types::*;

mod contract_errors;
mod internal;
mod types;
mod verifier;

const SMART_CONTRACT_INIT_GAS: Gas = Gas::from_tgas(50);

#[derive(BorshSerialize, BorshDeserialize, BorshStorageKey)]
pub enum StorageKey {
    CodeHashUpgradeTarget,
    BrandingCounter,
    WalletToAccountId,
    AccountIdToWallet,
}

#[near(contract_state)]
pub struct FactoryContractV1 {
    pub owner_id: AccountId,
    pub latest_code_hash: CryptoHash,
    pub code_hash_upgrade_target: LookupMap<CryptoHash, CryptoHash>,
}

#[near(contract_state)]
pub struct FactoryContract {
    pub owner_id: AccountId,
    pub latest_code_hash: CryptoHash,
    pub code_hash_upgrade_target: LookupMap<CryptoHash, CryptoHash>,
    pub branding_counter: LookupMap<String, u64>,
    pub wallet_to_account_id: LookupMap<(BlockchainId, BlockchainAddress), Array<AccountId>>,
    pub account_id_to_wallet: LookupMap<AccountId, Array<(BlockchainId, BlockchainAddress)>>,
}

impl Default for FactoryContract {
    fn default() -> Self {
        panic!("{}", ContractError::ContractUninitialized.message());
    }
}

#[near]
impl FactoryContract {
    #[init]
    pub fn new(owner_id: AccountId, latest_code_hash: Base64VecU8) -> Self {
        let latest_code_hash: Vec<u8> = latest_code_hash.into();

        Self {
            owner_id,
            latest_code_hash: latest_code_hash
                .try_into()
                .expect(ContractError::InvalidCodeHashLength.message()),
            code_hash_upgrade_target: LookupMap::new(StorageKey::CodeHashUpgradeTarget),
            branding_counter: LookupMap::new(StorageKey::BrandingCounter),
            wallet_to_account_id: LookupMap::new(StorageKey::WalletToAccountId),
            account_id_to_wallet: LookupMap::new(StorageKey::AccountIdToWallet),
        }
    }

    #[init(ignore_state)]
    pub fn migrate() -> Self {
        let old_state: FactoryContractV1 = env::state_read()
            .expect("Failed to read state")
            .expect("State is empty");

        Self {
            owner_id: old_state.owner_id,
            latest_code_hash: old_state.latest_code_hash,
            code_hash_upgrade_target: old_state.code_hash_upgrade_target,
            branding_counter: LookupMap::new(StorageKey::BrandingCounter),
            wallet_to_account_id: LookupMap::new(StorageKey::WalletToAccountId),
            account_id_to_wallet: LookupMap::new(StorageKey::AccountIdToWallet),
        }
    }

    pub fn update_latest_code_hash(&mut self, new_code_hash: Base64VecU8) {
        let new_code_hash: Vec<u8> = new_code_hash.into();

        assert_eq!(
            env::predecessor_account_id(),
            self.owner_id,
            "{}",
            ContractError::MustBeOwner.message()
        );

        self.code_hash_upgrade_target.insert(
            self.latest_code_hash,
            new_code_hash
                .clone()
                .try_into()
                .expect(ContractError::InvalidCodeHashLength.message()),
        );

        self.latest_code_hash = new_code_hash
            .try_into()
            .expect(ContractError::InvalidCodeHashLength.message());
    }

    pub fn get_latest_code_hash(&self) -> CryptoHash {
        self.latest_code_hash
    }

    pub fn get_code_hash_upgrade_target(&self, code_hash: CryptoHash) -> Option<&CryptoHash> {
        self.code_hash_upgrade_target.get(&code_hash)
    }

    pub fn message_for_create_account(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
    ) -> String {
        let deadline = env::block_timestamp().checked_add(300_000_000_000).unwrap(); // 5 minutes from now

        self.internal_message_for_create_account(blockchain_id, blockchain_address, deadline)
    }

    pub fn preview_account_id(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
    ) -> AccountId {
        self.internal_generate_account_id(blockchain_id, blockchain_address)
    }

    #[payable]
    pub fn create_account(
        &mut self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        deadline: U64,
        signature: String,
    ) -> Promise {
        assert!(
            env::block_timestamp() <= deadline.0,
            "{}",
            ContractError::SignatureExpired.message()
        );

        let deposit = env::attached_deposit();

        assert!(
            deposit.as_millinear() >= 1,
            "{}",
            ContractError::InsufficientDeposit.message()
        );

        let message = self.internal_message_for_create_account(
            blockchain_id.clone(),
            blockchain_address.clone(),
            deadline.0,
        );

        self.internal_verify_signature(
            blockchain_id.clone(),
            blockchain_address.clone(),
            message,
            signature,
        );

        let account_id =
            self.internal_generate_account_id(blockchain_id.clone(), blockchain_address.clone());

        Promise::new(account_id)
            .create_account()
            .transfer(deposit)
            .use_global_contract(self.latest_code_hash.into())
            .function_call(
                "init".to_string(),
                json!({
                    "blockchain_id": blockchain_id,
                    "blockchain_address": blockchain_address,
                    "code_hash": self.latest_code_hash,
                })
                .to_string()
                .as_bytes()
                .to_vec(),
                NearToken::from_near(0),
                SMART_CONTRACT_INIT_GAS,
            )
    }
}
