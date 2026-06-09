use std::str::FromStr as _;

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
const ACCOUNT_CREATED_CALLBACK_GAS: Gas = Gas::from_tgas(20);

#[derive(BorshSerialize, BorshDeserialize, BorshStorageKey)]
pub enum StorageKey {
    CodeHashUpgradeTarget,
    BrandingCounter,
    WalletToAccountId,
    AccountIdToWallet,
}

#[derive(BorshDeserialize)]
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
    pub wallet_to_account_id: LookupMap<(BlockchainId, BlockchainAddress), Vec<AccountId>>,
    pub account_id_to_wallet: LookupMap<AccountId, Vec<(BlockchainId, BlockchainAddress)>>,
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
        let old_state: FactoryContractV1 = env::state_read().expect("Failed to read state");

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

    // Dew Finance might not be the only user who want to use this multi chain account system
    // Any of the partners that we approve them using our contract, we will add their brand here
    pub fn add_brand(&mut self, brand: String) {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner_id,
            "{}",
            ContractError::MustBeOwner.message()
        );

        if self.branding_counter.get(&brand).is_some() {
            env::panic_str(ContractError::BrandExists.message());
        }

        self.branding_counter.insert(brand, 0);
    }

    pub fn list_wallets_for_account_id(
        &self,
        account_id: AccountId,
    ) -> &Vec<(BlockchainId, BlockchainAddress)> {
        self.account_id_to_wallet.get(&account_id).unwrap()
    }

    pub fn list_account_ids_for_wallet(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
    ) -> &Vec<AccountId> {
        self.wallet_to_account_id
            .get(&(blockchain_id, blockchain_address))
            .unwrap()
    }

    pub fn add_wallet(
        &mut self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
    ) {
        let account_id = env::predecessor_account_id();

        if self.account_id_to_wallet.get(&account_id).is_none() {
            env::panic_str(ContractError::InvalidAccountId.message());
        }

        self.wallet_to_account_id
            .entry((blockchain_id.clone(), blockchain_address.clone()))
            .or_insert_with(Vec::new)
            .push(account_id.clone());

        self.account_id_to_wallet
            .entry(account_id)
            .or_insert_with(Vec::new)
            .push((blockchain_id, blockchain_address));
    }

    pub fn remove_wallet(
        &mut self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
    ) {
        let account_id = env::predecessor_account_id();

        if self.account_id_to_wallet.get(&account_id).is_none() {
            env::panic_str(ContractError::InvalidAccountId.message());
        }

        self.wallet_to_account_id
            .entry((blockchain_id.clone(), blockchain_address.clone()))
            .and_modify(|account_ids| {
                account_ids.retain(|id| id != &account_id);
            });

        self.account_id_to_wallet
            .entry(account_id)
            .and_modify(|wallets| {
                wallets
                    .retain(|(id, address)| id != &blockchain_id || address != &blockchain_address);
            });
    }

    #[payable]
    pub fn create_account(
        &mut self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        deadline: U64,
        signature: String,
        brand: Option<String>,
        account_id: Option<String>,
    ) -> Promise {
        assert!(
            env::block_timestamp() <= deadline.0,
            "{}",
            ContractError::SignatureExpired.message()
        );

        assert!(
            brand.is_none() || account_id.is_none(),
            "{}",
            ContractError::BrandOrAccountIdExclusivity.message()
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

        let account_id = match brand {
            Some(brand) => {
                let counter = self
                    .branding_counter
                    .get(&brand)
                    .expect(ContractError::InvalidBrand.message())
                    + 1;

                // Even if account creation failed
                // A used counter should remain being used
                // This is to prevent hardlock if the brand and counter already being created for certain unknown reason
                self.branding_counter.insert(brand.clone(), counter);

                AccountId::from_str(
                    format!("{}-{}.{}", brand, counter, env::current_account_id()).as_str(),
                )
                .expect(ContractError::InvalidAccountId.message())
            }
            None => match account_id {
                Some(account_id) => {
                    // To prevent someone trying to mimic account created with certain brand
                    assert!(
                        !account_id.contains('-'),
                        "{}",
                        ContractError::NoDashesAllowed.message()
                    );
                    AccountId::from_str(
                        format!("{}.{}", account_id, env::current_account_id()).as_str(),
                    )
                    .expect(ContractError::InvalidAccountId.message())
                }
                None => self.internal_generate_account_id(
                    blockchain_id.clone(),
                    blockchain_address.clone(),
                ),
            },
        };

        // Option 1:
        // If the account_id already exists in lookup map, no need to try create account
        // Likely the account creation will failed, so directly panic here to save gas
        //
        // Option 2:
        // But since we expected we will never double create
        // So can comment out this part to save gas
        // The account creation will failed anyway if double use account id
        // if self.account_id_to_wallet.get(&account_id).is_some() {
        //     env::panic_str(ContractError::InvalidAccountId.message());
        // }

        Promise::new(account_id.clone())
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
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(ACCOUNT_CREATED_CALLBACK_GAS)
                    .account_created_callback(blockchain_id, blockchain_address, account_id),
            )
    }

    #[private]
    pub fn account_created_callback(
        &mut self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        account_id: AccountId,
    ) {
        assert!(
            env::promise_results_count() == 1,
            "{}",
            ContractError::InvalidPromiseResultCount.message()
        );

        match env::promise_result(0) {
            near_sdk::PromiseResult::Successful(_) => {
                self.wallet_to_account_id
                    .entry((blockchain_id.clone(), blockchain_address.clone()))
                    .or_insert_with(Vec::new)
                    .push(account_id.clone());

                self.account_id_to_wallet
                    .entry(account_id)
                    .or_insert_with(Vec::new)
                    .push((blockchain_id, blockchain_address));
            }
            _ => env::panic_str(ContractError::AccountCreationFailed.message()),
        }
    }
}
