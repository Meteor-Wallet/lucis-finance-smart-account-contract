pub mod blockchain_verifiers;
pub mod contract_errors;
pub mod types;

use crate::blockchain_verifiers::get_verifier;
use crate::contract_errors::ContractError;
use crate::types::{BlockchainAddress, BlockchainId, CrossChainAccessKey, Nonce};
use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::{env, near, store::LookupMap, AccountId, Promise, PublicKey};
use near_sdk::{ext_contract, BorshStorageKey, Gas, NearToken};
use std::num::NonZero;
use std::str::FromStr;

#[derive(BorshSerialize, BorshDeserialize, BorshStorageKey)]
pub enum StorageKey {
    CrossChainAccessKeys,
}

#[near(contract_state)]
pub struct SmartAccountContract {
    factory: AccountId,
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
    pub fn init(blockchain_id: BlockchainId, blockchain_address: BlockchainAddress) -> Self {
        let mut contract = Self {
            factory: env::predecessor_account_id(),
            cross_chain_access_keys: LookupMap::new(StorageKey::CrossChainAccessKeys),
        };

        contract.cross_chain_access_keys.insert(
            (blockchain_id.clone(), blockchain_address.clone()),
            CrossChainAccessKey {
                blockchain: blockchain_id,
                address: blockchain_address,
                nonce: contract.internal_generate_nonce(),
            },
        );

        contract
    }
}

impl SmartAccountContract {
    pub fn internal_generate_nonce(&self) -> Nonce {
        let seed = env::random_seed();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&seed[..8]);
        u64::from_le_bytes(bytes)
    }

    pub fn update_nonce(
        &mut self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
    ) {
        let cross_chain_access_key = self
            .cross_chain_access_keys
            .get(&(blockchain_id.clone(), blockchain_address.clone()))
            .expect(ContractError::UnauthorizedCrossChainAccessKey.message());

        let new_nonce = cross_chain_access_key.nonce + 1;

        self.cross_chain_access_keys.insert(
            (blockchain_id.clone(), blockchain_address.clone()),
            CrossChainAccessKey {
                blockchain: blockchain_id,
                address: blockchain_address,
                nonce: new_nonce,
            },
        );
    }
}

#[ext_contract(ext_self)]
pub trait ExtSelf {
    fn function_call_execution(
        &mut self,
        contract_id: AccountId,
        function_name: String,
        args: String,
        attached_deposit: NearToken,
        gas: Gas,
    ) -> Promise;

    fn access_key_with_allowance_execution(
        &mut self,
        public_key: String,
        contract_id: AccountId,
        function_names: String,
        allowance: NearToken,
    ) -> Promise;
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
            "{}",
            ContractError::CannotCallFunctionOnSelf.message()
        );

        let cross_chain_access_key = self
            .cross_chain_access_keys
            .get(&(blockchain_id.clone(), blockchain_address.clone()))
            .expect(ContractError::UnauthorizedCrossChainAccessKey.message());

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
            cross_chain_access_key.nonce + 1
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
            "{}",
            ContractError::CannotGrantAccessKeyToSelf.message()
        );

        let cross_chain_access_key = self
            .cross_chain_access_keys
            .get(&(blockchain_id.clone(), blockchain_address.clone()))
            .expect(ContractError::UnauthorizedCrossChainAccessKey.message());

        format!(
            "Grant access key {} to contract {} with function names {} and allowance {} from NEAR account {} linked to {} address {} with nonce {}",
            public_key,
            contract_id,
            function_names,
            allowance.exact_amount_display(),
            env::current_account_id(),
            blockchain_id,
            blockchain_address,
            cross_chain_access_key.nonce + 1
        )
    }

    pub fn function_call(
        &mut self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        contract_id: AccountId,
        function_name: String,
        args: String,
        attached_deposit: NearToken,
        gas: Gas,
        signature: String,
    ) -> Promise {
        let message = self.get_message_for_function_call(
            blockchain_id.clone(),
            blockchain_address.clone(),
            contract_id.clone(),
            function_name.clone(),
            args.clone(),
            attached_deposit,
            gas,
        );

        self.update_nonce(blockchain_id.clone(), blockchain_address.clone());

        let blockchain_verifier =
            get_verifier(&blockchain_id).expect(ContractError::UnsupportedBlockchain.message());

        blockchain_verifier
            .verify_signature(blockchain_address, message, signature)
            .expect(ContractError::SignatureVerificationFailed.message());

        let remaining_gas = env::prepaid_gas()
            .checked_sub(env::used_gas())
            .expect(ContractError::FailedToCalculateRemainingGas.message())
            .checked_sub(Gas::from_tgas(1))
            .expect(ContractError::NotEnoughGasLeft.message());

        ext_self::ext(env::current_account_id())
            .with_static_gas(remaining_gas)
            .function_call_execution(contract_id, function_name, args, attached_deposit, gas)
    }

    #[private]
    pub fn function_call_execution(
        &mut self,
        contract_id: AccountId,
        function_name: String,
        args: String,
        attached_deposit: NearToken,
        gas: Gas,
    ) -> Promise {
        Promise::new(contract_id).function_call(
            function_name,
            args.into_bytes(),
            attached_deposit,
            gas,
        )
    }

    pub fn access_key_with_allowance(
        &mut self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        public_key: String,
        contract_id: AccountId,
        function_names: String,
        allowance: NearToken,
        signature: String,
    ) {
        let message = self.get_message_for_access_key_with_allowance(
            blockchain_id.clone(),
            blockchain_address.clone(),
            public_key.clone(),
            contract_id.clone(),
            function_names.clone(),
            allowance,
        );

        self.update_nonce(blockchain_id.clone(), blockchain_address.clone());

        let blockchain_verifier =
            get_verifier(&blockchain_id).expect(&ContractError::UnsupportedBlockchain.message());

        blockchain_verifier
            .verify_signature(blockchain_address, message, signature)
            .expect(ContractError::SignatureVerificationFailed.message());

        let remaining_gas = env::prepaid_gas()
            .checked_sub(env::used_gas())
            .expect(ContractError::FailedToCalculateRemainingGas.message())
            .checked_sub(Gas::from_tgas(1))
            .expect(ContractError::NotEnoughGasLeft.message());

        ext_self::ext(env::current_account_id())
            .with_static_gas(remaining_gas)
            .access_key_with_allowance_execution(
                public_key,
                contract_id,
                function_names,
                allowance,
            );
    }

    #[private]
    pub fn access_key_with_allowance_execution(
        &mut self,
        public_key: String,
        contract_id: AccountId,
        function_names: String,
        allowance: NearToken,
    ) -> Promise {
        let public_key = PublicKey::from_str(&public_key)
            .expect(ContractError::InvalidNewPublicKeyFormat.message());
        Promise::new(env::current_account_id()).add_access_key_allowance(
            public_key,
            near_sdk::Allowance::Limited(NonZero::new(allowance.as_yoctonear()).unwrap()),
            contract_id,
            function_names,
        )
    }
}
