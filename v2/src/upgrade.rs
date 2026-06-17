use crate::*;

const VIEW_FUNCTION_GAS: Gas = Gas::from_tgas(5);
const UPGRADE_PREPARATION_GAS: Gas = VIEW_FUNCTION_GAS.saturating_add(VERIFY_SIGNATURE_GAS);
const MINIMUM_UPGRADE_GAS: Gas = Gas::from_tgas(135);
const MIGRATE_GAS: Gas = Gas::from_tgas(100);

#[ext_contract(ext_factory)]
pub trait ExtFactory {
    fn get_code_hash_upgrade_target(&self, code_hash: CryptoHash) -> Option<&CryptoHash>;
}

#[ext_contract(ext_upgrade_callback)]
pub trait ExtUpgradeCallback {
    fn on_get_code_hash_upgrade_target(
        &mut self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
    ) -> PromiseOrValue<()>;
}

#[near]
impl SmartAccountContract {
    #[private]
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        let old_contract: SmartAccountContractV2State =
            env::state_read().expect(ContractError::ReadStateFailed.message());

        Self {
            factory_contract_id: old_contract.factory_contract_id,
            current_code_hash: old_contract.current_code_hash,
            cross_chain_access_keys: old_contract.cross_chain_access_keys,
            upgrade_pending: false,
        }
    }

    pub fn get_current_code_hash(&self) -> CryptoHash {
        self.current_code_hash
    }

    pub fn message_for_upgrade(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
    ) -> String {
        let blockchain_address =
            Self::internal_normalize_blockchain_address(&blockchain_id, blockchain_address);
        let cross_chain_access_key = self
            .cross_chain_access_keys
            .get(&(blockchain_id.clone(), blockchain_address.clone()))
            .expect(ContractError::UnauthorizedCrossChainAccessKey.message());

        json!({
            "contract_id": env::current_account_id(),
            "blockchain_id": blockchain_id,
            "blockchain_address": blockchain_address,
            "action": "upgrade",
            "nonce": cross_chain_access_key.nonce.wrapping_add(1),
        })
        .to_string()
    }

    pub fn upgrade(
        &mut self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        signature: String,
    ) -> Promise {
        let blockchain_address =
            Self::internal_normalize_blockchain_address(&blockchain_id, blockchain_address);
        let message = self.message_for_upgrade(blockchain_id.clone(), blockchain_address.clone());

        assert!(
            env::prepaid_gas() >= MINIMUM_UPGRADE_GAS,
            "{}",
            ContractError::NotEnoughGasLeft.message()
        );

        assert!(
            !self.upgrade_pending,
            "{}",
            ContractError::UpgradeAlreadyPending.message()
        );

        self.internal_verify_signature(
            blockchain_id.clone(),
            blockchain_address.clone(),
            message,
            signature,
        );

        self.upgrade_pending = true;

        ext_factory::ext(self.factory_contract_id.clone())
            .with_static_gas(VIEW_FUNCTION_GAS)
            .get_code_hash_upgrade_target(self.current_code_hash)
            .then(
                ext_upgrade_callback::ext(env::current_account_id())
                    .with_static_gas(
                        env::prepaid_gas()
                            .checked_sub(UPGRADE_PREPARATION_GAS)
                            .expect(ContractError::NotEnoughGasLeft.message()),
                    )
                    .on_get_code_hash_upgrade_target(blockchain_id, blockchain_address),
            )
    }

    #[private]
    pub fn on_get_code_hash_upgrade_target(
        &mut self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
    ) -> PromiseOrValue<()> {
        self.upgrade_pending = false;

        if env::promise_results_count() != 1 {
            return PromiseOrValue::Value(());
        }

        let code_hash_option = match env::promise_result(0) {
            PromiseResult::Failed => return PromiseOrValue::Value(()),
            PromiseResult::Successful(result) => near_sdk::serde_json::from_slice(&result).ok(),
        };

        let Some(Some(new_code_hash)) = code_hash_option else {
            return PromiseOrValue::Value(());
        };

        if self
            .cross_chain_access_keys
            .get(&(blockchain_id.clone(), blockchain_address.clone()))
            .is_none()
        {
            return PromiseOrValue::Value(());
        }

        self.current_code_hash = new_code_hash;
        self.internal_update_nonce(blockchain_id, blockchain_address);

        PromiseOrValue::Promise(
            Promise::new(env::current_account_id())
                .use_global_contract(self.current_code_hash.into())
                .function_call(
                    "migrate".to_string(),
                    json!({}).to_string().as_bytes().to_vec(),
                    NearToken::from_near(0),
                    MIGRATE_GAS,
                ),
        )
    }
}
