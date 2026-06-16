use near_sdk::Allowance;

use crate::*;

impl SmartAccountContract {
    pub fn internal_generate_nonce(&self) -> Nonce {
        let seed = env::random_seed();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&seed[..8]);
        u64::from_le_bytes(bytes)
    }

    pub fn internal_update_nonce(
        &mut self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
    ) {
        let cross_chain_access_key = self
            .cross_chain_access_keys
            .get(&(blockchain_id.clone(), blockchain_address.clone()))
            .expect(ContractError::UnauthorizedCrossChainAccessKey.message());

        // Purposely allow overflow
        // As long as the nonce is unique, it's fine
        let new_nonce = cross_chain_access_key.nonce.wrapping_add(1);

        self.cross_chain_access_keys.insert(
            (blockchain_id.clone(), blockchain_address.clone()),
            CrossChainAccessKey {
                blockchain: blockchain_id,
                address: blockchain_address,
                nonce: new_nonce,
                last_usable_nonce: cross_chain_access_key.last_usable_nonce,
            },
        );
    }

    pub fn internal_usable_nonce_left(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
    ) -> u64 {
        let cross_chain_access_key = self
            .cross_chain_access_keys
            .get(&(blockchain_id.clone(), blockchain_address.clone()))
            .expect(ContractError::UnauthorizedCrossChainAccessKey.message());

        cross_chain_access_key
            .last_usable_nonce
            .wrapping_sub(cross_chain_access_key.nonce)
    }

    pub fn internal_validate_transaction(&self, transaction: &Transaction) {
        assert!(
            transaction.actions.len() > 0,
            "{}",
            ContractError::EmptyTransaction.message()
        );

        assert!(
            transaction.receiver_id != self.factory_contract_id,
            "{}",
            ContractError::ActionNotAllowed.message()
        );

        if transaction.receiver_id == env::current_account_id() {
            for action in &transaction.actions {
                match action {
                    Action::AddKey { access_key, .. } => match &access_key.permission {
                        // Not allowing full access keys to be added
                        AddKeyPermission::FullAccess => {
                            panic!("{}", ContractError::CannotGrantAccessKeyToSelf.message());
                        }
                        // Allow create function call access keys
                        // but only if the receiver_id is not self
                        AddKeyPermission::FunctionCall { receiver_id, .. } => {
                            assert!(
                                *receiver_id != *env::current_account_id(),
                                "{}",
                                ContractError::CannotGrantAccessKeyToSelf.message()
                            );
                        }
                    },
                    // Allow delete key, transfer, create account, and stake actions
                    // Although the transfer, create account, and stake actions are not useful, but they are not harmful
                    Action::DeleteKey { .. }
                    | Action::Transfer { .. }
                    | Action::CreateAccount
                    | Action::Stake { .. } => {}
                    // Not allowing delete account
                    // Not allowing deploy contract
                    // Not allowing function call, function call could bypass those private checks
                    Action::DeleteAccount { .. }
                    | Action::DeployContract { .. }
                    | Action::FunctionCall { .. } => {
                        panic!("{}", ContractError::ActionNotAllowed.message());
                    }
                }
            }
        } else if transaction
            .receiver_id
            .to_string()
            .ends_with(&format!(".{}", env::current_account_id()))
        {
            for action in &transaction.actions {
                match action {
                    Action::CreateAccount | Action::Transfer { .. } => {}
                    _ => {
                        panic!("{}", ContractError::ActionNotAllowed.message());
                    }
                }
            }
        }
    }

    pub fn internal_generate_promise(&self, transaction: Transaction) -> Promise {
        let mut promise = Promise::new(transaction.receiver_id);

        for action in transaction.actions {
            match action {
                Action::CreateAccount => {
                    promise = promise.create_account();
                }
                Action::Transfer { deposit } => {
                    promise = promise.transfer(deposit);
                }
                Action::DeployContract { code } => {
                    promise = promise.deploy_contract(code.into());
                }
                Action::FunctionCall {
                    method_name,
                    args,
                    gas,
                    deposit,
                } => {
                    promise = promise.function_call(
                        method_name,
                        near_sdk::serde_json::to_vec(&args).unwrap(),
                        deposit,
                        gas,
                    );
                }
                Action::AddKey {
                    public_key,
                    access_key,
                } => match access_key.permission {
                    AddKeyPermission::FullAccess => {
                        promise = match access_key.nonce {
                            Some(nonce) => {
                                promise.add_full_access_key_with_nonce(public_key, nonce)
                            }
                            None => promise.add_full_access_key(public_key),
                        };
                    }
                    AddKeyPermission::FunctionCall {
                        allowance,
                        receiver_id,
                        method_names,
                    } => {
                        let function_names = match method_names {
                            Some(names) => names.join(","),
                            None => String::new(),
                        };

                        let allowance = match allowance {
                            Some(allowance) => Allowance::limited(allowance).unwrap(),
                            None => Allowance::Unlimited,
                        };

                        promise = match access_key.nonce {
                            Some(nonce) => promise.add_access_key_allowance_with_nonce(
                                public_key,
                                allowance,
                                receiver_id,
                                function_names,
                                nonce,
                            ),
                            None => promise.add_access_key_allowance(
                                public_key,
                                allowance,
                                receiver_id,
                                function_names,
                            ),
                        };
                    }
                },
                Action::DeleteKey { public_key } => {
                    promise = promise.delete_key(public_key);
                }
                Action::DeleteAccount { beneficiary_id } => {
                    promise = promise.delete_account(beneficiary_id);
                }
                Action::Stake { stake, public_key } => {
                    promise = promise.stake(stake, public_key);
                }
            }
        }

        promise
    }
}
