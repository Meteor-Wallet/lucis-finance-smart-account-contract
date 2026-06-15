use std::str::FromStr;

use crate::*;

impl FactoryContract {
    pub fn internal_message_for_create_account(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        brand: Option<String>,
        account_id: Option<String>,
        deadline: u64,
    ) -> String {
        let resolved_account_id = self.internal_resolve_account_id(
            blockchain_id.clone(),
            blockchain_address.clone(),
            brand.clone(),
            account_id.clone(),
        );

        json!({
            "blockchain_id": blockchain_id,
            "blockchain_address": blockchain_address,
            "account_id": resolved_account_id,
            "brand": brand,
            "requested_account_id": account_id,
            "deadline": U64(deadline)
        })
        .to_string()
    }

    pub fn internal_resolve_account_id(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        brand: Option<String>,
        account_id: Option<String>,
    ) -> AccountId {
        assert!(
            brand.is_none() || account_id.is_none(),
            "{}",
            ContractError::BrandOrAccountIdExclusivity.message()
        );

        match brand {
            Some(brand) => {
                let counter = self
                    .branding_counter
                    .get(&brand)
                    .expect(ContractError::InvalidBrand.message())
                    + 1;

                AccountId::from_str(
                    format!("{}-{}.{}", brand, counter, env::current_account_id()).as_str(),
                )
                .expect(ContractError::InvalidAccountId.message())
            }
            None => match account_id {
                Some(account_id) => {
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
                None => self.internal_generate_account_id(blockchain_id, blockchain_address),
            },
        }
    }

    pub fn internal_generate_account_id(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
    ) -> AccountId {
        let short_blockchain_id = blockchain_id.chars().take(3).collect::<String>();
        let suffix =
            format!("-{}.{}", short_blockchain_id, env::current_account_id()).to_lowercase();

        let max_len = 64;
        let max_addr_len = max_len - suffix.len();

        let trimmed_addr: String = if blockchain_address.len() > max_addr_len {
            blockchain_address
                .chars()
                .rev()
                .take(max_addr_len)
                .collect::<String>()
                .chars()
                .rev()
                .collect()
        } else {
            blockchain_address.clone()
        };

        let account_id = format!("{}{}", trimmed_addr.to_lowercase(), suffix);

        AccountId::from_str(&account_id).expect(ContractError::InvalidAccountId.message())
    }
}
