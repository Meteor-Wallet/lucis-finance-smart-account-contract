use std::str::FromStr;

use crate::*;

impl FactoryContract {
    pub fn internal_message_for_create_account(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        deadline: u64,
    ) -> String {
        json!({
            "blockchain_id": blockchain_id,
            "blockchain_address": blockchain_address,
            "account_id": self.internal_generate_account_id(blockchain_id.clone(), blockchain_address.clone()),
            "deadline": U64(deadline)
        })
        .to_string()
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
