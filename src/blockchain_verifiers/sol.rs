use crate::blockchain_verifiers::BlockchainVerifier;
use crate::contract_errors::ContractError;

pub struct Sol;

impl BlockchainVerifier for Sol {
    fn verify_address(&self, address: String) -> Result<bool, ContractError> {
        // Convert the address to bytes
        let address_bytes = hex::decode(address).map_err(|_| ContractError::InvalidAddressFormat)?;

        if address_bytes.len() != 20 {
            return Err(ContractError::InvalidAddressFormat);
        }

        // Here you can add additional checks if needed, e.g., checksum validation
        Ok(true)
    }

    fn verify_signature(
        &self,
        _: String,
        _: String,
        _: String,
    ) -> Result<bool, ContractError> {
        Ok(true)
    }
}
