use near_sdk::{env, log};

use crate::blockchain_verifiers::BlockchainVerifier;
use crate::contract_errors::ContractError;

pub struct Eth;

impl BlockchainVerifier for Eth {
    fn verify_address(&self, address: String) -> Result<bool, ContractError> {
        // Trim the 0x
        let address = address.trim_start_matches("0x").to_lowercase();

        // Convert the address to bytes
        let address_bytes =
            hex::decode(address).map_err(|_| ContractError::InvalidAddressFormat)?;

        // Check if the address is 20 bytes long (Ethereum address length)
        if address_bytes.len() != 20 {
            return Err(ContractError::InvalidAddressFormat);
        }

        Ok(true)
    }

    fn verify_signature(
        &self,
        recovery_address: String,
        message: String,
        signature: String,
    ) -> Result<bool, ContractError> {
        // Step 1: Get the hash of the constructed message, this hash is what was signed
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut to_hash = Vec::new();
        to_hash.extend(prefix.as_bytes());
        to_hash.extend(message.as_bytes());
        let hash = env::keccak256_array(&to_hash);

        // Step 2: Extract rsv components from the signature
        let sig_clean = signature.trim_start_matches("0x");
        let sig_bytes = hex::decode(sig_clean).expect("Invalid signature format");
        if sig_bytes.len() != 65 {
            return Err(ContractError::InvalidSignatureFormat);
        }

        let mut rs = [0u8; 64];
        rs.copy_from_slice(&sig_bytes[0..64]);
        let mut v = sig_bytes[64];
        if v >= 27 {
            v -= 27;
        }

        // Step 3: Recover the public key from the signature using rsv components and the message hash
        let pubkey_bytes = self
            .recover_pubkey(&hash, &rs, v)
            .expect("Signature recovery failed");

        // Step 4: Derive Ethereum address from recovered public key
        let hash_pub = env::keccak256_array(&pubkey_bytes);
        let mut recovered_addr = hex::encode(&hash_pub[12..32]); // last 20 bytes of keccak256(pubkey)
        recovered_addr = format!("0x{}", recovered_addr);
        near_sdk::log!("recovered_addr = 0x{}", recovered_addr);

        // Step 5: Verify that the recovered address matches the provided Ethereum address
        log!("[{}] owner_address = {}", recovered_addr, recovery_address);
        if recovered_addr != recovery_address {
            return Err(ContractError::SignatureVerificationFailed);
        }

        Ok(true)
    }
}
