use near_sdk::{env};

mod eth;
mod sol;

use crate::contract_errors::ContractError;

pub use eth::Eth;
pub use sol::Sol;

pub trait BlockchainVerifier {
    /// Verify that `signature` signs `message` under `pubkey`.
    fn verify_signature(
        &self,
        recovery_address: String,
        message: String,
        signature: String,
    ) -> Result<bool, ContractError>;

    fn verify_address(&self, address: String) -> Result<bool, ContractError>;

    fn recover_pubkey(&self, hash: &[u8; 32], signature: &[u8; 64], v: u8) -> Option<[u8; 64]> {
        // Use the NEAR host function for secp256k1 recovery (requires "unstable" feature).
        env::ecrecover(hash, signature, v, false)
    }
}

/// An adapter that returns a boxed verifier:
pub fn get_verifier(chain: &str) -> Result<Box<dyn BlockchainVerifier>, ContractError> {
    match chain.to_lowercase().as_str() {
        "ethereum"  => Ok(Box::new(Eth)),
        "solana" => Ok(Box::new(Sol)),
        _ => Err(ContractError::UnsupportedBlockchain),
    }
}
