use crate::blockchain_verifiers::BlockchainVerifier;
use crate::contract_errors::ContractError;

use bs58;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub struct Sol;

impl BlockchainVerifier for Sol {
    fn verify_address(&self, address: String) -> Result<bool, ContractError> {
        let pubkey_vec = bs58::decode(address)
            .into_vec()
            .map_err(|_| ContractError::InvalidAddressFormat)?;

        let pubkey_bytes: [u8; 32] = pubkey_vec
            .try_into()
            .map_err(|_| ContractError::InvalidNewPublicKeyFormat)?;

        VerifyingKey::from_bytes(&pubkey_bytes)
            .map(|_| true)
            .map_err(|_| ContractError::InvalidNewPublicKeyFormat)
    }

    fn verify_signature(
        &self,
        recovery_address: String,
        message: String,
        signature: String,
    ) -> Result<bool, ContractError> {
        // Decode base58 public key
        let pubkey_vec = bs58::decode(recovery_address)
            .into_vec()
            .map_err(|_| ContractError::InvalidAddressFormat)?;

        let pubkey_bytes: [u8; 32] = pubkey_vec
            .try_into()
            .map_err(|_| ContractError::InvalidNewPublicKeyFormat)?;

        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|_| ContractError::InvalidNewPublicKeyFormat)?;

        // Decode base58 signature
        let signature_vec = bs58::decode(signature)
            .into_vec()
            .map_err(|_| ContractError::InvalidSignatureFormat)?;

        let signature_bytes: [u8; 64] = signature_vec
            .try_into()
            .map_err(|_| ContractError::InvalidSignatureFormat)?;

        let signature = Signature::from_bytes(&signature_bytes);

        // Verify message
        verifying_key
            .verify(message.as_bytes(), &signature)
            .map(|_| true)
            .map_err(|_| ContractError::SignatureVerificationFailed)
    }
}
