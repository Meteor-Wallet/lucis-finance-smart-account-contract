pub mod blockchain_verifiers;
pub mod contract_errors;
pub mod types;

use crate::blockchain_verifiers::get_verifier;
use crate::types::Blockchain;
use near_sdk::store::LookupMap;
use near_sdk::{env, near, near_bindgen, Promise, PublicKey};
use std::str::FromStr;

#[near(contract_state)]
pub struct SmartAccountContract {
    /// Reverse mapping from Ethereum address (20 bytes) to NEAR account.
    owner_accounts: LookupMap<Blockchain, Vec<String>>,
    nonce: u64, // Nonce for the contract, used to prevent replay attacks
}

impl Default for SmartAccountContract {
    fn default() -> Self {
        Self {
            owner_accounts: LookupMap::new(b"eth_to_account".to_vec()),
            nonce: 0, // Initialize nonce to 0
        }
    }
}

#[near_bindgen]
impl SmartAccountContract {
    // #[payable]
    pub fn link_eth_address(
        &mut self,
        blockchain: Blockchain,
        owner_address: String,
        nonce: u64,
        signature: String,
    ) {
        // Step 1: Verify the nonce and blockchain support
        self.verify_nonce(nonce)
            .expect("Invalid nonce: expected one greater than the current nonce");

        // Step 2: Get the blockchain verifier and validate the address format
        let blockchain_verifier =
            get_verifier(blockchain.as_str())
            .unwrap_or_else(|e| panic!("{}", e.message()));
        blockchain_verifier
            .verify_address(owner_address.clone())
            .unwrap_or_else(|e| panic!("{}", e.message()));

        // Step 3: Verify the signature
        let caller = env::signer_account_id();
        let account_id = caller.clone();
        blockchain_verifier.verify_signature(account_id.clone(), owner_address.clone(), nonce, signature)
            .unwrap_or_else(|e| panic!("{}", e.message()));

        // Step 4: Check if the Ethereum address is already linked to a NEAR account
        let mut linked_accounts = self
            .owner_accounts
            .get(&blockchain)
            .cloned()
            .unwrap_or_else(|| vec![]);
        if linked_accounts.iter().any(|record| record == &owner_address) {
            panic!("{}", contract_errors::ContractError::LinkedAddressAlreadyExists.message());
        }

        // Step 5: Add the new address to the mapping
        linked_accounts.push(owner_address.clone());
        self.owner_accounts.insert(blockchain, linked_accounts);
        self.nonce = nonce + 1;

        // Log event
        env::log_str(&format!(
            "Linked NEAR account {} to Ethereum address {}",
            account_id, owner_address
        ));
    }

    pub fn recover_account(
        &self,
        new_public_key: String,
        blockchain: Blockchain,
        signature: String,
    ) -> Promise {
        // Parse the new public key string into the PublicKey type
        let pk = PublicKey::from_str(&new_public_key).expect("Invalid public key format");

        let message = format!(
            "Recover NEAR account {} to new public key {}",
            env::signer_account_id(),
            new_public_key
        );
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut to_hash = Vec::new();
        to_hash.extend(prefix.as_bytes());
        to_hash.extend(message.as_bytes());
        let hash = env::keccak256_array(&to_hash);

        // Parse the signature
        let sig_clean = signature.trim_start_matches("0x");
        let sig_bytes = hex::decode(sig_clean).expect("hahahah Invalid signature format");
        assert!(
            sig_bytes.len() == 65,
            "Signature must be 65 bytes in hex format"
        );
        let mut rs = [0u8; 64];
        rs.copy_from_slice(&sig_bytes[0..64]);
        let mut v = sig_bytes[64];
        if v >= 27 {
            v -= 27;
        }
        // Recover the public key from the signature
        let pubkey_bytes = Self::recover_pubkey(&hash, &rs, v).expect("Signature recovery failed");
        // Derive Ethereum address and verify it matches the linked address
        let hash_pub = env::keccak256_array(&pubkey_bytes);
        let recovered_addr = &hash_pub[12..32];
        let recovered_hex = format!("0x{}", hex::encode(recovered_addr));

        let linked_accounts = self
            .owner_accounts
            .get(&blockchain)
            .cloned()
            .expect("Blockchain not supported");

        linked_accounts
            .iter()
            .find(|addr| {
                // strip any "0x" or uppercase differences:
                addr.trim_start_matches("0x")
                    .eq_ignore_ascii_case(&recovered_hex.trim_start_matches("0x"))
            })
            .expect("New public key not linked to any Ethereum address");

        env::log_str(&format!(
            "Account {} recovery: adding new key {} and removing old key",
            env::current_account_id(),
            new_public_key
        ));

        // Schedule the actions: add the new full access key and delete the old key
        Promise::new(env::current_account_id()).add_full_access_key(pk)
    }
}

impl SmartAccountContract {
    /// Internal helper: recovers the 64-byte public key (uncompressed, without 0x04 prefix) from an ECDSA signature.
    /// Returns None if recovery fails.
    fn recover_pubkey(hash: &[u8; 32], signature: &[u8; 64], v: u8) -> Option<[u8; 64]> {
        // Use the NEAR host function for secp256k1 recovery (requires "unstable" feature).
        env::ecrecover(hash, signature, v, false)
    }

    fn verify_nonce(&self, input_nonce: u64) -> Result<(), String> {
        // Assert input nonce is one greater than the stored nonce or throw an error
        if input_nonce == self.nonce as u64 + 1 {
            Ok(())
        } else {
            Err(format!(
                "Invalid nonce: expected {}, got {}",
                self.nonce + 1,
                input_nonce
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, AccountId};

    fn get_context() -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        let account_id = AccountId::try_from("alice.near".to_string()).unwrap();
        builder.predecessor_account_id(account_id);
        builder
    }

    #[test]
    #[should_panic(expected = "E001: unsupported blockchain")]
    fn test_unsupported_blockchain() {
        // 1. set up environment
        let mut builder = get_context();
        let caller = AccountId::try_from("rektdegen.testnet".to_string()).unwrap();
        builder.signer_account_id(caller.clone());
        let context = builder.build();
        testing_env!(context);
        let mut contract = SmartAccountContract::default();

        // 2. test signature verification success
        let eth_blockchain = "random_chain".to_string();
        let eth_address = "0x950918fe5deb16c90a7071d5f3daff3f2e84e0df".to_string();
        let signature = "0xfce0288ef179953be8cf0d1eb10b2c8f008c591f89deb3425348e6f520cee12e4392c85ee9e81973af97999b84e88886fe12969c39bd663a2cf20725b8deb2a61c".to_string();
        contract.link_eth_address(eth_blockchain.clone(), eth_address, 1, signature);
    }

    #[test]
    fn test_link_eth_address() {
        // 1. set up environment
        let mut builder = get_context();
        let caller = AccountId::try_from("rektdegen.testnet".to_string()).unwrap();
        builder.signer_account_id(caller.clone());
        let context = builder.build();
        testing_env!(context);
        let mut contract = SmartAccountContract::default();

        // 2. test signature verification success
        let eth_blockchain = "eth".to_string();
        let eth_address = "0x950918fe5deb16c90a7071d5f3daff3f2e84e0df".to_string();
        let signature = "0xfce0288ef179953be8cf0d1eb10b2c8f008c591f89deb3425348e6f520cee12e4392c85ee9e81973af97999b84e88886fe12969c39bd663a2cf20725b8deb2a61c".to_string();
        contract.link_eth_address(eth_blockchain.clone(), eth_address, 1, signature);

        // Optionally, assert that the mapping is set
        assert!(contract.owner_accounts.get(&eth_blockchain).is_some());
    }

    #[test]
    #[should_panic(expected = "Invalid signature")]
    fn test_link_eth_address_invalid_signature() {
        // 1. set up environment
        let mut builder = get_context();
        let caller = AccountId::try_from("rektdegen.testnet".to_string()).unwrap();
        builder.signer_account_id(caller.clone());
        let context = builder.build();
        testing_env!(context);
        let mut contract = SmartAccountContract::default();

        // 2. test signature verification failure
        let eth_blockchain = "eth".to_string();
        let eth_address = "0x950918fe5deb16c90a7071d5f3daff3f2e84e0df".to_string();
        // The signature was signed with address 0x86e25e65ae0e54e6bb3c5a3c321710cc56978e8e, original message: Link NEAR account rektdegen.testnet to Ethereum address 0x950918fe5deb16c90a7071d5f3daff3f2e84e0df with nonce 1
        let signature = "0xbf26cea246af7fce1984b1bcf50d5f09948b09fde3eadd77c2895bfa6c1b9d007e825ba033a028ccda816c4e5793f5a38317872aec858fafe652e942c33ae85c1c".to_string();
        contract.link_eth_address(eth_blockchain.clone(), eth_address, 1, signature);
    }
}
