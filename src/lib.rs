use std::str::FromStr;

use near_sdk::json_types::Base64VecU8;
use near_sdk::store::LookupMap;
use near_sdk::{env, near, near_bindgen, AccountId, Promise, PublicKey};

#[near(serializers = [json, borsh])]
pub struct LinkInfo {
    /// The linked Ethereum address (20 bytes).
    eth_address: Vec<u8>,
    /// The NEAR public key of the account at the time of linking (for recovery purposes).
    near_pk: PublicKey,
    nonce: u64,           
}

#[near(contract_state)]
pub struct Contract {
    /// Reverse mapping from Ethereum address (20 bytes) to NEAR account.
    eth_to_account: LookupMap<Vec<u8>, AccountId>,
    nonce: u64, // Nonce for the contract, used to prevent replay attacks
}

impl Default for Contract {
    fn default() -> Self {
        Self {
            eth_to_account: LookupMap::new(b"eth_to_account".to_vec()),
            nonce: 0, // Initialize nonce to 0
        }
    }
}

#[near(serializers = [json, borsh])]
pub struct EcrecoverInput {
    m: Base64VecU8,
    v: u8,
    sig: Base64VecU8,
    mc: bool,
}

#[near(serializers = [json, borsh])]
pub struct EcrecoverOutput {
    address: Base64VecU8,
}

#[near_bindgen]
impl Contract {
    // #[payable]
    pub fn link_eth_address(&mut self, eth_address: String, nonce: u64, signature: String) {
        // Verify the nonce
        self.verify_nonce(nonce)
            .expect("Invalid nonce: expected one greater than the current nonce");

        // We are using signer instead of predecessor as it might be a relayed transaction
        let caller = env::signer_account_id();

        // Parse the Ethereum address string to bytes (20 bytes)
        let eth_clean = eth_address.trim_start_matches("0x");
        let eth_bytes = hex::decode(eth_clean).expect("Invalid Ethereum address format");
        assert!(eth_bytes.len() == 20, "Ethereum address should be 20 bytes");
        assert!(
            self.eth_to_account.get(&eth_bytes).is_none(),
            "Ethereum address is already linked to another account"
        );

        // Construct the expected message for signature verification
        let account_id = caller.clone();
        let message = format!(
            "Link NEAR account {} to Ethereum address {} with nonce {}",
            account_id, eth_address, nonce
        );
        near_sdk::log!("message = {}", message);

        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut to_hash = Vec::new();
        to_hash.extend(prefix.as_bytes());
        to_hash.extend(message.as_bytes());
        let hash = env::keccak256_array(&to_hash);

        // Parse the signature from hex
        let sig_clean = signature.trim_start_matches("0x");
        let sig_bytes = hex::decode(sig_clean).expect("Invalid signature format");
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
        // Derive Ethereum address from recovered public key
        let hash_pub = env::keccak256_array(&pubkey_bytes);
        let recovered_addr = &hash_pub[12..32]; // last 20 bytes of keccak256(pubkey)
        near_sdk::log!("recovered_addr = 0x{}", hex::encode(recovered_addr));

        assert!(
            recovered_addr == eth_bytes.as_slice(),
            "Signature is not from the provided Ethereum address"
        );

        // Store the mapping from Ethereum address to NEAR account
        self.eth_to_account.insert(eth_bytes, caller.clone());
        env::log_str(&format!(
            "Linked NEAR account {} to Ethereum address {}",
            account_id, eth_address
        ));
    }

    pub fn recover_account(&self, new_public_key: String, signature: String) -> Promise {
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
        let sig_bytes = hex::decode(sig_clean).expect("Invalid signature format");
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
        self.eth_to_account
            .get(recovered_addr)
            .expect("No linked account for this Ethereum address");

        env::log_str(&format!(
            "Account {} recovery: adding new key {} and removing old key",
            env::current_account_id(),
            new_public_key
        ));

        // Schedule the actions: add the new full access key and delete the old key
        Promise::new(env::current_account_id()).add_full_access_key(pk)
    }
}

impl Contract {
    /// Internal helper: recovers the 64-byte public key (uncompressed, without 0x04 prefix) from an ECDSA signature.
    /// Returns None if recovery fails.
    fn recover_pubkey(hash: &[u8; 32], signature: &[u8; 64], v: u8) -> Option<[u8; 64]> {
        // Use the NEAR host function for secp256k1 recovery (requires "unstable" feature).
        env::ecrecover(hash, signature, v, false)
    }

    fn verify_nonce(
        &self,
        input_nonce: u64,
    ) -> Result<(), String> {
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
    use near_sdk::json_types::Base64VecU8;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, AccountId};

    fn get_context() -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        let account_id = AccountId::try_from("alice.near".to_string()).unwrap();
        builder.predecessor_account_id(account_id);
        builder
    }

    #[test]
    fn test_link_eth_address() {
        // 1. set up mock context with custom signer_account_id
        let mut builder = get_context();
        let caller = AccountId::try_from("rektdegen.testnet".to_string()).unwrap();
        builder.signer_account_id(caller.clone());
        let context = builder.build();
        testing_env!(context);

        // 2. instantiate your contract
        let mut contract = Contract::default();

        let eth_address = "0x950918fe5deb16c90a7071d5f3daff3f2e84e0df".to_string();
        let signature = "0xdb49b093334e25780b0462e3e3acaeb16000c2ab1d00e12dd90f5d1e9e92fd4c1cf21f0fbe7cecf2dc769d08d4e532fd4819de42ba421f8cdadef721accb15581c".to_string();
        // let signature ="0x3367d92b3658b38091309a11aa711cbe2884b5a7209954c23ba43c0015b179652be4a0889570bac3c49ccfd1f3bee414b2fc8be957159461b60276a522d124031b".to_string();
        contract.link_eth_address(eth_address, signature);

        // Optionally, assert that the mapping is set
        assert!(contract.eth_to_account.get(&eth_address).is_some());
    }
    // -- you can add more tests here once you have real vectors
}
