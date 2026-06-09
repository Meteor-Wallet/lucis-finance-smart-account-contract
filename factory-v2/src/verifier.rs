use base64::Engine;
use ripemd::Digest;

use crate::*;

/// Derive Bitcoin P2PKH payload (version + RIPEMD160(SHA256(pubkey)))
fn derive_payload(version: u8, pubkey_bytes: &[u8]) -> Vec<u8> {
    let sha = env::sha256_array(pubkey_bytes);
    let mut ripemd = ripemd::Ripemd160::new();
    ripemd.update(&sha);
    let ripemd_hash = ripemd.finalize();

    let mut payload = Vec::with_capacity(21);
    payload.push(version);
    payload.extend_from_slice(&ripemd_hash);
    payload
}

/// Compress uncompressed secp256k1 pubkey (64 or 65 bytes → 33 bytes)
fn compress_pubkey(uncompressed: &[u8]) -> Vec<u8> {
    // Handle NEAR's ecrecover (64 bytes) vs normal uncompressed (65 bytes)
    let raw = if uncompressed.len() == 64 {
        // prepend 0x04
        let mut full = Vec::with_capacity(65);
        full.push(0x04);
        full.extend_from_slice(uncompressed);
        full
    } else {
        assert!(uncompressed.len() == 65 && uncompressed[0] == 0x04);
        uncompressed.to_vec()
    };

    let x = &raw[1..33];
    let y = &raw[33..65];

    let mut compressed = Vec::with_capacity(33);
    // parity of y decides prefix
    if y[31] % 2 == 0 {
        compressed.push(0x02);
    } else {
        compressed.push(0x03);
    }
    compressed.extend_from_slice(x);
    compressed
}

impl FactoryContract {
    pub fn internal_verify_signature(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        message: String,
        signature: String,
    ) {
        match blockchain_id.to_lowercase().as_str() {
            "btc" => self.internal_verify_btc_signature(blockchain_address, signature, message),
            "ethereum" | "bnb" => {
                self.internal_verify_evm_signature(blockchain_address, signature, message)
            }
            "solana" => {
                self.internal_verify_solana_signature(blockchain_address, signature, message)
            }
            "stellar" => {
                self.internal_verify_stellar_signature(blockchain_address, signature, message)
            }
            "ton" => self.internal_verify_ton_signature(blockchain_address, signature, message),
            "tron" => self.internal_verify_tron_signature(blockchain_address, signature, message),
            _ => panic!("{}", ContractError::UnsupportedBlockchain.message()),
        }
    }

    pub fn internal_verify_btc_signature(
        &self,
        blockchain_address: String,
        signature: String,
        message: String,
    ) {
        // 1. Decode base58check address → get payload
        let addr_bytes = bs58::decode(&blockchain_address)
            .into_vec()
            .expect(ContractError::InvalidAddressFormat.message());

        assert!(
            addr_bytes.len() == 25,
            "{}",
            ContractError::InvalidAddressFormat.message()
        );

        let (addr_payload, addr_checksum) = addr_bytes.split_at(21);

        // 2. Verify address checksum = sha256(sha256(payload))[0..4]
        let h1 = env::sha256_array(addr_payload);
        let h2 = env::sha256_array(&h1);
        let expected_checksum = &h2[0..4];

        assert!(
            expected_checksum == addr_checksum,
            "{}",
            ContractError::InvalidAddressFormat.message()
        );

        // 3. Decode base64 signature (65 bytes, compact format)
        let sig: Vec<u8> = base64::engine::general_purpose::STANDARD
            .decode(&signature)
            .expect(ContractError::InvalidSignatureFormat.message());

        assert!(
            sig.len() == 65,
            "{}",
            ContractError::InvalidSignatureFormat.message()
        );

        let mut rs = [0u8; 64];
        rs.copy_from_slice(&sig[1..65]); // skip header byte
        let mut v = sig[0] - 27;
        if v >= 4 {
            v -= 4;
        }

        // 4. Construct Bitcoin message digest
        let prefix = b"\x18Bitcoin Signed Message:\n";
        let mut buf = Vec::new();
        buf.extend_from_slice(prefix);

        let msg_bytes = message.as_bytes();
        let msg_len = msg_bytes.len();
        if msg_len < 253 {
            buf.push(msg_len as u8);
        } else {
            panic!("{}", ContractError::InvalidMessageLen.message());
        }
        buf.extend_from_slice(msg_bytes);

        let h1 = env::sha256_array(&buf);
        let hash = env::sha256_array(&h1);

        // 5. Recover pubkey (always uncompressed from ecrecover)
        let pubkey_uncompressed = env::ecrecover(&hash, &rs, v, true)
            .expect(ContractError::SignatureVerificationFailed.message());

        // 6. Hash pubkey → derive Bitcoin address payload
        let candidate_payloads = vec![
            derive_payload(addr_payload[0], &pubkey_uncompressed), // uncompressed
            derive_payload(addr_payload[0], &compress_pubkey(&pubkey_uncompressed)), // compressed
        ];

        // 7. Check if any candidate matches provided address
        let mut success = false;
        for payload in candidate_payloads {
            // Double SHA256 checksum
            let h1 = env::sha256_array(&payload);
            let h2 = env::sha256_array(&h1);
            let checksum = &h2[0..4];

            let mut reconstructed = payload.clone();
            reconstructed.extend_from_slice(checksum);

            if reconstructed == addr_bytes {
                success = true;
                break;
            }
        }

        assert!(
            success,
            "{}",
            ContractError::SignatureVerificationFailed.message()
        );
    }

    pub fn internal_verify_evm_signature(
        &self,
        blockchain_address: String,
        signature: String,
        message: String,
    ) {
        // Step 1: Get the hash of the constructed message, this hash is what was signed
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut to_hash = Vec::new();
        to_hash.extend(prefix.as_bytes());
        to_hash.extend(message.as_bytes());
        let hash = env::keccak256_array(&to_hash);

        // Step 2: Extract rsv components from the signature
        let sig_clean = signature.trim_start_matches("0x");
        let sig_bytes =
            hex::decode(sig_clean).expect(ContractError::InvalidSignatureFormat.message());

        assert!(
            sig_bytes.len() == 65,
            "{}",
            ContractError::InvalidSignatureFormat.message()
        );

        let mut rs = [0u8; 64];
        rs.copy_from_slice(&sig_bytes[0..64]);
        let mut v = sig_bytes[64];
        if v >= 27 {
            v -= 27;
        }

        // Step 3: Recover the public key from the signature using rsv components and the message hash
        let pubkey_bytes = env::ecrecover(&hash, &rs, v, false)
            .expect(ContractError::SignatureVerificationFailed.message());

        // Step 4: Derive Ethereum address from recovered public key
        let hash_pub = env::keccak256_array(&pubkey_bytes);
        let mut recovered_addr = hex::encode(&hash_pub[12..32]); // last 20 bytes of keccak256(pubkey)
        recovered_addr = format!("0x{}", recovered_addr);

        // Step 5: Verify that the recovered address matches the provided Ethereum address
        assert!(
            recovered_addr.eq_ignore_ascii_case(&blockchain_address),
            "{}",
            ContractError::SignatureVerificationFailed.message()
        );
    }

    pub fn internal_verify_solana_signature(
        &self,
        blockchain_address: String,
        signature: String,
        message: String,
    ) {
        let pubkey: [u8; 32] = bs58::decode(blockchain_address)
            .into_vec()
            .expect(ContractError::InvalidAddressFormat.message())
            .try_into()
            .expect(ContractError::InvalidKeyLen.message());

        // 2. Decode base58 signature (64 bytes)
        let sig: [u8; 64] = bs58::decode(signature)
            .into_vec()
            .expect(ContractError::InvalidSignatureFormat.message())
            .try_into()
            .expect(ContractError::InvalidSignatureFormat.message());

        // 3. Use raw message bytes (must match exactly what Solana signed)
        let msg = message.as_bytes();

        // 4. Verify signature
        assert!(
            env::ed25519_verify(&sig, msg, &pubkey),
            "{}",
            ContractError::SignatureVerificationFailed.message()
        );
    }

    pub fn internal_verify_stellar_signature(
        &self,
        blockchain_address: String,
        signature: String,
        message: String,
    ) {
        // 1. Stellar addresses are StrKey encoded ("G..." → 32-byte ed25519 pubkey)
        let pubkey: [u8; 32] = stellar_strkey::ed25519::PublicKey::from_string(&blockchain_address)
            .expect(ContractError::InvalidAddressFormat.message())
            .0;

        // 2. Signature is usually base64 encoded (64 bytes)
        let sig: [u8; 64] = base64::engine::general_purpose::STANDARD
            .decode(&signature)
            .expect(ContractError::InvalidSignatureFormat.message())
            .try_into()
            .expect(ContractError::InvalidSignatureFormat.message());

        // 3. Raw message
        let msg = message.as_bytes();

        // 4. Verify
        assert!(
            env::ed25519_verify(&sig, msg, &pubkey),
            "{}",
            ContractError::SignatureVerificationFailed.message()
        );
    }

    pub fn internal_verify_ton_signature(
        &self,
        blockchain_address: String,
        signature: String,
        message: String,
    ) {
        let pubkey: [u8; 32] = hex::decode(blockchain_address)
            .expect(ContractError::InvalidAddressFormat.message())
            .try_into()
            .expect(ContractError::InvalidKeyLen.message());

        // 2. Decode base64 signature (64 bytes)
        let sig: [u8; 64] = base64::engine::general_purpose::STANDARD
            .decode(signature)
            .expect(ContractError::InvalidSignatureFormat.message())
            .try_into()
            .expect(ContractError::InvalidSignatureFormat.message());

        // 3. Use raw message bytes (must match exactly what Solana signed)
        let msg = message.as_bytes();

        // 4. Verify signature
        assert!(
            env::ed25519_verify(&sig, msg, &pubkey),
            "{}",
            ContractError::SignatureVerificationFailed.message()
        );
    }

    pub fn internal_verify_tron_signature(
        &self,
        blockchain_address: String, // "41...." hex string
        signature: String,
        message: String,
    ) {
        // Step 1: Get the hash of the constructed message, this hash is what was signed
        let prefix = format!("\x19TRON Signed Message:\n{}", message.len());
        let mut to_hash = Vec::new();
        to_hash.extend(prefix.as_bytes());
        to_hash.extend(message.as_bytes());
        let hash = env::keccak256_array(&to_hash);

        // Step 2: Extract r,s,v components from the signature
        let sig_clean = signature.trim_start_matches("0x");
        let sig_bytes =
            hex::decode(sig_clean).expect(ContractError::InvalidSignatureFormat.message());

        assert!(
            sig_bytes.len() == 65,
            "{}",
            ContractError::InvalidSignatureFormat.message()
        );

        let mut rs = [0u8; 64];
        rs.copy_from_slice(&sig_bytes[0..64]);
        let mut v = sig_bytes[64];
        if v >= 27 {
            v -= 27;
        }

        // Step 3: Recover the public key
        let pubkey_bytes = env::ecrecover(&hash, &rs, v, false)
            .expect(ContractError::SignatureVerificationFailed.message());

        // Step 4: Derive TRON address
        // Ethereum-style hash of pubkey
        let hash_pub = env::keccak256_array(&pubkey_bytes);
        let addr_20 = &hash_pub[12..32]; // last 20 bytes

        // Prepend 0x41
        let mut tron_addr = Vec::with_capacity(21);
        tron_addr.push(0x41);
        tron_addr.extend_from_slice(addr_20);

        // Step 5: Base58Check encode (Tron user-facing address, starts with "T")
        let first = env::sha256(&tron_addr);
        let second = env::sha256(&first);

        let mut addr_with_checksum = tron_addr.clone();
        addr_with_checksum.extend_from_slice(&second[0..4]);

        let recovered_addr = bs58::encode(addr_with_checksum).into_string();

        // Step 5: Verify against provided TRON address
        assert!(
            recovered_addr.eq_ignore_ascii_case(&blockchain_address),
            "{}",
            ContractError::SignatureVerificationFailed.message()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::{testing_env, AccountId};

    fn get_context(predecessor: AccountId) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder.predecessor_account_id(predecessor);
        builder
    }

    /**
     * BTC
     */

    #[test]
    fn test_internal_verify_btc_signature() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address = "mgm2K4RoQsmcvaCyANUGm479hWNfk6bXC9".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());

        let message = "Hello, NEAR!".to_string();
        let signature = "IEimFaFYMNk57Zg9ZMvK59hAyl6RTUC2mpsn/1v2WkjcCjMbvR7XMtyK2GAE+cM9UpMvAI5A89YGPMabuiYMXhs=".to_string();

        contract.internal_verify_btc_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E004: signature verification failed")]
    fn test_internal_verify_btc_signature_wrong_message() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address = "mgm2K4RoQsmcvaCyANUGm479hWNfk6bXC9".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());

        let message = "Hello, Bob!".to_string();

        // This signature was generated for message "Hello, NEAR!"
        let signature = "IEimFaFYMNk57Zg9ZMvK59hAyl6RTUC2mpsn/1v2WkjcCjMbvR7XMtyK2GAE+cM9UpMvAI5A89YGPMabuiYMXhs=".to_string();

        contract.internal_verify_btc_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E004: signature verification failed")]
    fn test_internal_verify_btc_signature_wrong_address() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address = "mgm2K4RoQsmcvaCyANUGm479hWNfk6bXC9".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());

        let message = "Hello, NEAR!".to_string();

        // This signature was generated with address mzQkhVBs6xTptEZzbqD7s4kysTP7s54cJG
        let signature =
            "IKs7s0Nsk0fdHd7dyIRUf77RmAq8vL7am69AbazuxklsVP7vSdqdLWXRoX4mXsHqzBBoNBY15621NDCMT5Xdicg=".to_string();

        contract.internal_verify_btc_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E005: invalid signature format")]
    fn test_internal_verify_btc_signature_invalid_signature() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address = "mgm2K4RoQsmcvaCyANUGm479hWNfk6bXC9".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());

        let message = "Hello, NEAR!".to_string();
        let signature = "abc123".to_string();

        contract.internal_verify_btc_signature(blockchain_address, signature, message);
    }

    /**
     * EVM
     */

    #[test]
    fn test_internal_verify_evm_signature() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address = "0x7286e6950fbdadf6c3f613b781eb6e007f5f1c0a".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());

        let message = "Hello, NEAR!".to_string();
        let signature = "0xc26a320535280363c7caa54fb8ba9a923fa9111dc99310e775d7d9e30a27745f4e23306be095be18fa29193ff17b6e5fc3fbf8bf759ee8b0b8a670fe5ffce22a1c".to_string();

        contract.internal_verify_evm_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E004: signature verification failed")]
    fn test_internal_verify_evm_signature_wrong_message() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address = "0x7286e6950fbdadf6c3f613b781eb6e007f5f1c0a".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());

        let message = "Hello, Bob!".to_string();

        // This signature was generated for message "Hello, NEAR!"
        let signature = "0xc26a320535280363c7caa54fb8ba9a923fa9111dc99310e775d7d9e30a27745f4e23306be095be18fa29193ff17b6e5fc3fbf8bf759ee8b0b8a670fe5ffce22a1c".to_string();

        contract.internal_verify_evm_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E004: signature verification failed")]
    fn test_internal_verify_evm_signature_wrong_address() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address = "0x7286e6950fbdadf6c3f613b781eb6e007f5f1c0a".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());

        let message = "Hello, NEAR!".to_string();

        // This signature was generated with address 0x30fe32f6f345e1fe048e8b2452dc058693d5f736
        let signature =
            "0xccba0dbb0265fd5fb917599e6c45bf409f3b4cc7f3a0ac12b8b1596369b643593d5d985449e0f54621d932d867796fca2526fdb2c072da44d6d9f0419f689dd41c".to_string();

        contract.internal_verify_evm_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E005: invalid signature format")]
    fn test_internal_verify_evm_signature_invalid_signature() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address = "0x7286e6950fbdadf6c3f613b781eb6e007f5f1c0a".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());

        let message = "Hello, NEAR!".to_string();
        let signature = "abc123".to_string();

        contract.internal_verify_evm_signature(blockchain_address, signature, message);
    }

    /**
     * Solana
     */

    #[test]
    fn test_internal_verify_solana_signature() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address = "3pVqCdnjVfqSvb5XcKTh5XVdRc9ftVFEwSRMfD5DwTF5".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());

        let message = "Hello, NEAR!".to_string();
        let signature = "4rNekrB9jANZyy3wWXveCZJKAf2tQX3afNEp8odvXiDr3yBiCXZGkJjibTA9Lvgt9Vcor6b2zJ4sgSAsXHfQZz4d".to_string();

        contract.internal_verify_solana_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E004: signature verification failed")]
    fn test_internal_verify_solana_signature_wrong_message() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address = "3pVqCdnjVfqSvb5XcKTh5XVdRc9ftVFEwSRMfD5DwTF5".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());

        let message = "Hello, Bob!".to_string();
        // This signature was generated for message "Hello, NEAR!"
        let signature = "4rNekrB9jANZyy3wWXveCZJKAf2tQX3afNEp8odvXiDr3yBiCXZGkJjibTA9Lvgt9Vcor6b2zJ4sgSAsXHfQZz4d".to_string();

        contract.internal_verify_solana_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E004: signature verification failed")]
    fn test_internal_verify_solana_signature_wrong_address() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address = "3pVqCdnjVfqSvb5XcKTh5XVdRc9ftVFEwSRMfD5DwTF5".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());
        let message = "Hello, NEAR!".to_string();
        // This signature was generated with address 5rPKwR6HNWfFK4RqghMZjxLNBUFRPKUBSLTmmxjgHqcK
        let signature = "46y9R2juQbQmEAPXmD2GBbrV97vY29CQnjHAXsAg5ydXstZNSJAn34faUE1wjyfZe5KAqwoRx1XXMX3WQTnBAgVD".to_string();

        contract.internal_verify_solana_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E005: invalid signature format")]
    fn test_internal_verify_solana_signature_invalid_signature() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address = "3pVqCdnjVfqSvb5XcKTh5XVdRc9ftVFEwSRMfD5DwTF5".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());

        let message = "Hello, NEAR!".to_string();
        let signature = "abc123".to_string();

        contract.internal_verify_solana_signature(blockchain_address, signature, message);
    }

    /**
     * TON
     */

    #[test]
    fn test_internal_verify_ton_signature() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address =
            "266463e50cd437d2ff2c65f1e23e3898af658e54aa78dfe14b99a82d08b9a28d".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());

        let message = "Hello, NEAR!".to_string();
        let signature = "klZvpjv6sBwqK2awnH4zJ8qXzhsd3zQLEbi1H5bhDE5YiLdzuR5Mq9ubkQN0PbzOGaxqbMjNAeve3mn1SOzjCg==".to_string();

        contract.internal_verify_ton_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E005: invalid signature format")]
    fn test_internal_verify_ton_signature_wrong_message() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address =
            "266463e50cd437d2ff2c65f1e23e3898af658e54aa78dfe14b99a82d08b9a28d".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());

        let message = "Hello, Bob!".to_string();
        // This signature was generated for message "Hello, NEAR!"
        let signature = "0klZvpjv6sBwqK2awnH4zJ8qXzhsd3zQLEbi1H5bhDE5YiLdzuR5Mq9ubkQN0PbzOGaxqbMjNAeve3mn1SOzjCg==".to_string();

        contract.internal_verify_ton_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E004: signature verification failed")]
    fn test_internal_verify_ton_signature_wrong_address() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address =
            "266463e50cd437d2ff2c65f1e23e3898af658e54aa78dfe14b99a82d08b9a28d".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());

        let message = "Hello, NEAR!".to_string();
        // This signature was generated with address dc6c42abca67f8fa03bbdaae828a01b7e085eef21b73774ae9600547a0d41359
        let signature = "KUO7g+6cfhLxG42MkGZ7L7RbOkkakoT8w8iipRig8GAtytUFd7TAg5cacuX6sCcNhQEduyAnafAoYYrFKypdBA==".to_string();

        contract.internal_verify_ton_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E005: invalid signature format")]
    fn test_internal_verify_ton_signature_invalid_signature() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address =
            "266463e50cd437d2ff2c65f1e23e3898af658e54aa78dfe14b99a82d08b9a28d".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());

        let message = "Hello, NEAR!".to_string();
        let signature = "abc123".to_string();

        contract.internal_verify_ton_signature(blockchain_address, signature, message);
    }

    /**
     * Stellar
     */
    #[test]
    fn test_internal_verify_stellar_signature() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address =
            "GAQE5YTNKY5FPRVIASCXOSZGFFRT66ZCZP5VK3HUJFMLHB2FM776Q6VZ".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());

        let message = "Hello, NEAR!".to_string();
        let signature = "0SM41kVz340OeGlBNuXgGA5+X5dQGRBrbEruGWD60oOjfe9tPGTfBTIu1BYGYdQujHkP8aO+FoPzF4YXvz37BA==".to_string();

        contract.internal_verify_stellar_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E004: signature verification failed")]
    fn test_internal_verify_stellar_signature_wrong_message() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address =
            "GAQE5YTNKY5FPRVIASCXOSZGFFRT66ZCZP5VK3HUJFMLHB2FM776Q6VZ".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());

        let message = "Hello, Bob!".to_string();
        // This signature was generated for message "Hello, NEAR!"
        let signature = "0SM41kVz340OeGlBNuXgGA5+X5dQGRBrbEruGWD60oOjfe9tPGTfBTIu1BYGYdQujHkP8aO+FoPzF4YXvz37BA==".to_string();

        contract.internal_verify_stellar_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E004: signature verification failed")]
    fn test_internal_verify_stellar_signature_wrong_address() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address =
            "GAQE5YTNKY5FPRVIASCXOSZGFFRT66ZCZP5VK3HUJFMLHB2FM776Q6VZ".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());

        let message = "Hello, NEAR!".to_string();
        // This signature was generated with address GBE6MUKMOMVN4MJ7USJY3M7BULPB7OXPMZIZDZF2J5FFWW43SZBD7QRT
        let signature = "dpWSJbbY8fm9XJOxN52LdMndqJk4ENybdHMK3q6xdViRIA4+Rm1mbwjuSypzcZkKYuWNTsR/ZGN6z5opxLfJAg==".to_string();

        contract.internal_verify_stellar_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E005: invalid signature format")]
    fn test_internal_verify_stellar_signature_invalid_signature() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address =
            "GAQE5YTNKY5FPRVIASCXOSZGFFRT66ZCZP5VK3HUJFMLHB2FM776Q6VZ".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());

        let message = "Hello, NEAR!".to_string();
        let signature = "abc123".to_string();

        contract.internal_verify_stellar_signature(blockchain_address, signature, message);
    }

    /**
     * TRON
     */

    #[test]
    fn test_internal_verify_tron_signature() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address = "TVhFeq7aXfPQFgcHVKkTqYpYiSjWknWgSc".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());

        let message = "Hello, NEAR!".to_string();
        let signature = "0x265454eecabd6fc9f15f92346685cb80523f06e4687f875858fcc8728d49458429b67ba834ea463e82df16e1e96b0c7f0d70f65f627ef84fd9cd420fd66973ef1c".to_string();

        contract.internal_verify_tron_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E004: signature verification failed")]
    fn test_internal_verify_tron_signature_wrong_message() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address = "TVhFeq7aXfPQFgcHVKkTqYpYiSjWknWgSc".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());

        let message = "Hello, Bob!".to_string();
        // This signature was generated for message "Hello, NEAR!"
        let signature = "0x265454eecabd6fc9f15f92346685cb80523f06e4687f875858fcc8728d49458429b67ba834ea463e82df16e1e96b0c7f0d70f65f627ef84fd9cd420fd66973ef1c".to_string();

        contract.internal_verify_tron_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E004: signature verification failed")]
    fn test_internal_verify_tron_signature_wrong_address() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address = "TVhFeq7aXfPQFgcHVKkTqYpYiSjWknWgSc".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());
        let message = "Hello, NEAR!".to_string();
        // This signature was generated with address TDVZt2PeSJq5FBLNzpQahVSkW5Lkw5G38b
        let signature = "0x52c6bc549c66d0afaa133d7d7e98283506f413b86a585c5573cc6ccace25d38b74505830cd7fc17778acde1891876f59b682d2cd3146c6735e0eb7672ba467801b".to_string();

        contract.internal_verify_tron_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E005: invalid signature format")]
    fn test_internal_verify_tron_signature_invalid_signature() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_address = "TVhFeq7aXfPQFgcHVKkTqYpYiSjWknWgSc".to_string();
        let code_hash: Vec<u8> = CryptoHash::default().into();

        let contract = FactoryContract::new(accounts(0).into(), code_hash.into());

        let message = "Hello, NEAR!".to_string();
        let signature = "abc123".to_string();

        contract.internal_verify_tron_signature(blockchain_address, signature, message);
    }
}
