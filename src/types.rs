use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::json_types::Base64VecU8;
use near_sdk::{near, PublicKey};

pub type Nonce = u64;
pub type BlockchainId = String;
pub type BlockchainAddress = String;

#[derive(BorshDeserialize, BorshSerialize)]
pub struct RecoveryKey {
    pub blockchain: BlockchainId,
    pub address: BlockchainAddress,
    pub nonce: Nonce,
}

#[near(serializers = [json, borsh])]
pub struct LinkInfo {
    /// The linked Ethereum address (20 bytes).
    eth_address: Vec<String>,
    /// The NEAR public key of the account at the time of linking (for recovery purposes).
    near_pk: PublicKey,
    nonce: u64,
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
