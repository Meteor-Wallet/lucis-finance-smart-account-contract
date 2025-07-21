#[derive(Debug)]
pub enum ContractError {
    UnsupportedBlockchain, // E001
    InvalidAddressFormat,    // E002
    InvalidKeyLen,    // E003
    SignatureVerificationFailed, // E004
    InvalidSignatureFormat, // E005
    LinkedAddressAlreadyExists, // E006
    InvalidNewPublicKeyFormat, // E007
    UnauthorizedRecoveryAddress, // E008
    InvalidOldPublicKeyFormat, // E009
}

impl ContractError {
    pub fn message(&self) -> &'static str {
        match self {
            ContractError::UnsupportedBlockchain => "E001: unsupported blockchain",
            ContractError::InvalidAddressFormat    => "E002: invalid address format",
            ContractError::InvalidKeyLen    => "E003: invalid public key length",
            ContractError::SignatureVerificationFailed => "E004: signature verification failed",
            ContractError::InvalidSignatureFormat => "E005: invalid signature format",
            ContractError::LinkedAddressAlreadyExists => "E006: linked address already exists",
            ContractError::InvalidNewPublicKeyFormat => "E007: invalid public key format",
            ContractError::UnauthorizedRecoveryAddress => "E008: unauthorized recovery address",
            ContractError::InvalidOldPublicKeyFormat => "E009: invalid old public key format",
        }
    }
}