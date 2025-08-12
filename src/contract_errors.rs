#[derive(Debug)]
pub enum ContractError {
    UnsupportedBlockchain,           // E001
    InvalidAddressFormat,            // E002
    InvalidKeyLen,                   // E003
    SignatureVerificationFailed,     // E004
    InvalidSignatureFormat,          // E005
    LinkedAddressAlreadyExists,      // E006
    InvalidNewPublicKeyFormat,       // E007
    UnauthorizedCrossChainAccessKey, // E008
    InvalidOldPublicKeyFormat,       // E009
    FailedToCalculateRemainingGas,   // E010
    NotEnoughGasLeft,                // E011
    CannotCallFunctionOnSelf,        // E012
    CannotGrantAccessKeyToSelf,      // E013
    ContractUninitialized,           // E014
}

impl ContractError {
    pub fn message(&self) -> &'static str {
        match self {
            ContractError::UnsupportedBlockchain => "E001: unsupported blockchain",
            ContractError::InvalidAddressFormat => "E002: invalid address format",
            ContractError::InvalidKeyLen => "E003: invalid public key length",
            ContractError::SignatureVerificationFailed => "E004: signature verification failed",
            ContractError::InvalidSignatureFormat => "E005: invalid signature format",
            ContractError::LinkedAddressAlreadyExists => "E006: linked address already exists",
            ContractError::InvalidNewPublicKeyFormat => "E007: invalid public key format",
            ContractError::UnauthorizedCrossChainAccessKey => {
                "E008: unauthorized cross-chain access key"
            }
            ContractError::InvalidOldPublicKeyFormat => "E009: invalid old public key format",
            ContractError::FailedToCalculateRemainingGas => {
                "E010: failed to calculate remaining gas"
            }
            ContractError::NotEnoughGasLeft => "E011: not enough gas left",
            ContractError::CannotCallFunctionOnSelf => "E012: cannot call function on self",
            ContractError::CannotGrantAccessKeyToSelf => "E013: cannot grant access key to self",
            ContractError::ContractUninitialized => "E014: contract uninitialized",
        }
    }
}
