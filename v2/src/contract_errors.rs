#[derive(Debug)]
pub enum ContractError {
    UnsupportedBlockchain,           // E001
    InvalidAddressFormat,            // E002
    InvalidKeyLen,                   // E003
    SignatureVerificationFailed,     // E004
    InvalidSignatureFormat,          // E005
    UnauthorizedCrossChainAccessKey, // E008
    NotEnoughGasLeft,                // E011
    CannotGrantAccessKeyToSelf,      // E013
    ContractUninitialized,           // E014
    EmptyTransaction,                // E016
    ActionNotAllowed,                // E018
    ReadStateFailed,                 // E023
    UnexpectedPromiseResultCount,    // E024
    UnexpectedPromiseFailure,        // E025
    NoUpgradeAvailable,              // E026
    NonceNearlyExhausted,            // E027
    InvalidMessageLen,               // E029
    CanNotRevokeSelf,                // E036
}

impl ContractError {
    pub fn message(&self) -> &'static str {
        match self {
            ContractError::UnsupportedBlockchain => "E001: unsupported blockchain",
            ContractError::InvalidAddressFormat => "E002: invalid address format",
            ContractError::InvalidKeyLen => "E003: invalid public key length",
            ContractError::SignatureVerificationFailed => "E004: signature verification failed",
            ContractError::InvalidSignatureFormat => "E005: invalid signature format",
            ContractError::UnauthorizedCrossChainAccessKey => {
                "E008: unauthorized cross-chain access key"
            }
            ContractError::NotEnoughGasLeft => "E011: not enough gas left",
            ContractError::CannotGrantAccessKeyToSelf => "E013: cannot grant access key to self",
            ContractError::ContractUninitialized => "E014: contract uninitialized",
            ContractError::EmptyTransaction => "E016: empty transaction",
            ContractError::ActionNotAllowed => "E018: action not allowed",
            ContractError::ReadStateFailed => "E023: read state failed",
            ContractError::UnexpectedPromiseResultCount => "E024: unexpected promise result count",
            ContractError::UnexpectedPromiseFailure => "E025: unexpected promise failure",
            ContractError::NoUpgradeAvailable => "E026: no upgrade available",
            ContractError::NonceNearlyExhausted => "E027: nonce nearly exhausted, the last few usable nonce need to be reserved for adding new keys",
            ContractError::InvalidMessageLen => "E029: invalid message length",
            ContractError::CanNotRevokeSelf => "E036: cannot revoke the access key that is used to sign the message",
        }
    }
}
