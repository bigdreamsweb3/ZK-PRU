use anchor_lang::prelude::*;

#[error_code]
pub enum ZkPruRegistryError {
    #[msg("Commitment value cannot be all zero bytes")]
    EmptyCommitment,
    #[msg("Encrypted seed blob cannot be empty")]
    EmptyEncryptedSeedBlob,
    #[msg("Encrypted seed blob exceeds the maximum supported size")]
    EncryptedSeedBlobTooLarge,
    #[msg("Capability expiry epoch must be greater than the current epoch")]
    InvalidCapabilityExpiry,
    #[msg("Capability record has already been revoked")]
    CapabilityAlreadyRevoked,
}
