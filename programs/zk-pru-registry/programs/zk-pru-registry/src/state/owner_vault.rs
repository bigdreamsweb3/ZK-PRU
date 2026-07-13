use anchor_lang::prelude::*;

use crate::constants::MAX_ENCRYPTED_SEED_BLOB_BYTES;

#[account]
pub struct ZkPruOwnerVault {
    pub authority: Pubkey,
    pub owner_commitment: [u8; 32],
    pub encrypted_master_seed_blob_hash: [u8; 32],
    pub encrypted_master_seed_blob: Vec<u8>,
    pub pru_commitment_root: [u8; 32],
    pub metadata_commitment: [u8; 32],
    pub created_at: i64,
    pub updated_at: i64,
    pub bump: u8,
}

impl ZkPruOwnerVault {
    pub const SPACE: usize = 8
        + 32
        + 32
        + 32
        + 4 + MAX_ENCRYPTED_SEED_BLOB_BYTES
        + 32
        + 32
        + 8
        + 8
        + 1;
}
