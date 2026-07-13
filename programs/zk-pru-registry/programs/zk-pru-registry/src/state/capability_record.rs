use anchor_lang::prelude::*;

#[account]
pub struct ZkPruCapabilityRecord {
    pub owner_vault: Pubkey,
    pub capability_commitment: [u8; 32],
    pub purpose_type_hash: [u8; 32],
    pub stable_unit_hash: [u8; 32],
    pub expiry_epoch: u64,
    pub revoked: bool,
    pub bump: u8,
}

impl ZkPruCapabilityRecord {
    pub const SPACE: usize = 8 + 32 + 32 + 32 + 32 + 8 + 1 + 1;
}
