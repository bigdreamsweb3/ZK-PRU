use anchor_lang::prelude::*;

#[account]
pub struct ZkPruRegistryConfig {
    pub authority: Pubkey,
    pub registry_version: u16,
    pub bump: u8,
}

impl ZkPruRegistryConfig {
    pub const SPACE: usize = 8 + 32 + 2 + 1;
}
