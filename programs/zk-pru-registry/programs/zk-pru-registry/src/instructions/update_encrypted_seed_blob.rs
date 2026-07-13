use anchor_lang::prelude::*;

use crate::{
    constants::MAX_ENCRYPTED_SEED_BLOB_BYTES,
    errors::ZkPruRegistryError,
    instructions::is_zero_commitment,
    state::*,
};

#[derive(Accounts)]
pub struct UpdateEncryptedSeedBlob<'info> {
    #[account(mut, has_one = authority)]
    pub owner_vault: Account<'info, ZkPruOwnerVault>,

    pub authority: Signer<'info>,
}

pub fn update_encrypted_seed_blob(
    ctx: Context<UpdateEncryptedSeedBlob>,
    encrypted_master_seed_blob_hash: [u8; 32],
    encrypted_master_seed_blob: Vec<u8>,
) -> Result<()> {
    require!(
        !is_zero_commitment(&encrypted_master_seed_blob_hash),
        ZkPruRegistryError::EmptyCommitment
    );
    require!(!encrypted_master_seed_blob.is_empty(), ZkPruRegistryError::EmptyEncryptedSeedBlob);
    require!(
        encrypted_master_seed_blob.len() <= MAX_ENCRYPTED_SEED_BLOB_BYTES,
        ZkPruRegistryError::EncryptedSeedBlobTooLarge
    );

    let owner_vault = &mut ctx.accounts.owner_vault;
    owner_vault.encrypted_master_seed_blob_hash = encrypted_master_seed_blob_hash;
    owner_vault.encrypted_master_seed_blob = encrypted_master_seed_blob;
    owner_vault.updated_at = Clock::get()?.unix_timestamp;

    Ok(())
}
