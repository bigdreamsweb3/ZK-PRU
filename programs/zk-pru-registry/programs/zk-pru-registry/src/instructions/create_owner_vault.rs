use anchor_lang::prelude::*;

use crate::{
    constants::*,
    errors::ZkPruRegistryError,
    instructions::is_zero_commitment,
    state::*,
};

#[derive(Accounts)]
#[instruction(owner_commitment: [u8; 32])]
pub struct CreateOwnerVault<'info> {
    #[account(
        init,
        payer = authority,
        space = ZkPruOwnerVault::SPACE,
        seeds = [OWNER_VAULT_SEED, owner_commitment.as_ref()],
        bump
    )]
    pub owner_vault: Account<'info, ZkPruOwnerVault>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn create_owner_vault(
    ctx: Context<CreateOwnerVault>,
    owner_commitment: [u8; 32],
    encrypted_master_seed_blob_hash: [u8; 32],
    encrypted_master_seed_blob: Vec<u8>,
    pru_commitment_root: [u8; 32],
    metadata_commitment: [u8; 32],
) -> Result<()> {
    require!(!is_zero_commitment(&owner_commitment), ZkPruRegistryError::EmptyCommitment);
    require!(
        !is_zero_commitment(&encrypted_master_seed_blob_hash),
        ZkPruRegistryError::EmptyCommitment
    );
    require!(!is_zero_commitment(&pru_commitment_root), ZkPruRegistryError::EmptyCommitment);
    require!(!encrypted_master_seed_blob.is_empty(), ZkPruRegistryError::EmptyEncryptedSeedBlob);
    require!(
        encrypted_master_seed_blob.len() <= MAX_ENCRYPTED_SEED_BLOB_BYTES,
        ZkPruRegistryError::EncryptedSeedBlobTooLarge
    );

    let now = Clock::get()?.unix_timestamp;
    let owner_vault = &mut ctx.accounts.owner_vault;
    owner_vault.authority = ctx.accounts.authority.key();
    owner_vault.owner_commitment = owner_commitment;
    owner_vault.encrypted_master_seed_blob_hash = encrypted_master_seed_blob_hash;
    owner_vault.encrypted_master_seed_blob = encrypted_master_seed_blob;
    owner_vault.pru_commitment_root = pru_commitment_root;
    owner_vault.metadata_commitment = metadata_commitment;
    owner_vault.created_at = now;
    owner_vault.updated_at = now;
    owner_vault.bump = ctx.bumps.owner_vault;

    Ok(())
}
