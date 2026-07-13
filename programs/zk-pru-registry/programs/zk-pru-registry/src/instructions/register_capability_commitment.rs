use anchor_lang::prelude::*;

use crate::{
    constants::CAPABILITY_RECORD_SEED,
    errors::ZkPruRegistryError,
    instructions::is_zero_commitment,
    state::*,
};

#[derive(Accounts)]
#[instruction(capability_commitment: [u8; 32])]
pub struct RegisterCapabilityCommitment<'info> {
    #[account(has_one = authority)]
    pub owner_vault: Account<'info, ZkPruOwnerVault>,

    #[account(
        init,
        payer = authority,
        space = ZkPruCapabilityRecord::SPACE,
        seeds = [
            CAPABILITY_RECORD_SEED,
            owner_vault.key().as_ref(),
            capability_commitment.as_ref()
        ],
        bump
    )]
    pub capability_record: Account<'info, ZkPruCapabilityRecord>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn register_capability_commitment(
    ctx: Context<RegisterCapabilityCommitment>,
    capability_commitment: [u8; 32],
    purpose_type_hash: [u8; 32],
    stable_unit_hash: [u8; 32],
    expiry_epoch: u64,
    current_epoch: u64,
) -> Result<()> {
    require!(!is_zero_commitment(&capability_commitment), ZkPruRegistryError::EmptyCommitment);
    require!(!is_zero_commitment(&purpose_type_hash), ZkPruRegistryError::EmptyCommitment);
    require!(!is_zero_commitment(&stable_unit_hash), ZkPruRegistryError::EmptyCommitment);
    require!(expiry_epoch > current_epoch, ZkPruRegistryError::InvalidCapabilityExpiry);

    let capability_record = &mut ctx.accounts.capability_record;
    capability_record.owner_vault = ctx.accounts.owner_vault.key();
    capability_record.capability_commitment = capability_commitment;
    capability_record.purpose_type_hash = purpose_type_hash;
    capability_record.stable_unit_hash = stable_unit_hash;
    capability_record.expiry_epoch = expiry_epoch;
    capability_record.revoked = false;
    capability_record.bump = ctx.bumps.capability_record;

    Ok(())
}
