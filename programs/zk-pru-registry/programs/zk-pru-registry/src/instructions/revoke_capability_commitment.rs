use anchor_lang::prelude::*;

use crate::{errors::ZkPruRegistryError, state::*};

#[derive(Accounts)]
pub struct RevokeCapabilityCommitment<'info> {
    #[account(has_one = authority)]
    pub owner_vault: Account<'info, ZkPruOwnerVault>,

    #[account(
        mut,
        constraint = capability_record.owner_vault == owner_vault.key()
    )]
    pub capability_record: Account<'info, ZkPruCapabilityRecord>,

    pub authority: Signer<'info>,
}

pub fn revoke_capability_commitment(ctx: Context<RevokeCapabilityCommitment>) -> Result<()> {
    let capability_record = &mut ctx.accounts.capability_record;
    require!(!capability_record.revoked, ZkPruRegistryError::CapabilityAlreadyRevoked);
    capability_record.revoked = true;
    Ok(())
}
