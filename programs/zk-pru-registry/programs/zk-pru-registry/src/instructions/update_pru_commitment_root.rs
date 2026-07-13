use anchor_lang::prelude::*;

use crate::{errors::ZkPruRegistryError, instructions::is_zero_commitment, state::*};

#[derive(Accounts)]
pub struct UpdatePruCommitmentRoot<'info> {
    #[account(mut, has_one = authority)]
    pub owner_vault: Account<'info, ZkPruOwnerVault>,

    pub authority: Signer<'info>,
}

pub fn update_pru_commitment_root(
    ctx: Context<UpdatePruCommitmentRoot>,
    pru_commitment_root: [u8; 32],
    metadata_commitment: [u8; 32],
) -> Result<()> {
    require!(!is_zero_commitment(&pru_commitment_root), ZkPruRegistryError::EmptyCommitment);

    let owner_vault = &mut ctx.accounts.owner_vault;
    owner_vault.pru_commitment_root = pru_commitment_root;
    owner_vault.metadata_commitment = metadata_commitment;
    owner_vault.updated_at = Clock::get()?.unix_timestamp;

    Ok(())
}
