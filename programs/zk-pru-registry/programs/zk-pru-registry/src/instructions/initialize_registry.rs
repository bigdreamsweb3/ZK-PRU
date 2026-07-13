use anchor_lang::prelude::*;

use crate::{constants::*, state::*};

#[derive(Accounts)]
pub struct InitializeRegistry<'info> {
    #[account(
        init,
        payer = authority,
        space = ZkPruRegistryConfig::SPACE,
        seeds = [REGISTRY_CONFIG_SEED],
        bump
    )]
    pub registry_config: Account<'info, ZkPruRegistryConfig>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn initialize_registry(ctx: Context<InitializeRegistry>) -> Result<()> {
    let registry_config = &mut ctx.accounts.registry_config;
    registry_config.authority = ctx.accounts.authority.key();
    registry_config.registry_version = REGISTRY_VERSION;
    registry_config.bump = ctx.bumps.registry_config;
    Ok(())
}
