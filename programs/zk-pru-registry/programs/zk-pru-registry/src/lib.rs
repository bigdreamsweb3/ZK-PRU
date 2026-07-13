use anchor_lang::prelude::*;

pub mod constants;
pub mod errors;
pub mod instructions;
pub mod state;

use instructions::*;

declare_id!("4hHyXGEzu8EcWrkka8A1YTzw9dGtTZYbg4N7PGoSdb3j");

#[program]
pub mod zk_pru_registry {
    use super::*;

    pub fn initialize_registry(ctx: Context<InitializeRegistry>) -> Result<()> {
        instructions::initialize_registry(ctx)
    }

    pub fn create_owner_vault(
        ctx: Context<CreateOwnerVault>,
        owner_commitment: [u8; 32],
        encrypted_master_seed_blob_hash: [u8; 32],
        encrypted_master_seed_blob: Vec<u8>,
        pru_commitment_root: [u8; 32],
        metadata_commitment: [u8; 32],
    ) -> Result<()> {
        instructions::create_owner_vault(
            ctx,
            owner_commitment,
            encrypted_master_seed_blob_hash,
            encrypted_master_seed_blob,
            pru_commitment_root,
            metadata_commitment,
        )
    }

    pub fn update_encrypted_seed_blob(
        ctx: Context<UpdateEncryptedSeedBlob>,
        encrypted_master_seed_blob_hash: [u8; 32],
        encrypted_master_seed_blob: Vec<u8>,
    ) -> Result<()> {
        instructions::update_encrypted_seed_blob(
            ctx,
            encrypted_master_seed_blob_hash,
            encrypted_master_seed_blob,
        )
    }

    pub fn update_pru_commitment_root(
        ctx: Context<UpdatePruCommitmentRoot>,
        pru_commitment_root: [u8; 32],
        metadata_commitment: [u8; 32],
    ) -> Result<()> {
        instructions::update_pru_commitment_root(ctx, pru_commitment_root, metadata_commitment)
    }

    pub fn register_capability_commitment(
        ctx: Context<RegisterCapabilityCommitment>,
        capability_commitment: [u8; 32],
        purpose_type_hash: [u8; 32],
        stable_unit_hash: [u8; 32],
        expiry_epoch: u64,
        current_epoch: u64,
    ) -> Result<()> {
        instructions::register_capability_commitment(
            ctx,
            capability_commitment,
            purpose_type_hash,
            stable_unit_hash,
            expiry_epoch,
            current_epoch,
        )
    }

    pub fn revoke_capability_commitment(ctx: Context<RevokeCapabilityCommitment>) -> Result<()> {
        instructions::revoke_capability_commitment(ctx)
    }
}
