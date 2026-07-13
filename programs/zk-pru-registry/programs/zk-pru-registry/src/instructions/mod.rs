pub mod create_owner_vault;
pub mod initialize_registry;
pub mod register_capability_commitment;
pub mod revoke_capability_commitment;
pub mod update_encrypted_seed_blob;
pub mod update_pru_commitment_root;

pub use create_owner_vault::*;
pub use initialize_registry::*;
pub use register_capability_commitment::*;
pub use revoke_capability_commitment::*;
pub use update_encrypted_seed_blob::*;
pub use update_pru_commitment_root::*;

pub fn is_zero_commitment(value: &[u8; 32]) -> bool {
    value.iter().all(|byte| *byte == 0)
}
