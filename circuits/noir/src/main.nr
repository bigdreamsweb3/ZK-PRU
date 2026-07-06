// ZK-PRU ownership + action-binding circuit - Noir canonical implementation.
//
// Constraint set:
//   identity_seed     = Poseidon(wallet_address, identity_signature)
//   PRU_seed          = Poseidon(identity_seed, context_id, vault_signature)
//   commitment_hash   == Poseidon(PRU_seed)
//   PRU               == Poseidon(PRU_seed, i)
//   action_commitment == Poseidon(PRU_seed, action_payload_hash)
//
// identity_signature and vault_signature are produced by signing canonical
// Solana messages bound to the registry program ID. That binding happens
// before the signature becomes a circuit input.

use std::hash::poseidon;

fn main(
    wallet_address: Field,
    identity_signature: Field,
    vault_signature: Field,
    context_id: Field,
    i: Field,
    commitment_hash: pub Field,
    pru: pub Field,
    action_payload_hash: pub Field,
    action_commitment: pub Field
) {
    let identity_seed = poseidon::bn254::hash_2([wallet_address, identity_signature]);
    let pru_seed = poseidon::bn254::hash_3([identity_seed, context_id, vault_signature]);

    assert(commitment_hash == poseidon::bn254::hash_1([pru_seed]));
    assert(pru == poseidon::bn254::hash_2([pru_seed, i]));
    assert(action_commitment == poseidon::bn254::hash_2([pru_seed, action_payload_hash]));
}

#[test]
fn test_valid_witness_passes() {
    let wallet_address = 111;
    let identity_signature = 222;
    let vault_signature = 333;
    let context_id = 444;
    let i = 0;
    let action_payload_hash = 555;

    let identity_seed = poseidon::bn254::hash_2([wallet_address, identity_signature]);
    let pru_seed = poseidon::bn254::hash_3([identity_seed, context_id, vault_signature]);
    let commitment_hash = poseidon::bn254::hash_1([pru_seed]);
    let pru = poseidon::bn254::hash_2([pru_seed, i]);
    let action_commitment = poseidon::bn254::hash_2([pru_seed, action_payload_hash]);

    main(wallet_address, identity_signature, vault_signature, context_id, i, commitment_hash, pru, action_payload_hash, action_commitment);
}

#[test(should_fail)]
fn test_tampered_private_input_fails() {
    let wallet_address = 111;
    let identity_signature = 222;
    let real_vault_signature = 333;
    let tampered_vault_signature = 999;
    let context_id = 444;
    let i = 0;
    let action_payload_hash = 555;

    let identity_seed = poseidon::bn254::hash_2([wallet_address, identity_signature]);
    let pru_seed = poseidon::bn254::hash_3([identity_seed, context_id, real_vault_signature]);
    let commitment_hash = poseidon::bn254::hash_1([pru_seed]);
    let pru = poseidon::bn254::hash_2([pru_seed, i]);
    let action_commitment = poseidon::bn254::hash_2([pru_seed, action_payload_hash]);

    main(wallet_address, identity_signature, tampered_vault_signature, context_id, i, commitment_hash, pru, action_payload_hash, action_commitment);
}

#[test(should_fail)]
fn test_tampered_public_commitment_fails() {
    let wallet_address = 111;
    let identity_signature = 222;
    let vault_signature = 333;
    let context_id = 444;
    let i = 0;
    let action_payload_hash = 555;

    let identity_seed = poseidon::bn254::hash_2([wallet_address, identity_signature]);
    let pru_seed = poseidon::bn254::hash_3([identity_seed, context_id, vault_signature]);
    let pru = poseidon::bn254::hash_2([pru_seed, i]);
    let action_commitment = poseidon::bn254::hash_2([pru_seed, action_payload_hash]);
    let wrong_commitment_hash = 0;

    main(wallet_address, identity_signature, vault_signature, context_id, i, wrong_commitment_hash, pru, action_payload_hash, action_commitment);
}

#[test(should_fail)]
fn test_proof_cannot_be_replayed_against_different_action() {
    let wallet_address = 111;
    let identity_signature = 222;
    let vault_signature = 333;
    let context_id = 444;
    let i = 0;
    let original_action = 555;
    let different_action = 777;

    let identity_seed = poseidon::bn254::hash_2([wallet_address, identity_signature]);
    let pru_seed = poseidon::bn254::hash_3([identity_seed, context_id, vault_signature]);
    let commitment_hash = poseidon::bn254::hash_1([pru_seed]);
    let pru = poseidon::bn254::hash_2([pru_seed, i]);
    let action_commitment = poseidon::bn254::hash_2([pru_seed, original_action]);

    main(wallet_address, identity_signature, vault_signature, context_id, i, commitment_hash, pru, different_action, action_commitment);
}
