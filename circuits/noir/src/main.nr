// ZK-PRU ownership + action-binding circuit — Noir (canonical implementation)
//
// Implements the full constraint set from docs/06-zk-proofs.md:
//   identity_seed        = Poseidon(wallet_address, identity_signature)
//   PRU_seed             = Poseidon(identity_seed, context_id, vault_signature)
//   commitment_hash      == Poseidon(PRU_seed)
//   PRU                  == Poseidon(PRU_seed, i)
//   action_commitment    == Poseidon(PRU_seed, action_payload_hash)
//
// identity_signature and vault_signature are produced by signing EIP-712
// typed data bound to the deployed registry contract's address (see
// docs/03-identity-model.md) — that binding happens client-side, before
// the signature ever becomes a circuit input; the circuit itself just
// treats both as opaque field elements.
//
// action_payload_hash/action_commitment bind a proof to one specific
// action (see docs/06-zk-proofs.md, "Binding a proof to a specific
// action"). For a pure login with no on-chain effect to bind, pass
// action_payload_hash = 0 and compute action_commitment accordingly.
//
// Private inputs (witness, never revealed): wallet_address,
// identity_signature, vault_signature, context_id, i
// Public inputs (visible to verifier): commitment_hash, pru,
// action_payload_hash

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
    // Values here are placeholders — replace with real field elements
    // computed via sdk/identity.ts + sdk/pru.ts during integration
    // testing, per CODEX_PROMPT.md deliverable 3(a).
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
    // Tampering with any single private input (here: vault_signature)
    // must invalidate the proof — per CODEX_PROMPT.md deliverable 3(b).
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
    // Tampering with any public input must invalidate the proof — per
    // CODEX_PROMPT.md deliverable 3(c).
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
    // A proof generated for one action_payload_hash must fail if
    // resubmitted against a different one — this is the concrete
    // replay/front-running protection described in docs/06-zk-proofs.md.
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
    // action_commitment computed for the ORIGINAL action...
    let action_commitment = poseidon::bn254::hash_2([pru_seed, original_action]);

    // ...but submitted against a DIFFERENT action_payload_hash. Must fail.
    main(wallet_address, identity_signature, vault_signature, context_id, i, commitment_hash, pru, different_action, action_commitment);
}
