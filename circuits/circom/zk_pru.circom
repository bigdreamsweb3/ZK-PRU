// ZK-PRU ownership + action-binding circuit — Circom (ported equivalent of circuits/noir/src/main.nr)
//
// Implements the same constraints as the Noir canonical circuit, per
// docs/06-zk-proofs.md, including action-binding for replay/front-running
// protection. Pick one circuit as canonical per deployment and treat
// the other as an audited port, not a second source of truth.

pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";

template ZKPRU() {
    // Private inputs
    signal input wallet_address;
    signal input identity_signature;
    signal input vault_signature;
    signal input context_id;
    signal input i;

    // Public inputs
    signal input commitment_hash;
    signal input pru;
    signal input action_payload_hash;
    signal input action_commitment;

    // identity_seed = Poseidon(wallet_address, identity_signature)
    component identitySeedHasher = Poseidon(2);
    identitySeedHasher.inputs[0] <== wallet_address;
    identitySeedHasher.inputs[1] <== identity_signature;
    signal identity_seed;
    identity_seed <== identitySeedHasher.out;

    // pru_seed = Poseidon(identity_seed, context_id, vault_signature)
    component pruSeedHasher = Poseidon(3);
    pruSeedHasher.inputs[0] <== identity_seed;
    pruSeedHasher.inputs[1] <== context_id;
    pruSeedHasher.inputs[2] <== vault_signature;
    signal pru_seed;
    pru_seed <== pruSeedHasher.out;

    // commitment_hash == Poseidon(pru_seed)
    component commitmentHasher = Poseidon(1);
    commitmentHasher.inputs[0] <== pru_seed;
    commitment_hash === commitmentHasher.out;

    // pru == Poseidon(pru_seed, i)
    component pruHasher = Poseidon(2);
    pruHasher.inputs[0] <== pru_seed;
    pruHasher.inputs[1] <== i;
    pru === pruHasher.out;

    // action_commitment == Poseidon(pru_seed, action_payload_hash)
    // Binds this proof to one specific action — a proof valid for one
    // action_payload_hash will fail verification against any other.
    // For a pure login with no on-chain effect, pass action_payload_hash = 0.
    component actionHasher = Poseidon(2);
    actionHasher.inputs[0] <== pru_seed;
    actionHasher.inputs[1] <== action_payload_hash;
    action_commitment === actionHasher.out;
}

component main { public [commitment_hash, pru, action_payload_hash, action_commitment] } = ZKPRU();
