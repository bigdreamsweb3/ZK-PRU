/**
 * Mock proving/verifying backend — for tests only. Simulates a ZK
 * backend by checking the same four constraints a real circuit would
 * enforce (docs/06-zk-proofs.md), without any actual proof compression.
 * Swap for a real Noir (bb.js) or Circom (snarkjs) backend in
 * production — see circuits/README.md.
 */
import { hash1, hash2, hash3 } from "./poseidon.js";
import type { CircuitWitness, ProverBackend, VerifierBackend } from "./verify.js";
import type { FieldElement, Public } from "./types.js";

interface MockProofPayload {
  identitySeed: FieldElement;
  pruSeed: FieldElement;
  commitmentHash: FieldElement;
  pru: FieldElement;
  actionCommitment: FieldElement;
}

function encodeProof(payload: MockProofPayload): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    identitySeed: payload.identitySeed.toString(),
    pruSeed: payload.pruSeed.toString(),
    commitmentHash: payload.commitmentHash.toString(),
    pru: payload.pru.toString(),
    actionCommitment: payload.actionCommitment.toString(),
  }));
}

function decodeProof(proof: Uint8Array): MockProofPayload {
  const raw = JSON.parse(new TextDecoder().decode(proof));
  return {
    identitySeed: BigInt(raw.identitySeed),
    pruSeed: BigInt(raw.pruSeed),
    commitmentHash: BigInt(raw.commitmentHash),
    pru: BigInt(raw.pru),
    actionCommitment: BigInt(raw.actionCommitment),
  };
}

export class MockProver implements ProverBackend {
  async prove(witness: CircuitWitness): Promise<Uint8Array> {
    const identitySeed = hash2(witness.walletAddress, witness.identitySignature);
    const pruSeed = hash3(identitySeed, witness.contextId, witness.vaultSignature);
    const expectedCommitment = hash1(pruSeed);
    const expectedPru = hash2(pruSeed, witness.index);
    const expectedActionCommitment = hash2(pruSeed, witness.actionPayloadHash);

    // A real circuit would reject an invalid witness at proving time
    // (or produce a proof that fails verification). We replicate that
    // by refusing to produce a proof for an inconsistent witness.
    if (
      expectedCommitment !== witness.commitmentHash ||
      expectedPru !== witness.pru ||
      expectedActionCommitment !== witness.actionCommitment
    ) {
      throw new Error("Witness does not satisfy circuit constraints.");
    }

    return encodeProof({
      identitySeed,
      pruSeed,
      commitmentHash: expectedCommitment,
      pru: expectedPru,
      actionCommitment: expectedActionCommitment,
    });
  }
}

export class MockVerifier implements VerifierBackend {
  async verify(
    proof: Uint8Array,
    publicInputs: {
      commitmentHash: Public<FieldElement>;
      pru: Public<FieldElement>;
      actionPayloadHash: Public<FieldElement>;
      actionCommitment: Public<FieldElement>;
    }
  ): Promise<boolean> {
    try {
      const payload = decodeProof(proof);
      // Recompute what actionCommitment SHOULD be for the
      // caller-supplied actionPayloadHash, using the pruSeed implied
      // by the proof, and check it matches what the caller submitted.
      // This is what actually rejects a proof replayed against a
      // different action — see docs/06-zk-proofs.md.
      const expectedActionCommitment = hash2(payload.pruSeed, publicInputs.actionPayloadHash);
      return (
        payload.commitmentHash === publicInputs.commitmentHash &&
        payload.pru === publicInputs.pru &&
        payload.actionCommitment === publicInputs.actionCommitment &&
        expectedActionCommitment === publicInputs.actionCommitment
      );
    } catch {
      return false;
    }
  }
}
