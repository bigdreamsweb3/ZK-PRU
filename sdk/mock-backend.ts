/**
 * Test proving/verifying backend.
 *
 * This is only for SDK tests. It checks the same public constraints as the
 * current master-seed circuit witness, but it is not a production proof system.
 */
import { hash1, hash2, hash3, stringToField } from "./poseidon.js";
import type { CircuitWitness, ProverBackend, VerifierBackend } from "./verify.js";
import type { FieldElement, Public } from "./types.js";

interface MockProofPayload {
  pruSeed: FieldElement;
  commitmentHash: FieldElement;
  pru: FieldElement;
  actionCommitment: FieldElement;
}

function encodeProof(payload: MockProofPayload): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    pruSeed: payload.pruSeed.toString(),
    commitmentHash: payload.commitmentHash.toString(),
    pru: payload.pru.toString(),
    actionCommitment: payload.actionCommitment.toString(),
  }));
}

function decodeProof(proof: Uint8Array): MockProofPayload {
  const raw = JSON.parse(new TextDecoder().decode(proof));
  return {
    pruSeed: BigInt(raw.pruSeed),
    commitmentHash: BigInt(raw.commitmentHash),
    pru: BigInt(raw.pru),
    actionCommitment: BigInt(raw.actionCommitment),
  };
}

export class MockProver implements ProverBackend {
  async prove(witness: CircuitWitness): Promise<Uint8Array> {
    const userSecretNamespace = hash2(witness.masterSeed, stringToField("ZK_PRU_USER_NAMESPACE_V1"));
    const pruSeed = hash3(userSecretNamespace, witness.protocolId, witness.purpose);
    const expectedCommitment = hash1(pruSeed);
    const expectedPru = hash2(pruSeed, witness.index);
    const expectedActionCommitment = hash2(pruSeed, witness.actionPayloadHash);

    if (
      expectedCommitment !== witness.commitmentHash ||
      expectedPru !== witness.pru ||
      expectedActionCommitment !== witness.actionCommitment
    ) {
      throw new Error("Witness does not satisfy circuit constraints.");
    }

    return encodeProof({
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
      const expectedCommitment = hash1(payload.pruSeed);
      const expectedActionCommitment = hash2(payload.pruSeed, publicInputs.actionPayloadHash);

      return (
        payload.commitmentHash === publicInputs.commitmentHash &&
        expectedCommitment === publicInputs.commitmentHash &&
        payload.pru === publicInputs.pru &&
        payload.actionCommitment === publicInputs.actionCommitment &&
        expectedActionCommitment === publicInputs.actionCommitment
      );
    } catch {
      return false;
    }
  }
}
