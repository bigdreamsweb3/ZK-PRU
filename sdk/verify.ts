/**
 * Proof generation and verification — wraps the Noir/Circom circuit's
 * prover and verifier per docs/06-zk-proofs.md.
 *
 * This module intentionally does NOT depend on a specific proving
 * backend at the type level — `ProverBackend` / `VerifierBackend` are
 * injected, so the SDK can run against a Noir (bb.js/nargo) backend or
 * a Circom (snarkjs) backend interchangeably, per circuits/README.md.
 */
import type { FieldElement, Private, Public } from "./types.js";

export interface CircuitWitness {
  walletAddress: Private<FieldElement>;
  identitySignature: Private<FieldElement>;
  vaultSignature: Private<FieldElement>;
  contextId: Private<FieldElement>;
  index: Private<FieldElement>;
  commitmentHash: Public<FieldElement>;
  pru: Public<FieldElement>;
  /** 0n for a pure login proof with no on-chain action to bind. */
  actionPayloadHash: Public<FieldElement>;
  actionCommitment: Public<FieldElement>;
}

export interface ProverBackend {
  prove(witness: CircuitWitness): Promise<Uint8Array>;
}

export interface VerifierBackend {
  verify(
    proof: Uint8Array,
    publicInputs: {
      commitmentHash: Public<FieldElement>;
      pru: Public<FieldElement>;
      actionPayloadHash: Public<FieldElement>;
      actionCommitment: Public<FieldElement>;
    }
  ): Promise<boolean>;
}

/** Basic shape validation before any input reaches the verifier backend. */
function isWellFormedProofInput(pru: unknown, commitmentHash: unknown): boolean {
  const pruOk = typeof pru === "bigint" || (typeof pru === "string" && pru.length > 0);
  const commitmentOk = typeof commitmentHash === "string" && commitmentHash.length > 0;
  return pruOk && commitmentOk;
}

export async function generateProof(
  backend: ProverBackend,
  witness: CircuitWitness
): Promise<Uint8Array> {
  return backend.prove(witness);
}

export async function verifyProof(
  backend: VerifierBackend,
  proof: Uint8Array,
  pru: Public<FieldElement>,
  commitmentHash: Public<string>,
  actionPayloadHash: Public<FieldElement>,
  actionCommitment: Public<FieldElement>
): Promise<boolean> {
  if (!isWellFormedProofInput(pru, commitmentHash)) {
    return false;
  }
  return backend.verify(proof, {
    pru,
    commitmentHash: BigInt(commitmentHash) as Public<FieldElement>,
    actionPayloadHash,
    actionCommitment,
  });
}
