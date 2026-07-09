/**
 * Proof generation and verification — wraps the Noir/Circom circuit's
 * prover and verifier per docs/06-zk-proofs.md.
 *
 * NEW SECURE ARCHITECTURE:
 * The circuit now proves knowledge of master_seed without revealing it.
 * The wallet's signature is NOT part of the circuit witness anymore.
 *
 * This module intentionally does NOT depend on a specific proving
 * backend at the type level — `ProverBackend` / `VerifierBackend` are
 * injected, so the SDK can run against a Noir (bb.js/nargo) backend or
 * a Circom (snarkjs) backend interchangeably, per circuits/README.md.
 */
import type { FieldElement, MasterSeed, Private, Public } from "./types.js";

/**
 * Circuit witness for the NEW secure architecture.
 *
 * Private inputs:
 * - masterSeed: The 32-byte CSPRNG-generated seed (converted to field element)
 * - protocolId: The protocol identifier
 * - purpose: Purpose within the protocol (e.g., "lending", "trading")
 * - index: PRU index within the purpose
 *
 * The master_seed is NOT derived from any wallet signature.
 * A stolen signature cannot reveal the master_seed.
 */
export interface CircuitWitness {
  /** Master seed as field element - NOT derived from wallet signatures */
  masterSeed: Private<FieldElement>;
  /** Protocol identifier */
  protocolId: Private<FieldElement>;
  /** Purpose within the protocol */
  purpose: Private<FieldElement>;
  /** PRU index within the purpose */
  index: Private<FieldElement>;
  /** Public commitment hash stored in registry */
  commitmentHash: Public<FieldElement>;
  /** The PRU public key being proven */
  pru: Public<FieldElement>;
  /** 0n for a pure login proof with no on-chain action to bind */
  actionPayloadHash: Public<FieldElement>;
  /** Action commitment for binding proof to specific action */
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

/**
 * Converts a MasterSeed (Uint8Array) to a FieldElement for circuit input.
 */
export function masterSeedToFieldElement(seed: MasterSeed): FieldElement {
  let value = 0n;
  for (const byte of seed) {
    value = (value << 8n) | BigInt(byte);
  }
  // Reduce modulo BN254 prime for field compatibility
  const BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  return value % BN254_PRIME;
}
