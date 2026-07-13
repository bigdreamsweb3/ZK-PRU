/**
 * PRU generation — NEW SECURE ARCHITECTURE.
 *
 * KEY SECURITY PRINCIPLE: PRU derivation is entirely local and derives from
 * the master_seed. No wallet signature is involved in PRU derivation.
 *
 * NEW DERIVATION CHAIN:
 *   master_seed (CSPRNG, never transmitted)
 *     ↓
 *   PRU_seed[protocol_id][purpose] = Poseidon(master_seed, protocol_id, purpose)
 *     ↓
 *   PRU[protocol_id][purpose][i] = Poseidon(PRU_seed, i)
 *     ↓
 *   commitment_hash = Poseidon(PRU_seed)
 *
 * The master_seed is independent of any wallet. A stolen signature cannot
 * derive the master_seed because there's no mathematical relationship between
 * them.
 *
 * Key features:
 * - purpose parameter allows multiple independent PRU sets per protocol
 * - Protocol-independent recovery: user can derive PRUs for ANY protocol from master_seed
 * - PRU_seed is never exposed outside the ZK circuit
 */
import { hash1, hash2, hash3, stringToField } from "./poseidon.js";
import type { FieldElement, MasterSeed, Private, Public } from "./types.js";

const USER_SECRET_NAMESPACE_DOMAIN = "ZK_PRU_USER_NAMESPACE_V1";


/**
 * Derives PRU_seed from master_seed for a specific protocol and purpose.
 *
 * @param masterSeed - The 32-byte master seed (CSPRNG-generated)
 * @param protocolId - Identifies the protocol (e.g., "defi-xyz")
 * @param purpose - Allows multiple independent PRU sets per protocol (e.g., "lending", "trading")
 */
export function deriveUserSecretNamespace(masterSeed: MasterSeed): Private<FieldElement> {
  return hash2(
    bytesToField(masterSeed),
    stringToField(USER_SECRET_NAMESPACE_DOMAIN)
  ) as Private<FieldElement>;
}

export function derivePRUSeed(
  masterSeed: MasterSeed,
  protocolId: string,
  purpose: string
): Private<FieldElement> {
  const userSecretNamespace = deriveUserSecretNamespace(masterSeed);

  return hash3(
    userSecretNamespace,
    stringToField(protocolId),
    stringToField(purpose)
  ) as Private<FieldElement>;
}

/**
 * Derives a specific PRU from a PRU_seed.
 */
export function derivePRU(
  pruSeed: Private<FieldElement>,
  index: number
): Public<FieldElement> {
  return hash2(pruSeed, BigInt(index)) as Public<FieldElement>;
}

/**
 * Computes the commitment hash for a PRU_seed.
 * This is stored in the registry, not the PRU_seed itself.
 */
export function commitmentHash(pruSeed: Private<FieldElement>): Public<string> {
  return hash1(pruSeed).toString() as Public<string>;
}

/**
 * Binds a proof to a specific action, preventing replay attacks.
 *
 * Safe to publish: it reveals nothing about pruSeed, but changes
 * completely for every distinct actionPayloadHash, so a proof can't be
 * silently replayed against a different action.
 *
 * Pass actionPayloadHash = 0n for a pure login proof with no on-chain
 * action to bind.
 */
export function actionCommitment(
  pruSeed: Private<FieldElement>,
  actionPayloadHash: FieldElement
): Public<FieldElement> {
  return hash2(pruSeed, actionPayloadHash) as Public<FieldElement>;
}

/**
 * Convenience helper: derive a PRU end-to-end for a given protocol+purpose+index,
 * without exposing PRU_seed to the caller.
 */
export function generatePRU(
  masterSeed: MasterSeed,
  protocolId: string,
  purpose: string,
  index: number
): { pru: Public<FieldElement>; commitmentHash: Public<string> } {
  const pruSeed = derivePRUSeed(masterSeed, protocolId, purpose);
  return {
    pru: derivePRU(pruSeed, index),
    commitmentHash: commitmentHash(pruSeed),
  };
}

/**
 * Converts a 32-byte array to a BN254 field element.
 * Uses simple big-endian conversion with field reduction.
 */
export function bytesToField(bytes: Uint8Array): FieldElement {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  // Reduce modulo BN254 prime for field compatibility
  const BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  return value % BN254_PRIME;
}

/**
 * Generates multiple PRUs for a protocol+purpose in one call.
 * All share the same PRU_seed but have different indices.
 */
export function generatePRUs(
  masterSeed: MasterSeed,
  protocolId: string,
  purpose: string,
  count: number,
  startIndex = 0
): Array<{ index: number; pru: Public<FieldElement> }> {
  const pruSeed = derivePRUSeed(masterSeed, protocolId, purpose);
  return Array.from({ length: count }, (_, i) => ({
    index: startIndex + i,
    pru: derivePRU(pruSeed, startIndex + i),
  }));
}
