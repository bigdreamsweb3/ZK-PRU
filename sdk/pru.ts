/**
 * PRU generation — implements docs/04-pru-generation.md exactly.
 *
 *   PRU_seed[context_id] = Poseidon(identity_seed, context_id, vault_signature)
 *   PRU[context_id][i]   = Poseidon(PRU_seed[context_id], i)
 *
 * PRU_seed is never exposed outside the ZK circuit — this module keeps
 * it in a Private<> wrapper and only returns the final PRU as Public<>.
 */
import { hash1, hash2, hash3, stringToField } from "./poseidon.js";
import type { FieldElement, Private, Public } from "./types.js";

export function derivePRUSeed(
  identitySeed: Private<FieldElement>,
  contextId: string,
  vaultSignature: Private<string>
): Private<FieldElement> {
  return hash3(
    identitySeed,
    stringToField(contextId),
    stringToField(vaultSignature)
  ) as Private<FieldElement>;
}

export function derivePRU(
  pruSeed: Private<FieldElement>,
  index: number
): Public<FieldElement> {
  return hash2(pruSeed, BigInt(index)) as Public<FieldElement>;
}

export function commitmentHash(pruSeed: Private<FieldElement>): Public<string> {
  // Single-input Poseidon over PRU_seed, per docs/05-registry.md:
  // commitment_hash = Poseidon(PRU_seed[context_id])
  return hash1(pruSeed).toString() as Public<string>;
}

/**
 * Binds a proof to a specific action, per docs/06-zk-proofs.md,
 * "Binding a proof to a specific action". Safe to publish: it reveals
 * nothing about pruSeed, but changes completely for every distinct
 * actionPayloadHash, so a proof can't be silently replayed against a
 * different action. Pass actionPayloadHash = 0n for a pure login proof
 * with no on-chain action to bind.
 */
export function actionCommitment(
  pruSeed: Private<FieldElement>,
  actionPayloadHash: FieldElement
): Public<FieldElement> {
  return hash2(pruSeed, actionPayloadHash) as Public<FieldElement>;
}

/**
 * Convenience helper: derive a PRU end-to-end for a given context+index,
 * without exposing PRU_seed to the caller.
 */
export function generatePRU(
  identitySeed: Private<FieldElement>,
  vaultSignature: Private<string>,
  contextId: string,
  index: number
): { pru: Public<FieldElement>; commitmentHash: Public<string> } {
  const pruSeed = derivePRUSeed(identitySeed, contextId, vaultSignature);
  return {
    pru: derivePRU(pruSeed, index),
    commitmentHash: commitmentHash(pruSeed),
  };
}
