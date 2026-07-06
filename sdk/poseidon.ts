/**
 * Poseidon is the ONLY hash function used anywhere in ZK-PRU — on the
 * client, in the registry, and inside the ZK circuit. See
 * docs/04-pru-generation.md ("Why this shape") for the rationale:
 * mixing a generic hash outside the circuit with Poseidon inside it
 * would force the circuit to reimplement the generic hash in-circuit,
 * which is far more expensive in constraints.
 *
 * This wraps `poseidon-lite`, a minimal dependency-free Poseidon
 * implementation over the BN254 scalar field, matching the field used
 * by common Noir/Circom BN254 backends.
 */
import { poseidon1, poseidon2, poseidon3 } from "poseidon-lite";
import type { FieldElement } from "./types.js";

/** Deterministically maps an arbitrary string to a BN254 field element. */
export function stringToField(value: string): FieldElement {
  const bytes = new TextEncoder().encode(value);
  let acc = 0n;
  for (const byte of bytes) {
    acc = (acc << 8n) | BigInt(byte);
  }
  // Reduce into the field via a single Poseidon absorption rather than
  // naive modulo, so short and long strings both hash unpredictably.
  return poseidon1([acc]);
}

export function hash1(a: FieldElement): FieldElement {
  return poseidon1([a]);
}

export function hash2(a: FieldElement, b: FieldElement): FieldElement {
  return poseidon2([a, b]);
}

export function hash3(a: FieldElement, b: FieldElement, c: FieldElement): FieldElement {
  return poseidon3([a, b, c]);
}
