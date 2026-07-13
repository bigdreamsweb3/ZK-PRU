/**
 * AES-256-GCM encryption module for ZK-PRU.
 *
 * SECURITY MODEL:
 * - Random entropy is encrypted with a key derived from wallet signature + unique challenge
 * - Only the encrypted blob is stored/transmitted; the plaintext never leaves the device
 * - Each encryption uses a fresh 12-byte IV for semantic security
 * - Authentication tag ensures ciphertext integrity and prevents tampering
 *
 * The wallet's role is ONLY to encrypt/decrypt the random entropy component.
 * This breaks the attack vector where a stolen signature could compromise the identity.
 * 
 * Even with a stolen signature, the attacker cannot derive master_seed because:
 * - master_seed = Poseidon(identity_seed, random_entropy)
 * - random_entropy is encrypted in the blob
 * - Without random_entropy, the master_seed cannot be computed
 */
import type { EncryptedSeed, MasterSeed, VaultKey } from "./types.js";

const ALGORITHM = "AES-GCM";
const IV_LENGTH = 12;  // 96 bits for GCM
const TAG_LENGTH = 128; // 128 bits

/**
 * Derives a 256-bit encryption key from the vault key using SHA-256.
 */
export async function deriveEncryptionKey(vaultKey: VaultKey): Promise<CryptoKey> {
  const vaultKeyHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(vaultKey));

  return crypto.subtle.importKey(
    "raw",
    vaultKeyHash,
    ALGORITHM,
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypts data (random entropy) using AES-256-GCM.
 * The ciphertext is safe to store anywhere - it cannot be decrypted without the vault key.
 */
export async function encryptMasterSeed(
  data: Uint8Array,
  vaultKey: VaultKey
): Promise<EncryptedSeed> {
  const key = await deriveEncryptionKey(vaultKey);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  const plaintext = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;

  const ciphertextWithTag = await crypto.subtle.encrypt(
    { name: ALGORITHM, iv: iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength) as ArrayBuffer, tagLength: TAG_LENGTH },
    key,
    plaintext
  );

  // GCM appends the auth tag to the ciphertext
  const ciphertext = new Uint8Array(ciphertextWithTag);
  const actualCiphertext = ciphertext.slice(0, -16);
  const authTag = ciphertext.slice(-16);

  return {
    ciphertext: base64Encode(actualCiphertext),
    iv: base64Encode(iv),
    authTag: base64Encode(authTag),
  };
}

/**
 * Decrypts encrypted data using AES-256-GCM.
 * Returns null if decryption fails (wrong key, tampered ciphertext, etc.)
 */
export async function decryptMasterSeed(
  encryptedSeed: EncryptedSeed,
  vaultKey: VaultKey
): Promise<Uint8Array | null> {
  try {
    const key = await deriveEncryptionKey(vaultKey);
    const iv = base64Decode(encryptedSeed.iv);
    const ciphertext = base64Decode(encryptedSeed.ciphertext);
    const authTag = base64Decode(encryptedSeed.authTag);

    // GCM expects ciphertext || authTag
    const combined = new Uint8Array(ciphertext.length + authTag.length);
    combined.set(ciphertext);
    combined.set(authTag, ciphertext.length);

    const plaintext = await crypto.subtle.decrypt(
      { name: ALGORITHM, iv: iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength) as ArrayBuffer, tagLength: TAG_LENGTH },
      key,
      combined.buffer.slice(combined.byteOffset, combined.byteOffset + combined.byteLength) as ArrayBuffer
    );

    return new Uint8Array(plaintext);
  } catch {
    // Decryption failed - wrong key, tampered data, or corrupted ciphertext
    return null;
  }
}

/**
 * Converts master seed to a FieldElement for Poseidon hashing.
 */
export function masterSeedToField(seed: MasterSeed): bigint {
  let value = 0n;
  for (const byte of seed) {
    value = (value << 8n) | BigInt(byte);
  }
  // Reduce modulo BN254 prime
  const BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  return value % BN254_PRIME;
}

// Base64 encoding/decoding utilities
function base64Encode(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data));
}

function base64Decode(data: string): Uint8Array {
  return Uint8Array.from(atob(data), c => c.charCodeAt(0));
}

/**
 * Verifies that an encrypted seed blob is well-formed.
 * Does NOT verify the decryption key - only the structure.
 */
export function isValidEncryptedSeed(seed: unknown): seed is EncryptedSeed {
  if (!seed || typeof seed !== "object") return false;
  const s = seed as Record<string, unknown>;
  return (
    typeof s.ciphertext === "string" &&
    typeof s.iv === "string" &&
    typeof s.authTag === "string" &&
    s.ciphertext.length > 0 &&
    s.iv.length > 0 &&
    s.authTag.length > 0
  );
}
