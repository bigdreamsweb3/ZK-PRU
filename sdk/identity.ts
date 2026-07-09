/**
 * Identity derivation for ZK-PRU — NEW SECURE ARCHITECTURE.
 *
 * KEY SECURITY PRINCIPLE: The master seed combines:
 * 1. CSPRNG entropy (random_entropy) - stored encrypted in blob
 * 2. Wallet identity binding (identity_seed) - from wallet signature
 *
 * This breaks the attack vector where a malicious protocol tricks you into signing
 * a message, steals your signature, and reconstructs your entire identity.
 *
 * FLOW:
 * 1. Generate random_entropy locally (CSPRNG) - pure entropy
 * 2. Derive identity_seed from wallet signature - provides wallet binding
 * 3. Combine: master_seed = Poseidon(identity_seed, random_entropy)
 * 4. Encrypt random_entropy with wallet-derived key → store encrypted blob
 * 5. For recovery: sign unique challenge → decrypt random_entropy → reconstruct master_seed
 * 6. PRU derivation happens entirely on-device from master_seed
 *
 * SECURITY: Even a stolen signature cannot derive master_seed (requires random_entropy).
 */
import { hash2, hash3, stringToField } from "./poseidon.js";
import { encryptMasterSeed, decryptMasterSeed, masterSeedToField } from "./encryption.js";
import type {
  EncryptedSeed,
  FieldElement,
  IdentityMaterial,
  MasterSeed,
  Private,
  RecoveryChallenge,
  RegistryBinding,
  SeedBlob,
  VaultKey,
  WalletSigner,
} from "./types.js";

const VAULT_PREFIX = "ZK-PRU-VAULT";
const RECOVERY_PREFIX = "ZK-PRU-RECOVERY";
const CHALLENGE_VALIDITY_MS = 5 * 60 * 1000; // 5 minutes

const textEncoder = new TextEncoder();

function encodeCanonicalMessage(lines: string[]): Uint8Array {
  return textEncoder.encode(lines.join("\n"));
}

function signatureToString(signature: Uint8Array | string): string {
  if (typeof signature === "string") return signature;
  return Buffer.from(signature).toString("base64");
}

/**
 * Generates cryptographically secure random entropy (32 bytes).
 * This is combined with identity_seed to create master_seed.
 */
export function generateRandomEntropy(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Derives identity_seed from wallet public key and signature.
 * This provides wallet binding - only the signing wallet can derive this.
 */
export function deriveIdentitySeed(
  walletPublicKey: string,
  signature: string
): FieldElement {
  return hash2(stringToField(walletPublicKey), stringToField(signature));
}

/**
 * Derives master_seed from identity_seed and random_entropy.
 * master_seed = Poseidon(identity_seed, random_entropy)
 */
export function deriveMasterSeed(
  identitySeed: FieldElement,
  randomEntropy: Uint8Array
): MasterSeed {
  // Convert random_entropy to field element
  let entropyField = 0n;
  for (const byte of randomEntropy) {
    entropyField = (entropyField << 8n) | BigInt(byte);
  }
  // Reduce modulo BN254 prime
  const BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  entropyField = entropyField % BN254_PRIME;

  // Combine with identity_seed
  const masterField = hash2(identitySeed, entropyField);
  
  // Convert back to 32 bytes (big-endian)
  const masterSeed = new Uint8Array(32);
  let value = masterField;
  for (let i = 31; i >= 0; i--) {
    masterSeed[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  
  return masterSeed as MasterSeed;
}

/**
 * Builds a unique vault challenge. Includes timestamp and nonce to ensure uniqueness.
 */
export function buildVaultChallenge(
  walletPublicKey: string,
  binding: RegistryBinding,
  timestamp: number,
  nonce: string
): Uint8Array {
  return encodeCanonicalMessage([
    "ZK-PRU Vault",
    `Cluster: ${binding.cluster}`,
    `Registry Program: ${binding.registryProgramId}`,
    `Wallet: ${walletPublicKey}`,
    `Version: ${binding.version}`,
    `Purpose: vault_encryption`,
    `Timestamp: ${timestamp}`,
    `Nonce: ${nonce}`,
  ]);
}

/**
 * Builds a recovery challenge for decrypting an existing seed blob.
 * This is a UNIQUE challenge that expires after CHALLENGE_VALIDITY_MS.
 */
export function buildRecoveryChallenge(
  walletPublicKey: string,
  binding: RegistryBinding
): RecoveryChallenge {
  const timestamp = Date.now();
  const nonce = crypto.randomUUID();
  const challenge = hash2(
    stringToField(`${RECOVERY_PREFIX}${walletPublicKey}`),
    hash3(
      stringToField(binding.cluster),
      stringToField(String(timestamp)),
      stringToField(nonce)
    )
  ).toString();

  return {
    challenge,
    timestamp,
    expiresAt: timestamp + CHALLENGE_VALIDITY_MS,
  };
}

/**
 * Signs the vault challenge to derive the vault key.
 * The vault key is used for encrypting/decrypting random_entropy.
 */
export async function signVaultChallenge(
  wallet: WalletSigner,
  binding: RegistryBinding,
  timestamp: number,
  nonce: string
): Promise<{ signature: string; vaultKey: VaultKey }> {
  const message = buildVaultChallenge(wallet.publicKey, binding, timestamp, nonce);
  const signature = signatureToString(await wallet.signMessage(message));
  const vaultKey = hash2(stringToField(wallet.publicKey), stringToField(signature)).toString() as VaultKey;
  return { signature, vaultKey };
}

/**
 * Signs the recovery challenge to decrypt an existing seed blob.
 */
export async function signRecoveryChallenge(
  wallet: WalletSigner,
  challenge: RecoveryChallenge
): Promise<string> {
  const message = textEncoder.encode(challenge.challenge);
  return signatureToString(await wallet.signMessage(message));
}

/**
 * Generates a NEW identity:
 * 1. Generate random_entropy locally (CSPRNG)
 * 2. Derive identity_seed from wallet signature
 * 3. Combine to create master_seed
 * 4. Encrypt random_entropy with wallet-derived key
 *
 * Called ONCE during initial setup. The encrypted blob can be stored anywhere.
 */
export async function createIdentity(
  wallet: WalletSigner,
  binding: RegistryBinding
): Promise<{
  identity: IdentityMaterial;
  seedBlob: SeedBlob;
}> {
  // Step 1: Generate random entropy
  const randomEntropy = generateRandomEntropy();

  // Step 2: Sign unique challenge to derive vault key and identity_seed
  const timestamp = Date.now();
  const nonce = crypto.randomUUID();
  const { signature, vaultKey } = await signVaultChallenge(wallet, binding, timestamp, nonce);

  // Step 3: Derive identity_seed (provides wallet binding)
  const identitySeed = deriveIdentitySeed(wallet.publicKey, signature);

  // Step 4: Create master_seed = Poseidon(identity_seed, random_entropy)
  const masterSeed = deriveMasterSeed(identitySeed, randomEntropy);

  // Step 5: Encrypt random_entropy (not master_seed) with wallet key
  const encryptedSeed = await encryptMasterSeed(randomEntropy, vaultKey);

  // Step 6: Create the seed blob for storage
  const seedBlob: SeedBlob = {
    encryptedSeed,
    ownerPubkeyHash: hash2(stringToField(wallet.publicKey), 0n).toString(),
    createdAt: timestamp,
    version: binding.version,
  };

  return {
    identity: { masterSeed, vaultKey },
    seedBlob,
  };
}

/**
 * Recovers an identity by decrypting the stored seed blob.
 *
 * The user signs the unique recovery challenge, which proves wallet ownership
 * without revealing any secrets. The decryption happens locally on-device.
 */
export async function recoverIdentity(
  wallet: WalletSigner,
  binding: RegistryBinding,
  seedBlob: SeedBlob,
  recoveryChallenge: RecoveryChallenge
): Promise<IdentityMaterial | null> {
  // Step 1: Verify the challenge hasn't expired
  if (Date.now() > recoveryChallenge.expiresAt) {
    return null;
  }

  // Step 2: Sign the recovery challenge
  const signature = await signRecoveryChallenge(wallet, recoveryChallenge);

  // Step 3: Derive the vault key from the recovery signature
  const vaultKey = hash2(
    stringToField(signature),
    stringToField(recoveryChallenge.challenge)
  ) as VaultKey;

  // Step 4: Decrypt the random_entropy
  const randomEntropy = await decryptMasterSeed(seedBlob.encryptedSeed, vaultKey);
  if (!randomEntropy) {
    return null;
  }

  // Step 5: Re-derive identity_seed
  const identitySeed = deriveIdentitySeed(wallet.publicKey, signature);

  // Step 6: Reconstruct master_seed
  const masterSeed = deriveMasterSeed(identitySeed, randomEntropy);

  return { masterSeed, vaultKey };
}

/**
 * Derives the master seed as a FieldElement for PRU generation.
 */
export function masterSeedToFieldElement(seed: MasterSeed): Private<FieldElement> {
  return masterSeedToField(seed) as Private<FieldElement>;
}

/**
 * Session challenge for Mode B fallback authorization.
 */
export function buildSessionChallenge(
  walletPublicKey: string,
  timestamp: number,
  nonce: string
): string {
  return hash2(
    stringToField(`${VAULT_PREFIX}${walletPublicKey}`),
    hash2(stringToField(String(timestamp)), stringToField(nonce))
  ).toString();
}

/**
 * Builds a challenge for the wallet to sign. Used when initializing a new vault.
 */
export function buildInitChallenge(
  walletPublicKey: string,
  binding: RegistryBinding
): { timestamp: number; nonce: string; message: Uint8Array } {
  const timestamp = Date.now();
  const nonce = crypto.randomUUID();
  const message = buildVaultChallenge(walletPublicKey, binding, timestamp, nonce);
  return { timestamp, nonce, message };
}
