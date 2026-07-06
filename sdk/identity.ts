/**
 * Identity derivation for Solana-native ZK-PRU.
 *
 * Both fixed challenges are canonical UTF-8 Solana signMessage payloads.
 * They are domain-separated and bound to the registry program ID,
 * cluster, wallet public key, and ZK-PRU version.
 *
 * SECURITY: identitySignature and vaultSignature must never be logged,
 * cached to persistent storage, or transmitted over the network. They
 * exist only as private ZK circuit inputs and transient in-memory values
 * during proof generation.
 */
import { hash2, stringToField } from "./poseidon.js";
import type { FieldElement, Private, RegistryBinding, WalletSigner } from "./types.js";

const SESSION_PREFIX = "ZK-PRU-SESSION";
const textEncoder = new TextEncoder();

function encodeCanonicalMessage(lines: string[]): Uint8Array {
  return textEncoder.encode(lines.join("\n"));
}

function signatureToString(signature: Uint8Array | string): string {
  if (typeof signature === "string") return signature;
  return Buffer.from(signature).toString("base64");
}

export function buildIdentityChallenge(
  walletPublicKey: string,
  binding: RegistryBinding
): Uint8Array {
  return encodeCanonicalMessage([
    "ZK-PRU Identity Root",
    `Cluster: ${binding.cluster}`,
    `Registry Program: ${binding.registryProgramId}`,
    `Wallet: ${walletPublicKey}`,
    `Version: ${binding.version}`,
    "Purpose: identity_root",
  ]);
}

export function buildVaultChallenge(
  walletPublicKey: string,
  binding: RegistryBinding
): Uint8Array {
  return encodeCanonicalMessage([
    "ZK-PRU Vault Root",
    `Cluster: ${binding.cluster}`,
    `Registry Program: ${binding.registryProgramId}`,
    `Wallet: ${walletPublicKey}`,
    `Version: ${binding.version}`,
    "Purpose: vault_root",
  ]);
}

export async function signIdentityChallenge(
  wallet: WalletSigner,
  binding: RegistryBinding
): Promise<string> {
  const message = buildIdentityChallenge(wallet.publicKey, binding);
  return signatureToString(await wallet.signMessage(message));
}

export async function signVaultChallenge(
  wallet: WalletSigner,
  binding: RegistryBinding
): Promise<string> {
  const message = buildVaultChallenge(wallet.publicKey, binding);
  return signatureToString(await wallet.signMessage(message));
}

export function buildSessionChallenge(
  walletPublicKey: string,
  timestamp: number,
  nonce: string
): string {
  return hash2(
    stringToField(`${SESSION_PREFIX}${walletPublicKey}`),
    hash2(stringToField(String(timestamp)), stringToField(nonce))
  ).toString();
}

/**
 * Signs both fixed Solana messages and derives identity_seed. Both
 * signatures are returned as Private<> values.
 */
export async function deriveIdentity(
  wallet: WalletSigner,
  binding: RegistryBinding
): Promise<{
  identitySeed: Private<FieldElement>;
  identitySignature: Private<string>;
  vaultSignature: Private<string>;
}> {
  const identitySignature = (await signIdentityChallenge(wallet, binding)) as Private<string>;
  const vaultSignature = (await signVaultChallenge(wallet, binding)) as Private<string>;

  const identitySeed = hash2(
    stringToField(wallet.publicKey),
    stringToField(identitySignature)
  ) as Private<FieldElement>;

  return { identitySeed, identitySignature, vaultSignature };
}
