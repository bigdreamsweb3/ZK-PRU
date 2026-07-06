/**
 * Identity derivation — implements docs/03-identity-model.md exactly.
 *
 * Both fixed challenges are EIP-712 typed data, domain-separated and
 * bound to the deployed registry contract via `verifyingContract`.
 * This closes a phishing gap that a plain fixed string does not: a
 * look-alike site replaying the same challenge text against a
 * different contract address will show a mismatched domain in any
 * wallet that surfaces EIP-712 fields.
 *
 * REJECTED DESIGN — do not reintroduce: an earlier draft proposed
 * mixing a user-memorized 4-digit PIN into this derivation
 * (`Poseidon(vault_signature, user_pin)`), with recovery done by
 * scanning the public registry for a match. This is unsafe: since the
 * registry is public and verification is offline, anyone who obtains
 * `vault_signature` (e.g. via a phishing signature request) can
 * brute-force all 10,000 PINs in well under a second and deanonymize
 * the wallet across every registered context. No low-entropy secret
 * may ever be mixed into this derivation — see docs/03-identity-model.md.
 *
 * SECURITY: identitySignature and vaultSignature must NEVER be logged,
 * cached to persistent storage, or transmitted over the network. They
 * exist only as private ZK circuit inputs (see docs/06-zk-proofs.md)
 * and as transient in-memory values during proof generation.
 *
 * A repo-level check (scripts/check-no-secret-leak.sh) greps the
 * codebase for these identifiers appearing near fetch/axios/console.log/
 * storage calls and fails the build if found — see CODEX_PROMPT.md,
 * deliverable 1.
 */
import { hash2, stringToField } from "./poseidon.js";
import type { EIP712Domain, FieldElement, Private, WalletSigner } from "./types.js";

const SESSION_PREFIX = "ZK-PRU-SESSION";

function buildDomain(chainId: number, registryAddress: string): EIP712Domain {
  return {
    name: "ZK-PRU Protocol",
    version: "1.0.0",
    chainId,
    verifyingContract: registryAddress,
  };
}

export async function signIdentityChallenge(
  wallet: WalletSigner,
  chainId: number,
  registryAddress: string
): Promise<string> {
  return wallet.signTypedData(
    buildDomain(chainId, registryAddress),
    { Identity: [{ name: "purpose", type: "string" }] },
    { purpose: "ZK-PRU Identity Root" }
  );
}

export async function signVaultChallenge(
  wallet: WalletSigner,
  chainId: number,
  registryAddress: string
): Promise<string> {
  return wallet.signTypedData(
    buildDomain(chainId, registryAddress),
    { Vault: [{ name: "purpose", type: "string" }] },
    { purpose: "ZK-PRU Vault Root" }
  );
}

export function buildSessionChallenge(
  walletAddress: string,
  timestamp: number,
  nonce: string
): string {
  // Poseidon over structured fields, not string concatenation, so the
  // three inputs can't be reinterpreted (e.g. by shifting characters
  // between fields) to produce a colliding challenge.
  return hash2(
    stringToField(`${SESSION_PREFIX}${walletAddress}`),
    hash2(stringToField(String(timestamp)), stringToField(nonce))
  ).toString();
}

/**
 * Signs both fixed EIP-712 challenges and derives identity_seed. Both
 * signatures are returned as Private<> — callers must not pass them to
 * any network call or storage write.
 */
export async function deriveIdentity(
  wallet: WalletSigner,
  chainId: number,
  registryAddress: string
): Promise<{
  identitySeed: Private<FieldElement>;
  identitySignature: Private<string>;
  vaultSignature: Private<string>;
}> {
  const identitySignature = (await signIdentityChallenge(
    wallet,
    chainId,
    registryAddress
  )) as Private<string>;

  const vaultSignature = (await signVaultChallenge(
    wallet,
    chainId,
    registryAddress
  )) as Private<string>;

  const identitySeed = hash2(
    stringToField(wallet.address),
    stringToField(identitySignature)
  ) as Private<FieldElement>;

  return { identitySeed, identitySignature, vaultSignature };
}
