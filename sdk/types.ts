/**
 * Shared type definitions for ZK-PRU.
 *
 * These types encode the security rules from docs/09-security-model.md
 * at the type level where possible: private values are wrapped in
 * branded types so they can't be accidentally passed where a public
 * value is expected (e.g. into a fetch() call or a registry write).
 */

/** A value that must never cross a network boundary or be persisted in plaintext. */
export type Private<T> = T & { readonly __private: true };

/** A value that is safe to publish (registry, network, logs). */
export type Public<T> = T & { readonly __public: true };

export type FieldElement = bigint;

export interface EIP712Domain {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: string;
}

export interface WalletSigner {
  address: string;
  /** Must produce a deterministic signature for a given fixed message. */
  signMessage(message: string): Promise<string>;
  /**
   * Signs EIP-712 typed data. Used for the two fixed challenges
   * (identity, vault) so they're bound to a specific deployed contract
   * via `domain.verifyingContract` — see docs/03-identity-model.md for
   * why this matters (phishing resistance).
   */
  signTypedData(
    domain: EIP712Domain,
    types: Record<string, Array<{ name: string; type: string }>>,
    message: Record<string, unknown>
  ): Promise<string>;
}

export interface IdentityMaterial {
  identitySeed: Private<FieldElement>;
  vaultSignature: Private<string>;
}

export interface PRUHandle {
  contextId: string;
  index: number;
  pru: Public<FieldElement>;
}

export interface RegistryRecord {
  contextId: string;
  pruPublicKeys: string[];
  commitmentHash: string;
}

export interface ProofBundle {
  contextId: string;
  pru: Public<FieldElement>;
  proof: Uint8Array;
}

export interface Registry {
  register(contextId: string, pruPublicKeys: string[], commitmentHash: string): Promise<void>;
  getCommitment(contextId: string): Promise<string | null>;
  getPRUs(contextId: string): Promise<string[]>;
}

/** Mode B fallback must be explicitly requested — see docs/07-authorization.md */
export interface AuthorizeOptions {
  allowFallback?: boolean;
}
