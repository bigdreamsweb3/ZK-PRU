/**
 * Shared type definitions for ZK-PRU.
 *
 * Private values are wrapped in branded types so they cannot be
 * accidentally passed where public values are expected.
 */

/** A value that must never cross a network boundary or be persisted in plaintext. */
export type Private<T> = T & { readonly __private: true };

/** A value that is safe to publish in registry records, network calls, or logs. */
export type Public<T> = T & { readonly __public: true };

export type FieldElement = bigint;

export type SolanaCluster = "devnet" | "testnet" | "mainnet-beta" | "localnet";

export interface RegistryBinding {
  cluster: SolanaCluster;
  registryProgramId: string;
  version: string;
}

export interface WalletSigner {
  publicKey: string;
  /** Must produce a deterministic signature for a given canonical message. */
  signMessage(message: Uint8Array): Promise<Uint8Array | string>;
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
  pru: string;
  contextId: string;
  commitmentHash: string;
}

export interface ProofBundle {
  contextId: string;
  pru: Public<FieldElement>;
  proof: Uint8Array;
}

/**
 * Registry keyed by PRU, not by context_id. The context_id is shared by
 * every user of a protocol, while each PRU is unique.
 */
export interface Registry {
  register(contextId: string, pru: string, commitmentHash: string): Promise<void>;
  getRecord(pru: string): Promise<{ contextId: string; commitmentHash: string } | null>;
  getPRUsForContext(contextId: string): Promise<string[]>;
}

/** Mode B fallback must be explicitly requested. */
export interface AuthorizeOptions {
  allowFallback?: boolean;
}
