/**
 * @zk-pru/sdk main entry point — NEW SECURE ARCHITECTURE.
 *
 * KEY CHANGES FROM OLD ARCHITECTURE:
 * - Master seed is generated locally by CSPRNG, NOT derived from wallet signatures
 * - Wallet's only role is to encrypt/decrypt the master seed
 * - PRU derivation happens entirely on-device from master_seed
 * - Circuit witness contains master_seed (as field element), NOT wallet signatures
 * - Purpose parameter allows multiple independent PRU sets per protocol
 *
 * FLOW:
 * 1. Initialize vault: generate master_seed → encrypt with wallet-derived key → store blob
 * 2. Unlock vault: sign unique challenge → decrypt master_seed → hold in memory
 * 3. Generate PRUs: derive from master_seed locally (wallet not involved)
 * 4. Prove ownership: generate ZK proof using master_seed as private input
 *
 * RECOVERY:
 * - User can derive PRUs for ANY protocol/purpose from master_seed
 * - No dependency on any protocol to recover funds
 * - Protocol ID is just a namespace, not a dependency
 */
import {
  createIdentity,
  recoverIdentity,
  buildSessionChallenge,
  buildRecoveryChallenge,
} from "./identity.js";
import {
  generatePRU as derivePRUPair,
  derivePRUSeed,
  commitmentHash as computeCommitment,
  actionCommitment as computeActionCommitment,
  bytesToField,
  type generatePRUs,
} from "./pru.js";
import {
  generateProof,
  verifyProof,
  type ProverBackend,
  type VerifierBackend,
  type CircuitWitness,
} from "./verify.js";
import { stringToField } from "./poseidon.js";
import type {
  AuthorizeOptions,
  EncryptedSeed,
  FieldElement,
  IdentityMaterial,
  MasterSeed,
  Private,
  Public,
  Registry,
  RecoveryChallenge,
  RegistryBinding,
  SeedBlob,
  WalletSigner,
} from "./types.js";

export interface ZKPRUOptions {
  wallet: WalletSigner;
  registry: Registry;
  prover: ProverBackend;
  registryBinding: RegistryBinding;
  /** Storage adapter for encrypted seed blobs */
  storage: SeedStorage;
}

export interface SeedStorage {
  /** Save encrypted seed blob for recovery */
  save(seedBlob: SeedBlob): Promise<void>;
  /** Load encrypted seed blob for recovery */
  load(): Promise<SeedBlob | null>;
}

/**
 * ZK-PRU Client for the new secure architecture.
 *
 * SECURITY INVARIANT: The master seed is ONLY held in memory during active use.
 * It is NEVER stored persistently in plaintext. It is NEVER transmitted over the network.
 */
export class ZKPRU {
  private wallet: WalletSigner;
  private registry: Registry;
  private prover: ProverBackend;
  private registryBinding: RegistryBinding;
  private storage: SeedStorage;

  // Identity state - held only in memory
  private masterSeed?: MasterSeed;

  constructor(opts: ZKPRUOptions) {
    this.wallet = opts.wallet;
    this.registry = opts.registry;
    this.prover = opts.prover;
    this.registryBinding = opts.registryBinding;
    this.storage = opts.storage;
  }

  /**
   * Initializes a new vault: generates a fresh master seed and encrypts it.
   * Called once during initial setup. The encrypted blob is stored in the
   * configured storage adapter.
   *
   * The encrypted blob is bound to this specific wallet - only this wallet
   * can decrypt it later.
   */
  async initializeVault(): Promise<SeedBlob> {
    const { identity, seedBlob } = await createIdentity(this.wallet, this.registryBinding);
    await this.storage.save(seedBlob);

    // Hold master seed in memory for this session
    this.masterSeed = identity.masterSeed;

    return seedBlob;
  }

  /**
   * Unlocks an existing vault by decrypting the stored seed blob.
   * The user signs a unique recovery challenge to prove wallet ownership.
   * Decryption happens entirely on-device.
   *
   * After unlock, the user can derive PRUs for ANY protocol/purpose.
   */
  async unlockVault(seedBlob: SeedBlob, recoveryChallenge: RecoveryChallenge): Promise<boolean> {
    const identity = await recoverIdentity(
      this.wallet,
      this.registryBinding,
      seedBlob,
      recoveryChallenge
    );

    if (!identity) {
      return false;
    }

    this.masterSeed = identity.masterSeed;
    return true;
  }

  /**
   * Checks if the vault is currently unlocked (master seed in memory).
   */
  isUnlocked(): boolean {
    return this.masterSeed !== undefined;
  }

  /**
   * Locks the vault by wiping the master seed from memory.
   * Call this when the user logs out or the session ends.
   */
  lockVault(): void {
    // Securely wipe the master seed from memory
    this.masterSeed = undefined;
  }

  private assertUnlocked(): MasterSeed {
    if (!this.masterSeed) {
      throw new Error("Vault is locked. Call unlockVault() first.");
    }
    return this.masterSeed;
  }

  /**
   * Generates a PRU for a specific protocol and purpose.
   * The derivation happens entirely on-device from the master seed.
   *
   * @param protocolId - Identifies the protocol (e.g., "defi-xyz")
   * @param purpose - Allows multiple PRU sets per protocol (e.g., "lending", "trading")
   * @param index - PRU index within the purpose
   */
  async generatePRU(args: { protocolId: string; purpose: string; index: number }): Promise<{
    pru: Public<FieldElement>;
    protocolId: string;
    purpose: string;
    commitmentHash: Public<string>;
  }> {
    const masterSeed = this.assertUnlocked();
    const { pru, commitmentHash } = derivePRUPair(
      masterSeed,
      args.protocolId,
      args.purpose,
      args.index
    );
    return { pru, protocolId: args.protocolId, purpose: args.purpose, commitmentHash };
  }

  /**
   * Generates multiple PRUs for a protocol and purpose.
   */
  async generatePRUs(args: {
    protocolId: string;
    purpose: string;
    count: number;
    startIndex?: number;
  }): Promise<Array<{ index: number; pru: Public<FieldElement>; commitmentHash: Public<string> }>> {
    const masterSeed = this.assertUnlocked();
    const pruSeed = derivePRUSeed(masterSeed, args.protocolId, args.purpose);
    const commitment = computeCommitment(pruSeed);

    const prus = Array.from({ length: args.count }, (_, i) => {
      const index = (args.startIndex ?? 0) + i;
      const pru = derivePRUPair(masterSeed, args.protocolId, args.purpose, index);
      return { index, pru: pru.pru, commitmentHash: commitment };
    });

    return prus;
  }

  /**
   * Registers a PRU in the registry for a specific protocol and purpose.
   */
  async register(args: { protocolId: string; purpose: string; index?: number }): Promise<void> {
    const masterSeed = this.assertUnlocked();
    const pruSeed = derivePRUSeed(masterSeed, args.protocolId, args.purpose);
    const commitment = computeCommitment(pruSeed);
    const { pru } = derivePRUPair(masterSeed, args.protocolId, args.purpose, args.index ?? 0);

    await this.registry.register(args.protocolId, pru.toString(), commitment);
  }

  /**
   * Generates a ZK proof of PRU ownership.
   *
   * The proof demonstrates knowledge of the master_seed that derives the PRU,
   * without revealing the master_seed or any wallet signature.
   */
  async proveOwnership(args: {
    protocolId: string;
    purpose: string;
    index: number;
    actionPayloadHash?: FieldElement;
  }): Promise<{
    proof: Uint8Array;
    actionPayloadHash: Public<FieldElement>;
    actionCommitment: Public<FieldElement>;
  }> {
    const masterSeed = this.assertUnlocked();

    const pruSeed = derivePRUSeed(masterSeed, args.protocolId, args.purpose);
    const { pru } = derivePRUPair(masterSeed, args.protocolId, args.purpose, args.index);
    const commitment = computeCommitment(pruSeed);
    const actionPayloadHash = (args.actionPayloadHash ?? 0n) as Public<FieldElement>;
    const actionCommit = computeActionCommitment(pruSeed, actionPayloadHash);

    // Build circuit witness with master_seed as the secret
    const witness: CircuitWitness = {
      masterSeed: bytesToField(masterSeed) as Private<FieldElement>,
      protocolId: stringToField(args.protocolId) as Private<FieldElement>,
      purpose: stringToField(args.purpose) as Private<FieldElement>,
      index: BigInt(args.index) as Private<FieldElement>,
      commitmentHash: BigInt(commitment) as Public<FieldElement>,
      pru,
      actionPayloadHash,
      actionCommitment: actionCommit,
    };

    const proof = await generateProof(this.prover, witness);
    return { proof, actionPayloadHash, actionCommitment: actionCommit };
  }

  /**
   * Mode B fallback for systems that cannot verify ZK proofs.
   * WARNING: This reveals the wallet public key to the verifier.
   */
  async authorizeFallback(opts: AuthorizeOptions = {}): Promise<string> {
    if (!opts.allowFallback) {
      throw new Error(
        "Mode B (signature fallback) requires allowFallback: true. " +
          "Using it reveals the wallet public key to the verifier."
      );
    }
    const timestamp = Date.now();
    const nonce = crypto.randomUUID();
    const challenge = buildSessionChallenge(this.wallet.publicKey, timestamp, nonce);
    const signature = await this.wallet.signMessage(new TextEncoder().encode(challenge));
    return typeof signature === "string" ? signature : Buffer.from(signature).toString("base64");
  }
}

export interface ZKPRUVerifierOptions {
  registry: Registry;
  verifier: VerifierBackend;
}

/**
 * Verifier class for protocol-side proof verification.
 */
export class ZKPRUVerifier {
  private registry: Registry;
  private verifier: VerifierBackend;

  constructor(opts: ZKPRUVerifierOptions) {
    this.registry = opts.registry;
    this.verifier = opts.verifier;
  }

  async verify(args: {
    pru: Public<FieldElement>;
    proof: Uint8Array;
    protocolId: string;
    actionPayloadHash?: Public<FieldElement>;
    actionCommitment?: Public<FieldElement>;
  }): Promise<boolean> {
    const record = await this.registry.getRecord(args.pru.toString());
    if (!record || record.contextId !== args.protocolId) return false;

    return verifyProof(
      this.verifier,
      args.proof,
      args.pru,
      record.commitmentHash as Public<string>,
      (args.actionPayloadHash ?? 0n) as Public<FieldElement>,
      (args.actionCommitment ?? 0n) as Public<FieldElement>
    );
  }
}

export * from "./types.js";
export { buildRecoveryChallenge, buildSessionChallenge } from "./identity.js";
export { derivePRU, derivePRUSeed, deriveUserSecretNamespace, commitmentHash, actionCommitment, generatePRUs, bytesToField } from "./pru.js";
export { isValidEncryptedSeed } from "./encryption.js";
export * from "./purpose.js";
export * from "./stable-units.js";
export * from "./delegated-capability.js";
