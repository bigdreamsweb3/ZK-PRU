/**
 * @zk-pru/sdk — main entry point.
 *
 * Implements the client-side and protocol-side APIs described in
 * docs/08-protocol-integration.md. See docs/07-authorization.md for
 * the Mode A / Mode B distinction enforced here, and docs/06-zk-proofs.md
 * for the action-binding constraint used to stop proof replay/front-running.
 */
import { deriveIdentity, buildSessionChallenge } from "./identity.js";
import { generatePRU as derivePRUPair, derivePRUSeed, commitmentHash as computeCommitment, actionCommitment as computeActionCommitment } from "./pru.js";
import { generateProof, verifyProof, type ProverBackend, type VerifierBackend, type CircuitWitness } from "./verify.js";
import { stringToField } from "./poseidon.js";
import type {
  AuthorizeOptions,
  FieldElement,
  Private,
  Public,
  Registry,
  WalletSigner,
} from "./types.js";

export interface ZKPRUOptions {
  wallet: WalletSigner;
  registry: Registry;
  prover: ProverBackend;
  /** Chain ID and deployed registry contract address, used to bind
   *  the two fixed EIP-712 challenges — see docs/03-identity-model.md. */
  chainId: number;
  registryAddress: string;
}

export class ZKPRU {
  private wallet: WalletSigner;
  private registry: Registry;
  private prover: ProverBackend;
  private chainId: number;
  private registryAddress: string;

  // In-memory only for the session — never persisted. See
  // docs/09-security-model.md, "Operational recommendations."
  private identitySeed?: Private<FieldElement>;
  private identitySignature?: Private<string>;
  private vaultSignature?: Private<string>;

  constructor(opts: ZKPRUOptions) {
    this.wallet = opts.wallet;
    this.registry = opts.registry;
    this.prover = opts.prover;
    this.chainId = opts.chainId;
    this.registryAddress = opts.registryAddress;
  }

  /** Step 1: derive identity from two fixed, EIP-712-bound wallet signatures. */
  async deriveIdentity(): Promise<void> {
    const { identitySeed, identitySignature, vaultSignature } = await deriveIdentity(
      this.wallet,
      this.chainId,
      this.registryAddress
    );
    this.identitySeed = identitySeed;
    this.identitySignature = identitySignature;
    this.vaultSignature = vaultSignature;
  }

  private assertIdentityDerived(): { seed: Private<FieldElement>; vault: Private<string> } {
    if (!this.identitySeed || !this.vaultSignature) {
      throw new Error("Call deriveIdentity() before generating or proving a PRU.");
    }
    return { seed: this.identitySeed, vault: this.vaultSignature };
  }

  /** Step 2: generate a PRU for a given protocol context + index. */
  async generatePRU(args: { contextId: string; index: number }): Promise<{
    pru: Public<FieldElement>;
    contextId: string;
    commitmentHash: Public<string>;
  }> {
    const { seed, vault } = this.assertIdentityDerived();
    const { pru, commitmentHash } = derivePRUPair(seed, vault, args.contextId, args.index);
    return { pru, contextId: args.contextId, commitmentHash };
  }

  /** Step 3: register the PRU's commitment for a context (first use only). */
  async register(contextId: string, index = 0): Promise<void> {
    const { seed, vault } = this.assertIdentityDerived();
    const pruSeed = derivePRUSeed(seed, contextId, vault);
    const commitment = computeCommitment(pruSeed);
    const { pru } = derivePRUPair(seed, vault, contextId, index);

    const existing = await this.registry.getPRUs(contextId);
    await this.registry.register(contextId, [...existing, pru.toString()], commitment);
  }

  /**
   * Step 4 (Mode A): generate a ZK proof of ownership for a PRU.
   * Pass `actionPayloadHash` for anything with an on-chain effect
   * (computed by the calling protocol from the actual action, e.g.
   * hash(amount, recipient) for a transfer) to bind the proof against
   * replay/front-running — see docs/06-zk-proofs.md. Omit it (defaults
   * to 0n) for a pure login proof with no action to bind.
   */
  async proveOwnership(args: {
    contextId: string;
    index: number;
    actionPayloadHash?: FieldElement;
  }): Promise<{ proof: Uint8Array; actionPayloadHash: Public<FieldElement>; actionCommitment: Public<FieldElement> }> {
    const { seed, vault } = this.assertIdentityDerived();
    if (!this.identitySignature) throw new Error("Identity not derived.");

    const pruSeed = derivePRUSeed(seed, args.contextId, vault);
    const { pru } = derivePRUPair(seed, vault, args.contextId, args.index);
    const commitment = computeCommitment(pruSeed);
    const actionPayloadHash = (args.actionPayloadHash ?? 0n) as Public<FieldElement>;
    const actionCommit = computeActionCommitment(pruSeed, actionPayloadHash);

    const witness: CircuitWitness = {
      walletAddress: stringToField(this.wallet.address) as Private<FieldElement>,
      identitySignature: stringToField(this.identitySignature) as Private<FieldElement>,
      vaultSignature: stringToField(vault) as Private<FieldElement>,
      contextId: stringToField(args.contextId) as Private<FieldElement>,
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
   * Mode B fallback — signature-based authorization for systems that
   * cannot verify ZK proofs. Requires an explicit opt-in flag; this
   * is NOT reachable by default. See docs/07-authorization.md.
   */
  async authorizeFallback(opts: AuthorizeOptions = {}): Promise<string> {
    if (!opts.allowFallback) {
      throw new Error(
        "Mode B (signature fallback) requires allowFallback: true. " +
          "Using it reveals the wallet address to the verifier — see docs/07-authorization.md."
      );
    }
    const timestamp = Date.now();
    const nonce = crypto.randomUUID();
    const challenge = buildSessionChallenge(this.wallet.address, timestamp, nonce);
    return this.wallet.signMessage(challenge);
  }
}

export interface ZKPRUVerifierOptions {
  registry: Registry;
  verifier: VerifierBackend;
}

export class ZKPRUVerifier {
  private registry: Registry;
  private verifier: VerifierBackend;

  constructor(opts: ZKPRUVerifierOptions) {
    this.registry = opts.registry;
    this.verifier = opts.verifier;
  }

  /**
   * Protocol-side check: does this proof legitimately own this PRU,
   * and — if an action is being authorized — was the proof generated
   * specifically for this action? The protocol must compute
   * `actionPayloadHash` itself from the real action being requested;
   * never trust a client-supplied value for it.
   */
  async verify(args: {
    pru: Public<FieldElement>;
    proof: Uint8Array;
    contextId: string;
    actionPayloadHash?: Public<FieldElement>;
    actionCommitment?: Public<FieldElement>;
  }): Promise<boolean> {
    const commitment = await this.registry.getCommitment(args.contextId);
    if (!commitment) return false;
    return verifyProof(
      this.verifier,
      args.proof,
      args.pru,
      commitment as Public<string>,
      (args.actionPayloadHash ?? 0n) as Public<FieldElement>,
      (args.actionCommitment ?? 0n) as Public<FieldElement>
    );
  }
}

export * from "./types.js";
export { deriveIdentity, signIdentityChallenge, signVaultChallenge } from "./identity.js";
export { derivePRU, derivePRUSeed, commitmentHash, actionCommitment } from "./pru.js";
