/**
 * @zk-pru/sdk main entry point.
 */
import { deriveIdentity, buildSessionChallenge } from "./identity.js";
import {
  generatePRU as derivePRUPair,
  derivePRUSeed,
  commitmentHash as computeCommitment,
  actionCommitment as computeActionCommitment,
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
  FieldElement,
  Private,
  Public,
  Registry,
  RegistryBinding,
  WalletSigner,
} from "./types.js";

export interface ZKPRUOptions {
  wallet: WalletSigner;
  registry: Registry;
  prover: ProverBackend;
  registryBinding: RegistryBinding;
}

export class ZKPRU {
  private wallet: WalletSigner;
  private registry: Registry;
  private prover: ProverBackend;
  private registryBinding: RegistryBinding;

  private identitySeed?: Private<FieldElement>;
  private identitySignature?: Private<string>;
  private vaultSignature?: Private<string>;

  constructor(opts: ZKPRUOptions) {
    this.wallet = opts.wallet;
    this.registry = opts.registry;
    this.prover = opts.prover;
    this.registryBinding = opts.registryBinding;
  }

  /** Step 1: derive identity from two fixed Solana signMessage signatures. */
  async deriveIdentity(): Promise<void> {
    const { identitySeed, identitySignature, vaultSignature } = await deriveIdentity(
      this.wallet,
      this.registryBinding
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

  async generatePRU(args: { contextId: string; index: number }): Promise<{
    pru: Public<FieldElement>;
    contextId: string;
    commitmentHash: Public<string>;
  }> {
    const { seed, vault } = this.assertIdentityDerived();
    const { pru, commitmentHash } = derivePRUPair(seed, vault, args.contextId, args.index);
    return { pru, contextId: args.contextId, commitmentHash };
  }

  async register(contextId: string, index = 0): Promise<void> {
    const { seed, vault } = this.assertIdentityDerived();
    const pruSeed = derivePRUSeed(seed, contextId, vault);
    const commitment = computeCommitment(pruSeed);
    const { pru } = derivePRUPair(seed, vault, contextId, index);

    await this.registry.register(contextId, pru.toString(), commitment);
  }

  async proveOwnership(args: {
    contextId: string;
    index: number;
    actionPayloadHash?: FieldElement;
  }): Promise<{
    proof: Uint8Array;
    actionPayloadHash: Public<FieldElement>;
    actionCommitment: Public<FieldElement>;
  }> {
    const { seed, vault } = this.assertIdentityDerived();
    if (!this.identitySignature) throw new Error("Identity not derived.");

    const pruSeed = derivePRUSeed(seed, args.contextId, vault);
    const { pru } = derivePRUPair(seed, vault, args.contextId, args.index);
    const commitment = computeCommitment(pruSeed);
    const actionPayloadHash = (args.actionPayloadHash ?? 0n) as Public<FieldElement>;
    const actionCommit = computeActionCommitment(pruSeed, actionPayloadHash);

    const witness: CircuitWitness = {
      walletAddress: stringToField(this.wallet.publicKey) as Private<FieldElement>,
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
    contextId: string;
    actionPayloadHash?: Public<FieldElement>;
    actionCommitment?: Public<FieldElement>;
  }): Promise<boolean> {
    const record = await this.registry.getRecord(args.pru.toString());
    if (!record || record.contextId !== args.contextId) return false;

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
export {
  buildIdentityChallenge,
  buildVaultChallenge,
  deriveIdentity,
  signIdentityChallenge,
  signVaultChallenge,
} from "./identity.js";
export { derivePRU, derivePRUSeed, commitmentHash, actionCommitment } from "./pru.js";
