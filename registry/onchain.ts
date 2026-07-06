/**
 * On-chain registry adapter — thin interface over a smart contract
 * that stores the same record shape as MemoryRegistry. The contract
 * itself is out of scope here (see CODEX_PROMPT.md, deliverable 2) —
 * this file defines the adapter contract implementers must satisfy.
 *
 * Swap `contractClient` for a real chain client (ethers/viem/anchor/etc.)
 * per target chain. The adapter must not add any field beyond
 * {contextId, pruPublicKeys, commitmentHash} to on-chain storage.
 */
import type { Registry } from "../sdk/types.js";

export interface OnChainContractClient {
  callRegister(contextId: string, pruPublicKeys: string[], commitmentHash: string): Promise<void>;
  callGetCommitment(contextId: string): Promise<string | null>;
  callGetPRUs(contextId: string): Promise<string[]>;
}

export class OnChainRegistry implements Registry {
  constructor(private readonly client: OnChainContractClient) {}

  async register(
    contextId: string,
    pruPublicKeys: string[],
    commitmentHash: string
  ): Promise<void> {
    await this.client.callRegister(contextId, pruPublicKeys, commitmentHash);
  }

  async getCommitment(contextId: string): Promise<string | null> {
    return this.client.callGetCommitment(contextId);
  }

  async getPRUs(contextId: string): Promise<string[]> {
    return this.client.callGetPRUs(contextId);
  }
}
