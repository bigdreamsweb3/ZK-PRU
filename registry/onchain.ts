/**
 * On-chain registry adapter — thin interface over a smart contract
 * that stores the same record shape as MemoryRegistry, keyed by PRU
 * (see docs/05-registry.md for why context_id alone can't be the key).
 *
 * Swap `contractClient` for a real chain client (ethers/viem/anchor/etc.)
 * per target chain. The adapter must not add any field beyond
 * {pru, contextId, commitmentHash} to on-chain storage.
 */
import type { Registry } from "../sdk/types.js";

export interface OnChainContractClient {
  callRegister(contextId: string, pru: string, commitmentHash: string): Promise<void>;
  callGetRecord(pru: string): Promise<{ contextId: string; commitmentHash: string } | null>;
  callGetPRUsForContext(contextId: string): Promise<string[]>;
}

export class OnChainRegistry implements Registry {
  constructor(private readonly client: OnChainContractClient) {}

  async register(contextId: string, pru: string, commitmentHash: string): Promise<void> {
    await this.client.callRegister(contextId, pru, commitmentHash);
  }

  async getRecord(pru: string): Promise<{ contextId: string; commitmentHash: string } | null> {
    return this.client.callGetRecord(pru);
  }

  async getPRUsForContext(contextId: string): Promise<string[]> {
    return this.client.callGetPRUsForContext(contextId);
  }
}
