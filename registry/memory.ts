/**
 * In-memory registry — for local development and testing.
 * Implements docs/05-registry.md exactly: one record per context_id,
 * containing only PRU public keys and a commitment hash. No field
 * links one record to another or to a wallet.
 */
import type { Registry, RegistryRecord } from "../sdk/types.js";

export class MemoryRegistry implements Registry {
  private records = new Map<string, RegistryRecord>();

  async register(
    contextId: string,
    pruPublicKeys: string[],
    commitmentHash: string
  ): Promise<void> {
    // Enforce the record shape at the boundary — no extra fields can
    // sneak in even if a caller tries to pass them via object spread
    // upstream, since this function only accepts these three values.
    this.records.set(contextId, { contextId, pruPublicKeys, commitmentHash });
  }

  async getCommitment(contextId: string): Promise<string | null> {
    return this.records.get(contextId)?.commitmentHash ?? null;
  }

  async getPRUs(contextId: string): Promise<string[]> {
    return this.records.get(contextId)?.pruPublicKeys ?? [];
  }

  /** Test/debug helper only — not part of the Registry interface. */
  _dump(): RegistryRecord[] {
    return Array.from(this.records.values());
  }
}
