/**
 * In-memory registry — for local development and testing.
 *
 * Keyed by PRU, not by context_id. See docs/05-registry.md, "Why keyed
 * by PRU, not by context_id": context_id is shared by every user of a
 * protocol, so keying by context_id alone would let one user's
 * registration overwrite another user's commitment under the same key.
 */
import type { Registry, RegistryRecord } from "../sdk/types.js";

export class MemoryRegistry implements Registry {
  private records = new Map<string, RegistryRecord>();

  async register(contextId: string, pru: string, commitmentHash: string): Promise<void> {
    this.records.set(pru, { pru, contextId, commitmentHash });
  }

  async getRecord(pru: string): Promise<{ contextId: string; commitmentHash: string } | null> {
    const record = this.records.get(pru);
    if (!record) return null;
    return { contextId: record.contextId, commitmentHash: record.commitmentHash };
  }

  async getPRUsForContext(contextId: string): Promise<string[]> {
    return Array.from(this.records.values())
      .filter((r) => r.contextId === contextId)
      .map((r) => r.pru);
  }

  /** Test/debug helper only — not part of the Registry interface. */
  _dump(): RegistryRecord[] {
    return Array.from(this.records.values());
  }
}
