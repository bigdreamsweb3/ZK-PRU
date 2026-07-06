import { describe, expect, it } from "vitest";
import { MemoryRegistry } from "../registry/memory.js";

describe("MemoryRegistry", () => {
  it("stores one independent record per context", async () => {
    const registry = new MemoryRegistry();
    await registry.register("protocol-A", ["pru-0"], "commit-a");
    await registry.register("protocol-B", ["pru-0"], "commit-b");

    expect(await registry.getCommitment("protocol-A")).toBe("commit-a");
    expect(await registry.getCommitment("protocol-B")).toBe("commit-b");
  });

  it("returns null for an unregistered context", async () => {
    const registry = new MemoryRegistry();
    expect(await registry.getCommitment("nonexistent")).toBeNull();
  });

  it("never stores any field beyond contextId, pruPublicKeys, commitmentHash", async () => {
    const registry = new MemoryRegistry();
    await registry.register("protocol-A", ["pru-0"], "commit-a");
    const [record] = registry._dump();

    expect(Object.keys(record).sort()).toEqual(
      ["commitmentHash", "contextId", "pruPublicKeys"].sort()
    );
  });
});
