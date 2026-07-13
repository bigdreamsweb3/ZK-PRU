import { describe, expect, it } from "vitest";
import { MemoryRegistry } from "../registry/memory.js";

describe("MemoryRegistry", () => {
  it("stores one independent record per PRU", async () => {
    const registry = new MemoryRegistry();
    await registry.register("protocol-A", "pru-a", "commit-a");
    await registry.register("protocol-B", "pru-b", "commit-b");

    expect(await registry.getRecord("pru-a")).toEqual({
      contextId: "protocol-A",
      commitmentHash: "commit-a",
    });
    expect(await registry.getRecord("pru-b")).toEqual({
      contextId: "protocol-B",
      commitmentHash: "commit-b",
    });
  });

  it("returns null for an unregistered PRU", async () => {
    const registry = new MemoryRegistry();
    expect(await registry.getRecord("nonexistent")).toBeNull();
  });

  it("never stores any field beyond pru, contextId, commitmentHash", async () => {
    const registry = new MemoryRegistry();
    await registry.register("protocol-A", "pru-0", "commit-a");
    const [record] = registry._dump();

    if (!record) throw new Error("expected a registry record to be present");

    expect(Object.keys(record).sort()).toEqual(
      ["commitmentHash", "contextId", "pru"].sort(),
    );
  });
});
