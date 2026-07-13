import { describe, expect, it } from "vitest";
import { derivePRUSeed, derivePRU, deriveUserSecretNamespace, generatePRU } from "../sdk/pru.js";
import type { MasterSeed } from "../sdk/types.js";

function masterSeed(fill: number): MasterSeed {
  return new Uint8Array(32).fill(fill) as MasterSeed;
}

describe("PRU generation", () => {
  it("derives a stable user secret namespace from the master seed", () => {
    const seed = masterSeed(5);

    expect(deriveUserSecretNamespace(seed)).toBe(deriveUserSecretNamespace(seed));
    expect(deriveUserSecretNamespace(seed)).not.toBe(deriveUserSecretNamespace(masterSeed(6)));
  });

  it("produces different PRU_seed values for different protocols", () => {
    const seed = masterSeed(7);

    const seedA = derivePRUSeed(seed, "protocol-A", "payment");
    const seedB = derivePRUSeed(seed, "protocol-B", "payment");

    expect(seedA).not.toBe(seedB);
  });

  it("produces different PRU_seed values for different purposes", () => {
    const seed = masterSeed(7);

    const receiving = derivePRUSeed(seed, "trustlink", "tin-receiving");
    const settlement = derivePRUSeed(seed, "trustlink", "tsn-settlement");

    expect(receiving).not.toBe(settlement);
  });

  it("is deterministic for the same master seed, protocol, purpose, and index", () => {
    const seed = masterSeed(11);

    const first = generatePRU(seed, "protocol-A", "payment", 0);
    const second = generatePRU(seed, "protocol-A", "payment", 0);

    expect(first.pru).toBe(second.pru);
    expect(first.commitmentHash).toBe(second.commitmentHash);
  });

  it("produces distinct PRUs for different indices within the same purpose", () => {
    const seed = masterSeed(13);
    const pruSeed = derivePRUSeed(seed, "protocol-A", "payment");

    const pru0 = derivePRU(pruSeed, 0);
    const pru1 = derivePRU(pruSeed, 1);

    expect(pru0).not.toBe(pru1);
  });
});
