import { describe, expect, it } from "vitest";
import { buildRecoveryChallenge, createIdentity, deriveMasterSeed, generateRandomEntropy } from "../sdk/identity.js";
import { MockWallet } from "../sdk/mock-wallet.js";
import type { RegistryBinding } from "../sdk/types.js";

const REGISTRY_BINDING: RegistryBinding = {
  cluster: "devnet",
  registryProgramId: "ZkPruRegistryDevnet111111111111111111111111",
  version: "v1",
};

describe("identity and master seed", () => {
  it("generates 32 bytes of random entropy", () => {
    expect(generateRandomEntropy()).toHaveLength(32);
  });

  it("derives deterministic master seeds from the same identity seed and entropy", () => {
    const entropy = new Uint8Array(32).fill(9);
    const first = deriveMasterSeed(12345n, entropy);
    const second = deriveMasterSeed(12345n, entropy);

    expect(Buffer.from(first).toString("hex")).toBe(Buffer.from(second).toString("hex"));
  });

  it("creates different master seeds across fresh vault initializations", async () => {
    const wallet = new MockWallet("SoLanaWallet111111111111111111111111111111", "secret-key-1");

    const first = await createIdentity(wallet, REGISTRY_BINDING);
    const second = await createIdentity(wallet, REGISTRY_BINDING);

    expect(Buffer.from(first.identity.masterSeed).toString("hex")).not.toBe(
      Buffer.from(second.identity.masterSeed).toString("hex")
    );
  });

  it("builds expiring recovery challenges", () => {
    const challenge = buildRecoveryChallenge("SoLanaWallet111111111111111111111111111111", REGISTRY_BINDING);

    expect(challenge.challenge.length).toBeGreaterThan(0);
    expect(challenge.expiresAt).toBeGreaterThan(challenge.timestamp);
  });
});
