import { describe, expect, it } from "vitest";
import { deriveIdentity } from "../sdk/identity.js";
import { derivePRUSeed, derivePRU, generatePRU } from "../sdk/pru.js";
import { MockWallet } from "../sdk/mock-wallet.js";

const CHAIN_ID = 1;
const REGISTRY_ADDRESS = "0xRegistryContractAddress";

describe("PRU generation", () => {
  it("produces different PRU_seed values for different contexts from the same identity", async () => {
    const wallet = new MockWallet("0xabc123", "secret-key-1");
    const { identitySeed, vaultSignature } = await deriveIdentity(wallet, CHAIN_ID, REGISTRY_ADDRESS);

    const seedA = derivePRUSeed(identitySeed, "protocol-A", vaultSignature);
    const seedB = derivePRUSeed(identitySeed, "protocol-B", vaultSignature);

    expect(seedA).not.toBe(seedB);
  });

  it("produces different commitment hashes for different contexts, with no shared derivable value", async () => {
    const wallet = new MockWallet("0xabc123", "secret-key-1");
    const { identitySeed, vaultSignature } = await deriveIdentity(wallet, CHAIN_ID, REGISTRY_ADDRESS);

    const a = generatePRU(identitySeed, vaultSignature, "protocol-A", 0);
    const b = generatePRU(identitySeed, vaultSignature, "protocol-B", 0);

    expect(a.commitmentHash).not.toBe(b.commitmentHash);
    expect(a.pru).not.toBe(b.pru);
  });

  it("is deterministic: same identity + context + index always yields the same PRU", async () => {
    const wallet = new MockWallet("0xabc123", "secret-key-1");
    const { identitySeed, vaultSignature } = await deriveIdentity(wallet, CHAIN_ID, REGISTRY_ADDRESS);

    const first = generatePRU(identitySeed, vaultSignature, "protocol-A", 0);
    const second = generatePRU(identitySeed, vaultSignature, "protocol-A", 0);

    expect(first.pru).toBe(second.pru);
    expect(first.commitmentHash).toBe(second.commitmentHash);
  });

  it("produces distinct PRUs for different indices within the same context", async () => {
    const wallet = new MockWallet("0xabc123", "secret-key-1");
    const { identitySeed, vaultSignature } = await deriveIdentity(wallet, CHAIN_ID, REGISTRY_ADDRESS);
    const seed = derivePRUSeed(identitySeed, "protocol-A", vaultSignature);

    const pru0 = derivePRU(seed, 0);
    const pru1 = derivePRU(seed, 1);

    expect(pru0).not.toBe(pru1);
  });
});
