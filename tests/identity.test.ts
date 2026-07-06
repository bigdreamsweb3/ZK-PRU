import { describe, expect, it } from "vitest";
import { deriveIdentity, signIdentityChallenge, signVaultChallenge } from "../sdk/identity.js";
import { MockWallet } from "../sdk/mock-wallet.js";
import type { RegistryBinding } from "../sdk/types.js";

const REGISTRY_BINDING: RegistryBinding = {
  cluster: "devnet",
  registryProgramId: "ZkPruRegistryDevnet111111111111111111111111",
  version: "v1",
};

describe("identity derivation", () => {
  it("is deterministic across repeated calls for the same wallet", async () => {
    const wallet = new MockWallet("SoLanaWallet111111111111111111111111111111", "secret-key-1");
    const first = await deriveIdentity(wallet, REGISTRY_BINDING);
    const second = await deriveIdentity(wallet, REGISTRY_BINDING);

    expect(first.identitySeed).toBe(second.identitySeed);
    expect(first.vaultSignature).toBe(second.vaultSignature);
  });

  it("produces different identity seeds for different wallets", async () => {
    const walletA = new MockWallet("SoLanaWalletAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "secret-a");
    const walletB = new MockWallet("SoLanaWalletBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "secret-b");

    const a = await deriveIdentity(walletA, REGISTRY_BINDING);
    const b = await deriveIdentity(walletB, REGISTRY_BINDING);

    expect(a.identitySeed).not.toBe(b.identitySeed);
  });

  it("builds distinct Solana signatures for identity vs vault", async () => {
    const wallet = new MockWallet("SoLanaWallet111111111111111111111111111111", "secret-key-1");
    const identitySig = await signIdentityChallenge(wallet, REGISTRY_BINDING);
    const vaultSig = await signVaultChallenge(wallet, REGISTRY_BINDING);
    expect(identitySig).not.toBe(vaultSig);
  });

  it("produces a different identity signature when bound to a different registry program", async () => {
    const wallet = new MockWallet("SoLanaWallet111111111111111111111111111111", "secret-key-1");
    const realBinding = REGISTRY_BINDING;
    const phishingBinding: RegistryBinding = {
      ...REGISTRY_BINDING,
      registryProgramId: "FakeZkPruRegistry1111111111111111111111111",
    };

    expect(await signIdentityChallenge(wallet, realBinding)).not.toBe(
      await signIdentityChallenge(wallet, phishingBinding)
    );
  });
});
