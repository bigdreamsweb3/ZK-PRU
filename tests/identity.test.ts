import { describe, expect, it } from "vitest";
import { deriveIdentity, signIdentityChallenge, signVaultChallenge } from "../sdk/identity.js";
import { MockWallet } from "../sdk/mock-wallet.js";

const CHAIN_ID = 1;
const REGISTRY_ADDRESS = "0xRegistryContractAddress";

describe("identity derivation", () => {
  it("is deterministic across repeated calls for the same wallet", async () => {
    const wallet = new MockWallet("0xabc123", "secret-key-1");
    const first = await deriveIdentity(wallet, CHAIN_ID, REGISTRY_ADDRESS);
    const second = await deriveIdentity(wallet, CHAIN_ID, REGISTRY_ADDRESS);

    expect(first.identitySeed).toBe(second.identitySeed);
    expect(first.vaultSignature).toBe(second.vaultSignature);
  });

  it("produces different identity seeds for different wallets", async () => {
    const walletA = new MockWallet("0xaaa", "secret-a");
    const walletB = new MockWallet("0xbbb", "secret-b");

    const a = await deriveIdentity(walletA, CHAIN_ID, REGISTRY_ADDRESS);
    const b = await deriveIdentity(walletB, CHAIN_ID, REGISTRY_ADDRESS);

    expect(a.identitySeed).not.toBe(b.identitySeed);
  });

  it("builds distinct EIP-712 signatures for identity vs vault", async () => {
    const wallet = new MockWallet("0xabc123", "secret-key-1");
    const identitySig = await signIdentityChallenge(wallet, CHAIN_ID, REGISTRY_ADDRESS);
    const vaultSig = await signVaultChallenge(wallet, CHAIN_ID, REGISTRY_ADDRESS);
    expect(identitySig).not.toBe(vaultSig);
  });

  it("produces a different identity signature when bound to a different registry contract", async () => {
    // This is the phishing-resistance property from docs/03-identity-model.md:
    // the same wallet signing the "same" challenge against a different
    // verifyingContract must produce a different signature.
    const wallet = new MockWallet("0xabc123", "secret-key-1");
    const sigForRealContract = await signIdentityChallenge(wallet, CHAIN_ID, "0xRealRegistry");
    const sigForPhishingContract = await signIdentityChallenge(wallet, CHAIN_ID, "0xPhishingRegistry");
    expect(sigForRealContract).not.toBe(sigForPhishingContract);
  });
});
