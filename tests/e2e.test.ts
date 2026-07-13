import { describe, expect, it } from "vitest";
import { ZKPRU, ZKPRUVerifier, type SeedStorage } from "../sdk/index.js";
import { MockWallet } from "../sdk/mock-wallet.js";
import { MockProver, MockVerifier } from "../sdk/mock-backend.js";
import { MemoryRegistry } from "../registry/memory.js";
import type { RegistryBinding, SeedBlob } from "../sdk/types.js";

const REGISTRY_BINDING: RegistryBinding = {
  cluster: "devnet",
  registryProgramId: "ZkPruRegistryDevnet111111111111111111111111",
  version: "v1",
};

class MemorySeedStorage implements SeedStorage {
  private seedBlob: SeedBlob | null = null;

  async save(seedBlob: SeedBlob): Promise<void> {
    this.seedBlob = seedBlob;
  }

  async load(): Promise<SeedBlob | null> {
    return this.seedBlob;
  }
}

function makeClient(wallet: MockWallet, registry: MemoryRegistry) {
  return new ZKPRU({
    wallet,
    registry,
    prover: new MockProver(),
    registryBinding: REGISTRY_BINDING,
    storage: new MemorySeedStorage(),
  });
}

describe("end-to-end: vault -> PRU -> proof -> verify", () => {
  it("generates two unlinkable PRUs across two protocols, both independently verifiable", async () => {
    const wallet = new MockWallet("SoLanaWallet111111111111111111111111111111", "secret-key-1");
    const registry = new MemoryRegistry();
    const client = makeClient(wallet, registry);
    const verifier = new ZKPRUVerifier({ registry, verifier: new MockVerifier() });

    await client.initializeVault();

    const pruA = await client.generatePRU({ protocolId: "protocol-A", purpose: "payment", index: 0 });
    const pruB = await client.generatePRU({ protocolId: "protocol-B", purpose: "payment", index: 0 });

    await client.register({ protocolId: "protocol-A", purpose: "payment", index: 0 });
    await client.register({ protocolId: "protocol-B", purpose: "payment", index: 0 });

    const recordA = registry._dump().find((r) => r.contextId === "protocol-A")!;
    const recordB = registry._dump().find((r) => r.contextId === "protocol-B")!;

    expect(recordA.commitmentHash).not.toBe(recordB.commitmentHash);
    expect(recordA.pru).not.toBe(recordB.pru);

    const proofA = await client.proveOwnership({ protocolId: "protocol-A", purpose: "payment", index: 0 });
    const proofB = await client.proveOwnership({ protocolId: "protocol-B", purpose: "payment", index: 0 });

    expect(await verifier.verify({
      pru: pruA.pru,
      proof: proofA.proof,
      protocolId: "protocol-A",
      actionPayloadHash: proofA.actionPayloadHash,
      actionCommitment: proofA.actionCommitment,
    })).toBe(true);

    expect(await verifier.verify({
      pru: pruB.pru,
      proof: proofB.proof,
      protocolId: "protocol-B",
      actionPayloadHash: proofB.actionPayloadHash,
      actionCommitment: proofB.actionCommitment,
    })).toBe(true);
  });

  it("rejects a proof for protocol A when checked against protocol B", async () => {
    const wallet = new MockWallet("SoLanaWallet111111111111111111111111111111", "secret-key-1");
    const registry = new MemoryRegistry();
    const client = makeClient(wallet, registry);
    const verifier = new ZKPRUVerifier({ registry, verifier: new MockVerifier() });

    await client.initializeVault();

    const pruA = await client.generatePRU({ protocolId: "protocol-A", purpose: "payment", index: 0 });
    await client.register({ protocolId: "protocol-A", purpose: "payment", index: 0 });
    await client.register({ protocolId: "protocol-B", purpose: "payment", index: 0 });

    const proofA = await client.proveOwnership({ protocolId: "protocol-A", purpose: "payment", index: 0 });

    expect(await verifier.verify({
      pru: pruA.pru,
      proof: proofA.proof,
      protocolId: "protocol-B",
      actionPayloadHash: proofA.actionPayloadHash,
      actionCommitment: proofA.actionCommitment,
    })).toBe(false);
  });

  it("rejects a proof replayed against a different action payload", async () => {
    const wallet = new MockWallet("SoLanaWallet111111111111111111111111111111", "secret-key-1");
    const registry = new MemoryRegistry();
    const client = makeClient(wallet, registry);
    const verifier = new ZKPRUVerifier({ registry, verifier: new MockVerifier() });

    await client.initializeVault();

    const pruA = await client.generatePRU({ protocolId: "protocol-A", purpose: "payment", index: 0 });
    await client.register({ protocolId: "protocol-A", purpose: "payment", index: 0 });

    const originalAction = 111222333n;
    const attackerSubstitutedAction = 999888777n;

    const proof = await client.proveOwnership({
      protocolId: "protocol-A",
      purpose: "payment",
      index: 0,
      actionPayloadHash: originalAction,
    });

    expect(await verifier.verify({
      pru: pruA.pru,
      proof: proof.proof,
      protocolId: "protocol-A",
      actionPayloadHash: originalAction as any,
      actionCommitment: proof.actionCommitment,
    })).toBe(true);

    expect(await verifier.verify({
      pru: pruA.pru,
      proof: proof.proof,
      protocolId: "protocol-A",
      actionPayloadHash: attackerSubstitutedAction as any,
      actionCommitment: proof.actionCommitment,
    })).toBe(false);
  });

  it("blocks Mode B fallback unless allowFallback is explicitly set", async () => {
    const wallet = new MockWallet("SoLanaWallet111111111111111111111111111111", "secret-key-1");
    const registry = new MemoryRegistry();
    const client = makeClient(wallet, registry);

    await client.initializeVault();

    await expect(client.authorizeFallback()).rejects.toThrow(/allowFallback/);
    await expect(client.authorizeFallback({ allowFallback: true })).resolves.toBeTypeOf("string");
  });
});
