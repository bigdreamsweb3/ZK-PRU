import { describe, expect, it } from "vitest";
import { ZKPRU, ZKPRUVerifier } from "../sdk/index.js";
import { MockWallet } from "../sdk/mock-wallet.js";
import { MockProver, MockVerifier } from "../sdk/mock-backend.js";
import { MemoryRegistry } from "../registry/memory.js";

const CHAIN_ID = 1;
const REGISTRY_ADDRESS = "0xRegistryContractAddress";

function makeClient(wallet: MockWallet, registry: MemoryRegistry) {
  return new ZKPRU({
    wallet,
    registry,
    prover: new MockProver(),
    chainId: CHAIN_ID,
    registryAddress: REGISTRY_ADDRESS,
  });
}

describe("end-to-end: connect wallet -> PRU -> proof -> verify", () => {
  it("generates two unlinkable PRUs across two contexts, both independently verifiable", async () => {
    const wallet = new MockWallet("0xabc123", "secret-key-1");
    const registry = new MemoryRegistry();
    const client = makeClient(wallet, registry);
    const verifier = new ZKPRUVerifier({ registry, verifier: new MockVerifier() });

    await client.deriveIdentity();

    const pruA = await client.generatePRU({ contextId: "protocol-A", index: 0 });
    const pruB = await client.generatePRU({ contextId: "protocol-B", index: 0 });

    await client.register("protocol-A", 0);
    await client.register("protocol-B", 0);

    // No shared derivable value between the two registry records.
    const recordA = registry._dump().find((r) => r.contextId === "protocol-A")!;
    const recordB = registry._dump().find((r) => r.contextId === "protocol-B")!;
    expect(recordA.commitmentHash).not.toBe(recordB.commitmentHash);
    expect(recordA.pruPublicKeys).not.toEqual(recordB.pruPublicKeys);

    const proofA = await client.proveOwnership({ contextId: "protocol-A", index: 0 });
    const proofB = await client.proveOwnership({ contextId: "protocol-B", index: 0 });

    expect(
      await verifier.verify({
        pru: pruA.pru,
        proof: proofA.proof,
        contextId: "protocol-A",
        actionPayloadHash: proofA.actionPayloadHash,
        actionCommitment: proofA.actionCommitment,
      })
    ).toBe(true);
    expect(
      await verifier.verify({
        pru: pruB.pru,
        proof: proofB.proof,
        contextId: "protocol-B",
        actionPayloadHash: proofB.actionPayloadHash,
        actionCommitment: proofB.actionCommitment,
      })
    ).toBe(true);
  });

  it("rejects a proof for context A when checked against context B's commitment", async () => {
    const wallet = new MockWallet("0xabc123", "secret-key-1");
    const registry = new MemoryRegistry();
    const client = makeClient(wallet, registry);
    const verifier = new ZKPRUVerifier({ registry, verifier: new MockVerifier() });

    await client.deriveIdentity();
    const pruA = await client.generatePRU({ contextId: "protocol-A", index: 0 });
    await client.generatePRU({ contextId: "protocol-B", index: 0 });
    await client.register("protocol-A", 0);
    await client.register("protocol-B", 0);

    const proofA = await client.proveOwnership({ contextId: "protocol-A", index: 0 });

    // Verifying protocol-A's proof/PRU against protocol-B's commitment must fail.
    const isValid = await verifier.verify({
      pru: pruA.pru,
      proof: proofA.proof,
      contextId: "protocol-B",
      actionPayloadHash: proofA.actionPayloadHash,
      actionCommitment: proofA.actionCommitment,
    });
    expect(isValid).toBe(false);
  });

  it("rejects a proof replayed against a different action payload", async () => {
    // This is the concrete replay/front-running protection from
    // docs/06-zk-proofs.md: a proof generated for one action must not
    // verify against a different action_payload_hash.
    const wallet = new MockWallet("0xabc123", "secret-key-1");
    const registry = new MemoryRegistry();
    const client = makeClient(wallet, registry);
    const verifier = new ZKPRUVerifier({ registry, verifier: new MockVerifier() });

    await client.deriveIdentity();
    const pruA = await client.generatePRU({ contextId: "protocol-A", index: 0 });
    await client.register("protocol-A", 0);

    const originalAction = 111222333n;
    const attackerSubstitutedAction = 999888777n;

    const proof = await client.proveOwnership({
      contextId: "protocol-A",
      index: 0,
      actionPayloadHash: originalAction,
    });

    // Legit verification against the real action succeeds.
    expect(
      await verifier.verify({
        pru: pruA.pru,
        proof: proof.proof,
        contextId: "protocol-A",
        actionPayloadHash: originalAction as any,
        actionCommitment: proof.actionCommitment,
      })
    ).toBe(true);

    // Replaying the same proof against a different action must fail.
    expect(
      await verifier.verify({
        pru: pruA.pru,
        proof: proof.proof,
        contextId: "protocol-A",
        actionPayloadHash: attackerSubstitutedAction as any,
        actionCommitment: proof.actionCommitment,
      })
    ).toBe(false);
  });

  it("blocks Mode B fallback unless allowFallback is explicitly set", async () => {
    const wallet = new MockWallet("0xabc123", "secret-key-1");
    const registry = new MemoryRegistry();
    const client = makeClient(wallet, registry);

    await client.deriveIdentity();

    await expect(client.authorizeFallback()).rejects.toThrow(/allowFallback/);
    await expect(client.authorizeFallback({ allowFallback: true })).resolves.toBeTypeOf("string");
  });
});
