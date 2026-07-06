# Protocol Integration

## Integration checklist

To integrate ZK-PRU, a protocol needs to:

1. Choose a stable `context_id` for itself (e.g. `"acme.protocol.mainnet"`).
2. Deploy or connect to a registry instance (in-memory for testing, on-chain for production — see [`05-registry.md`](./05-registry.md)).
3. Deploy or connect to a ZK verifier for the ZK-PRU circuit (see [`06-zk-proofs.md`](./06-zk-proofs.md)).
4. Accept `{PRU, π}` pairs at any point that currently accepts a wallet address/signature, and call the verifier instead of checking a raw signature.
5. (Optional) Offer Mode B fallback explicitly, flagged as lower-privacy, for compatibility.

## SDK usage — client side

```ts
import { ZKPRU } from "@zk-pru/sdk";

const zkpru = new ZKPRU({ wallet, registry });

// One-time: derive identity (cached client-side for the session)
await zkpru.deriveIdentity();

// Per protocol: generate a PRU
const { pru, contextId } = await zkpru.generatePRU({ contextId: "acme.protocol.mainnet", index: 0 });

// Register the PRU + commitment (first use only)
await zkpru.register(contextId);

// Generate a proof to authorize an action
const proof = await zkpru.proveOwnership({ contextId, index: 0 });

// Submit to the protocol
await fetch("https://acme.protocol/authorize", {
  method: "POST",
  body: JSON.stringify({ pru, proof }),
});
```

## SDK usage — protocol/verifier side

```ts
import { ZKPRUVerifier } from "@zk-pru/sdk";

const verifier = new ZKPRUVerifier({ registry });

app.post("/authorize", async (req, res) => {
  const { pru, proof } = req.body;
  const isValid = await verifier.verify({ pru, proof, contextId: "acme.protocol.mainnet" });
  if (!isValid) return res.status(401).send("invalid proof");
  // proceed with authorized action
});
```

## Design constraints for integrators

- Never request a raw wallet signature as a substitute for a ZK proof unless explicitly falling back to Mode B, and never do so silently.
- Never store `PRU_seed`, `identity_seed`, or either fixed signature server-side, even temporarily, even for debugging.
- Treat `context_id` as part of your protocol's public identity — changing it later effectively issues all users new, unlinked PRUs.
- If your protocol needs Sybil-resistance, do not rely on ZK-PRU alone (see [`09-security-model.md`](./09-security-model.md), Non-Goals). Layer a separate mechanism on top.
