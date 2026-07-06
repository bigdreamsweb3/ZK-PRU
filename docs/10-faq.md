# FAQ

**Do I need to remember a seed phrase for ZK-PRU specifically?**
No. Everything is derived from two fixed wallet signatures, which your wallet can always reproduce. There is nothing separate to write down.

**What happens if I lose my wallet?**
Recovery depends entirely on your wallet's own recovery method (its own seed phrase, hardware key, etc.) — the same as for any wallet-based system. ZK-PRU adds no additional loss risk on top of that.

**Can a protocol tell that two of my PRUs (in different protocols) belong to the same wallet?**
Not from the registry or the proof alone. Each `context_id` produces a structurally independent `PRU_seed` and `commitment_hash`. See [`05-registry.md`](./05-registry.md).

**Can I use the same PRU across multiple protocols to build reputation?**
No — PRUs are context-bound by design. If you want a persistent identity within a single protocol, use the same `context_id` and index every time within that protocol; it will stay consistent there, but won't carry over to a different protocol.

**Does ZK-PRU stop people from creating multiple accounts?**
No. That's explicitly out of scope — see the Non-Goals section in [`09-security-model.md`](./09-security-model.md). ZK-PRU is a privacy tool, not a Sybil-resistance tool.

**What's the actual difference between Mode A and Mode B?**
Mode A (ZK proof) never reveals your wallet address. Mode B (raw signature) does. Mode B exists only for systems that can't yet verify ZK proofs and should never be the default.

**What if `identity_signature` or `vault_signature` leaks?**
This is the most sensitive failure mode in the system — an attacker could reconstruct every PRU you've ever created. See the threat model in [`09-security-model.md`](./09-security-model.md) for mitigations. This is why both values are restricted to client-side use only, as private ZK circuit inputs.
