# Registry

## Purpose

The registry is the only globally visible state in ZK-PRU. It exists to let a verifier check that a `commitment_hash` presented alongside a proof actually corresponds to a previously registered PRU set — nothing more.

## Record shape

One record per `context_id`:

```json
{
  "context_id": "protocol-A",
  "PRU_public_keys": ["PRU_0", "PRU_1"],
  "commitment_hash": "Poseidon(PRU_seed[context_id])"
}
```

## Why one record per context, not one per identity

An earlier version of this design stored a single `commitment_hash` per identity, shared across every PRU that identity generated. This is a critical privacy defect: any two PRUs sharing a commitment are trivially linkable to the same underlying identity, even though the PRUs themselves look unrelated.

Because `PRU_seed` is derived per-`context_id` (see [`04-pru-generation.md`](./04-pru-generation.md)), each context naturally produces its own independent `commitment_hash`. Two records for two different protocols share no field:

```json
{ "context_id": "protocol-A", "PRU_public_keys": ["PRU_0"], "commitment_hash": "0xabc..." }
{ "context_id": "protocol-B", "PRU_public_keys": ["PRU_0"], "commitment_hash": "0xdef..." }
```

There is no column, index, or derivable value that connects these two records. An observer with full read access to the entire registry cannot determine whether they belong to the same wallet.

## Strict rules

- No entropy, seed, or signature storage — the registry never receives anything private.
- No wallet address storage, in any field, at any point.
- No cross-context index, foreign key, or shared identifier of any kind.
- Only `context_id`, `PRU_public_keys`, and `commitment_hash` per record.

## Storage backends

The registry interface is backend-agnostic. Two reference implementations are included:

- **In-memory** (`registry/memory.ts`) — for local development and testing.
- **On-chain adapter** (`registry/onchain.ts`) — a thin interface over a smart contract that stores the same record shape, for deployments where public verifiability of the registry itself matters.

Both implement the same interface:

```ts
interface Registry {
  register(contextId: string, pruPublicKeys: string[], commitmentHash: string): Promise<void>;
  getCommitment(contextId: string): Promise<string | null>;
  getPRUs(contextId: string): Promise<string[]>;
}
```

## Threat model note

The registry is assumed to be fully public and readable by anyone, including adversaries. The entire design goal of §4–5 is that this assumption causes no privacy loss — the registry should be safe to publish on a public blockchain with no additional access control.
