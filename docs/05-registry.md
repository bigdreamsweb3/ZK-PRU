# Registry

## Purpose

The registry is the only globally visible state in ZK-PRU. It lets a verifier check that a `commitment_hash` presented alongside a proof corresponds to a previously registered PRU.

## Record Shape

One record is stored per PRU:

```json
{
  "pru": "PRU_0",
  "context_id": "protocol-A",
  "commitment_hash": "Poseidon(PRU_seed[context_id])"
}
```

## Why Keyed By PRU

`context_id` identifies the protocol, application, or deployment scope. It is shared by every user of that protocol, so it cannot be the registry key. If records were keyed only by `context_id`, one user's registration could overwrite another user's commitment under the same protocol.

The PRU is the unique public handle. The verifier receives a PRU, looks up that exact PRU, checks that the record belongs to the expected `context_id`, then verifies the proof against the stored `commitment_hash`.

Because `PRU_seed` is derived per `context_id` (see [`04-pru-generation.md`](./04-pru-generation.md)), each context naturally produces its own independent `commitment_hash`. Two records for two different protocols share no field:

```json
{ "pru": "PRU_A_0", "context_id": "protocol-A", "commitment_hash": "commitment_a" }
{ "pru": "PRU_B_0", "context_id": "protocol-B", "commitment_hash": "commitment_b" }
```

There is no column, index, or derivable value that connects these two records. An observer with full read access to the registry cannot determine whether they belong to the same wallet.

## Strict Rules

- No entropy, seed, or signature storage. The registry never receives anything private.
- No wallet address storage, in any field, at any point.
- No cross-context index, foreign key, or shared identifier of any kind.
- Only `pru`, `context_id`, and `commitment_hash` are stored per record.

## Storage Backends

The registry interface is backend-agnostic. Two reference implementations are included:

- **In-memory** (`registry/memory.ts`) for local development and testing.
- **On-chain adapter** (`registry/onchain.ts`) as a thin interface over a smart contract that stores the same record shape.

Both implement the same interface:

```ts
interface Registry {
  register(contextId: string, pru: string, commitmentHash: string): Promise<void>;
  getRecord(pru: string): Promise<{ contextId: string; commitmentHash: string } | null>;
  getPRUsForContext(contextId: string): Promise<string[]>;
}
```

## Registry Ownership Model

Protocols can integrate ZK-PRU in two ways:

- Use a shared ZK-PRU registry deployment, where many protocols register records under different `context_id` values.
- Deploy their own registry, if they need independent governance, upgrade control, or chain-specific settlement rules.

The privacy model is registry-scoped. If a protocol deploys its own registry, users get PRUs scoped to that registry and `context_id`. If multiple protocols share one registry, they still cannot link users across contexts from registry data alone.

## Threat Model Note

The registry is assumed to be fully public and readable by anyone, including adversaries. The design goal is that publishing the registry does not reveal wallet addresses, signatures, seeds, or cross-context links.
