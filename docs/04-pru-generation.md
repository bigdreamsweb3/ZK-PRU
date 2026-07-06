# PRU Generation

## Derivation

```
PRU_seed[context_id] = Poseidon(identity_seed, context_id, vault_signature)
PRU[context_id][i]   = Poseidon(PRU_seed[context_id], i)
```

- `context_id` identifies the protocol, dApp, or session the PRU belongs to. It should be a stable, unique string chosen by convention (e.g. a reverse-domain-style identifier: `xyz.protocol.governance`).
- `i` is a simple integer index, allowing a user to derive multiple PRUs within the same context (e.g. one per sub-application, or a fresh one per session) without changing `context_id`.
- `PRU_seed` is context-bound: two different `context_id` values produce completely unrelated `PRU_seed` values, even though both derive from the same `identity_seed`.

## Why this shape

- **One hash function throughout.** Poseidon is used for every derivation step, including inside the ZK circuit. Using a generic hash function (e.g. SHA-256) outside the circuit and Poseidon inside it would force the circuit to also implement SHA-256 in-circuit, which is far more expensive in constraints. Standardizing on Poseidon avoids this entirely.
- **`vault_signature` inside `PRU_seed`, not `identity_seed`.** This means `identity_seed` alone is not sufficient to derive any PRU — both fixed signatures are required. This preserves the two-factor property that a memorized recovery phrase used to provide, without requiring the user to hold anything themselves.
- **Context-binding at the `PRU_seed` level, not the `PRU` level.** Binding context earlier (at the seed) rather than later (only at the final PRU) ensures that even the intermediate seed is unrecoverable across contexts — there's no shared intermediate value an attacker could target to compromise multiple contexts at once.

## Example

```ts
import { poseidon } from "./poseidon";

function deriveIdentitySeed(walletAddress: string, identitySignature: string): bigint {
  return poseidon([walletAddress, identitySignature]);
}

function derivePRUSeed(identitySeed: bigint, contextId: string, vaultSignature: string): bigint {
  return poseidon([identitySeed, contextId, vaultSignature]);
}

function derivePRU(pruSeed: bigint, index: number): bigint {
  return poseidon([pruSeed, index]);
}
```

## Multiple PRUs per context

A user may want more than one PRU within a single protocol — for example, a fresh identity per sub-feature. Simply increment `i`:

```
PRU[context_id][0] = Poseidon(PRU_seed[context_id], 0)
PRU[context_id][1] = Poseidon(PRU_seed[context_id], 1)
```

Both share the same `PRU_seed`, so a protocol that controls both contexts internally could in principle correlate PRUs it itself issued indices for — but no external party can, since `PRU_seed` is never exposed.

## What is never exposed

| Value | Exposed to registry? | Exposed to protocol? | Exposed to circuit verifier? |
|---|---|---|---|
| `wallet_address` | No | No | No (private input) |
| `identity_signature` | No | No | No (private input) |
| `vault_signature` | No | No | No (private input) |
| `identity_seed` | No | No | No (intermediate, computed in-circuit) |
| `PRU_seed` | No | No | No (intermediate, computed in-circuit) |
| `PRU` | Yes | Yes | Yes (public input) |
| `commitment_hash` | Yes | Yes | Yes (public input) |
