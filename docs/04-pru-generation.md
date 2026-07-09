# PRU Generation

## Derivation (New Architecture)

```
PRU_seed[protocol_id][purpose] = Poseidon(master_seed, protocol_id, purpose)
PRU[protocol_id][purpose][i]   = Poseidon(PRU_seed[protocol_id][purpose], i)
```

- `protocol_id` identifies the protocol, dApp, or service the PRU belongs to. It should be a stable, unique string chosen by convention (e.g. a reverse-domain-style identifier: `xyz.protocol.governance`). The protocol_id is stored in the registry as a lookup key.
- `purpose` allows a user to have multiple independent PRU sets within the same protocol — for example, separate PRUs for "lending", "trading", "gaming", or "main" vs "gaming wallet" within a DeFi protocol.
- `i` is a simple integer index, allowing a user to derive multiple PRUs within the same purpose (e.g. one per sub-feature, or a fresh one per session) without changing `purpose`.
- `PRU_seed` is purpose-bound: two different `purpose` values produce completely unrelated `PRU_seed` values, even though both derive from the same `master_seed`.

## Key Security Properties

1. **The master seed is independent of any wallet.** In the old architecture, PRUs were derived from `identity_seed`, which was derived from wallet signatures. This meant a stolen signature could compromise all PRUs.

2. **Protocol-independent recovery.** The user can derive ALL their PRUs using ONLY their wallet + encrypted seed blob, without depending on any protocol. This is crucial if a PRU holds funds and the original protocol disappears.

```
master_seed ← CSPRNG (no wallet involvement)
PRU_seed ← Poseidon(master_seed, protocol_id, purpose)
```

A stolen wallet signature cannot derive the master_seed because there is no mathematical relationship between them.

## Why This Design

- **One hash function throughout.** Poseidon is used for every derivation step, including inside the ZK circuit. Using a generic hash function (e.g. SHA-256) outside the circuit and Poseidon inside it would force the circuit to also implement SHA-256 in-circuit, which is far more expensive in constraints. Standardizing on Poseidon avoids this entirely.
- **Purpose for multi-purpose wallets.** A user might want separate PRU sets for different use cases within the same protocol. The `purpose` parameter allows this without requiring a new master seed.
- **Protocol-independent derivation.** The protocol_id is included in PRU derivation, but the user can ALWAYS recompute their PRUs from just the master_seed. The protocol_id is a namespace, not a dependency.

## Example

```ts
import { poseidon } from "./poseidon";

function derivePRUSeed(masterSeed: Uint8Array, protocolId: string, purpose: string): bigint {
  // Convert 32-byte master seed to field element
  let value = 0n;
  for (const byte of masterSeed) {
    value = (value << 8n) | BigInt(byte);
  }
  // Reduce modulo BN254 prime
  const BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  value = value % BN254_PRIME;

  return poseidon([value, protocolId, purpose]);
}

function derivePRU(pruSeed: bigint, index: number): bigint {
  return poseidon([pruSeed, index]);
}
```

## Purpose Examples

A user might use the same ZK-PRU master seed across many protocols:

```
Protocol: defi-xyz
├── Purpose: "lending"     → PRU_seed = Poseidon(master_seed, "defi-xyz", "lending")
├── Purpose: "trading"     → PRU_seed = Poseidon(master_seed, "defi-xyz", "trading")
└── Purpose: "gaming"      → PRU_seed = Poseidon(master_seed, "defi-xyz", "gaming")

Protocol: social-app
├── Purpose: "posts"       → PRU_seed = Poseidon(master_seed, "social-app", "posts")
└── Purpose: "dms"         → PRU_seed = Poseidon(master_seed, "social-app", "dms")
```

Each purpose is completely independent. If the "social-app" protocol disappears, the user can still access their funds through their PRUs derived from the master seed.

## Multiple PRUs per Purpose

A user may want more than one PRU within a single purpose — for example, a fresh identity per session. Simply increment `i`:

```
PRU[protocol_id][purpose][0] = Poseidon(PRU_seed[protocol_id][purpose], 0)
PRU[protocol_id][purpose][1] = Poseidon(PRU_seed[protocol_id][purpose], 1)
```

Both share the same `PRU_seed`, so a protocol that controls both indices internally could in principle correlate PRUs it itself issued indices for — but no external party can, since `PRU_seed` is never exposed.

## What is Never Exposed

| Value | Exposed to registry? | Exposed to protocol? | Exposed to circuit verifier? |
|---|---|---|---|
| `master_seed` | No | No | No (private input, converted to field) |
| `vault_key` | No | No | No (memory only, for encryption only) |
| `PRU_seed` | No | No | No (intermediate, computed in-circuit) |
| `PRU` | Yes | Yes | Yes (public input) |
| `commitment_hash` | Yes | Yes | Yes (public input) |
