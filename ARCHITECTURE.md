# ZK-PRU Architecture Summary

This is a condensed, single-file version of the full spec in `/docs`. For details on any section, follow the linked doc.

## Data flow

```
Wallet
  │ sign(identity_challenge)   [fixed message, signed once]
  │ sign(vault_challenge)      [fixed message, signed once]
  ▼
identity_seed = Poseidon(wallet_address, identity_signature)
  │
  │ + context_id (per protocol) + vault_signature
  ▼
PRU_seed[context_id] = Poseidon(identity_seed, context_id, vault_signature)
  │
  ▼
PRU[context_id][i] = Poseidon(PRU_seed[context_id], i)
  │
  ▼
commitment_hash = Poseidon(PRU_seed[context_id])   → stored in registry
  │
  ▼
ZK Proof (π) proves knowledge of the private inputs behind a PRU
  │
  ▼
Verifier checks π against commitment_hash → authorizes action
```

See: [`docs/02-architecture.md`](./docs/02-architecture.md), [`docs/03-identity-model.md`](./docs/03-identity-model.md), [`docs/04-pru-generation.md`](./docs/04-pru-generation.md)

## Core invariants

1. `wallet_address`, `identity_signature`, and `vault_signature` never leave the client except as private ZK circuit inputs.
2. `identity_seed` and `PRU_seed` are never stored or transmitted in plaintext, anywhere.
3. The registry stores exactly one record per `context_id`: a list of PRU public keys and a `commitment_hash`. No field links two records to the same identity.
4. Every hash in the system uses Poseidon, for circuit compatibility.
5. Recovery requires only wallet access. There is no user-memorized secret anywhere in this design.

See: [`docs/09-security-model.md`](./docs/09-security-model.md)

## Modules

| Module | Responsibility | Location |
|---|---|---|
| Identity derivation | Wallet signature → `identity_seed` | `sdk/identity.ts` |
| PRU generator | `identity_seed` + context → `PRU_seed` → `PRU[i]` | `sdk/pru.ts` |
| Registry | Store/query `{context_id, PRU_public_keys, commitment_hash}` | `registry/` |
| ZK circuit | Prove PRU ownership without revealing private inputs | `circuits/` |
| Proof verifier | Verify π against `commitment_hash` | `sdk/verify.ts` |
| Integration SDK | Protocol-facing API for connect → generate → prove → verify | `sdk/` |

See: [`docs/08-protocol-integration.md`](./docs/08-protocol-integration.md)
