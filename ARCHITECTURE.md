# ZK-PRU Architecture Summary

This is a condensed, single-file version of the full spec in `/docs`. For details on any section, follow the linked doc.

## The Security Problem We Solved

**Old architecture (VULNERABLE):**
```
identity_seed = Poseidon(wallet_address, identity_signature)
PRU_seed = Poseidon(identity_seed, ...)  // Direct derivation
```
A stolen signature → full identity compromise (can derive all PRUs).

**New architecture (SECURE):**
```
identity_seed = Poseidon(wallet_address, signature)     // From wallet
random_entropy = CSPRNG(32 bytes)                     // Generated locally
master_seed = Poseidon(identity_seed, random_entropy) // Combines both
PRU_seed = Poseidon(master_seed, ...)                  // From master_seed
```
A stolen signature → CANNOT derive master_seed (needs random_entropy which is encrypted).

## New Data Flow

```
Step 1 — Generate (device only)
  random_entropy = CSPRNG(32 bytes)
  
Step 2 — Wallet signs unique challenge
  signature = wallet.sign(challenge)
  wallet_key = Poseidon(wallet_pubkey, signature)
  identity_seed = Poseidon(wallet_pubkey, signature)
  
Step 3 — Create master seed
  master_seed = Poseidon(identity_seed, random_entropy)
  
Step 4 — Encrypt
  encrypted_entropy = AES-256-GCM(random_entropy, wallet_key)
  // Encrypted blob is BOUND to this specific wallet
  // Stores ONLY random_entropy, NOT master_seed
  
Step 5 — Derive PRUs (device only, wallet not involved)
  PRU_seed[P][U] = Poseidon(master_seed, protocol_id, purpose)
  PRU[i] = Poseidon(PRU_seed, i)
  master_seed wiped after session

Step 6 — Register (public)
  commitment_hash = Poseidon(PRU_seed[P][U]) → stored in registry
  PRU_public_keys[0..N] → stored in registry
  
Step 7 — Prove ownership (ZK circuit)
  Proves: "I know master_seed such that Poseidon(master_seed, P, U) = PRU_seed"
  Reveals: nothing about master_seed or any signature
```

**Security properties:**
- Even a stolen signature gives identity_seed, NOT master_seed
- random_entropy is encrypted in blob → cannot be derived from signature
- Encrypted blob is bound to specific wallet — only that wallet can decrypt
- `purpose` parameter allows multiple independent PRU sets per protocol

See: [`docs/02-architecture.md`](./docs/02-architecture.md), [`docs/03-identity-model.md`](./docs/03-identity-model.md), [`docs/04-pru-generation.md`](./docs/04-pru-generation.md)

## Core Invariants

1. `master_seed = Poseidon(identity_seed, random_entropy)` — combines wallet binding with CSPRNG entropy.
2. `random_entropy` is encrypted in the blob — NOT derivable from any signature.
3. Even a stolen signature cannot derive `master_seed` (needs `random_entropy`).
4. `master_seed` and `random_entropy` never leave the device in plaintext.
5. The encrypted blob is safe to store anywhere — it's useless without wallet access + the blob.
6. The registry stores exactly one record per PRU: the PRU public value, its `protocol_id`, and its `commitment_hash`. No field links two records to the same master seed.
7. Every hash in the system uses Poseidon, for circuit compatibility.
8. Recovery requires wallet access + encrypted blob. There is no user-memorized secret.
9. User can derive PRUs for ANY protocol/purpose — no dependency on any protocol.

See: [`docs/09-security-model.md`](./docs/09-security-model.md)

## Modules

| Module | Responsibility | Location |
|---|---|---|
| Encryption | AES-256-GCM encrypt/decrypt random_entropy | `sdk/encryption.ts` |
| Identity | Generate master_seed from identity_seed + random_entropy | `sdk/identity.ts` |
| PRU generator | `master_seed` + protocol + purpose → `PRU_seed` → `PRU[i]` | `sdk/pru.ts` |
| Registry | Store/query `{pru, protocol_id, commitment_hash}` | `registry/` |
| ZK circuit | Prove PRU ownership without revealing master_seed | `circuits/` |
| Proof verifier | Verify π against `commitment_hash` | `sdk/verify.ts` |
| Integration SDK | Protocol-facing API for initialize → unlock → generate → prove | `sdk/` |

See: [`docs/08-protocol-integration.md`](./docs/08-protocol-integration.md)

## Why This Is a Protocol, Not Just a Package

A package or SDK is something you import into an application. The application still controls the flow.

A protocol is something applications connect to and follow its rules. The rules are enforced cryptographically, not by trusting the application.

ZK-PRU is a protocol because:
- The registry enforces that only commitment hashes and PRU public keys are stored — it structurally cannot store raw seeds because it never receives them
- The verification is cryptographic — a protocol cannot authorize an action without a valid ZK proof, regardless of what its application layer wants to do
- The privacy guarantee is enforced by math, not by trusting the SDK consumer to use it correctly
- The user can recover ALL their PRUs without any protocol being available — the protocol is a namespace, not a dependency
