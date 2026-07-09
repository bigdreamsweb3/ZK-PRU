# Architecture

## The Security Problem We're Solving

**The old architecture had a critical vulnerability.** It derived `identity_seed` from wallet signatures:

```
identity_seed = Poseidon(wallet_address, identity_signature)
```

A malicious protocol could trick you into signing the same fixed message (disguised as "connect wallet" or "verify identity"), steal your signature, and reconstruct your entire private identity.

**The new architecture breaks this attack vector.** The master seed is independently random and has no mathematical relationship to any wallet signature.

## New System Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        USER'S DEVICE                              │
│                                                                  │
│  ┌──────────────────────┐                                       │
│  │    CSPRNG Generator   │  ← Generates pure entropy             │
│  │   master_seed (32B)   │    NO wallet relationship            │
│  └──────────┬───────────┘                                       │
│             │                                                    │
│             │ Wallet signs unique challenge                      │
│             │ (timestamp + nonce prevent reuse)                  │
│             ▼                                                    │
│  ┌──────────────────────┐                                       │
│  │   AES-256-GCM Vault   │  ← Encrypt master_seed               │
│  │   encrypted_seed_blob │    Only encrypted blob stored         │
│  └──────────┬───────────┘                                       │
│             │                                                    │
│             │ PRU derivation (entirely on-device)                 │
│             ▼                                                    │
│  ┌──────────────────────┐                                       │
│  │   PRU Generator      │                                       │
│  │  PRU_seed[P] =       │                                       │
│  │    Poseidon(         │                                       │
│  │      master_seed,    │                                       │
│  │      protocol_id,    │                                       │
│  │      salt            │                                       │
│  │    )                 │                                       │
│  │  PRU[i] = Poseidon(PRU_seed, i)                             │
│  └──────────┬───────────┘                                       │
│             │                                                    │
└─────────────┼────────────────────────────────────────────────────┘
              │ PRU (public) + commitment_hash (public)
              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PUBLIC LAYER (on-chain/registry)              │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Registry stores per protocol:                             │  │
│  │    - commitment_hash = Poseidon(PRU_seed[P])              │  │
│  │    - PRU_public_keys[0..N]                                │  │
│  │    - NOTHING else                                          │  │
│  └────────────────────────────────────────────────────────────┘  │
│             │                                                    │
│             │ verify(π, commitment_hash)                         │
│             ▼                                                    │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  ZK Circuit proves: "I know master_seed such that           │  │
│  │    Poseidon(master_seed, protocol_id, salt) = PRU_seed     │  │
│  │    Poseidon(PRU_seed) = commitment_hash                    │  │
│  │    Poseidon(PRU_seed, i) = PRU[i]"                        │  │
│  │                                                         │  │
│  │  Reveals: NOTHING about master_seed, wallet, or signatures  │  │
│  └────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## The Key Security Invariant

```
┌─────────────────────────────────────────────────────────────────┐
│  ATTACKER STEALS WALLET SIGNATURE                                │
│                                                                  │
│  OLD ARCHITECTURE:                                               │
│    signature → derive identity_seed → derive all PRUs  ← BROKEN  │
│                                                                  │
│  NEW ARCHITECTURE:                                               │
│    signature → (nothing useful)                                  │
│    master_seed cannot be derived from any signature  ✓ SECURE     │
└─────────────────────────────────────────────────────────────────┘
```

## Modules

### 1. Encryption Module (`sdk/encryption.ts`)
Handles AES-256-GCM encryption/decryption of the master seed. The wallet's signature derives the encryption key, but the key is never used to generate the master seed itself.

### 2. Identity Module (`sdk/identity.ts`)
- `createIdentity()`: Generates master seed locally, derives vault key from wallet signature, encrypts seed
- `recoverIdentity()`: Signs unique challenge, decrypts master seed locally
- All operations happen on-device; no secrets leave the browser/node process

### 3. PRU Generator (`sdk/pru.ts`)
Derives PRU_seed and PRUs directly from master_seed. No wallet involvement:
```
PRU_seed[protocol_id] = Poseidon(master_seed, protocol_id, salt)
PRU[i] = Poseidon(PRU_seed, i)
```

### 4. ZK Circuit (`circuits/`)
Proves knowledge of master_seed without revealing it. New constraint set:
```
PRU_seed = Poseidon(master_seed, protocol_id, salt)
commitment_hash = Poseidon(PRU_seed)
PRU = Poseidon(PRU_seed, index)
```

### 5. Registry (`registry/`)
Stores only commitment hashes and PRU public keys. Structurally cannot store seeds because it never receives them.

### 6. Authorization
Two modes: ZK mode (primary, private) and signature-fallback mode (compatibility, less private). See [`07-authorization.md`](./07-authorization.md).

## Trust Boundaries

| Component | Trusted with |
|---|---|
| User's device | Master seed (in memory only), vault key |
| Registry | PRU public keys, commitment hashes — nothing private |
| Protocol / verifier | PRU, proof π, commitment_hash — nothing private |
| ZK circuit | Runs entirely client-side; master_seed never leaves device |

**The critical difference:** Nothing outside the user's device ever has access to the master seed or any value that could derive it. The registry structurally cannot store raw seeds because the system is designed so it never receives them.
