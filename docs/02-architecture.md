# Architecture

## System diagram

```
                          ┌────────────────────┐
                          │   User's Wallet     │
                          │  (never exposes key) │
                          └─────────┬────────────┘
                                    │ sign(identity_challenge)  [fixed]
                                    │ sign(vault_challenge)     [fixed]
                                    ▼
                          ┌────────────────────┐
                          │   Identity Layer     │
                          │  identity_seed =      │
                          │  Poseidon(addr, sig)  │
                          └─────────┬────────────┘
                                    │ + context_id + vault_signature
                                    ▼
                          ┌────────────────────┐
                          │   PRU Generator       │
                          │  PRU_seed[ctx] =       │
                          │  Poseidon(seed, ctx,   │
                          │           vault_sig)   │
                          │  PRU[ctx][i] =          │
                          │  Poseidon(PRU_seed, i)  │
                          └─────────┬────────────┘
                                    │ PRU (public) + commitment_hash (public)
                                    ▼
                          ┌────────────────────┐
                          │   Registry            │
                          │  one record per        │
                          │  context_id             │
                          └─────────┬────────────┘
                                    │ verify(π, commitment_hash)
                                    ▼
                          ┌────────────────────┐
                          │   ZK Circuit +         │
                          │   Verifier              │
                          └─────────┬────────────┘
                                    ▼
                          ┌────────────────────┐
                          │  Authorized Action    │
                          │  (transfer/vote/login) │
                          └────────────────────┘
```

## Modules

### 1. Identity Layer (client-side only)
Derives `identity_seed` and `vault_signature` from two fixed wallet signatures. Never transmits either signature or the resulting seed. See [`03-identity-model.md`](./03-identity-model.md).

### 2. PRU Generator (client-side only)
Combines `identity_seed`, a `context_id`, and `vault_signature` to derive a `PRU_seed`, and from that, any number of indexed PRUs for that context. See [`04-pru-generation.md`](./04-pru-generation.md).

### 3. Registry (public, on-chain or off-chain)
Stores exactly one record per `context_id`: the list of PRU public keys issued under that context, and a single `commitment_hash`. No record contains any field that links it to another record or to a wallet. See [`05-registry.md`](./05-registry.md).

### 4. ZK Circuit + Verifier
The circuit proves knowledge of the private inputs (`wallet_address`, `identity_signature`, `vault_signature`, `context_id`, `i`) that produce a given `PRU` and `commitment_hash`, without revealing those inputs. See [`06-zk-proofs.md`](./06-zk-proofs.md).

### 5. Authorization
Two modes: ZK mode (primary, private) and signature-fallback mode (compatibility, less private). See [`07-authorization.md`](./07-authorization.md).

### 6. Protocol Integration SDK
The interface a protocol uses to accept a PRU + proof, and the interface a client app uses to connect a wallet and generate PRUs/proofs. See [`08-protocol-integration.md`](./08-protocol-integration.md).

## Trust boundaries

| Component | Trusted with |
|---|---|
| User's device / wallet | Private key, both signatures, identity_seed, PRU_seed |
| Registry (public) | PRU public keys, commitment hashes — nothing private |
| Protocol / verifier | PRU, proof π, commitment_hash — nothing private |
| ZK circuit | Runs entirely client-side; private inputs never leave the proving environment |

Nothing outside the user's own device ever has access to `wallet_address` paired with `identity_signature` or `vault_signature` in a way that could be replayed or used to reconstruct `identity_seed`.
