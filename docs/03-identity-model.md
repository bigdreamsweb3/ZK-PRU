# Identity Model

## Goal

Derive a private, permanent `identity_seed` from a wallet, such that:
- It can be reproduced identically at any point in the future, using only wallet access.
- It never needs to be stored anywhere, by the user or the system.
- Nothing observed publicly (registry entries, PRUs, commitments) can be used to reconstruct it.

## Two signatures, two purposes

A single signature scheme is not enough: if the same signature is used both for identity derivation and for everyday session actions, it either has to change on every use (breaking reproducibility) or stay fixed forever (creating replay risk in session contexts). ZK-PRU splits this into two fixed signatures plus one session signature.

### 1. Identity signature (fixed, derives `identity_seed`)

```
identity_challenge = "ZK-PRU-IDENTITY-V1" || wallet_address
identity_signature = sign(wallet, identity_challenge)
identity_seed = Poseidon(wallet_address, identity_signature)
```

This message never changes. Signing it always produces the same signature (standard wallet signature schemes, e.g. ECDSA/EdDSA over a fixed message, are deterministic or can be made so), so `identity_seed` is always reproducible.

### 2. Vault signature (fixed, replaces any memorized secret)

```
vault_challenge = "ZK-PRU-VAULT-V1" || wallet_address
vault_signature = sign(wallet, vault_challenge)
```

This plays the role that a manually-memorized recovery phrase would otherwise play — an additional secret folded into PRU derivation (see [`04-pru-generation.md`](./04-pru-generation.md)) — but it costs the user nothing to maintain, since the wallet can regenerate it identically at any time.

### 3. Session signature (per-session, never touches identity derivation)

```
session_challenge = Poseidon("ZK-PRU-SESSION", wallet_address, timestamp, nonce)
session_signature = sign(wallet, session_challenge)
```

Used only for Mode B fallback authorization (see [`07-authorization.md`](./07-authorization.md)). Changes every time, so it cannot be replayed — but for that same reason it must never be used as an input to `identity_seed`.

## Handling rules

- `identity_signature` and `vault_signature` are used only as private inputs to the ZK circuit (§`06-zk-proofs.md`). They are never sent to a server, never logged, never included in any transaction.
- `identity_seed` and `PRU_seed` (derived downstream, see `04-pru-generation.md`) exist only in client-side memory during proof generation and are discarded immediately after.
- If `identity_signature` or `vault_signature` is ever exposed outside the client (e.g. through a compromised app, a malicious dependency, or a debugging log), an attacker gains the ability to reconstruct every PRU tied to that wallet. This is the primary threat this system must defend against operationally — see [`09-security-model.md`](./09-security-model.md).

## Why not derive identity from the wallet's private key directly?

Wallets deliberately do not expose private keys to applications. Signatures over app-chosen messages are the only cryptographic material a wallet is designed to expose, which is why identity derivation is built entirely from signatures rather than key material.
