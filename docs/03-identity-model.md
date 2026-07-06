# Identity Model

## Goal

Derive a private, permanent `identity_seed` from a Solana wallet, such that:

- It can be reproduced using the same wallet on the same ZK-PRU registry binding.
- It never needs to be stored by the user or the system.
- Nothing observed publicly can reconstruct it.

## Registry Binding

Every fixed signing challenge is bound to:

- Solana cluster, for example `devnet`.
- ZK-PRU registry program ID.
- ZK-PRU version.
- Wallet public key.

This makes the identity root specific to one Solana registry deployment. A fake registry program produces a different message and therefore a different signature.

## Two Fixed Messages

### Identity Signature

```text
ZK-PRU Identity Root
Cluster: devnet
Registry Program: <registry_program_id>
Wallet: <wallet_public_key>
Version: v1
Purpose: identity_root
```

The wallet signs this canonical UTF-8 message with Solana `signMessage`.

```ts
const identity_signature = await wallet.signMessage(identityMessage);
const identity_seed = Poseidon(wallet_public_key, identity_signature);
```

### Vault Signature

```text
ZK-PRU Vault Root
Cluster: devnet
Registry Program: <registry_program_id>
Wallet: <wallet_public_key>
Version: v1
Purpose: vault_root
```

The wallet signs this second canonical UTF-8 message with Solana `signMessage`.

```ts
const vault_signature = await wallet.signMessage(vaultMessage);
```

The vault signature is folded into PRU derivation. It is not stored, transmitted, or logged.

## Session Signature

Session signatures are separate from identity derivation.

```text
session_challenge = Poseidon("ZK-PRU-SESSION", wallet_public_key, timestamp, nonce)
```

They are used only for explicit fallback authorization. They must never be used as an input to `identity_seed`.

## Handling Rules

- `identity_signature` and `vault_signature` are private ZK inputs.
- `identity_seed` and `PRU_seed` exist only in memory during proof generation.
- The registry never stores wallet public keys, signatures, `identity_seed`, or `PRU_seed`.
- If both fixed signatures leak, an attacker can reconstruct the user's PRUs for that registry binding. The protection is operational: never log, store, or transmit these signatures.

## Why Not Derive From The Wallet Private Key

Solana wallets do not expose private keys to applications. Canonical `signMessage` payloads are the correct wallet-facing primitive for deriving reproducible secret material without asking for key export.
