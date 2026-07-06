# Identity Model

## Goal

Derive a private, permanent `identity_seed` from a wallet, such that:
- It can be reproduced identically at any point in the future, using only wallet access.
- It never needs to be stored anywhere, by the user or the system.
- Nothing observed publicly (registry entries, PRUs, commitments) can be used to reconstruct it.

## Two signatures, two purposes

A single signature scheme is not enough: if the same signature is used both for identity derivation and for everyday session actions, it either has to change on every use (breaking reproducibility) or stay fixed forever (creating replay risk in session contexts). ZK-PRU splits this into two fixed signatures plus one session signature.

Both fixed challenges use **EIP-712 typed data**, domain-separated and bound to the specific deployed registry contract via `verifyingContract`. This matters for a concrete reason: a generic plain-text message (`"ZK-PRU-IDENTITY-V1" || wallet_address`) can be reproduced character-for-character by a phishing site and presented to a wallet under a look-alike domain, with nothing in the signing prompt to distinguish it from the real thing. Binding the challenge to `verifyingContract` means a wallet that checks EIP-712 domain fields (most modern wallets surface this) will show a mismatched contract address if a phishing site tries to replay the same challenge shape against a different deployment, giving the user a concrete signal something is wrong.

### 1. Identity signature (fixed, derives `identity_seed`)

```js
const identityChallenge = {
  domain: {
    name: "ZK-PRU Protocol",
    version: "1.0.0",
    chainId: chainId,
    verifyingContract: ZK_PRU_REGISTRY_ADDRESS
  },
  types: {
    Identity: [{ name: "purpose", type: "string" }]
  },
  message: { purpose: "ZK-PRU Identity Root" }
};
const identity_signature = await wallet.signTypedData(identityChallenge);
const identity_seed = Poseidon(wallet_address, identity_signature);
```

This message never changes. Signing it always produces the same signature (EIP-712 signatures are deterministic for a given key and payload), so `identity_seed` is always reproducible.

### 2. Vault signature (fixed, replaces any memorized secret)

```js
const vaultChallenge = {
  domain: {
    name: "ZK-PRU Protocol",
    version: "1.0.0",
    chainId: chainId,
    verifyingContract: ZK_PRU_REGISTRY_ADDRESS
  },
  types: {
    Vault: [{ name: "purpose", type: "string" }]
  },
  message: { purpose: "ZK-PRU Vault Root" }
};
const vault_signature = await wallet.signTypedData(vaultChallenge);
```

This plays the role that a manually-memorized recovery phrase (or a PIN) would otherwise play — an additional secret folded into PRU derivation (see [`04-pru-generation.md`](./04-pru-generation.md)) — but it costs the user nothing to maintain, since the wallet can regenerate it identically at any time.

**Why not add a PIN on top of this, for extra defense-in-depth?** It was tried and explicitly rejected — see the box below. The short version: a PIN only adds real security if it's kept secret from the party who could otherwise brute-force it, but in ZK-PRU's fully public registry model, anyone who has `vault_signature` can already brute-force a 4-digit PIN space offline in well under a second, since verification requires nothing but public data and a Poseidon hash. Adding a PIN doesn't add a defense layer here — it just narrows the system down to depending on `vault_signature` alone, which is exactly the same trust assumption as not having a PIN at all, while giving a false sense of "two-factor" security.

> **Rejected design: PIN-mixed entropy.** A candidate revision proposed `secret_entropy = Poseidon(DOMAIN, vault_signature, user_pin)`, with recovery working by scanning the public registry for a matching `PRU_identifier`. This is unsafe specifically *because* the registry is public: the same offline scan a legitimate user runs to recover access is available to any attacker who obtains `vault_signature` (e.g. via a phishing signature request), letting them brute-force all 10,000 PINs and deanonymize the wallet across every registered context in under a second. Any future proposal to add a human-memorized secret to this system must be checked against this same failure mode: **if the registry is public and verification is offline, no low-entropy secret can ever be mixed into the derivation, no matter how it's hashed or salted.**

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
