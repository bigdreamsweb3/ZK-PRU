# Overview

## What is ZK-PRU?

ZK-PRU (Zero-Knowledge Private Routing Units) is a privacy identity layer that lets a user interact with any number of protocols using **PRUs** — deterministic, unlinkable, per-protocol identities — instead of their wallet address.

A PRU is:
- **Deterministic**: always regenerable from the same wallet, for the same protocol.
- **Unlinkable**: a PRU used in one protocol cannot be connected to a PRU used in another, even by someone with full read access to every public registry.
- **Provable**: ownership of a PRU can be proven with a zero-knowledge proof, without revealing the wallet, any signature, or any other private input.
- **Recoverable by wallet alone**: there is no separate secret phrase to memorize or lose. As long as the user can sign with their wallet, every PRU they've ever created can be regenerated.

## The problem

Wallet addresses function as public, permanent identifiers. Every action taken from a given address — every transaction, vote, login, or claim — is trivially linkable to every other action from that same address, across every protocol that address has ever touched. This creates several concrete problems:

- **Surveillance**: anyone can construct a full behavioral profile of a wallet from public chain data alone.
- **Leaked intent**: private actions (e.g. a governance vote, a payment to a specific counterparty) are exposed the moment they're signed.
- **No real per-protocol boundaries**: a user's identity in one protocol is, by default, the same as their identity in every other protocol.

## The approach

ZK-PRU addresses this by inserting a derivation layer between the wallet and the protocol:

```
Wallet → Identity Seed → PRU (per protocol) → Commitment (public) → ZK Proof (per action)
```

The wallet is used only to produce two fixed, reproducible signatures. Everything after that — the identity seed, the per-protocol PRU seed, and the resulting PRU — is derived deterministically and never needs to be stored, memorized, or backed up separately.

## What ZK-PRU is not

- **Not a Sybil-resistance system.** One wallet can generate any number of unlinkable PRUs by design. Protocols that need Sybil resistance must layer additional mechanisms (e.g. proof-of-personhood, staking, nullifiers) on top of ZK-PRU.
- **Not a custody solution.** ZK-PRU never holds keys, seeds, or funds. It only derives identities and verifies proofs.
- **Not chain-specific.** The design is chain-agnostic; it requires only a wallet capable of producing a deterministic signature over a fixed message, and a verifier capable of checking a ZK proof.

## Next

Continue to [`02-architecture.md`](./02-architecture.md) for the full system diagram.
