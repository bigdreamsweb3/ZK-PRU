# ZK-PRU

**Zero-Knowledge Private Routing Units** — a wallet-bound, zero-knowledge identity layer for privacy-preserving protocol participation.

ZK-PRU lets a user generate a unique, unlinkable identity (a **PRU**) for every protocol and purpose they interact with, prove ownership of that identity using a zero-knowledge proof, and never expose their wallet address, signatures, or any recovery secret to the protocols they use. Recovery requires nothing but wallet access — there is no separate phrase to write down or lose.

---

## Why ZK-PRU exists

Wallet addresses are public by default. Every transaction, vote, and login using a raw wallet address is linkable to every other action that wallet has ever taken, across every protocol. ZK-PRU breaks that link:

| Without ZK-PRU | With ZK-PRU |
|---|---|
| One wallet address, visible everywhere | One unlinkable PRU per protocol/purpose |
| Full on-chain activity history is public | Only per-protocol activity is visible, with no cross-protocol trail |
| Voting/payment history traceable to identity | Ownership provable via ZK proof, without revealing identity |
| Sybil detection relies on wallet uniqueness | Protocols can layer their own Sybil rules on top of PRUs |

## How it works, in one paragraph

A user generates a master seed locally using a cryptographically secure random number generator (CSPRNG). This master seed has NO mathematical relationship to the user's wallet. The wallet's only role is to encrypt the master seed with a wallet-derived key, so only that specific wallet can decrypt it. The encrypted seed blob can be stored anywhere (TIN account, personal vault, cloud storage). For each protocol (`protocol_id`) and purpose (`purpose`) the user interacts with, a `PRU_seed` and public `PRU` are derived from the master seed entirely on-device. Only the PRU and a public commitment hash are ever registered anywhere. To act, the user generates a zero-knowledge proof showing they know the master seed behind a given PRU, without revealing the master seed or any wallet signature. Because the master seed is encrypted by the wallet, recovery works by decrypting with the wallet — there is nothing else to back up.

## Key Security Properties

**The new architecture breaks the signature-theft attack vector.** In the old design, `identity_seed = Poseidon(wallet_address, identity_signature)` meant a malicious protocol could trick you into signing a fixed message, steal your signature, and reconstruct your entire identity. In the new design, the master seed is independently random. A stolen signature reveals nothing about the master seed because there is no mathematical relationship between them.

**Protocol-independent recovery.** A user can derive PRUs for ANY protocol/purpose from their master seed. If a protocol disappears, the user can still access their funds by decrypting the master seed with their wallet and deriving the PRUs themselves. The protocol ID is just a namespace, not a dependency.

## Documentation

Full documentation lives in [`/docs`](./docs), structured the way you'd expect from a protocol spec:

- [`01-overview.md`](./docs/01-overview.md) — what ZK-PRU is and the problem it solves
- [`02-architecture.md`](./docs/02-architecture.md) — system diagram and module breakdown
- [`03-identity-model.md`](./docs/03-identity-model.md) — master seed generation and wallet encryption
- [`04-pru-generation.md`](./docs/04-pru-generation.md) — PRU and PRU_seed derivation with purpose
- [`05-registry.md`](./docs/05-registry.md) — commitment registry design
- [`06-zk-proofs.md`](./docs/06-zk-proofs.md) — circuit spec and proof system
- [`07-authorization.md`](./docs/07-authorization.md) — spending/authorization modes
- [`08-protocol-integration.md`](./docs/08-protocol-integration.md) — integrating ZK-PRU into a protocol
- [`09-security-model.md`](./docs/09-security-model.md) — guarantees, threat model, non-goals
- [`10-faq.md`](./docs/10-faq.md) — plain-English FAQ

## Repository layout

```
zk-pru/
├── docs/          full specification and documentation set
├── circuits/       Noir/Circom ZK circuits
├── sdk/            protocol integration SDK (TypeScript)
│   ├── encryption.ts   AES-256-GCM encryption module
│   ├── identity.ts    Master seed generation and wallet encryption
│   ├── pru.ts        PRU derivation with purpose
│   ├── verify.ts     ZK circuit witness and proof generation
│   └── index.ts      Main SDK entry point
├── registry/       registry implementation (in-memory + on-chain adapter)
├── scripts/        dev/build/test scripts
├── tests/          unit + integration tests
└── ARCHITECTURE.md single-file architecture summary
```

## Status

This repository contains the ZK-PRU specification, TypeScript SDK scaffold, registry interfaces, circuit definitions, verifier adapter, and tests.

## License

MIT — see [`LICENSE`](./LICENSE).
