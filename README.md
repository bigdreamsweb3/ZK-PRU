# ZK-PRU

**Zero-Knowledge Private Routing Units** — a wallet-bound, zero-knowledge identity layer for privacy-preserving protocol participation.

ZK-PRU lets a user generate a unique, unlinkable identity (a **PRU**) for every protocol they interact with, prove ownership of that identity using a zero-knowledge proof, and never expose their wallet address, signatures, or any recovery secret to the protocols they use. Recovery requires nothing but wallet access — there is no separate phrase to write down or lose.

---

## Why ZK-PRU exists

Wallet addresses are public by default. Every transaction, vote, and login using a raw wallet address is linkable to every other action that wallet has ever taken, across every protocol. ZK-PRU breaks that link:

| Without ZK-PRU | With ZK-PRU |
|---|---|
| One wallet address, visible everywhere | One unlinkable PRU per protocol |
| Full on-chain activity history is public | Only per-protocol activity is visible, with no cross-protocol trail |
| Voting/payment history traceable to identity | Ownership provable via ZK proof, without revealing identity |
| Sybil detection relies on wallet uniqueness | Protocols can layer their own Sybil rules on top of PRUs |

## How it works, in one paragraph

A user connects a wallet and signs two fixed, reusable messages. These signatures deterministically derive a private `identity_seed`, which never leaves the client. For each protocol (`context_id`) the user interacts with, a `PRU_seed` and a public `PRU` are derived from that identity seed. Only the PRU and a public commitment hash are ever registered anywhere. To act, the user generates a zero-knowledge proof showing they know the private inputs behind a given PRU, without revealing what those inputs are. Because both signatures are fixed messages, the wallet can always re-derive them — there is nothing else to back up.

## Documentation

Full documentation lives in [`/docs`](./docs), structured the way you'd expect from a protocol spec:

- [`01-overview.md`](./docs/01-overview.md) — what ZK-PRU is and the problem it solves
- [`02-architecture.md`](./docs/02-architecture.md) — system diagram and module breakdown
- [`03-identity-model.md`](./docs/03-identity-model.md) — wallet → identity seed derivation
- [`04-pru-generation.md`](./docs/04-pru-generation.md) — PRU and PRU_seed derivation
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
├── registry/       registry implementation (in-memory + on-chain adapter)
├── scripts/        dev/build/test scripts
├── tests/          unit + integration tests
├── CODEX_PROMPT.md the full build prompt for AI-assisted implementation
└── ARCHITECTURE.md single-file architecture summary
```

## Status

This repository currently contains the full specification, and documentation. Reference implementation is scaffolded for: PRU generation module, registry (in-memory + on-chain-ready interface), ZK circuit, proof verifier, and SDK.

## License

MIT — see [`LICENSE`](./LICENSE).
