# ZK-PRU SDK

TypeScript implementation of the client and verifier APIs described in
[`/docs/08-protocol-integration.md`](../docs/08-protocol-integration.md).

## Install

```bash
npm install
```

## Build

```bash
npm run build
```

## Test

```bash
npm test
```

Runs the full suite in `/tests`, including:
- `identity.test.ts` — deterministic identity derivation
- `pru.test.ts` — per-context PRU/commitment independence
- `registry.test.ts` — record shape enforcement
- `e2e.test.ts` — full connect → PRU → proof → verify flow, plus negative cross-context and action-replay checks

## Adversarial attack simulation

```bash
npm run test:attacks
```

Runs `tests/attack-simulations/run-attacks.mjs` — 12 narrated attack scenarios using **real cryptographic keys** (no npm install needed, built on Node's core `crypto` module), showing exactly what an attacker starts with, attempts, and gets. See `tests/attack-simulations/README.md` for the full breakdown of what's real vs. simulated in that suite, and how it relates to `nargo test` for actual circuit-level soundness testing.

## Security check

```bash
bash scripts/check-no-secret-leak.sh
```

Fails if `identitySignature`/`vaultSignature` appear near any network, logging, or storage call anywhere in `/sdk` or `/registry`. Run this in CI before every merge.

## Modules

| File | Purpose |
|---|---|
| `poseidon.ts` | The one hash function used everywhere |
| `identity.ts` | Solana `signMessage` fixed wallet signatures → `identity_seed` |
| `pru.ts` | `identity_seed` + context → `PRU_seed` → `PRU`, plus `actionCommitment` for replay-bound proofs |
| `verify.ts` | Proof generation/verification wrapper (backend-agnostic) |
| `index.ts` | `ZKPRU` client class + `ZKPRUVerifier` protocol-side class |
| `mock-wallet.ts`, `mock-backend.ts` | Test-only stand-ins — **do not use in production** |

## Constructing a client

`ZKPRU` requires a Solana registry binding because both fixed challenges are canonical `signMessage` payloads bound to the cluster, registry program ID, wallet public key, and ZK-PRU version:

```ts
const client = new ZKPRU({
  wallet,
  registry,
  prover,
  registryBinding: {
    cluster: "devnet",
    registryProgramId: "ZkPruRegistryDevnet111111111111111111111111",
    version: "v1",
  },
});
```

## Authorizing an action (not just logging in)

For anything with an on-chain effect, pass `actionPayloadHash` — computed from the real action — into `proveOwnership`, and have the verifying protocol compute the same hash independently rather than trusting a client-supplied value:

```ts
const { proof, actionPayloadHash, actionCommitment } = await client.proveOwnership({
  contextId: "acme.protocol.mainnet",
  index: 0,
  actionPayloadHash: hashOf({ amount, recipient }), // computed by your app from the real action
});
```

See [`docs/06-zk-proofs.md`](../docs/06-zk-proofs.md), "Binding a proof to a specific action," for why this stops proof replay and mempool front-running.

## Swapping in a real proving backend

`sdk/verify.ts` defines `ProverBackend` / `VerifierBackend` interfaces. To go to production:

1. Implement `ProverBackend` using `@noir-lang/noir_js` + `@aztec/bb.js` (for the Noir circuit) or `snarkjs` (for the Circom circuit).
2. Implement `VerifierBackend` similarly, or verify through a Solana-compatible verifier path generated from the circuit.
3. Replace `MockProver`/`MockVerifier` in your app wiring — the `ZKPRU`/`ZKPRUVerifier` classes take these as constructor args, so no other code changes are required.

See [`/circuits/README.md`](../circuits/README.md) for circuit-side build steps.
