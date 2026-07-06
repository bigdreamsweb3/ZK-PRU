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
- `e2e.test.ts` — full connect → PRU → proof → verify flow, plus negative cross-context checks

## Security check

```bash
bash scripts/check-no-secret-leak.sh
```

Fails if `identitySignature`/`vaultSignature` appear near any network, logging, or storage call anywhere in `/sdk` or `/registry`. Run this in CI before every merge.

## Modules

| File | Purpose |
|---|---|
| `poseidon.ts` | The one hash function used everywhere |
| `identity.ts` | EIP-712-bound fixed wallet signatures → `identity_seed` |
| `pru.ts` | `identity_seed` + context → `PRU_seed` → `PRU`, plus `actionCommitment` for replay-bound proofs |
| `verify.ts` | Proof generation/verification wrapper (backend-agnostic) |
| `index.ts` | `ZKPRU` client class + `ZKPRUVerifier` protocol-side class |
| `mock-wallet.ts`, `mock-backend.ts` | Test-only stand-ins — **do not use in production** |

## Constructing a client

`ZKPRU` requires the chain ID and deployed registry contract address, since both fixed challenges are EIP-712 typed data bound to `verifyingContract` (see [`docs/03-identity-model.md`](../docs/03-identity-model.md)):

```ts
const client = new ZKPRU({
  wallet,
  registry,
  prover,
  chainId: 1,
  registryAddress: "0xYourDeployedRegistryContract",
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
2. Implement `VerifierBackend` similarly, or verify entirely on-chain via a deployed Solidity/Move/Anchor verifier contract generated from the circuit.
3. Replace `MockProver`/`MockVerifier` in your app wiring — the `ZKPRU`/`ZKPRUVerifier` classes take these as constructor args, so no other code changes are required.

See [`/circuits/README.md`](../circuits/README.md) for circuit-side build steps.
