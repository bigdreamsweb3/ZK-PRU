# ZK-PRU Attack Simulation Suite

Adversarial tests against the Solana-native ZK-PRU design.

## Run It

```bash
node tests/attack-simulations/run-attacks.mjs
```

No `npm install` is required. The suite uses Node's built-in `crypto` module.

## What Is Real

- Wallet keys are genuine Ed25519 keypairs.
- Signing and verification use real asymmetric cryptography.
- The suite checks that a fake registry program binding cannot reuse signatures generated for the real registry program binding.

## What Is Simulated

- The actual ZK-PRU spec uses Poseidon because it is efficient inside the ZK circuit.
- This suite uses SHA-256 as a stand-in hash chain so it can run with no dependencies.
- These tests validate protocol logic, not ZK circuit soundness.

Run circuit tests separately:

```bash
cd circuits/noir
nargo test
```

## Scenarios

| # | Attack | What It Tests |
|---|---|---|
| 1 | Signature forgery without the private key | Cannot fake identity or vault signatures without the wallet key |
| 2 | Registry-only cross-context correlation | Public registry records do not link contexts |
| 3 | Cross-context proof substitution | One context cannot satisfy another context's commitment |
| 4 | Action replay / mempool front-running | Action binding prevents proof reuse for a different action |
| 5 | Signature leak | Documents the critical boundary if both fixed signatures leak |
| 6 | PIN brute-force | Confirms why low-entropy user secrets are excluded |
| 7 | Fake registry program phishing | Registry program binding changes the signed message |
| 8 | Malformed proof submission | Bad inputs do not verify |
| 9 | Silent fallback downgrade | Mode B requires explicit opt-in |
| 10 | Registry field injection | Registry records cannot store extra wallet-linking fields |
| 11 | Stale session replay | Session nonces and timestamps prevent replay |
| 12 | Recovery reproducibility | The legitimate wallet recovery path is deterministic |
