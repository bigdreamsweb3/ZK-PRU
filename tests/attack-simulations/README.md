# ZK-PRU Attack Simulation Suite

Adversarial tests against the ZK-PRU design — NEW SECURE ARCHITECTURE.

## Architecture Security

**NEW ARCHITECTURE (SECURE):**
```
identity_seed = Poseidon(wallet_address, signature)     // From wallet
random_entropy = CSPRNG(32 bytes)                     // Generated locally
master_seed = Poseidon(identity_seed, random_entropy)  // Combines both
PRU_seed = Poseidon(master_seed, protocol_id, purpose) // From master_seed
```

**OLD ARCHITECTURE (VULNERABLE):**
```
identity_seed = Poseidon(wallet_address, signature)
PRU_seed = Poseidon(identity_seed, protocol_id, vault_signature)
```

Key difference: **NEW architecture prevents signature theft attacks** because stolen signatures cannot derive master_seed (missing random_entropy).

## Run It

```bash
# Test NEW secure architecture
node tests/attack-simulations/new-architecture-attacks.mjs

# Test OLD architecture (legacy control)
node tests/attack-simulations/run-attacks.mjs
```

No `npm install` is required. The suite uses Node's built-in `crypto` module.

## What Is Real

- Wallet keys are genuine Ed25519 keypairs.
- Signing and verification use real asymmetric cryptography.
- AES-256-GCM encryption with authentication tags.

## What Is Simulated

- The actual ZK-PRU spec uses Poseidon because it is efficient inside the ZK circuit.
- This suite uses SHA-256 as a stand-in hash chain so it can run with no dependencies.
- These tests validate protocol logic, not ZK circuit soundness.

Run circuit tests separately:

```bash
cd circuits/noir
nargo test
```

## NEW Architecture Attack Scenarios

| # | Attack | What It Tests |
|---|---|---|
| 1 | Stolen signature → master_seed | Attacker cannot derive master_seed from stolen signature alone |
| 2 | Stolen sig + blob → decrypt | Cannot decrypt blob with stolen signature (different challenge) |
| 3 | Phishing same challenge | Phishing protection through unique challenges |
| 4 | Cross-protocol correlation | Registry does not link PRUs across protocols |
| 5 | Old architecture vulnerability | Control test showing OLD architecture was broken |
| 6 | Protocol-independent recovery | User can recover PRUs without protocol being available |
| 7 | Wrong wallet cannot decrypt | Encrypted blob is bound to specific wallet only |
| 8 | Tampered blob detection | AES-256-GCM auth tag detects modifications |
| 9 | Signature replay prevention | Unique challenges prevent signature reuse |
| 10 | Brute force PRU_seed | Commitment hash is computationally infeasible to invert |
