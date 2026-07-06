# Security Model

## Guarantees

- **No private key exposure.** The wallet is only ever asked to sign messages; the private key never leaves the wallet.
- **No stored secrets.** The system (registry, protocols, verifiers) never receives or stores `wallet_address` paired with either fixed signature, `identity_seed`, or `PRU_seed`.
- **No cross-context linkability.** Two PRUs generated under different `context_id` values share no derivable value, even though both trace back to the same `identity_seed`.
- **No recoverable-secret risk.** There is no user-memorized phrase. Full recovery of every PRU requires only wallet access.
- **Commitment-based verification.** A verifier never needs to see a PRU's private derivation path — only the public `commitment_hash` and a valid proof.

## Threat model

| Threat | Mitigation |
|---|---|
| Attacker observes registry contents | Registry contains only PRUs + commitments, no linking data — see [`05-registry.md`](./05-registry.md) |
| Attacker intercepts network traffic between client and protocol | Only `{PRU, π}` or `{PRU, π, commitment_hash}` ever transit the network — no private inputs |
| `identity_signature` or `vault_signature` leaked (e.g. compromised client, malicious dependency) | **Critical.** Attacker can reconstruct every PRU tied to that wallet across every context. This is the single most sensitive value in the system and must never be logged, cached insecurely, or sent off-device. |
| Phishing site requests a look-alike signature for a fake registry | Both fixed challenges are canonical Solana messages bound to the registry program ID, cluster, wallet public key, and version (see [`03-identity-model.md`](./03-identity-model.md)); a fake registry program produces a different signature |
| A captured proof `π` replayed against a different action, or front-run from a public mempool | Mode A authorization proofs bind `π` to a protocol-computed `action_payload_hash` via a checked `action_commitment` constraint — see [`06-zk-proofs.md`](./06-zk-proofs.md), "Binding a proof to a specific action" |
| Low-entropy secret (PIN, password) mixed into identity/vault derivation | **Rejected by design.** Because the registry is fully public and verification is offline, any low-entropy secret mixed into the derivation is brute-forceable by anyone who obtains the accompanying signature — see the rejected-design note in [`03-identity-model.md`](./03-identity-model.md). No future revision should reintroduce a human-memorized secret into this system. |
| Malicious protocol tries to correlate a user across contexts it controls | Cannot succeed from PRU/commitment data alone; a protocol that controls multiple `context_id`s it issues to the same user could still notice repeat usage patterns at the application layer — this is a metadata/behavioral risk outside ZK-PRU's scope |
| Replay of a session signature (Mode B) | `session_challenge` includes a timestamp + nonce, making stale signatures rejectable |

## Non-goals

- **Sybil resistance.** One wallet can generate unlimited unlinkable PRUs. This is intentional — it's a privacy feature, not a bug — and means ZK-PRU on its own cannot guarantee "one person, one identity." Protocols needing that guarantee must add their own mechanism (proof-of-personhood, staking-weighted identity, nullifier schemes, etc.) on top of ZK-PRU.
- **Metadata privacy.** ZK-PRU protects cryptographic linkability. It does not protect against correlation via IP address, timing analysis, wallet funding source tracing at the chain level, or other out-of-band metadata. Integrators concerned about this should combine ZK-PRU with network-level privacy tooling (e.g. relayers, mixnets) as appropriate.
- **Fund custody.** ZK-PRU has no concept of balances or custody. It authorizes actions; what those actions do (including moving funds) is entirely up to the integrating protocol.

## Operational recommendations

- Never transmit `identity_signature` or `vault_signature` to any server, including your own backend, even over TLS, even for "convenience caching."
- If caching derived values client-side for UX (e.g. avoiding re-signing every action), cache only in memory for the session — never in persistent storage in plaintext.
- Audit any circuit implementation (Noir or Circom) against the constraint set in [`06-zk-proofs.md`](./06-zk-proofs.md) before deployment; a circuit that under-constrains any of the four equalities listed there would allow forged proofs.
