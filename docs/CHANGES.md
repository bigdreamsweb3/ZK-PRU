# Implementation Notes / Deviations from Spec

Per `CODEX_PROMPT.md`: the files in `/docs` are the source of truth and are not rewritten during implementation. Anything the implementation needed to clarify or add beyond the literal spec text is logged here instead.

## 1. Mock proving/verifying backend (`sdk/mock-backend.ts`)

The spec (`docs/06-zk-proofs.md`) describes the circuit's constraint set but doesn't mandate a specific proving library. For tests and local development, `MockProver`/`MockVerifier` simulate the circuit's four constraints directly in TypeScript, without producing a real succinct proof. This is explicitly test-only — see the warning comments in `sdk/mock-backend.ts` and `sdk/README.md`, "Swapping in a real proving backend."

## 2. `stringToField` for non-numeric inputs

`context_id` and wallet addresses are strings in practice, but the circuit constraints operate over field elements. `sdk/poseidon.ts`'s `stringToField` deterministically maps a string to a BN254 field element via a single Poseidon absorption. `docs/06-zk-proofs.md` mentions this approach as one valid option ("hashed down to a field element first if they're strings") — this implementation adopts it as the concrete default rather than leaving it unspecified.

## 3. Commitment hash construction

`docs/05-registry.md` specifies `commitment_hash = Poseidon(PRU_seed[context_id])` as a single-input hash. Implemented via `poseidon-lite`'s `poseidon1` (see `sdk/pru.ts`'s `commitmentHash`), matching the Noir circuit's `poseidon::bn254::hash_1`.

## 4. Deterministic mock wallet signatures

`sdk/mock-wallet.ts`'s `MockWallet` is not a real signature scheme — it's a deterministic stand-in so identity derivation tests don't require a live wallet connection. Flagged clearly in its own file comment; must never be used outside tests/local dev.

## 5. EIP-712 domain binding for the two fixed challenges

Both `identity_challenge` and `vault_challenge` were upgraded from plain fixed strings to EIP-712 typed data, with `domain.verifyingContract` bound to the deployed registry contract address. Rationale: a plain fixed string can be reproduced character-for-character by a phishing site under a different domain, with nothing in the wallet's signing prompt to distinguish it from the legitimate request. Binding to `verifyingContract` gives wallets that surface EIP-712 domain fields a concrete way to flag the mismatch. See `docs/03-identity-model.md`.

## 6. Action-binding constraint added to the ZK circuit

The original circuit proved *ownership* of a PRU but said nothing about *what* the proof was authorizing, meaning a captured `π` could in principle be replayed against a different action, or front-run from a public mempool. Added `action_payload_hash` (public input, computed by the verifying protocol from the real action) and `action_commitment = Poseidon(PRU_seed, action_payload_hash)` (public output, checked in-circuit). See `docs/06-zk-proofs.md`, "Binding a proof to a specific action." Both `circuits/noir/src/main.nr` and `circuits/circom/zk_pru.circom` were updated, along with `sdk/verify.ts`, `sdk/index.ts`, `sdk/pru.ts` (new `actionCommitment` helper), and a new replay-rejection test in `tests/e2e.test.ts`.

## 7. Rejected: PIN-mixed entropy derivation

A proposed revision suggested mixing a user-memorized 4-digit PIN into `secret_entropy`, with recovery done by scanning the fully public registry for a match. This was rejected and is documented as a permanent design constraint, not just a one-off decision: because the registry is public and verification is offline, any low-entropy secret mixed into the derivation is brute-forceable in well under a second by anyone who obtains the accompanying wallet signature — the same offline scan that makes recovery convenient for a legitimate user makes attack just as easy. See the "Rejected design" callout in `docs/03-identity-model.md` and the corresponding row in `docs/09-security-model.md`'s threat table.
