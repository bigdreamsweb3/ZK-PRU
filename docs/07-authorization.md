# Authorization Model

## Mode A — ZK Mode (primary)

Used for all privacy-sensitive actions: votes, private payments, protocol logins, reward claims.

**Requirements to authorize:**
- Wallet access (to re-derive `identity_signature` and `vault_signature` if not cached client-side for the session)
- Knowledge of the `context_id` and index `i` for the PRU being used

**Flow:**
1. Client rebuilds `identity_seed`, `PRU_seed[context_id]`, and `PRU[context_id][i]`.
2. Client generates proof `π` (see [`06-zk-proofs.md`](./06-zk-proofs.md)).
3. Client submits `{PRU, π}`.
4. Verifier checks `π` against the registry's `commitment_hash` for that `context_id`.
5. If valid, the action is authorized. Nothing about the wallet is ever revealed.

## Mode B — Signature Fallback (compatibility only)

Used only when a system cannot yet verify ZK proofs (e.g. legacy integrations).

**Requirements to authorize:**
- A fresh `session_signature` over a `session_challenge` (see [`03-identity-model.md`](./03-identity-model.md))

**Flow:**
1. Wallet signs a fresh, nonce-bound challenge.
2. Signature is submitted directly.
3. Verifier checks the signature against the known wallet address.

**Important:** this mode reveals `wallet_address` to the verifier. Any integration offering Mode B must visibly flag it as lower-privacy in the UI, and should not silently fall back to it without user awareness — the whole point of the system is defeated if Mode B is used by default.

## Choosing between modes

| | Mode A (ZK) | Mode B (fallback) |
|---|---|---|
| Reveals wallet address | No | Yes |
| Requires ZK verifier support | Yes | No |
| Recommended for | All primary actions | Legacy/compatibility only |
| Default | Yes | No — opt-in only |
