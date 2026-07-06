# Authorization Model

## Mode A — ZK Mode (primary)

Used for all privacy-sensitive actions: votes, private payments, protocol logins, reward claims.

**Requirements to authorize:**
- Wallet access (to re-derive `identity_signature` and `vault_signature` if not cached client-side for the session)
- Knowledge of the `context_id` and index `i` for the PRU being used
- For any action with an on-chain effect (not a pure login), a protocol-computed `action_payload_hash` that the proof will be bound to — see [`06-zk-proofs.md`](./06-zk-proofs.md), "Binding a proof to a specific action"

**Flow:**
1. Client rebuilds `identity_seed`, `PRU_seed[context_id]`, and `PRU[context_id][i]`.
2. For an authorization proof, the protocol supplies `action_payload_hash` (e.g. a hash of the transfer amount + recipient), computed from the actual action being requested — never trusted from client input.
3. Client generates proof `π`, including the `action_commitment` binding if `action_payload_hash` is present.
4. Client submits `{PRU, π}` (plus `{action_payload_hash, action_commitment}` for authorization proofs).
5. Verifier checks `π` against the registry's `commitment_hash` for that `context_id`, and against `action_payload_hash`/`action_commitment` if present.
6. If valid, the action is authorized. Nothing about the wallet is ever revealed, and the proof cannot be replayed against a different action.

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
