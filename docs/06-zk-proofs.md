# Zero-Knowledge Proof System

## What the circuit proves

Given a public `commitment_hash` and a public `PRU`, the circuit proves that the prover knows a set of private inputs that legitimately derive both, without revealing any of those inputs.

```
Private inputs (witness):
  wallet_address
  identity_signature
  vault_signature
  context_id
  i

Public inputs:
  commitment_hash
  PRU

Constraints enforced in-circuit:
  identity_seed         = Poseidon(wallet_address, identity_signature)
  PRU_seed              = Poseidon(identity_seed, context_id, vault_signature)
  commitment_hash       == Poseidon(PRU_seed)
  PRU                   == Poseidon(PRU_seed, i)
```

## Binding a proof to a specific action (replay/front-running protection)

The base ownership proof above proves *who* is authorizing something, but says nothing about *what* is being authorized. That's fine for a pure login, but for anything with an on-chain effect (a transfer, a vote), a captured proof `π` could otherwise be replayed against a different action than the one the user actually approved, or front-run by an observer who sees `π` sitting in a public mempool and resubmits it against their own payload first.

To close this, Mode A authorization proofs (see [`07-authorization.md`](./07-authorization.md)) add one more public input and one more constraint, binding the proof to a specific `action_payload_hash` chosen by the calling protocol (e.g. a hash of the transfer amount + recipient, or the vote choice + proposal ID):

```
Additional public input:
  action_payload_hash

Additional public output:
  action_commitment

Additional constraint enforced in-circuit:
  action_commitment == Poseidon(PRU_seed, action_payload_hash)
```

`action_commitment` is safe to expose publicly: it reveals nothing about `PRU_seed` (it's a one-way hash), but it changes completely for every distinct `action_payload_hash`, so a proof generated for one action cannot be silently reused for another — the verifier checks that the `action_commitment` the prover produced matches `Poseidon(PRU_seed_implied_by_commitment_hash, action_payload_hash)` for the specific action being submitted. An earlier draft attempted something similar with an unconstrained `Dummy_Constraint` that computed a hash but never checked it against anything — that version enforced nothing at all; the version here is a real, checked constraint tied to a public output the verifier actually inspects.

## Full constraint set (ownership + action binding)

```
Private inputs (witness):
  wallet_address
  identity_signature
  vault_signature
  context_id
  i

Public inputs:
  commitment_hash
  PRU
  action_payload_hash        (only present for Mode A authorization proofs, omitted for pure login proofs)

Public outputs:
  action_commitment          (only present alongside action_payload_hash)

Constraints enforced in-circuit:
  identity_seed         = Poseidon(wallet_address, identity_signature)
  PRU_seed              = Poseidon(identity_seed, context_id, vault_signature)
  commitment_hash       == Poseidon(PRU_seed)
  PRU                   == Poseidon(PRU_seed, i)
  action_commitment     == Poseidon(PRU_seed, action_payload_hash)      [only when action_payload_hash is present]
```

Output: `π`, a succinct proof that the above constraints hold, with no information about the private inputs leaked.

## Reference implementation targets

Two equivalent circuit implementations are targeted:

- **Noir** (`circuits/noir/zk_pru.nr`) — preferred for readability and native Poseidon support via `std::hash::poseidon`.
- **Circom** (`circuits/circom/zk_pru.circom`) — for ecosystems standardized on Circom + snarkjs tooling.

Both compile the same constraint set above. Pick one as canonical per deployment; do not maintain both as source of truth simultaneously — keep one as canonical and the other as a generated/audited port.

## Noir sketch

```rust
use std::hash::poseidon;

fn main(
    wallet_address: Field,
    identity_signature: Field,
    vault_signature: Field,
    context_id: Field,
    i: Field,
    commitment_hash: pub Field,
    pru: pub Field,
    action_payload_hash: pub Field,
    action_commitment: pub Field
) {
    let identity_seed = poseidon::bn254::hash_2([wallet_address, identity_signature]);
    let pru_seed = poseidon::bn254::hash_3([identity_seed, context_id, vault_signature]);

    assert(commitment_hash == poseidon::bn254::hash_1([pru_seed]));
    assert(pru == poseidon::bn254::hash_2([pru_seed, i]));
    assert(action_commitment == poseidon::bn254::hash_2([pru_seed, action_payload_hash]));
}
```

For a pure login proof with no on-chain action to bind, pass `action_payload_hash = 0` and check `action_commitment` accordingly — see `sdk/verify.ts` for how the SDK handles this optional path.

## Proof generation flow (client-side)

1. Wallet signs `identity_challenge` and `vault_challenge`, both canonical Solana `signMessage` payloads bound to the cluster, registry program ID, wallet public key, and ZK-PRU version (see [`03-identity-model.md`](./03-identity-model.md)).
2. Client computes `identity_seed`, `PRU_seed`, and `PRU[context_id][i]` locally.
3. For an authorization proof, the calling protocol supplies `action_payload_hash`; the client computes `action_commitment`.
4. Client feeds all private + public inputs into the circuit's proving function.
5. Circuit outputs `π`.
6. Client submits `{PRU, π, action_payload_hash, action_commitment}` (or just `{PRU, π}` for a pure login) to the verifier. No other value leaves the client.

## Verification flow (protocol-side)

1. Protocol looks up `commitment_hash` for the relevant `context_id` in the registry.
2. Protocol computes `action_payload_hash` itself, from the actual action being requested (it must never trust a client-supplied value for this).
3. Protocol calls the verifier with `{PRU, π, commitment_hash, action_payload_hash, action_commitment}`.
4. If `π` verifies against all supplied public inputs, the action is authorized.

## Performance notes

- Poseidon is used exclusively (see [`04-pru-generation.md`](./04-pru-generation.md)) specifically because it's efficient in-circuit; avoid introducing any non-arithmetic-friendly hash (SHA-2, Keccak) anywhere in this pipeline, as it would substantially increase circuit size and proving time.
- `context_id` and `i` can be treated as field elements directly if they're numeric, or hashed down to a field element first if they're strings (e.g. `context_id_field = Poseidon(utf8_bytes(context_id))`, computed once outside the circuit and passed in as a private input, with the circuit itself only ever seeing the field element).
