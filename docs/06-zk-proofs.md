# Zero-Knowledge Proof System

## What the Circuit Proves (New Architecture)

Given a public `commitment_hash` and a public `PRU`, the circuit proves that the prover knows the `master_seed` that legitimately derives both, **without revealing the master_seed or any wallet signature**.

This is the key security improvement: the circuit no longer takes wallet signatures as private inputs. A stolen signature cannot be used to forge proofs because the circuit proves knowledge of master_seed, not signatures.

```
Private inputs (witness):
  master_seed (as field element)
  protocol_id
  purpose
  index

Public inputs:
  commitment_hash
  PRU

Constraints enforced in-circuit:
  PRU_seed        = Poseidon(master_seed, protocol_id, purpose)
  commitment_hash  == Poseidon(PRU_seed)
  PRU              == Poseidon(PRU_seed, index)
```

## Why This Is Better Than the Old Architecture

**Old circuit:**
```
Private inputs: wallet_address, identity_signature, vault_signature, context_id, i
Problem: A stolen signature can reconstruct identity_seed → all PRUs
```

**New circuit:**
```
Private inputs: master_seed (as field element), protocol_id, purpose, index
Benefit: Master seed has NO mathematical relationship to any signature
```

## Binding a Proof to a Specific Action (Replay/Front-running Protection)

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

`action_commitment` is safe to expose publicly: it reveals nothing about `PRU_seed` (it's a one-way hash), but it changes completely for every distinct `action_payload_hash`, so a proof generated for one action cannot be silently reused for another.

## Full Constraint Set (Ownership + Action Binding)

```
Private inputs (witness):
  master_seed (as field element)
  protocol_id
  purpose
  index

Public inputs:
  commitment_hash
  PRU
  action_payload_hash        (only present for Mode A authorization proofs, omitted for pure login proofs)

Public outputs:
  action_commitment          (only present alongside action_payload_hash)

Constraints enforced in-circuit:
  PRU_seed            = Poseidon(master_seed, protocol_id, purpose)
  commitment_hash     == Poseidon(PRU_seed)
  PRU                 == Poseidon(PRU_seed, index)
  action_commitment   == Poseidon(PRU_seed, action_payload_hash)      [only when action_payload_hash is present]
```

Output: `π`, a succinct proof that the above constraints hold, with no information about the private inputs leaked.

## Reference Implementation Targets

Two equivalent circuit implementations are targeted:

- **Noir** (`circuits/noir/zk_pru.nr`) — preferred for readability and native Poseidon support via `std::hash::poseidon`.
- **Circom** (`circuits/circom/zk_pru.circom`) — for ecosystems standardized on Circom + snarkjs tooling.

Both compile the same constraint set above. Pick one as canonical per deployment; do not maintain both as source of truth simultaneously — keep one as canonical and the other as a generated/audited port.

## Noir Sketch

```rust
use std::hash::poseidon;

fn main(
    master_seed: Field,     // 32-byte seed as field element
    protocol_id: Field,     // Protocol identifier (e.g., "defi-xyz")
    purpose: Field,         // Purpose within protocol (e.g., "lending")
    index: Field,           // PRU index
    commitment_hash: pub Field,
    pru: pub Field,
    action_payload_hash: pub Field,
    action_commitment: pub Field
) {
    // Derive PRU_seed from master_seed, protocol_id, and purpose
    let pru_seed = poseidon::bn254::hash_3([master_seed, protocol_id, purpose]);

    // Verify commitment and PRU
    assert(commitment_hash == poseidon::bn254::hash_1([pru_seed]));
    assert(pru == poseidon::bn254::hash_2([pru_seed, index]));

    // Verify action binding
    assert(action_commitment == poseidon::bn254::hash_2([pru_seed, action_payload_hash]));
}
```

For a pure login proof with no on-chain action to bind, pass `action_payload_hash = 0` and check `action_commitment` accordingly — see `sdk/verify.ts` for how the SDK handles this optional path.

## Proof Generation Flow (Client-Side)

1. User unlocks vault: signs unique challenge → master_seed decrypted locally
2. Client computes `PRU_seed[protocol_id][purpose]` and `PRU[protocol_id][purpose][i]` from master_seed
3. For an authorization proof, the calling protocol supplies `action_payload_hash`; the client computes `action_commitment`
4. Client feeds all private + public inputs into the circuit's proving function
5. Circuit outputs `π`
6. Client submits `{PRU, π, action_payload_hash, action_commitment}` (or just `{PRU, π}` for a pure login) to the verifier

**Critical:** No wallet signature is ever sent to the circuit. The proof proves knowledge of master_seed, not possession of a signature.

## Verification Flow (Protocol-Side)

1. Protocol looks up `commitment_hash` for the relevant `protocol_id` in the registry
2. Protocol computes `action_payload_hash` itself, from the actual action being requested (it must never trust a client-supplied value for this)
3. Protocol calls the verifier with `{PRU, π, commitment_hash, action_payload_hash, action_commitment}`
4. If `π` verifies against all supplied public inputs, the action is authorized

## Performance Notes

- Poseidon is used exclusively (see [`04-pru-generation.md`](./04-pru-generation.md)) specifically because it's efficient in-circuit; avoid introducing any non-arithmetic-friendly hash (SHA-2, Keccak) anywhere in this pipeline, as it would substantially increase circuit size and proving time.
- `protocol_id`, `purpose`, and `index` can be treated as field elements directly if they're numeric, or hashed down to a field element first if they're strings (e.g. `protocol_id_field = Poseidon(utf8_bytes(protocol_id))`, computed once outside the circuit and passed in as a private input, with the circuit itself only ever seeing the field element).
- Master seed conversion to field element: 32 bytes → bigint → mod BN254 prime. This is done outside the circuit and the resulting field element is passed in as a private input.
