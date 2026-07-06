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
    pru: pub Field
) {
    let identity_seed = poseidon::bn254::hash_2([wallet_address, identity_signature]);
    let pru_seed = poseidon::bn254::hash_3([identity_seed, context_id, vault_signature]);

    assert(commitment_hash == poseidon::bn254::hash_1([pru_seed]));
    assert(pru == poseidon::bn254::hash_2([pru_seed, i]));
}
```

## Proof generation flow (client-side)

1. Wallet signs `identity_challenge` and `vault_challenge` (both fixed messages — see [`03-identity-model.md`](./03-identity-model.md)).
2. Client computes `identity_seed`, `PRU_seed`, and `PRU[context_id][i]` locally.
3. Client feeds all private + public inputs into the circuit's proving function.
4. Circuit outputs `π`.
5. Client submits `{PRU, π}` to the verifier. No other value leaves the client.

## Verification flow (protocol-side)

1. Protocol looks up `commitment_hash` for the relevant `context_id` in the registry.
2. Protocol calls the verifier with `{PRU, π, commitment_hash}`.
3. If `π` verifies, the action is authorized.

## Performance notes

- Poseidon is used exclusively (see [`04-pru-generation.md`](./04-pru-generation.md)) specifically because it's efficient in-circuit; avoid introducing any non-arithmetic-friendly hash (SHA-2, Keccak) anywhere in this pipeline, as it would substantially increase circuit size and proving time.
- `context_id` and `i` can be treated as field elements directly if they're numeric, or hashed down to a field element first if they're strings (e.g. `context_id_field = Poseidon(utf8_bytes(context_id))`, computed once outside the circuit and passed in as a private input, with the circuit itself only ever seeing the field element).
