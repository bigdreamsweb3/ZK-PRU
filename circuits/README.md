# ZK-PRU Circuits

Two equivalent implementations of the constraint set in [`/docs/06-zk-proofs.md`](../docs/06-zk-proofs.md):

- `noir/src/main.nr` is canonical and includes in-circuit tests.
- `circom/zk_pru.circom` is a ported equivalent for Circom/snarkjs toolchains.

Keep one as the source of truth per deployment. Treat the other as an audited port, not a second spec.

## Noir

Requires Nargo.

```bash
cd circuits/noir
nargo test
nargo compile
```

Proving and verification keys for SDK integration are produced through a Noir-compatible proving stack such as `@noir-lang/noir_js` and `@aztec/bb.js`.

## Circom

Requires Circom, snarkjs, and circomlib.

```bash
cd circuits/circom
circom zk_pru.circom --r1cs --wasm --sym -l node_modules
snarkjs groth16 setup zk_pru.r1cs pot_final.ptau zk_pru_0.zkey
snarkjs zkey export verificationkey zk_pru_0.zkey verification_key.json
```

## Test Coverage Required

- A valid witness produces a valid proof.
- Tampering with any private input invalidates the proof.
- Tampering with any public input invalidates the proof.
- Replaying a proof against a different action payload fails.
