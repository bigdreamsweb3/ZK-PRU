# ZK-PRU Circuits

Two equivalent implementations of the constraint set in
[`/docs/06-zk-proofs.md`](../docs/06-zk-proofs.md):

- `noir/src/main.nr` — **canonical**. Includes in-circuit tests.
- `circom/zk_pru.circom` — ported equivalent, for Circom/snarkjs toolchains.

Keep one as the source of truth per deployment; treat the other as an audited port, not a second spec (see `CODEX_PROMPT.md`, deliverable 3).

## Noir (canonical)

Requires [Nargo](https://noir-lang.org/docs/getting_started/installation/).

```bash
cd circuits/noir
nargo test          # runs the in-circuit tests defined in main.nr
nargo compile        # produces the compiled circuit artifact
```

Proving/verifying keys and proof generation for integration with the SDK are produced via `@noir-lang/noir_js` + `@aztec/bb.js` — wire this up in `scripts/circuit/prove.ts`.

## Circom

Requires [circom](https://docs.circom.io/getting-started/installation/) and [snarkjs](https://github.com/iden3/snarkjs), plus `circomlib` as a dependency for the `Poseidon` template used in `zk_pru.circom`.

```bash
cd circuits/circom
circom zk_pru.circom --r1cs --wasm --sym -l node_modules
snarkjs groth16 setup zk_pru.r1cs pot_final.ptau zk_pru_0.zkey
snarkjs zkey export verificationkey zk_pru_0.zkey verification_key.json
```

(You'll need a Powers of Tau file (`pot_final.ptau`) sized for this circuit's constraint count — see [snarkjs docs](https://github.com/iden3/snarkjs#7-prepare-phase-2) for generating or downloading one.)

## Test coverage required (per CODEX_PROMPT.md deliverable 3)

- (a) A valid witness produces a valid proof — see `main.nr`'s `test_valid_witness_passes`.
- (b) Tampering with any single private input invalidates the proof — see `test_tampered_private_input_fails`.
- (c) Tampering with either public input invalidates the proof — see `test_tampered_public_commitment_fails`.

Port these same three cases to the Circom circuit using `circom_tester` or `snarkjs` witness-calculation + verification before treating the Circom port as production-ready.
