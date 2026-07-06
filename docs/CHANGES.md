# Changes

## Solana-Native Registry Binding

ZK-PRU uses canonical Solana `signMessage` payloads for identity and vault signatures. Each fixed message is bound to the Solana cluster, registry program ID, wallet public key, and ZK-PRU version.

## PRU-Keyed Registry

Registry records are keyed by PRU, not by `context_id`. The stored record shape is `{ pru, context_id, commitment_hash }`.
