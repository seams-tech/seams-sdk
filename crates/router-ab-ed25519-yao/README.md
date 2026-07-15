# Router A/B Ed25519 Yao adapter

This crate is the single transport-neutral composition boundary between
`router-ab-core` lifecycle admission and the fixed Ed25519 Yao role engines.
It is a Phase 9C local precursor with `production_eligible = false`.

The public builders consume one admitted ceremony binding plus one Deriver's
zeroizing contribution. They return one move-only 128 KiB role engine. A
transport adapter must relay the resulting framed messages and exact EOF events
directly between Deriver A and Deriver B.

Recipient package opening is separated by module:

- `recipient::client` combines only the two Client activation packages or the
  two explicit-export packages;
- `recipient::signing_worker` combines only the two SigningWorker activation
  packages;
- Router and relay code use public commitments, receipts, and opaque typed
  packages. They do not import recipient opening functions.

Current validation:

```sh
cargo test --offline --manifest-path crates/router-ab-ed25519-yao/Cargo.toml
```

The integration test executes the complete activation and export circuits with
non-fixture role inputs, fragmented framed transport, terminal EOF evidence,
recipient-specific package decoding, the signer-core two-party FROST public-key
relation, and exact export-share reconstruction.

Complete local usability now passes through the frozen signer-core KDF,
standard Ed25519 signing/export vectors, separate local service routes,
recovery, refresh, and the one-command lifecycle smoke. The deprecated local
HSS path is deleted. Deployment evidence and promoted public SDK transport are
tracked in the production phases of `docs/yaos-ab.md`.
