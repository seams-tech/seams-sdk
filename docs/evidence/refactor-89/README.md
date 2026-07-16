# Refactor 89 evidence

The Phase 0/1 canonical machine-readable record is
`phase0-phase1-wasm-baseline-v1.json`. It freezes the historical mixed Wasm
baseline from repository commit
`7e080b30f14a579d38b58c65fb058e1abac19c56` without restoring deleted packages
to the active worktree.

## Reproduction boundary

1. Export the pinned repository commit into an empty temporary directory with
   `git archive`.
2. Build `wasm/eth_signer` and `wasm/ecdsa_client_signer` using their committed
   lockfiles, `wasm-pack 0.13.1`, `--release`, and the Homebrew LLVM clang for
   `CC_wasm32_unknown_unknown`.
3. Build a second private package with `--no-opt` to retain the function-name
   section for symbol attribution.
4. Run `scripts/refactor-89/wasm-metadata.mjs strip` on each optimized
   post-binding Wasm artifact.
5. Run `assert-stripped` and `compare-surface` before functional replay.
6. Run the historical Node/browser lifecycle benchmark against the optimized
   artifact and again against the explicitly stripped artifact.
7. Run `scripts/refactor-89/cloudflare-wasm-smoke.mjs` against each stripped
   artifact and its generated binding under local `workerd`.
8. Run `scripts/refactor-89/check-wasm-budget.mjs` against the frozen budget
   record.

The historical benchmark at the pinned commit omitted the then-required
application-binding digest. The evidence run supplies the signer-core test
vector value, 32 bytes of `0x55`, at the Client, SigningWorker, and export
boundaries. The normalized harness digest is recorded in the JSON evidence.

## Commands owned by this evidence

```text
node scripts/refactor-89/wasm-metadata.mjs summary <private-or-shipped.wasm>
node scripts/refactor-89/wasm-metadata.mjs strip <optimized.wasm> <stripped.wasm>
node scripts/refactor-89/wasm-metadata.mjs assert-stripped <stripped.wasm>
node scripts/refactor-89/wasm-metadata.mjs compare-surface <optimized.wasm> <stripped.wasm>
node scripts/refactor-89/wasm-load-benchmark.mjs <bindings.js> <stripped.wasm> [first-call-export]
node scripts/refactor-89/cloudflare-wasm-smoke.mjs --binding <bindings.js> --wasm <stripped.wasm> --sha256 <frozen-digest>
node scripts/refactor-89/check-wasm-budget.mjs <evidence.json> <budget-name> <wasm>
```

## Interpretation

The pinned mixed signer is 553,980 raw bytes and 210,039 gzip-9 bytes after
`wasm-opt`. Explicit removal of its remaining `producers` section yields
553,854 raw bytes and 209,954 gzip-9 bytes. Metadata stripping saves 126 raw
bytes. Reachable code determines the artifact size.

The private name-section report attributes 152,816 encoded function-body bytes
to NEAR threshold signing, 86,754 to MessagePack, and 23,656 to futures. These
groups overlap when one symbol matches multiple ownership tokens, so they are
review evidence rather than an additive partition.

The active build has zero references to the deleted `eth_signer` and
`ecdsa_client_signer` packages. Phase 1 therefore retains historical strip
evidence and reusable guards without adding either package back to a shipping
path.

## Phase 2 utility-leaf experiment

`phase2-leaf-artifact-map-v1.json` freezes the exact experimental leaf
exports, forbidden dependency capabilities, release digests, and compressed
sizes. The EIP-1559 leaf is 71,942 raw, 33,921 gzip-9, and 29,505 Brotli-11
bytes. The WebAuthn P-256/COSE leaf is 93,803 raw, 42,410 gzip-9, and 36,643
Brotli-11 bytes.

This evidence does not select the final ownership layout. Local Phase C
compares clean total distribution size and operation waterfalls, then either
finishes the extraction or deletes it.

The stripped artifacts also pass cold and warm requests in local Miniflare,
which runs them under `workerd` as compiled Wasm modules. This establishes
Workers-runtime compatibility. It does not measure deployed Cloudflare network
fetch or startup latency.

## Evidence assigned to implementation phases

Phase 0 freezes the baseline, policy, budgets, and ownership of the following
future-state evidence. These checks require the integrated replacement
lifecycle and remain production-promotion gates:

- complete SDK distribution bytes;
- real network and Cloudflare Worker fetch/startup;
- pool-fill, pool-hit, and pool-miss signing latency;
- peak and retained Worker memory during those flows;
- complete invalid-message, retry, replay, duplicate, wrong-role, wrong-key,
  wrong-epoch, and abort corpus; and
- wallet, user, tenant, and global refill admission and burn budgets.
