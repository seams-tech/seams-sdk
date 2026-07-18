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

## Phase 5 production presign cutover

`phase5-presign-cutover-v1.json` records the production build in which both
Client and SigningWorker presigning use the purpose-built fixed 2-of-2
backend. The Client artifact is 172,561 raw, 73,497 gzip-9, and 60,605
Brotli-11 bytes. The SigningWorker artifact, which also contains role-local
derivation bootstrap, is 199,117 raw, 87,788 gzip-9, and 73,935 Brotli-11
bytes. Both normal dependency graphs exclude `signer-core` and
`threshold-signatures`.

The historical 553,854-byte mixed artifact owned more responsibilities, so its
209,954-byte gzip size is contextual rather than a like-for-like presign-only
comparison. The production Client presign artifact is nevertheless 136,457
gzip bytes smaller, and its dependency attribution is now unambiguous.

## Phase E local readiness

`phase-e-local-artifacts-v1.json` records the final role-specific Wasm and
worker digests, compressed sizes, zero-old-caller counts, and validation
checkpoint. `phase-e-local-timings-v1.json` records reproducible local Wasm
compile/instantiate medians and the native fixed presign/online lifecycle.
Cloudflare network, placement, CPU, and tail-latency results remain deployment
evidence.

`client-bundle-size-improvements-v1.md` summarizes the client-visible result:
normal pool-hit signing falls from 329,411 to 39,927 gzip bytes, an 87.9%
reduction, and first registration falls from approximately 250,506 to 102,165
gzip bytes, a 59.2% reduction. It also records which larger lifecycle-specific
artifacts are deferred.

`completion-audit-v1.md` derives the 30 authoritative tracker requirements,
maps every requirement to current implementation and executable evidence, and
records 27 requirements as aligned. B3, B6, and D7 are blocked by the completed
Cloudflare lifecycle review. It also records the resolved checkpoint-era
documentation drift found during the audit.

`final-local-test-receipt-v1.md` records the final Rust, Cloudflare route,
SDK/server build, source-guard, and focused browser rerun. It also separates
fresh local evidence from credential-dependent and deployment-owned cases.

`registration-package-delta-review-v1.md` records the sound registration-only
Wasm split, renamed production asset, compressed-size evidence, and browser
waterfall. It rejects whole-tree closure as packaging-only and now delegates
the reviewed lifecycle blockers to the lifecycle receipt.

`cloudflare-signing-lifecycle-security-review-v1.md` is the bounded security
review for the newer SigningWorker pool/online lifecycle and the live
same-account Ed25519 Yao adapter. It contains 19 Spec-IR entries, 69
function-level Code-IR records, full Alignment-IR, six findings,
platform-assumption citations,
focused check results, and the independent `REJECTED` verdict.
`cloudflare-signing-lifecycle-manifest-v1.json` pins the exact reviewed source,
specification, and test corpus plus the executed checks.

`rar-01-public-coin-remediation-v1.md` records the low-latency two-role online
rerandomization fix, its cross-language commitment vector, regenerated
artifacts, and the complete post-remediation test matrix. The superseding
digest-pinned decision in `docs/security/router-ab-ecdsa-phase4-review.md`
approves that exact receipt and closes `RAR-01`.

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
