# Refactor 89 registration package delta review v1

Date: July 17, 2026

Status: **REJECTED FOR WHOLE-TREE CLOSURE — registration package split sound;
Cloudflare lifecycle review completed and rejected**

Reviewer: Codex independent cryptographic review agent

This receipt reviews the registration-only ECDSA client package introduced
after the bounded construction review in
`docs/security/router-ab-ecdsa-phase4-review.md`. It covers source ownership,
Wasm exports, operation-selective loading, build and hosted-asset paths,
compressed-size enforcement, and browser network behavior.

## Decision

The registration package split is approved in isolation. It changes package
ownership and generated artifact names without changing the fixed 2-of-2
presign construction, online signing equations, transcript domains,
randomness, adversary model, or formal assumption ledger. All 16 artifacts in
the approved cryptographic corpus retain their recorded SHA-256 digests. The
current lifecycle receipt supersedes those immutable documents'
Cloudflare-adapter completeness statements.

The current complete tree is rejected as a packaging-only delta. Three
separately changed `router-ab-cloudflare` files belong to the approved
122-file manifest and contain signing/pool lifecycle behavior. They require a
bounded lifecycle review before Refactor 89 formal closure.

That review is now complete at
`docs/evidence/refactor-89/cloudflare-signing-lifecycle-security-review-v1.md`
and returned `REJECTED`. The result does not change this receipt's approval of
the registration package split. Formal closure now requires lifecycle
remediation and independent re-review; restoring the earlier bytes would
discard the required Cloudflare integration rather than close it.

The new `ecdsa_registration_client` owns bootstrap preparation, bootstrap
finalization, resolved Email OTP bootstrap, and opening of activated role-local
signing material. `router_ab_ecdsa_derivation_client` retains only explicit
recovery/export ownership. The production worker initializes the package
selected by the requested operation. Registration cannot initialize or fetch
the deferred export Wasm.

## Security boundary review

- The new wrapper performs fixed-length decoding, validates public role and
  participant fields, zeroizes decoded root-share buffers, and delegates
  secret arithmetic to the existing role-local signer core.
- The wrapper adds no division, remainder, table lookup, loop bound, or branch
  controlled by locally held secret scalar bytes.
- Base64 and JSON processing remain variable-time browser boundary operations.
  Runtime constant-time behavior remains excluded from the construction claim.
- The registration worker and Email OTP worker import the registration package;
  presign and online workers are guarded against importing it.
- Explicit export initializes the deferred derivation/export package.
  Registration prepare and finalize initialize only the registration package.
- The old `router_ab_ecdsa_registration_client` crate, generated package, and
  hosted asset names are absent. No compatibility alias remains.

## Blocking manifest drift

These current files contain no registration-package references and differ from
their independently reviewed bytes:

| File | Approved SHA-256 | Current SHA-256 |
| --- | --- | --- |
| `crates/router-ab-cloudflare/Cargo.lock` | `ff7afbe12eefd7e1e52892ab17ce504ecc9847a3bcdb45dbc2dafdb73a48e4b3` | `f989c8520ca4ecf51f2117a46ccc262d0175e3ceff7121d5c7f030f52af254f0` |
| `crates/router-ab-cloudflare/Cargo.toml` | `f89b46182145f269ae9fd32657849e53e122870e397a4112710ad0d5e02e1535` | `1d709044d22611378f6f597296812435f0f9060abdf6a3ae52c8255ce71397b1` |
| `crates/router-ab-cloudflare/src/lib.rs` | `cd603e51b4a6b774d81df343fa39ea326d51eb024b24e8aace55f5fa74fee202` | `95b78eb5fcfc0a50f14af91dddd34add23a0cda4069df70a7373bef989d55ad0` |

The `src/lib.rs` delta includes pool admission, reserve, commit, finish, and
tombstone lifecycle behavior. The separate review found material-bearing
committed persistence, unreachable destructive recovery, incomplete
failure/expiry/retirement burns, rollback revival exposure, and an uncapped
reservation lease.

The generated online worker and the two expected registration boundary guards
also changed. They are evidence/artifact entries rather than the blocking
cause:

- `packages/sdk-web/dist/public/sdk/workers/ecdsa-online-client.worker.js`:
  `25c2cb86…` to `8de3c8cb…`;
- `tests/scripts/check-ecdsa-client-worker-split.mjs`: `7b19a96e…` to
  `7cccbfbf…`; and
- `tests/scripts/check-router-ab-ecdsa-derivation-boundaries.mjs`:
  `7c0eb8d3…` to `15be5f6b…`.

## Executable evidence

| Check | Result |
| --- | --- |
| Registration crate locked offline `cargo check` | passed |
| Registration crate release `wasm-pack` build | passed |
| Production SDK build, TypeScript compile, worker bundle, and hosted asset emission | passed |
| Router A/B derivation boundary guard | passed |
| ECDSA worker ownership split guard | passed |
| Ed25519 Yao/NEAR signing boundary guard | passed |
| Browser registration waterfall | passed; registration Wasm fetched and deferred export Wasm absent |
| Static hosted-asset MIME and transformation eligibility | passed |
| Stale source, package, and production artifact name search | passed |

The current registration Wasm is 218,036 raw bytes, 92,334 gzip-9 bytes, and
76,739 Brotli-11 bytes. The current production derivation worker is 46,718 raw
bytes, 9,831 gzip-9 bytes, and 8,699 Brotli-11 bytes. Their per-file compressed
totals are 102,165 gzip-9 bytes and 85,438 Brotli-11 bytes. The registration
Wasm stays below its 100 KiB gzip and 85 KiB Brotli ceilings; the combined path
stays below its 110,000-byte gzip ceiling.

## Reviewed delta manifest

The records below are bytewise sorted before hashing. The SHA-256 of the
34 canonical `sha256`, two-space, repository-relative path, LF records is
`9ff370b127f05cc4a4937c5c5d943d1e4b2f4cdafc3de0c358b6acab4da38302`.
The review document itself is excluded.

```text
cb6cacba5daa4b99fe23f6863d96743126d9d325fdfeebc872174903f3050bfb  packages/sdk-web/dist/workers/ecdsa-derivation-client.worker.js
3aea1b0067e668f51a3cae16005a3ebb68ab83a75e6d54cca155b4872bbbf83f  packages/sdk-web/dist/workers/ecdsa_registration_client_bg.wasm
f9dfcdccf840ecf5c97214d25dc78a066f9798597c2f1dc22bb742d95ef264fd  packages/sdk-web/dist/workers/router_ab_ecdsa_derivation_client_bg.wasm
da56c2bae4fb8d602ebb2035791a55975ea9608c0d6bdf313085615b31ee4783  packages/sdk-web/build-paths.sh
3a4dea874c2ab5dd9b9a7a5ae81aa40097d268a73b013d53406cd06f411fcc45  packages/sdk-web/build-paths.ts
ae88972c9ee2cc73b2331db28013f152ef086db9b3b21cf97b475943f5262c3e  packages/sdk-web/rolldown.config.ts
ac949e668514178c412be17ebe1cfc28f2bf9f04e505eed691a2d3c0e14cce28  packages/sdk-web/scripts/build/build-prod.sh
5e9fe779a041e2642ba31e1e7b704ef6605c67dcb3332af86b8087fc93cde35e  packages/sdk-web/scripts/build/build-sdk.sh
346465b8452205cb0d45f1fc25551dc09626f6f2dc58850b64db1490e2e0d416  packages/sdk-web/scripts/build/build-wasm.sh
e79066a1ba43bebae808e6247affd81c9e36ff29cbbc8ec77f0c3644391038f6  packages/sdk-web/scripts/checks/assert-static-wallet-assets.mjs
d111d0219d2bd84fe1f0c5e2be0b466121377a55a8a3b6394ff195e5fe2d8dd7  packages/sdk-web/scripts/checks/report-wallet-iframe-bundle-size.mjs
eff46c150c3c9684805cf8d96fb5b69cc6e432b703e3e6e329a0e53caca36872  packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsa-derivation-client.worker.ts
379f42afd8b7a06326b2630af9b8a3dec06c22b62413fa98e6b4fb1e8fe113b3  packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts
f3df77683200c972d802724bd84c5d335583191b2d1fec206cec6132918151b1  tests/helpers/thresholdEcdsaClientBootstrap.ts
7cccbfbfe36599e0e86b2860264175109e29cbdae5d6247a31604cda20427522  tests/scripts/check-ecdsa-client-worker-split.mjs
f50f279ecc9bd00d3601fb4fd6e35d0665a7c835de2176f6de02c452c9faf67b  tests/scripts/check-ed25519-yao-near-signing-boundaries.mjs
15be5f6b0de021904dca0999d8241ef5f4709544fd8551add8dcbec7d0836d37  tests/scripts/check-router-ab-ecdsa-derivation-boundaries.mjs
1630864802ea5f0f38412233843f0b53a810839a2adaaf3c50f8446b06ee14c3  tests/unit/cloudflareD1ConsoleServices.unit.test.ts
ba242c4f6cd6fdf19da873f7b61d4eb4bc1a730c21fc8e16b4a9601eef96a8ee  tests/unit/routerAbEcdsaRegistrationWaterfall.unit.test.ts
a9b6c3aad7a59b66900aaca1c41ec33cd0b9ba1bedbd58b8f0aa1c9f49a923b8  tests/unit/thresholdEcdsa.derivationBootstrapPolicy.unit.test.ts
c3977a2cd6bb6a2594de1f9cbfb7d3b603e5c8e2b6a01807b08b427a4978028a  tests/unit/thresholdEcdsa.derivationRoleLocalExportPolicy.unit.test.ts
a21bb9c0b4deee5f677fcba8ea8602413149b114fa9f03a09775c2881d763b9b  tests/unit/thresholdEcdsa.derivationWasmSurface.unit.test.ts
42d8465fa8a4b2a97cc22bee4688beea500f739ffa4140b60662e14fb3c3f1c9  tests/unit/thresholdEcdsa.signingRootResolver.script.unit.test.ts
e80c817fcbe27fc51ea09f3d743051fd308d538f78cbbaef2a2205a0e595a293  wasm/ecdsa_registration_client/Cargo.lock
3df30fdd41f8ded46e3dc0f76044463206a0fbd68296d17f4eab0558d19de821  wasm/ecdsa_registration_client/Cargo.toml
b8c54c02b263df7a1ce18cffae017e8e1eec97368d5a9d129c10479a0d6d6132  wasm/ecdsa_registration_client/README.md
ebd06345426b01e6ae92c40983add39a9051a13d8f0f5d95d474724fa8ae8f52  wasm/ecdsa_registration_client/pkg/ecdsa_registration_client.d.ts
1f92bd5390b392d69b131ebd747ab281fb663f082f1b182277d569d9afecf292  wasm/ecdsa_registration_client/pkg/ecdsa_registration_client.js
3aea1b0067e668f51a3cae16005a3ebb68ab83a75e6d54cca155b4872bbbf83f  wasm/ecdsa_registration_client/pkg/ecdsa_registration_client_bg.wasm
adc878910e6ee8929978609364c0ed5adf9db639340d89a1309fbb9286438937  wasm/ecdsa_registration_client/src/lib.rs
2da18ab26586f0ec42194b9dd08f4ffc775edca83865b890cf485ac001ffcb17  wasm/router_ab_ecdsa_derivation_client/Cargo.lock
ac99dbddc11a0cf03dbcc782b37f6552c585afe370cbc8d1b8f9d7f732ba0c88  wasm/router_ab_ecdsa_derivation_client/Cargo.toml
e456a674261a444ea28737ee55db607683d47d695d25dda49bc98435001e95e4  wasm/router_ab_ecdsa_derivation_client/src/ecdsa_role_local.rs
1ab690ff2b0da9d8f22b6fe586f28dd94f18215ec1584794dfca7e7e372c9a8a  wasm/router_ab_ecdsa_derivation_client/src/lib.rs
```

The deleted `wasm/router_ab_ecdsa_derivation_client/src/js.rs` and all
`router_ab_ecdsa_registration_client` paths are recorded as required absences
by the executable boundary guards rather than as hash records.

## Retained exclusions

This receipt supplies no claim that the entire current tree is packaging-only,
that pool lifecycle and normal-signing paths are unchanged, or that all 122
reviewed paths remain byte-identical. It also supplies no claim of browser
runtime constant-time execution, production Cloudflare account separation,
deployed latency, cost, rollback readiness, or security after both signing
parties are corrupted.
