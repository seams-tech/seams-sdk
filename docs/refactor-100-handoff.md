# Refactor 100 — handoff

Branch `refactor-100-passkey-custody`, worktree `/private/tmp/seams-sdk-r100`.
Read `docs/refactor-100-passkey-account-refactor.md` first; it is the spec and
carries every frozen decision. This file is orientation, not a substitute.

## Why this refactor exists

One reason, and it should drive judgement calls: **passkey and Email OTP become
interchangeable auth methods for the same signer and the same signing
materials.** Today each factor derives its own roots, so a passkey account and
an OTP account are different wallets with different keys — you cannot add OTP to
a passkey wallet, because the keys would not match.

That is a capability, not a cleanup, and it cannot be retrofitted: independent
per-factor roots are irreconcilable after the fact. "Less code" and
"performance" are *not* justifications here — line count is up, and registration
is marginally slower. Don't argue the refactor on those grounds.

## The model, in one pass

- **One wallet custody seed** per wallet. Random, generated inside wasm, never
  crosses into JavaScript.
- **Owner roots derive from the seed in parallel** under domain-separated HKDF.
  No signing root is ever a function of another — that chaining was a real
  defect in the Email OTP runtime and is gone.
- **Factors wrap the seed.** Each factor derives its own KEK, so compromising
  one factor's key does not open the other's envelope. Adding a factor reseals
  the same seed under a new KEK.
- **Key sets are independent.** The EVM-family and NEAR Ed25519 key sets may be
  provisioned at different times. Each records its own manifest.
- **The manifest digest has no record of its own.** It rides the operational
  registration state that signing already depends on, so deleting it breaks
  signing loudly rather than narrowing the wallet silently. Enumerate key sets
  from registration state — never from "which manifests exist".

## What is built and green

Rust:

- `crates/signer-core/src/passkey_custody.rs` — envelope AAD, KEK, seal/open,
  the reseal path for adding a factor.
- `.../wallet_recovery_custody.rs` — two-level recovery wrap, wallet-scoped.
- `.../wallet_seed_derivation.rs` — root derivation, per-key-set manifest,
  and the proof tokens.
- `crates/router-ab-ed25519-yao-client` — `prepare_client_registration_with_root_v1`
  and `prepare_client_recovery_with_root_v1` (the continuity seam).
- `wasm/wallet_custody_ceremony` — the ceremony typestate, one key set per run,
  plus its `wasm_bindgen` boundary.

TypeScript:

- `packages/shared-ts/src/passkey-custody`, `.../wallet-recovery` — records and
  parsers.
- `packages/sdk-server-ts/.../d1WalletCustodyCommitStore.ts` — atomic commit of
  envelope + recovery set in one D1 transaction.
- `.../walletCustodyRegistrationCommit.ts` — payload → records adapter.
- `packages/sdk-web/.../workers/wallet-custody-ceremony.worker.ts` and
  `.../walletCustody/ceremonyDriver.ts` — worker and driver.

Verification: signer-core 9 suites, 24 tests in the ceremony crate (12 output
contract, 8 through the real Router A/B circuit, 4 at the wasm boundary), 67
TypeScript custody unit tests, `tsc` clean across shared-ts / sdk-server-ts /
sdk-web.

The circuit tests are the ones to read first if you want the model in your head
rather than on paper: they establish custody with an EVM-family run, then reach
the same seed from a NEAR run by opening the envelope it sealed.

## Two guarantees that look like style but are not

**Proof tokens.** `VerifiedWalletKeySetManifestDigestV1` and
`WalletCustodySeedFromSealedEnvelopeV1` have private fields and single
constructors. They exist so that "verify before you seal" is a type, not a
convention, and so a proof for one key set cannot write another's record. Do not
add a conversion between them, and do not let either cross the wasm boundary — a
token that came back would prove only that *some* verification once succeeded.

**Establish vs join.** A ceremony run either establishes custody (generates the
seed, seals it, issues ten codes) or joins existing custody (opens the envelope,
writes only its manifest). `finish()` refuses both crossed combinations. A
joining run that sealed would give the wallet a second seed and a second
recovery set, leaving half its keys covered by neither. `join_existing_custody`
is the only constructor for that origin and it requires a successful open.

## Next steps, in order

1. **Splice the ceremony into `registration.ts`.** The file was split for this —
   4,154 lines now, with the Yao and ECDSA phases in their own modules. Respect
   Refactor 94C's tested contract: deferred NEAR work is handed off before
   activate and never awaited. With key sets decoupled this is no longer a
   conflict; EVM commits its custody immediately and NEAR records its manifest
   whenever its Yao work settles.

   Both blockers were settled on 2026-08-07 — decisions and reasons are pinned
   in the plan's splice entry. In brief:

   **Everything stays on the router-ab registration route — and (verified
   2026-08-08) with no wire, Gateway-kind, or Router change for the key
   substitution.** The Router never checks the client share's provenance: the
   SigningWorker composes the activation receipt from the client's *claimed*
   facts against its own material (`router-ab-cloudflare/src/lib.rs:3215`),
   and every digest the request validation pins is a pure function of the
   registration request the client built. So the client runs registration
   exactly as today and presents activation facts computed from the
   seed-derived share instead of `xClientBase`. The rounds keep running — they
   provision the SigningWorker's relayer half, which is still needed. Earlier
   notes proposing a new ECDSA payload kind are superseded; the proof chain is
   in the plan's flow map. Do NOT reach for
   `thresholdEcdsaDerivationRoleLocalBootstrap` — it has no server counterpart;
   the format it names is the registration route's own activate output. The
   binding digest is not a problem: the local create step computes it from the
   setup facts before any network leg, and the digest requirement stays.

   **The custody commit rides the activate/finalize leg** — no standalone
   route. Authorization is the registration's own: verified `signedSetup` plus
   the leg's auth proof; the handler checks the payload's wallet is the
   verified registration's wallet and supplies the factor ref from the
   credential it just verified. On `custody_already_established`, the client
   discards the run's seed and re-enters as a join; on `already_exists`, it
   stops.

   **The NEAR half is a narrow substitution** at
   `RouterAbEd25519YaoClientV1.registerAdmitted`, which today derives the root
   from `secret32`. But do not splice it alone for mixed wallets: a wallet
   whose NEAR keys come from the seed while its EVM keys are still PRF-derived
   is half-covered by its own recovery set. Ed25519-only wallets are the safe
   first slice.

   The store side of the establish race is already in place and tested: the
   commit store distinguishes a lost race (`custody_already_established` — a
   different ceremony won; this run's key set is still unrecorded) from a
   replayed commit (`already_exists` — this commit already applied). What the
   splice adds is the client reaction: on the first, discard the run's seed and
   re-enter as a join — the driver's `custody` union expresses this — and on
   the second, stop.
2. **Shrink `wasm/ecdsa_registration_client`** once registration leaves it.
   It is not registration-only: `open_ecdsa_role_local_signing_share_v1` runs at
   rehydration and two workers load it. Rename around role-local material
   rehydration, or fold the remainder into its natural owner — do not leave a
   compatibility shell under a misleading name.
3. **Delete the PRF-derived signing-root paths** and wipe dev OTP wallets. Last,
   so registration is never without a working path.

## Working notes for whoever picks this up

- `AGENTS.md` has the custody vocabulary. Each term names exactly one thing, and
  the glossary exists because a naming collision once caused a misdiagnosed
  vulnerability report. Check a value before citing it in a security claim.
- The testing policy in `AGENTS.md` is real: classify a failure before changing
  code for it. Several suites here encode retired shapes.
- Two source-guard items are open and **not** caused by this work:
  `HostedSeamsAuthMenu/types.ts` is missing from the type-filename inventory
  (from `fa24c2569`), and two `addWalletSigner.orchestration` tests fail
  identically on an untouched checkout.
- A gap worth closing: a cdylib inherits every `#[wasm_bindgen]` export
  reachable through its rlib dependencies. That leaked the Yao client's seed
  export into the ceremony package, and it was caught only by reading the
  generated `.js`. The other half of this is now covered —
  `pnpm -C packages/sdk-web check:wasm-import-drift` fails on an import naming
  something a generated wrapper does not export, and runs in the source-guard
  chain — but nothing yet asserts the *outbound* surface, i.e. that a package
  exports only what it means to. `check:wasm-exports` reports it; read it when
  adding a wasm package.
- The other gap: nothing tests the Rust↔TypeScript wire contract. Each side
  tests itself, which is how the seed-binding drift went unnoticed. A shared
  fixture that round-trips a record through both parsers would catch the whole
  class.
- A third, cheaper to close than either: the one-key-set rebuild deleted
  `ceremony::tests` along with the states it was written against, and the crate
  stayed green because the remaining tests still passed. An earlier version of
  this file then described those tests as present. Nothing watches whether a
  refactor removes coverage — a green suite says only that what still compiles
  passes. When a commit rewrites a module, check the test count moved the way
  you expect.
