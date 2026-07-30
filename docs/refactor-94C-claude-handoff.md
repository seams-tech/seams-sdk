# Refactor 94C: Claude Handoff — Regression-Review Fixes

Date: July 30, 2026
Author lane: Claude (per the Fable review split — Codex owned the Ed25519
wallet-session lane fix in `f26daf55f`; everything else from the review landed
here).

Base: `f26daf55f` (fix(near): authorize ed25519 wallet sessions by lane).
This handoff covers the six commits on top of it:

| Commit | Subject |
| --- | --- |
| `a5ba74039` | fix(registration): bind replay and activation to verified owners |
| `72fb458fd` | fix(router): bind recovery and refresh to request policy |
| `b8bbc75e1` | fix(session): honor requested expiry and scope at mint |
| `bf0678f60` | chore(deploy): align staging readiness and runbook with the live gateway |
| `9ab4ff6ff` | test(registration): repair stale strict-registration token issuer stub |
| `d5339eefe` | docs(94c): record staging recovery/export exercise as open |

Review-item mapping: item 1 → `a5ba74039`; item 2 → already fixed by your
`f26daf55f`, no work here; item 3 → `72fb458fd`; items 4–5 → `a5ba74039`;
item 6 → `b8bbc75e1`; cleanup items → `b8bbc75e1` + `bf0678f60`.

## 1. Respond replay authorization (review item 1)

`verifyRespondReplayAuthority` in
`packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService.ts`
now guards both stored-result replay paths (ECDSA
`evm_family_ecdsa_pending_activation` replay and the Ed25519-only stored
admission). It:

1. re-runs `verifyRegistrationAuthorityForIntent` on the presented proof, and
2. requires `storedRegistrationAuthoritiesMatch(stored, verified)`.

Step 2 is the part to review: re-verification alone is insufficient because
registration *mints* the credential — an attacker holding a stolen
`signedSetup` could verify a fresh passkey over the same challenge digest.
The match pins `credentialIdB64u`/`credentialPublicKeyB64u` (passkey) and
`providerSubject`/`registrationAuthorityId` (Email OTP) to the authority that
originally passed respond. Failure codes: `invalid_state` when no verified
authority exists, `unauthorized` on authority mismatch, and the underlying
verifier code otherwise.

Client impact: a legitimate client replaying respond must present a fresh
valid proof (it always re-collects one on retry today, so no client change
was needed).

## 2. Activation ownership (review item 4)

`StoredWalletRegistrationEvmFamilyEcdsaActivationClaimedBranch` and the
`…ActivatedBranch` gain `activationOwner: string` — the activate operation's
idempotency key, stamped by `claimEcdsaActivation`
(`d1RegistrationCeremonyStore.ts`). Enforcement points, all in
`d1WalletRegistrationService.ts` `activateWalletRegistrationEcdsa`:

- claim adoption (`claimed = existing`) requires owner equality — a
  concurrent activate under a different idempotency key now gets
  `conflict` instead of adopting the claim and re-running Router custody;
- the activated-branch readback requires owner equality before returning the
  stored activation/bootstrap;
- the commit-CAS conflict reconcile additionally compares owners before
  treating the stored branch as its own write.

The finalized branch intentionally drops the field
(`buildStoredWalletRegistrationEvmFamilyEcdsaFinalizedBranch` strips it) —
after finalize the operation row is the replay authority.

Legacy-row semantics to review: the record parsers
(`d1RegistrationCeremonyRecords.ts`) default a missing `activationOwner` to
`''`, which never matches, so pre-deploy claimed/activated branches DENY
adoption/readback rather than allow it. Blast radius: in-flight activations
during the deploy window can see `conflict` until the 10-minute ceremony TTL
clears them. Chosen deliberately over a permissive default.

### Tombstone

The post-commit `deleteCeremony` had two provably dead guard branches
(`idempotencyKey` is mandatory upstream); they are removed. A delete throw is
now logged (`console.warn`, tagged `[wallet-registration]`) and the response
still succeeds. This deviates from "tombstone deletion should be
authoritative" on purpose: the commit above it is irreversible, so failing
the response would strand a created wallet, and with owner-binding a
surviving ceremony can no longer re-run custody — the residue is a stale row
until TTL, not a second wallet. If you want stronger guarantees, folding the
delete into the commit batch is the follow-up, not response failure.

## 3. Near-provisioning retry identity (review item 5)

Client (`packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts`):
`deriveNearProvisioningIdempotencyKey` replaces the per-attempt random UUID.
Key = `wallet-registration-near-provisioning:` + SHA-256 over
`{registrationCeremonyId, activationReference.lifecycle_id,
activationReference.session_id (bytes as lowercase hex)}`. Every retry is
therefore the same consumer: the server-side `consumerBinding` (derived from
the request fingerprint, which includes the key) stays stable, so an
ambiguous first attempt resumes via same-key takeover instead of poisoning
the activation with `activation_consumed`.

Server (`d1WalletRegistrationService.ts`): a pre-consume guard now rejects
`activationReference.lifecycle_id !== ceremony.registrationCeremonyId` with
`scope_mismatch` BEFORE `consumeActivated` runs its first-writer CAS. This
closes consume-before-bind: ceremony A's `signedSetup` can no longer burn
ceremony B's activation. The post-consume deep-compare against
`storedYao.admissionRequest` remains as defence-in-depth.

Deploy-window caveat: retry loops started before this deploy still carry a
random key and stay poisoned until their ceremony TTL expires; fresh
registrations are unaffected.

## 4. Recovery and server-share refresh request policy (review item 3)

`packages/sdk-server-ts/src/router/routerAbEcdsaStrictRegistration.ts`:
`forwardRaw` now calls `tokenIssuer.issueRequest` for ALL post-registration
kinds, with `workKind: 'recovery' | 'server_share_refresh' | 'key_export'`
and the caller-supplied request digest. The policy-less `issue()` path for
these calls is gone.

Wire change: the recovery and refresh Gateway routes
(`cloudflare/routes/thresholdEcdsa.ts`) now take the same
`{request, requestDigestB64u}` envelope export uses (shared
`parseStrictEcdsaRequestDigestEnvelope`), and the sdk-web wrappers
(`routerAbEcdsaRecovery`, `routerAbEcdsaActivationRefresh`) send it. This is
a breaking body change, made safely: both wrappers have ZERO live callers
repo-wide (verified by grep), so no deployed client sends the old shape. The
digest is not trusted at the Gateway — the Router recomputes it from the
forwarded request and rejects mismatches — it only tells the Gateway which
request its signed policy covers. The dead `explicit_export` variant of the
client-side call union was removed while there.

Note: whoever wires the first live recovery/refresh caller must obtain the
canonical request digest. The WASM ceremony exposes
`explicit_export_request_digest_b64u()` for export;
`build_activation_refresh_request` / the recovery builder do not yet expose
their digests — a small WASM accessor will be needed then.

## 5. Session expiry and app-session scope (review item 6 + cleanup)

`packages/console-server-ts/src/router/cloudflare/d1StagingSession.ts`
`signToken`: `exp = min(payload.exp, now + ttlSeconds)` when the payload
carries a valid future `exp`; the adapter TTL is now a ceiling instead of an
override. Wallet-session JWTs no longer outlive their threshold session, and
the Router's budget-status `expiresAtMs` reflects the real session expiry.

`packages/sdk-server-ts/src/router/walletRegistrationRoutes.ts` activate
route: `verifyWalletRegistrationSetupClaims` is hoisted above both mints and
runs once for every successful activate. The Email OTP app session minted at
activate now carries `runtimePolicyScope` from the signed setup policy
(parity with `/session/exchange`), un-breaking the org-scoped enrollment
fallback in `authorizeStrictEcdsaSessionActivation` for
registration-minted sessions. Behavior shift to review: Ed25519-only
activates now also verify `signedSetup` at the route layer (the service
already verified it, so this only re-fails pathological cases).

## 6. Staging readiness and runbook (cleanup items)

`packages/console-server-ts/scripts/d1-staging-readiness-check.mjs`:

- gateway profile now requires the `ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK`
  secret and the `_KEY_ID`/`_ISSUER`/`_AUDIENCE` vars the worker
  hard-requires on every request;
- the dead `RELAY_SESSION_HMAC_SECRET`/`_ISSUER`/`_AUDIENCE` requirements are
  dropped (only the console worker still uses HMAC, via `CONSOLE_SESSION_*`);
- `ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK` joins `forbiddenPlaintextVars` so a
  staging config can never ship the signing key as a `[vars]` value (the
  local config legitimately does; staging must not).

All eight `d1-staging-*` runbook scripts, both `.toml.example` templates, and
the gitignored real `wrangler.d1-staging-gateway.toml` now name
`seams-console-staging-nrt` / `seams-signer-staging-nrt`, matching what
`generate-github-env-values.mjs` provisions since `3731c9989`. Operators
following the runbook no longer migrate/import/drill against the abandoned
pre-rename databases.

NOT done here: `scripts/deployment-targets.mjs` and the env-value generator
still emit `RELAY_SESSION_HMAC_SECRET` into the gateway manifest. It is dead
but harmless; removing it touches the GitHub environment values and belongs
to your deploy-tooling lane — flag if you want it gone in the same sweep.

## Validation performed

- `pnpm -C packages/{sdk-server-ts,sdk-web,console-server-ts,shared-ts} type-check` — all clean.
- Focused unit runs, all green (170 tests): `walletRegistrationRespondRoute`,
  `walletRegistrationActivateRoute`, `walletRegistrationSetupRoute`,
  `threeRouteRegistrationCeremony`, `registrationTerminalCancellation`
  (after the stub repair in `9ab4ff6ff`), `addWalletSigner.orchestration`,
  `walletRegistrationYaoClientContracts`, `nearProvisioningLifecycle`,
  `registrationDeferredNearLifecycle`,
  `ecdsaSigningIndependentOfNearProvisioning`, all nine `d1Staging*` script
  tests, `d1StagingSession`, `deploymentTargets`.
- Pre-existing failures, NOT from this change set (verified against a clean
  tree): `routerAbEcdsaDerivationRefresh.unit.test.ts` — 4 failures; the
  fixture's `recipient_encryption_key` no longer satisfies the
  `x25519:<64 lowercase hex>` parser. Classify per AGENTS.md (looks like
  `valid_test_needs_update` on a stale fixture key); left untouched.
- Not run here: `cargo test -p router-ab-cloudflare` (no Rust changes in
  these commits; your `f26daf55f` covered the Router side with the 198
  binding tests), repo-wide `pnpm check`.

## What remains before production

1. Staging exercise on the redeployed revision: NEAR signing + budget-status
   200 (your instruction), plus recovery and export — these were broken until
   `72fb458fd`, so the Wave 3 checkbox stays open until they pass.
2. Server-side tests still missing for: `/near-provisioning` (zero coverage),
   double-activate with different idempotency keys (would pin the new
   `conflict`), and any concurrency scenario. The owner-binding made these
   cheap to write against the D1 fixture if you want them in the minimum
   validation set.
3. Backlog explicitly deferred by the review (unchanged): diagnostics
   gating / Server-Timing rewiring, client intent-digest verification
   restore, custody hardening (KEK rotation window, forbidden-env keys,
   decrypt-failure logging), `near_pending` recovery path after ceremony TTL,
   operation-row expiry/sweeper.
4. Production deploy + the Wave 3 delete pass (migration blocks, retired
   bindings, `bootstrap_tokens` drop migration) per the plan doc.
