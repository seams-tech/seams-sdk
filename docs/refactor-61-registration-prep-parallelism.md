# Registration Preparation Parallelism

Date created: June 8, 2026

Status: route split, registration warmup instrumentation, passkey confirmation
sub-buckets, and direct registration confirmation path landed, benchmarked, and
retained.

## Goal

Move registration preparation work under the user's passkey or Email OTP proof
collection window.

The target is a registration flow where the SDK starts every safe preparation
task as soon as the registration intent exists, then consumes the prepared
material only after the final authority proof verifies. This should reduce the
post-proof path to proof verification, prepared-material binding, HSS respond
and finalize, persistence, and readiness checks.

Near-term latency target:

- full browser wallet-iframe registration p50 at or below `1500ms`
- `/wallets/register/start` no longer dominated by fresh
  `registrationHssPrepareMs`
- no weakening of registration intent, authority, HSS, signing-root, or wallet
  scope binding

## Relationship To Existing Plans

- `docs/refactor-59-optimize.md` owns the full registration benchmark and the
  timing report that showed `/wallets/register/start` p50 around `376ms`,
  dominated by `registrationHssPrepareMs`.
- `docs/refactor-55-hss-optimize-registration.md` owns historical HSS
  registration optimization work and the older registration-start pipelining
  candidate.
- `docs/refactor-62-hss-prepare-preauth.md` owns the HSS-specific preauth
  prepare contract and binding rules.
- This plan owns full registration orchestration across grant/intent work,
  wallet iframe warmup, worker/WASM init, HSS preauth prepare, optional account
  reservation, route contracts, and lifecycle state.

## Current Flow

Current browser registration is mostly serial:

```text
create managed registration grant
  -> create registration intent
  -> verify local registration intent digest
  -> collect passkey create or Email OTP proof
  -> POST /wallets/register/start
       -> load and consume registration intent
       -> verify authority proof
       -> prepare Ed25519 HSS server session
       -> prepare optional ECDSA route-local context
       -> persist registration ceremony
  -> prepare client HSS request
  -> POST /wallets/register/hss/respond
  -> build client-owned HSS evaluation artifact
  -> POST /wallets/register/finalize
  -> local persistence and readiness checks
```

The measured problem is that `registrationHssPrepareMs` runs after the user has
already completed the passkey or OTP proof. That makes HSS server prepare part
of the post-auth critical path.

## Target Flow

The new flow should start independent preparation tasks as soon as their inputs
exist:

```text
validate local inputs
  -> start wallet iframe warmup and signing worker/WASM init
  -> create managed registration grant
  -> create registration intent
  -> verify local registration intent digest
  -> start registration preparation
       -> Ed25519 HSS server prepare
       -> optional ECDSA prepare context
       -> optional account reservation
       -> route diagnostics preallocation
  -> collect passkey create or Email OTP proof in parallel
  -> wait until proof and required preparation are both ready
  -> POST /wallets/register/start with registrationPreparationId
       -> load prepared record
       -> verify authority proof
       -> atomically consume registration intent for the verified preparation
       -> bind prepared material to the verified intent and authority
       -> persist registration ceremony
  -> prepare client HSS request
  -> POST /wallets/register/hss/respond
  -> build client-owned HSS evaluation artifact
  -> POST /wallets/register/finalize
  -> local persistence and readiness checks
```

The route contract changes are intentional. The start route should receive a
typed `registrationPreparationId` for signer modes that require preauth
material. Missing prepared material should be a typed lifecycle error, because
the optimized flow is the only flow this refactor should support.

## Preparation Work Items

Safe to start before the final proof:

- wallet iframe load, handshake, and router warmup
- signing engine worker startup
- HSS client signer WASM init
- Email OTP worker startup
- registration intent digest computation
- Ed25519 HSS server prepare after the registration intent exists
- optional ECDSA registration prepare context after the registration intent
  exists
- optional bounded account reservation after the registration intent exists

Must wait for the final proof:

- WebAuthn registration verification
- Email OTP registration proof verification
- registration intent consumption
- ceremony persistence with verified authority
- HSS respond
- HSS finalize
- wallet, signer, credential, session, and key publication persistence
- any irreversible NEAR account creation or key publication

Optional account reservation is a latency and race-control optimization only. It
must expire quickly, be quota-bound by the managed registration grant or project
policy, and still require final existence checks before account creation.

## Route Contract

Add a registration preparation route:

```text
POST /wallets/register/prepare
```

Request:

```ts
type WalletRegistrationPrepareRequest = {
  registrationIntentGrant: RegistrationIntentGrant;
  registrationIntentDigestB64u: string;
  intent: RegistrationIntentV1;
  work: WalletRegistrationPrepareWork;
};

type WalletRegistrationPrepareWork =
  | {
      kind: 'ed25519_hss';
      accountReservation: AccountReservationRequest;
      ecdsa?: never;
    }
  | {
      kind: 'ed25519_hss_and_ecdsa';
      accountReservation: AccountReservationRequest;
      ecdsa: EcdsaRegistrationPrepareRequest;
    }
  | {
      kind: 'ecdsa_only';
      accountReservation: AccountReservationRequest;
      ecdsa: EcdsaRegistrationPrepareRequest;
    };
```

Response:

```ts
type WalletRegistrationPrepareResponse =
  | {
      ok: true;
      state: 'prepared';
      registrationPreparationId: RegistrationPreparationId;
      expiresAtMs: number;
      prepared: WalletRegistrationPreparedBranches;
      diagnostics: RegistrationPrepareDiagnostics;
    }
  | {
      ok: true;
      state: 'preparing';
      registrationPreparationId: RegistrationPreparationId;
      expiresAtMs: number;
      diagnostics: RegistrationPrepareDiagnostics;
    }
  | {
      ok: false;
      code: string;
      message: string;
    };
```

Update `/wallets/register/start`:

```ts
type WalletRegistrationStartRequest = {
  registrationIntentGrant: RegistrationIntentGrant;
  registrationIntentDigestB64u: string;
  intent: RegistrationIntentV1;
  registrationPreparationId: RegistrationPreparationId;
  authority: WalletRegistrationStartAuthority;
};
```

The route parser should reject legacy HSS branches, raw session branches,
ad-hoc prepared material, and start requests without a preparation id for
prepared signer modes.

## Lifecycle Types

Model SDK registration with a discriminated lifecycle. Core functions should
accept the narrow branch they need.

```ts
type RegistrationPreparationLifecycle =
  | {
      kind: 'intent_allocated';
      intent: RegistrationIntentV1;
      registrationIntentGrant: RegistrationIntentGrant;
      registrationIntentDigestB64u: string;
    }
  | {
      kind: 'preauth_preparing';
      intent: RegistrationIntentV1;
      registrationIntentGrant: RegistrationIntentGrant;
      registrationIntentDigestB64u: string;
      registrationPreparationId: RegistrationPreparationId;
      startedAtMs: number;
      expiresAtMs: number;
    }
  | {
      kind: 'preauth_prepared';
      intent: RegistrationIntentV1;
      registrationIntentGrant: RegistrationIntentGrant;
      registrationIntentDigestB64u: string;
      registrationPreparationId: RegistrationPreparationId;
      prepared: WalletRegistrationPreparedBranches;
      expiresAtMs: number;
    }
  | {
      kind: 'authority_collected';
      prepared: RegistrationPreauthPreparedLifecycle;
      authority: WalletRegistrationStartAuthority;
    }
  | {
      kind: 'start_ready';
      prepared: RegistrationPreauthPreparedLifecycle;
      authority: WalletRegistrationStartAuthority;
    }
  | {
      kind: 'ceremony_started';
      registrationCeremonyId: string;
      started: WalletRegistrationStartedBranches;
    };
```

Do not use broad object spreads to construct these branches. Use branch-specific
builders that require all identity, digest, preparation, and authority fields.

## Client Implementation Plan

### Phase 1: Warmup Inventory

- [x] Identify wallet iframe warmup calls that are safe before authority proof.
- [x] Identify signing worker and HSS WASM init calls that can run without user
      secrets.
- [x] Identify Email OTP worker init paths that can run before proof.
- [x] Add diagnostics for warmup start, warmup ready, and warmup wait time.
- [x] Add tests proving diagnostics do not influence registration control flow.

Notes:

- Registration now starts `warmCriticalResources` before managed grant
  creation and records `registrationWarmupMs` plus
  `registrationWarmupWaitMs`.
- `warmCriticalResources` uses the existing safe warmup boundary: UI prewarm,
  worker creation, nonce context, and account-local IndexedDB/key-material
  reads where an account id is available. Worker WASM initialization remains
  operation-lazy unless the worker exposes a no-secret initialization command.
- The orchestration fixture covers warmup diagnostics as observational timing
  fields and keeps ECDSA-only registration off the Ed25519 preauth prepare
  route.

### Phase 2: Preparation Route Client

- [x] Add `RegistrationPreparationId` as a branded domain id.
- [x] Add `prepareWalletRegistration` to the relayer RPC client.
- [x] Parse prepare responses into discriminated result branches at the RPC
      boundary.
- [x] Update `startWalletRegistration` callers for Ed25519 signer modes to pass
      `registrationPreparationId`.
- [x] Add type fixtures rejecting raw strings, missing preparation id, mixed
      work branches, and direct object-literal invalid lifecycle states.

### Phase 3: Registration Orchestration

- [x] Start iframe warmup and worker/WASM init before grant creation where the
      current platform runtime can do so.
- [x] Include UserConfirm worker initialization in registration warmup so host
      origin passkey auth no longer pays worker startup on the proof path.
- [x] Start `/wallets/register/prepare` immediately after the registration
      intent digest verifies locally.
- [x] Collect passkey create or Email OTP proof in parallel with preparation.
- [x] Wait for both `preauth_prepared` and `authority_collected` before calling
      `/wallets/register/start`.
- [x] Keep user-visible progress events stable while moving internal work
      earlier.
- [x] Split timing buckets into preparation wait, proof wait, and start-route
      execution.

### Phase 4: Server Route And Store Contract

- [x] Add a prepared-registration record to `RegistrationCeremonyStore`.
- [x] Persist preparation records separately from verified registration
      ceremonies.
- [x] Add an atomic consume method that consumes an intent only after the
      caller supplies the verified digest, preparation id, and expected scope.
- [x] Bind preparation records to grant, digest, wallet id, rp id, signer
      selection, signing root, expected origin, participant ids, and expiry.
- [x] Consume or invalidate the preparation record when
      `/wallets/register/start` succeeds.
- [x] Expire abandoned preparation records aggressively.
- [x] Keep raw DB parsing inside the store boundary.

### Phase 5: Optional Account Reservation

- [ ] Define `AccountReservationRequest` as an explicit branch with required
      wallet id, rp id, intent digest, reservation ttl, and reservation purpose.
- [ ] Add a disabled-by-default reservation policy in server config.
- [ ] Implement memory-store reservation first for tests and benchmarks.
- [ ] Add durable-store reservation only if benchmarks show a real win.
- [ ] Recheck account availability during finalize or account creation.
- [ ] Add abuse tests for abandoned reservations and repeated preparation.

### Phase 6: Benchmark And Keep Decision

- [x] Add benchmark buckets for preparation route, preparation wait, and
      start-route execution.
- [x] Add benchmark buckets for registration warmup and warmup wait.
- [x] Add benchmark sub-buckets for authenticated wallet-state activation,
      nonce prefetch, key-material read, UI confirm prewarm, and signer worker
      prewarm after the warmup surface exposes them.
- [x] Expose HSS worker WASM init wait p50/p95 in the registration-flow HSS
      worker diagnostics table.
- [x] Add passkey auth proof sub-buckets for confirmation bridge, PRF
      extraction, and credential redaction.
- [x] Add passkey confirmation/WebAuthn bridge sub-buckets for UserConfirm
      worker ready, worker round trip, prompt UI, credential create,
      credential serialization, duplicate retry count, and main-thread total.
- [x] Split prompt UI timing into element-definition, mount, and decision-wait
      buckets so wallet-iframe prompt cost can be separated from credential
      creation.
- [x] Route registration credential confirmation directly on the main-thread UI
      path, bypassing the UserConfirm worker bounce for registration while
      preserving the worker-backed path for signing flows.
- [x] Add benchmark-only wallet-iframe auto-confirm diagnostics for iframe
      attachment, frame resolution, confirm-button visibility, click dispatch,
      click duration, attempts, and total helper time.
- [x] Retain stable benchmark auto-confirm retry hygiene: keep the `50ms`
      locator timeout, remove the extra benchmark retry sleep, and stop the
      benchmark helper after the first successful click.
- [x] Add benchmark sub-buckets for wallet-iframe mount, load wait,
      boot-hint wait, handshake, connect total, and handshake attempts.
- [ ] Add benchmark sub-buckets for account reservation after that surface
      exposes explicit no-secret timing hooks and benchmarks show route
      contention.
- [x] Run `pnpm benchmark:registration-flow:smoke` before and after the route
      split.
- [x] Keep the change because the post-proof start path improves materially.
- [x] Record retained results in `docs/benchmarks/registration-flow.md`.
- [x] Update `docs/refactor-59-optimize.md` with the new bottleneck ranking.

Notes:

- One-run wallet-iframe validation `20260610-125951Z` captured
  `walletIframeTransportDiagnosticsCount=1`; sample transport buckets were
  mount `2ms`, load wait `33ms`, boot-hint wait `52ms`, handshake `0ms`,
  connect total `87ms`, and one handshake attempt.
- Full smoke `20260610-130323Z` passed all four passkey scenarios and captured
  wallet-iframe transport diagnostics for both wallet-iframe scenarios. P50
  transport connect was `99ms` Ed25519-only and `115ms` combined, while
  wallet-iframe passkey auth was `878ms` / `866ms` and
  `ed25519EvaluationArtifactMs` was `496ms` / `489ms`. This keeps transport
  optimization as secondary and points the next latency lane back to refactor-64
  client artifact construction or a separately specced passkey activation UX
  change.
- Smoke run `20260609-170907Z` passed all four passkey scenarios and synced
  `docs/benchmarks/registration-flow.md`. New warmup sub-buckets showed
  `registrationWarmupMs` p50 at `1ms`, `1ms`, `3ms`, and `2ms`, with
  `registrationWarmupWaitMs` p50 still `0ms` in every scenario. Wallet-state
  activation accounts for nearly all measured warmup time, while nonce
  prefetch, key-material read, UI prewarm, and signer-worker prewarm are
  effectively zero in the smoke path.
- The same report now exposes HSS worker `wasmInitWaitMs` p50/p95 in the HSS
  worker diagnostics table. It was `0ms` p50 and p95 for
  `prepare_client_request` and `build_client_owned_staged_evaluator_artifact`,
  so lazy HSS WASM initialization is not currently a meaningful registration
  bottleneck.
- Smoke run `20260609-171626Z` added passkey auth proof sub-buckets and passed
  all four passkey scenarios. `passkeyAuthConfirmationMs` matched
  `authProofMs` in every scenario: `907ms`, `904ms`, `569ms`, and `573ms` p50.
  PRF extraction and credential redaction were `0ms` p50/p95, so the wallet
  iframe auth penalty sits inside the confirmation/WebAuthn bridge rather than
  local passkey post-processing.
- Smoke run `20260609-172910Z` added confirmation/WebAuthn bridge sub-buckets
  and passed all four passkey scenarios. Host-origin auth proof was split into
  about `377ms` p50 UserConfirm worker readiness plus `202ms` to `203ms` p50
  WebAuthn credential creation. Wallet-iframe auth proof was about `870ms` p50:
  roughly `369ms` to `372ms` worker readiness, `281ms` to `294ms` prompt/UI
  handoff, and `203ms` credential creation. Response validation, request setup,
  credential serialization, PRF extraction, and credential redaction were
  `0ms` p50.
- Smoke run `20260609-173305Z` included UserConfirm worker initialization in
  registration warmup and passed all four passkey scenarios. Host-origin
  `authProofMs` dropped from `578ms` to `580ms` p50 down to `203ms` to `206ms`
  p50, with `passkeyAuthWorkerReadyMs` now `0ms`. Wallet-iframe SDK p50 stayed
  roughly flat (`1851ms` and `1903ms`), because the remaining auth time sits in
  worker request round trip plus prompt/UI handoff. This keeps the worker
  prewarm because it removes host-origin critical-path startup without changing
  the trust model.
- Smoke run `20260609-174456Z` split prompt UI into element-definition, mount,
  and decision-wait buckets. Element definition and mount were `0ms` p50 in the
  passkey smoke path; wallet-iframe cost sat in decision wait plus WebAuthn
  credential creation.
- Smoke run `20260609-174752Z` tightened benchmark accounting by measuring
  browser duration before the post-result log-settle sleep and lowering the
  wallet-iframe auto-confirm polling interval from `250ms` to `50ms`. This was
  retained as benchmark harness hygiene: browser-observed p50 dropped by
  `185ms` to `874ms` depending on scenario, while SDK timing stayed comparable.
- A CSS prewarm experiment (`20260609-175140Z`) was rejected. It produced only
  noise-level movement in prompt decision timing and did not move the retained
  registration bottlenecks.
- Smoke run `20260609-180125Z` routed registration credential confirmation
  directly through the main-thread UI path. This removed the redundant
  UserConfirm worker round trip (`passkeyAuthWorkerRequestRoundTripMs` is now
  `0ms`) and improved wallet-iframe SDK p50 by about `41ms` to `43ms` versus
  `20260609-174752Z`. Host-origin p50 stayed essentially flat because it was
  already dominated by WebAuthn credential creation. The direct path is retained
  as a small, low-risk refactor-61 win.
- A more aggressive `10ms` wallet-iframe auto-confirm polling experiment was
  rejected because it made the registration benchmark unstable. Keep the stable
  `50ms` benchmark helper floor unless a future event-driven auto-confirm
  helper replaces polling.
- Smoke run `20260609-181959Z` added benchmark-only wallet-iframe auto-confirm
  diagnostics. The iframe was attached almost immediately (`2ms` p50), while
  the confirm button was first observed at roughly `679ms` to `688ms` p50 and
  the successful click was dispatched at roughly `871ms` to `899ms` p50. This
  showed that browser-observed wallet-iframe timing still included benchmark
  confirmation automation delay.
- Smoke run `20260609-182306Z` kept the stable `50ms` locator timeout but
  removed the extra benchmark retry sleep and stopped the helper after the first
  successful click. It passed all four smoke scenarios and is retained as
  benchmark harness hygiene: wallet-iframe browser p50 improved by `116ms` to
  `147ms` versus `20260609-180125Z`, while SDK p50 changed by only `12ms` to
  `40ms`. The remaining wallet-iframe auto-confirm p50 is button visible at
  `639ms` to `645ms`, click dispatch at `843ms` to `849ms`, and click duration
  at `35ms` to `41ms`.
- Smoke run `20260609-032110Z` passed all four passkey scenarios and synced
  `docs/benchmarks/registration-flow.md`.
- `/wallets/register/start` is now out of the HSS prepare business for prepared
  Ed25519 modes: p50 was `6ms` to `7ms` in wallet-iframe scenarios and
  single-digit in host-origin scenarios.
- `walletRegisterPrepareWaitMs` was `0ms` p50 and p95 in every smoke scenario,
  so server HSS prepare is fully hidden under the measured passkey proof
  window.
- `registrationWarmupWaitMs` was also `0ms` p50 and p95 in every smoke
  scenario. The current warmup is useful as coverage and instrumentation, but
  it is not the limiting registration bucket in this smoke path.
- Current retained SDK p50 from smoke run `20260610-135445Z` is `1663ms`
  wallet-iframe Ed25519-only, `1703ms` wallet-iframe combined, `1299ms`
  host-origin Ed25519-only, and `1359ms` host-origin combined. Browser-observed
  p50 is `2304ms`, `2559ms`, `1690ms`, and `1724ms` respectively. Host-origin
  remains under the `1500ms` SDK target; wallet iframe remains about `160ms` to
  `200ms` above target in full SDK timing.
- Wallet-iframe Ed25519-only p50 is now dominated by passkey confirmation
  timing and HSS artifact construction: `authProofMs` `831ms`,
  `passkeyAuthPromptDecisionWaitMs` `634ms`,
  `passkeyAuthCredentialCreateMs` `202ms`, and
  `ed25519EvaluationArtifactMs` `471ms`. Server-side prepare is hidden
  (`walletRegisterPrepareWaitMs` `0ms`), finalize is much smaller
  (`walletRegisterFinalizeMs` about `53ms`), and transport is secondary
  (`20260610-130323Z` wallet-iframe connect p50 `99ms` / `115ms`).
- Product-side wallet-iframe prompt readiness is not the bottleneck: the
  confirmation host reaches first update and interactive state in about `1ms`
  p50 after prompt start, while the measured iframe prompt decision wait is
  about `634ms` to `642ms` p50 in the benchmark auto-confirm path. The derived
  smoke buckets show post-prompt SDK p50 at `1028ms` / `1060ms` in wallet iframe
  scenarios and post-prompt auth proof p50 at `203ms` in both wallet iframe
  scenarios. The remaining full-SDK wallet-iframe gap is therefore mainly a
  registration confirmation UX/security decision, with HSS artifact work still
  useful for margin.

## Next Optimization Steps

1. [x] Add benchmark-side wallet-iframe confirmation observability for iframe
       attachment, frame resolution, visible-button readiness, click dispatch,
       click duration, attempts, and helper total time.
2. [x] Tighten benchmark auto-confirm without aggressive polling. The retained
       helper still uses a stable `50ms` locator timeout, but avoids an extra retry
       sleep and stops after the first successful click.
3. [x] Add product-side wallet-iframe UI readiness timing for host-message handoff,
       first rendered/interactive state, confirm-event arrival, and WebAuthn-start
       time. Smoke run `20260610-024516Z` shows host first-update and interactive
       p50 at about `1ms`, so Lit rendering and prompt host attachment are not the
       current p50 bottleneck.
4. [x] Resume refactor-64 HSS artifact work. The retained `CoreBitWordSide`
       round-sigma and message-schedule small-sigma slices moved
       `ed25519EvaluationArtifactMs` to `450ms` to `457ms` p50 in smoke run
       `20260610-033610Z`.
5. [x] Revisit `/wallets/register/finalize` after the next HSS artifact pass.
       Smoke run `20260610-035655Z` keeps the seed-output prepared-session cache
       path: `walletRegisterFinalizeMs` p50 dropped from roughly `211ms` to `215ms`
       down to `51ms` to `55ms`.
6. [x] Continue the registration route-local pass into `/wallets/register/hss/respond`.
       Smoke run `20260610-041350Z` keeps the one-pass server-input delivery
       patch: route `registrationHssRespondMs` p50 moved
       `88/89/88/89ms -> 81/86/83/83ms`, and
       `registrationHssRespondPrepareDeliveryMs` moved
       `70/70/69/69ms -> 64/66/64/64ms`.
7. [x] Continue the respond-route pass with prepared OT branch caching. Smoke
       run `20260610-043955Z` keeps the patch: route
       `registrationHssRespondMs` p50 moved `81/86/83/83ms -> 77/79/77/77ms`,
       `registrationHssRespondPrepareDeliveryMs` moved
       `64/66/64/64ms -> 58/58/57/57ms`, and
       `registrationHssRespondDeliveryOtOpenJoinMs` moved from `55ms` to
       `58ms` down to `49ms`.
8. [x] Keep account reservation pending until account availability or route
       contention appears in benchmarks; it is not currently in the p50
       bottleneck order.
9. [x] Re-rank after Phase 7I HSS artifact work and route-local finalize/respond
       passes. Current retained smoke `20260610-135445Z` puts host-origin under
       target and leaves wallet iframe slightly above target.
10. [x] Add derived benchmark buckets for
        `sdkMinusPasskeyPromptDecisionWaitMs` and
        `authProofMinusPasskeyPromptDecisionWaitMs` so benchmark reports split
        post-confirm runtime from passkey prompt decision wait.
11. [x] Run the registration-flow smoke again and sync
        `docs/benchmarks/registration-flow.md` so the derived buckets are
        captured in the saved report. Smoke `20260610-135445Z` passed all four
        scenarios.
12. [x] Use the derived buckets to decide whether the remaining wallet-iframe
        gap is product/runtime work or a registration confirmation UX decision.
        The full-SDK wallet-iframe gap is mostly prompt decision wait; a UX
        change needs a short security spec before implementation because it
        changes when registration authority is granted.
13. [x] Decide the next product optimization lane. Do not weaken the
        wallet-iframe `modal + requireClick` clamp by honoring `skipClick`;
        instead specify a pre-mounted wallet-owned activation surface so the
        user's first registration click can land inside the iframe.
14. [x] Implement a wallet-iframe registration activation surface prototype
        behind the normal wallet iframe runtime boundary. The prototype should
        render a wallet-owned button before registration starts, then call
        registration from inside the iframe on that click. Source validation and
        the one-run benchmark probe passed on `20260610-175332Z`.
15. [x] Benchmark the activation-surface prototype against the current modal
        confirmation path. Keep it only if wallet-iframe full SDK p50 moves
        materially while `authProofMinusPasskeyPromptDecisionWaitMs` stays near
        the current `203ms` WebAuthn floor. Run `20260610-175514Z` keeps the
        prototype: Ed25519-only wallet iframe SDK p50 moved `1600ms -> 1170ms`
        and `passkeyAuthPromptDecisionWaitMs` moved `616ms -> 0ms`.
16. [x] Decide whether to continue UX activation work or return to refactor-64
        protocol-kernel work after the prototype benchmark. Keep the activation
        surface and harden it with targeted lifecycle tests, then return to
        refactor-64 for HSS artifact/runtime work.

### Phase 7: Wallet-Iframe Registration Activation Surface

Goal:

- remove the second-click latency in wallet-iframe registration without moving
  WebAuthn authority back to the parent origin.

Current behavior:

- Host-origin registration can honor `uiMode: 'none'` / `behavior: 'skipClick'`
  in benchmark mode, so the passkey operation starts immediately and p50 auth is
  about `202ms`.
- Wallet-iframe registration is intentionally clamped by
  `determineConfirmationConfig` to `modal + requireClick` for
  `REGISTER_ACCOUNT` and `LINK_DEVICE`. This keeps the WebAuthn activation
  inside the wallet iframe. Request-level `skipClick` does not bypass the clamp.
- Smoke `20260610-135445Z` shows the clamp cost in the benchmark:
  wallet-iframe `passkeyAuthPromptDecisionWaitMs` is `634ms` / `642ms`, while
  `authProofMinusPasskeyPromptDecisionWaitMs` is `203ms` in both wallet-iframe
  scenarios.

Proposed architecture:

- Add a wallet-owned registration activation component that can be mounted
  before the app starts the registration RPC.
- The visible CTA belongs to the wallet iframe. The user's click happens inside
  the iframe and directly starts the registration authority flow.
- The parent app supplies the registration intent parameters and receives
  progress/results over the existing wallet-iframe message boundary.
- The fallback remains the current modal confirmation path for callers that use
  the existing imperative `registerPasskey` API.

Current prototype status:

- Public API shape, wallet-iframe messages, host routing, and result delivery
  are implemented for `createPasskeyRegistrationActivationSurface`.
- Normal `registerPasskey` in wallet-iframe mode still strips caller-supplied
  activation proofs and keeps the `modal + requireClick` clamp.
- The activation path creates the proof only inside the iframe click handler and
  forces `uiMode: 'none'`, `behavior: 'skipClick'`, and `autoProceedDelay: 0`
  after caller config is merged.
- One-run probe `20260610-175332Z` for
  `passkey_ed25519_only_wallet_iframe_activation` passed with SDK `1357ms`,
  `passkeyAuthPromptDecisionWaitMs` `0ms`, and
  `authProofMinusPasskeyPromptDecisionWaitMs` `207ms`. Browser duration was
  `1937ms` because the benchmark auto-click helper first saw the activation
  button at `540ms`.
- Five-run comparison `20260610-175514Z` keeps the prototype:
  `passkey_ed25519_only_wallet_iframe` SDK p50/p95 `1600ms / 1629ms`,
  browser p50/p95 `2434ms / 2781ms`, prompt decision wait p50/p95
  `616ms / 652ms`; activation SDK p50/p95 `1170ms / 1381ms`, browser p50/p95
  `1411ms / 2209ms`, prompt decision wait p50/p95 `0ms / 0ms`, and
  `authProofMinusPasskeyPromptDecisionWaitMs` stayed at `203ms / 205ms`.
- Five-run ECDSA comparison `20260610-180121Z` keeps the same conclusion:
  `passkey_ed25519_and_ecdsa_wallet_iframe` SDK p50/p95 `1615ms / 1684ms`,
  browser p50/p95 `2431ms / 2575ms`, prompt decision wait p50/p95
  `599ms / 658ms`; activation SDK p50/p95 `1173ms / 1403ms`, browser p50/p95
  `1452ms / 1944ms`, prompt decision wait p50/p95 `0ms / 0ms`, and
  `authProofMinusPasskeyPromptDecisionWaitMs` stayed at `204ms / 205ms`.
- June 11 focused revalidation passed:
  `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  ./unit/walletIframeHost.registrationActivation.unit.test.ts
  ./unit/confirmTxFlow.determineConfirmationConfig.test.ts --reporter=line`
  completed `11` tests. This covers forged activation proof stripping,
  duplicate clicks, cancellation, expiry, iframe registration/link skip-click
  clamping, and the activation-proof skip path.

Security constraints:

- Do not treat parent-origin clicks as wallet-origin activation.
- Do not honor `skipClick` for wallet-iframe registration/link flows.
- Bind the activation click to the activation id and intended account id inside
  the wallet iframe. Once the click starts normal registration, keep wallet id,
  rp id, signer selection, and registration intent digest binding in the
  prepared-registration lifecycle.
- Expire prepared activation state quickly and make repeated clicks idempotent.
- Keep the WebAuthn credential creation and PRF collection inside the wallet
  iframe runtime.

Todo:

- [x] Confirm the current latency gap is prompt decision wait, not WebAuthn,
      HSS, or iframe transport.
- [x] Add a regression test proving wallet-iframe registration/link request-level
      `skipClick` overrides are clamped to `modal + requireClick`.
- [x] Define the activation-surface public SDK API shape.
- [x] Define the wallet-iframe messages for pre-mounted activation, start,
      cancel, expiry, and result delivery.
- [x] Prototype the wallet-owned activation button using wallet iframe theme
      variables and an explicit activation-start selector.
- [x] Add unit tests for activation lifecycle, forged-proof stripping, expiry,
      duplicate click behavior, and fallback to the existing modal path.
- [x] Add benchmark scenarios for the activation-surface path.
- [x] Run a multi-run activation benchmark against the current modal baseline
      and record the keep/drop decision.
- [x] Add lifecycle tests for activation expiry, duplicate clicks, cancellation,
      and fallback to the existing modal path.
- [x] Run the Ed25519+ECDSA activation benchmark variant and compare whether the
      same prompt-wait reduction holds when ECDSA provisioning is enabled.

Public SDK shape:

```ts
type RegistrationActivationSurfaceState =
  | { kind: 'idle' }
  | { kind: 'ready'; activationId: string; expiresAtMs: number }
  | { kind: 'starting'; activationId: string }
  | { kind: 'completed'; activationId: string; result: RegistrationResult }
  | { kind: 'cancelled'; activationId: string; reason: 'user_cancelled' | 'expired' | 'disposed' }
  | { kind: 'failed'; activationId: string; error: string };

type WalletIframeRegistrationActivationSurface = {
  kind: 'wallet_iframe_registration_activation_surface_v1';
  mount(target: HTMLElement): void;
  dispose(): void;
  state(): RegistrationActivationSurfaceState;
  onStateChange(listener: (state: RegistrationActivationSurfaceState) => void): () => void;
};

type CreatePasskeyRegistrationActivationSurfaceArgs = {
  options?: RegistrationHooksOptions;
  presentation: RegistrationActivationButtonPresentation;
};
```

Candidate API entrypoint:

```ts
const surface = seams.registration.createPasskeyRegistrationActivationSurface({
  options,
  presentation,
});
surface.mount(buttonContainer);
```

Notes:

- The app controls placement, but the rendered button and click handler live
  inside the wallet iframe.
- The existing `registerPasskey(options)` API remains the fallback imperative
  path and keeps the current modal confirmation behavior.
- Invalid states should be unrepresentable with a discriminated state union; no
  optional identity/session fields in the activation start path.

Wallet-iframe message lifecycle:

```ts
type WalletIframeRegistrationActivationRequest =
  | {
      type: 'PM_REGISTRATION_ACTIVATION_PREPARE';
      activationId: string;
      options: SerializableRegistrationHooksOptions;
      presentation: RegistrationActivationButtonPresentation;
      expiresAtMs: number;
    }
  | {
      type: 'PM_REGISTRATION_ACTIVATION_CANCEL';
      activationId: string;
      reason: 'user_cancelled' | 'expired' | 'disposed';
    };

type WalletIframeRegistrationActivationEvent =
  | {
      type: 'PM_REGISTRATION_ACTIVATION_READY';
      activationId: string;
      expiresAtMs: number;
    }
  | {
      type: 'PM_REGISTRATION_ACTIVATION_STARTED';
      activationId: string;
    };
```

Message rules:

- `activationId` is generated by the parent and echoed by the wallet iframe for
  every state transition.
- The iframe owns the visible activation button. The registration call starts
  only from the iframe click handler for `PM_REGISTRATION_ACTIVATION_PREPARE`.
- `options` must be serialized through the same function-stripping boundary as
  current wallet-iframe `registerPasskey`; parent callbacks remain bridged via
  progress events.
- `PM_REGISTRATION_ACTIVATION_CANCEL` is best-effort and idempotent. The iframe
  must reject starts after expiry or cancellation.
- The fallback imperative path must not consume activation state.
- Result and error delivery use the existing wallet-iframe `PM_RESULT` / `ERROR`
  response envelope for the `PM_REGISTRATION_ACTIVATION_PREPARE` request.

## Acceptance Criteria

- `/wallets/register/start` no longer runs fresh Ed25519 HSS prepare for
  prepared signer modes.
- Start requests require a `registrationPreparationId` for prepared signer
  modes.
- Prepared registration records cannot be reused across wallet id, rp id,
  digest, signing root, signer selection, expected origin, participant ids, or
  auth method kind.
- Registration intent consumption still happens only after authority proof
  verification.
- Prepared records expire and cannot create wallets, sessions, keys, or NEAR
  accounts by themselves.
- Client lifecycle state makes invalid proof/preparation combinations
  unrepresentable.
- Benchmarks show the post-proof path and full registration timing before the
  change is kept.

## Validation

Cheapest useful checks for this refactor:

- `pnpm -C sdk type-check`
- focused type fixtures for registration lifecycle and relayer RPC contracts
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/registrationIntentAllocation.unit.test.ts ./unit/relayWalletRegistration.boundary.unit.test.ts --reporter=line`
- `pnpm benchmark:registration-flow:smoke` for keep decisions
- `git diff --check`

Run broader source guards only after the route/store shape lands, because this
touches public registration contracts, persistence boundaries, and auth-adjacent
flow state.
