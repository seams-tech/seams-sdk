# Refactor 94C — Product Lane Wave 0: Contract Draft And Deletion Inventory

Date: July 28, 2026
Lane: `claude/refactor-94c-product-path` (based on `35aa9fe7c`; rebases onto the
split commit at the contract checkpoint).
Status: Wave 0 deliverable — input to the contract checkpoint. Not implementation.

## 1. Current product-flow map (what the three routes replace)

Every leg below is measured; server totals are the co-location-corrected
staging expectation in parentheses where known.

| Leg | Route | What it does today | Persistence today |
| --- | --- | --- | --- |
| Grant | `POST /v1/registration/bootstrap-grants` | API-key auth, env/project reads, 2 quota COUNTs, mint stored grant token | ~6 serial Console D1 ops |
| Intent | `POST /wallets/register/intent` | verify+consume grant, wallet check, **reservation write**, intent store | 3+ Signer D1 ops |
| Start | `POST /wallets/register/start` | journal pre-read (dup, `6759f9c21`), intent read, ceremony insert, ECDSA prepare + Yao admission via Router, resumable side-effect journal | 4+ D1 ops + Router |
| Respond | `POST /wallets/register/derivation/respond` | D1 claim → Router register leg (A/B concurrent) → D1 terminal CAS | 2 D1 ops + Router |
| Activate | `POST /wallets/register/derivation/activate` | D1 claim → Router activate (SigningWorker) → session/budget DO provision → D1 CAS → policy lookup → JWT mint | 2 D1 ops + Router + 2 DOs |
| Finalize | `POST /wallets/register/finalize` | outer side-effect journal, inner replay load, ceremony load, kind-scoped persistence, email enrollment plan, replay-cache write, ceremony CAS/delete | 6+ D1 ops |
| Deferred NEAR | second `finalize` (`kind: 'near_ed25519'`) | Yao consume + Ed25519 signer persistence; async since lazy-Yao 4+5 | own idempotency domain |
| Client tail | React context | 2 serial iframe refreshes after return | none |

Client orchestration lives in
`packages/wallet/src/SeamsWeb/operations/registration/registration.ts`
(single serial chain; only Email OTP enrollment material overlaps start).

## 2. Proposed public contract (checkpoint input)

Names follow the existing `WalletRegistration*` convention. All three are
kind-discriminated on the existing auth branches (`passkey` / `email_otp`)
and reuse existing payload types unchanged wherever named below.

### Route 1 — `POST /wallets/register/setup`

```ts
type WalletRegistrationSetupRequest = {
  // existing app auth: publishable key / project environment (managed mode)
  wallet: RegisterWalletInput;                       // provided | server_allocated
  signerSelection: RegistrationSignerSetSelection;    // unchanged
  authMethod: RegistrationAuthMethodDescriptor;       // kind + rpId | email binding, no proof yet
};

type WalletRegistrationSetupResponse =
  | { ok: true;
      registrationCeremonyId: string;
      walletId: WalletId;                             // generated name, UNIQUE-arbitrated at insert
      signedSetup: SignedSetupPayloadB64u;            // opaque; client-carried, echoed on routes 2-3
      ecdsa: WalletRegistrationEcdsaPreparePayload;   // unchanged
      ed25519?: { admissionRequest; admissionReceipt } // unchanged Yao types; mixed plans only
    }
  | WalletRegistrationRouteError;
```

Signed payload claims (server-internal shape, Codex owns encoding): operation
id, environment, request fingerprint, `iat`/`exp`, policy+key version, wallet
candidate, auth challenge binding, signer plan digest. The client never parses
it — the public width is exactly one opaque string. **Policy never crosses the
public wire**: the Gateway mints an internal Router-policy JWT per concrete
Router call, so the client cannot replay a policy token across operations and
the Router still performs zero policy/JWKS lookups.

### Route 2 — `POST /wallets/register/respond`

```ts
type WalletRegistrationRespondRequest = {
  registrationCeremonyId: string;
  signedSetup: SignedSetupPayloadB64u;
  authority: WalletRegistrationStartAuthority;        // existing passkey/email_otp proof union, unchanged
  ecdsa: { kind: 'router_ab_ecdsa_registration_v1';
           strictRegistration: RouterAbEcdsaRegistrationRequestV1 }; // unchanged
};

type WalletRegistrationRespondResponse =
  | { ok: true; ecdsa: RouterAbEcdsaStrictForwardedRegistrationResponseV1 } // exact A/B bundles, unchanged
  | WalletRegistrationRouteError;
```

Gateway bookkeeping: none once the role-retry test passes (plan §2); until
then the existing claim/terminal pair stays behind the same wire shape, so the
contract does not change when the bookkeeping is removed.

### Route 3 — `POST /wallets/register/activate`

```ts
type WalletRegistrationActivateRequest = {
  registrationCeremonyId: string;
  signedSetup: SignedSetupPayloadB64u;
  idempotencyKey: RegistrationFinalizeIdempotencyKey;  // existing brand; operation-row key
  ecdsa: { clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;   // unchanged
           expectedKeyHandles: string[] };
  emailOtpEnrollment?: WalletRegistrationEmailOtpEnrollmentMaterial;  // blocking, per plan
  emailOtpBackupAck?: WalletRegistrationEmailOtpBackupAck;
};

type WalletRegistrationActivateResponse =
  | { ok: true; kind: 'evm_family_ecdsa';
      walletId; authority; authMethod;
      ecdsa: { walletKeys; session; bootstrap };       // current finalize + activation session merged
      nearProvisioning?: { status: 'pending' } }        // mixed plans; snapshot only
  | WalletRegistrationRouteError;
```

The terminal response bytes ARE the replay record (one operation row). Exact
retry with the same `idempotencyKey` + fingerprint returns them byte-identical;
conflicting fingerprint returns the existing typed conflict.

### Deferred NEAR (non-blocking; not one of the three)

Keeps the existing deferred call shape (`kind: 'near_ed25519'`, own
idempotency key, activation reference) renamed off the deleted finalize route:
`POST /wallets/register/near-provisioning`. Persists Yao consume + signer
material only — no RPC, no chain state, per the effect ledger.

**Checkpoint decisions (approved 2026-07-28; contract frozen):**
1. **Fingerprint**: the existing typed domain encoder with a `PublicDigest32`
   request digest over canonical encoded request bytes — never raw JSON or
   property-order-dependent serialization. **Each route computes its own
   canonical `PublicDigest32`** (setup, respond, and activate digests are
   separate values over that route's canonical bytes); the signed payloads and
   idempotency rows bind the digest of the route they protect, so a payload
   for one route can never satisfy another.
2. **Signed payloads**: compact Ed25519 JWS/JWT strings, opaque to the client.
   Claims: issuer, audience, subject, environment, expiry, work kind, policy
   version, canonical request digest. Unknown algorithms rejected; verification
   is local against the pinned deployment key. No JWKS fetch anywhere.
3. **Activate response**: the exact terminal activation/finalization response
   bytes; the operation row is the replay record. Router validates role
   receipts internally — no readiness receipt crosses the public wire.
4. **Wallet-session JWT**: Gateway is the sole minting authority. Router and
   roles verify locally with pinned key material and never mint.

Boundary decisions folded in: `respond` stays deterministic-or-refused at the
role layer with a stable public wire shape while the Gateway bookkeeping
deletion is validated; policy travels only in the Gateway-minted internal
Router-policy JWT attached per concrete Router call (Router does no
policy/quota/abuse/JWKS lookup, and no policy token is client-visible);
registration creates an implicit-account keypair only; no compatibility route,
legacy field, or dual-write path. Existing wallets require no migration:
destructive testnet cutover is authorized, so retired records are dropped, not
converted.

## 3. Deletion inventory (TypeScript, product lane)

### Routes and services deleted

- Bootstrap-grant route + `bootstrapGrantBroker` storage path
  (`packages/console-server-ts/src/router/bootstrapGrantBroker.ts` stored
  tokens; auth+quota decision moves inline into setup).
- Intent route + `d1RegistrationIntentService` reservation machinery and the
  unconsumed-reservation cancellation job
  (`cancelUnconsumedRegistrationIntentWalletReservations` — observed in
  `cloudflareD1RouterApiRegistrationCeremony.unit.test.ts:699`).
- Start route (`handleRouterApiWalletRegistrationStart` + service method) —
  absorbed into setup; duplicate journal pre-read dies with it.
- Standalone finalize route + outer journal
  (`runRouterAbEd25519YaoRegistrationSideEffectV1` wrapping for registration)
  + inner replay pair (`getFinalizeReplay`/`putFinalizeReplay`) + replay-cache
  write; replaced by the activate operation row.
- Session/budget DO provisioning calls in activate
  (`ecdsaActivateSessionProvision`) — replaced by Codex's SigningWorker D1
  batch behind the frozen internal interface.

### Client (sdk-web)

- `walletRegistration.ts` RPC builders/parsers for grant, intent, start,
  finalize (ECDSA kind); new builders for the three routes.
- `registration.ts`: the five-leg orchestration collapses to
  setup → auth → respond → verify → activate; enrollment-material overlap
  retargets setup; `finalizeEcdsaOrMixedRegistration` and
  `registrationEcdsaExpectedKeyHandles` fold into the activate call;
  deferred-NEAR commit #2 retargets the renamed route.
- React context: the two serial refreshes become hydrate-from-response +
  one background refresh (`useSeamsContextValue.ts:11`).
- New client work (this lane): ECDSA wasm init during the auth prompt
  (extends the existing `registrationWarmup*` hook family), typed
  passkey-seal pending state (seal off the blocking path).

### Tests and fixtures

Delete or rewrite (classification per `tests/AGENTS.md`; fixtures encoding
the retired shape are deleted, not preserved):

- `cloudflareD1RouterApiRegistrationCeremony.unit.test.ts` — start/finalize
  sections rewritten against setup/activate; reservation-cancellation test
  deleted with the job.
- `d1WalletRegistrationFinalizeConvergence.unit.test.ts` + fixtures — the
  convergence properties move to the activate operation row; the fixture
  harness retargets (`createFinalizeConvergenceHarness` becomes the activate
  harness); sponsored-named cases keep the full ceremony and stay.
- `walletRegistrationYaoFinalizeContracts.domain.guard.unit.test.ts`,
  `walletRegistrationYaoClientContracts.unit.test.ts` — re-anchor to the new
  request parsers.
- `addWalletSigner.orchestration.unit.test.ts` — mocked route table
  (`/wallets/register/*`) rewritten to three routes; timing/dedup/deferred
  assertions carry over.
- `ecdsaRegistrationServerTiming.unit.test.ts`,
  `registrationTerminalCancellation.unit.test.ts` — carry over; anchors move.
- Typecheck fixtures: `registrationRequests.typecheck.ts`,
  `sdkPublicResults.typecheck.ts` — start/finalize unions replaced by the
  three-route unions; `tests/typecheck/*` referencing deleted wire kinds.
- Intended harness (`tests/e2e/intended-behaviours/harness.ts` + registration
  contracts) — route expectations updated in the same change as the wire
  flip (Wave 2, one coherent revision).
- Delete on sight: any fixture asserting the grant token, reservation row,
  start journal, or finalize replay-cache record — those records cease to
  exist.

### Explicitly kept

Two-leg verify boundary; deferred NEAR provisioning semantics and its tests
(lazy-Yao 4+5, Phase 6 lifecycle suite); `mergeRouterServerTiming` and the
whole timing apparatus (it is 94C's acceptance instrument); Email OTP
enrollment as a blocking part of activate; the sponsored-named path's full
ceremony (scoped there by the 94B effect ledger).
