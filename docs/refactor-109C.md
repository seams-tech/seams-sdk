# Refactor 109C — Add the Missing Wallet Auth Method

Date created: August 22, 2026

Status: implementation in progress. Depends on Refactor 103E.

R109C is the sole implementation authority for same-device auth-method
addition. Refactor 109D remains the separate device-linking plan.

## Live implementation ledger

Implementation branch `codex/refactor-109c`, based on `dev` at `ff395dfe1` and
merged with `dev` at `c3b96e235` (the three R103E cleanup commits). R103E's
closure edit was already committed on `dev` in `ff395dfe1`, so this branch adds
no separate documentation commit for it.

**R109C is not ready to merge.** Phase 0's same-authority sibling revocation
prerequisite is green, both public addition entry points exist, and the Phase 3
inventory/addition/removal UI is implemented. The remaining closure work is the
real two-transition browser matrix, explicit unlock and step-up selection proof,
interruption coverage, and Phase 4 deletion of obsolete fixtures and branches.

A checkpoint is marked done only when the named command was run and reported
green. Green lower-tier evidence does not close a product transition; only a
real browser flow does.

### Phase 0 — revocation prerequisite — MET

- [x] Exact method revocation between two siblings on ONE authority, proven in
      both directions, through the composed path —
      `tests/unit/r109cSiblingRevocation.unit.test.ts`, 4 passing. One authority
      holds a Passkey and an Email OTP method; each revokes the other through
      the D1-backed service, the sibling and its envelope survive, the revoked
      method cannot then take the last one, and no method revokes itself.
      Repairing it exposed a real fixture defect: the shared management factory
      stamped placeholder authority digests, which every server read rejects as
      corrupt. The factory now computes both canonical digests.
- [x] Authority-ID and self-proof revocation requests are rejected at the
      boundary — `linkedDeviceManagement.unit.test.ts` covers exactly this and
      passes on its own.

The unrelated add-signer fixtures in
`cloudflareD1RouterApiWalletAuthMethods.unit.test.ts` and the stale
`ed25519_yao_client_root_v1` parser assertion remain Phase 4 cleanup. They are
outside the completed sibling-revocation prerequisite.

### Phase 1 — shared contract and thin SDK entry points

- [x] Two-branch internal contract with branded identities, branch builders,
      admission, and negative type fixtures:
      `packages/shared-ts/src/utils/addWalletAuthMethod.ts` and its
      `.typecheck.ts`. Command: `npx tsc --noEmit` in `packages/shared-ts`,
      clean.

The plan named `tests/typecheck/` for the negative fixtures. That directory is
covered by no `tsconfig` in the repo, so nothing compiles it; the fixtures live
beside the contract in `packages/shared-ts/src/utils/`, which
`packages/wallet/tsconfig.json` does include and `pnpm type-check:sdk`
therefore enforces.

### Phase 3 — inventory, explicit selection, and removal — IN PROGRESS

- [x] Inventory projects every exact active method instead of truncating each
      authority to its first method. Owner entries carry `walletAuthorityId`;
      linked entries group by their stable linked-device identity.
- [x] The addition action is derived from active methods on the authority that
      contains the exact selected `walletAuthMethodId`. It offers only the
      missing family and disappears when both Passkey and Email OTP are active.
- [x] The Passkey-to-Email-OTP form renders the required security note and uses
      a labelled email input. The Email-OTP-to-Passkey branch uses the configured
      wallet RP ID.
- [x] Removal targets one exact `walletAuthMethodId`, requires a different
      selected sibling as its proof source, exposes both owner methods, and
      preserves the server's atomic final-method guard.
- [ ] Run both browser transitions, explicitly lock and unlock with each method,
      then prove step-up and Wallet Session issuance remain bound to the exact
      method selected by the user.

Checkpoint commands: `pnpm -C packages/wallet type-check` and scoped
`git diff --check`, both clean after `8924bf4ef` and `3c55658a8`.

### Architecture facts established before implementation

These were read directly and change the size of the remaining work. The plan's
"Current gap" section understates how much R103E already built.

- **The custody reseal is already factor-agnostic; no Rust or WASM change is
  needed.** `passkey_custody_open_wallet_seed_v1` in
  `wasm/near_signer/src/passkey_custody_wasm.rs:237` documents itself as "the
  second-factor enrolment path: a wallet with an Email OTP factor gains a
  passkey, or the reverse" — R109C's operation exactly — and
  `reseal_wallet_custody_seed_under_new_factor_v1` in
  `crates/signer-core/src/passkey_custody.rs:685` rejects only a changed wallet
  or binding, with the message "a reseal may change only the factor and the
  envelope id". The KEK and AAD are derived from the replacement factor and
  binding, so an `email_otp` replacement factor is already supported. The
  worker op is named `linkWalletCustodyPasskey`, but its payload takes an
  envelope whose factor is the full union plus an opaque replacement binding
  JSON; only the name is passkey-specific.
- **The D1 service already accepts an Email OTP source for a Passkey target.**
  `resolveAddAuthMethodExistingAuth` in
  `packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthMethodService.ts:1078`
  resolves the Email OTP authority, verifies its authority ref, and checks the
  enrollment; `resolveActiveAddAuthMethodSource` resolves the V2 method for
  that branch; and `startWalletAddAuthMethod` already handles
  `storedAuth.auth.kind === 'email_otp'` inside its Passkey-target branch. The
  refusal is one layer up: `parseWalletAddAuthMethodStartBody` admits only
  `webauthn_assertion` and `wallet_session`, and the `wallet_session` branch of
  `handleRouterApiWalletAddAuthMethodStart` requires
  `authority.factor?.kind === 'passkey'`. `email_otp_to_passkey` is therefore a
  route-boundary change, not a service rewrite.
- **The Email-OTP-owned Wallet Session already names its exact source method.**
  `EmailOtpWalletAuthAuthority.bindingId` is a `WalletAuthMethodId`
  (`packages/shared-ts/src/utils/walletAuthAuthority.ts:66`), so the route can
  supply the exact source method without inference.
- **One remaining wallet-wide Email selector sits in the addition path.** The
  add-auth-method start resolves its Email authority through
  `resolveActiveEmailOtpAuthorityForVerifiedSubject`, which requires exactly one
  active Email method for the wallet. That is the same shape as the three
  escaped defects R103E repaired. R109C must use the exact-method resolver
  `resolveActiveEmailOtpAuthorityForVerifiedMethod` that R103E already added.

### Inventory defects resolved during Phase 3

These defects were found while mapping Phase 3. Each was load-bearing for
deriving the available add action from exact active methods.

- **First-method truncation:** the management projection now emits one entry
  for every exact active method on owner and linked authorities.
- **Missing owner authority identity:** `OwnerDeviceSummaryV1` now carries
  `walletAuthorityId`, allowing the UI to scope the missing-family action to
  the authority containing the selected method.
- **Owner-method removal gate:** owner and linked cards now use the same exact
  `WalletAuthMethodId` revocation model. A different selected sibling supplies
  fresh proof, while the D1 final-method guard remains atomic.

An earlier reading said owner-method removal already worked because
`revokeDevice` handled owner cards. The UI and server gates prevented that path
from being reached; both are now removed.

### The unit suite cannot gate R109C

`npx playwright test -c playwright.unit.config.ts --list` from `tests/` reports
**26 collection errors** and collects zero tests. The failures are unresolvable
imports across unrelated files — missing fixture exports such as
`activeLinkedDeviceWalletSessionFixture`,
`selectWalletHostOwnerSourceLaneCandidatesV1`, and
`parseDerivedEmailOtpRecoveryKeyId`. This branch has touched exactly one file
under `tests/`, so the condition is pre-existing on `dev`.

Because one unresolvable import aborts collection for every file, `pnpm
test:unit` reports failure regardless of what R109C does, and a green unit
suite is not an available gate. Targeted single-file runs do work and are what
this ledger cites throughout.

Repairing the other 25 is a test-only project of its own and is deliberately
not attempted here: `AGENTS.md` forbids fixture-repair loops, and none of these
imports is R109C's to own. `tests/unit/emailOtpRegistrationRoute.unit.test.ts`
was repaired only because its two dead route imports were discovered while
verifying R109C's own Email OTP path.

### Demonstrated R103E defect: revocation never revokes the custody envelope

`revokePasskeyFactorAtomically`
(`packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/d1PasskeyCustodyEnvelopeStore.ts:428`)
documents itself as the revocation path for a factor's envelopes, carries the
last-active-envelope guard, and **has no callers anywhere in the repo**.
`revokeWalletAuthMethod` in the D1 auth-method service touches no envelope at
all. So revoking an auth method today revokes the method, its verifier, and its
sessions, and leaves the factor-sealed custody envelope active in D1.

R103E's own contract says revocation "invalidates that method, its verifier,
its sealed local records, and sessions issued through that method". The durable
server-side ciphertext that the revoked factor can still unwrap is not among
the things it invalidates, and `lookupEnvelopeForFactor` will still return it.

This is recorded rather than repaired. R109C's revocation requirement names
_local_ sealed records, so the gap is not on R109C's critical path, and silently
changing accepted revocation behaviour mid-implementation is the wrong way to
land a security-relevant fix. It needs its own decision and its own change set.
Note also that the function is passkey-typed, so whoever wires it up has to
generalize it the way `linkWalletCustodyFactorAtomically` was generalized.

### The authority digest has two different brands

`AddWalletAuthMethodSourceV1.authorityDigestB64u` is a `DigestB64u`. The active
Wallet Session projection's `authority.authorityDigest` is a
`WalletAuthorityBindingDigest` — a different value and a different brand. The
correct source is `WalletAuthorityV1.authorityDigestB64u`. The branding makes
the substitution a compile error, which is the point, but the two names are
close enough to be worth stating.

### Scope note: the entry-point plumbing is a surface change

Adding `registration.addEmailOtp` touches thirteen files in
`packages/wallet/src` — the public capability, the two facades, the iframe
client router, the message contract, the request router, the runtime context,
the host handler — because every one of them enumerates request kinds
explicitly. That is a planned Phase 1/2 surface change, not one localized
defect, so the "more than five files" stop condition does not apply to it.

### First failing acceptance boundary

`tests/unit/cloudflareD1RouterApiWalletAuthMethods.unit.test.ts:373`
("adds Email OTP wallet auth methods through partitioned D1"), at
`expect(intent.ok).toBe(true)` — `createAddAuthMethodIntent` now refuses a
command with no caller branch.

This is the R109C addition path's own test and it is `valid_test_needs_update`:
the protocol changed on purpose, so the test must mint its intent with
`caller: 'same_device_addition'` and a source claim. It cannot be repaired by
adding those fields alone — the test builds no source authority or method to
claim, which is also why it was already red on `dev` with `Passkey wallet
authority is not active for this wallet` before any R109C change. Repairing it
means giving it a real founding authority through the shared factory.

The three other failures in that file are unchanged and unrelated: a stale
WebAuthn assertion fixture, a missing custody envelope in setup, and the same
missing authority.

### Acceptance stack: port preflight

The acceptance origins — `9443` (site), `9444` (router/console), `9447` (docs)
and `8443` (wallet iframe) via one Caddy process, plus `3600` (vite) — are held
only by the main worktree at `/Users/pta/Dev/rust/seams-sdk`. A second worktree,
`/private/tmp/seams-sdk-r100`, runs many `workerd` processes, but every one of
them binds `--socket-addr=entry=127.0.0.1:0`, so none contends for those ports.

The stack is therefore free to take when there is a flow to run. It is not
taken yet: taking it means rebuilding the SDK dist the running stack serves, and
there is nothing to exercise until the client operation and its intended-e2e
action exist. Doing it earlier would disrupt the serving tree for no evidence.

### Method-bound custody envelopes — the five behaviours

Landed. An envelope now records the one auth method that owns it, and that
ownership is inside the AAD, so it cannot be relabelled. `Unbound` decodes
pre-109C envelopes and is never written.

| Behaviour                                                           | Where it is proven                                       |
| ------------------------------------------------------------------- | -------------------------------------------------------- |
| V2 opens under its original AAD and is resealed as V3               | `an_unbound_envelope_opens_then_reseals_as_method_bound` |
| A sibling cannot open or relabel a V3 envelope                      | `a_sibling_method_cannot_open_a_relabelled_envelope`     |
| Revoking one method preserves the sibling and the shared enrollment | `r109cEmailEnrollmentReferences.unit.test.ts`            |
| Revoking the final method removes the enrollment                    | same file                                                |
| No path writes a new V2 envelope                                    | `sealing_an_unbound_envelope_is_refused`                 |

Commands: `cargo test --lib --features passkey-custody` in `crates/signer-core`
(6 passed) and `npx playwright test -c playwright.unit.config.ts
./unit/r109cEmailEnrollmentReferences.unit.test.ts` from `tests/` (2 passed).

Two facts worth keeping. Behaviour 5 was genuinely absent until its test asked
for it — `seal_custody_secret` sealed an unbound binding happily, so nothing
stopped a fresh V2 being minted. And fixing it broke behaviour 1's own setup,
which had been sealing a V2 to have one to open; the fixture now seals through
a test-only legacy helper, because production can no longer produce one.

The upgrade runs on the unlock that opens the envelope, which is the only place
holding the factor secret and the exact selected method at the same instant. A
failed persist costs a retry rather than access: the old row stands and the next
unlock produces the upgrade again.

### Stop condition: authenticating envelope ownership is a Rust change

Binding `walletAuthMethodId` into the AAD cannot be done in TypeScript. The AAD
is built by `encode_passkey_custody_aad_v1`
(`crates/signer-core/src/passkey_custody.rs:383`) from
`PasskeyCustodyEnvelopeBindingV1` (`:247`), whose fields are `wallet_id`,
`envelope_id`, `factor`, `envelope_revision`, and `binding`. TypeScript's
`custodyEnvelopeBindingJson` only serialises those; adding a field there changes
nothing unless the Rust struct and encoder change too.

So making ownership authenticated requires: a new field on that struct, a
`labeled_str` in the encoder, an envelope version bump so already-sealed
envelopes still verify, regenerated `wasm/wallet_custody_ceremony` wire
fixtures, and a wasm rebuild. That is the plan's declared stop condition —
"changing Rust/WASM cryptography beyond the existing reseal capability" — and
it is reported rather than performed.

The version bump is not optional. Every deployed envelope was sealed under the
current AAD; adding a labelled field without discriminating on version makes
all of them fail `aad_hash` verification, which is indistinguishable from
custody loss.

An earlier note in this ledger claimed the parser "drops unknown fields", so a
top-level record field would be free. That was wrong:
`parsePasskeyCustodyEnvelopeRecord` calls
`rejectUnknownFields(record, ENVELOPE_RECORD_FIELDS, label)`
(`custodyEnvelope.ts:322`), so the field must be added to the type, the
builder, the allowed-field list, the parser, and all four construction sites.

### The four construction sites need the id threaded, not just added

None of the four has an auth-method id in scope today:
`walletCustodyRegistrationCommit.ts:136`, `passkeyLink.ts:177`,
`email-otp.worker.ts:4075`, `deviceLinkingEd25519ExportRoot.ts:276`. Each needs
it passed from its caller, and one of them crosses the Email OTP worker payload
boundary whose strict unknown-field allow-list produced R103E's silent 60-second
export hang when a field was added without updating it. That plumbing is the
next unit of work and was not begun.

### Email custody: the model, and why the earlier reading was wrong

An earlier revision of this ledger said an Email method's envelope "cannot be
revoked" because `email_otp_wallet_enrollments` holds one row per wallet, so
siblings would share an envelope. The shared enrollment is real and
intentional — R109D requires active and pending methods to keep referencing it
— but the conclusion did not follow. Three concepts were collapsed into one:

- **the custody envelope and local signer state are per method.** An envelope
  row is already keyed by its own `envelopeId`; only _lookup by factor_ is
  shared, because `WalletCustodyFactorRef` for Email is
  `(enrollmentId, enrollmentSealKeyVersion)`. The record can carry the auth
  method that owns it, and doing so changes no ciphertext: the AAD is derived
  from `binding` and `factor` alone (`custodyEnvelopeBindingJson`), so a
  top-level `walletAuthMethodId` sits outside it.
- **the provider enrollment is shared and stays shared.** Revoking one Email
  method deletes that method's exact local custody records and leaves the
  enrollment alone.
- **the shared enrollment is deleted only when its last reference goes.** No
  active or pending method may still reference it.

So the binding is a narrow `0013` extension plus one required field on
`PasskeyCustodyEnvelopeRecord`, not a new enrollment path and not a new table.
There are exactly four construction sites
(`walletCustodyRegistrationCommit.ts:136`, `email-otp.worker.ts:4075`,
`passkeyLink.ts:177`, `deviceLinkingEd25519ExportRoot.ts:276`), and each already
knows its method — `passkeyLink` now has it from the intent, which the protocol
change made possible.

Not yet implemented. The revocation path currently contributes envelope
statements for the Passkey branch only, which is why this is still open.

### Open P1: the source-proof protocol does not yet meet the spec

This is the largest correctness gap and nothing on this branch has closed it.
R109C requires a fresh source assertion bound to the wallet, authority, source
method, source session, target method ID, operation purpose, authority state,
and intent digest. What exists binds far less:

- `AddAuthMethodIntentV1` carries only wallet, target description, policy
  scope, and nonce, so the digest a proof signs cannot name the authority, the
  source method, the source session, or the target method.
- The target `WalletAuthMethodId` is allocated _after_ the source is
  authenticated, so no source proof can be bound to it. Binding it requires
  allocating the target id in the intent rather than in start.
- The route still admits `auth.kind: 'wallet_session'` — a reusable bearer
  credential — in place of a fresh assertion.

The last one is not simply a bug. That branch is R103E's deliberate zero-prompt
handoff for the _linked-device_ ceremony start, where Device 1 holds owner
authority and Device 2 holds the PRF, and the two paths share one endpoint. So
R109C cannot just delete it; the endpoint has to distinguish a same-device
addition from a linked-device ceremony start, and today nothing in the request
does.

A related symptom is not a separate defect: that branch resolves an Ed25519
owner session only, which an ECDSA-only wallet never has. Making it curve-
agnostic does not work — the ECDSA binding has no `authority` field at all, so
it cannot name a source method. An attempt to widen it was reverted for that
reason. The real answer is that an R109C addition must present a fresh proof,
which is curve-independent, and then the ECDSA-only cell needs nothing special.

Consequence for the shared contract: production currently consumes only
`admitAddWalletAuthMethod` from `addWalletAuthMethod.ts`. Nothing builds
`VerifiedAddWalletAuthMethodInputV1`, so the branded two-branch input is not
yet load-bearing. It becomes load-bearing exactly when this protocol is fixed —
the builders are what force the proof, the target, and the identities to agree.

### Reversed: the `0013` provider-identity migration is in scope

An earlier revision of this ledger deferred
`0013_r109c_multi_auth_email_cardinality.sql`, arguing it was really R109D's
because R109D's document specifies it. That reading was wrong in both
directions.

`docs/refactor-109D-multi-auth-linking.md` assigns ownership explicitly —
"R109C owns multi-method inventory, same-device factor addition, Email OTP
cardinality, and verification of the R103E revocation prerequisite" — and its
Phase 0 refuses to start until "the R109C schema change becomes
`0013_r109c_multi_auth_email_cardinality.sql`, after the R103E `0012` repair."
R109D specifies the migration because it is blocked on it, not because it owns
it. `docs/refactor-103E.md` agrees: it assigns the canonical Passkey and Email
OTP provider-identity branches to R109C and forbids implementing them in R103E.

The deferral's supporting argument was also unsound. It claimed the addition
race was "closed transactionally" by a conditional insert, so the cardinality
index could wait. There was no conditional insert. There is one now, and it is
tested, but a guard in one code path is not the schema-level cardinality
constraint the migration is for.

What `0013` must do, from R109D's specification: join the canonical wallet
Email enrollment, copy `provider_user_id`, infer `provider` (a `google:`
subject is `google`, otherwise `email`), retain the normalized
`email_hash_hex`, rewrite columns and JSON to the final provider identity
shape, drop `registrationAuthorityId`, and apply the cardinality index. It
aborts if an active or pending Email method cannot resolve its enrollment, and
drops unresolvable revoked history. No nullable compatibility fields.

This ripples into `EmailOtpWalletAuthMethodDraftV1`, the V2 store and its
parsers, and this refactor's own `addWalletAuthMethod.ts` contract, because
`registrationAuthorityId` disappears from the Email branch. It is not started
yet and is the largest single remaining server item.

### Open: an added method can be created but cannot yet unlock

Completion asks that both methods "explicitly unlock, issue sessions, sign,
export, step up, and revoke their sibling". Revocation is proven both
directions. Unlock is not, and a browser run says why in two steps.

The first was a real local-installation gap, now fixed. Unlock reads the
profile, then the profile's authenticators, then keeps only those whose
credential belongs to an ACTIVE V2 passkey method. A cross-family addition
wrote the V1 auth-method row alone, so an Email-registered wallet that gained a
passkey had the method on the server and could not open with it here —
`[login] ECDSA wallet <id> has no local passkey profile`. The same-family
addition never showed it, because a passkey-registered wallet already had all
three records.

The second is unresolved and deeper:

    [WalletRuntimePostcondition] ecdsa_lane_missing
    {"source":"wallet_unlock","authMethod":"passkey","curve":"ecdsa",
     "targetKey":"tempo:42431","state":"missing","candidateCount":0}

The added passkey reaches unlock and finds no ECDSA lane material. The cause is
exact, in `availableSigningLanes.ts`:

    for (const lane of canonicalEcdsaLanes) {
      const authMethod = signingLaneAuthMethod(lane.auth);
      if (input.authMethod && authMethod !== input.authMethod) continue;

Unlocking with the added passkey sets `input.authMethod` to `passkey`, and every
existing lane was created under `email_otp`, so all are skipped.

A first reading says the filter should key on authority rather than family,
since R109C's siblings share one authority. That reading is wrong, and the
correction is the point. `SigningLaneAuthBinding` names a specific method — rpId
plus credential id for a passkey, provider identity for Email OTP — not an
authority. A lane is bound to the method that provisioned it by construction,
and the binding is enforced twice below the filter: the material's AEAD AAD
commits to that method's authority ref, and capability construction refuses a
mismatched digest. Matching on authority would widen what an existing lane
authorizes, which is a signing-material decision and not a resolution tweak.

The plan already answers this, in step 5 of the linear operation: "reseal the
same custody seed AND EVERY EXISTING LOCAL SIGNER/EXPORT ACCESS RECORD under the
verified target factor", followed by steps 6-8 which install those sealed
records as pending, then flip them to active. The addition creates no new
signer material because it reseals the material the wallet already has, once per
method. That is the same shape as the custody envelope, extended to signer
access.

What is implemented today is only the custody envelope. Steps 5-8 are not:
an addition writes the auth-method rows and its envelope, and no signer access
record is resealed for the added method. That is the whole of the gap.

Tracing the owner ECDSA path to its records answers where the reseal has to
land, and turns up a contradiction the plan does not yet resolve. Four facts,
each read off the code rather than inferred:

1. The ECDSA role-local material is sealed under a randomly generated,
   non-extractable AES-GCM key held in IndexedDB
   (`generateMaterialSealingKey`, `SEALING_KEY_STORE`). It is device-local and
   not factor-derived, so nothing about it needs a factor to open.
2. It is nonetheless method-bound, through the AEAD AAD rather than the key.
   `activationBindingAadProjection` commits `signer.authority` — a
   `WalletAuthAuthorityRef` carrying that credential's `authorityDigest` and
   `walletAuthMethodId`. A sibling method cannot open it.
3. `buildCanonicalEvmFamilyEcdsaSigningCapability` refuses to build a
   capability whose authority digest differs from the manifest's. So a sibling
   cannot borrow the source method's capability either; both layers agree the
   capability belongs to one credential.
4. `lookupByMaterialActivation` returns `exact_record_conflict` when more than
   one ACTIVE manifest shares a `materialActivation`. Retired manifests are
   skipped, active ones are not.

Facts 2 and 3 say the added method needs its own binding of the material.
Fact 4 says it cannot have one while the source method keeps its own, and
invariant 8 forbids giving the target its own signer activation to escape the
collision. Retiring the source binding would clear fact 4 and violate
invariant 9, which keeps the source method selected after addition.

So `WalletAuthAuthority` is not the wallet's authority. It is a per-credential
binding whose digest covers the factor identity, and the ECDSA capability model
binds one capability to one such binding at three layers: the manifest record,
the material AAD, and the identity assertion. R109C's "one authority, two
methods" premise meets that model here, and one of the two has to give.

Two ways out, both real:

- **Bind per method, and allow siblings.** Install a target-bound manifest and
  material at addition: open under the source binding, reseal under the target
  binding. That is a local re-AAD, not a derivation — no new activation, share,
  public key, or key manifest, so invariant 8 holds. It requires relaxing fact
  4 so that `materialActivation` selects by requested authority rather than
  erroring on multiplicity. This is step 5 read literally, and it keeps both
  methods working. `openActiveMaterial` already returns the ready blob to the
  same JavaScript layer the signing path uses, so this needs no new custody
  worker operation and no new plaintext exposure.
- **Bind per authority.** Key manifests to `WalletAuthorityV1.authorityId` and
  the revocation epoch instead of the per-credential ref, so one manifest
  serves every active method. Architecturally this is what "one authority, two
  methods" means, but it changes a persisted, digest-bound record and the
  per-credential addressing the Refactor 103E revocation contract selects on,
  which is out of scope here.

The first is the smaller change and the one the plan already describes. The
second is the one that would be right if this model were being designed now.

The per-method branch is now built, and the sibling model holds. An added method
gets its own encrypted access projection over the wallet's existing activation:
uniqueness moved from one active manifest per material activation to one per
(material activation, exact authority), the activation lookup takes the exact
`WalletAuthAuthorityRef` and answers `ambiguous_authority` rather than picking a
sibling, and the copy boundary requires both methods to be active members of the
same `walletAuthorityId` before it opens anything. No activation, share, public
key, or key manifest is created, so invariant 8 holds.

Three further assumptions were in the way, each hiding the next, and each is
recorded here because the shape repeats: a place that reasoned about a
capability as though it had exactly one auth method.

1. A pointerless lookup scanned by capability and wallet, found the source
   method's manifest, and called the target's absent projection a binding
   mismatch. Installing the second method's access read as corruption.
2. The capability listing walked one subject at a time and then rebuilt each
   capability by material activation, which no longer names one manifest. Every
   sibling collapsed onto the selected method, so an added method never appeared
   as a candidate for its own family.
3. Canonical lane selection cancelled the siblings out. They share a material
   identity by construction, which is what the tie-break keys on, so neither
   superseded the other and the wallet reported no lane for a target it can
   sign for. Siblings are one lane reachable by two credentials; the Ed25519
   side already collapses them, and now so does ECDSA.

Unlocking with the added passkey has since been driven through four more
layers, each a real defect and each hiding the next. They are recorded because
the pattern is the same one: a place that assumed a wallet has exactly one auth
method.

4. The unlock postcondition saw a `deferred` lane, because the ECDSA capability
   listing had not yet produced an authorized capability for the added
   credential. Once the sibling projection resolved, the Wallet Session minted
   during warm-up matched the added method's authority digest exactly, and the
   lane reached `ready`.
5. The wallet selection refused to move. The stored selection still named the
   source method, as invariant 9 requires, and marking a different method
   unlocked was read as a corrupt selection - which made lock and unlock, the
   route invariant 9 gives a new method, the one thing it could not do. The
   selection now moves between active members of the same wallet authority.
6. The reverse contract had not waited for NEAR. An Email OTP registration can
   return ECDSA-ready with NEAR still provisioning, so the wallet had no
   Ed25519 signer and unlock correctly resolved it as ECDSA-only, returning no
   NEAR account id. That was the test's sequencing, not the product's; every
   other unlock contract already calls `awaitNearReady()`.

The Ed25519 half was the last of it, and it was a server-side gate rather than
a custody one. The server builds a credential binding for an added passkey, and
the Email OTP branch of that builder returned early with no wallet identity
fields at all - there is no source credential binding to copy them from, and
nothing filled the gap. WebAuthn login reads exactly those fields to decide
whether a credential carries Ed25519, so the added passkey claimed none and
unlock answered `capability_unavailable`. Adding a second way into a NEAR wallet
silently cost it NEAR.

The fields now come from the wallet's own Ed25519 signer, the only server record
of its NEAR identity, through a narrow lister rather than the whole wallet
store. Nothing is derived; the added credential points at the signer the wallet
already has. A wallet with no Ed25519 signer still gets a binding without
identity fields - that is the ECDSA-only case, not a failure - and more than one
signer is refused rather than guessed at.

## Where this stands

`email_otp_to_passkey` is proven end to end in a real browser: register with
Email OTP, wait for NEAR, add a passkey, and unlock the wallet with that
passkey, keeping its NEAR identity. `harness.unlockWithAddedPasskey()` is in the
committed contract.

`passkey_to_email_otp` proves the addition, and its unlock is blocked on
something the plan does not describe. Chasing it down leads out of custody
entirely:

- `registration.addEmailOtp({ walletId, emailAddress })` enrols the method under
  the address itself. `providerSubjectForVerifiedAddress` is explicit that there
  is no external IdP on this branch, so the address is the identity.
- The only email login that discovers a wallet is
  `auth.beginGoogleEmailOtpWalletAuth`, which takes a Google `idToken` and
  resolves the wallet from the Google subject. There is no address-based
  equivalent on the public surface.
- So an added Email OTP method cannot open its wallet. Pointed at a wallet
  registered with a passkey, the Google flow resolves whichever wallet that
  Google subject owns and fails with a wallet mismatch - correctly, because it
  was never asked about this wallet.

The remaining public pieces do not close it. `auth.requestEmailOtpChallenge`
takes a `walletId` and an exact method id, but the login that consumes it,
`loginWithEmailOtpEcdsaCapability`, is a capability primitive taking key handles
and participant ids; the wallet-level orchestration around it exists only inside
the Google flow, and its Ed25519 half is not exported at all.

Taking the Google-backed route seriously turns up the constraint that decides
it. `resolveLoginSession` resolves a Google subject through a single
`linkedWalletId`: one subject maps to one wallet. Attaching a Google identity to
a second wallet - which is exactly what adding it to a Passkey wallet means when
that subject already owns an Email OTP wallet - has no representation, and login
would have no way to say which wallet was meant. Google-backed additions
therefore need the identity-to-wallet mapping to become one-to-many plus a
wallet selector at login, which is a product identity change, not a smaller
alternative to the address-based login.

That leaves a decision rather than a defect. Either the product grows an
address-based email login - new public auth surface, which invariant 10 rules
out for this refactor - or an added Email OTP method is specified to carry an
IdP subject, in which case `addEmailOtp` needs the Google-backed proof kind its
own comment already anticipates. The completion criterion "both methods can
explicitly unlock" cannot be met for the Email OTP direction until one of those
is chosen, and neither is a custody change.

Nine distinct assumptions had to go before this point, and they were all the
same assumption: that a wallet has exactly one auth method, so a capability, a
lane, a selection, a credential binding, or an identity could be addressed
without saying which method was asking. That is the shape to look for in
anything R109C has not yet touched.

## Goal

Give an authenticated user one **Add authentication method** product action:

```text
Passkey present, Email OTP absent
  -> add Email OTP
  -> Passkey and Email OTP both active

Email OTP present, Passkey absent
  -> add Passkey
  -> Email OTP and Passkey both active
```

The operation fills the missing factor family on the selected installed wallet
authority. It creates one `WalletAuthMethodRecordV2` and preserves the existing
authority, device, permissions, signer activations, shares, public keys, export
material, key manifest, revocation epoch, and selected Wallet Session.

## Product contract

The settings inventory derives the available action from exact active methods
on the selected authority:

| Current factor families | Available action   | Result                            |
| ----------------------- | ------------------ | --------------------------------- |
| Passkey only            | **Add email code** | Passkey and Email OTP             |
| Email OTP only          | **Add passkey**    | Email OTP and Passkey             |
| Passkey and Email OTP   | no add action      | `already_configured` from the API |

An authority may already contain several Passkeys. That counts as “Passkey
present.” Existing methods remain valid; R109C never creates another method
from a family already present on the authority.

Email OTP remains limited to one active method per authority across Email OTP
providers. Revoked Email OTP history does not consume the active slot.

## Required prerequisite: exact method revocation

Do not expose either addition flow until ordinary auth-method revocation works
through the real composed path.

The prerequisite behavior is:

1. every user request targets one exact `WalletAuthMethodId`;
2. fresh proof comes from a different active local method for the same wallet;
3. revoking a method invalidates that method, its verifier, its sealed local
   records, and sessions issued through it;
4. the sibling method, shared authority, signer activations, and sibling
   sessions remain active;
5. the transaction refuses to revoke the wallet's final active method;
6. no user-facing operation targets `WalletAuthorityId` or revokes several
   methods at once.

After either R109C addition succeeds, the source method must be able to revoke
the new method, and the new method must be able to revoke the source method.
Both directions use fresh proof from the sibling method. The final-method guard
must remain atomic under competing revocation requests.

Refactor 103E owns this revocation contract. R109C verifies it as a prerequisite
and does not add another revocation model.

## Email OTP security boundary

Adding Email OTP reduces the assurance of a Passkey-only installation because
the email inbox becomes an independent way to unlock it. Show this short note
in the Email OTP addition UI:

> **Security note:** Adding email code lowers this wallet's security because
> your inbox becomes another way to unlock it.

The note is informational. It adds no confirmation step or separate Passkey
authorization ceremony. The shared add-auth-method operation shows the note,
then requires a fresh Passkey assertion for the exact intent immediately before
creating the Email OTP challenge. The assertion is bound to the exact wallet,
authority, source method, source session, target method ID, operation purpose,
authority state, and intent digest. A cancelled or failed attempt removes its
intent, challenge, verification receipt, and pending local method.

## Decisions

1. One internal add-auth-method operation has two exhaustive branches:
   `passkey_to_email_otp` and `email_otp_to_passkey`.
2. Keep two thin typed SDK entry points:
   `registration.addPasskey` and `registration.addEmailOtp`. Both call the same
   internal operation and own no persistence, retry, session, or activation
   logic.
3. The product UI presents one **Add authentication method** action and chooses
   the branch from exact active inventory.
4. The active Wallet Session names the exact source method. The server resolves
   its wallet, authority, device, authority digest, and revocation epoch.
5. The source supplies a fresh operation-specific proof. The target factor is
   verified independently; the source proof cannot serve as target
   verification.
6. The target family must be absent before target verification starts. The
   activation transaction repeats the check to close races.
7. Factor addition is a local reseal. The custody worker opens the source
   method's authenticated envelope and seals the same custody seed and existing
   local signer/export access under the target factor. JavaScript receives no
   custody seed or unsealed signer material.
8. The new method reuses the exact `WalletAuthorityId` and `DeviceId`. It
   creates no authority, signer activation, share, public key, export root, or
   key manifest.
9. The source method and Wallet Session remain selected after addition. The
   new method is used only after explicit selection or lock and unlock.
10. Reuse the existing add-auth-method intent, routes, custody worker, stores,
    and Wallet Session model. Add no aggregate, projection, or workflow
    framework.
11. Parse raw request, factor, and persistence input once at its boundary. Core
    code receives branded identities and one verified branch.

## Out of scope

- adding another Passkey when Passkey is already present;
- adding another Email OTP method when Email OTP is already present;
- replacing an existing factor identity;
- adding a factor on another device;
- changing the Refactor 103E revocation contract;
- changing permissions or signer families;
- deriving, rotating, repairing, or re-establishing signer material;
- transferring custody seed or signer material between devices;
- custom factor-management permissions;
- enterprise SSO;
- a generic ceremony, migration, or projection framework.

## Current gap

The codebase already provides generic intent routes,
`WalletAuthMethodRecordV2`, D1 and IndexedDB stores, the Passkey custody-link
path, and `registration.addPasskey`. The missing operating behavior is narrow:

- `registration.addPasskey` rejects an Email OTP source proof;
- `registration.addEmailOtp` does not exist for an established wallet;
- unlock and settings do not deliberately expose both exact methods on one
  authority;
- route and service branches still assume matching source and target families.

R109C keeps `registration.addPasskey`, adds `registration.addEmailOtp`, and
makes both thin adapters over one internal operation.

## Domain model

```text
WalletAuthorityV1
  authorityId
  deviceId
  permissions
  exact signer activations
       ^
       |
       +-- WalletAuthMethodRecordV2: Passkey
       +-- WalletAuthMethodRecordV2: Email OTP
```

`WalletAuthorityV1` owns permissions and signer state. Each auth method owns
one factor identity, lifecycle, sealed custody envelope, sealed access to local
material, and sessions issued through that method. The presence of both active
branches is the combined state; no combined-auth record is persisted.

## Public and core contracts

Keep branch-specific SDK inputs:

```ts
registration.addPasskey(args: {
  readonly walletId: WalletId | string;
  readonly rpId: string;
  readonly options?: AddPasskeyHooksOptions;
}): Promise<AddWalletAuthMethodResultV1>;

registration.addEmailOtp(args: {
  readonly walletId: WalletId | string;
  readonly emailAddress: string;
  readonly options?: AddEmailOtpHooksOptions;
}): Promise<AddWalletAuthMethodResultV1>;
```

The selected Wallet Session supplies the source method and authority. Callers
do not construct a broad authorization object. The server supplies the target
`WalletAuthMethodId`, scope, intent nonce, authority snapshot, challenge, and
expiry.

After verification, core code accepts only:

- verified Passkey source plus verified new Email OTP target;
- verified Email OTP source plus verified new Passkey target.

Use existing verified proof values when they carry the required guarantees.
Use branch-specific builders and exhaustive switches. Type fixtures reject
same-family additions, mixed target fields, unverified input, ID mismatches,
broad spreads, and unsafe casts.

Both SDK entry points return the same result union with `active`,
`already_configured`, `cancelled`, `expired`, `unauthorized`,
`target_verification_failed`, and `integrity_error` branches. Reuse existing
failure reason unions. UI control flow switches on the result discriminant;
messages and diagnostics remain display data.

## One linear operation

1. Load the active Wallet Session, exact source method, and active authority.
   Require current digest and epoch, complete local installation, exact
   `FULL_OWNER_PERMISSIONS`, and an absent target family.
2. For Passkey-to-Email-OTP, show the short security note in the addition UI.
   Obtain the source authorization required by the shared operation. For
   Email-OTP-to-Passkey, obtain one fresh Email OTP owner grant.
3. Reuse the existing intent route. Bind one server-allocated target method ID
   to the wallet, authority, device, source method, source session, target
   family, authority snapshot, nonce, and expiry.
4. Verify the target factor:

   | Source    | Target    | User actions                                       |
   | --------- | --------- | -------------------------------------------------- |
   | Passkey   | Email OTP | security note, source assertion, target email code |
   | Email OTP | Passkey   | source email code, target credential creation      |

5. In the custody worker, reseal the same custody seed and every existing local
   signer/export access record under the verified target factor.
6. Write the pending target method, sealed records, and installation receipt in
   one IndexedDB transaction. Pending material cannot unlock, sign, export,
   step up, or issue a Wallet Session.
7. Revalidate the source, target, authority snapshot, missing-family invariant,
   intent, and receipt. One D1 transaction inserts the active method and factor
   verifier, consumes the target grant, writes the audit event, and completes
   the intent. It changes no authority or signer record.
8. Replace the pending local method with the exact active server record in one
   IndexedDB transaction. Retain sealed material, delete temporary state, and
   keep the source method selected.

Initial admission returns `already_configured` before target verification when
the target family is present. Activation uses a conditional insert that
succeeds only while the target family remains absent. This closes concurrent
addition races while preserving previously stored multi-Passkey inventories.

Retries reuse the same intent and target method ID. An exact retry returns the
same active method. Cancellation and expiry before activation remove temporary
challenges, source proofs, and matching pending local state.

## Persistence, unlock, and revocation

Reuse `wallet_auth_methods` and its canonical V2 parser. Keep active Passkey
credential uniqueness. Keep one active Email OTP method per
`(scope, wallet_authority_id)` across Email OTP providers. Add no table for the
derived two-family state.

IndexedDB addresses sealed records by the exact wallet, authority, auth method,
and activation or root identity required by the store. A method is locally
usable only when its complete exact record set is present.

Unlock begins with explicit method selection:

```text
selected WalletAuthMethodId
  -> exact active auth method
  -> exact active authority
  -> verify selected factor
  -> open that method's sealed local records
  -> issue an ordinary Wallet Session
```

Both methods resolve the same authority and signer activations. Each issues its
own Wallet Session. Step-up verifies the session's exact method. Lock remains
durable across refresh, and unlock never infers a method from factor kind,
email hint, recent use, display label, or record order.

Revocation continues through the exact Refactor 103E method-level operation.
The addition UI must expose removal for each method once the sibling is active.
Removing either method leaves the sibling usable; removing the final wallet
method is refused.

## Implementation phases

### Phase 0 — Prove the revocation prerequisite

- run exact method revocation through the composed server and IndexedDB path;
- prove each method can revoke its sibling with fresh proof;
- prove the final wallet method cannot be revoked;
- prove authority-ID and batch revocation requests are rejected;
- block R109C product exposure until these checks pass.

### Phase 1 — Shared internal contract and thin SDK entry points

- add the two-branch verified internal input;
- retain `registration.addPasskey` and add `registration.addEmailOtp`;
- make both entry points call the same internal operation;
- make authority, source method, source session, and target method IDs required;
- add boundary parsers, branch builders, exhaustive switches, and type fixtures;
- reject a target family already present before target verification.

Primary locations:

- `packages/shared-ts/src/utils/registrationIntent.ts`
- `packages/shared-ts/src/utils/addAuthMethodRegistration.ts`
- `packages/wallet/src/SeamsWeb/publicApi/types.ts`
- `packages/wallet/src/SeamsWeb/publicApi/createPublicApi.ts`
- `tests/typecheck/`

### Phase 2 — Both cross-family paths

- implement Passkey source to Email OTP target with the short security note;
- implement Email OTP source to Passkey target through the same operation;
- route the existing Passkey custody-link code through the shared reseal and
  activation stages;
- keep the source method and session selected after both paths.

Primary locations:

- `packages/wallet/src/SeamsWeb/operations/authMethods/`
- existing custody, Passkey, and Email OTP workers
- `packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthMethodService.ts`
- existing add-auth-method routes and IndexedDB stores

### Phase 3 — Inventory, selection, and removal

- derive the missing-family action from exact active inventory;
- hide the add action once both families are active;
- require explicit method selection for unlock and step-up;
- issue sessions through the selected exact method;
- expose exact sibling-authorized removal for both methods.

Primary locations:

- `packages/wallet/src/SeamsWeb/operations/auth/login.ts`
- `packages/wallet/src/react/components/AccountMenuButton/`
- `packages/wallet/src/SeamsWeb/walletIframe/host/auth-menu/`

### Phase 4 — Delete and verify

- delete the Email-OTP-source rejection and duplicated branch persistence;
- delete fixtures and mocks that assume one factor family;
- update `docs/intended-behaviours.md` and its contract tests;
- run the real operating matrix.

## Required verification

Run both transitions against Ed25519-only, ECDSA-only, and both-family wallets:

| Existing method | Added method |
| --------------- | ------------ |
| Passkey         | Email OTP    |
| Email OTP       | Passkey      |

For every cell and signer configuration:

1. prove authority, device, permissions, activation refs, digest, epoch, source
   method, and source session remain unchanged;
2. prove one target method has a fresh opaque ID and complete local records;
3. explicitly lock and unlock with each method;
4. sign through every present signer family under each method;
5. export every present family with step-up from the exact selected method;
6. reload while locked and prove neither method auto-unlocks;
7. prove the add action disappears when both families are active;
8. repeat the target request and receive `already_configured` before target
   verification or local writes;
9. revoke the new method using the source method and prove the source still
   operates;
10. add again, revoke the source using the new method, and prove the new method
    still operates;
11. refuse revocation of the remaining final method.

For Passkey-to-Email-OTP, verify that the short security note renders in the
addition UI.

Run interruption and lost-response cases once per target branch. Every retry
must converge on the same target method without increasing method or sealed
record counts. External email delivery and chain RPC may be stubbed at their
network boundaries; intent, proof, reseal, IndexedDB, D1 activation, unlock,
session, signing, export, step-up, and revocation use the real composed path.

## Completion criteria

R109C is complete when:

- Refactor 103E exact method revocation passes before addition is exposed;
- a Passkey-only authority can add Email OTP after seeing the short security
  note;
- an Email-OTP-only authority can add a Passkey;
- `registration.addPasskey` and `registration.addEmailOtp` are thin entry
  points into one exhaustive two-branch internal operation;
- both methods reference the original authority and signer activations;
- factor addition creates no authority or signer material;
- both methods can explicitly unlock, issue sessions, sign, export, step up,
  and revoke their sibling;
- the source method and session remain selected after addition;
- a target family already present returns `already_configured` before target
  verification;
- same-family addition is absent from the R109C operation;
- duplicated persistence and obsolete fixtures are deleted;
- the real two-transition browser matrix passes.
