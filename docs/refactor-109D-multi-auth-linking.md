# Refactor 109D — Multi-auth device linking

Date created: August 20, 2026

Status: implementation-blocked on Phase 0.

## Goal

Allow an active Passkey or Email OTP session on Device 1 to link Device 2 with
either target factor:

| Device 1  | Device 2  |
| --------- | --------- |
| Passkey   | Passkey   |
| Passkey   | Email OTP |
| Email OTP | Passkey   |
| Email OTP | Email OTP |

The source method authorizes linking. The target factor authenticates and seals
Device 2. They do not need to match.

## Dependency boundaries

- R103E owns authorities, auth-method records, signer activations, the
  link-session lifecycle, seedless installation, Wallet Session issuance,
  retry, inventory, unlock, and exact-method revocation.
- R109C owns multi-method inventory, same-device factor addition, Email OTP
  cardinality, and verification of the R103E revocation prerequisite.
- R109D owns source/target factor independence, Email base-method selection,
  Passkey target configuration, mixed-factor UI, and the four-combination
  operating path.

Merge in that order. R109D reuses the final R103E installation and activation
functions. It does not copy R109C's same-device custody or persistence flow.

## Phase 0

Do not implement R109D until:

1. R103E prose and exports agree on `awaiting_source_contribution` and the
   source-contribution fields in `VerifiedLinkInputV1`.
2. R109C is re-implemented on the final R103E tree. The retired pre-R103E
   implementation is not rebased or cherry-picked.
3. The R109C schema change becomes
   `0022_r109c_multi_auth_email_cardinality.sql`, after the R103E `0021`
   transcript repair. Keep the eight deployed signer migrations byte-for-byte
   and preserve lexical migration order.
4. Only the current V2 `wallet_auth_methods` schema remains. Do not restore a
   legacy table or runtime compatibility path.
5. Every ordinary Wallet Session, including founding and linked sessions,
   stores the operation credential required by
   `readExactWithOperationCredential`.
6. Delete linked-device `step_up`, `orderedOwnerSourceLaneHints`, and the
   retired owner/lane projections.
7. Fix the stale `VerifiedLinkInputV1` authority-install test fixture through
   its shared factory, then make the focused R103E tests and type checks green.

## Successful result

One link creates:

- a fresh Device 2 ID and authority;
- a fresh target auth method owned by that authority;
- one fresh activation for each signer family in the source manifest;
- a normal active Wallet Session;
- an independently revocable inventory entry.

The administered `walletKeyId` and public signer identity stay the same.
Activation refs and all share material are fresh. Device 1 remains unchanged.

The wallet custody seed never enters linking or Device 2. Ed25519 export uses
the existing one-use encrypted export-root handoff. R109D adds no R102 lane,
custody reseal, recovery flow, or linked-device-specific signing path.

## User flow

1. Device 2 chooses its target factor and creates the QR session.
2. Device 1 scans the QR and claims the session with its exact active Wallet
   Session.
3. For an Email OTP target, Device 1 selects the exact base method before
   approval.
4. Device 1 approves the immutable target branch.
5. Device 2 completes Passkey registration or Email OTP verification and
   registers its material recipients.
6. Device 1 supplies the factor-neutral R103E source contribution.
7. The server commits one pending authority and package set.
8. Device 2 installs locally, the server activates the exact records, and an
   ordinary Wallet Session is issued.
9. Device 2 acknowledges success and temporary link state is deleted.

## Device 1 source

The browser:

1. resolves the selected wallet, authority, and auth method;
2. calls
   `readExactWithOperationCredential({ walletId, authorityId, authMethodId })`;
3. uses that exact operation credential for linking.

The linked-device authorization union is replaced by the single valid branch:

```ts
type LinkedDeviceOwnerAuthorizationSourceV1 = {
  readonly kind: 'wallet_session';
  readonly walletSessionId: WalletSessionId;
  readonly authorizationId: WalletSessionAuthorizationId;
};
```

There is no `readActiveForWallet` fallback, founding-authority exception,
source picker, client-supplied signer manifest, or linked-device `step_up`.

At approval and source contribution, the server revalidates the exact active
session, method, authority, digest, revocation epoch, `link_devices`
permission, signer manifest, and activation set.

The temporary approval transcript stores the verified source facts needed for
that second check:

```ts
type LinkedDeviceVerifiedSourceFactsV1 = {
  readonly walletSessionId: WalletSessionId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly authMethodId: WalletAuthMethodId;
  readonly authorityDigestB64u: DigestB64u;
  readonly revocationEpoch: number;
  readonly signerManifest: ExactAdministeredSignerManifestV1;
  readonly activationSetDigestB64u: DigestB64u;
};
```

These are temporary protocol facts. Do not persist them on the new authority,
auth method, activation, or Wallet Session.

R103E's existing source-contribution planner derives the required work from
those server facts. Ed25519 precedes ECDSA when both are present. R109D adds no
second planner or lane model.

The planner input is the verified source facts, link/enrollment/device IDs,
verified target factor, and recipient requests. It returns the existing
`LinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1`. Its output
must contain exactly the signer families in the manifest.

A successful read proving the source absent, inactive, changed, revoked, or
unauthorized terminally fails the precommit session. Infrastructure failures
remain retryable.

## Device 2 target

Device 2 chooses `passkey_prf` or `email_otp` before QR creation. The choice
is immutable for the session.

Approval proves the branch is complete:

```ts
type LinkedDeviceApprovedTargetFactorV1 =
  | {
      readonly kind: 'passkey_prf';
      readonly baseWalletAuthMethodId?: never;
    }
  | {
      readonly kind: 'email_otp';
      readonly baseWalletAuthMethodId: WalletAuthMethodId;
    };
```

The QR and claim keep the simpler factor discriminator. The approval builder
requires it to match this branch.

### Passkey

Use the managed `LINKED_DEVICE_WEBAUTHN_RP_ID` and
`LINKED_DEVICE_WEBAUTHN_ORIGIN`. Normalize and validate them once at server
composition, then bind their digest into target preparation.

```ts
type LinkedDevicePasskeyTargetConfigurationV1 = {
  readonly kind: 'linked_device_passkey_target_configuration_v1';
  readonly rpId: WebAuthnRpId;
  readonly expectedOrigin: SessionOrigin;
  readonly configurationDigestB64u: DigestB64u;
};
```

Make this a required server-composition value. Missing or invalid
configuration prevents device-linking startup. Recompute and compare the
configuration digest at verification; a mid-flow change fails closed.

Creation options use a fresh challenge, target method ID, wallet ID as the user
handle, existing PRF salts, and `excludeCredentials: []`. They never copy the
source factor, credential, or RP configuration.

### Email OTP

Device 1 selects the base Email OTP method. Device 2 receives a masked address
and enters the code; it never supplies or edits an email address.

Eligible methods have an active method, active authority, exact canonical
enrollment, and addressable factor release in the same wallet.

The candidate operation returns only these shapes:

```ts
type LinkedDeviceEmailOtpBaseFactorChoiceV1 = {
  readonly baseWalletAuthMethodId: WalletAuthMethodId;
  readonly maskedEmailHint: string;
};

type LinkedDeviceEmailOtpBaseFactorResolutionV1 =
  | {
      readonly kind: 'selected';
      readonly choice: LinkedDeviceEmailOtpBaseFactorChoiceV1;
    }
  | {
      readonly kind: 'selection_required';
      readonly choices: readonly [
        LinkedDeviceEmailOtpBaseFactorChoiceV1,
        ...LinkedDeviceEmailOtpBaseFactorChoiceV1[],
      ];
    }
  | {
      readonly kind: 'unavailable';
      readonly reason: 'no_active_email_otp_base_factor';
    };
```

The D1 adapter joins `CloudflareD1WalletAuthMethodService`,
`D1WalletAuthorityStore`, `CloudflareD1EmailOtpEnrollmentStore`, and the
existing factor-release loader. Wallet ID comes from the verified source; the
client cannot nominate it.

- zero candidates: typed terminal unavailable result;
- one: automatic selection;
- several: Device 1 chooses from rows sorted by `WalletAuthMethodId`;
- stale or foreign ID: the same non-disclosing ineligible result.

Persist `baseWalletAuthMethodId` in approval and bind it through preparation,
challenge, grant, verification, and pending commit. No later path may use
`active[0]` or repeat selection.

The canonical identity is `provider`, `providerUserId`, and `emailHashHex`
from `EmailOtpWalletEnrollmentRecord`. Do not use
`registrationAuthorityId`. The verified grant constructs an independent
Device 2 auth-method draft.

The one-use grant directly carries the base method ID, the three provider
identity fields, and a digest over all four. Revalidate the exact base record
and enrollment at challenge start, verification, and pending commit.

| Artifact                 | Required Email binding                 |
| ------------------------ | -------------------------------------- |
| approval                 | base method ID                         |
| preparation              | base method ID and identity digest     |
| challenge and grant      | base method ID and identity digest     |
| verified target          | base method ID and verification digest |
| pending package set      | target verification digest             |
| temporary replay records | base method ID until cleanup           |

The new Device 2 auth method stores its own provider identity. It does not
store a parent/base-method relationship after activation.

Keep target preparation branch-specific:

```ts
type LinkedDeviceTargetPreparationV1 =
  | (LinkedDeviceTargetPreparationBaseV1 & {
      readonly targetFactor: { readonly kind: 'passkey_prf' };
      readonly passkeyCreationOptions: LinkedDevicePasskeyCreationOptionsV1;
      readonly passkeyConfigurationDigestB64u: DigestB64u;
      readonly baseWalletAuthMethodId?: never;
      readonly baseFactorIdentityDigestB64u?: never;
    })
  | (LinkedDeviceTargetPreparationBaseV1 & {
      readonly targetFactor: { readonly kind: 'email_otp' };
      readonly passkeyCreationOptions?: never;
      readonly passkeyConfigurationDigestB64u?: never;
      readonly baseWalletAuthMethodId: WalletAuthMethodId;
      readonly baseFactorIdentityDigestB64u: DigestB64u;
    });
```

The Email branch of `VerifiedTargetFactorV1` also carries the exact
`baseWalletAuthMethodId`; the Passkey branch rejects it with `never`.

Active and pending methods retain their shared provider enrollment. Delete it
only after its last reference is gone.

Add an owner-authenticated candidate-resolution operation and owner-cancel
operation to the existing linking route and Device 1 transport. Both use the
exact Wallet Session credential and expected revision. Candidate reads do not
mutate state; approval revalidates the selected ID and performs the CAS.
Owner-cancel moves only `claimed` to `cancelled`. Device 2's cancel path is
unchanged.

Use these action paths under the existing session route:

- `POST /wallet/device-linking/v1/sessions/:id/email-otp-base-factor` with
  `{ expectedRevision, request: { kind: 'resolve' } | { kind: 'select',
baseWalletAuthMethodId } }`;
- `POST /wallet/device-linking/v1/sessions/:id/owner-cancel` with
  `{ expectedRevision }`.

Candidate `selected` and `selection_required` responses retain the current
revision. `unavailable` terminally fails that exact revision. Owner-cancel is
idempotent for the resulting terminal record and returns `invalid_state` from
any other lifecycle branch.

## Product UI

Expose one factor-neutral “Scan and Link Device” action after either Passkey or
Email OTP authentication. Its ready state contains required wallet, authority,
auth-method, and Wallet Session IDs from the exact selected session. Opening
linking must retain that state; it must not trigger another login or step-up.

Device 2 chooses the target factor before QR creation. Device 1 owns Email
base-method selection and sees server-masked choices keyed by exact auth-method
ID. Device 2 has no email-entry control.

Both devices branch on typed lifecycle and failure results. Release the
in-progress guard after `active`, `failed_before_commit`, `cancelled`, or
`expired`.

## Lifecycle and retry

Use the final R103E states:

```text
displaying_qr
  -> claimed
  -> awaiting_target_factor
  -> awaiting_source_contribution
  -> provisioning
  -> authority_pending_local_install
  -> active
```

`failed_before_commit`, `cancelled`, and `expired` are precommit terminal
states. `deleted` is cleanup, not a state.

Recording approval moves `claimed` to `awaiting_target_factor`. Durable target
verification and recipient registration move it to
`awaiting_source_contribution`. The accepted source contribution moves it to
`provisioning`.

Source-contribution mutation results have exact meanings:

- `applied`: persist one transcript and enter `provisioning`;
- `replayed`: return the same transcript and revision;
- `invalid_input`: retain state for malformed or binding-mismatched input;
- `conflict`: return the current record after a revision race;
- `invalid_state`: reject a lifecycle violation;
- `integrity_error`: fail closed on persisted ID or digest disagreement.

Approval expiry calls the existing expiry CAS. Durable source failure calls
the existing precommit-failure CAS with one of these reasons:

```ts
type LinkedDeviceUnauthorizedSourceReasonV1 =
  | { readonly kind: 'source_authorization_expired' }
  | { readonly kind: 'source_state_unavailable' }
  | { readonly kind: 'source_identity_changed' }
  | { readonly kind: 'source_permission_missing' };

type LinkedDeviceRevokedSourceReasonV1 = {
  readonly kind: 'source_revoked';
};
```

`source_state_unavailable` means a successful authoritative read found the
exact record absent or inactive. Transport and infrastructure failures do not
use that reason.

Target-preparation expiry gates verification and registration. After a
registered Passkey target, the approval deadline governs remaining precommit
work. An Email grant must also remain live until pending commit.

`authority_pending_local_install` is the point of no return. Later retry
resumes the same authority, auth method, activation refs, verification digest,
and byte-identical package set. Cancellation and ordinary expiry are forbidden.

| Failure                                     | Result                                  |
| ------------------------------------------- | --------------------------------------- |
| no eligible Email base method               | terminal typed unavailable              |
| selected Email method changes before commit | terminal typed changed                  |
| incorrect Email code before expiry          | remain awaiting target; retry or resend |
| target preparation or Email grant expires   | terminal target-verification expiry     |
| Passkey configuration changes before commit | terminal configuration-changed          |
| source session fails revalidation           | terminal typed source failure           |
| malformed source contribution               | `invalid_input`; retain state           |
| failure after pending commit                | resume exact pending installation       |

## Durable target registration

Close the current response-loss gap. The existing target-credential row must
atomically persist a versioned payload containing:

- target registration and verified target factor;
- recipient requests;
- source-contribution preparation;
- their canonical digests.

```ts
type LinkedDeviceRegisteredTargetCredentialRecordV2 = {
  readonly kind: 'linked_device_registered_target_credential_v2';
  readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
  readonly verifiedTargetFactor: VerifiedTargetFactorV1;
  readonly sourceContributionPreparation: LinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1;
  readonly sourceContributionPreparationDigestB64u: DigestB64u;
  readonly recipientRequestsDigestB64u: DigestB64u;
};
```

The row's link, wallet, enrollment, device, target-factor, credential/grant,
manifest, digest, and timestamp columns must agree with the parsed payload.

The session CAS copies that stored preparation. Replay reads it and never
recomputes mutable source or target state.

At the D1 boundary, accept only the new version. Clean up an old precommit shape
and return `relink_required` with
`{ kind: 'retired_target_registration_shape' }`. Add that branch to
`RelinkRequiredReasonV1`. Drain or retire any old pending authority before
rollout. Do not add a core compatibility parser.

Precommit terminal transitions delete target credentials, reservations, Email
grants, source preparation, transcripts, and one-use transport rows in the
same D1 transaction. Keep a minimal terminal session until QR expiry so Device
2 can poll it. Release inactive worker reservations idempotently.

| Record owner                                | Precommit terminal action                 |
| ------------------------------------------- | ----------------------------------------- |
| D1 target credential and commit reservation | delete in terminal transaction            |
| Email challenge, grant, and factor release  | delete or revoke by exact ID              |
| source preparation, transcript, and handoff | delete in terminal transaction            |
| one-use transport and export-root rows      | delete in terminal transaction            |
| inactive worker reservation                 | release after D1 commit; retry on cleanup |
| authority installation                      | must be absent before terminal transition |

Acknowledging `active` deletes temporary link state without deleting the
installed wallet.

The pending commit revalidates source, target, permissions, signer manifest,
activation refs, recipient requests, and any Email grant in one operation. It
writes one pending authority, target method, activation set, package set, and
installation row. Worker reservations are idempotent by activation ref.

Every retry compares the exact link session, device, authority, auth method,
activation refs, target-verification digest, and package-set digest. A
difference is an integrity error; retry never allocates replacement material.

The required resume boundaries are: target registration before session CAS,
one worker reservation before pending D1 commit, pending commit before local
installation, partial worker activation, and active D1 commit before response.

## R109C migration

`0013_r109c_multi_auth_email_cardinality.sql` rewrites current V2 Email rows:

1. join the canonical wallet Email enrollment;
2. copy `provider_user_id`;
3. infer `provider` with the current rule: a `google:` subject is `google`,
   otherwise `email`;
4. retain normalized `email_hash_hex`;
5. rewrite columns and JSON to the final provider identity shape;
6. remove `registrationAuthorityId` and apply R109C cardinality.

Abort if an active or pending Email method cannot resolve its enrollment. Drop
unresolvable revoked history during the reset. Add no nullable compatibility
fields.

The migration test covers a successful backfill, an unresolvable live row,
lexical ordering, the cardinality index, and absence of retired fields and
legacy tables.

## Primary code map

| Concern                    | Primary files                                                                                                                                                                                     |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Shared protocol            | `packages/shared-ts/src/device-linking/contracts.ts`, `parsers.ts`, `digests.ts`, `sourceContribution.ts`                                                                                         |
| Exact browser source       | `walletSessionAuthorizationStore.ts`, `walletHostOwnerAuthority.ts`, `browserSigningSurfaceAssembly.ts`                                                                                           |
| Browser flow and UI        | `scanDevice.ts`, `linkDevice.ts`, `deviceLinkingOwnerTransport.ts`, `deviceLinkingHttpTransport.ts`, auth-menu `session.ts`, `controller.ts`, `auth-menu-domain.ts`, `seams-auth-menu-surface.ts` |
| Server route and lifecycle | `routes/deviceLinking.ts`, `core/deviceLinking/linkedDeviceSession.ts`, `d1LinkedDeviceSessionService.ts`, `d1LinkedDeviceSessionStore.ts`                                                        |
| Source verification        | `d1LinkedDeviceVerifiedLinkSourceReader.ts`, `d1LinkedDeviceOwnerAuthorizationProvider.ts`, `d1LinkedDeviceSourceContributionPreparationPlanner.ts`                                               |
| Email target               | `d1LinkedDeviceEmailOtpTargetFactor.ts`, `d1LinkedDeviceEmailOtpGrantStore.ts`, auth-method, authority, and Email enrollment stores                                                               |
| Passkey and replay         | `d1LinkedDeviceTargetPlanner.ts`, `d1LinkedDeviceTargetCredentialProvider.ts`, `d1LinkedDeviceVerifiedLinkBuilder.ts`                                                                             |
| Commit and activation      | `d1LinkedDeviceAuthorityInstallService.ts` and the existing R103E worker adapters                                                                                                                 |
| Composition                | `d1RouterApiAuthConfig.ts`, `d1RouterApiAuthService.ts`, local/staging D1 worker composition                                                                                                      |

## Implementation order

1. Finish Phase 0.
2. Update shared contracts, parsers, digests, and type fixtures; delete the
   retired source branches in the same change.
3. Implement exact source reads, target adapters, candidate operations,
   durable target replay, and typed cleanup.
4. Wire local/staging composition and expose the same link action after
   Passkey or Email OTP authentication.
5. Reuse R103E installation, activation, Wallet Session, inventory, signing,
   export, unlock, and revocation paths.

Do not add a workflow engine, projection, generic factor framework, migration
shim, or parallel activation path.

## Verification

Run all four factor combinations for Ed25519-only, ECDSA-only, and combined
signer profiles.

Each of the twelve cases proves:

- Device 1 is unchanged;
- Device 2 gets exactly one fresh authority, method, and required activations;
- reload, lock, unlock, inventory, signing, export, and exact revocation use
  ordinary paths;
- acknowledgement removes temporary state;
- revoking Device 2 does not affect Device 1 or sibling methods.

Focused coverage also includes:

- exact source selection for founding and linked sessions;
- zero, one, several, stale, and foreign Email candidates;
- masking and provider identity binding;
- Passkey configuration with no source-credential dependency;
- response loss before the target-registration session CAS;
- source-contribution replay and source revocation;
- terminal cleanup;
- retries after pending commit, local install, worker activation, and active D1
  commit without duplicates;
- the `0013` migration.

## Ready to begin

Implementation may begin when Phase 0 is merged and green. Completion requires
the twelve browser cases and no linked-device `step_up`, lane, same-factor,
source-RP-copying, legacy auth-method, or compatibility path.
