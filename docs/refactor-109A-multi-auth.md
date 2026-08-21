# Refactor 109A — Multi-Method Wallet Authentication

Date created: August 20, 2026

Status: implementation-ready. Depends on Refactor 103E and must land before
Refactor 109B.

When this document conflicts with Refactor 103E, the R103E authority,
activation, Wallet Session, lock, and identity model controls. R109A extends
that model by allowing several auth methods to reference one authority. It does
not introduce another authority model.

## Goal

Allow one installed wallet authority to use multiple active authentication
methods across both supported factor families:

- one or more Passkeys;
- one or more verified Email OTP methods;
- any valid combination of the two.

Every added method opens the same authenticated wallet custody seed and the
same exact signer activations. It receives its own opaque
`WalletAuthMethodId`, factor credential, sealed local records, lifecycle, and
Wallet Sessions. It reuses the existing `WalletAuthorityId` and `DeviceId`.

## Non-negotiable decisions

An implementer should not reopen these decisions:

1. Factor addition creates one `WalletAuthMethodRecord`. It does not create a
   wallet authority, device identity, signer activation, client share, server
   share, public key, export root, or key manifest.
2. The new method references the exact active `WalletAuthorityId` authorized
   by the source method's fresh proof.
3. Adding a factor is a local reseal. It uses
   `WalletCustodySeedFromSealedEnvelopeV1` and never runs registration,
   recovery, custody re-establishment, signer derivation, rotation, or device
   linking.
4. Passkey and Email OTP have different verification boundaries and converge
   into one verified factor-addition input before persistence begins.
5. Server state and browser IndexedDB cannot share one transaction. The browser
   installs one pending local record set first. The server then activates the
   method in one transaction. The existing intent is the sole server-side
   resume record; R109A does not persist a second pending-method workflow in
   D1.
6. The existing authority, its activations, its revocation epoch, and every
   sibling auth method remain unchanged when a method is added or revoked.
7. A new method is never selected silently. The source Wallet Session remains
   selected after addition; the new method is exercised through an explicit
   lock and unlock or explicit method switch.
8. Revoking a method invalidates only sessions and local envelopes issued for
   that exact `WalletAuthMethodId`. It never revokes the shared authority.
9. Until a separate `manage_auth_methods` permission is designed, add and
   revoke operations require an active authority with the exact canonical
   `FULL_OWNER_PERMISSIONS` set. A signing-only or attenuated authority cannot
   escalate itself by adding a factor.
10. Runtime code never infers a method from `walletId`, auth kind, email hint,
    credential label, recent use, or record order. It resolves one exact
    branded `WalletAuthMethodId`.

## Explicitly out of scope

- creating a factor on a different device;
- mixed-method device linking, which belongs to R109B;
- changing an authority's permissions or signer families;
- transferring custody seed or signer material between devices;
- recovery-factor replacement or revoking the final active method;
- enterprise SSO;
- custom factor-management permissions;
- a generic ceremony, workflow, saga, projection, or migration framework;
- repairing corrupt or incomplete local material during unlock.

## Current state

The persistence layer can store several `wallet_auth_methods` rows, while the
operating lifecycle still assumes one effective factor family:

- `registration.addPasskey` supports only a Passkey source proof;
- its nominal Email OTP authorization branch terminates without a production
  implementation;
- no production `addEmailOtp` operation exists for an established wallet;
- registration chooses a Passkey wallet or Email OTP wallet;
- unlock and settings do not deliberately select among every exact active
  local method;
- current auth-method IDs are derived from factor fields in several paths;
- local projections and recent-account labels can influence method selection.

R109A replaces those assumptions. It does not preserve them as compatibility
branches in core code.

## Smallest domain model

R109A uses the R103E concepts without adding a durable aggregate.

```text
WalletAuthorityV1
  authorityId
  deviceId
  permissions
  exact signer activations
       ^
       |
       +-- WalletAuthMethodRecord: Passkey A
       +-- WalletAuthMethodRecord: Passkey B
       +-- WalletAuthMethodRecord: Email OTP A
```

All methods in this relation operate the same authority. Each method owns only
its factor-specific credential and sealed local access to that authority's
existing material.

### Authoritative ownership

| Fact | Authoritative owner |
| --- | --- |
| permissions, signer activations, device identity, authority lifecycle | `WalletAuthorityV1` from R103E |
| factor kind, credential identity, method lifecycle | `WalletAuthMethodRecord` |
| Passkey authenticator | existing Passkey authenticator store |
| verified Email OTP provider subject and email hash | existing Email OTP factor store |
| custody-seed envelope for one method | existing factor-sealed custody store |
| sealed access to existing local signer/export material | existing factor-sealed local material stores, keyed by authority, method, and activation/root identity |
| temporary addition progress | existing add-auth-method intent/ceremony record |
| runtime authorization | ordinary Wallet Session authorization store |

Do not add a multi-auth projection. Inventory joins the authority's auth
methods by `WalletAuthorityId`; local availability is derived from exact local
sealed records for each `WalletAuthMethodId`.

### Canonical identities

Reuse these R103E identities:

- `WalletId`;
- `WalletAuthorityId`;
- `DeviceId`;
- `WalletAuthMethodId`;
- `MpcMaterialActivationRef`;
- `WalletSessionAuthorizationId`.

Reuse the existing add-auth-method intent or ceremony identity. Add no second
intent ID for Email OTP. The server allocates one opaque
`WalletAuthMethodId` when it creates the intent and binds it to the wallet,
authority, device, source method, and target factor branch. A raw client cannot
nominate or replace it.

Add two narrow value brands because the observed code currently passes these
values as interchangeable strings:

- `NormalizedEmailAddressHashHex` accepts only the canonical hash encoding
  produced from a normalized verified email. It cannot be constructed from a
  masked hint, provider subject, challenge ID, or arbitrary digest.
- `AddAuthMethodIntentNonceB64u` accepts only the canonical base64url output
  and byte length produced by the existing secure-random intent nonce helper.

`EmailOtpProviderUserId` remains the provider identity; the email hash remains
verified matching metadata. The nonce is replay protection and never serves
as an intent, ceremony, method, session, or authority identity.

For the `email` provider, `providerUserId` comes from the consumed,
server-verified target grant. Browser code never derives it from the raw email,
masked hint, or email hash. The boundary parser must prove that the grant's
provider subject and normalized email hash describe the same verified target
before constructing the Email OTP branch.

New methods use the R103E opaque `wallet-auth-method:<random UUID>` format.
Derived `passkey:*` and `email_otp:*` formats remain boundary-only migration
inputs and are deleted after cutover.

Required active uniqueness constraints are:

- Passkey: `(scope, rp_id, credential_id)`;
- Email OTP: `(scope, wallet_authority_id, provider, provider_user_id)`;
- all methods: opaque `wallet_auth_method_id` primary key.

Here, `scope` is the existing server tenant/environment scope. It is never a
wallet ID or browser-local profile. `credential_id` and `provider_user_id` use
their existing branded domain types; normalized email and masked email remain
attributes rather than substitute identifiers.

Replace the current wallet-only `AddAuthMethodIntentV1` with one precise
versioned intent. Do not extend V1 with optional identity fields:

```ts
type AddAuthMethodTargetV2 =
  | {
      readonly kind: 'passkey';
      readonly rpId: WebAuthnRpId;
      readonly provider?: never;
      readonly requestedEmailHashHex?: never;
    }
  | {
      readonly kind: 'email_otp';
      readonly provider: 'email';
      readonly requestedEmailHashHex: NormalizedEmailAddressHashHex;
      readonly rpId?: never;
    };

type AddAuthMethodIntentV2 = {
  readonly version: 'add_auth_method_intent_v2';
  readonly walletId: WalletId;
  readonly walletAuthorityId: WalletAuthorityId;
  readonly deviceId: DeviceId;
  readonly sourceWalletAuthMethodId: WalletAuthMethodId;
  readonly sourceWalletSessionAuthorizationId: WalletSessionAuthorizationId;
  readonly sourceAuthorityDigestB64u: DigestB64u;
  readonly sourceAuthorityRevocationEpoch: number;
  readonly targetWalletAuthMethodId: WalletAuthMethodId;
  readonly target: AddAuthMethodTargetV2;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly nonceB64u: AddAuthMethodIntentNonceB64u;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};
```

The create-intent wire request is deliberately narrower than the durable
intent:

```ts
type CreateAddAuthMethodIntentRequestV2 = {
  readonly sourceWalletAuthMethodId: WalletAuthMethodId;
  readonly sourceWalletSessionAuthorizationId: WalletSessionAuthorizationId;
  readonly target:
    | { readonly kind: 'passkey'; readonly emailAddress?: never }
    | { readonly kind: 'email_otp'; readonly emailAddress: string };
};
```

`walletId` comes from the route. The request boundary accepts the raw email
only long enough to normalize and hash it. The Passkey RP comes from the
server's trusted configuration. A caller cannot submit an authority ID,
device ID, authority digest, revocation epoch, runtime scope, nonce, target
method ID, RP ID, provider subject, or timestamps.

R109A exposes email-code addition, so its Email OTP target provider is the
literal `email`. Existing Google-backed Email OTP methods remain valid source
methods. Adding a new Google identity method is a separate product operation
outside this refactor. The server derives the runtime scope, source authority
snapshot, expiry, nonce, and target method ID. The client selects the source
method and session; `start` proves that exact selection and rejects any stale
authority digest or epoch.

`AddAuthMethodIntentGrant` remains the sole opaque lookup and retry key.
`addAuthMethodCeremonyId` remains the factor-verification substage identity.
Do not add another operation ID. Once a client has the grant, every retry uses
the same intent. If the initial create response is lost, the unobserved intent
expires without a method or verifier commit; a new create may allocate a new
intent and target method ID safely.

A repeated finalize with the same intent returns the original method. An
attempt to add a credential already active under another method returns
`already_exists`; it does not create an alias or duplicate envelope. That
result carries no existing method ID. The caller refreshes the exact authority
inventory, which avoids disclosing a credential association from another
authority or tenant. Masked email text never participates in identity or
deduplication.

The uniqueness indexes apply to active methods. Re-adding a factor identity
after its prior method was revoked creates a fresh opaque method ID through a
fresh intent and target verification. It never reactivates or overwrites the
revoked audit record.

### Canonical auth-method factor fields

`WalletAuthMethodRecordV2` is the R103E common record and lifecycle combined
with exactly one factor branch. Implementers must update the shared type in
place. They must not create a second R109A record type.

| Branch | Required factor fields | Forbidden factor fields |
| --- | --- | --- |
| Passkey | `rpId: WebAuthnRpId`, `credentialIdB64u: WebAuthnCredentialIdB64u`, existing parsed credential-public-key value, non-negative authenticator `counter` | Email OTP provider, provider user, email hash |
| Email OTP | `provider: EmailOtpProvider`, `providerUserId: EmailOtpProviderUserId`, `emailHashHex: NormalizedEmailAddressHashHex` | RP ID, credential ID, credential public key, authenticator counter |

Use `never` fields to reject mixed branches. `registrationAuthorityId` is
ceremony provenance rather than durable factor identity. Keep that value on
the target-verification grant and audit event, then remove it from the
canonical V2 auth-method record. An existing V1 record may use it only while a
boundary parser proves and constructs the V2 provider identity.

### Auth-method lifecycle

Use the generic R103E auth-method lifecycle:

```ts
type WalletAuthMethodLifecycleV1 =
  | {
      readonly status: 'pending_local_install';
      readonly activatedAtMs?: never;
      readonly revokedAtMs?: never;
    }
  | {
      readonly status: 'active';
      readonly activatedAtMs: number;
      readonly revokedAtMs?: never;
    }
  | {
      readonly status: 'revoked';
      readonly activatedAtMs: number;
      readonly revokedAtMs: number;
    };
```

R103E's device-linking path and R109A factor-addition path both use
`pending_local_install`. For R109A this branch is stored in IndexedDB only;
the server's canonical auth-method row first appears as `active` in the final
transaction. R103E may persist the branch with its new pending Device 2
authority because that flow coordinates a separate device and signer workers.
Do not add `pending_authority_activation`, `pending_factor_addition`, `paused`,
or factor-specific lifecycle branches. The containing R109A authority remains
active while the local method is pending.

Lifecycle states do not own operation receipts or package digests. R103E's
pending authority owns its link package-set digest. R109A's existing
add-auth-method intent owns the expected local-record-set digest, while the
IndexedDB installation receipt owns the observed digest. The auth method
stores only its lifecycle and factor identity, which prevents the same resume
fact from being represented in two server records.

Pending methods cannot unlock, issue a Wallet Session, authorize step-up, or
appear as usable in settings. Active methods require an active referenced
authority and a complete exact local record set.

### Verified source and target branches

The method authorizing the operation and the method being added are distinct.
Use exhaustive, versioned unions with factor-specific proof fields:

```ts
type VerifiedFactorAdditionSourceV1 = {
  readonly kind: 'verified_factor_addition_source_v1';
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly deviceId: DeviceId;
  readonly sourceAuthMethodId: WalletAuthMethodId;
  readonly sourceSessionAuthorizationId: WalletSessionAuthorizationId;
  readonly authorityDigestB64u: DigestB64u;
  readonly authorityRevocationEpoch: number;
  readonly proof:
    | { readonly kind: 'passkey'; readonly assertion: VerifiedPasskeyOwnerAssertionV1 }
    | { readonly kind: 'email_otp'; readonly grant: VerifiedEmailOtpOwnerGrantV1 };
  readonly verifiedAtMs: number;
};

type VerifiedNewWalletFactorV1 =
  | {
      readonly kind: 'verified_new_passkey_factor_v1';
      readonly authMethod: PasskeyWalletAuthMethodDraftV1;
      readonly registration: VerifiedPasskeyRegistrationV1;
      readonly verificationDigestB64u: DigestB64u;
    }
  | {
      readonly kind: 'verified_new_email_otp_factor_v1';
      readonly authMethod: EmailOtpWalletAuthMethodDraftV1;
      readonly grant: VerifiedEmailOtpFactorGrantV1;
      readonly verificationDigestB64u: DigestB64u;
    };
```

The names of existing verified proof values should be reused when they already
carry these exact guarantees. Do not create wrappers that merely rename an
existing verified value. Raw route bodies are parsed once into these branches;
core code never accepts an optional proof bag.

The source boundary verifies:

1. Wallet Session wallet, authority, and auth-method IDs;
2. active source method and active referenced authority;
3. exact authority digest and revocation epoch;
4. exact `FULL_OWNER_PERMISSIONS`;
5. source proof freshness, purpose, operation digest, and one-use status;
6. source method, authority, and device all belong to the selected local
   installation.

The target boundary verifies:

- the server-issued target `WalletAuthMethodId` and intent digest;
- exact wallet, authority, device, and target factor kind;
- Passkey RP, challenge, credential ID, public key, and registration result;
- or Email OTP provider subject, normalized email hash, challenge, expiry,
  attempt budget, and one-use grant;
- no fields from the other factor branch.

## One linear factor-addition flow

The public operation is one typed function after source and target
verification:

```ts
type VerifiedAddWalletAuthMethodInputV1 = {
  readonly kind: 'verified_add_wallet_auth_method_input_v1';
  readonly intent: AddAuthMethodIntentV2;
  readonly source: VerifiedFactorAdditionSourceV1;
  readonly target: VerifiedNewWalletFactorV1;
};

async function addWalletAuthMethod(
  input: VerifiedAddWalletAuthMethodInputV1,
): Promise<AddWalletAuthMethodResultV1> {
  const receipt = await prepareAndInstallPendingWalletAuthMethod(input);
  const active = await activateInstalledWalletAuthMethod(receipt);
  await finalizeLocalWalletAuthMethod(active);
  return active;
}
```

The implementation exhaustively switches over each result before calling the
next function. The successful branch has these steps.

### 1. Create and bind the intent

The server creates one add-auth-method intent and allocates the target
`WalletAuthMethodId`. The immutable intent binds:

- wallet, authority, device, and source auth-method IDs;
- target factor kind;
- operation nonce and digest;
- issue and expiry times;
- one-use state.

A retry returns the same intent and target method ID. A request with different
immutable fields returns a conflict.

### 2. Verify source and target factors

Obtain a fresh source-owner proof. Then create or verify the target factor.
These are separate security actions even when both branches use the same
factor family.

Interaction budget:

| Source | Added factor | Required user actions |
| --- | --- | --- |
| Passkey | Passkey | one source assertion and one target credential creation |
| Passkey | Email OTP | one source assertion and one target email-code verification |
| Email OTP | Passkey | one source email-code verification and one target credential creation |
| Email OTP | Email OTP | one source email-code verification and one target email-code verification |

Do not trigger either action twice. Adding the same active credential or exact
Email OTP provider identity is rejected as `already_exists`.

### 3. Reseal and install the pending local record set

Inside the existing custody worker:

1. open the source method's authenticated custody envelope;
2. produce `WalletCustodySeedFromSealedEnvelopeV1`;
3. seal the same custody seed under the verified target factor;
4. reseal access to every existing local signer activation owned by the
   authority under the target factor;
5. reseal the existing Ed25519 Yao Client export root when that authority has
   Ed25519 plus `export_keys`;
6. return opaque sealed records and exact public identities/digests.

The operation does not derive signer roots, create shares, contact signer
workers, or modify `WalletAuthorityV1`. JavaScript receives no custody seed,
PRF output, OTP factor secret, client share, or export root.

The prepared record-set digest covers the target auth-method ID, authority and
device IDs, custody envelope identity, every exact activation ref and sealed
record digest, the optional export-root identity and digest, and the target
verification digest in canonical order.

The custody worker output is written immediately by one IndexedDB transaction:

- the pending auth-method record;
- its factor-sealed custody envelope;
- factor-sealed access records for every existing authority activation;
- the factor-sealed Ed25519 export root when required;
- one installation receipt keyed by target `WalletAuthMethodId` and intent
  grant.

The transaction either installs the complete record set and receipt or writes
nothing. The pending record is invisible to unlock, Wallet Session issuance,
step-up, export, linking, and ordinary settings inventory.

The receipt shape is fixed:

```ts
type LocalAuthMethodInstallReceiptV1 = {
  readonly kind: 'local_auth_method_install_receipt_v1';
  readonly intentGrant: AddAuthMethodIntentGrant;
  readonly walletId: WalletId;
  readonly walletAuthorityId: WalletAuthorityId;
  readonly deviceId: DeviceId;
  readonly sourceWalletAuthMethodId: WalletAuthMethodId;
  readonly targetWalletAuthMethodId: WalletAuthMethodId;
  readonly targetFactorKind: AddAuthMethodTargetV2['kind'];
  readonly sourceAuthorityDigestB64u: DigestB64u;
  readonly sourceAuthorityRevocationEpoch: number;
  readonly targetVerificationDigestB64u: DigestB64u;
  readonly localRecordSetDigestB64u: DigestB64u;
  readonly installedAtMs: number;
};
```

The receipt contains no credential secret or unsealed key material. The target
factor ceremony binds the receipt digest to its verified grant. Retry reads
the receipt and complete pending record set by exact intent and method IDs;
the server never stores or reconstructs browser ciphertext.

The receipt proves binding and consistency; it cannot prove to the server that
IndexedDB is physically durable. The local-first order prevents ordinary crash
recovery from activating an unusable method. A malicious browser can lie about
its own local install and make only that new method unusable; it cannot change
the shared authority, sibling methods, signer activations, or server secrets.

### 4. Activate in one server transaction

The server revalidates the still-active source session, method, authority
digest, revocation epoch, permissions, source proof, intent, target proof, and
receipt. It then performs one D1 transaction that:

- inserts the target factor-specific auth method directly as `active`;
- inserts or activates its factor verifier/authenticator;
- consumes the target verification grant;
- writes the factor-addition audit event;
- marks the intent complete.

Credential uniqueness is checked in this transaction. The transaction changes
no authority, signer activation, sibling method, or source Wallet Session. An
exact retry returns the stored active method and completion digest. A changed
receipt, proof, target factor, or immutable intent field returns
`integrity_error`.

R109A creates no pending D1 auth-method row and no server copy of the opaque
sealed local record set. This ordering eliminates a state where D1 promises a
resumable install after the only copy of the browser ciphertext was lost.

### 5. Finalize locally

The browser's final IndexedDB transaction replaces the pending local method
with the exact active method returned by the server, retains the sealed
records, deletes the receipt and temporary intent state, and leaves the
currently selected source method and Wallet Session unchanged. If this
transaction is interrupted, reload resolves the completed intent by its exact
grant and repeats only this local state transition.

No Wallet Session is issued automatically for the new method. Its first
explicit selection and successful unlock issues its first ordinary Wallet
Session. This prevents factor addition from silently changing the active
authorization.

## Retry, cancellation, and typed results

| Interruption | Required behavior |
| --- | --- |
| before IndexedDB install | cancel or retry the same intent; consume temporary challenges on cancellation |
| during IndexedDB install | transaction aborts; retry the same preparation for the exact intent |
| after local install, before server activation | read and resubmit the exact local receipt |
| source proof or Wallet Session expires before activation | keep the intent and receipt, obtain one fresh proof from the same source method, and retry |
| target proof expires before activation | close the intent, delete the exact pending local record set, and restart with a new intent and target verification |
| during server activation transaction | transaction aborts completely or commits the one active method |
| after server activation, before response | return the same active method; never consume the grant twice |
| after server activation, before final local transaction | fetch exact active result by intent and finalize locally |

Before server activation, cancellation deletes temporary challenges and
worker handles, closes the intent, and deletes matching pending local records
by exact intent and method IDs. There is no server auth-method row to revoke.
It never touches the authority or source method.

An `already_exists` result discovered by the activation transaction performs
the same exact local pending-record cleanup after the server closes the intent.
The existing active method remains unchanged and the target proof cannot be
reused.

After server activation, cancellation is impossible. Retry converges on the
same active method. Any mismatch in wallet, authority, device, method, intent,
factor branch, record-set digest, or verification digest returns
`integrity_error`.

```ts
type AddFactorAuthorizationFailureV1 =
  | 'source_reauthorization_required'
  | 'source_binding_invalid'
  | 'source_method_inactive'
  | 'authority_inactive'
  | 'authority_snapshot_changed';

type TargetFactorFailureV1 =
  | 'passkey_registration_rejected'
  | 'email_code_invalid'
  | 'email_code_expired'
  | 'email_code_attempts_exhausted'
  | 'target_factor_binding_invalid';

type AddFactorIntegrityFailureV1 =
  | 'intent_binding_mismatch'
  | 'local_receipt_binding_mismatch'
  | 'local_record_set_incomplete';

type AddWalletAuthMethodResultV1 =
  | {
      readonly kind: 'active';
      readonly authMethod: Extract<
        WalletAuthMethodRecord,
        { readonly status: 'active' }
      >;
    }
  | {
      readonly kind: 'resume_required';
      readonly stage: 'server_activation' | 'local_finalization';
      readonly authMethodId: WalletAuthMethodId;
      readonly recordSetDigestB64u: DigestB64u;
    }
  | { readonly kind: 'already_exists' }
  | { readonly kind: 'cancelled' }
  | { readonly kind: 'expired' }
  | { readonly kind: 'unauthorized'; readonly reason: AddFactorAuthorizationFailureV1 }
  | { readonly kind: 'forbidden'; readonly reason: 'full_owner_permission_required' }
  | { readonly kind: 'target_verification_failed'; readonly reason: TargetFactorFailureV1 }
  | { readonly kind: 'integrity_error'; readonly reason: AddFactorIntegrityFailureV1 };
```

UI behavior switches on `kind`. Message strings and diagnostics never drive
control flow.

`resume_required` is an operation result, not an auth-method lifecycle state.
At `server_activation`, the exact local record set is installed and the server
method is absent. At `local_finalization`, the server method is active and the
local record still has `pending_local_install`. Reload resumes by the intent
grant and exact target method ID.

If the source proof or Wallet Session expires after local installation, the
operation returns `unauthorized` with
`source_reauthorization_required`. The browser keeps the same intent and local
receipt, obtains one fresh proof from the same source method, and retries
activation. A revoked source method, changed authority digest, changed
revocation epoch, or changed permission set cancels the intent and deletes the
exact pending local record set. Those changes cannot be rebound to the old
intent.

A target proof cannot be refreshed in place because its verification digest
is part of the installed record-set binding. Expiry or exhaustion of the
target proof deletes the exact pending set and requires a fresh intent. This
prevents one target credential or OTP grant from being mixed with another
attempt.

### Route and public API contract

Reuse the existing route family and service. Do not add factor-specific route
stacks or a second finalizer:

- `POST /wallets/:walletId/auth-methods/intent` allocates and binds the one
  intent and target method ID;
- `POST /wallets/:walletId/auth-methods/start` verifies the exact source
  authority and begins the selected target-factor branch;
- `POST /wallets/:walletId/auth-methods/finalize` validates the target result
  and local installation receipt, then activates the method;
- `POST /wallets/:walletId/auth-methods/revoke` revokes one exact active
  method.

Each route has one input owner:

| Route | Caller supplies | Server derives or verifies |
| --- | --- | --- |
| `intent` | source method ID, source Wallet Session ID, target kind, raw email only for Email OTP | route wallet, authority, device, RP, provider, normalized email hash, authority snapshot, scope, nonce, expiry, target method ID |
| `start` | intent grant, intent digest, fresh source proof | exact source session/method/authority binding and one factor-specific target challenge |
| `finalize` | intent grant, target ceremony result, exact local installation receipt | target proof, credential uniqueness, unchanged source authority snapshot, active method commit |
| `revoke` | target method ID and fresh proof from a different source method | same active authority, full-owner permission, remaining-method invariant, exact session invalidation |

Boundary parsers construct the narrow verified unions once. Core services do
not accept the raw create request, route wallet string, optional proof bags, or
client-supplied copies of server-owned identity fields.

The public SDK keeps `registration.addPasskey` and adds
`registration.addEmailOtp`. Both are thin typed entry points into the same
factor-addition operation. They may prepare different target proofs; they may
not own separate persistence, activation, retry, or session code.

Boundary failures map consistently:

| HTTP | Typed result |
| --- | --- |
| `400` | malformed boundary input or `target_verification_failed` |
| `401` | missing, expired, or invalid Wallet Session/source proof |
| `403` | `forbidden` for a valid authority without exact management permission |
| `409` | `already_exists`, immutable client retry conflict, or request/receipt binding mismatch |
| `410` | `expired` or `cancelled` intent |
| `503` | required existing custody or local-install dependency unavailable before commit |
| `500` | unexpected internal failure only |

The browser parses the response once into `AddWalletAuthMethodResultV1` and
switches exhaustively. Route codes, error strings, and diagnostic stages do
not become a second lifecycle model.

A disagreement discovered while parsing already-durable server state is an
unexpected internal integrity failure and maps to `500`. It does not share the
client-facing `409` branch or trigger repair.

### Persistence schema delta

Update the existing D1 `wallet_auth_methods` table in place. The canonical V2
columns are:

- tenant scope columns and `wallet_auth_method_id` as the primary key;
- required `wallet_id` and `wallet_authority_id`;
- `kind`, `status`, `created_at_ms`, `activated_at_ms`, `updated_at_ms`, and
  nullable `revoked_at_ms` constrained by the lifecycle union;
- Passkey-only `rp_id`, `credential_id_b64u`, credential public key, and
  counter;
- Email-OTP-only `provider`, `provider_user_id`, and `email_hash_hex`;
- exact canonical `record_json`, checked against the indexed identity and
  lifecycle columns.

Delete `auth_identifier_key`, factor-derived method-ID checks, and
`registration_authority_id` after boundary cutover. Use the factor-specific
unique indexes defined under **Canonical identities**. A direct lookup by
opaque method ID plus an inventory index on `(scope, wallet_authority_id,
status)` replace wallet-wide candidate scans.

IndexedDB stores the same V2 method under `(walletId, walletAuthorityId,
walletAuthMethodId)`. Delete the current derived compound key and the separate
`localStatus` lifecycle. The method's discriminated `status` is sufficient.
Factor-sealed custody, signer-activation access, and export-root records keep
their existing stores and gain required exact authority and auth-method keys
where absent. The installation receipt is keyed by `(intentGrant,
walletAuthMethodId)` and exists only while the local method is pending.

No new table stores a multi-auth projection, prepared ciphertext, signer
coverage, or copied authority fields. D1 inventory joins methods to the one
authority record. IndexedDB availability checks exact sealed records against
that authority's signer activation set.

## Unlock and Wallet Sessions

Unlock begins with one explicit locally installed `WalletAuthMethodId`:

```text
selected WalletAuthMethodId
  -> exact active WalletAuthMethodRecord
  -> exact active WalletAuthorityV1
  -> verify selected factor
  -> open that method's sealed local records
  -> issue ordinary Wallet Session for that method and authority
```

The Wallet Session records the exact auth-method ID, shared authority ID,
authority digest, revocation epoch, and capability subjects. Sibling methods
can issue separate sessions for the same authority. Revoking one method
invalidates only sessions whose `authMethodId` matches it.

Every Wallet Session admission resolves the exact `authMethodId` and requires
that method to remain active in addition to checking the authority digest and
revocation epoch. Method revocation deliberately leaves the shared authority
epoch unchanged, so authority validation alone cannot admit a session.

An explicit durable lock remains authoritative across refresh. Lock generation
from R103E prevents stale unlock, factor-addition, or warm-session work from
publishing an unlocked runtime. R109A adds no second rehydration path.

Ordinary signing, export, linking, and device administration resolve the same
authority and activations regardless of which active method issued the
session. Step-up always verifies the session's exact selected method and is
scoped to its exact operation. Proof from one method cannot satisfy step-up for
a session issued through a sibling method.

## Method inventory, selection, and revocation

The settings surface lists auth methods for the selected authority. Server
records provide identity, factor kind, lifecycle, and approved display hint.
IndexedDB determines whether each active method is locally usable.

Supported display states are:

- `active_local` — server active with a complete local record set;
- `active_unavailable` — server active with no complete local record set;
- `pending_local_install` — shown only inside its resumable addition flow;
- `revoked` — optional audit/history display, never selectable.

There is no `paused` state. An active method with corrupt or incomplete local
material returns a typed `local_material_unavailable` or `relink_required`
result. Unlock never scans for a sibling method or repairs it automatically.

Selection requires an explicit user action. Labels and masked email hints are
display data. They are never authority inputs.

Revocation requires fresh proof from a different active local method attached
to the same full-owner authority. The method being revoked cannot authorize
its own revocation. The server transaction:

1. verifies at least one other active method will remain;
2. marks the exact target method and its verifier/authenticator revoked;
3. invalidates Wallet Sessions issued through that method;
4. writes the audit event.

Local cleanup deletes only records keyed by the revoked auth-method ID. If
cleanup fails, server admission still rejects the method. The authority,
signer activations, source method, sibling methods, and their sessions remain
unchanged. Revocation of the final active method is refused; recovery
replacement is outside R109A.

## Product behavior

### Add Email OTP

From an unlocked full-owner wallet:

1. Open **Authentication methods**.
2. Select **Add email code** and enter an email address.
3. Complete fresh source-method authorization.
4. Verify the code for the new email identity.
5. Complete the linear factor-addition flow.
6. Show the new method as active without changing the selected session.

Raw email is normalized once at the request boundary. Core records retain the
verified provider identity and email hash. The server supplies the masked
display hint; masked text is never compared for identity or authorization.

### Add Passkey

From an unlocked full-owner wallet:

1. Open **Authentication methods**.
2. Select **Add passkey**.
3. Complete fresh source-method authorization.
4. Create exactly one target Passkey with server-issued RP and challenge
   options.
5. Complete the linear factor-addition flow.
6. Show the new method as active without changing the selected session.

Passkey-to-Passkey and Email-OTP-to-Passkey use the same target branch. Source
factor kind changes only the fresh source proof.

## Relationship to R103E and R109B

R103E must land first and provide:

- `WalletAuthorityV1` and opaque `WalletAuthorityId`;
- generic `pending_local_install | active | revoked` auth-method lifecycle;
- exact auth-method-to-authority resolution;
- ordinary Wallet Session issuance and step-up;
- durable lock generation;
- exact authority and local-material readers.

R109A adds methods only to one existing authority on one device. It does not
reuse R103E's link session, one-use Device 2 recipient, encrypted export-root
transport, worker-share provisioning, or new-authority activation.

R109B may then use any active R109A source method to authorize a separate new
Device 2 authority. R109B's target method is attached to that new authority,
not to Device 1's authority. R109A methods on Device 1 remain unchanged.

The currently planned R109B document must be reconciled with this seam before
R109B implementation. In particular, R109B must delete any requirement that:

- reuses R109A's same-device factor-addition finalizer to create Device 2's
  target method;
- treats a Device 1 Email OTP method as Device 2's target credential or
  canonical authority;
- transfers the wallet custody seed to Device 2;
- creates a factor-specific owner-authority model or linked-lane selection
  model beside R103E.

R109B may reuse R109A's exact source-method authorization boundary and target
factor verification adapters. Its successful path still creates a new R103E
authority, auth method, signer activations, and permission-derived export
material for Device 2 through R103E's linear activation. This is reuse of
verified inputs, not reuse of R109A persistence or activation.

## Implementation phases

### Single implementation map and merge order

One workstream owns each concern. Other workstreams import its symbols and do
not define equivalents.

| Workstream | Exclusive responsibility | Canonical locations |
| --- | --- | --- |
| Contract | shared brands, records, lifecycle unions, request/result parsers, branch builders, type fixtures | `packages/shared-ts/src/utils/registrationIntent.ts`, `packages/shared-ts/src/utils/addAuthMethodRegistration.ts`, canonical R103E authority module, `tests/typecheck/` |
| Browser operation | the single `addWalletAuthMethod` orchestrator, Passkey/Email target adapters, custody-worker reseal call, IndexedDB pending install/finalization, public SDK entry points | `packages/wallet/src/SeamsWeb/operations/authMethods/`, existing custody workers and local repositories, `packages/wallet/src/SeamsWeb/publicApi/` |
| Server operation | existing route parsers, intent service, source/target verification, one activation transaction, inventory and revocation persistence | existing wallet auth-method routes, `d1WalletAuthMethodService.ts`, `d1WalletAuthMethodBoundary.ts`, existing verifier stores |
| Product verification | explicit method selection UI, unlock/session integration, settings inventory/revocation, real intended-behaviour browser coverage | existing auth menu, account settings, login/session operations, `tests/e2e/intended-behaviours/` |

Merge Phase 1 contract changes first. Browser and server work may then proceed
in parallel against those exact symbols. Product integration begins after the
browser operation and server activation result compile together. Shared
contract changes discovered later return to the Contract workstream; another
workstream must not add a local copy, temporary optional field, compatibility
union, or alternate result enum.

There is exactly one orchestration function, one intent service, one server
activation transaction, and one local installation receipt. Factor adapters
end when they produce `VerifiedNewWalletFactorV1`. They do not persist methods,
activate server state, issue Wallet Sessions, or own retries.

### Phase 1 — Reconcile the shared contract

- update R103E's auth-method pending branch to generic
  `pending_local_install`;
- make `WalletAuthMethodRecord.walletAuthorityId` required;
- replace Passkey-shaped add-auth-method inputs with the two verified unions;
- bind the server-allocated target method ID into the existing intent;
- add branch-specific builders and exhaustive boundary parsers;
- add type fixtures for ID swaps, mixed factor fields, authority changes, and
  invalid lifecycle states;
- delete dead authorization branches after callers migrate.

Primary locations:

- `packages/shared-ts/src/utils/registrationIntent.ts`
- `packages/shared-ts/src/utils/addAuthMethodRegistration.ts`
- the canonical R103E wallet-authority/auth-method module
- request parsers beside their existing add-auth-method routes
- `tests/typecheck/` and existing shared typecheck fixtures

Exit: the compiler rejects an unverified target, a factor-branch mismatch, a
new authority/device identity, and a method record without its exact authority.

### Phase 2 — Implement the single linear operation

- make both factor branches produce `VerifiedNewWalletFactorV1`;
- implement custody and existing-local-material reseal inside the worker;
- implement idempotent local pending installation, one server activation
  transaction, and final local commit;
- preserve source authority, source method, source session, and signer records;
- expose typed retry, cancellation, duplicate, and integrity results;
- add `registration.addEmailOtp` beside the existing public operation;
- make existing `registration.addPasskey` call the shared operation.

Primary locations:

- `packages/wallet/src/SeamsWeb/operations/authMethods/`
- `packages/wallet/src/SeamsWeb/publicApi/registration.ts`
- `packages/wallet/src/SeamsWeb/publicApi/types.ts`
- existing custody/passkey and Email OTP workers
- existing wallet auth-method D1 service and add-auth-method routes
- existing IndexedDB auth-method and sealed-material stores

Exit: all four source/target factor combinations activate one new method with
the original authority, device, and activation refs unchanged, and no pending
R109A auth-method row or sealed local payload stored in D1.

### Phase 3 — Unlock, inventory, and revocation

- list exact server methods plus exact local availability;
- require explicit method selection;
- issue sessions through the selected method and shared authority;
- revoke one exact method using a different active method's fresh proof;
- reject final-method revocation;
- remove recent-record, auth-kind, and first-record inference;
- preserve durable lock behavior across refresh and pending addition retries.

Primary locations:

- `packages/wallet/src/react/components/AccountMenuButton/`
- `packages/wallet/src/SeamsWeb/walletIframe/host/auth-menu/`
- `packages/wallet/src/SeamsWeb/operations/auth/login.ts`
- existing authorization/session services
- existing IndexedDB and D1 auth-method stores

Exit: either active local method can unlock explicitly, and revoking either
method leaves the sibling method and authority operational.

### Phase 4 — Delete obsolete paths and verify

- delete derived-ID builders after data cutover;
- delete Passkey-only authorization and finalize branches;
- delete `LocalWalletAuthMethodRecord.localStatus` and derived IndexedDB
  method keys;
- delete projections and recent-account inference used as authority;
- delete inline fixtures that assume one method per wallet;
- update `docs/intended-behaviours.md`;
- run the real browser matrix below.

Exit: one factor-addition path remains, core code has no compatibility branch,
and the operating matrix passes without mocked lifecycle transitions.

## Required verification

Use a fresh wallet and clean browser profile for every source-factor case.
Run all four additions against Ed25519-only, ECDSA-only, and both-family
wallets:

| Existing selected method | Added method |
| --- | --- |
| Passkey | Passkey |
| Passkey | Email OTP |
| Email OTP | Passkey |
| Email OTP | Email OTP using a different verified provider identity |

For every applicable cell:

1. add exactly one method and assert the original authority ID, device ID,
   activation refs, authority digest, revocation epoch, and source method are
   unchanged;
2. assert the target has a new opaque method ID and complete factor-specific
   local records for exactly the authority's present signer families;
3. lock and unlock explicitly with the source method;
4. lock and unlock explicitly with the new method;
5. sign through every present signer family under each method;
6. export every present family with one fresh step-up from the exact selected
   method per export;
7. reload while locked and prove neither method auto-unlocks;
8. revoke the new method using the source method and prove the source method
   still unlocks and operates;
9. reject self-revocation and final-method revocation;
10. repeat finalize after a lost response and prove the method, verifier,
    envelope, and local record counts do not increase;
11. interrupt at every boundary in the retry table and prove convergence or
    complete precommit cleanup;
12. attempt to add the same Passkey credential or Email OTP provider identity
    twice and assert `already_exists` without duplicate records.

External email delivery and chain RPC may be stubbed at their network
boundaries. Auth-method intents, source proofs, target verification, custody
reseal, IndexedDB installation, D1 lifecycle, unlock, Wallet Sessions, step-up,
and revocation must use the real composed production path.

## Delete during cutover

- one-method-per-wallet selection and assertions;
- the factor-specific `WalletAuthAuthority` aggregate/ref model after its
  credential fields move to `WalletAuthMethodRecord` and authorization uses
  `WalletAuthorityId` plus `WalletAuthMethodId`; retain existing factor-proof
  primitives whose semantics are verification, and rename them if their old
  authority name becomes misleading;
- factor-derived canonical auth-method ID builders;
- dead `AddPasskeyAuthorization.email_otp` handling;
- Passkey-only add-auth-method request/finalize shapes;
- local projections used as server authority;
- wallet-wide and auth-kind candidate scans;
- repair-on-unlock behavior for incomplete methods;
- mocked factor-addition success transitions;
- fixtures and source guards that encode any removed behavior.

Compatibility parsing is allowed only at request and persistence boundaries
during the cutover. Incomplete legacy methods return `relink_required` or must
be re-added. Core operations never synthesize authority relationships,
envelopes, or signer coverage.

### Data cutover rule

Do not build a general migration subsystem. After R103E has established the
canonical authority for an installation, a boundary parser may convert a
complete existing auth method by attaching that exact authority ID and
preserving its factor credential identity. A record that cannot prove one
exact authority, factor identity, and complete local envelope set is rejected
as `relink_required`; it is never guessed from wallet ID, auth kind, email
hint, or record order.

Development and staging data may be reset. Any production conversion is a
one-time boundary operation with an explicit deletion checkpoint for its
parser and derived-ID inputs. New writes use only the R109A form from the
first implementation commit.

## Constraints against overengineering

1. Add no durable aggregate beyond `WalletAuthMethodRecord`.
2. Add no new signer, authority, device, export, or session model.
3. Use one factor-addition function after verified factor boundaries.
4. Keep factor differences inside verification and sealing adapters.
5. Persist only states required to resume after reload.
6. Prefer deleting same-family branches over wrapping them.
7. Use existing stores and routes unless they cannot express the normative
   lifecycle.
8. Require one behavioral test per matrix cell instead of source-text policy
   guards.
9. Finish the successful operating path before adding secondary guardrails.
10. If an implementation needs a second answer to “which authority does this
    method operate?”, stop and simplify it.

## Handoff checklist

1. Land or rebase onto R103E first.
2. Record current add-auth-method routes, types, stores, and behavioral tests.
3. Land shared union/lifecycle changes and type fixtures without runtime
   adapters.
4. Implement one successful Passkey-to-Email-OTP path end to end.
5. Add the other three factor combinations through the same operation.
6. Add exact unlock and Wallet Session selection.
7. Add method inventory and revocation.
8. Add only the specified interruption and deduplication behavior.
9. Delete the obsolete paths and fixtures listed above.
10. Run the real browser matrix and inspect exact IDs and record counts.

Checkpoint commits should separate shared contracts, factor reseal and
activation, unlock/session selection, inventory/revocation, behavioral tests,
and legacy deletion.

## Completion criteria

R109A is complete when:

- one active authority owns several independently revocable auth methods;
- every method references the same exact authority and device;
- factor addition changes no signer or authority material;
- Passkey and Email OTP converge after their verified boundaries;
- pending installation resumes without duplicate methods or envelopes;
- explicit lock survives refresh;
- every active local method can unlock and issue its own ordinary Wallet
  Session;
- step-up uses the exact selected method;
- revoking one method leaves the authority and sibling methods operational;
- final-method revocation is refused;
- obsolete one-method, per-factor-authority, projection, inference, and mocked
  paths are deleted;
- the real four-combination browser matrix passes.
