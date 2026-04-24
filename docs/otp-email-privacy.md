# Email OTP NEAR Account ID Privacy

## Problem

Email OTP registration currently creates NEAR account IDs that encode the user's
email address into the public onchain account name.

Example:

```text
n6378056-gmail-com-1776502017920.w3a-relayer.testnet
```

This leaks personally identifiable information onchain. NEAR account IDs are
public, permanent, indexable, and difficult to rename. Any account ID derived
from a raw email address can be scraped and correlated across applications,
wallet activity, and future identity leaks.

This should be fixed before real customer wallets are created.

## Goals

- Do not expose raw emails in NEAR account IDs.
- Avoid account IDs that are reversible through dictionary attacks.
- Keep account IDs short enough to be readable and valid on NEAR.
- Support Email OTP, Google/OIDC, and future hosted auth providers.
- Use deterministic account ID generation so accounts can be recovered from a
  verified identity without relying only on a server-side account-name mapping.
- Keep generated account IDs human-readable.
- Keep the implementation simple for local development.
- Make this a breaking change; do not preserve legacy email-derived account ID
  generation.

## Non-Goals

- This does not hide transaction metadata once a user publicly shares their
  account ID.
- This does not implement private payments or chain-level privacy.
- This does not migrate already-created real user accounts. There should be no
  real customer accounts yet; development accounts can be recreated.
- This does not change threshold signing cryptography.
- This does not define Email OTP signing-secret recovery. Deterministic account
  ID recovery from verified identity is separate from recovering device-local
  enrollment escrow `enc_s(S)`, which requires the recovery-key
  model in `otp-restore-threshold-property.md`.

## Threat Model

### Raw Email In Account ID

Raw email-derived account IDs leak the email directly.

```text
n6378056-gmail-com-1776502017920.w3a-relayer.testnet
```

Impact:

- public identity leakage;
- permanent onchain correlation;
- easy scraping by relayer root account;
- possible phishing targeting;
- poor privacy posture for wallet-as-a-service customers.

### Plain Hash Of Email

Plain hashes are not sufficient.

```text
u_<sha256(email)>.<relayer_root_account>
```

Emails are low-entropy. Attackers can brute-force common email lists and compare
hashes. A plain hash only hides the email cosmetically.

### Keyed Hash Of Email Or Provider Subject

A keyed hash is much better:

```text
slug = HMAC_SHA256(ACCOUNT_ID_DERIVATION_SECRET, context)
```

Observers cannot brute-force emails without the derivation secret. However, the
derivation secret becomes a durable secret. If the secret is lost,
deterministic regeneration is lost. If the secret is compromised, historical
slugs become brute-forceable against candidate identity lists.

### Deterministic Readable Slug

A deterministic readable slug uses a keyed HMAC as seed material, then maps that
seed into a safe word list and random-looking suffix.

```text
brisk-maple-k7q9yh.w3a-relayer.testnet
```

This keeps account IDs human-readable while avoiding raw email leakage. The
public account ID is still derived from identity, but only through a secret
HMAC. Observers cannot verify candidate emails unless the HMAC secret leaks.

### Random Opaque Slug

A random opaque slug leaks the least:

```text
u_<random_slug>.<relayer_root_account>
```

The mapping from email/auth identity to account ID is held in application state.
This has the strongest privacy properties because the onchain account ID is not
derived from the email at all, but account recovery requires durable server-side
mapping or user-provided account IDs.

## Recommendation

Use deterministic HMAC-generated readable account slugs by default.

Example:

```text
brisk-maple-k7q9yh.w3a-relayer.testnet
```

Properties:

- no raw email leakage;
- no public dictionary attack unless the account ID HMAC secret leaks;
- deterministic recovery from verified identity;
- human-readable public account IDs;
- deterministic separation across projects and environments;
- works for Email OTP and OIDC accounts.

Derive the slug from a keyed HMAC:

```ts
context = [
  'near_account_slug_v1',
  projectId,
  envId,
  authProvider,
  providerSubject ?? verifiedEmail,
].join('\0');

seed = HMAC_SHA256(ACCOUNT_ID_DERIVATION_SECRET, context);
```

Map the seed into the account name:

```ts
adjective = adjectives[seedWord(seed, 0) % adjectives.length];
noun = nouns[seedWord(seed, 1) % nouns.length];
suffix = base36(seed).slice(0, 6);
accountId = `${adjective}-${noun}-${suffix}.${relayerRootAccount}`;
```

The internal identity-to-account mapping should still be stored durably as an
index/cache:

```ts
type HostedAccountIdentityLink = {
  walletId: string;
  projectId: string;
  envId: string;
  authProvider: 'email_otp' | 'google_oidc' | string;
  providerSubject?: string;
  verifiedEmail?: string;
  nearAccountId: string;
  createdAt: string;
};
```

This mapping improves lookup, analytics, support, and duplicate registration
handling, but deterministic HMAC derivation remains the recovery path if the
mapping is lost.

For local development, it is acceptable to log or show the mapping. The public
NEAR account ID should still never include raw email.

## Account ID Format

Use this format for hosted Email OTP/OIDC-created NEAR accounts:

```text
<adjective>-<noun>-<suffix>.<relayer_root_account>
```

Example:

```text
brisk-maple-k7q9yh.w3a-relayer.testnet
```

Slug requirements:

- lowercase only;
- NEAR account-id safe;
- starts with an alphanumeric character;
- contains no raw email substring;
- generated from HMAC seed material, not a plain hash;
- uses curated safe word lists for adjective and noun;
- uses a 6 character base36 suffix derived from the HMAC seed;
- uses word lists large enough that the visible namespace is not just the
  suffix namespace;
- short enough to leave room for the relayer root account.

Recommended deterministic slug:

```ts
slug = `${adjective}-${noun}-${suffix}`;
```

Recommended namespace:

- Use at least 1,024 adjectives and 1,024 nouns if the suffix stays at 6 base36
  characters.
- A 6 character base36 suffix contributes about 31 bits.
- Two 1,024-entry word lists contribute about 20 additional bits.
- The visible namespace is then about 51 bits before collision retry.
- If the word lists are much smaller, increase the suffix to 8 base36
  characters.

Collision handling:

- Check whether the generated account ID already exists in durable app state.
- Check whether the NEAR account exists before creation.
- On collision, derive a retry candidate by adding a collision counter to the
  HMAC context.
- Do not append email-derived fallback text.

Collision retry context:

```ts
context = [
  'near_account_slug_v1',
  projectId,
  envId,
  authProvider,
  providerSubject ?? verifiedEmail,
  `collision:${counter}`,
].join('\0');
```

The first candidate must omit `collision:0` so that the canonical account ID is
stable when there is no collision.

Collision counters should be extremely rare if the visible namespace is large
enough. If a non-zero collision counter is used, store it in the durable identity
mapping. Recovery without that mapping can still retry counters in order, but
the system should be designed so this path is exceptional.

## Account ID Derivation Secret

`ACCOUNT_ID_DERIVATION_SECRET` is a long-lived secret used only for public NEAR
account ID slug derivation.

Rules:

- Store it in server-side secret storage, not client code.
- Do not reuse signing-root, Email OTP, JWT, or database encryption secrets.
- Back it up with the same availability-first posture as other recovery-critical
  secrets.
- Do not rotate it casually because existing NEAR account IDs are permanent.
- If rotation is required, introduce a new version string such as
  `near_account_slug_v2` for new accounts only.
- Keep old derivation versions available for account recovery unless all old
  accounts have durable identity mappings.

Secret compromise impact:

- Attackers still cannot derive signing keys or spend funds from this secret.
- Attackers can test candidate identities against public account IDs.
- Impact is privacy/correlation, not custody loss.

## Identity Canonicalization

For Email OTP:

- Use verified email for internal identity linking.
- Normalize email for lookup using a conservative canonical form:
  - trim whitespace;
  - lowercase the domain;
  - lowercase the local part only if the provider guarantees case-insensitive
    local parts, or choose a product-wide canonicalization policy and document
    it.
- Do not put the canonical email into the public account ID.

For Google/OIDC:

- Prefer stable provider `sub`.
- Store verified email as display/contact metadata.
- Do not derive public account ID from email if `sub` is available.

## UX Requirements

- Registration UI should not show email-derived account ID previews.
- If the UI shows the NEAR account ID, label it as a public account address.
- Recovery/account settings can show verified email separately from the public
  account ID.
- Local development logs may include email and account mapping, but production
  logs should avoid raw email unless required for an explicit audit/event path.

## Implementation Decisions

Hosted Google SSO + Email OTP registration owns account ID generation on the
server. Client-provided account IDs are not part of hosted Email OTP
registration. Self-hosted or local flows that need explicit account naming must
use separate self-hosted registration/bootstrap routes and must not share the
hosted Email OTP account ID generation path.

First release supports only deterministic HMAC-readable account IDs:

```ts
accountIdMode = 'hmac_readable';
```

Do not add a random opaque account ID mode in the first release. Random opaque
IDs have stronger unlinkability, but they require durable identity mapping as
the recovery source of truth. The current hosted product requirement is
deterministic recovery from verified identity plus `ACCOUNT_ID_DERIVATION_SECRET`.

## Operational Requirements

`ACCOUNT_ID_DERIVATION_SECRET` is recovery-critical for deterministic account
ID regeneration. Operators must:

- store it in server-side secret storage or a secrets manager;
- back it up with availability controls similar to other recovery-critical
  secrets;
- keep it separate from signing-root, Email OTP seal, JWT, database, and
  webhook secrets;
- treat rotation as a versioned migration, not a normal key rotation;
- preserve old slug derivation versions for accounts already created under
  those versions.

Public account IDs are public identifiers. Specs, UI copy, and support copy
should describe them as public readable wallet addresses that do not encode the
user's email. Verified email remains private account metadata and should not be
displayed as part of the public account address.

## Implementation Plan

### Phase 1: Inventory Current Account ID Generation

- [x] Find all Email OTP account ID generation call sites.
- [x] Find all OIDC/Google account ID generation call sites.
- [x] Find tests and fixtures that assert email-derived account IDs.
- [x] Find UI copy that previews or displays email-derived account IDs.
- [x] Find server routes that accept caller-provided `new_account_id`.
- [x] Identify whether account ID generation currently happens client-side,
  server-side, or both.

Acceptance criteria:

- Every account ID generation path is documented.
- There is one chosen owner for hosted account ID generation.

### Phase 2: Introduce Deterministic Readable Account Slug Generator

- [x] Add a shared HMAC-based account slug generator for NEAR hosted accounts.
- [x] Add curated adjective and noun word lists.
- [x] Ensure word lists are large enough for the target visible namespace.
- [x] Derive adjective, noun, and suffix from HMAC seed material.
- [x] Use a 10 character base36 suffix.
- [x] Require `ACCOUNT_ID_DERIVATION_SECRET` in hosted registration
  environments.
- [x] Include version, project, env, auth provider, and provider subject/email in
  the HMAC context.
- [x] Validate final NEAR account ID before use.
- [x] Add collision retry logic.
- [x] Add unit tests for format, length, deterministic parity, and validation.

Acceptance criteria:

- Generated account IDs never contain raw email substrings.
- Generated account IDs are valid NEAR account IDs.
- The same identity and context deterministically produce the same account ID.
- Different project/env/provider contexts produce different account IDs.

### Phase 3: Move Hosted Account ID Generation To A Trusted Boundary

- [x] Prefer server-side account ID generation for hosted registration.
- [x] Stop trusting client-provided Email OTP `new_account_id` for hosted
  account creation.
- [x] Allow self-hosted/local development flows to provide explicit account IDs
  only through a clearly separate path.
- [x] Store the generated account ID in the account identity mapping.
- [x] Return the generated account ID to the client after registration planning.
- [x] Ensure the HMAC derivation secret is never exposed to the client.

Acceptance criteria:

- Hosted Email OTP registration cannot force an email-derived public account ID.
- Self-hosted explicit account naming remains possible without affecting hosted
  defaults.

### Phase 4: Persist Identity-To-Account Mapping

- [x] Add or update durable storage for identity-to-account links.
- [x] Store `walletId`, `projectId`, `envId`, auth provider, provider subject,
  verified email, generated NEAR account ID, slug version, and collision
  counter if non-zero.
- [x] Enforce uniqueness for provider identity within project/environment.
- [x] Enforce uniqueness for generated NEAR account ID.
- [x] Add lookup helpers for login/unlock flows.
- [x] Add tests for duplicate identity registration.

Acceptance criteria:

- Existing users log in by identity lookup first.
- If the identity mapping is unavailable, the account ID can be recomputed from
  the verified identity and account ID derivation secret.
- Duplicate Email OTP registration returns the existing account or fails with a
  typed duplicate-account error according to product policy.

### Phase 5: Remove Email-Derived Account IDs

- [x] Delete email-to-account-name slugification helpers.
- [x] Delete timestamp-plus-email account ID generation.
- [x] Delete plain email hash account ID generation if any exists.
- [x] Update UI copy and tests to expect readable privacy-preserving account
  IDs.
- [ ] Update smoke tests and fixtures.
- [ ] Reset local development IndexedDB/state if needed.
- [ ] Recreate local dev accounts.

Acceptance criteria:

- `rg` finds no production code that slugifies email into NEAR account IDs.
- Tests do not assert email-derived account IDs.

### Phase 6: Random Opaque Mode Decision

- [x] Decide whether random opaque account IDs are needed for any deployment.
- [x] Do not add `accountIdMode: 'hmac_readable' | 'random'` in first release;
  keep one hosted account ID mode until random opaque IDs are required.
- [x] Keep `hmac_readable` as the hosted default.
- [x] If random mode is added, require durable identity-to-account mapping for
  recovery.
- [x] Add tests proving plain hash mode is unavailable.
- [x] Document the recovery tradeoff for random mode.

Acceptance criteria:

- There is no plain hash mode.
- Deterministic HMAC readable mode is the default.
- Random mode, if added, is explicitly marked as requiring durable mapping.

### Phase 7: Logging And Observability Cleanup

- [x] Inventory logs that include raw email and account ID together.
- [x] Redact or hash email in production logs where possible.
- [x] Keep explicit audit events only where email is required.
- [x] Ensure account IDs in logs are treated as public identifiers.
- [x] Add tests or lint checks for obvious email-derived account ID strings if
  practical.

Notes:

- Email OTP challenge delivery logs emit `emailHint`, `walletId`, `userId`,
  challenge metadata, and the development OTP code only in non-production log
  or memory delivery modes.
- Raw email is retained in the dev-only in-memory OTP outbox and passed to the
  future email provider adapter, but it is not emitted in the Email OTP
  delivery log payload.
- Email OTP lifecycle audit/webhook payloads include wallet ids, challenge ids,
  policy decisions, and operation names. They do not add raw email to the event
  payload; session claims are only used by the relay webhook layer to resolve
  org scope.
- Account IDs are treated as public wallet identifiers in server logs; privacy
  depends on account IDs not encoding the user's email address.

Acceptance criteria:

- Production logs do not casually emit email/account linkages.
- Audit paths that include email are intentional and documented.

## Test Plan

- [x] Unit test deterministic readable account ID format.
- [x] Unit test generated account IDs contain no email substrings.
- [x] Unit test same identity/context produces same account ID.
- [x] Unit test different project/env/provider contexts produce different
  account IDs.
- [x] Unit test plain hash mode is unavailable.
- [x] Unit test collision retry.
- [x] Unit test duplicate identity registration.
- [x] Unit test hosted registration rejects or ignores client-provided
  email-derived account IDs.
- [x] Integration test Email OTP registration creates readable
  privacy-preserving NEAR account ID.
- [x] Integration test Email OTP login finds account by identity mapping.
- [x] Integration test Email OTP account recovery recomputes account ID from
  verified identity and derivation secret.
- [x] Integration test Google/OIDC registration uses provider subject for
  internal identity linking.
- [x] Regression test that plain hashed emails are not used.

## Release Gates

- [x] No production Email OTP account ID contains raw email.
- [x] No production OIDC account ID contains raw email.
- [x] Hosted account ID generation is owned by a trusted boundary.
- [x] Hosted account ID generation uses keyed HMAC, not a plain hash.
- [x] `ACCOUNT_ID_DERIVATION_SECRET` storage and backup are documented.
- [x] Identity-to-account mapping is durable and tested as the primary lookup
  path.
- [ ] Existing local dev state has been reset or migrated.
- [x] Specs and UI copy describe account IDs as public readable addresses that
  do not encode email.
