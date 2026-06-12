# Auth Secret Terminology Cleanup Plan

Date created: June 12, 2026

## Scope

The codebase still uses passkey-specific language in places where the product
now supports multiple authentication methods, including passkeys, Email OTP,
Google-authenticated OTP flows, and future factor sources.

This plan defines a repo-wide terminology cleanup. It does not rename APIs yet.
The implementation pass should be a clean rename, with compatibility limited to
request and persistence boundaries that still need migration handling.

## Target Vocabulary

Use these terms for steady-state architecture:

| Use | Preferred term | Notes |
| --- | --- | --- |
| General auth-derived secret material | `factor-derived secret` | Covers passkey PRF, OTP-derived worker secret, recovery-derived material, and future auth methods. |
| Material used to unwrap signing-root or session material | `share unwrap secret` | Use when the concrete job is decrypting or unwrapping protected share/session material. |
| Session-scoped signing secret | `signing_session_secret32` | Already used in sealed refresh docs. Keep it. |
| Concrete passkey adapter output | `WebAuthn PRF output` or `passkey PRF output` | Use only inside passkey/WebAuthn adapter boundaries. |
| Auth-specific source selector | `secret source` or `auth secret source` | Use for discriminated unions over passkey, Email OTP, recovery, etc. |

Avoid these terms outside passkey adapter boundaries:

- `passkey PRF as secret`
- `passkey PRF secret`
- `passkey-derived secret` for auth-neutral flows
- `PRF secret` for Email OTP, recovery, or generic signing-session flows

## Boundary Rule

The steady-state model should read:

```text
auth method -> factor-derived secret -> share unwrap / signing-session input
```

Passkey/WebAuthn code may still say `passkey PRF output` because that is the
actual browser primitive. Core signing, threshold, sealed-refresh, restore,
budget, session, and routing code should use auth-method-neutral terms.

## Current Hotspots

Initial grep showed passkey-specific wording in:

- product docs under `apps/docs/src/concepts`
- Email OTP and intended-behavior docs under `docs/`
- signing-session sealed-refresh docs
- ECDSA bootstrap/session code under `packages/sdk-web/src/core/signingEngine`
- passkey cache and passkey adapter code
- source guards and tests that assert Email OTP isolation from passkey-only paths

Some passkey wording is still correct:

- WebAuthn adapter implementation
- passkey-only source guards
- passkey-specific error messages shown when the selected auth method is a
  passkey and WebAuthn PRF output is missing

## Phased Plan

### Phase 1: Inventory And Classification

- [ ] Produce a checked-in inventory of current terms and files.
- [ ] Classify each hit as:
  - keep passkey-specific
  - rename to factor-derived secret
  - rename to share unwrap secret
  - rename to signing-session secret
  - persistence/request compatibility boundary
- [ ] Identify exported TypeScript and Rust names that need breaking renames.

Exit criteria:

- every passkey/PRF terminology hit has a planned disposition
- auth-neutral and passkey-specific boundaries are explicit

### Phase 2: Docs Rename

- [x] Rename auth-neutral docs first.
- [x] Keep passkey-specific docs precise where they describe WebAuthn PRF.
- [x] Update diagrams and flow labels.
- [x] Add a short terminology section to the main signing/session architecture
  docs.

Exit criteria:

- product and architecture docs describe passkeys as one auth method
- Email OTP docs no longer define themselves in negative relation to passkey PRF

### Phase 3: Type And Code Rename

- [ ] Rename auth-neutral TypeScript domain types.
- [ ] Rename auth-neutral route/request/response fields where compatibility is
  not required.
- [ ] Keep compatibility parsing only at persistence and request boundaries.
- [ ] Delete obsolete helper names after replacement.
- [ ] Preserve passkey-specific names inside passkey adapter modules.

Exit criteria:

- core signing/session logic uses auth-neutral names
- passkey PRF names are isolated to WebAuthn/passkey boundaries

### Phase 4: Source Guards And Tests

- [x] Add source guard coverage for auth-neutral docs:
  high-risk passkey PRF terms stay out of selected active docs.
- [ ] Extend source guards to enforce the code boundary:
  passkey PRF terms appear only under approved passkey adapter paths and
  explicit passkey tests.
- [ ] Update TypeScript fixtures that reject invalid cross-auth states.
- [ ] Delete tests that only preserve obsolete wording.

Exit criteria:

- CI catches new passkey-specific wording in auth-neutral code
- Email OTP, recovery, and future auth methods do not import passkey-only
  secret-source helpers

### Phase 5: Release Notes And Migration Boundaries

- [ ] Document any request/persistence field migrations.
- [ ] Keep migration code only at request and persistence boundaries.
- [ ] Delete compatibility paths once stored records and callers are migrated.

Exit criteria:

- naming cleanup is complete without long-lived aliases
- compatibility code has an owner and deletion point

## First Implementation Slice

When we decide to start the actual rename, begin with docs and source guards.
That creates clear ownership before touching TypeScript domain types and route
schemas.

Status as of June 12, 2026:

- [x] Auth-neutral product and architecture docs use `factor-derived secret`
  terminology.
- [x] The main signing-session architecture doc defines the steady-state
  vocabulary.
- [x] Source guard coverage prevents high-risk passkey PRF wording from
  returning to the auth-neutral docs.
- [ ] TypeScript domain type, route field, and persistence-boundary rename
  remains a later API cleanup pass.
