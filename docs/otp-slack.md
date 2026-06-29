# Slack OTP Step-Up Spec

Status: architecture spec

Related docs:

- [Email OTP Architecture](./otp/email-otp.md)
- [Step-Up Adaptor Refactor Plan](./refactor-34b-stepup-adaptor.md)
- [Centaur Secrets Vault Architecture Plan](./centaur-secrets-vault.md)
- [Cloudflare-Native Centaur Fork Plan](./centaur-cloud-fork.md)

## Objective

Add Slack OTP as an out-of-band step-up factor for browser-based sensitive
operations. The first use cases are MPC signing, key export authorization, and
secrets vault access.

Slack OTP should behave like Email OTP at the step-up boundary:

```text
browser operation starts
  -> Seams creates an exact operation challenge
  -> Seams delivers a one-time code or confirm action to Slack
  -> user proves control of the linked Slack identity
  -> browser operation continues with a verified step-up result
```

Slack never owns MPC execution, vault plaintext, key export material, signing
shares, or browser-local cryptographic state.

## Product Claims

Allowed claims:

```text
Slack OTP can be used as a second factor for Seams browser operations.
Slack OTP can require a linked Slack identity before a vault or signing action proceeds.
Slack OTP challenges are bound to a specific operation digest and expire quickly.
```

Avoid these claims:

```text
Slack performs MPC signing.
Slack OTP provides hardware-backed user presence.
Slack OTP protects against a compromised Slack account.
```

## Design Decisions

1. Implement Slack OTP as a step-up method, not as a new signing or vault
   capability.
2. Keep MPC signing, vault access, and key export execution in existing Seams
   browser or Worker flows.
3. Require a linked Slack identity before Slack OTP can be selected.
4. Bind every Slack OTP challenge to tenant, principal, browser session, exact
   operation digest, operation kind, exact lane, expiration, and nonce.
5. Support two completion modes:
   - code entry in the browser;
   - Slack confirm button that completes the same challenge server-side.
6. Treat Slack OTP as weaker than passkey/WebAuthn user presence.
7. Let policy choose Slack OTP for medium-risk operations and require passkey or
   MPC-backed authorization for high-risk operations.
8. Store only challenge metadata, OTP hashes, Slack delivery metadata, and audit
   events.
9. Keep Slack tokens in platform secret storage or the first-party vault; do not
   expose bot tokens to browser code.

## Slack Capability Boundary

Slack provides:

- user and workspace identity from a linked Slack install;
- DM delivery for OTP messages;
- Block Kit messages, buttons, and modals;
- interaction payloads for user actions;
- URL buttons that can open Seams browser approval pages.

Slack does not provide:

- a place to load Seams MPC WASM inside Slack Desktop;
- direct access to WebAuthn/passkey APIs owned by the Seams origin;
- durable Seams auth session state;
- a cryptographic boundary for vault plaintext or signing shares.

## Threat Model

Slack OTP improves security against:

- stolen Seams bearer sessions when policy requires fresh Slack OTP;
- unattended browser sessions when the attacker cannot access the user's Slack;
- accidental approval of the wrong operation when digest and summary match
  between browser and Slack;
- replay of old approvals through one-time challenge consumption.

Slack OTP does not protect against:

- a fully compromised Slack account;
- malware controlling the browser and Slack session together;
- server compromise when the server can bypass policy and access unwrap keys;
- phishing where the user approves a digest without checking context.

High-assurance policies should combine Slack OTP with passkey, MPC digest
authorization, two-person approval, sidecar unwrap, or customer-managed keys.

## Identity Model

Slack identity is linked to a Seams principal. The link is scoped to tenant and
Slack workspace.

```ts
type SlackLinkedIdentity =
  | {
      kind: "active_slack_identity_link";
      tenantId: TenantId;
      principalId: PrincipalId;
      slackTeamId: SlackTeamId;
      slackUserId: SlackUserId;
      linkedAt: IsoTimestamp;
      revokedAt?: never;
    }
  | {
      kind: "revoked_slack_identity_link";
      tenantId: TenantId;
      principalId: PrincipalId;
      slackTeamId: SlackTeamId;
      slackUserId: SlackUserId;
      linkedAt: IsoTimestamp;
      revokedAt: IsoTimestamp;
    };
```

Boundary rules:

1. Slack request payloads are raw external input and must be parsed once at the
   Slack webhook boundary.
2. A Slack user ID is never a Seams principal ID.
3. A Slack link must include tenant, workspace, user, and Seams principal.
4. Revoked links cannot verify or complete challenges.
5. Slack Enterprise Grid identities should include enterprise IDs when present;
   the tenant mapping must still use the installed workspace ID.

## Challenge Model

Slack OTP challenges are operation-bound. A challenge cannot be reused for a
different digest, lane, browser session, Slack user, or tenant.

```ts
type SlackOtpAction =
  | "mpc_sign_step_up"
  | "key_export_step_up"
  | "vault_access_step_up"
  | "vault_reveal_step_up"
  | "account_link_verification";

type SlackOtpDeliveryMode =
  | { kind: "browser_code_entry" }
  | { kind: "slack_confirm_button" };

type SlackOtpChallengeStatus =
  | {
      kind: "pending";
      otpHash: OtpHash;
      attemptsRemaining: PositiveInteger;
      verifiedAt?: never;
      consumedAt?: never;
      failureReason?: never;
    }
  | {
      kind: "verified";
      verificationId: SlackOtpVerificationId;
      verifiedAt: IsoTimestamp;
      otpHash?: never;
      attemptsRemaining?: never;
      consumedAt?: never;
      failureReason?: never;
    }
  | {
      kind: "consumed";
      verificationId: SlackOtpVerificationId;
      verifiedAt: IsoTimestamp;
      consumedAt: IsoTimestamp;
      otpHash?: never;
      attemptsRemaining?: never;
      failureReason?: never;
    }
  | {
      kind: "failed";
      failureReason: "expired" | "attempts_exhausted" | "revoked_link" | "cancelled";
      otpHash?: never;
      attemptsRemaining?: never;
      verifiedAt?: never;
      consumedAt?: never;
    };

type SlackOtpChallenge = {
  tenantId: TenantId;
  challengeId: SlackOtpChallengeId;
  principalId: PrincipalId;
  slackTeamId: SlackTeamId;
  slackUserId: SlackUserId;
  browserSessionId: BrowserSessionId;
  action: SlackOtpAction;
  deliveryMode: SlackOtpDeliveryMode;
  operationDigest: OperationDigest;
  laneBinding: SensitiveOperationLaneBinding;
  nonce: ChallengeNonce;
  issuedAt: IsoTimestamp;
  expiresAt: IsoTimestamp;
  slackMessageTs: SlackMessageTs | null;
  status: SlackOtpChallengeStatus;
};
```

`operationDigest` must already include the exact operation target:

- MPC signing: wallet, curve, chain target, signing grant, threshold session,
  transaction digest, policy version, expiration, nonce.
- Key export: wallet, key ID, export lane, export policy, expiration, nonce.
- Vault access: tenant, item, version, field, grant, destination policy,
  injection policy, expiration, nonce.

## User Flows

### Link Slack Identity

```text
User opens Seams dashboard
  -> chooses Link Slack
  -> Seams redirects through Slack OAuth or admin-installed workspace mapping
  -> Seams records pending Slack identity link
  -> Seams sends verification message to Slack DM
  -> user enters code in browser or confirms in Slack
  -> Seams stores active SlackLinkedIdentity
  -> audit records slack_otp.identity_linked
```

The link flow should require an existing Seams-authenticated browser session.
Slack linking alone must not create a Seams principal.

### Browser Code Entry

```text
Browser prepares sensitive operation
  -> StepUp selects slack_otp
  -> Seams creates SlackOtpChallenge
  -> Seams sends OTP to Slack DM
  -> user reads code in Slack
  -> user enters code in browser
  -> Seams verifies challenge binding and OTP
  -> StepUp returns SlackOtpStepUpAuthorization
  -> browser operation continues
```

This is the default mode because the browser remains the operation owner.

### Slack Confirm Button

```text
Browser prepares sensitive operation
  -> StepUp selects slack_otp
  -> Seams creates SlackOtpChallenge
  -> Seams sends Slack message with operation summary and confirm button
  -> user clicks Confirm in Slack
  -> Slack sends interaction payload to Seams
  -> Seams verifies Slack signature and linked identity
  -> Seams marks challenge verified
  -> browser polls or receives push update
  -> browser operation continues
```

The confirm button must include only an opaque challenge ID. It must not include
secret values, raw transaction payloads, JWTs, or operation grants.

### MPC Signing With Slack OTP

```text
Browser builds signing operation
  -> exact signing lane is selected
  -> operation digest is created
  -> Slack OTP verifies linked Slack identity for that digest
  -> browser MPC client performs signing flow
  -> signing session budget is consumed
  -> audit records step-up and signing decision
```

Slack OTP is only the factor. The browser still owns the MPC client path.

### Vault Access With Slack OTP

```text
Agent or dashboard requests vault access
  -> policy requires slack_otp step-up
  -> browser creates or joins approval session
  -> Slack OTP verifies linked Slack identity for exact VaultAccessIntent
  -> Seams mints short-lived vault operation grant
  -> Secret Broker or Egress Gateway executes approved operation
  -> audit records step-up, grant, and access outcome
```

For cloud injection, Worker-side plaintext exposure remains governed by the
vault runtime mode. Slack OTP does not make cloud injection server-blind.

## Step-Up Integration

Slack OTP should be added beside Email OTP in the step-up method layer.

```ts
type StepUpMethod =
  | "passkey"
  | "email_otp"
  | "slack_otp"
  | "authenticator_otp"
  | "magic_link"
  | "password";

type SlackOtpStepUpAuthorization = {
  method: "slack_otp";
  tenantId: TenantId;
  principalId: PrincipalId;
  slackTeamId: SlackTeamId;
  slackUserId: SlackUserId;
  challengeId: SlackOtpChallengeId;
  verificationId: SlackOtpVerificationId;
  operationDigest: OperationDigest;
  browserSessionId: BrowserSessionId;
  verifiedAt: IsoTimestamp;
  expiresAt: IsoTimestamp;
};

type StepUpAuthResult =
  | { method: "passkey"; authorization: PasskeyStepUpAuthorization }
  | { method: "email_otp"; authorization: EmailOtpStepUpAuthorization }
  | { method: "slack_otp"; authorization: SlackOtpStepUpAuthorization };
```

Slack OTP method runner:

```ts
type SlackOtpStepUpRunner = {
  prepareChallenge(input: SlackOtpPrepareChallengeInput): Promise<SlackOtpChallenge>;
  completeWithCode(input: SlackOtpCodeCompletionInput): Promise<SlackOtpStepUpAuthorization>;
  completeFromSlackInteraction(input: SlackOtpInteractionCompletionInput): Promise<SlackOtpStepUpAuthorization>;
  resend(input: SlackOtpResendInput): Promise<SlackOtpChallenge>;
};
```

Import direction should match the existing step-up pattern:

| From | May import | Must not import |
| --- | --- | --- |
| operation flows | `stepUpConfirmation` contracts and method runner ports | Slack API client internals |
| `stepUpConfirmation` | method selection, prompt plans, `SlackOtpStepUpRunner` type | operation executors |
| Slack OTP runtime | Slack API client, challenge store, audit writer | MPC signer internals, vault unwrap internals |
| MPC and vault executors | verified `StepUpAuthResult` | raw Slack payloads |

## API Sketch

Internal browser APIs:

```text
POST /step-up/slack-otp/challenges
POST /step-up/slack-otp/challenges/{challenge_id}/verify
POST /step-up/slack-otp/challenges/{challenge_id}/resend
GET  /step-up/slack-otp/challenges/{challenge_id}/status
```

Slack webhooks:

```text
POST /slack/events
POST /slack/interactions
```

Dashboard linking:

```text
POST /settings/slack-links
POST /settings/slack-links/{link_id}/verify
DELETE /settings/slack-links/{link_id}
```

Every route parser should return precise internal types. Core Slack OTP logic
must not accept raw Slack payloads, raw route bodies, or partial records.

## Slack Message Design

OTP DM:

```text
Seams verification code

Action: Vault access step-up
Target: Stripe Refund API key
Digest: 8F3K-19QZ
Expires: 2 minutes

Code: 123456
```

Confirm-button DM:

```text
Seams approval requested

Action: MPC signing step-up
App: Commerce harness
Digest: 8F3K-19QZ
Expires: 2 minutes

[Confirm] [Deny] [Open in Seams]
```

The Slack message and browser page must display the same short digest. The
browser page should show the fuller operation summary before the user proceeds.

## Persistence

Suggested D1 tables:

```text
slack_identity_links(
  tenant_id,
  link_id,
  principal_id,
  slack_team_id,
  slack_enterprise_id,
  slack_user_id,
  status,
  linked_at,
  revoked_at
)

slack_otp_challenges(
  tenant_id,
  challenge_id,
  principal_id,
  slack_team_id,
  slack_user_id,
  browser_session_id,
  action,
  delivery_mode,
  operation_digest,
  lane_binding_json,
  otp_hash,
  attempts_remaining,
  status,
  slack_message_ts,
  issued_at,
  expires_at,
  verified_at,
  consumed_at
)

slack_otp_audit_events(
  tenant_id,
  event_id,
  challenge_id,
  principal_id,
  slack_team_id,
  slack_user_id,
  event_kind,
  operation_digest,
  created_at
)
```

Persist OTP hashes with a server-side pepper. Do not persist raw OTP values.
Slack bot tokens belong in platform secret storage or the Seams vault.

## Security Rules

1. Verify every Slack event and interaction request signature at the webhook
   boundary.
2. Resolve Slack user and team IDs to a single active `SlackLinkedIdentity`.
3. Reject challenges with expired browser sessions.
4. Reject challenges when the operation digest or lane binding differs from the
   active browser operation.
5. Consume successful challenges once.
6. Rate-limit challenge creation by principal, Slack user, tenant, and IP.
7. Rate-limit verification attempts by challenge ID and principal.
8. Do not reveal whether a Slack user is linked across tenants.
9. Redact OTPs, Slack bot tokens, operation grants, authorization headers, and
   vault secret values from logs.
10. Revoke pending challenges when a Slack identity link is revoked.
11. Require passkey or stronger policy for high-risk actions when Slack account
   compromise is in scope.
12. Keep challenge TTL short, with resend creating a new OTP for the same
   challenge or a replacement challenge under explicit policy.

## Policy Defaults

Recommended defaults:

| Operation | Slack OTP suitability |
| --- | --- |
| Low-risk workflow approval | Allowed |
| Vault use for non-production secret | Allowed |
| Vault use for production secret | Allowed with tenant opt-in |
| Vault reveal | Require passkey or Slack OTP plus approval |
| Vault delegation | Require passkey or two-person approval |
| Raw DB access | Require passkey, approval, or strict tenant policy |
| MPC transaction signing | Allowed as factor when lane policy permits Email OTP-class auth |
| Key export | Require passkey by default |

Slack OTP should share the same policy vocabulary as Email OTP where possible:

```ts
type SensitiveOperationPolicy =
  | "inherit_session_policy"
  | "require_fresh_same_method"
  | "require_passkey"
  | "deny_email_otp"
  | "deny_slack_otp";
```

If policy needs more nuance, add method classes:

```ts
type StepUpAssuranceClass =
  | "bearer_session"
  | "out_of_band_otp"
  | "user_present_passkey"
  | "mpc_digest_authorization";
```

## Audit Events

Event types:

- `slack_otp.identity_link_started`
- `slack_otp.identity_linked`
- `slack_otp.identity_unlinked`
- `slack_otp.challenge_created`
- `slack_otp.challenge_delivered`
- `slack_otp.challenge_delivery_failed`
- `slack_otp.challenge_verified`
- `slack_otp.challenge_denied`
- `slack_otp.challenge_expired`
- `slack_otp.challenge_consumed`
- `slack_otp.challenge_replayed`

Audit records should include tenant, principal, Slack team, Slack user,
challenge ID, action, operation digest, short digest, browser session, delivery
mode, and decision. They must omit OTP values and secret-bearing operation
payloads.

## Failure Handling

| Failure | Behavior |
| --- | --- |
| Slack DM cannot be sent | Return `delivery_failed` and offer another method |
| user has no active Slack link | Hide Slack OTP from method selection |
| Slack user clicks expired challenge | Mark failed and ask browser to restart |
| browser session expires | Reject verification and clear pending challenge |
| operation digest mismatch | Reject and audit `challenge_replayed` |
| attempts exhausted | Mark failed and require a fresh challenge |
| Slack install revoked | Revoke all pending challenges for that install |

## Implementation Phases

| Phase | Focus | Deliverable |
| --- | --- | --- |
| 0 | Domain and policy | Slack identity link, challenge, status, and step-up auth types |
| 1 | Linking | Dashboard Slack link flow and active link parser |
| 2 | Challenge runtime | D1 tables, OTP generation, hash storage, expiration, resend |
| 3 | Slack delivery | DM delivery, Block Kit message, interaction verification |
| 4 | Step-up integration | `slack_otp` method runner under step-up confirmation |
| 5 | Browser UX | Code-entry prompt, status polling, digest matching |
| 6 | Operation integration | MPC signing and vault access policy hooks |
| 7 | Hardening | rate limits, replay tests, audit redaction, Slack install revocation |

## Validation Plan

Type-level checks:

- Pending, verified, consumed, and failed challenge states reject invalid field
  combinations.
- Slack OTP authorization requires tenant, principal, Slack team, Slack user,
  browser session, operation digest, challenge ID, and verification ID.
- Raw Slack payloads cannot be passed to core challenge verification.
- Slack OTP authorization cannot be used for a different operation digest.

Unit tests:

- Slack identity link parser.
- Challenge creation and expiration.
- OTP hash verification and failed attempts.
- Slack interaction parser.
- Operation digest and lane binding checks.
- Audit redaction.

Integration tests:

- Browser code-entry flow.
- Slack confirm-button flow with fake Slack interaction payload.
- Expired challenge denial.
- Replay denial after consumption.
- Revoked Slack link denial.
- Method-selection fallback when Slack delivery fails.

Security tests:

- Raw OTP never appears in logs.
- Slack bot token never appears in logs.
- Vault secret values never appear in Slack messages.
- A challenge for tenant A cannot verify tenant B operations.
- A challenge for Slack user A cannot verify Slack user B operations.

## Open Questions

- Should the first release support Slack confirm buttons, or only browser code
  entry?
- Should Slack OTP be available for key export, or should key export require
  passkey only?
- Should Slack OTP share Email OTP budget and post-operation consumption logic,
  or use separate method-specific counters?
- Should Enterprise Grid identity include enterprise user ID in all challenge
  records?
- Should Slack OTP delivery use DM only, or allow private approval channels for
  team workflows?

## References

- Slack Block Kit: https://docs.slack.dev/block-kit/
- Slack button element: https://docs.slack.dev/reference/block-kit/block-elements/button-element/
- Slack modals: https://docs.slack.dev/surfaces/modals
- Slack App Home: https://docs.slack.dev/surfaces/app-home
