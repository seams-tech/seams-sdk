# Email Integration Plan

Date updated: March 11, 2026

## Objective

Add a real email delivery layer for console features that currently stop at persistence or placeholder state, starting with backup-email verification and other transactional account emails.

Primary product goals:

- Verify backup recovery emails instead of leaving them indefinitely in `PENDING`.
- Support reliable transactional emails for account and organization flows.
- Keep the implementation compatible with both Express and Cloudflare console deployments.
- Choose a low-cost provider strategy that does not add unnecessary operational overhead.

## Recommendation (Locked for v1)

Use this split:

- Cloudflare remains the runtime and edge platform.
- Cloudflare Email Routing remains the inbound email and email-worker layer we already use for email recovery.
- Resend is the default outbound transactional email provider for v1.
- Keep a narrow provider interface so Amazon SES can be added later if volume makes cost optimization worth the extra complexity.

Do not anchor v1 on Cloudflare-only outbound email.

Reason:

- Cloudflare Email Routing docs still describe the current product as forward-only and explicitly state that Cloudflare does not process outbound email or provide SMTP.
- Cloudflare does have Worker-based email sending primitives and a newer Email Service beta direction, but that is not yet the cleanest or most stable foundation for arbitrary user-facing transactional email.
- Resend already documents direct Cloudflare Workers integration and has a simpler developer path for shipping this quickly.
- Amazon SES is likely cheaper at scale, but it is a worse first integration if our immediate goal is to ship verification and other transactional mail quickly.

## Current Codebase State

### What already exists

- Inbound email handling exists in `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/cloudflare/email.ts`.
- Email-recovery service types already exist in `/Users/pta/Dev/rust/simple-threshold-signer/server/src/email-recovery/types.ts`.
- The account settings UI already models backup email status as `PENDING | VERIFIED` in `/Users/pta/Dev/rust/simple-threshold-signer/examples/tatchi-site/src/pages/dashboard/routes/account-settings/consoleAccountApi.ts`.

### What is missing

- New backup emails are inserted directly as `PENDING` in `/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/account/postgres.ts`.
- I did not find any route that sends a verification email for backup addresses.
- I did not find any route that consumes a verification token and flips a backup email from `PENDING` to `VERIFIED`.
- Current relayer coverage explicitly expects newly added backup emails to remain `PENDING` in `/Users/pta/Dev/rust/simple-threshold-signer/tests/relayer/console-account-router.test.ts`.

### Consequence

Today, `PENDING` is effectively a placeholder state. It implies verification, but no verification workflow exists yet.

That should be treated as a product bug, not just a missing enhancement.

## Cheap Transactional Email Options

### Option A: Cloudflare-only outbound

Not recommended for v1.

Why:

- Cloudflare's Email Routing docs still say the current service is forward-only for general email handling.
- The Worker send-email docs are useful, but they are documented around verified Email Routing destinations and operational notifications, not as the primary foundation for app-wide transactional mail to arbitrary end users.
- Cloudflare announced a broader Email Service private beta in September 2025, but pricing was still not finalized in the announcement and we should not bet this feature on a beta product.

Good use of Cloudflare here:

- inbound email handling,
- email-triggered workflows,
- running the application that calls the outbound provider,
- storing secrets and bindings at the edge.

### Option B: Resend

Recommended for v1.

Why:

- Resend has an official Cloudflare Workers integration path.
- Current pricing is simple and startup-friendly:
  - free tier: `3,000` emails/month with `100` emails/day,
  - pro tier: `$20/month` for `50,000` emails/month,
  - overages: `$0.90 / 1,000` emails.
- It is operationally much simpler than SES.
- It fits the existing TypeScript/Workers stack well.

Best fit:

- low to moderate transactional volume,
- fast implementation,
- minimal deliverability/platform overhead.

### Option C: Amazon SES

Recommended as a future cost-optimization option, not the day-one default.

Why:

- SES is very cheap at scale.
- Current published base outbound price is `$0.10 / 1,000` emails with no subscription minimum.
- The tradeoff is more setup and more operational surface area around sender reputation, configuration, and tooling.

Best fit:

- high email volume,
- mature delivery operations,
- a team that wants to optimize marginal email cost over implementation speed.

## Decision Summary

For this codebase, the pragmatic answer is:

- build the email integration around Resend now,
- keep the provider boundary clean,
- revisit Cloudflare Email Service if it reaches GA with stable pricing and arbitrary-recipient transactional support,
- add SES later if volume justifies a cheaper backend.

## Proposed Architecture

Create a dedicated outbound email module:

- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/email/transactional/types.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/email/transactional/templates.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/email/transactional/service.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/email/transactional/providers/resend.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/email/transactional/providers/noop.ts`

Optional later:

- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/email/transactional/providers/ses.ts`

Provider interface:

```ts
export interface TransactionalEmailProvider {
  send(input: {
    category: 'backup_email_verification' | 'org_invite' | 'owner_transfer_notice';
    to: string;
    subject: string;
    html: string;
    text: string;
    idempotencyKey?: string;
    metadata?: Record<string, string>;
  }): Promise<{ providerMessageId: string }>;
}
```

Service responsibilities:

- render email templates,
- generate verification links,
- call the selected provider,
- persist send attempts and message ids,
- emit structured logs and audit events when useful,
- centralize retry/error handling.

## Product Flows

### 1. Add backup email

1. User submits backup email from account settings.
2. Backend stores the email as `PENDING_VERIFICATION` or keeps `PENDING` with explicit meaning.
3. Backend creates a one-time verification token.
4. Backend sends a verification email to the backup address.
5. UI shows `Pending verification`, not bare `PENDING`.

### 2. Verify backup email

1. User clicks the verification link in the email.
2. Public verification route validates token, user, and expiry.
3. Matching backup email is marked `VERIFIED`.
4. Token is consumed and cannot be reused.
5. User is redirected back to dashboard with a success state.

### 3. Resend verification

1. User clicks `Resend verification`.
2. Existing unexpired token is either rotated or reused, depending on implementation choice.
3. Another transactional email is sent with rate limits.

### 4. Remove backup email

1. User may remove a `PENDING_VERIFICATION` email at any time.
2. User may remove a `VERIFIED` backup email subject to any future safety rules.

## Data Model Changes

Add a verification-token table:

- `console_email_verification_tokens`
  - `id`
  - `namespace`
  - `user_id`
  - `email`
  - `email_normalized`
  - `purpose`
  - `token_hash`
  - `expires_at_ms`
  - `consumed_at_ms`
  - `created_at_ms`

Recommended purpose values:

- `backup_email_verification`
- `primary_email_change`

Add an email delivery log table:

- `console_transactional_email_events`
  - `id`
  - `namespace`
  - `user_id`
  - `purpose`
  - `recipient_email`
  - `provider`
  - `provider_message_id`
  - `status`
  - `error_code`
  - `error_message`
  - `created_at_ms`

Breaking cleanup recommended:

- Replace ambiguous UI text `PENDING` with `Pending verification`.
- Consider renaming the stored status enum to `PENDING_VERIFICATION` if we are willing to do a breaking cleanup now.

## Route Plan

### Console-authenticated routes

- `GET /console/account/profile`
  - unchanged shape, but backup emails should return meaningful verification state.
- `PATCH /console/account/profile`
  - keep add/remove semantics for now.
- `POST /console/account/profile/backup-emails/:email/resend-verification`
  - new authenticated resend endpoint.

### Public routes

- `GET /console/email/verify`
  - verifies token from email link and redirects.

Optional later:

- `POST /console/email/provider/webhooks/resend`
  - delivery, bounce, complaint, and suppression event intake.

## UI Plan

Account settings changes:

- Change backup email status label from `PENDING` to `Pending verification`.
- Add `Resend verification` action for unverified emails.
- Keep `Remove` for pending emails.
- Show clear success/error toast states for add, resend, verify, and remove actions.

Copy changes:

- If verification is not yet enabled in a partially rolled-out environment, do not show fake status language.
- Never imply an email was verified unless the verification token flow completed.

## Runtime and Deployment Plan

### Express deployment

- Read provider secrets from server environment.
- Send emails directly from the Node server through the provider SDK or REST API.

### Cloudflare deployment

- Store provider secret in Workers secrets.
- Call Resend from the Worker runtime.
- Keep the Cloudflare inbound email-recovery path as its own module; do not force outbound transactional logic through the inbound email handler.

## Templates

Start with plain, product-critical templates only:

- backup email verification
- org invite
- owner transfer notification
- billing contact confirmation if needed later

Keep templates in code, not in a separate legacy email system.

Reason:

- versioned with application changes,
- easier review,
- easier typed template inputs,
- easier breaking cleanup.

## Observability and Safety

Must-have guardrails:

- idempotency keys on send requests where supported,
- token expiry,
- single-use verification tokens,
- resend rate limiting,
- structured logs with provider message ids,
- masking email addresses in logs where appropriate,
- alerting for provider failures once email becomes required for account recovery.

Recommended later:

- provider webhook ingestion for bounce/complaint tracking,
- suppression-list awareness,
- retry queue for transient failures.

## Implementation Phases

### Phase 0: Honest UX cleanup

- Update backup-email UI copy from `PENDING` to `Pending verification`.
- Add plan/docs comments that verification is not implemented yet if rollout is staged.

Exit criteria:

- The product no longer implies that verification already exists when it does not.

### Phase 1: Provider abstraction + Resend integration

- Add transactional email provider interface.
- Implement Resend provider.
- Add environment/config wiring for Express and Cloudflare runtimes.
- Add a `noop` provider for local development and tests.

Exit criteria:

- The backend can send a templated transactional email through one provider interface.

### Phase 2: Backup email verification

- Add verification token persistence.
- Add verification email template.
- Send email on backup-email add.
- Add public verify endpoint.
- Mark backup email as `VERIFIED` on successful token redemption.
- Add resend-verification endpoint and UI action.

Exit criteria:

- A backup email can move from newly added to verified through an actual email flow.

### Phase 3: Tests

- Add parser/service tests for verification token generation and redemption.
- Add route parity coverage for Express and Cloudflare.
- Add UI wiring coverage for add, resend, verify success, verify expiry, and remove flows.

Exit criteria:

- Verification flow is covered end-to-end in the existing console test strategy.

### Phase 4: Expand transactional email catalog

- Reuse the same module for org invites, owner-transfer notifications, and other account emails.
- Add provider webhooks if we need delivery or bounce visibility.

Exit criteria:

- Transactional mail is a real platform capability, not a one-off backup-email implementation.

## Open Questions

- Should backup-email verification be mandatory before the address is considered usable for recovery flows? Recommendation: yes.
- Should we allow more than one unverified backup email at a time? Recommendation: yes, but rate-limit sends.
- Should we rename the stored status enum now to `PENDING_VERIFICATION`? Recommendation: yes if we are already doing a migration.
- When Cloudflare Email Service reaches GA, do we want to replace Resend or simply keep it as an alternative provider? Recommendation: keep the provider boundary and decide later based on pricing and deliverability, not platform preference alone.

## Sources

- Cloudflare Email Routing overview: [developers.cloudflare.com/email-routing](https://developers.cloudflare.com/email-routing/)
- Cloudflare Email Routing get started: [developers.cloudflare.com/email-routing/get-started](https://developers.cloudflare.com/email-routing/get-started/)
- Cloudflare send emails from Workers: [developers.cloudflare.com/email-routing/email-workers/send-email-workers](https://developers.cloudflare.com/email-routing/email-workers/send-email-workers/)
- Cloudflare Workers tutorial with Resend: [developers.cloudflare.com/workers/tutorials/send-emails-with-resend](https://developers.cloudflare.com/workers/tutorials/send-emails-with-resend/)
- Cloudflare Email Service private beta announcement: [blog.cloudflare.com/email-service](https://blog.cloudflare.com/email-service)
- Resend docs: [resend.com/docs/introduction](https://resend.com/docs/introduction)
- Resend Cloudflare Workers guide: [resend.com/docs/send-with-cloudflare-workers](https://resend.com/docs/send-with-cloudflare-workers)
- Resend pricing: [resend.com/pricing](https://resend.com/pricing)
- Amazon SES pricing: [aws.amazon.com/ses/pricing](https://aws.amazon.com/ses/pricing/)
