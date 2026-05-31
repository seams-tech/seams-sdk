# Refactor 46b: Email OTP Identity Binding

Date created: 2026-05-29

Status: completed.

## Goal

Make Email OTP registration identity explicit after the `walletId` rename. The
OTP challenge should be owned by an authentication subject, while registration
proofs should identify the OIDC provider subject that requested the OTP.

This documents the follow-up cleanup that landed after Refactor 46 and the
registration-flow rework.

## Problem Addressed

Google Email OTP registration can issue one OTP, then reroll the generated
wallet name before finalizing registration. That means the OTP cannot be bound
only to the first `walletId` or first app-session digest.

The earlier implementation reused `userId` for several meanings:

- current route/session user id
- durable wallet id for some hosted sessions
- Google/OIDC provider subject
- stored Email OTP challenge owner

That made the critical reroll check read like:

```ts
record.userId === proof.providerSubject
```

The comparison was correct in intent, but the field names obscured what was
being compared.

## Target Vocabulary

| Term | Meaning |
| --- | --- |
| `walletId` | Durable wallet identity being registered or used. |
| `providerSubject` | OIDC provider subject from the app-session JWT and Email OTP registration proof. |
| `challengeSubjectId` | Subject that owns an Email OTP challenge. For Google registration this is the provider subject that requested the OTP. |
| `proofEmail` | Email asserted by the registration proof. It must match the challenged email. |

## Target Model

Email OTP registration proof:

```ts
type EmailOtpRegistrationProof = {
  version: 'email_otp_registration_proof_v1';
  providerSubject: string;
  email: string;
  challengeId: string;
  otpCode: string;
  otpChannel: 'email_otp';
  registrationIntentDigestB64u: string;
  appSessionVersion: string;
};
```

Stored Email OTP challenge:

```ts
type EmailOtpChallengeRecord = {
  version: 'email_otp_challenge_v1';
  challengeId: string;
  challengeSubjectId: string;
  walletId: string;
  orgId?: string;
  email: string;
  sessionHash: string;
  appSessionVersion: string;
  action: EmailOtpChallengeAction;
  operation: EmailOtpChallengeOperation;
};
```

Registration reroll binding:

```ts
record.challengeSubjectId === input.providerSubject
```

The reroll branch also requires the challenged email to match
`EmailOtpRegistrationProof.email`.

## Completed Changes

- [x] Renamed normalized Email OTP challenge ownership from `userId` to
      `challengeSubjectId`.
- [x] Updated Email OTP challenge context lookups to use
      `challengeSubjectId`.
- [x] Kept physical persistence compatibility isolated to challenge record
      parsing and store boundaries.
- [x] Made `EmailOtpRegistrationProof.providerSubject` required and documented
      the field purpose.
- [x] Removed provider-subject fallback behavior in Google registration routes.
      Missing `providerSubject` now fails explicitly.
- [x] Replaced broad reroll flags with a narrow registration reroll proof
      binding carrying `providerSubject` and `proofEmail`.
- [x] Resolve the reroll proof email from the durable Google registration
      attempt when `googleEmailOtpRegistrationAttemptId` is present. The
      current app session may omit the email claim after a wallet-name reroll.
- [x] Include `googleEmailOtpRegistrationAttemptId` in the registration finalize
      body from the app-session JWT, so finalize does not depend on cookie or
      server-claim propagation to recover the active registration attempt.
- [x] Kept add-auth-method Email OTP verification wallet-bound. It does not use
      the registration reroll branch.
- [x] Updated the registration-flow plan to describe the final
      `challengeSubjectId` binding.

## Invariants

- Google/OIDC Email OTP registration requires `providerSubject` in the app
  session and in the registration proof.
- The challenge owner must match the proof subject:
  `record.challengeSubjectId === input.providerSubject`.
- The challenged email must match the proof email.
- For Google registration finalize, the durable registration attempt supplies
  the proof email and must match the current provider subject and wallet id.
- The reroll exemption applies only to Email OTP registration.
- Login, export, recovery, and add-auth-method OTP verification remain bound to
  their normal wallet/session context.
- A successful verification consumes the challenge once.

## Validation

- [x] `pnpm type-check:relay-server`
- [x] Focused unit suite covering hosted-account privacy, registration routes,
      Postgres record parsing, SDK Email OTP helpers, registration intent
      allocation, and wallet-registration boundaries.
- [x] Relayer Email OTP auth-service suite.
- [x] `git diff --check`

## Follow-Up

No follow-up is required for this refactor. Future Email OTP route/API cleanup
can rename external request fields that still use `userId` for login or recovery
contexts, but that should be a separate route compatibility decision.
