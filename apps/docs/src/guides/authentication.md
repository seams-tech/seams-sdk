---
title: Authentication
description: Select passkey, email OTP, and step-up authentication flows while preserving wallet and application trust boundaries.
---

# Authentication

Start with [Wallet setup and authentication](/examples/wallet-setup-and-authentication)
to configure the provider, register a wallet, and unlock it. Use this guide to
choose the factor and keep the resulting state explicit.

## Choose a flow

- **Passkey** — primary registration and unlock on supported browsers. The
  wallet origin and RP ID own the credential scope.
- **Google plus email OTP** — account discovery with a recoverable second
  factor. The application supplies the Google token; the wallet flow owns OTP
  and recovery state.
- **VoiceID or another step-up** — an additional proof for a high-risk
  operation. Define consent, fallback, and retention rules before enabling it.

## Keep auth state explicit

- Preserve the same wallet identity when someone registers, unlocks, or adds
  a factor.
- Create an exact wallet session before signing. Authentication alone does not
  authorize an operation.
- Render cancellation, expiry, retryable delivery failure, and policy denial as
  separate outcomes.
- Keep passkeys, session tokens, and factor material out of application or agent
  storage.

Read [passkeys](/concepts/auth-methods/passkeys), [email
OTP](/concepts/auth-methods/email-otp), and [auth planes](/concepts/auth-planes)
for the boundaries behind each flow.
