---
title: Authentication
description: Select passkey, email OTP, and step-up authentication flows while preserving wallet and application trust boundaries.
---

# Authentication

Use authentication to establish the person or device allowed to enter a wallet
lifecycle. Signing still requires an exact wallet session and an authorized
operation.

## Choose a method

| Method                     | Best fit                                              | Important boundary                                                                      |
| -------------------------- | ----------------------------------------------------- | --------------------------------------------------------------------------------------- |
| Passkey                    | Primary registration and unlock on supported browsers | The wallet origin and RP ID own credential scope.                                       |
| Google plus email OTP      | Account discovery with a recoverable second factor    | The application acquires the Google token; the wallet flow owns OTP and recovery state. |
| VoiceID or another step-up | Explicit high-risk operation policy                   | Treat it as an additional proof, with consent, fallback, and retention rules.           |

Prefer the public `beginGoogleEmailOtpWalletAuth` flow for standard Google and
email OTP integration. Use lower-level challenge and enrollment methods only
when the application intentionally owns the extra UI and lifecycle branches.

## Expected result

A completed flow yields a stable wallet identity and the state required to
create or restore a wallet session. Render cancellation, expiry, retryable
delivery failure, and policy denial separately.

Review [passkeys](/concepts/auth-methods/passkeys), [email
OTP](/concepts/auth-methods/email-otp), and [auth planes](/concepts/auth-planes)
for the underlying boundaries.
