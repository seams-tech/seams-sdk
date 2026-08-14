# Google OIDC

Use Google OIDC for application login independently from wallet ownership.
Store the user's wallet locator in your application, then let the wallet SDK
complete passkey or Email OTP owner authentication.

The built-in Google-assisted Email OTP flow verifies a Google identity only to
resolve the Email OTP owner identity or begin registration. Email OTP remains
the wallet owner proof.

See [Application Auth Provider Integrations](./README.md).
