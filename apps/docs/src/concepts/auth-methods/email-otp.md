---
title: Email OTP
description: Use email OTP as a server-verified challenge while keeping recovery and signing secrets on the wallet boundary.
---

# Email OTP

Email OTP is a server-verified channel challenge and worker-owned secret flow.

## Role in the model

Email OTP can:

1. prove control of a verified email channel;
2. authorize worker-owned Email OTP secret reconstruction;
3. create or restore signing capabilities under Wallet Session policy;
4. step up exhausted or expired Email OTP Wallet Session quotas;
5. authorize export or recovery only through fresh operation-specific policy.

Secret-bearing Email OTP material belongs in the dedicated Email OTP worker or
encrypted storage. App-origin code should not receive recovered Email OTP
secrets or derived signing shares.

## Start a login

Exchange a Google ID token for a typed login flow, then submit the code entered
by the user. The registration branch is handled separately because it carries
its own wallet selection and recovery-code backup ceremony.

::: details Runnable TypeScript example

<<< ../../examples/email-otp.ts

:::
