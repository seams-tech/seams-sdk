---
title: Email OTP
---

# Email OTP

Email OTP is a server-verified channel challenge and worker-owned secret flow.

## Role In The Model

Email OTP can:

1. prove control of a verified email channel;
2. authorize worker-owned Email OTP secret reconstruction;
3. create or restore signing capabilities under Wallet Session policy;
4. step up exhausted or expired Email OTP signing grants;
5. authorize export or recovery only through fresh operation-specific policy.

Secret-bearing Email OTP material belongs in the dedicated Email OTP worker or
encrypted storage. App-origin code should not receive recovered Email OTP
secrets or derived signing shares.
