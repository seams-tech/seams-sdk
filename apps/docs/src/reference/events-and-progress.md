---
title: Events and progress
description: Render stable wallet-flow event phases and statuses without using diagnostics to drive SDK lifecycle control flow.
---

# Events and progress

Registration, unlock, signing, account sync, key export, and device linking can
emit `WalletFlowEvent` branches. Use these events for progress UI, accessibility
announcements, telemetry, and support diagnostics.

The main entrypoint exports phase enums, event constructors, stable event
messages and steps, and the `isWalletFlowEvent` boundary guard.

## Rendering guidance

- Announce meaningful phase changes through one polite live region.
- Keep the operation's button label stable while a nearby status explains the
  current step.
- Preserve cancellation and retry controls while an operation waits on user
  presence or a remote service.
- Log the event version, phase, status, and operation identifier. Remove
  credentials, OTP codes, key material, tokens, and raw assertion data.

Progress events describe what the SDK is doing. Drive control flow from the
operation result and domain state, since telemetry can be delayed, filtered, or
disabled.
