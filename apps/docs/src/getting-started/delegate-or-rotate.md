---
title: Add devices, export, and recover
description: Link another device, export a key, or restore a wallet account through fresh authorization.
---

# Add devices, export, and recover

Use these flows after your first wallet can sign. Each operation
has its own authorization and result; keep it separate from normal signing.

## Link another device

Device 2 starts a link session and displays a QR code. Device 1 scans that code
and approves the new device.

<<< ../examples/device-linking.tsx

`ShowQRCode` owns the Device 2 side end to end: it starts the link session,
displays the code, and cancels an abandoned session on close. `useDeviceLinking`
runs the Device 1 side and reports progress through `onEvent` and failures
through `onError`. Request a fresh code instead of reusing an old QR payload.

## Export a key

`exportKeypair` resolves the exact export lane and opens the wallet-origin
export viewer in one call, from a freshly authorized action.

<<< ../examples/export-wallet.ts

Ed25519 export uses the wallet's NEAR account; ECDSA export names a configured
chain. Both default to the signed-in wallet — pass `walletSession`,
`nearAccount`, or `chainTarget` to name an exact one.

Check the outcome: `relink_required` means this device has no canonical owner
binding, so route the person through device linking rather than showing a
generic error. Use `resolveExactKeyExportLane` and `exportKeypairWithUI`
directly when you want to check export availability before opening the viewer.

Never place the returned key material in logs, URLs, or application analytics.

## Recover a wallet account

Synchronize the wallet record when your recovery flow needs to restore its
wallet-scoped account identity.

<<< ../examples/recovery.ts

Check `success` before reading `walletId` or `nearAccountId`. The helper throws
for a failed synchronization so the caller can render a retry state.

## Delegation and rotation

Delegated agents, lane refresh, and key rotation add policy and deployment
choices that depend on your product. Start with [delegated agents](/guides/delegated-agents),
[linked devices](/guides/linked-devices), or [recovery, export, and rotation](/guides/recovery-export-and-rotation).

## Safe retries

- Ask for fresh authorization after cancellation or session expiry.
- Do not retry export or rotation with a stale session.
- Revoke a linked device or delegated lane when it should no longer sign.
