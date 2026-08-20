---
title: Advanced wallet operations
description: Link another device, synchronize wallet recovery, and export Ed25519 or ECDSA key material through explicit user flows.
---

# Advanced wallet operations

These operations change access or disclose key material. Start each one from a
fresh user action, keep progress visible, and retain the returned identity or
receipt for your audit trail.

## Prerequisites

Complete [wallet setup and authentication](/examples/wallet-setup-and-authentication)
and obtain an active wallet session. Device linking also needs a camera or a
way to deliver the QR payload between devices.

## Link another device

Device 2 starts a short-lived session and displays its QR code. Device 1 scans
that code and approves the request with fresh authentication.

<<< ./device-linking.tsx

`ShowQRCode` owns the Device 2 cycle end to end — starting the session,
displaying the code, and cancelling an abandoned one on close. Expire abandoned
QR sessions and show the device name after success so it can be recognized and
revoked later.

## Recover a wallet account

Call recovery synchronization with the wallet id from the account record.

<<< ./recovery.ts

The successful result exposes the restored wallet id and NEAR account id. Use
the returned values to refresh app state before rendering signing controls.

## Export an Ed25519 or ECDSA key

`exportKeypair` resolves the exact export lane and opens the wallet-origin
export viewer in one call.

<<< ./export-wallet.ts

`exportNearKey` exports the Ed25519 lane for the wallet's NEAR account;
`exportEvmKey` exports the ECDSA lane for a configured chain. Both default to
the authenticated wallet and receive progress through `KeyExportFlowEvent`.

Check the outcome: `relink_required` means this device has no canonical owner
binding, so route the person through device linking rather than showing a
generic error. `resolveExactKeyExportLane` and `exportKeypairWithUI` remain
available when you want to check export availability before opening the viewer.

## Expected result

- Device linking creates a separate device credential and lane.
- Recovery synchronization returns the restored wallet and NEAR identity.
- Export opens a protected viewer after the exact lane is authorized.

## Recoverable failures

- A cancelled or expired QR session must be started again. Do not approve an
  old QR payload.
- Recovery can return a failure result. Keep the existing account state until
  synchronization succeeds.
- Export can return `relink_required` instead of opening the viewer. That is a
  handled outcome, not an error: send the person through device linking.
- Export authorization and viewer errors should end the current disclosure
  attempt. Ask for fresh authentication before another export.

Read next: [linked devices](/guides/linked-devices), [recovery, export, and rotation](/guides/recovery-export-and-rotation), or [results and errors](/reference/results-and-errors).
