---
title: Linked devices
description: Link a second user-controlled device through a short-lived QR session and explicit approval on the existing device.
---

# Linked devices

Device linking gives a new device its own credential and lane. The existing
device approves the relationship; it does not transfer its credential.

## Flow

The new device starts a short-lived linking session and displays a QR code. The
existing device scans the code, shows the exact wallet and device request, and
approves it with fresh authentication. Both devices then observe the final
result.

Expire abandoned sessions, stop polling when the UI unmounts, and make repeat
scans idempotent. Display the device name and creation time after success so the
user can recognize and revoke it later.

Use the React `useDeviceLinking`, `useQRCamera`, `QRCodeScanner`, and
`ShowQRCode` surfaces where they fit. Handle every `LinkDeviceResult` branch.

See [linked devices](/concepts/delegation/linked-devices) for protocol and
revocation detail.
