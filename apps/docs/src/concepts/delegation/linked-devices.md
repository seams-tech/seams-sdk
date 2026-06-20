---
title: Linked Devices
---

# Linked Devices

Device linking creates a distinct signing lane for another user-controlled
device.

## Flow

1. A new device presents a QR link session with a link public key.
2. An existing owner device authenticates the user and approves permissions.
3. The owner worker creates a distinct holder share for the linked device.
4. The server creates the matching server share for the linked-device lane.
5. The linked device receives an encrypted holder-share package.
6. The lane activates after delivery receipt and address parity checks.

The linked device has its own `laneId`, `laneShareEpoch`, holder-share envelope,
permission policy, revocation status, and audit history.

Owner-equivalent linked-device lanes should require local user presence for
signing. Scoped linked-device lanes should use the same mandate admission model
as delegated agents.
