---
title: Recovery, export, and rotation
description: Design fresh-auth recovery, wallet export, signer rotation, and key-version changes as separate high-impact operations.
---

# Recovery, export, and rotation

Recovery restores authorized access. Export reveals key material. Rotation
changes a signer, custody share, or wallet key version. Keep these operations
separate in UI, policy, audit, and result handling.

## Safety sequence

1. Require fresh operation-specific authentication.
2. Display the exact wallet and consequence.
3. Apply policy, cooldown, notification, and step-up requirements.
4. Complete the recovery, export, or rotation ceremony.
5. Verify resulting identity and public-key invariants.
6. Revoke obsolete sessions or lanes and write an audit receipt.

Export viewers belong on the wallet origin and should minimize key exposure.
Rotation that preserves the wallet address needs explicit parity checks;
rekeying can intentionally create a new address.

Continue with [recovery and export](/concepts/custody/recovery-and-export) and
[key rotation](/concepts/delegation/key-rotation).
