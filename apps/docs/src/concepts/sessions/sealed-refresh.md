---
title: Sealed Refresh
---

# Sealed Refresh

Sealed refresh restores an already-authenticated signing grant after accidental
iframe or page reload, while keeping signing material out of browser storage in
plaintext.

The persisted artifact is a sealed session secret stored in wallet-origin
IndexedDB. It is useful only with live server participation and valid
server-side signing-session state.

## Rules

1. Store sealed refresh records in the wallet iframe origin.
2. Bind records to the signing grant and browser-session marker.
3. Delete records on logout, lock, account switch, revocation, expiry, and
   remaining-use exhaustion.
4. Restore only transaction signing capability.
5. Require fresh operation auth for export, linked-device creation, key
   rotation, and delegated-agent issuance.
