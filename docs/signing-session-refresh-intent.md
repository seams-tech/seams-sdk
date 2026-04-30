The intended behavior should be:

Core Rule
A valid signing session survives page refresh. Refresh should not force OTP or passkey again just because worker memory was lost. The durable sealed session in IndexedDB is the restore source of truth; worker memory is only hot unsealed material.

Normal Flow

User unlocks wallet with OTP or passkey.
App creates/restores signing sessions for Ed25519 and/or ECDSA.
User signs transactions without extra auth while the wallet signing session is active and has remaining budget.
User refreshes the page.
On the next signing command, the exact needed lane is restored from sealed durable state.
The transaction signs without OTP/passkey, assuming budget is still valid.
Session Exhaustion
After the signing session budget is exhausted:

OTP accounts: next Ed25519/ECDSA transaction should show Email OTP.
Passkey accounts: next Ed25519/ECDSA transaction should trigger passkey/TouchID.
After successful step-up, signing continues under a fresh/renewed signing session.
Important Non-Goals
Refresh is not exhaustion.
Missing worker memory is not exhaustion.
Missing sessionStorage is not exhaustion.
A status poll should not unseal, restore, consume, delete, or prompt.

Storage Ownership

IndexedDB: durable sealed restore records plus durable non-secret lane identity.
Worker memory: hot unsealed signing material only.
Server: authoritative session validity and remaining-use budget.
JS memory: operation-local prepared identity.
sessionStorage: not required for signing-session correctness.
Per-Curve Intent
Ed25519 and ECDSA must restore independently and exactly:

NEAR Ed25519 signing restores Ed25519 material.
Tempo/ARC/EVM signing restores ECDSA material for the requested chain.
One curve should not accidentally work only because another curve’s restore path had side effects.
Security Boundary
Transaction signing should go through a command boundary:

exact intent
exact restore
exact lane selection
trusted budget status
reserve
sign
authoritative consume/finalize
Reads/snapshots only report state. They must not repair state as a side effect.