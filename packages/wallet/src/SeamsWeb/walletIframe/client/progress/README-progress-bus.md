# Wallet Iframe Progress Bus

`OnEventsProgressBus` forwards typed `WalletFlowEvent` payloads from the wallet
iframe to the matching app callback. It records per-request flow, phase,
status, count, and timestamp diagnostics.

The progress bus does not control the iframe DOM. In particular,
`event.interaction.overlay` is progress metadata and cannot show, hide, move,
or focus the wallet iframe.

## Surface Ownership

`WalletIframeRouter` creates one typed foreground surface for each request that
requires wallet-origin UI:

- `modal_registration_confirm`
- `modal_transaction_confirm`
- `modal_key_export_confirm`
- `modal_unlock_confirm`

The surface renderer is the only code that changes iframe visibility,
focusability, pointer events, title, or geometry. A result, error, timeout, or
cancel event clears only the surface whose connection and request identity
match the active owner. A stale result cannot hide a successor.

Key export keeps its progress subscription after its initial `PM_RESULT` so the
host can report the viewer lifecycle. Its surface finishes when the matching
terminal progress event arrives.

## Registration And Signing Activation

The registration activation button is an anchored surface. Its click occurs in
wallet-origin iframe DOM and starts `navigator.credentials.create()` inline.

Code-only registration, transaction signing, key export, unlock, and device
link use wallet-origin modal surfaces. Their confirmation controls remain the
wallet-origin source of user activation. App-origin callbacks receive progress
but never mint activation or manipulate the iframe.
