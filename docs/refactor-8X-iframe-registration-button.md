# Immediate Wallet-Origin Registration Modal

Date: July 18, 2026

Status: implemented

## Intent

Improve the passkey registration experience:

- open the wallet-origin registration modal immediately after the user clicks
  the app registration button;
- minimize the elapsed time from that click to the browser passkey prompt.

## Decision

Passkey registration uses one ordinary app-origin button and one wallet-origin
modal flow.

1. The user clicks the app registration button.
2. The wallet origin immediately mounts a modal in a loading state.
3. Registration intent preparation and registration-specific client warm-up
   start behind the visible modal and run concurrently.
4. The same modal element switches from loading to the existing passkey
   confirmation content as soon as the exact registration authority is ready.
5. The user confirms and `navigator.credentials.create()` starts from the
   wallet-origin modal.

The iframe-owned activation button, transparent anchored hit target, geometry
mirroring, prepared-activation continuation, and their public APIs are removed.

## Scope

This refactor changes the browser interaction and preparation ordering only.
The existing registration transports, authentication branches, server
endpoints, intent semantics, and registration cryptography remain in place.

The implementation covers:

- an ordinary registration CTA in `SeamsAuthMenu`;
- registration-runtime, modal-element, and modal-style preload during the
  wallet iframe configuration handshake;
- an enabled passkey CTA only after that handshake completes;
- an immediate wallet-origin loading modal;
- one continuous modal element from preparation through passkey confirmation;
- parallel modal mounting and existing registration precompute;
- cleanup of activation messages, router branches, public APIs, assets, and
  tests;
- cancellation of an intent that finishes preparing after modal setup fails;
- closing the preparation modal on success, cancellation, and failure.

## Lifecycle

```text
app click
  -> wallet iframe registerWallet request
  -> open wallet-origin loading modal
     + start registration precompute
       -> intent preparation
       + registration client warm-up
  -> replace loading modal with passkey confirmation
  -> user confirms
  -> navigator.credentials.create()
  -> finish registration
```

The modal request is started before precompute. Both promises are awaited
together, so asset/custom-element mounting does not delay network and client
preparation. The preparation handle transfers to the confirmation flow, which
updates the mounted element in place and avoids a second portal animation.

## State and ownership

The wallet signing surface owns the preparation modal. Its internal state is a
discriminated union:

- `closed`;
- `opening`, with a generation;
- `open`, with the matching generation and modal handle.

Generation checks prevent a late modal mount from reviving a closed or replaced
surface. The regular confirmation flow keeps ownership of the ready and
WebAuthn-prompt states.

Wallet iframe surface arbitration now contains request-owned fullscreen
surfaces only. Registration no longer has an anchored activation identity or a
second ownership model.

## User-visible behavior

The loading modal displays:

- `Create your passkey`;
- `Preparing secure registration…`;
- the wallet label, or `New wallet` while the server allocates it;
- the wallet RP ID;
- a loading state until the existing confirmation flow is ready.

An invalid wallet label, signer slot, or RP ID fails at the UI boundary. A
preparation failure closes the loading modal and follows the existing
registration error path.

## Acceptance criteria

- The app registration CTA is a standard button wired directly to
  `controller.onProceed`.
- The passkey CTA stays disabled until the wallet iframe configuration
  handshake has preloaded the registration runtime, modal element, and modal
  styles.
- The wallet-origin loading modal begins mounting before registration
  precompute begins.
- Modal mounting and precompute run concurrently.
- Loading-to-confirmation handoff preserves the same confirmer element.
- Intent allocation and registration-specific client warm-up retain their
  existing concurrency.
- The passkey prompt still runs at the wallet origin.
- Email OTP and other registration branches retain their existing behavior.
- No activation-surface API, message, router branch, component, style, fixture,
  or test remains.
- SDK type checking and the focused iframe, WebAuthn-origin, registration
  capability, and UI tests pass.

## Validation

The focused checks cover:

- immediate loading-modal configuration;
- modal-before-precompute ordering and concurrent awaiting;
- wallet-origin WebAuthn policy;
- modal-only iframe surface arbitration;
- the ordinary registration CTA;
- absence of activation compatibility paths.
