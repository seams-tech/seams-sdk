# seams-passkey-registration-btn

Wallet-origin activation element for iframe passkey registration.

The app domain owns the visible `.seams-passkey-registration-btn` outline. The
wallet iframe renders this custom element over that outline, and the element
owns the real trusted `<button>` click used to start WebAuthn.

This component lives with the Lit UI assets for build and ownership consistency,
while keeping its runtime narrow and independent from transaction confirmation
state.
