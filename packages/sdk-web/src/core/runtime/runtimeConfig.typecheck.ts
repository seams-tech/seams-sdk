import type { SigningRuntimeConfig } from './runtime.types';

declare const runtimeConfig: SigningRuntimeConfig;

runtimeConfig.network;
runtimeConfig.registration;
runtimeConfig.signing;

// @ts-expect-error browser WebAuthn options are excluded from runtime config.
runtimeConfig.webauthn;

// @ts-expect-error iframe wallet settings are excluded from runtime config.
runtimeConfig.wallet;

// @ts-expect-error UI and React-facing appearance settings are excluded from runtime config.
runtimeConfig.ui;
