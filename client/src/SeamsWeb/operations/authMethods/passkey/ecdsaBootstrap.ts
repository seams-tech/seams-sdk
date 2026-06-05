import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '@/core/types';
import { normalizeRegistrationCredential } from '@/core/signingEngine/webauthnAuth/credentials/helpers';
import {
  getPrfFirstB64uFromCredential,
  redactCredentialExtensionOutputs,
} from '@/core/signingEngine/threshold/crypto/webauthn';

export function passkeyPrfFirstB64uFromCredential(credential: unknown): string {
  return String(getPrfFirstB64uFromCredential(credential) || '').trim();
}

export function requirePasskeyPrfFirstB64u(credential: unknown, context: string): string {
  const prfFirstB64u = passkeyPrfFirstB64uFromCredential(credential);
  if (!prfFirstB64u) {
    throw new Error(`${context} requires PRF.first output from the passkey credential`);
  }
  return prfFirstB64u;
}

export function passkeyCredentialIdB64uFromAuthentication(
  credential: WebAuthnAuthenticationCredential | undefined,
): string {
  return String(credential?.rawId || credential?.id || '').trim();
}

export function redactedPasskeyRegistrationCredential(
  credential: WebAuthnRegistrationCredential,
): WebAuthnRegistrationCredential {
  const webauthnRegistration = redactCredentialExtensionOutputs<WebAuthnRegistrationCredential>(
    normalizeRegistrationCredential(credential),
  );
  if (!Array.isArray(webauthnRegistration.response.transports)) {
    webauthnRegistration.response.transports = [];
  }
  return webauthnRegistration;
}
