import { base64UrlEncode } from '@shared/utils/base64';
import { isPlainObject } from '@shared/utils/validation';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import type { WebAuthnCredentialIdB64u, WebAuthnRpId } from '@shared/utils/domainIds';
import { verifyWebAuthnAuthenticationLiteWithStore } from '../../../core/authService/webauthn';
import { decodeBase64UrlOrBase64 } from '../../../core/authService/webauthnOidcHelpers';
import type { WebAuthnAuthenticatorStore } from '../../../core/WebAuthnAuthenticatorStore';
import type { WebAuthnAuthenticationCredential } from '../../../core/types';
import type { NormalizedLogger } from '../../../core/logger';
import type {
  CloudflareD1PasskeyCustodyEnvelopeStore,
  PasskeyCustodyEnvelopeLocator,
  WalletCustodyFactorRef,
} from '../../cloudflare/d1/passkeyCustody/d1PasskeyCustodyEnvelopeStore';

/**
 * A locator narrowed to the passkey factor. Email OTP envelopes are
 * unrepresentable in this request type: their factor secret is not a
 * credential, so a WebAuthn assertion is never evidence for them.
 */
export type PasskeyEnvelopeRetrievalLocator = Omit<PasskeyCustodyEnvelopeLocator, 'factor'> & {
  readonly factor: Extract<WalletCustodyFactorRef, { kind: 'passkey' }>;
};

/**
 * Authenticated retrieval of one server-held passkey custody envelope.
 *
 * This path serves passkey-factor envelopes only: it is gated on a WebAuthn
 * assertion, which an Email OTP envelope has no counterpart for. Email OTP
 * envelopes are retrieved through the Email OTP admission boundary instead.
 *
 * Retrieval requires a server-verified assertion for the exact wallet, RP ID,
 * credential ID, and operation challenge. The response carries ciphertext and
 * public binding only: the KEK is derived from the PRF result, which never
 * leaves the browser's secure worker, so this path cannot open what it returns.
 */

export type PasskeyCustodyEnvelopeRetrievalRequest = {
  readonly locator: PasskeyEnvelopeRetrievalLocator;
  readonly rpId: WebAuthnRpId;
  readonly userId: string;
  readonly expectedChallenge: string;
  readonly expectedOrigin: string;
  /**
   * The assertion with its extension outputs already removed. The PRF result
   * must be stripped in the worker before the assertion crosses this boundary.
   */
  readonly webauthnAuthentication: WebAuthnAuthenticationCredential;
};

export type PasskeyCustodyEnvelopeRetrievalResult =
  | {
      readonly kind: 'active';
      readonly envelope: PasskeyCustodyEnvelopeRecord;
      readonly storeVersion: string;
    }
  /**
   * The assertion still carried WebAuthn extension output. A PRF result that
   * reaches the server has already escaped the worker, so the request fails
   * loudly instead of being silently sanitized and served.
   */
  | { readonly kind: 'prf_disclosed'; readonly message: string }
  | { readonly kind: 'assertion_rejected'; readonly code: string; readonly message: string }
  | { readonly kind: 'credential_mismatch' }
  | { readonly kind: 'retired'; readonly retiredAtMs: number }
  | { readonly kind: 'revoked'; readonly revokedAtMs: number }
  | { readonly kind: 'missing' }
  | { readonly kind: 'digest_mismatch' };

/**
 * Detects any surviving WebAuthn extension output on an assertion.
 *
 * This checks for extension results generally rather than a `prf` key alone: a
 * caller that forwards raw extension outputs is not honouring the redaction
 * contract, and the next extension to carry secret material would otherwise
 * pass unnoticed.
 */
function disclosedExtensionOutputs(credential: WebAuthnAuthenticationCredential): string | null {
  const top = (credential as { clientExtensionResults?: unknown }).clientExtensionResults;
  if (isPlainObject(top) && Object.keys(top).length > 0) {
    return 'webauthn_authentication.clientExtensionResults must be redacted before retrieval';
  }
  const response = (credential as { response?: unknown }).response;
  if (isPlainObject(response)) {
    const nested = (response as { clientExtensionResults?: unknown }).clientExtensionResults;
    if (isPlainObject(nested) && Object.keys(nested).length > 0) {
      return 'webauthn_authentication.response.clientExtensionResults must be redacted before retrieval';
    }
  }
  return null;
}

function assertionCredentialIdB64u(
  credential: WebAuthnAuthenticationCredential,
): WebAuthnCredentialIdB64u | null {
  const raw = (credential as { rawId?: unknown; id?: unknown }).rawId;
  const fallback = (credential as { id?: unknown }).id;
  const chosen =
    typeof raw === 'string' && raw.trim()
      ? raw.trim()
      : typeof fallback === 'string'
        ? fallback.trim()
        : '';
  if (!chosen) return null;
  try {
    // Normalize through decode/encode so a padded or standard-base64 assertion
    // id compares equal to the unpadded base64url form on the envelope.
    return base64UrlEncode(
      decodeBase64UrlOrBase64(chosen, 'webauthn_authentication.rawId'),
    ) as WebAuthnCredentialIdB64u;
  } catch {
    return null;
  }
}

/**
 * The assertion verifier this retrieval depends on. It is injectable so the
 * lifecycle mapping below can be tested against a verified assertion without
 * forging authenticator signatures; production callers take the default.
 */
export type PasskeyCustodyAssertionVerifier = typeof verifyWebAuthnAuthenticationLiteWithStore;

export async function retrievePasskeyCustodyEnvelope(input: {
  readonly request: PasskeyCustodyEnvelopeRetrievalRequest;
  readonly envelopeStore: CloudflareD1PasskeyCustodyEnvelopeStore;
  readonly authenticatorStore: WebAuthnAuthenticatorStore;
  readonly logger: NormalizedLogger;
  readonly verifyAssertion?: PasskeyCustodyAssertionVerifier;
}): Promise<PasskeyCustodyEnvelopeRetrievalResult> {
  const { request } = input;
  const verifyAssertion = input.verifyAssertion || verifyWebAuthnAuthenticationLiteWithStore;

  const disclosed = disclosedExtensionOutputs(request.webauthnAuthentication);
  if (disclosed !== null) {
    input.logger.error('[passkey-custody] assertion carried unredacted extension output', {
      walletId: String(request.locator.walletId),
      rpId: String(request.rpId),
    });
    return { kind: 'prf_disclosed', message: disclosed };
  }

  // The type already makes Email OTP unrepresentable here; this guard covers
  // unparsed wire input, where TypeScript's erasure offers no protection.
  if (request.locator.factor.kind !== 'passkey') {
    return {
      kind: 'assertion_rejected',
      code: 'invalid_body',
      message: 'WebAuthn retrieval serves passkey envelopes only',
    };
  }

  // The assertion is verified against request.rpId, so the envelope being
  // fetched must belong to that same relying party — otherwise an assertion
  // for one RP could retrieve ciphertext sealed under another.
  if (String(request.locator.factor.rpId) !== String(request.rpId)) {
    return {
      kind: 'assertion_rejected',
      code: 'rp_mismatch',
      message: 'Locator RP ID does not match the assertion RP ID',
    };
  }

  // The assertion must name the same credential the caller is asking an
  // envelope for; otherwise one credential's assertion could fetch another
  // credential's ciphertext.
  const assertedCredentialId = assertionCredentialIdB64u(request.webauthnAuthentication);
  if (assertedCredentialId === null) {
    return {
      kind: 'assertion_rejected',
      code: 'invalid_body',
      message: 'Missing webauthn_authentication.id/rawId',
    };
  }
  if (String(assertedCredentialId) !== String(request.locator.factor.credentialIdB64u)) {
    return { kind: 'credential_mismatch' };
  }

  const verified = await verifyAssertion({
    userId: request.userId,
    rpId: request.rpId,
    expectedChallenge: request.expectedChallenge,
    expectedOrigin: request.expectedOrigin,
    webauthnAuthentication: request.webauthnAuthentication,
    authenticatorStore: input.authenticatorStore,
    logger: input.logger,
  });
  if (!verified.success || !verified.verified) {
    return {
      kind: 'assertion_rejected',
      code: verified.code || 'not_verified',
      message: verified.message || 'Authentication verification failed',
    };
  }

  const lookup = await input.envelopeStore.lookupEnvelope(request.locator);
  switch (lookup.kind) {
    case 'active':
      return { kind: 'active', envelope: lookup.envelope, storeVersion: lookup.storeVersion };
    case 'retired':
      return { kind: 'retired', retiredAtMs: lookup.retiredAtMs };
    case 'revoked':
      return { kind: 'revoked', revokedAtMs: lookup.revokedAtMs };
    case 'digest_mismatch':
      input.logger.error('[passkey-custody] stored envelope failed its ciphertext digest', {
        walletId: String(request.locator.walletId),
        envelopeId: String(lookup.envelopeId),
      });
      return { kind: 'digest_mismatch' };
    case 'missing':
      return { kind: 'missing' };
  }
}
