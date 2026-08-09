import {
  buildBearerAuthorizationHeader,
  buildRelayerJsonPostRequestInit,
  normalizeRelayerBaseUrl,
} from './relayerHttp';
import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';
import { redactedPasskeyRegistrationCredential } from '@/SeamsWeb/operations/authMethods/passkey/ecdsaBootstrap';
import {
  parsePasskeyCustodyEnvelopeRecord,
  type PasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';

/**
 * Installing the replacement credential a recovery enrolled.
 *
 * Sent after activation, carrying an envelope this client sealed under the new
 * credential. The server cannot open that ciphertext because it has no seed.
 * It queries its signer registry and exact activation receipts before a
 * `promoted` reply can consume the code and retire old credentials.
 *
 * `retireFailures` is the field callers forget. The wallet is recovered, but
 * a credential the user was replacing still opens it; surfacing it is the
 * difference between a stale credential someone revokes and one nobody knows
 * about.
 */

const WALLET_RECOVERY_FINALIZE_PATH = '/wallets/recovery/finalize';

export type WalletRecoveryFinalizeResult =
  | {
      readonly kind: 'promoted';
      readonly storeVersion: string;
      readonly retiredEnvelopeIds: readonly string[];
      /** Old credentials that still open the wallet. Usually empty. */
      readonly retireFailures: readonly string[];
    }
  /** The recovery did not reproduce every required key set. */
  | { readonly kind: 'incomplete'; readonly message: string }
  /** The envelope was refused; repeating will not help. */
  | { readonly kind: 'envelope_rejected'; readonly message: string }
  /** The replacement WebAuthn registration was refused; retrying cannot fix it. */
  | { readonly kind: 'registration_rejected'; readonly message: string }
  | { readonly kind: 'conflict'; readonly message: string }
  | { readonly kind: 'transport_failed'; readonly message: string };

export async function finalizeWalletRecovery(args: {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly sessionToken: string;
  readonly reservationId: string;
  readonly challengeId: string;
  readonly replacementId: string;
  readonly webauthnRegistration: WebAuthnRegistrationCredential;
  readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly fetchImpl?: typeof fetch;
}): Promise<WalletRecoveryFinalizeResult> {
  const url = `${normalizeRelayerBaseUrl(args.relayUrl)}${WALLET_RECOVERY_FINALIZE_PATH}`;
  const doFetch = args.fetchImpl || fetch;
  let webauthnRegistration: WebAuthnRegistrationCredential;
  try {
    webauthnRegistration = redactedPasskeyRegistrationCredential(args.webauthnRegistration);
  } catch {
    return {
      kind: 'registration_rejected',
      message: 'the replacement registration is unusable',
    };
  }
  let replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  try {
    replacementEnvelope = parsePasskeyCustodyEnvelopeRecord(
      args.replacementEnvelope,
      'walletRecoveryFinalize.replacementEnvelope',
    );
    if (String(replacementEnvelope.walletId) !== String(args.walletId)) {
      throw new Error('replacement envelope changed the wallet identity');
    }
    if (String(replacementEnvelope.envelopeId) !== String(args.replacementId)) {
      throw new Error('replacement envelope changed the replacement identity');
    }
    if (replacementEnvelope.factor.kind !== 'passkey') {
      throw new Error('replacement envelope is not bound to a passkey');
    }
  } catch {
    return {
      kind: 'envelope_rejected',
      message: 'the replacement envelope is unusable',
    };
  }

  let response: Response;
  try {
    response = await doFetch(
      url,
      buildRelayerJsonPostRequestInit({
        headers: buildBearerAuthorizationHeader({
          token: args.sessionToken,
          missingMessage: 'wallet recovery finalization requires an app session',
        }),
        body: {
          walletId: args.walletId,
          reservationId: args.reservationId,
          challengeId: args.challengeId,
          replacementId: args.replacementId,
          webauthnRegistration,
          replacementEnvelope,
        },
      }),
    );
  } catch (error: unknown) {
    return {
      kind: 'transport_failed',
      message: error instanceof Error ? error.message : 'recovery finalization request failed',
    };
  }

  const bodyUnknown: unknown = await response.json().catch(() => ({}));
  const body = isRecord(bodyUnknown) ? bodyUnknown : {};
  const message = typeof body.message === 'string' ? body.message : '';

  if (response.status === 200 && body.ok === true) {
    const storeVersion = String(body.storeVersion || '').trim();
    if (!storeVersion) {
      return {
        kind: 'transport_failed',
        message: 'recovery finalization returned no store version',
      };
    }
    return {
      kind: 'promoted',
      storeVersion,
      retiredEnvelopeIds: stringList(body.retiredEnvelopeIds),
      /* Defaulted to empty rather than left undefined: a caller checking
         `.length` should not have to know the field is conditional. */
      retireFailures: stringList(body.retireFailures),
    };
  }
  if (response.status === 409) {
    if (body.code === 'recovery_conflict') {
      return { kind: 'conflict', message: message || 'recovery finalization conflicted' };
    }
    return { kind: 'incomplete', message: message || 'recovery did not reproduce every key set' };
  }
  if (response.status === 400) {
    if (body.code === 'registration_rejected') {
      return {
        kind: 'registration_rejected',
        message: message || 'the replacement registration was refused',
      };
    }
    return {
      kind: 'envelope_rejected',
      message: message || 'the replacement envelope was refused',
    };
  }
  return {
    kind: 'transport_failed',
    message: message || `recovery finalization failed (HTTP ${response.status})`,
  };
}

function stringList(value: unknown): readonly string[] {
  if (!Array.isArray(value)) return [];
  return value.map((entry) => String(entry || '').trim()).filter(Boolean);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
