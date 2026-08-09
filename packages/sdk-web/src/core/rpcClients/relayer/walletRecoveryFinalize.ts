import {
  buildBearerAuthorizationHeader,
  buildRelayerJsonPostRequestInit,
  normalizeRelayerBaseUrl,
} from './relayerHttp';

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
  | { readonly kind: 'conflict'; readonly message: string }
  | { readonly kind: 'transport_failed'; readonly message: string };

export async function finalizeWalletRecovery(args: {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly sessionToken: string;
  readonly reservationId: string;
  readonly replacementEnvelope: Record<string, unknown>;
  readonly fetchImpl?: typeof fetch;
}): Promise<WalletRecoveryFinalizeResult> {
  const url = `${normalizeRelayerBaseUrl(args.relayUrl)}${WALLET_RECOVERY_FINALIZE_PATH}`;
  const doFetch = args.fetchImpl || fetch;

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
          replacementEnvelope: args.replacementEnvelope,
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
    return {
      kind: 'promoted',
      storeVersion: String(body.storeVersion || '').trim(),
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
