import { buildRelayerJsonPostRequestInit, normalizeRelayerBaseUrl } from './relayerHttp';

/**
 * Installing the replacement credential a recovery enrolled.
 *
 * Sent after a spend, carrying an envelope this client sealed under the new
 * credential. The server cannot check that sealing — it has no seed — so a
 * `promoted` reply means the envelope was stored and the old credentials
 * retired, not that the new credential has been proven to open anything. The
 * proof of that is the next unlock.
 *
 * `retireFailures` is the field callers forget. The wallet is recovered, but
 * a credential the user was replacing still opens it; surfacing it is the
 * difference between a stale credential someone revokes and one nobody knows
 * about.
 */

const WALLET_RECOVERY_PROMOTE_PATH = '/wallets/recovery/promote';

export type WalletRecoveryPromoteResult =
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
  | { readonly kind: 'transport_failed'; readonly message: string };

export async function promoteRecoveredWalletCredential(args: {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly replacementEnvelope: Record<string, unknown>;
  readonly requiredKeySets: readonly string[];
  readonly outcomes: readonly Record<string, unknown>[];
  readonly fetchImpl?: typeof fetch;
}): Promise<WalletRecoveryPromoteResult> {
  const url = `${normalizeRelayerBaseUrl(args.relayUrl)}${WALLET_RECOVERY_PROMOTE_PATH}`;
  const doFetch = args.fetchImpl || fetch;

  let response: Response;
  try {
    response = await doFetch(
      url,
      buildRelayerJsonPostRequestInit({
        body: {
          walletId: args.walletId,
          replacementEnvelope: args.replacementEnvelope,
          requiredKeySets: args.requiredKeySets,
          outcomes: args.outcomes,
        },
      }),
    );
  } catch (error: unknown) {
    return {
      kind: 'transport_failed',
      message: error instanceof Error ? error.message : 'promotion request failed',
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
    message: message || `promotion failed (HTTP ${response.status})`,
  };
}

function stringList(value: unknown): readonly string[] {
  if (!Array.isArray(value)) return [];
  return value.map((entry) => String(entry || '').trim()).filter(Boolean);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
