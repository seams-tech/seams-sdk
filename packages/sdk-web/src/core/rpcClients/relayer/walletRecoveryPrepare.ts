import {
  buildBearerAuthorizationHeader,
  buildRelayerJsonPostRequestInit,
  normalizeRelayerBaseUrl,
} from './relayerHttp';

/**
 * Preparing an admitted wallet recovery.
 *
 * The response is ciphertext: a wrapped manifest KEK and the entry ciphertexts
 * it opens. The code never leaves this call, and the server cannot open what
 * it returns — it only matched a derived identifier against stored wraps.
 *
 * **`rejected` says nothing about why.** The server answers identically for an
 * unknown wallet, an unknown code, a spent code and a malformed one, so that
 * the route cannot be used to count how many of a user's ten codes remain.
 * This keeps that: no client-side guess at which case it was, however helpful
 * a "you already used this one" would be to show.
 *
 * `conflict` is the exception worth distinguishing, because it is the one
 * failure where the same code is still worth trying again.
 */

const WALLET_RECOVERY_PREPARE_PATH = '/wallets/recovery/prepare';

export type WalletRecoveryPrepareResult =
  | {
      readonly kind: 'prepared';
      readonly wrap: {
        readonly nonceB64u: string;
        readonly wrappedManifestKekB64u: string;
        readonly aadHashB64u: string;
      };
      readonly entries: readonly Record<string, unknown>[];
      readonly reservationId: string;
      readonly reservationExpiresAtMs: number;
      readonly storeVersion: string;
    }
  /** The code did not work. Deliberately without a reason. */
  | { readonly kind: 'rejected'; readonly message: string }
  /** Another attempt landed first; this code may still be good. */
  | { readonly kind: 'conflict'; readonly message: string }
  | { readonly kind: 'transport_failed'; readonly message: string };

export async function prepareWalletRecovery(args: {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly sessionToken: string;
  readonly challengeId: string;
  readonly otpCode: string;
  /** Base64url of the decoded code. Not persisted, not logged. */
  readonly recoveryCode: string;
  readonly reservationId: string;
  readonly fetchImpl?: typeof fetch;
}): Promise<WalletRecoveryPrepareResult> {
  const url = `${normalizeRelayerBaseUrl(args.relayUrl)}${WALLET_RECOVERY_PREPARE_PATH}`;
  const doFetch = args.fetchImpl || fetch;

  let response: Response;
  try {
    response = await doFetch(
      url,
      buildRelayerJsonPostRequestInit({
        headers: buildBearerAuthorizationHeader({
          token: args.sessionToken,
          missingMessage: 'wallet recovery preparation requires an app session',
        }),
        body: {
          walletId: args.walletId,
          recoveryCode: args.recoveryCode,
          reservationId: args.reservationId,
          challengeId: args.challengeId,
          otpCode: args.otpCode,
        },
      }),
    );
  } catch (error: unknown) {
    return {
      kind: 'transport_failed',
      message: error instanceof Error ? error.message : 'recovery preparation request failed',
    };
  }

  const bodyUnknown: unknown = await response.json().catch(() => ({}));
  const body = isRecord(bodyUnknown) ? bodyUnknown : {};
  const message = typeof body.message === 'string' ? body.message : '';

  if (response.status === 200 && body.ok === true) {
    const wrap = isRecord(body.wrap) ? body.wrap : null;
    const nonceB64u = String(wrap?.nonceB64u || '').trim();
    const wrappedManifestKekB64u = String(wrap?.wrappedManifestKekB64u || '').trim();
    const aadHashB64u = String(wrap?.aadHashB64u || '').trim();
    const reservationId = String(body.reservationId || '').trim();
    const reservationExpiresAtMs = Number(body.reservationExpiresAtMs);
    if (
      !nonceB64u ||
      !wrappedManifestKekB64u ||
      !aadHashB64u ||
      reservationId !== args.reservationId ||
      !Number.isSafeInteger(reservationExpiresAtMs) ||
      reservationExpiresAtMs <= 0
    ) {
      return {
        kind: 'transport_failed',
        message: 'recovery preparation returned an unusable payload',
      };
    }
    return {
      kind: 'prepared',
      wrap: { nonceB64u, wrappedManifestKekB64u, aadHashB64u },
      entries: Array.isArray(body.entries)
        ? (body.entries.filter(isRecord) as Record<string, unknown>[])
        : [],
      reservationId,
      reservationExpiresAtMs,
      storeVersion: String(body.storeVersion || '').trim(),
    };
  }

  if (response.status === 409) {
    return { kind: 'conflict', message: message || 'the recovery set changed; try again' };
  }
  if (response.status === 401 || response.status === 400) {
    return { kind: 'rejected', message: message || 'that recovery code cannot be used' };
  }
  return {
    kind: 'transport_failed',
    message: message || `recovery preparation failed (HTTP ${response.status})`,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
