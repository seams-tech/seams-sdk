import {
  buildBearerAuthorizationHeader,
  buildRelayerJsonPostRequestInit,
  normalizeRelayerBaseUrl,
} from './relayerHttp';

/**
 * Replacing a wallet's recovery codes.
 *
 * The caller has already opened custody and re-wrapped the same manifest KEK
 * under ten fresh codes; this only swaps which codes unwrap it. The server
 * never holds the seed and cannot check that the wraps are the right ones —
 * it checks the set's shape.
 *
 * `issuedAtMs` comes back because it is what re-arms the backup prompt. A
 * client that shows the new codes without recording it cannot tell whether the
 * user has acknowledged the set in front of them, and the user is either
 * nagged about codes they saved or never asked about codes they did not.
 */

const WALLET_RECOVERY_ROTATE_PATH = '/wallets/recovery/rotate';

export type WalletRecoveryRotateResult =
  | { readonly kind: 'rotated'; readonly issuedAtMs: number; readonly storeVersion: string }
  /** The wallet has no codes to replace. */
  | { readonly kind: 'no_recovery_set'; readonly message: string }
  /** Recovery finalization or another rotation landed first; re-read and retry. */
  | { readonly kind: 'conflict'; readonly message: string }
  /** The set was refused — wrong shape, or a clock that did not advance. */
  | { readonly kind: 'rejected'; readonly message: string }
  | { readonly kind: 'transport_failed'; readonly message: string };

export async function rotateWalletRecoveryCodes(args: {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly sessionToken: string;
  /** Ten wraps of the same manifest KEK, under fresh codes. */
  readonly manifestKekWraps: readonly Record<string, unknown>[];
  readonly fetchImpl?: typeof fetch;
}): Promise<WalletRecoveryRotateResult> {
  const url = `${normalizeRelayerBaseUrl(args.relayUrl)}${WALLET_RECOVERY_ROTATE_PATH}`;
  const doFetch = args.fetchImpl || fetch;

  let response: Response;
  try {
    response = await doFetch(
      url,
      buildRelayerJsonPostRequestInit({
        headers: buildBearerAuthorizationHeader({
          token: args.sessionToken,
          missingMessage: 'wallet recovery rotation requires an app session',
        }),
        body: { walletId: args.walletId, manifestKekWraps: args.manifestKekWraps },
      }),
    );
  } catch (error: unknown) {
    return {
      kind: 'transport_failed',
      message: error instanceof Error ? error.message : 'rotation request failed',
    };
  }

  const bodyUnknown: unknown = await response.json().catch(() => ({}));
  const body = isRecord(bodyUnknown) ? bodyUnknown : {};
  const message = typeof body.message === 'string' ? body.message : '';

  if (response.status === 200 && body.ok === true) {
    const issuedAtMs = Number(body.issuedAtMs);
    if (!Number.isFinite(issuedAtMs) || issuedAtMs <= 0) {
      /* Without it the caller cannot record which issuance the user is about
         to acknowledge, so this is a failure rather than a rotation whose
         bookkeeping quietly goes missing. */
      return { kind: 'transport_failed', message: 'rotation returned no issuance timestamp' };
    }
    return { kind: 'rotated', issuedAtMs, storeVersion: String(body.storeVersion || '').trim() };
  }
  if (response.status === 404) {
    return { kind: 'no_recovery_set', message: message || 'this wallet has no codes to rotate' };
  }
  if (response.status === 409) {
    return { kind: 'conflict', message: message || 'the recovery set changed; try again' };
  }
  if (response.status === 400) {
    return { kind: 'rejected', message: message || 'the replacement code set was refused' };
  }
  return {
    kind: 'transport_failed',
    message: message || `rotation failed (HTTP ${response.status})`,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
