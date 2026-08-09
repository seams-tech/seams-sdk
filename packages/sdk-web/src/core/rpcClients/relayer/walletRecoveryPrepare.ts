import {
  buildBearerAuthorizationHeader,
  buildRelayerJsonPostRequestInit,
  normalizeRelayerBaseUrl,
} from './relayerHttp';
import {
  parseDigestField,
  parseEnvelopeCiphertextB64u,
  parseEnvelopeNonceB64u,
  parseUnixMs,
  rejectUnknownFields,
  requireRecord,
  type EnvelopeCiphertextB64u,
  type EnvelopeNonceB64u,
} from '@shared/passkey-custody';
import {
  parseWalletRecoveryEnvelopeEntry,
  type WalletRecoveryEnvelopeEntry,
} from '@shared/wallet-recovery';
import type { DigestB64u } from '@shared/utils';
import { parseWalletId } from '@shared/utils/domainIds';

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
        readonly nonceB64u: EnvelopeNonceB64u;
        readonly wrappedManifestKekB64u: EnvelopeCiphertextB64u;
        readonly aadHashB64u: DigestB64u;
      };
      readonly entries: readonly [WalletRecoveryEnvelopeEntry];
      readonly reservationId: string;
      readonly reservationExpiresAtMs: number;
      readonly storeVersion: string;
    }
  /** The code did not work. Deliberately without a reason. */
  | { readonly kind: 'rejected'; readonly message: string }
  /** Another attempt landed first; this code may still be good. */
  | { readonly kind: 'conflict'; readonly message: string }
  | { readonly kind: 'transport_failed'; readonly message: string };

export type PreparedWalletRecovery = Extract<
  WalletRecoveryPrepareResult,
  { readonly kind: 'prepared' }
>;

/**
 * Builds the only recovery-custody wire accepted by the ceremony WASM.
 *
 * The recovery key id and code are absent. Rust derives the id from the code
 * bytes supplied through the worker's separate secret field, so serialized
 * custody can contain only the reserved wrap and the wallet's single seed
 * entry.
 */
export function buildWalletRecoveryCeremonyCustodyJson(args: {
  readonly walletId: string;
  readonly prepared: PreparedWalletRecovery;
}): string {
  const walletId = parseWalletId(args.walletId);
  if (!walletId.ok) throw new Error(`wallet recovery ${walletId.error.message}`);
  return JSON.stringify({
    walletId: String(walletId.value),
    wrap: args.prepared.wrap,
    entry: args.prepared.entries[0],
  });
}

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
    try {
      const wrap = parsePreparedRecoveryWrap(body.wrap);
      const entries = parsePreparedRecoveryEntries(body.entries);
      const reservationId = requireResponseString(body.reservationId, 'reservationId');
      const reservationExpiresAtMs = parseUnixMs(
        body.reservationExpiresAtMs,
        'walletRecoveryPrepare.reservationExpiresAtMs',
      );
      const storeVersion = requireResponseString(body.storeVersion, 'storeVersion');
      if (reservationId !== args.reservationId) {
        throw new Error('wallet recovery preparation changed the reservation identity');
      }
      return {
        kind: 'prepared',
        wrap,
        entries,
        reservationId,
        reservationExpiresAtMs,
        storeVersion,
      };
    } catch {
      return {
        kind: 'transport_failed',
        message: 'recovery preparation returned an unusable payload',
      };
    }
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

const PREPARED_WRAP_FIELDS = ['nonceB64u', 'wrappedManifestKekB64u', 'aadHashB64u'] as const;

function parsePreparedRecoveryWrap(raw: unknown): {
  readonly nonceB64u: EnvelopeNonceB64u;
  readonly wrappedManifestKekB64u: EnvelopeCiphertextB64u;
  readonly aadHashB64u: DigestB64u;
} {
  const wrap = requireRecord(raw, 'walletRecoveryPrepare.wrap');
  rejectUnknownFields(wrap, PREPARED_WRAP_FIELDS, 'walletRecoveryPrepare.wrap');
  return {
    nonceB64u: parseEnvelopeNonceB64u(wrap.nonceB64u, 'walletRecoveryPrepare.wrap.nonceB64u'),
    wrappedManifestKekB64u: parseEnvelopeCiphertextB64u(
      wrap.wrappedManifestKekB64u,
      'walletRecoveryPrepare.wrap.wrappedManifestKekB64u',
    ),
    aadHashB64u: parseDigestField(wrap.aadHashB64u, 'walletRecoveryPrepare.wrap.aadHashB64u'),
  };
}

function parsePreparedRecoveryEntries(raw: unknown): readonly [WalletRecoveryEnvelopeEntry] {
  if (!Array.isArray(raw) || raw.length !== 1) {
    throw new Error('walletRecoveryPrepare.entries must contain exactly one custody seed');
  }
  return [parseWalletRecoveryEnvelopeEntry(raw[0], 'walletRecoveryPrepare.entries[0]')];
}

function requireResponseString(raw: unknown, field: string): string {
  if (typeof raw !== 'string' || !raw.trim()) {
    throw new Error(`walletRecoveryPrepare.${field} must be a non-empty string`);
  }
  return raw.trim();
}
