import {
  buildBearerAuthorizationHeader,
  buildRelayerJsonPostRequestInit,
  normalizeRelayerBaseUrl,
} from './relayerHttp';
import {
  parseWalletRecoveryEnvelopeSetRecord,
  type WalletRecoveryEnvelopeSetRecord,
} from '@shared/wallet-recovery/walletRecoveryEnvelopeSet';

const WALLET_RECOVERY_READ_PATH = '/wallets/recovery/read';
const WALLET_RECOVERY_ROTATE_PATH = '/wallets/recovery/rotate';

export type WalletRecoverySetReadResult =
  | {
      readonly kind: 'ready';
      readonly recoverySet: WalletRecoveryEnvelopeSetRecord;
      readonly storeVersion: string;
    }
  | { readonly kind: 'no_recovery_set'; readonly message: string }
  | { readonly kind: 'transport_failed'; readonly message: string };

export async function readWalletRecoverySet(args: {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly sessionToken: string;
  readonly fetchImpl?: typeof fetch;
}): Promise<WalletRecoverySetReadResult> {
  return await requestWalletRecoverySet({
    ...args,
    path: WALLET_RECOVERY_READ_PATH,
    body: { walletId: args.walletId },
  });
}

export type WalletRecoverySetRotateResult =
  | { readonly kind: 'rotated'; readonly issuedAtMs: number; readonly storeVersion: string }
  | { readonly kind: 'conflict'; readonly message: string }
  | { readonly kind: 'rejected'; readonly message: string }
  | { readonly kind: 'no_recovery_set'; readonly message: string }
  | { readonly kind: 'transport_failed'; readonly message: string };

export async function rotateWalletRecoverySet(args: {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly sessionToken: string;
  readonly expectedStoreVersion: string;
  readonly manifestKekWraps: WalletRecoveryEnvelopeSetRecord['manifestKekWraps'];
  readonly fetchImpl?: typeof fetch;
}): Promise<WalletRecoverySetRotateResult> {
  const response = await postWalletRecoveryRoute({
    relayUrl: args.relayUrl,
    sessionToken: args.sessionToken,
    path: WALLET_RECOVERY_ROTATE_PATH,
    body: {
      walletId: args.walletId,
      expectedStoreVersion: args.expectedStoreVersion,
      manifestKekWraps: args.manifestKekWraps,
    },
    fetchImpl: args.fetchImpl,
  });
  const body = asRecord(await response.json().catch(() => ({})));
  const message = typeof body.message === 'string' ? body.message : '';
  if (response.status === 200 && body.ok === true) {
    const issuedAtMs = Number(body.issuedAtMs);
    const storeVersion = String(body.storeVersion || '').trim();
    if (!Number.isSafeInteger(issuedAtMs) || issuedAtMs <= 0 || !storeVersion) {
      return { kind: 'transport_failed', message: 'rotation returned an unusable response' };
    }
    return { kind: 'rotated', issuedAtMs, storeVersion };
  }
  if (response.status === 404) return { kind: 'no_recovery_set', message: message || 'no recovery set' };
  if (response.status === 409) return { kind: 'conflict', message: message || 'recovery set changed' };
  if (response.status === 400) return { kind: 'rejected', message: message || 'rotation rejected' };
  return { kind: 'transport_failed', message: message || `rotation failed (HTTP ${response.status})` };
}

async function requestWalletRecoverySet(args: {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly sessionToken: string;
  readonly path: string;
  readonly body: Record<string, unknown>;
  readonly fetchImpl?: typeof fetch;
}): Promise<WalletRecoverySetReadResult> {
  const response = await postWalletRecoveryRoute(args);
  const body = asRecord(await response.json().catch(() => ({})));
  const message = typeof body.message === 'string' ? body.message : '';
  if (response.status === 404) {
    return { kind: 'no_recovery_set', message: message || 'this wallet has no recovery set' };
  }
  if (response.status !== 200 || body.ok !== true) {
    return {
      kind: 'transport_failed',
      message: message || `recovery set read failed (HTTP ${response.status})`,
    };
  }
  try {
    const recoverySet = parseWalletRecoveryEnvelopeSetRecord(body.recoverySet, {
      expectedWalletId: args.walletId,
      label: 'walletRecoveryRead.recoverySet',
    });
    const storeVersion = String(body.storeVersion || '').trim();
    if (!storeVersion) throw new Error('missing recovery set store version');
    return { kind: 'ready', recoverySet, storeVersion };
  } catch {
    return { kind: 'transport_failed', message: 'recovery set read returned an unusable payload' };
  }
}

async function postWalletRecoveryRoute(args: {
  readonly relayUrl: string;
  readonly sessionToken: string;
  readonly path: string;
  readonly body: Record<string, unknown>;
  readonly fetchImpl?: typeof fetch;
}): Promise<Response> {
  const url = `${normalizeRelayerBaseUrl(args.relayUrl)}${args.path}`;
  const doFetch = args.fetchImpl || fetch;
  return await doFetch(
    url,
    buildRelayerJsonPostRequestInit({
      headers: buildBearerAuthorizationHeader({
        token: args.sessionToken,
        missingMessage: 'wallet recovery rotation requires an app session',
      }),
      body: args.body,
    }),
  );
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}
