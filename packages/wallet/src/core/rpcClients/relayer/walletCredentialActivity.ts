import {
  parsePasskeyCustodyEnvelopeLifecycle,
  parseWalletCustodyEnvelopeFactor,
  type PasskeyDeviceEnvelopeIndexRecord,
} from '@shared/passkey-custody';
import {
  parseWalletCredentialActivityRecordV1,
  type WalletCredentialActivityRecordV1,
} from '@shared/passkey-custody/credentialActivity';
import {
  parsePasskeyEnvelopeId,
  parseWalletId,
} from '@shared/utils/domainIds';
import { parseUnixMs, requireRecord } from '@shared/passkey-custody/primitives';
import { normalizeRelayerBaseUrl } from './relayerHttp';
import type { WalletCustodyFactorProof } from './walletRecoveryRotate';

const CREDENTIALS_LIST_PATH = '/wallets/:walletId/custody/credentials';
const CREDENTIAL_LABEL_PATH = '/wallets/:walletId/custody/credentials/label';

export type WalletCredentialActivityProjection = {
  readonly index: PasskeyDeviceEnvelopeIndexRecord;
  readonly activity: WalletCredentialActivityRecordV1;
};

export type WalletCredentialActivityListResult =
  | { readonly kind: 'listed'; readonly credentials: readonly WalletCredentialActivityProjection[] }
  | { readonly kind: 'unauthorized'; readonly message: string }
  | { readonly kind: 'transport_failed'; readonly message: string };

export type WalletCredentialRenameResult =
  | { readonly kind: 'renamed'; readonly credential: WalletCredentialActivityProjection }
  | { readonly kind: 'missing'; readonly message: string }
  | { readonly kind: 'conflict'; readonly message: string }
  | { readonly kind: 'rejected'; readonly message: string }
  | { readonly kind: 'transport_failed'; readonly message: string };

export async function listWalletCredentialActivity(args: {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly factorProof: WalletCustodyFactorProof;
  readonly fetchImpl?: typeof fetch;
}): Promise<WalletCredentialActivityListResult> {
  const url = `${normalizeRelayerBaseUrl(args.relayUrl)}${CREDENTIALS_LIST_PATH.replace(
    ':walletId',
    encodeURIComponent(args.walletId),
  )}`;
  const headers: Record<string, string> = { Accept: 'application/json', 'Content-Type': 'application/json' };
  const doFetch = args.fetchImpl || fetch;
  let response: Response;
  try {
    response = await doFetch(url, {
      method: 'POST',
      credentials: 'include',
      headers,
      body: JSON.stringify({ factorProof: args.factorProof }),
    });
  } catch (error: unknown) {
    return {
      kind: 'transport_failed',
      message: error instanceof Error ? error.message : 'credential list request failed',
    };
  }
  const body = await response.json().catch(() => ({}));
  if (response.status === 401 || response.status === 403) {
    return { kind: 'unauthorized', message: responseMessage(body, 'credential list is unauthorized') };
  }
  if (!response.ok) {
    return { kind: 'transport_failed', message: responseMessage(body, `credential list failed (HTTP ${response.status})`) };
  }
  try {
    const record = requireRecord(body, 'credential list response');
    if (record.ok !== true || !Array.isArray(record.credentials)) {
      throw new Error('credential list response is invalid');
    }
    return { kind: 'listed', credentials: record.credentials.map(parseProjection) };
  } catch (error: unknown) {
    return {
      kind: 'transport_failed',
      message: error instanceof Error ? error.message : 'credential list response is invalid',
    };
  }
}

export async function renameWalletCredential(args: {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly envelopeId: string;
  readonly label?: string;
  readonly factorProof: WalletCustodyFactorProof;
  readonly fetchImpl?: typeof fetch;
}): Promise<WalletCredentialRenameResult> {
  const url = `${normalizeRelayerBaseUrl(args.relayUrl)}${CREDENTIAL_LABEL_PATH.replace(
    ':walletId',
    encodeURIComponent(args.walletId),
  )}`;
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const doFetch = args.fetchImpl || fetch;
  let response: Response;
  try {
    response = await doFetch(url, {
      method: 'POST',
      credentials: 'include',
      headers,
      body: JSON.stringify({
        envelopeId: args.envelopeId,
        factorProof: args.factorProof,
        ...(args.label === undefined ? {} : { label: args.label }),
      }),
    });
  } catch (error: unknown) {
    return {
      kind: 'transport_failed',
      message: error instanceof Error ? error.message : 'credential rename request failed',
    };
  }
  const body = await response.json().catch(() => ({}));
  const message = responseMessage(body, `credential rename failed (HTTP ${response.status})`);
  if (response.status === 401 || response.status === 403) {
    return { kind: 'rejected', message };
  }
  if (response.status === 404) return { kind: 'missing', message };
  if (response.status === 409) return { kind: 'conflict', message };
  if (response.status !== 200) return { kind: 'rejected', message };
  try {
    const record = requireRecord(body, 'credential rename response');
    if (record.ok !== true) throw new Error('credential rename response is invalid');
    return { kind: 'renamed', credential: parseProjection(record.credential) };
  } catch (error: unknown) {
    return {
      kind: 'transport_failed',
      message: error instanceof Error ? error.message : 'credential rename response is invalid',
    };
  }
}

function parseProjection(raw: unknown): WalletCredentialActivityProjection {
  const record = requireRecord(raw, 'credential projection');
  const index = requireRecord(record.index, 'credential projection index');
  const walletId = parseWalletId(index.walletId);
  if (!walletId.ok) throw new Error('credential projection wallet id is invalid');
  const envelopeId = parsePasskeyEnvelopeId(index.envelopeId);
  if (!envelopeId.ok) throw new Error('credential projection envelope id is invalid');
  if (
    index.kind !== 'wallet_custody_envelope_index_v2' ||
    (index.custodySecretKind !== 'wallet_custody_seed_v1' &&
      index.custodySecretKind !== 'ed25519_lane_holder_share_v1' &&
      index.custodySecretKind !== 'ecdsa_lane_holder_share_v1')
  ) {
    throw new Error('credential projection index is invalid');
  }
  const factor = parseWalletCustodyEnvelopeFactor(index.factor);
  if (factor.kind !== 'passkey') throw new Error('credential projection factor is invalid');
  const lifecycle = parsePasskeyCustodyEnvelopeLifecycle(index.lifecycle);
  const createdAtMs = parseUnixMs(index.createdAtMs, 'credential projection.createdAtMs');
  const updatedAtMs = parseUnixMs(index.updatedAtMs, 'credential projection.updatedAtMs');
  const label = index.deviceLabel;
  if (label !== undefined && typeof label !== 'string') {
    throw new Error('credential projection deviceLabel is invalid');
  }
  const activityResult = parseWalletCredentialActivityRecordV1(record.activity, {
    expectedWalletId: String(walletId.value),
  });
  if (!activityResult.ok) throw new Error(activityResult.reason);
  return {
    index: {
      kind: 'wallet_custody_envelope_index_v2',
      walletId: walletId.value,
      custodySecretKind: index.custodySecretKind,
      factor,
      envelopeId: envelopeId.value,
      ...(label === undefined ? {} : { deviceLabel: label }),
      lifecycle,
      createdAtMs,
      updatedAtMs,
    },
    activity: activityResult.record,
  };
}

function responseMessage(value: unknown, fallback: string): string {
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    const message = (value as Record<string, unknown>).message;
    if (typeof message === 'string' && message.trim()) return message;
  }
  return fallback;
}
