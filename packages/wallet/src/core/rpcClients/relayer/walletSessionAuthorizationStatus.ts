import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
  type MpcWalletSigningQuotaId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseWalletSessionOperationCredentialV1 } from '@shared/device-linking/parsers';
import type { WalletSessionOperationCredentialV1 } from '@shared/device-linking/contracts';
import {
  buildBearerAuthorizationHeader,
  buildRelayerJsonPostRequestInit,
  normalizeRelayerBaseUrl,
} from './relayerHttp';

export const REUSABLE_WALLET_SESSION_STATUS_PATH = '/wallet/session/status' as const;

type ReusableWalletSessionStatusIdentity = {
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
};

export type ReusableWalletSessionStatus =
  | (ReusableWalletSessionStatusIdentity & {
      readonly status: 'active';
      readonly remainingUses: number;
      readonly expiresAtMs: number;
    })
  | (ReusableWalletSessionStatusIdentity & {
      readonly status: 'exhausted';
      readonly remainingUses: 0;
      readonly expiresAtMs: number;
    })
  | (ReusableWalletSessionStatusIdentity & {
      readonly status: 'expired';
      readonly expiresAtMs: number;
      readonly remainingUses?: never;
    })
  | (ReusableWalletSessionStatusIdentity & {
      readonly status: 'superseded' | 'missing' | 'invalid';
      readonly remainingUses?: never;
      readonly expiresAtMs?: never;
    });

export interface ReusableWalletSessionStatusPort {
  read(input: ReusableWalletSessionStatusIdentity): Promise<ReusableWalletSessionStatus>;
}

export type RelayerReusableWalletSessionStatusPortOptions = {
  readonly relayerUrl: string;
  readonly operationCredential: WalletSessionOperationCredentialV1;
  readonly fetchImpl?: typeof fetch;
};

const defaultStatusFetch: typeof fetch = (input, init) => globalThis.fetch(input, init);
const statusReadsByFetch = new WeakMap<
  typeof fetch,
  Map<string, Promise<ReusableWalletSessionStatus>>
>();

const ACTIVE_FIELDS = [
  'ok',
  'status',
  'walletSessionId',
  'quotaId',
  'remainingUses',
  'expiresAtMs',
] as const;
const EXPIRED_FIELDS = ['ok', 'status', 'walletSessionId', 'quotaId', 'expiresAtMs'] as const;
const TERMINAL_FIELDS = ['ok', 'status', 'walletSessionId', 'quotaId'] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactFields(record: Record<string, unknown>, fields: readonly string[]): boolean {
  const actual = Object.keys(record);
  return actual.length === fields.length && actual.every((field) => fields.includes(field));
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function parseIdentity(
  record: Record<string, unknown>,
  expected: ReusableWalletSessionStatusIdentity,
): ReusableWalletSessionStatusIdentity | null {
  const walletSessionId = parseWalletSessionId(record.walletSessionId);
  const quotaId = parseMpcWalletSigningQuotaId(record.quotaId);
  if (
    !walletSessionId.ok ||
    !quotaId.ok ||
    walletSessionId.value !== expected.walletSessionId ||
    quotaId.value !== expected.quotaId
  ) {
    return null;
  }
  return {
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
  };
}

export function parseReusableWalletSessionStatusResponse(
  value: unknown,
  expected: ReusableWalletSessionStatusIdentity,
): ReusableWalletSessionStatus | null {
  if (!isRecord(value) || value.ok !== true) return null;
  const identity = parseIdentity(value, expected);
  if (!identity) return null;
  switch (value.status) {
    case 'active':
      if (
        !hasExactFields(value, ACTIVE_FIELDS) ||
        !isPositiveSafeInteger(value.remainingUses) ||
        !isPositiveSafeInteger(value.expiresAtMs)
      ) {
        return null;
      }
      return {
        status: 'active',
        ...identity,
        remainingUses: value.remainingUses,
        expiresAtMs: value.expiresAtMs,
      };
    case 'exhausted':
      if (
        !hasExactFields(value, ACTIVE_FIELDS) ||
        value.remainingUses !== 0 ||
        !isPositiveSafeInteger(value.expiresAtMs)
      ) {
        return null;
      }
      return {
        status: 'exhausted',
        ...identity,
        remainingUses: 0,
        expiresAtMs: value.expiresAtMs,
      };
    case 'expired':
      if (!hasExactFields(value, EXPIRED_FIELDS) || !isPositiveSafeInteger(value.expiresAtMs)) {
        return null;
      }
      return {
        status: 'expired',
        ...identity,
        expiresAtMs: value.expiresAtMs,
      };
    case 'superseded':
    case 'missing':
    case 'invalid':
      return hasExactFields(value, TERMINAL_FIELDS) ? { status: value.status, ...identity } : null;
    default:
      return null;
  }
}

export class RelayerReusableWalletSessionStatusPort implements ReusableWalletSessionStatusPort {
  private readonly relayerUrl: string;
  private readonly operationCredential: WalletSessionOperationCredentialV1;
  private readonly fetchImpl: typeof fetch;

  constructor(options: RelayerReusableWalletSessionStatusPortOptions) {
    this.relayerUrl = normalizeRelayerBaseUrl(options.relayerUrl);
    if (!this.relayerUrl) throw new Error('Relayer URL is required');
    this.operationCredential = parseWalletSessionOperationCredentialV1(options.operationCredential);
    this.fetchImpl = options.fetchImpl ?? defaultStatusFetch;
  }

  async read(input: ReusableWalletSessionStatusIdentity): Promise<ReusableWalletSessionStatus> {
    let reads = statusReadsByFetch.get(this.fetchImpl);
    if (!reads) {
      reads = new Map();
      statusReadsByFetch.set(this.fetchImpl, reads);
    }
    const readKey = [
      this.relayerUrl,
      this.operationCredential.token,
      input.walletSessionId,
      input.quotaId,
    ].join('\u0000');
    const existing = reads.get(readKey);
    if (existing) return await existing;

    const pending = this.readRemote(input);
    reads.set(readKey, pending);
    try {
      return await pending;
    } finally {
      if (reads.get(readKey) === pending) reads.delete(readKey);
    }
  }

  private async readRemote(
    input: ReusableWalletSessionStatusIdentity,
  ): Promise<ReusableWalletSessionStatus> {
    const response = await this.fetchImpl(
      `${this.relayerUrl}${REUSABLE_WALLET_SESSION_STATUS_PATH}`,
      {
        ...buildRelayerJsonPostRequestInit({
          body: {
            walletSessionId: input.walletSessionId,
            quotaId: input.quotaId,
          },
          headers: buildBearerAuthorizationHeader({
            token: this.operationCredential.token,
            missingMessage: 'Wallet Session token is required for Wallet Session status',
          }),
        }),
        credentials: 'omit',
      },
    );
    const payload = (await response.json().catch(() => null)) as unknown;
    if (!response.ok) {
      const message =
        isRecord(payload) && typeof payload.message === 'string'
          ? payload.message
          : `Wallet Session status request failed with HTTP ${response.status}`;
      throw new Error(message);
    }
    const parsed = parseReusableWalletSessionStatusResponse(payload, input);
    if (!parsed) throw new Error('Wallet Session status response is invalid');
    return parsed;
  }
}

export function createRelayerReusableWalletSessionStatusPort(
  options: RelayerReusableWalletSessionStatusPortOptions,
): ReusableWalletSessionStatusPort {
  return new RelayerReusableWalletSessionStatusPort(options);
}
