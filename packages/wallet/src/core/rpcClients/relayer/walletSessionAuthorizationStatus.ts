import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
  type MpcWalletSigningQuotaId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  parseActiveWalletSessionV1,
  parseWalletSessionOperationCredentialV1,
} from '@shared/device-linking/parsers';
import type {
  ActiveWalletSessionV1,
  WalletSessionOperationCredentialV1,
} from '@shared/device-linking/contracts';
import {
  buildBearerAuthorizationHeader,
  buildRelayerJsonPostRequestInit,
  normalizeRelayerBaseUrl,
} from './relayerHttp';

export const EXACT_WALLET_SESSION_STATUS_PATH = '/wallet/session/status' as const;

type ExactWalletSessionStatusIdentity = {
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
};

/** The quota facts every observed status carries, whatever its lifecycle. */
type ObservedWalletSessionQuotaFacts = {
  readonly remainingUses: number;
  readonly expiresAtMs: number;
  readonly quotaLifecycle: 'active' | 'exhausted';
};

/**
 * The facts an observed status carries: the server's complete digest-free
 * authorization projection alongside its quota, so a reader reconciles its own
 * record from the same read that reports the lifecycle.
 */
type ObservedWalletSessionStatusFacts = ObservedWalletSessionQuotaFacts & {
  readonly authorization: ActiveWalletSessionV1;
};

/**
 * The quota facts a caller can assemble locally from an already-resolved
 * authorization, without a status read. This is deliberately narrower than a
 * status response: it makes no claim about the server's current projection.
 */
export type ActiveWalletSessionQuotaStatusV1 = ExactWalletSessionStatusIdentity & {
  readonly status: 'active';
  readonly remainingUses: number;
  readonly expiresAtMs: number;
};

/**
 * Every branch that observed a stored authorization carries it in full. The two
 * terminal branches name no authorization the caller can reconcile against and
 * cannot carry one.
 */
export type ExactWalletSessionStatus =
  | (ActiveWalletSessionQuotaStatusV1 & ObservedWalletSessionStatusFacts)
  | (ExactWalletSessionStatusIdentity &
      ObservedWalletSessionStatusFacts & {
        readonly status: 'exhausted';
        readonly remainingUses: 0;
      })
  | (ExactWalletSessionStatusIdentity &
      ObservedWalletSessionStatusFacts & {
        readonly status:
          | 'expired'
          | 'superseded'
          | 'authority_unavailable'
          | 'method_unavailable'
          | 'capability_unavailable';
      })
  | (ExactWalletSessionStatusIdentity & {
      readonly status: 'missing' | 'invalid';
      readonly remainingUses?: never;
      readonly expiresAtMs?: never;
      readonly quotaLifecycle?: never;
      readonly authorization?: never;
    });

export interface ExactWalletSessionStatusPort {
  read(input: ExactWalletSessionStatusIdentity): Promise<ExactWalletSessionStatus>;
}

export type RelayerExactWalletSessionStatusPortOptions = {
  readonly relayerUrl: string;
  readonly operationCredential: WalletSessionOperationCredentialV1;
  readonly fetchImpl?: typeof fetch;
};

const defaultStatusFetch: typeof fetch = (input, init) => globalThis.fetch(input, init);
const statusReadsByFetch = new WeakMap<
  typeof fetch,
  Map<string, Promise<ExactWalletSessionStatus>>
>();

const OBSERVED_FIELDS = [
  'ok',
  'status',
  'walletSessionId',
  'quotaId',
  'remainingUses',
  'expiresAtMs',
  'quotaLifecycle',
  'authorization',
] as const;
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
  expected: ExactWalletSessionStatusIdentity,
): ExactWalletSessionStatusIdentity | null {
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

function isNonnegativeSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

/**
 * Reads the facts every observed branch carries. The authorization must be a
 * complete `ActiveWalletSessionV1` naming the quota the caller asked about, and
 * the quota lifecycle must agree with its own remaining-use count.
 */
function parseObservedStatusFacts(
  value: Record<string, unknown>,
  identity: ExactWalletSessionStatusIdentity,
): ObservedWalletSessionStatusFacts | null {
  if (!hasExactFields(value, OBSERVED_FIELDS)) return null;
  if (value.quotaLifecycle !== 'active' && value.quotaLifecycle !== 'exhausted') return null;
  if (!isNonnegativeSafeInteger(value.remainingUses)) return null;
  if ((value.quotaLifecycle === 'exhausted') !== (value.remainingUses === 0)) return null;
  if (!isPositiveSafeInteger(value.expiresAtMs)) return null;
  let authorization: ActiveWalletSessionV1;
  try {
    authorization = parseActiveWalletSessionV1(value.authorization);
  } catch {
    return null;
  }
  if (
    authorization.quotaId !== identity.quotaId ||
    authorization.expiresAtMs !== value.expiresAtMs
  ) {
    return null;
  }
  return {
    remainingUses: value.remainingUses,
    expiresAtMs: value.expiresAtMs,
    quotaLifecycle: value.quotaLifecycle,
    authorization,
  };
}

export function parseExactWalletSessionStatusResponse(
  value: unknown,
  expected: ExactWalletSessionStatusIdentity,
): ExactWalletSessionStatus | null {
  if (!isRecord(value) || value.ok !== true) return null;
  const identity = parseIdentity(value, expected);
  if (!identity) return null;
  switch (value.status) {
    case 'active': {
      const facts = parseObservedStatusFacts(value, identity);
      if (!facts || facts.quotaLifecycle !== 'active') return null;
      return { status: 'active', ...identity, ...facts };
    }
    case 'exhausted': {
      const facts = parseObservedStatusFacts(value, identity);
      if (!facts || facts.remainingUses !== 0) return null;
      return { status: 'exhausted', ...identity, ...facts, remainingUses: 0 };
    }
    case 'expired':
    case 'superseded':
    case 'authority_unavailable':
    case 'method_unavailable':
    case 'capability_unavailable': {
      const facts = parseObservedStatusFacts(value, identity);
      return facts ? { status: value.status, ...identity, ...facts } : null;
    }
    case 'missing':
    case 'invalid':
      return hasExactFields(value, TERMINAL_FIELDS) ? { status: value.status, ...identity } : null;
    default:
      return null;
  }
}

export class RelayerExactWalletSessionStatusPort implements ExactWalletSessionStatusPort {
  private readonly relayerUrl: string;
  private readonly operationCredential: WalletSessionOperationCredentialV1;
  private readonly fetchImpl: typeof fetch;

  constructor(options: RelayerExactWalletSessionStatusPortOptions) {
    this.relayerUrl = normalizeRelayerBaseUrl(options.relayerUrl);
    if (!this.relayerUrl) throw new Error('Relayer URL is required');
    this.operationCredential = parseWalletSessionOperationCredentialV1(options.operationCredential);
    this.fetchImpl = options.fetchImpl ?? defaultStatusFetch;
  }

  async read(input: ExactWalletSessionStatusIdentity): Promise<ExactWalletSessionStatus> {
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
    input: ExactWalletSessionStatusIdentity,
  ): Promise<ExactWalletSessionStatus> {
    const response = await this.fetchImpl(`${this.relayerUrl}${EXACT_WALLET_SESSION_STATUS_PATH}`, {
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
    });
    const payload = (await response.json().catch(() => null)) as unknown;
    if (!response.ok) {
      const message =
        isRecord(payload) && typeof payload.message === 'string'
          ? payload.message
          : `Wallet Session status request failed with HTTP ${response.status}`;
      throw new Error(message);
    }
    const parsed = parseExactWalletSessionStatusResponse(payload, input);
    if (!parsed) throw new Error('Wallet Session status response is invalid');
    return parsed;
  }
}

export function createRelayerExactWalletSessionStatusPort(
  options: RelayerExactWalletSessionStatusPortOptions,
): ExactWalletSessionStatusPort {
  return new RelayerExactWalletSessionStatusPort(options);
}
