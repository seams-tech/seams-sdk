import type {
  TransactionSummary,
  UserConfirmDecision,
  UserConfirmResponseEnvelope,
  UserConfirmProgressEnvelope,
} from './confirmTypes';
import type { UserConfirmProgressEvent } from '../types';
import { UserConfirmMessageType } from './confirmTypes';
import { isObject, isFunction, isString } from '@shared/utils/validation';
import {
  toError,
  isTouchIdCancellationError,
  isWebAuthnRpIdOriginConfigurationError,
} from '@shared/utils/errors';
import { normalizeOptionalNonEmptyString } from '@shared/utils/normalize';

export function parseTransactionSummary(summaryData: unknown): TransactionSummary {
  if (typeof summaryData === 'string') {
    const raw = summaryData.trim();
    if (!raw) return {};
    try {
      const parsed = JSON.parse(raw);
      if (isObject(parsed) && !Array.isArray(parsed)) {
        return parsed as TransactionSummary;
      }
      return {};
    } catch {
      return {};
    }
  }
  if (!isObject(summaryData) || Array.isArray(summaryData)) {
    throw new Error('Invalid secure confirm request summary: expected an object');
  }
  return summaryData as TransactionSummary;
}

// ===== Utility: postMessage sanitization (exported in case flows need to respond directly) =====
export type NonFunctionKeys<T> = {
  [K in keyof T]: T[K] extends (...args: never[]) => unknown ? never : K;
}[keyof T];

export type ShallowPostMessageSafe<T> = T extends object
  ? Omit<Pick<T, NonFunctionKeys<T>>, '_confirmHandle'>
  : T;

export function sanitizeForPostMessage<T>(data: T): ShallowPostMessageSafe<T> {
  if (data == null) return data as ShallowPostMessageSafe<T>;
  if (Array.isArray(data)) return data.map((v) => v) as unknown as ShallowPostMessageSafe<T>;
  if (isObject(data)) {
    const src = data as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(src)) {
      if (key === '_confirmHandle') continue;
      const value = src[key];
      if (isFunction(value)) continue;
      out[key] = value;
    }
    return out as ShallowPostMessageSafe<T>;
  }
  return data as ShallowPostMessageSafe<T>;
}

// ===== Shared worker response + UI close helpers =====
export const ERROR_MESSAGES = {
  cancelled: 'User cancelled secure confirm request',
  collectCredentialsFailed: 'Failed to collect credentials',
  nearRpcFailed: 'Failed to fetch NEAR data',
} as const;

const WORKER_CHANNEL_TOKEN_FIELD = '__w3aSecureConfirmChannelToken';

export type UserConfirmResponsePort = Pick<Worker, 'postMessage'>;

type UserConfirmWorkerChannelProxy = UserConfirmResponsePort & {
  [WORKER_CHANNEL_TOKEN_FIELD]?: string;
};

function getWorkerChannelToken(worker: UserConfirmResponsePort): string | undefined {
  return normalizeOptionalNonEmptyString(
    (worker as UserConfirmWorkerChannelProxy)[WORKER_CHANNEL_TOKEN_FIELD],
  );
}

export function createUserConfirmScopedWorker(
  worker: Worker,
  options?: { channelToken?: string },
): Worker {
  const channelToken = normalizeOptionalNonEmptyString(options?.channelToken);
  if (!channelToken) {
    return worker;
  }
  return {
    postMessage: (message: unknown, transfer?: Transferable[]) => {
      if (transfer && transfer.length > 0) {
        worker.postMessage(message, transfer);
        return;
      }
      worker.postMessage(message);
    },
    [WORKER_CHANNEL_TOKEN_FIELD]: channelToken,
  } as unknown as Worker;
}

export function sendConfirmResponse(
  worker: UserConfirmResponsePort,
  response: UserConfirmDecision,
  options?: { channelToken?: string },
) {
  const sanitized = sanitizeForPostMessage(response);
  const requestId = isString(sanitized?.requestId) ? sanitized.requestId : response.requestId;
  const channelToken =
    normalizeOptionalNonEmptyString(options?.channelToken) ?? getWorkerChannelToken(worker);
  const envelope: UserConfirmResponseEnvelope = {
    type: UserConfirmMessageType.USER_PASSKEY_CONFIRM_RESPONSE,
    requestId,
    data: sanitized as UserConfirmDecision,
    ...(channelToken ? { channelToken } : {}),
  };
  worker.postMessage(envelope);
}

export function sendConfirmProgress(
  worker: Worker,
  progress: UserConfirmProgressEvent,
  options?: { channelToken?: string },
): void {
  const sanitized = sanitizeForPostMessage(progress);
  const requestId = isString(sanitized?.requestId) ? sanitized.requestId : progress.requestId;
  const channelToken =
    normalizeOptionalNonEmptyString(options?.channelToken) ?? getWorkerChannelToken(worker);
  const envelope: UserConfirmProgressEnvelope = {
    type: UserConfirmMessageType.USER_PASSKEY_CONFIRM_PROGRESS,
    requestId,
    data: sanitized as UserConfirmProgressEvent,
    ...(channelToken ? { channelToken } : {}),
  };
  worker.postMessage(envelope);
}

export function isUserCancelledUserConfirm(error: unknown): boolean {
  if (isWebAuthnRpIdOriginConfigurationError(error)) return false;
  return (
    isTouchIdCancellationError(error) ||
    (() => {
      const e = toError(error);
      return e?.name === 'NotAllowedError' || e?.name === 'AbortError';
    })()
  );
}
