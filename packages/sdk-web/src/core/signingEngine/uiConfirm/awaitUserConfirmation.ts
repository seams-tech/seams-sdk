/**
 * Worker-side handshake entrypoint.
 *
 * Called by the UserConfirm worker runtime (`passkey-confirm.worker.ts`) and waits for
 * `USER_PASSKEY_CONFIRM_RESPONSE` messages emitted by the main-thread uiConfirm runtime.
 */
import {
  WorkerConfirmationResponse,
  UserConfirmMessageType,
  UserConfirmPromptEnvelope,
  UserConfirmRequest,
  UserConfirmResponseEnvelope,
  RegistrationConfirmationDiagnostics,
  SerializableCredential,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import type { NonceLeaseRef } from '@/core/signingEngine/interfaces/nonceLease';
import { isObject, isString, isBoolean } from '@shared/utils/validation';
import { errorMessage, toError } from '@shared/utils/errors';
import { normalizeOptionalNonEmptyString } from '@shared/utils/normalize';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { TransactionContext } from '@/core/types/rpc';
import { validateUserConfirmRequest } from './handlers/flows/adapters/request';

type ConfirmResponsePayload = {
  requestId: string;
  confirmed: boolean;
  intentDigest?: string;
  credential?: SerializableCredential;
  otpCode?: string;
  emailOtpChallengeId?: string;
  transactionContext?: TransactionContext;
  nonceLeases?: NonceLeaseRef[];
  registrationDiagnostics?: RegistrationConfirmationDiagnostics;
  error?: string;
};

type ConfirmResponseEnvelope = {
  type: UserConfirmMessageType.USER_PASSKEY_CONFIRM_RESPONSE;
  requestId?: string;
  channelToken?: string;
  data: ConfirmResponsePayload;
};

/**
 * Worker-side bridge used by the UserConfirm worker runtime to request a main-thread confirmation.
 *
 * Where this runs:
 * - Runs inside the UserConfirm Web Worker (not the main thread).
 * - Invoked from the worker runtime; the UserConfirm worker exposes this as
 *   `globalThis.awaitUserConfirmationV2` in `client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts`.
 *
 * High-level flow:
 * 1) UserConfirm runtime calls `awaitUserConfirmationV2(request)`
 * 2) This posts `PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD` to the main thread
 * 3) Main-thread uiConfirm runtime intercepts that message and runs uiConfirm handlers
 *    (`handlePromptFromWorker`), then posts back `USER_PASSKEY_CONFIRM_RESPONSE`
 * 4) This resolves to a Rust-friendly `WorkerConfirmationResponse` (snake_case fields)
 *
 * API contract:
 * - V2 objects only (no JSON strings / shorthand shapes).
 * - The `requestId` is used to correlate responses when multiple confirmations are in-flight.
 */
export function awaitUserConfirmationV2(
  requestInput: UserConfirmRequest,
  opts: { timeoutMs?: number; signal?: AbortSignal } = {},
): Promise<WorkerConfirmationResponse> {
  return new Promise((resolve, reject) => {
    // 1) Validate request object coming from the UserConfirm worker runtime.
    // Rust passes a plain JS object (serde_wasm_bindgen), so we validate defensively here
    // to avoid propagating malformed requests to the main thread.
    let request: UserConfirmRequest;
    try {
      request = validateUserConfirmRequest(requestInput);
    } catch (e: unknown) {
      return reject(new Error(`[signer-worker]: invalid V2 request: ${errorMessage(e)}`));
    }
    const channelToken = createChannelToken(request.requestId);

    // 2) Setup cleanup utilities for this single in-flight request.
    let timeoutId: ReturnType<typeof setTimeout> | undefined;
    const cleanup = () => {
      if (timeoutId) clearTimeout(timeoutId);
      self.removeEventListener('message', onDecisionReceived);
      if (opts.signal) opts.signal.removeEventListener('abort', onAbort);
    };

    const onAbort = () => {
      cleanup();
      reject(new Error('[signer-worker]: confirmation aborted'));
    };

    // 3) Wait for the matching decision message from the main thread.
    // Note: `passkey-confirm.worker.ts` intentionally ignores USER_PASSKEY_CONFIRM_RESPONSE
    // at the worker `onmessage` level and lets this handler consume it.
    const onDecisionReceived = (messageEvent: MessageEvent) => {
      const env = messageEvent?.data as unknown;
      if (!isConfirmResponseEnvelope(env)) return;
      if (!isValidUserConfirmOrigin(messageEvent)) return;
      if (resolveEnvelopeRequestId(env) !== request.requestId) return;
      if (!isMatchingChannelToken(env, channelToken)) return;
      cleanup();
      let response: WorkerConfirmationResponse;
      try {
        response = env.data.confirmed
          ? buildConfirmedWorkerConfirmationResponse({
              requestId: request.requestId,
              data: env.data,
            })
          : {
              request_id: request.requestId,
              intent_digest: env.data.intentDigest,
              confirmed: false,
              registration_diagnostics: env.data.registrationDiagnostics,
              error: env.data.error,
            };
      } catch (error: unknown) {
        return reject(toError(error));
      }
      return resolve(response);
    };
    self.addEventListener('message', onDecisionReceived);

    // Optional timeout / abort support
    if (opts.timeoutMs && opts.timeoutMs > 0) {
      timeoutId = setTimeout(() => {
        cleanup();
        reject(new Error('[signer-worker]: confirmation timed out'));
      }, opts.timeoutMs);
    }
    if (opts.signal) {
      if (opts.signal.aborted) {
        cleanup();
        return reject(new Error('[signer-worker]: confirmation aborted'));
      }
      opts.signal.addEventListener('abort', onAbort);
    }

    // 4) Post request to the main thread.
    // postMessage performs the structured clone. The request has already been
    // normalized by validateUserConfirmRequest, so avoid cloning the full
    // transaction-display payload twice.
    try {
      const promptEnvelope: UserConfirmPromptEnvelope = {
        type: UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD,
        requestId: request.requestId,
        channelToken,
        data: request,
      };
      self.postMessage(promptEnvelope);
    } catch (postErr: unknown) {
      cleanup();
      console.error('[signer-worker][V2] postMessage failed', postErr);
      return reject(toError(postErr));
    }
  });
}

function buildConfirmedWorkerConfirmationResponse(args: {
  requestId: string;
  data: ConfirmResponsePayload;
}): WorkerConfirmationResponse {
  const nonceLeases = normalizeNonceLeaseRefs(args.data.nonceLeases);
  const base = {
    request_id: args.requestId,
    confirmed: true as const,
    ...(args.data.intentDigest ? { intent_digest: args.data.intentDigest } : {}),
    ...(args.data.credential ? { credential: args.data.credential } : {}),
    ...(args.data.otpCode ? { otp_code: args.data.otpCode } : {}),
    ...(args.data.emailOtpChallengeId
      ? { email_otp_challenge_id: args.data.emailOtpChallengeId }
      : {}),
    ...(args.data.registrationDiagnostics
      ? { registration_diagnostics: args.data.registrationDiagnostics }
      : {}),
  };
  if (args.data.transactionContext) {
    if (!nonceLeases?.length) {
      throw new Error('Secure confirm transaction response requires nonceLeases');
    }
    return {
      ...base,
      transaction_context: args.data.transactionContext,
      nonce_leases: nonceLeases,
    };
  }
  if (nonceLeases !== undefined) {
    throw new Error('Secure confirm response nonceLeases require transactionContext');
  }
  return base;
}

function normalizeNonceLeaseRefs(value: unknown): NonceLeaseRef[] | undefined {
  if (value == null) return undefined;
  if (!Array.isArray(value)) {
    throw new Error('Invalid secure confirm response nonceLeases: expected array');
  }
  return value.map(normalizeNonceLeaseRef);
}

function normalizeNonceLeaseRef(value: unknown): NonceLeaseRef {
  if (!isObject(value)) {
    throw new Error('Invalid secure confirm response nonceLease: expected object');
  }
  const record = value as Record<string, unknown>;
  const leaseId = normalizeNonceLeaseString(record.leaseId, 'nonceLease.leaseId');
  const operationId = normalizeNonceLeaseString(record.operationId, 'nonceLease.operationId');
  const operationFingerprint = normalizeNonceLeaseString(
    record.operationFingerprint,
    'nonceLease.operationFingerprint',
  );
  const nonce = normalizeNonceLeaseString(record.nonce, 'nonceLease.nonce');
  const batchId =
    record.batchId == null ? undefined : normalizeNonceLeaseString(record.batchId, 'nonceLease.batchId');
  const txIndex = normalizeNonceLeaseTxIndex(record.txIndex);
  return {
    leaseId,
    operationId,
    operationFingerprint,
    nonce,
    ...(batchId ? { batchId } : {}),
    ...(txIndex !== undefined ? { txIndex } : {}),
  };
}

function normalizeNonceLeaseString(value: unknown, field: string): string {
  if (!isString(value)) {
    throw new Error(`Invalid secure confirm response ${field}: expected string`);
  }
  const normalized = value.trim();
  if (!normalized) {
    throw new Error(`Invalid secure confirm response ${field}: expected non-empty string`);
  }
  return normalized;
}

function normalizeNonceLeaseTxIndex(value: unknown): number | undefined {
  if (value == null) return undefined;
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    throw new Error('Invalid secure confirm response nonceLease.txIndex: expected safe integer');
  }
  return value;
}

function isConfirmResponseEnvelope(msg: unknown): msg is ConfirmResponseEnvelope {
  if (!isObject(msg)) return false;
  const type = (msg as { type?: unknown }).type;
  if (type !== UserConfirmMessageType.USER_PASSKEY_CONFIRM_RESPONSE) return false;
  const data = (msg as { data?: unknown }).data;
  if (!isObject(data)) return false;
  const d = data as { requestId?: unknown; confirmed?: unknown };
  return isString(d.requestId) && isBoolean(d.confirmed);
}

function createChannelToken(requestId: string): string {
  const seed = String(requestId || '').trim() || 'sc';
  const randomPart = secureRandomBase64Url(32, 'user confirmation channel tokens');
  return `${seed}:${randomPart}`;
}

function resolveEnvelopeRequestId(
  env: ConfirmResponseEnvelope | UserConfirmResponseEnvelope,
): string {
  const topLevelRequestId = isString((env as { requestId?: unknown }).requestId)
    ? String((env as { requestId?: string }).requestId).trim()
    : '';
  if (topLevelRequestId) {
    return topLevelRequestId;
  }
  return String(env.data.requestId || '').trim();
}

function isMatchingChannelToken(
  env: ConfirmResponseEnvelope | UserConfirmResponseEnvelope,
  expectedChannelToken: string,
): boolean {
  return (
    (normalizeOptionalNonEmptyString((env as { channelToken?: unknown }).channelToken) || '') ===
    expectedChannelToken
  );
}

function isValidUserConfirmOrigin(messageEvent: MessageEvent): boolean {
  const origin = isString((messageEvent as { origin?: unknown }).origin)
    ? String((messageEvent as { origin?: string }).origin).trim()
    : '';
  if (!origin) {
    return true;
  }
  try {
    const selfOrigin = String(self.location?.origin || '').trim();
    return !!selfOrigin && origin === selfOrigin;
  } catch {
    return false;
  }
}
