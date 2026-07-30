/** Passkey confirmation worker. */
import { awaitUserConfirmationV2 } from '../../uiConfirm/awaitUserConfirmation';
import { parseNearOperationStepUpPreparationRef } from '../../interfaces/operationStepUpPreparation';
import {
  UserConfirmMessageType,
  type UserConfirmDecision,
  type UserConfirmRequest,
} from '../../stepUpConfirmation/channel/confirmTypes';

type UserConfirmWorkerGlobal = typeof globalThis & {
  awaitUserConfirmationV2?: typeof awaitUserConfirmationV2;
};

type UserConfirmWorkerIncomingMessage = {
  id?: unknown;
  type?: unknown;
  payload?: unknown;
};

(globalThis as UserConfirmWorkerGlobal).awaitUserConfirmationV2 = awaitUserConfirmationV2;

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function asIncomingMessage(value: unknown): UserConfirmWorkerIncomingMessage {
  const record = asRecord(value);
  return record
    ? {
        id: record.id,
        type: record.type,
        payload: record.payload,
      }
    : {};
}

function postUserConfirmWorkerResponse(
  id: unknown,
  payload: { success: boolean; data?: unknown; error?: string },
): void {
  self.postMessage({
    ...(typeof id === 'string' && id.trim() ? { id: id.trim() } : {}),
    success: payload.success,
    ...(payload.data !== undefined ? { data: payload.data } : {}),
    ...(payload.error ? { error: payload.error } : {}),
  });
}

function toDecisionFromWorkerResponse(
  response: Awaited<ReturnType<typeof awaitUserConfirmationV2>>,
): UserConfirmDecision {
  const requestId = String(response.request_id || '').trim();
  if (!response.confirmed) {
    return response.wallet_session_failure
      ? {
          requestId,
          intentDigest: response.intent_digest,
          confirmed: false,
          registrationDiagnostics: response.registration_diagnostics,
          walletSessionFailure: response.wallet_session_failure,
        }
      : {
          requestId,
          intentDigest: response.intent_digest,
          confirmed: false,
          registrationDiagnostics: response.registration_diagnostics,
          error: response.error,
        };
  }
  const decisionBase = {
    requestId,
    intentDigest: response.intent_digest,
    confirmed: true,
    credential: response.credential,
    operationStepUpPreparation: response.operation_step_up_preparation
      ? parseNearOperationStepUpPreparationRef(response.operation_step_up_preparation)
      : undefined,
    otpCode: response.otp_code,
    emailOtpChallengeId: response.email_otp_challenge_id,
    registrationDiagnostics: response.registration_diagnostics,
  } as const;
  if (response.near_transaction_readiness) {
    return {
      ...decisionBase,
      nearTransactionReadiness: response.near_transaction_readiness,
    };
  }
  if (response.transaction_context) {
    return {
      ...decisionBase,
      transactionContext: response.transaction_context,
      nonceLeases: response.nonce_leases,
    };
  }
  return decisionBase;
}

function forwardUserConfirmProgressToHost(value: unknown): void {
  const envelope = asRecord(value);
  if (envelope) self.postMessage(envelope);
}

self.onmessage = (event: MessageEvent) => {
  const incoming = asIncomingMessage(event.data);
  const eventType = incoming.type;
  if (eventType === UserConfirmMessageType.USER_PASSKEY_CONFIRM_RESPONSE) return;
  if (eventType === UserConfirmMessageType.USER_PASSKEY_CONFIRM_PROGRESS) {
    forwardUserConfirmProgressToHost(event.data);
    return;
  }

  const id = incoming.id;
  if (eventType === 'PING') {
    postUserConfirmWorkerResponse(id, { success: true, data: { ok: true } });
    return;
  }

  if (eventType === 'SECURE_CONFIRM_REQUEST') {
    void (async () => {
      try {
        const payload = asRecord(incoming.payload);
        const requestInput = payload?.request;
        if (!requestInput || typeof requestInput !== 'object') {
          postUserConfirmWorkerResponse(id, {
            success: false,
            error: 'Invalid SECURE_CONFIRM_REQUEST payload: missing request object',
          });
          return;
        }
        const workerResponse = await awaitUserConfirmationV2(requestInput as UserConfirmRequest);
        postUserConfirmWorkerResponse(id, {
          success: true,
          data: toDecisionFromWorkerResponse(workerResponse),
        });
      } catch (error: unknown) {
        postUserConfirmWorkerResponse(id, {
          success: false,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    })();
    return;
  }

  if (typeof id === 'string' && id.trim()) {
    postUserConfirmWorkerResponse(id, {
      success: false,
      error: `Unsupported UserConfirm worker message type: ${String(eventType)}`,
    });
  }
};

self.onerror = (error) => {
  console.error('[passkey-confirm-worker] error:', error);
};

self.onunhandledrejection = (event) => {
  console.error('[passkey-confirm-worker] Unhandled promise rejection:', event.reason);
  event.preventDefault();
};
