import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { NormalizedConfirmationConfig } from '@/core/types/confirmationConfig.types';
import { secureRandomId } from '@shared/utils/secureRandomId';
import {
  UserConfirmationType,
  type RegistrationUserConfirmRequest,
  type TransactionSummary,
  UserConfirmMessageType,
  type RegistrationActivationProof,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import {
  parseAndValidateRegistrationCredentialConfirmationPayload,
  type RegistrationCredentialConfirmationPayload,
} from '@/core/signingEngine/workerManager/validation';
import type { UiConfirmContext, UiConfirmSecureConfirmationPort } from '../../uiConfirm.types';
import { determineConfirmationConfig } from '../determineConfirmationConfig';
import { handleRegistrationFlow } from './registration';
import {
  assertNoForbiddenMainThreadSigningSecrets,
  getIntentDigest,
  validateUserConfirmRequest,
} from './adapters/request';
import {
  parseTransactionSummary,
  type UserConfirmResponsePort,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmCommon';
import { coerceThemeName } from '@shared/utils/theme';
import { isBoolean, isObject, isString } from '@shared/utils/validation';
import { errorMessage } from '@shared/utils/errors';

type RegistrationCredentialConfirmationArgs = {
  walletId: string;
  nearAccountId?: string;
  signerSlot: number;
  confirmerText?: { title?: string; body?: string };
  confirmationConfig?: Partial<ConfirmationConfig>;
  challengeB64u?: string;
  walletIframeActivation?: RegistrationActivationProof;
};

type RegistrationCredentialDecisionInput = {
  requestId: string;
  confirmed: boolean;
  intentDigest?: string;
  credential?: unknown;
  transactionContext?: unknown;
  registrationDiagnostics?: unknown;
  error?: string;
};

export async function requestRegistrationCredentialConfirmation({
  touchConfirm,
  walletId,
  nearAccountId,
  signerSlot,
  confirmerText,
  confirmationConfig,
  challengeB64u,
  walletIframeActivation,
}: {
  touchConfirm: Pick<UiConfirmSecureConfirmationPort, 'requestUserConfirmation'>;
} & RegistrationCredentialConfirmationArgs): Promise<RegistrationCredentialConfirmationPayload> {
  if (typeof touchConfirm.requestUserConfirmation !== 'function') {
    throw new Error('UserConfirm manager request bridge is unavailable');
  }

  const request = buildRegistrationCredentialConfirmationRequest({
    walletId,
    nearAccountId,
    signerSlot,
    confirmerText,
    confirmationConfig,
    challengeB64u,
    walletIframeActivation,
  });
  const decision = await touchConfirm.requestUserConfirmation(request);
  return parseRegistrationCredentialDecision({ requestId: request.requestId, decision });
}

export async function requestRegistrationCredentialConfirmationOnMainThread({
  ctx,
  walletId,
  nearAccountId,
  signerSlot,
  confirmerText,
  confirmationConfig,
  challengeB64u,
  walletIframeActivation,
}: {
  ctx: UiConfirmContext;
} & RegistrationCredentialConfirmationArgs): Promise<RegistrationCredentialConfirmationPayload> {
  const request = buildRegistrationCredentialConfirmationRequest({
    walletId,
    nearAccountId,
    signerSlot,
    confirmerText,
    confirmationConfig,
    challengeB64u,
    walletIframeActivation,
  });
  validateUserConfirmRequest(request);
  assertNoForbiddenMainThreadSigningSecrets(request);

  const resolvedConfirmationConfig = determineConfirmationConfig(ctx, request);
  const transactionSummary = buildRegistrationTransactionSummary(request);
  const theme = coerceThemeName(ctx.getTheme?.()) ?? 'dark';
  const decision = await runRegistrationFlowOnMainThread({
    ctx,
    request,
    confirmationConfig: resolvedConfirmationConfig,
    transactionSummary,
    theme,
  });
  return parseRegistrationCredentialDecision({ requestId: request.requestId, decision });
}

function buildRegistrationCredentialConfirmationRequest({
  walletId,
  nearAccountId,
  signerSlot,
  confirmerText,
  confirmationConfig,
  challengeB64u,
  walletIframeActivation,
}: RegistrationCredentialConfirmationArgs): RegistrationUserConfirmRequest {
  const requestId = secureRandomId('register', 32, 'registration credential confirmation IDs');
  const title = confirmerText?.title;
  const body = confirmerText?.body;
  const normalizedWalletId = String(walletId || '').trim();
  const normalizedNearAccountId = String(nearAccountId || '').trim();
  if (!normalizedWalletId) {
    throw new Error('Registration credential confirmation requires walletId');
  }
  return {
    requestId,
    type: UserConfirmationType.REGISTER_ACCOUNT,
    summary: {
      walletId: normalizedWalletId,
      ...(normalizedNearAccountId ? { nearAccountId: normalizedNearAccountId } : {}),
      signerSlot,
      ...(title != null ? { title } : {}),
      ...(body != null ? { body } : {}),
    },
    payload: {
      walletId: normalizedWalletId,
      ...(normalizedNearAccountId ? { nearAccountId: normalizedNearAccountId } : {}),
      signerSlot,
      ...(challengeB64u
        ? {
            webauthnChallenge: {
              kind: 'intent_digest',
              challengeB64u,
            },
          }
        : {}),
      ...(walletIframeActivation ? { walletIframeActivation } : {}),
    },
    confirmationConfig,
    intentDigest: `register:${normalizedWalletId}:${signerSlot}`,
  };
}

function buildRegistrationTransactionSummary(
  request: RegistrationUserConfirmRequest,
): TransactionSummary {
  const parsedSummary = parseTransactionSummary(request.summary);
  const intentDigest = getIntentDigest(request);
  return {
    ...parsedSummary,
    ...(intentDigest ? { intentDigest } : {}),
  };
}

async function runRegistrationFlowOnMainThread({
  ctx,
  request,
  confirmationConfig,
  transactionSummary,
  theme,
}: {
  ctx: UiConfirmContext;
  request: RegistrationUserConfirmRequest;
  confirmationConfig: NormalizedConfirmationConfig;
  transactionSummary: TransactionSummary;
  theme: 'dark' | 'light';
}): Promise<RegistrationCredentialDecisionInput> {
  let resolveDecision!: (decision: RegistrationCredentialDecisionInput) => void;
  let rejectDecision!: (error: Error) => void;
  let decisionSettled = false;
  const decisionPromise = new Promise<RegistrationCredentialDecisionInput>((resolve, reject) => {
    resolveDecision = resolve;
    rejectDecision = reject;
  });
  const responsePort: UserConfirmResponsePort = {
    postMessage: (message: unknown) => {
      const decision = parseDirectRegistrationDecisionMessage(message, request.requestId);
      if (decision.ok) {
        resolveDecision(decision.value);
        return;
      }
      rejectDecision(new Error(decision.message));
    },
  };
  const flowPromise = handleRegistrationFlow(ctx, request, responsePort, {
    confirmationConfig,
    transactionSummary,
    theme,
  }).then(
    () => {
      if (!decisionSettled) {
        rejectDecision(new Error('Registration confirmation completed without a decision'));
      }
    },
    (error: unknown) => {
      rejectDecision(new Error(errorMessage(error) || 'Registration confirmation failed'));
    },
  );
  const decision = await decisionPromise;
  decisionSettled = true;
  await flowPromise;
  return decision;
}

function parseDirectRegistrationDecisionMessage(
  message: unknown,
  expectedRequestId: string,
): { ok: true; value: RegistrationCredentialDecisionInput } | { ok: false; message: string } {
  if (!isObject(message)) {
    return { ok: false, message: 'Registration confirmation returned a malformed response' };
  }
  const envelope = message as { type?: unknown; requestId?: unknown; data?: unknown };
  if (envelope.type !== UserConfirmMessageType.USER_PASSKEY_CONFIRM_RESPONSE) {
    return { ok: false, message: 'Registration confirmation returned an unexpected response type' };
  }
  const requestId = isString(envelope.requestId) ? envelope.requestId.trim() : '';
  if (requestId !== expectedRequestId) {
    return { ok: false, message: 'Registration confirmation response requestId mismatch' };
  }
  if (!isObject(envelope.data)) {
    return { ok: false, message: 'Registration confirmation returned missing decision data' };
  }
  const data = envelope.data as {
    requestId?: unknown;
    intentDigest?: unknown;
    confirmed?: unknown;
    credential?: unknown;
    transactionContext?: unknown;
    registrationDiagnostics?: unknown;
    error?: unknown;
  };
  const decisionRequestId = isString(data.requestId) ? data.requestId.trim() : '';
  if (decisionRequestId !== expectedRequestId) {
    return { ok: false, message: 'Registration confirmation decision requestId mismatch' };
  }
  if (!isBoolean(data.confirmed)) {
    return { ok: false, message: 'Registration confirmation returned invalid decision state' };
  }
  return {
    ok: true,
    value: {
      requestId: decisionRequestId,
      confirmed: data.confirmed,
      ...(isString(data.intentDigest) ? { intentDigest: data.intentDigest } : {}),
      ...(data.credential ? { credential: data.credential } : {}),
      ...(data.transactionContext ? { transactionContext: data.transactionContext } : {}),
      ...(data.registrationDiagnostics
        ? { registrationDiagnostics: data.registrationDiagnostics }
        : {}),
      ...(isString(data.error) ? { error: data.error } : {}),
    },
  };
}

function parseRegistrationCredentialDecision({
  requestId,
  decision,
}: {
  requestId: string;
  decision: RegistrationCredentialDecisionInput;
}): RegistrationCredentialConfirmationPayload {
  if (!decision.confirmed) {
    throw new Error(decision.error || 'User rejected registration request');
  }
  if (!decision.credential) {
    throw new Error('Missing credential from registration confirmation');
  }

  return parseAndValidateRegistrationCredentialConfirmationPayload({
    confirmed: decision.confirmed,
    requestId,
    intentDigest: decision.intentDigest || '',
    credential: decision.credential,
    transactionContext: decision.transactionContext,
    registrationDiagnostics: decision.registrationDiagnostics,
    error: decision.error,
  });
}
