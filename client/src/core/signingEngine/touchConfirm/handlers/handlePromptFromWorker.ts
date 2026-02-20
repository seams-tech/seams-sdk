import type { TouchConfirmContext } from '../';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import { determineConfirmationConfig } from './determineConfirmationConfig';
import {
  TransactionSummary,
  UserConfirmRequest,
  SecureConfirmationType,
} from '../shared/confirmTypes';
import { errorMessage, toError } from '@shared/utils/errors';
import {
  parseTransactionSummary,
  createUserConfirmScopedWorker,
  sendConfirmResponse,
  sanitizeForPostMessage,
} from '../shared/confirmCommon';
import { getIntentDigest } from './flows/adapters/request';
import {
  assertNoForbiddenMainThreadSigningSecrets,
  validateUserConfirmRequest,
} from './flows/adapters/request';
import type {
  LocalOnlyUserConfirmRequest,
  RegistrationUserConfirmRequest,
  SigningUserConfirmRequest,
  IntentDigestUserConfirmRequest,
  SecureConfirmPromptEnvelope,
} from '../shared/confirmTypes';
import { coerceThemeName } from '@shared/utils/theme';
import type { ThemeName } from '@/core/types/tatchi';

/**
 * Handles secure confirmation requests from the worker with robust error handling
 * => SecureConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD
 * and proper data validation. Supports both transaction and registration confirmation flows.
 */
export async function handlePromptFromWorker(
  ctx: TouchConfirmContext,
  message: SecureConfirmPromptEnvelope,
  worker: Worker
): Promise<void> {
  const scopedWorker = createUserConfirmScopedWorker(worker, { channelToken: message.channelToken });

  // 1. Validate and parse request
  let request: UserConfirmRequest;
  let confirmationConfig: ConfirmationConfig;
  let transactionSummary: TransactionSummary;
  let theme: ThemeName;

  try {

    request = validateUserConfirmRequest(message.data);
    assertNoForbiddenMainThreadSigningSecrets(request);
    confirmationConfig = determineConfirmationConfig(ctx, request);
    theme = coerceThemeName(ctx.getTheme?.()) ?? 'dark';

    const parsedSummary = parseTransactionSummary(request.summary);
    const intentDigest = getIntentDigest(request);

    transactionSummary = sanitizeForPostMessage({
      ...parsedSummary,
      ...(intentDigest ? { intentDigest } : {}),
    }) as TransactionSummary;

  } catch (e: unknown) {

    console.error('[SecureConfirm][Host] validateAndParseRequest failed', e);
    // Attempt to send a structured error back to the worker to avoid hard failure
    try {
      const rid = (message?.data as { requestId?: unknown } | undefined)?.requestId;
      if (typeof rid === 'string' && rid) {
        sendConfirmResponse(scopedWorker, {
          requestId: rid,
          confirmed: false,
          error: errorMessage(e) || 'Invalid secure confirm request',
        });
        return;
      }
    } catch {
      throw toError(e);
    }
    throw toError(e);
  }

  const handler = HANDLERS[request.type];
  if (!handler) {
    // Unsupported type fallback: return structured error to worker.
    sendConfirmResponse(scopedWorker, {
      requestId: request.requestId,
      confirmed: false,
      error: 'Unsupported secure confirmation type'
    });
    return;
  }

  try {
    await handler({ ctx, request, worker: scopedWorker, confirmationConfig, transactionSummary, theme });
  } catch (e: unknown) {
    console.error('[SecureConfirm][Host] handler failed', e);
    // Best-effort: always respond to the worker so worker-side requests don't hang indefinitely.
    sendConfirmResponse(scopedWorker, {
      requestId: request.requestId,
      intentDigest: getIntentDigest(request),
      confirmed: false,
      error: errorMessage(e) || 'Secure confirmation failed',
    });
  }
}

type HandlerArgs = {
  ctx: TouchConfirmContext;
  request: UserConfirmRequest;
  worker: Worker;
  confirmationConfig: ConfirmationConfig;
  transactionSummary: TransactionSummary;
  theme: ThemeName;
};

type Handler = (args: HandlerArgs) => Promise<void>;

async function importFlow<T>(label: string, loader: () => Promise<T>): Promise<T> {
  try {
    return await loader();
  } catch (e) {
    console.error(`[SecureConfirm][Host] failed to import ${label} flow module`, e);
    throw e;
  }
}

const HANDLERS: Partial<Record<SecureConfirmationType, Handler>> = {
  [SecureConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF]: async ({ ctx, request, worker, confirmationConfig, transactionSummary, theme }) => {
    const { handleLocalOnlyFlow } = await importFlow('localOnly', () => import('./flows/localOnly'));
    await handleLocalOnlyFlow(ctx, request as LocalOnlyUserConfirmRequest, worker, { confirmationConfig, transactionSummary, theme });
  },
  [SecureConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI]: async ({ ctx, request, worker, confirmationConfig, transactionSummary, theme }) => {
    const { handleLocalOnlyFlow } = await importFlow('localOnly', () => import('./flows/localOnly'));
    await handleLocalOnlyFlow(ctx, request as LocalOnlyUserConfirmRequest, worker, { confirmationConfig, transactionSummary, theme });
  },
  [SecureConfirmationType.REGISTER_ACCOUNT]: async ({ ctx, request, worker, confirmationConfig, transactionSummary, theme }) => {
    const { handleRegistrationFlow } = await importFlow('registration', () => import('./flows/registration'));
    await handleRegistrationFlow(ctx, request as RegistrationUserConfirmRequest, worker, { confirmationConfig, transactionSummary, theme });
  },
  [SecureConfirmationType.LINK_DEVICE]: async ({ ctx, request, worker, confirmationConfig, transactionSummary, theme }) => {
    const { handleRegistrationFlow } = await importFlow('registration', () => import('./flows/registration'));
    await handleRegistrationFlow(ctx, request as RegistrationUserConfirmRequest, worker, { confirmationConfig, transactionSummary, theme });
  },
  [SecureConfirmationType.SIGN_TRANSACTION]: async ({ ctx, request, worker, confirmationConfig, transactionSummary, theme }) => {
    const { handleTransactionSigningFlow } = await importFlow('signing', () => import('./flows/signing'));
    await handleTransactionSigningFlow(ctx, request as SigningUserConfirmRequest, worker, { confirmationConfig, transactionSummary, theme });
  },
  [SecureConfirmationType.SIGN_NEP413_MESSAGE]: async ({ ctx, request, worker, confirmationConfig, transactionSummary, theme }) => {
    const { handleTransactionSigningFlow } = await importFlow('signing', () => import('./flows/signing'));
    await handleTransactionSigningFlow(ctx, request as SigningUserConfirmRequest, worker, { confirmationConfig, transactionSummary, theme });
  },
  [SecureConfirmationType.SIGN_INTENT_DIGEST]: async ({ ctx, request, worker, confirmationConfig, transactionSummary, theme }) => {
    const { handleIntentDigestSigningFlow } = await importFlow('signing', () => import('./flows/signing'));
    await handleIntentDigestSigningFlow(ctx, request as IntentDigestUserConfirmRequest, worker, { confirmationConfig, transactionSummary, theme });
  },
};
