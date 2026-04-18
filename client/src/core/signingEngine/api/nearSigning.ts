import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { DelegateActionInput } from '@/core/types/delegate';
import { ActionPhase, ActionStatus, type onProgressEvents } from '@/core/types/sdkSentEvents';
import type {
  ConfirmationConfig,
  RpcCallPayload,
  WasmSignedDelegate,
} from '@/core/types/signer-worker';
import type { SignTransactionResult } from '@/core/types/tatchi';
import type { TransactionInputWasm } from '@/core/types/actions';
import {
  SENSITIVE_OPERATION_POLICIES,
  type SensitiveOperationPolicy,
} from '@shared/utils/signerDomain';
import {
  createEmailOtpWalletAuthAdapter,
  createPasskeyWalletAuthAdapter,
  createWalletAuthModeResolver,
  type AccountAuthMetadata,
  type WalletAuthPlan,
} from '@/core/signingEngine/auth';
import type { SignerWorkerManagerContext } from '../workerManager';
import { signNearWithTouchConfirm } from '../orchestration/near/nearSigningFlow';
import { resolveThresholdEd25519CommitQueueKey } from './thresholdLifecycle/thresholdEd25519CommitQueue';
import {
  getStoredThresholdEd25519SessionRecordForAccount,
  type ThresholdEd25519SessionRecord,
} from './thresholdLifecycle/thresholdSessionStore';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';

export type SignDelegateActionResult = {
  signedDelegate: WasmSignedDelegate;
  hash: string;
  nearAccountId: AccountId;
  logs?: string[];
};

export type SignNep413MessagePayload = {
  message: string;
  recipient: string;
  nonce: string;
  state: string | null;
  accountId: AccountId;
  signerSlot?: number;
  title?: string;
  body?: string;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
};

export type SignNep413MessageResult = {
  success: boolean;
  accountId: string;
  publicKey: string;
  signature: string;
  state?: string;
  error?: string;
};

export type SignTransactionsWithActionsInput = {
  transactions: TransactionInputWasm[];
  rpcCall: RpcCallPayload;
  signerSlot?: number;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  onEvent?: (update: onProgressEvents) => void;
  sessionId?: string;
  sensitivePolicy?: SensitiveOperationPolicy;
};

export type SignDelegateActionInput = {
  delegate: DelegateActionInput;
  rpcCall: RpcCallPayload;
  signerSlot?: number;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  onEvent?: (update: onProgressEvents) => void;
};

export type NearSignIntentRequest =
  | {
      chain: 'near';
      kind: 'transactionsWithActions';
      args: SignTransactionsWithActionsInput;
    }
  | {
      chain: 'near';
      kind: 'delegateAction';
      args: SignDelegateActionInput;
    }
  | {
      chain: 'near';
      kind: 'nep413';
      args: SignNep413MessagePayload;
    };

export type NearSignIntentResultByKind = {
  transactionsWithActions: SignTransactionResult[];
  delegateAction: SignDelegateActionResult;
  nep413: SignNep413MessageResult;
};

export type NearSignIntentResult<TRequest extends NearSignIntentRequest> = TRequest extends {
  kind: infer TKind;
}
  ? TKind extends keyof NearSignIntentResultByKind
    ? NearSignIntentResultByKind[TKind]
    : never
  : never;

export async function signNear<TRequest extends NearSignIntentRequest>(
  deps: NearSigningApiDeps,
  request: TRequest,
): Promise<NearSignIntentResult<TRequest>> {
  if (request.kind === 'transactionsWithActions') {
    return (await signTransactionsWithActions(
      deps,
      request.args,
    )) as NearSignIntentResult<TRequest>;
  }
  if (request.kind === 'delegateAction') {
    return (await signDelegateAction(deps, request.args)) as NearSignIntentResult<TRequest>;
  }
  if (request.kind === 'nep413') {
    return (await signNEP413Message(deps, request.args)) as NearSignIntentResult<TRequest>;
  }
  throw new Error(
    `[SigningEngine] unsupported near signing intent: ${String((request as { kind?: unknown }).kind || '')}`,
  );
}

export type NearSigningApiDeps = {
  nearRpcUrl: string;
  resolveThresholdEd25519SessionId?: (nearAccountId: AccountId) => string | null;
  requestEmailOtpChallengeForSigning?: (args: {
    nearAccountId: AccountId | string;
    chain: 'near';
    operation?: 'transaction_sign' | 'export_key';
    appSessionJwt?: string;
  }) => Promise<{ challengeId: string; emailHint?: string }>;
  isEmailOtpEd25519WarmupPending?: (args: { nearAccountId: AccountId | string }) => boolean;
  waitForPendingEmailOtpEd25519Warmup?: (args: {
    nearAccountId: AccountId | string;
  }) => Promise<boolean>;
  loginWithEmailOtpEd25519CapabilityForSigning?: (args: {
    nearAccountId: AccountId | string;
    challengeId: string;
    otpCode: string;
    record: ThresholdEd25519SessionRecord;
    operation?: 'transaction_sign' | 'export_key';
  }) => Promise<{ sessionId: string }>;
  markThresholdEd25519EmailOtpSessionConsumedForAccount?: (args: {
    nearAccountId: AccountId | string;
    thresholdSessionId?: string;
  }) => void;
  createSigningSessionId: (prefix: string) => string;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  withThresholdEd25519CommitQueue: <T>(args: {
    queueKey: string;
    nearAccountId: AccountId | string;
    enabled: boolean;
    shouldAbort?: () => boolean;
    maxQueueLength?: number;
    queueTimeoutMs?: number;
    task: () => Promise<T>;
  }) => Promise<T>;
};

function resolveNearTransactionAccountAuth(
  record: ThresholdEd25519SessionRecord | null | undefined,
): AccountAuthMetadata {
  if (record?.source === 'email_otp') {
    return {
      primaryAuthMethod: 'email_otp',
      linkedAuthMethods: ['email_otp'],
    };
  }
  return {
    primaryAuthMethod: 'passkey',
    linkedAuthMethods: ['passkey'],
  };
}

async function resolveNearTransactionWalletAuth(args: {
  deps: NearSigningApiDeps;
  nearAccountId: AccountId;
  record: ThresholdEd25519SessionRecord | null;
  onEvent?: (update: onProgressEvents) => void;
  sensitivePolicy?: SensitiveOperationPolicy;
}): Promise<{
  walletAuthPlan: WalletAuthPlan;
  emailOtpSigning?: {
    challengeId: string;
    emailHint?: string;
    complete: (otpCode: string) => Promise<{ sessionId: string }>;
    markConsumed: (thresholdSessionId?: string) => void;
  };
}> {
  const sensitivePolicy =
    args.sensitivePolicy || SENSITIVE_OPERATION_POLICIES.inheritSessionPolicy;
  if (
    args.record?.source === 'email_otp' &&
    (sensitivePolicy === SENSITIVE_OPERATION_POLICIES.requirePasskey ||
      sensitivePolicy === SENSITIVE_OPERATION_POLICIES.denyEmailOtp)
  ) {
    throw new Error(
      '[SigningEngine] NEAR operation requires passkey authentication after Email OTP login',
    );
  }

  const resolver = createWalletAuthModeResolver({
    passkey: createPasskeyWalletAuthAdapter({
      challenge: async () => ({}),
      complete: async () => ({
        method: 'passkey',
        webauthnAuthentication: {},
      }),
    }),
    emailOtp: createEmailOtpWalletAuthAdapter({
      challenge: async () => {
        if (typeof args.deps.requestEmailOtpChallengeForSigning !== 'function') {
          throw new Error('[SigningEngine] Email OTP per-operation NEAR signing is not configured');
        }
        args.onEvent?.({
          step: 2,
          phase: ActionPhase.STEP_2_USER_CONFIRMATION,
          status: ActionStatus.PROGRESS,
          message: 'Sending Email OTP for transaction authorization',
        });
        const challenge = await args.deps.requestEmailOtpChallengeForSigning({
          nearAccountId: args.nearAccountId,
          chain: 'near',
        });
        const challengeId = String(challenge.challengeId || '').trim();
        if (!challengeId) {
          throw new Error('[SigningEngine] Email OTP challenge response did not include challengeId');
        }
        args.onEvent?.({
          step: 2,
          phase: ActionPhase.STEP_2_USER_CONFIRMATION,
          status: ActionStatus.SUCCESS,
          message: 'Email OTP challenge ready',
        });
        return {
          challengeId,
          email: String(challenge.emailHint || '').trim(),
        };
      },
      complete: async ({ challengeId, code }) => {
        if (
          typeof args.deps.loginWithEmailOtpEd25519CapabilityForSigning !== 'function' ||
          !args.record
        ) {
          throw new Error('[SigningEngine] Email OTP per-operation NEAR signing is not configured');
        }
        const refreshed = await args.deps.loginWithEmailOtpEd25519CapabilityForSigning({
          nearAccountId: args.nearAccountId,
          challengeId,
          otpCode: code,
          record: args.record,
          operation: 'transaction_sign',
        });
        return {
          method: 'email_otp',
          emailOtpAuthentication: refreshed,
        };
      },
    }),
    warmSession: {
      resolveWarmSessionPlan: async (input) => {
        if (sensitivePolicy === SENSITIVE_OPERATION_POLICIES.requireFreshSameMethod) return null;
        const record = args.record;
        const isSingleUseEmailOtpRecord =
          record?.source === 'email_otp' &&
          record.emailOtpAuthContext?.retention === 'single_use';
        if (!record || isSingleUseEmailOtpRecord) return null;
        return {
          kind: 'warmSession',
          method: input.accountAuth.primaryAuthMethod,
          accountId: input.accountId,
          intent: input.intent,
          ...(input.curve ? { curve: input.curve } : {}),
          ...(record.runtimePolicyScope
            ? {
                signingRootId: signingRootScopeFromRuntimePolicyScope(record.runtimePolicyScope)
                  .signingRootId,
              }
            : {}),
          sessionId: record.thresholdSessionId,
          retention: record.emailOtpAuthContext?.retention || 'session',
          expiresAtMs: record.expiresAtMs,
          remainingUses: record.remainingUses,
        };
      },
    },
  });
  const walletAuthPlan = await resolver.resolveWalletAuthPlan({
    accountId: args.nearAccountId,
    accountAuth: resolveNearTransactionAccountAuth(args.record),
    intent: 'transaction_sign',
    curve: 'ed25519',
  });
  if (walletAuthPlan.kind !== 'emailOtpReauth') return { walletAuthPlan };

  const challenge = await walletAuthPlan.challenge();
  return {
    walletAuthPlan,
    emailOtpSigning: {
      challengeId: challenge.challengeId,
      ...(challenge.email ? { emailHint: challenge.email } : {}),
      complete: async (otpCode: string) => {
        const proof = await walletAuthPlan.complete({
          challengeId: challenge.challengeId,
          code: otpCode,
        });
        return proof.emailOtpAuthentication as { sessionId: string };
      },
      markConsumed: (thresholdSessionId?: string) =>
        args.deps.markThresholdEd25519EmailOtpSessionConsumedForAccount?.({
          nearAccountId: args.nearAccountId,
          ...(thresholdSessionId ? { thresholdSessionId } : {}),
        }),
    },
  };
}

function resolveSigningRequestSessionId(args: {
  deps: NearSigningApiDeps;
  providedSessionId?: string;
  nearAccountId: AccountId;
}): string {
  const provided = String(args.providedSessionId || '').trim();
  if (provided) return provided;
  if (typeof args.deps.resolveThresholdEd25519SessionId === 'function') {
    const canonical = String(
      args.deps.resolveThresholdEd25519SessionId(args.nearAccountId) || '',
    ).trim();
    if (canonical) return canonical;
  }
  return args.deps.createSigningSessionId('threshold-ed25519');
}

async function withThresholdEd25519CommitQueue<T>(args: {
  deps: NearSigningApiDeps;
  nearAccountId: AccountId;
  thresholdSessionId: string;
  task: () => Promise<T>;
}): Promise<T> {
  const queueKey = resolveThresholdEd25519CommitQueueKey({
    thresholdSessionId: args.thresholdSessionId,
  });
  return await args.deps.withThresholdEd25519CommitQueue({
    queueKey,
    nearAccountId: args.nearAccountId,
    enabled: true,
    task: args.task,
  });
}

export async function signTransactionsWithActions(
  deps: NearSigningApiDeps,
  args: SignTransactionsWithActionsInput,
): Promise<SignTransactionResult[]> {
  const nearAccountId = toAccountId(args.rpcCall.nearAccountId);
  let thresholdSessionRecord = getStoredThresholdEd25519SessionRecordForAccount(nearAccountId);
  const hasPendingEmailOtpEd25519Warmup = (): boolean =>
    deps.isEmailOtpEd25519WarmupPending?.({ nearAccountId }) === true;
  if (!thresholdSessionRecord && hasPendingEmailOtpEd25519Warmup()) {
    args.onEvent?.({
      step: 1,
      phase: ActionPhase.STEP_1_PREPARATION,
      status: ActionStatus.PROGRESS,
      message: 'Finalizing NEAR signing session...',
    });
    await deps.waitForPendingEmailOtpEd25519Warmup?.({ nearAccountId });
    thresholdSessionRecord = getStoredThresholdEd25519SessionRecordForAccount(nearAccountId);
  }
  const ed25519Warmup =
    thresholdSessionRecord?.source === 'email_otp' &&
    hasPendingEmailOtpEd25519Warmup() &&
    typeof deps.waitForPendingEmailOtpEd25519Warmup === 'function'
      ? {
          isPending: hasPendingEmailOtpEd25519Warmup,
          waitForReady: () => deps.waitForPendingEmailOtpEd25519Warmup!({ nearAccountId }),
        }
      : undefined;
  const { walletAuthPlan, emailOtpSigning } = await resolveNearTransactionWalletAuth({
    deps,
    nearAccountId,
    record: thresholdSessionRecord,
    onEvent: args.onEvent,
    sensitivePolicy: args.sensitivePolicy,
  });
  const resolvedSessionId = resolveSigningRequestSessionId({
    deps,
    providedSessionId: args.sessionId,
    nearAccountId,
  });
  return await withThresholdEd25519CommitQueue({
    deps,
    nearAccountId,
    thresholdSessionId: resolvedSessionId,
    task: async () => {
      const ctx = deps.getSignerWorkerContext();
      return (await signNearWithTouchConfirm({
        chain: 'near',
        kind: 'transactionsWithActions',
        payload: {
          ctx,
          transactions: args.transactions,
          rpcCall: args.rpcCall,
          signerSlot: args.signerSlot,
          confirmationConfigOverride: args.confirmationConfigOverride,
          title: args.title,
          body: args.body,
          onEvent: args.onEvent,
          sessionId: resolvedSessionId,
          walletAuthPlan,
          ...(emailOtpSigning ? { emailOtpSigning } : {}),
          ...(ed25519Warmup ? { ed25519Warmup } : {}),
        },
      })) as unknown as SignTransactionResult[];
    },
  });
}

export async function signDelegateAction(
  deps: NearSigningApiDeps,
  args: SignDelegateActionInput,
): Promise<SignDelegateActionResult> {
  const nearAccountId = toAccountId(args.rpcCall.nearAccountId || args.delegate.senderId);
  const normalizedRpcCall: RpcCallPayload = {
    nearRpcUrl: args.rpcCall.nearRpcUrl || deps.nearRpcUrl,
    nearAccountId,
  };

  try {
    const activeSessionId = resolveSigningRequestSessionId({
      deps,
      nearAccountId,
    });
    console.debug('[SigningEngine][delegate] session created', { sessionId: activeSessionId });
    return await withThresholdEd25519CommitQueue({
      deps,
      nearAccountId,
      thresholdSessionId: activeSessionId,
      task: async () => {
        const ctx = deps.getSignerWorkerContext();
        return (await signNearWithTouchConfirm({
          chain: 'near',
          kind: 'delegateAction',
          payload: {
            ctx,
            delegate: args.delegate,
            rpcCall: normalizedRpcCall,
            signerSlot: args.signerSlot,
            confirmationConfigOverride: args.confirmationConfigOverride,
            title: args.title,
            body: args.body,
            onEvent: args.onEvent,
            sessionId: activeSessionId,
          },
        })) as unknown as SignDelegateActionResult;
      },
    });
  } catch (err) {
    console.error('[SigningEngine][delegate] failed', err);
    throw err;
  }
}

export async function signNEP413Message(
  deps: NearSigningApiDeps,
  payload: SignNep413MessagePayload,
): Promise<SignNep413MessageResult> {
  try {
    const nearAccountId = toAccountId(payload.accountId);
    const activeSessionId = resolveSigningRequestSessionId({
      deps,
      nearAccountId,
    });
    const result = await withThresholdEd25519CommitQueue({
      deps,
      nearAccountId,
      thresholdSessionId: activeSessionId,
      task: async () => {
        const ctx = deps.getSignerWorkerContext();
        return (await signNearWithTouchConfirm({
          chain: 'near',
          kind: 'nep413',
          payload: {
            ctx,
            payload: {
              ...payload,
              sessionId: activeSessionId,
            },
          },
        })) as unknown as SignNep413MessageResult;
      },
    });
    if (result.success) {
      return result;
    }
    throw new Error(`NEP-413 signing failed: ${result.error || 'Unknown error'}`);
  } catch (error: unknown) {
    console.error('SigningEngine: NEP-413 signing error:', error);
    const message = error instanceof Error ? error.message : String(error || 'Unknown error');
    return {
      success: false,
      accountId: '',
      publicKey: '',
      signature: '',
      error: message,
    };
  }
}
