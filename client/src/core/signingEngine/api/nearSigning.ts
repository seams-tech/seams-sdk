import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { DelegateActionInput } from '@/core/types/delegate';
import {
  createSigningFlowEvent,
  SigningEventPhase,
  type CreateSigningFlowEventInput,
  type SigningFlowEvent,
} from '@/core/types/sdkSentEvents';
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
  resolveAccountAuthMetadataForSignerSource,
  type WalletAuthPlan,
} from '@/core/signingEngine/auth';
import type { SignerWorkerManagerContext } from '../workerManager';
import { signNearWithTouchConfirm } from '../orchestration/near/nearSigningFlow';
import { resolveThresholdEd25519CommitQueueKey } from './thresholdLifecycle/thresholdEd25519CommitQueue';
import {
  getStoredThresholdEd25519SessionRecordForAccount,
  type ThresholdEd25519SessionRecord,
  type ThresholdEcdsaSessionRecord,
} from './thresholdLifecycle/thresholdSessionStore';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  readSigningSessionSealedRecord,
  type SigningSessionSealedStoreRecord,
} from './session/signingSessionSealedStore';
import type { ThresholdEcdsaSessionBootstrapResult } from '../orchestration/thresholdActivation';
import type { ThresholdEcdsaActivationChain } from '../orchestration/thresholdActivation';
import { createWarmSessionManager } from '../session/WarmSessionManager';
import { clearThresholdEcdsaClientPresignaturesForLane } from '../orchestration/walletOrigin/thresholdEcdsaCoordinator';
import type { WarmSessionStatusResult } from '../touchConfirm';
import type { WebAuthnAuthenticationCredential } from '@/core/types';

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
  onEvent?: (update: SigningFlowEvent) => void;
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
  onEvent?: (update: SigningFlowEvent) => void;
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
    remainingUses?: number;
  }) => Promise<{ sessionId: string }>;
  reconnectPasskeyEd25519CapabilityForSigning?: (args: {
    nearAccountId: AccountId | string;
    record: ThresholdEd25519SessionRecord;
    localPrfCredential: WebAuthnAuthenticationCredential;
    usesNeeded?: number;
  }) => Promise<{ sessionId: string }>;
  markThresholdEd25519EmailOtpSessionConsumedForAccount?: (args: {
    nearAccountId: AccountId | string;
    thresholdSessionId?: string;
  }) => void;
  getThresholdEcdsaSessionRecordForSigning?: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }) => ThresholdEcdsaSessionRecord;
  rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord?: (args: {
    sealedRecord: SigningSessionSealedStoreRecord;
    ecdsaRecord: ThresholdEcdsaSessionRecord;
    ed25519Record?: ThresholdEd25519SessionRecord | null;
  }) => Promise<{
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    remainingUses: number;
    expiresAtMs: number;
  } | null>;
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
  clearThresholdEcdsaSessionRecordForLane?: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
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
) {
  return resolveAccountAuthMetadataForSignerSource({ source: record?.source });
}

function emitNearSigningEvent(
  onEvent: ((event: SigningFlowEvent) => void) | undefined,
  accountId: AccountId | string,
  event: Omit<CreateSigningFlowEventInput, 'flowId' | 'accountId'>,
): void {
  try {
    onEvent?.(
      createSigningFlowEvent({
        ...event,
        flowId: `signing:near:${String(accountId)}:${event.phase}`,
        accountId: String(accountId),
      }),
    );
  } catch {}
}

async function tryRestoreEmailOtpSigningSessionForNearTransaction(args: {
  deps: NearSigningApiDeps;
  nearAccountId: AccountId;
  onEvent?: (update: SigningFlowEvent) => void;
}): Promise<void> {
  if (
    typeof args.deps.getThresholdEcdsaSessionRecordForSigning !== 'function' ||
    typeof args.deps.rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord !== 'function'
  ) {
    return;
  }
  const ctx = args.deps.getSignerWorkerContext();
  const touchConfirm = ctx.touchConfirm;
  if (!touchConfirm) return;
  await createWarmSessionManager({
    touchConfirm,
    clearThresholdEcdsaSigningArtifactsForLane: ({ nearAccountId, chain }) => {
      const record = args.deps.getThresholdEcdsaSessionRecordForSigning?.({
        nearAccountId: String(nearAccountId),
        chain,
      });
      if (!record) return;
      clearThresholdEcdsaClientPresignaturesForLane({
        relayerUrl: record.relayerUrl,
        ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
        participantIds: record.participantIds,
      });
    },
    ...(args.deps.clearThresholdEcdsaSessionRecordForLane
      ? {
          clearThresholdEcdsaSessionRecordForLane:
            args.deps.clearThresholdEcdsaSessionRecordForLane,
        }
      : {}),
    getThresholdEcdsaSessionRecordForSigning: args.deps.getThresholdEcdsaSessionRecordForSigning,
    rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord:
      args.deps.rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord,
    getEmailOtpWarmSessionStatus: args.deps.getEmailOtpWarmSessionStatus,
    onSealedRestore: (event) => {
      if (event.status === 'started') {
        emitNearSigningEvent(args.onEvent, args.nearAccountId, {
          phase: SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED,
          status: 'waiting_for_user',
          message: 'Restoring signing session...',
          interaction: { kind: 'transaction_confirmation', overlay: 'show' },
          data: {
            chain: event.chain,
            thresholdSessionId: event.thresholdSessionId,
            ...(event.walletSigningSessionId
              ? { walletSigningSessionId: event.walletSigningSessionId }
              : {}),
          },
        });
        return;
      }
      if (event.status === 'restored') {
        emitNearSigningEvent(args.onEvent, args.nearAccountId, {
          phase: SigningEventPhase.STEP_06_AUTH_WARM_SESSION_CLAIMED,
          status: 'succeeded',
          message: 'Signing session restored',
          interaction: { kind: 'none', overlay: 'none' },
          data: {
            chain: event.chain,
            thresholdSessionId: event.thresholdSessionId,
            ...(event.walletSigningSessionId
              ? { walletSigningSessionId: event.walletSigningSessionId }
              : {}),
          },
        });
      }
    },
  })
    .getWarmSession(args.nearAccountId)
    .catch(() => undefined);
}

async function resolveNearTransactionWalletAuth(args: {
  deps: NearSigningApiDeps;
  nearAccountId: AccountId;
  record: ThresholdEd25519SessionRecord | null;
  onEvent?: (update: SigningFlowEvent) => void;
  sensitivePolicy?: SensitiveOperationPolicy;
  usesNeeded?: number;
}): Promise<{
  walletAuthPlan: WalletAuthPlan;
  emailOtpSigning?: {
    challengeId: string;
    emailHint?: string;
    resend?: () => Promise<{ challengeId: string; emailHint?: string }>;
    complete: (otpCode: string, challengeId?: string) => Promise<{ sessionId: string }>;
    markConsumed: (thresholdSessionId?: string) => void;
  };
}> {
  const sensitivePolicy = args.sensitivePolicy || SENSITIVE_OPERATION_POLICIES.inheritSessionPolicy;
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
        emitNearSigningEvent(args.onEvent, args.nearAccountId, {
          phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_CHALLENGE_STARTED,
          status: 'running',
          message: 'Sending Email OTP for transaction authorization',
          interaction: { kind: 'none', overlay: 'none' },
        });
        const challenge = await args.deps.requestEmailOtpChallengeForSigning({
          nearAccountId: args.nearAccountId,
          chain: 'near',
        });
        const challengeId = String(challenge.challengeId || '').trim();
        if (!challengeId) {
          throw new Error(
            '[SigningEngine] Email OTP challenge response did not include challengeId',
          );
        }
        emitNearSigningEvent(args.onEvent, args.nearAccountId, {
          phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_INPUT_REQUIRED,
          status: 'waiting_for_user',
          message: 'Email OTP challenge ready',
          interaction: { kind: 'otp_input', overlay: 'show' },
          ...(challenge.emailHint ? { data: { emailHint: challenge.emailHint } } : {}),
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
          remainingUses: Math.max(
            Math.floor(Number(args.usesNeeded) || 1) + 1,
            args.record.emailOtpAuthContext?.retention === 'session'
              ? Math.floor(Number(args.record.remainingUses) || 0)
              : 0,
          ),
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
          record?.source === 'email_otp' && record.emailOtpAuthContext?.retention === 'single_use';
        if (!record || isSingleUseEmailOtpRecord) return null;
        const sessionId = String(record.thresholdSessionId || '').trim();
        if (!sessionId) return null;
        const usesNeeded = Math.max(1, Math.floor(Number(args.usesNeeded) || 1));
        const workerCtx = args.deps.getSignerWorkerContext();
        const liveStatus = await createWarmSessionManager({
          touchConfirm: workerCtx.touchConfirm,
        })
          .getEd25519SigningSessionStatus(args.nearAccountId)
          .catch(() => null);
        if (liveStatus?.sessionId === sessionId) {
          if (liveStatus.status !== 'active') return null;
          const remainingUses = Math.floor(Number(liveStatus.remainingUses) || 0);
          if (remainingUses < usesNeeded) return null;
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
            sessionId,
            retention: record.emailOtpAuthContext?.retention || 'session',
            expiresAtMs: Math.floor(Number(liveStatus.expiresAtMs) || record.expiresAtMs),
            remainingUses,
          };
        }
        const sealedRecord = await readSigningSessionSealedRecord(sessionId).catch(() => null);
        if (sealedRecord) {
          const remainingUses = Math.floor(Number(sealedRecord.remainingUses) || 0);
          const expiresAtMs = Math.floor(Number(sealedRecord.expiresAtMs) || 0);
          if (remainingUses < usesNeeded || expiresAtMs <= Date.now()) return null;
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
            sessionId,
            retention: record.emailOtpAuthContext?.retention || 'session',
            expiresAtMs,
            remainingUses,
          };
        }
        if (workerCtx.touchConfirm) return null;
        const remainingUses = Math.floor(Number(record.remainingUses) || 0);
        const expiresAtMs = Math.floor(Number(record.expiresAtMs) || 0);
        if (remainingUses < usesNeeded || expiresAtMs <= Date.now()) return null;
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
          sessionId,
          retention: record.emailOtpAuthContext?.retention || 'session',
          expiresAtMs,
          remainingUses,
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
  let activeChallenge = challenge;
  return {
    walletAuthPlan,
    emailOtpSigning: {
      challengeId: activeChallenge.challengeId,
      ...(activeChallenge.email ? { emailHint: activeChallenge.email } : {}),
      resend: async () => {
        activeChallenge = await walletAuthPlan.challenge();
        return {
          challengeId: activeChallenge.challengeId,
          ...(activeChallenge.email ? { emailHint: activeChallenge.email } : {}),
        };
      },
      complete: async (otpCode: string, challengeId?: string) => {
        const resolvedChallengeId = String(challengeId || activeChallenge.challengeId).trim();
        const proof = await walletAuthPlan.complete({
          challengeId: resolvedChallengeId,
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
    emitNearSigningEvent(args.onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
      status: 'running',
      message: 'Finalizing NEAR signing session',
      interaction: { kind: 'none', overlay: 'none' },
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
  await tryRestoreEmailOtpSigningSessionForNearTransaction({
    deps,
    nearAccountId,
    onEvent: args.onEvent,
  });
  thresholdSessionRecord = getStoredThresholdEd25519SessionRecordForAccount(nearAccountId);
  const { walletAuthPlan, emailOtpSigning } = await resolveNearTransactionWalletAuth({
    deps,
    nearAccountId,
    record: thresholdSessionRecord,
    onEvent: args.onEvent,
    sensitivePolicy: args.sensitivePolicy,
    usesNeeded: Math.max(1, args.transactions.length),
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
          ...(walletAuthPlan.kind === 'passkeyReauth' &&
          thresholdSessionRecord &&
          typeof deps.reconnectPasskeyEd25519CapabilityForSigning === 'function'
            ? {
                passkeyEd25519Reconnect: {
                  reconnect: async ({ credential, usesNeeded }) =>
                    await deps.reconnectPasskeyEd25519CapabilityForSigning!({
                      nearAccountId,
                      record: thresholdSessionRecord,
                      localPrfCredential: credential,
                      usesNeeded,
                    }),
                },
              }
            : {}),
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
