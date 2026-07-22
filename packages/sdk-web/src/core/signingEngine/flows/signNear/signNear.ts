import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { parseWebAuthnRpId, type WebAuthnRpId } from '@shared/utils/domainIds';
import { parseSignerSlot } from '@shared/utils/signerSlot';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
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
import type {
  NearEd25519EmailOtpStepUpAuthorization,
  NearEd25519YaoCapabilitySource,
  NearEd25519YaoSigningCapability,
  NearTransactionWithActionsPayload,
} from '../../interfaces/near';
import type { SignTransactionResult } from '@/core/types/seams';
import type { TransactionInputWasm } from '@/core/types/actions';
import {
  SENSITIVE_OPERATION_POLICIES,
  type SensitiveOperationPolicy,
} from '@shared/utils/signerDomain';
import {
  SigningAuthPlanKind,
  type SigningAuthPlan,
} from '@/core/signingEngine/stepUpConfirmation/types';
import type { NearSigningApiDeps } from '../../interfaces/operationDeps';
import { signNearWithUiConfirm } from './nearSigningFlow';
import { resolveThresholdEd25519CommitQueueKey } from '../../threshold/ed25519/commitQueue';
import {
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  type ThresholdEd25519SessionRecord,
} from '../../session/persistence/records';
import {
  emailOtpAuthContextReason,
  emailOtpAuthContextRetention,
  type Ed25519LaneCandidate,
  type SelectedEd25519Lane,
  type ThresholdEd25519SessionStoreSource,
} from '../../session/identity/laneIdentity';
import { signingLaneAuthMethod } from '../../session/identity/signingLaneAuthBinding';
import { exactSigningLaneIdentityKey } from '../../session/identity/exactSigningLaneIdentity';
import { buildExactPasskeyEd25519RefreshLaneIdentity } from '../../session/passkey/ed25519BudgetRefresh';
import type {
  AvailableSigningLanes,
  AvailableEd25519SigningLane,
} from '../../session/availability/availableSigningLanes';
import type { EmailOtpTransactionSigningChallenge } from '../../session/emailOtp/publicTypes';
import { demoEmailOtpCodeFromDelivery } from '../../session/emailOtp/challengeDelivery';
import { publishResolvedIdentity } from '../../session/persistence/sealedSessionStore';
import {
  buildPasskeyEd25519SessionPolicy,
  isSigningSessionAuthUnavailableError,
} from '../../threshold/sessionPolicy';
import { buildThresholdEd25519WebAuthnPrfSecretSource } from '../../threshold/ed25519/walletSession';
import {
  SigningOperationIntent,
  SigningSessionPlanKind,
  SigningSessionIds,
  type ResolvedEd25519SigningSessionIdentity,
  type SigningOperationId,
} from '../../session/operationState/types';
import {
  buildNearTransactionSigningLane,
  type NearTransactionSigningLane,
} from '../../session/operationState/lanes';
import {
  toWalletId,
  type NearCommandSubject,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  SigningSessionCoordinator,
  type SigningSessionReadiness,
} from '../../session/SigningSessionCoordinator';
import {
  buildSigningGrantAdmissionQueueKey,
  decideSigningGrantAdmissionError,
  signingGrantAdmissionAuthorityKeyFromAuth,
  waitForSigningGrantAdmissionRetry,
} from '../../session/budget/admission';
import type { SigningSessionBudgetStatusAuth } from '../../session/budget/budget';
import {
  normalizeStepUpOperationId,
  resolvePostExhaustionStepUpBudgetPolicy,
  resolveSigningBudgetPolicyRemainingUses,
} from '../../session/budget/policy';
import { signingAuthPlanFromSigningSessionPlan } from '../shared/signingConfirmation';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
  emitSigningLaneResolutionTrace,
  emitSigningPlannerDecisionTrace,
} from '../../session/operationState/trace';
import {
  type PreparedThresholdSigningOperation,
  type ThresholdSigningReadinessInput,
} from '../../session/operationState/preparedOperation';
import {
  resolveRouterAbEd25519WalletSessionStateForOperation,
  type ResolvedRouterAbEd25519WalletSessionState,
} from '../../session/warmCapabilities/routerAbEd25519WalletSessionState';
import {
  buildEd25519SigningLane,
  type Ed25519SigningLane,
} from '../../session/emailOtp/ed25519SigningLane';
import { buildEmailOtpEd25519SigningSessionAuthority } from '../../session/emailOtp/ed25519SigningSessionAuthority';
import {
  classifyRouterAbEd25519PersistedSigningRecord,
  parseRouterAbEd25519WalletSessionAuthorityFromRecord,
} from '../../session/routerAbSigningWalletSession';
import { resolveEmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import {
  receiveTransactionIntent,
  recordAvailableSigningLanesRead,
  selectTransactionLaneFromAvailableLanes,
  type NearEd25519TransactionSelectableAvailableLane,
  type NearEd25519TransactionSelectableLane,
  type TransactionLaneSelectedState,
} from '../../session/identity/selectLane';
import {
  classifyTransactionReadiness,
  prepareTransactionOperationFromReadiness,
  prepareTransactionSigningOperation,
  type BudgetAdmittedOperation,
  type NearEd25519TransactionSigningIntent,
  type PreparedTransactionBudgetState,
  type NearEd25519TransactionSignerSelection,
  type PreparedTransactionOperation,
  type TransactionAuthSelectionPolicy,
  type TransactionSigningIntent,
  type TransactionReadiness,
  type TransactionReadinessClassifiedState,
} from '../../session/operationState/transactionState';
import type { NearEd25519PasskeyStepUpAuthorization } from './stepUpAuthorization';
import { requiredNearTransactionSignatureUses } from './signatureUses';

function requirePasskeyEd25519ReauthRpId(value: unknown): WebAuthnRpId {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

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
  commandSubject: NearCommandSubject;
  signerSlot?: number;
  title?: string;
  body?: string;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
};

export type SignNep413MessageResult =
  | {
      success: true;
      accountId: string;
      publicKey: string;
      signature: string;
      state?: string;
      error?: never;
    }
  | {
      success: false;
      error: string;
      accountId?: never;
      publicKey?: never;
      signature?: never;
      state?: never;
    };

export type SignTransactionWithActionsInput = {
  commandSubject: NearCommandSubject;
  transaction: TransactionInputWasm;
  rpcCall: RpcCallPayload;
  signerSlot?: number;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  onEvent?: (update: SigningFlowEvent) => void;
  sessionId?: string;
  sensitivePolicy?: SensitiveOperationPolicy;
};

type NearTransactionPublicSigningOptions = Pick<
  SignTransactionWithActionsInput,
  'confirmationConfigOverride' | 'title' | 'body' | 'onEvent' | 'signerSlot'
>;

export type SignDelegateActionInput = {
  commandSubject: NearCommandSubject;
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
      kind: 'transactionWithActions';
      args: SignTransactionWithActionsInput;
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
  transactionWithActions: SignTransactionResult;
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

function resolveTransactionStepUpSessionUses(args: {
  operationId: SigningOperationId;
  requiredSignatureUses: number;
}): number {
  const requiredSignatureUses = Math.max(1, Math.floor(Number(args.requiredSignatureUses) || 1));
  const budgetPolicy = resolvePostExhaustionStepUpBudgetPolicy({
    operationId: normalizeStepUpOperationId(args.operationId),
    requiredSignatureUses,
  });
  return Math.max(requiredSignatureUses, resolveSigningBudgetPolicyRemainingUses(budgetPolicy));
}

export async function signNear<TRequest extends NearSignIntentRequest>(
  deps: NearSigningApiDeps,
  request: TRequest,
): Promise<NearSignIntentResult<TRequest>> {
  if (request.kind === 'transactionWithActions') {
    return (await signTransactionWithActions(deps, request.args)) as NearSignIntentResult<TRequest>;
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

type NearTransactionPreConfirmSigningDeps = {
  getWarmThresholdEd25519SessionStatusForSession?: NearSigningApiDeps['getWarmThresholdEd25519SessionStatusForSession'];
  signingSessionCoordinator: SigningSessionCoordinator;
  hasUiConfirm: () => boolean;
};

type NearEd25519PasskeyReconnect = {
  prepare: (args: { requiredSignatureUses: number }) => Promise<{
    sessionId: string;
    signingGrantId: string;
    sessionPolicyDigest32: string;
  }>;
  reconnect: (args: {
    authorization: NearEd25519PasskeyStepUpAuthorization;
    requiredSignatureUses: number;
  }) => Promise<{
    sessionId: string;
    activeClient: NearEd25519YaoSigningCapability['activeClient'];
    sessionState: NearEd25519YaoSigningCapability['walletSessionState'];
  }>;
};

type NearEd25519EmailOtpReconnect = {
  prepare: () => Promise<EmailOtpTransactionSigningChallenge>;
  resend: () => Promise<EmailOtpTransactionSigningChallenge>;
  reconnect: (args: {
    authorization: NearEd25519EmailOtpStepUpAuthorization;
    requiredSignatureUses: number;
  }) => Promise<{
    sessionId: string;
    activeClient: NearEd25519YaoSigningCapability['activeClient'];
    sessionState: NearEd25519YaoSigningCapability['walletSessionState'];
  }>;
};

type NearEd25519SelectedTransactionLane = TransactionLaneSelectedState<
  SelectedEd25519Lane,
  NearEd25519TransactionSelectableAvailableLane,
  Ed25519LaneCandidate,
  NearEd25519TransactionSelectableLane
>;

type PreparedNearEd25519TransactionSigningSession = {
  thresholdSessionRecord: ThresholdEd25519SessionRecord | null;
  signingAuthPlan: SigningAuthPlan;
  signingLane: NearTransactionSigningLane;
  transactionLane: SelectedEd25519Lane;
  identity: ResolvedEd25519SigningSessionIdentity;
  resolvedSessionId: string;
  availableLanesGeneration: number;
  preparedOperation: PreparedNearEd25519Operation;
  transactionOperation: PreparedTransactionOperation<SelectedEd25519Lane>;
  budget: PreparedTransactionBudgetState<SelectedEd25519Lane>;
  emailOtpCommittedLane?: Ed25519SigningLane;
};

type PreparedNearTransactionExecutionState = {
  kind: 'prepared_near_transaction_execution';
  sessionId: string;
  signingSessionPlan: PreparedNearEd25519Operation['signingSessionPlan'];
  signingAuthPlan: SigningAuthPlan;
  signingLane: NearTransactionSigningLane;
  initialBudgetAdmittedOperation: BudgetAdmittedOperation<SelectedEd25519Lane> | null;
  signingSessionCoordinator: SigningSessionCoordinator;
  transactionOperation: PreparedTransactionOperation<SelectedEd25519Lane>;
  emailOtpCommittedLane: Ed25519SigningLane | null;
  passkeyEd25519Reconnect: NearEd25519PasskeyReconnect | null;
  emailOtpEd25519Reconnect: NearEd25519EmailOtpReconnect | null;
};

type NearEd25519LifecycleMetadata = {
  thresholdSessionRecord: ThresholdEd25519SessionRecord;
  transactionLane: SelectedEd25519Lane;
  transactionOperation: PreparedTransactionOperation<SelectedEd25519Lane>;
  transactionReadinessState: TransactionReadinessClassifiedState;
  identity: ResolvedEd25519SigningSessionIdentity;
  availableLanesGeneration: number;
  readiness: ThresholdSigningReadinessInput;
};

type PreparedNearEd25519Operation = PreparedThresholdSigningOperation<
  NearTransactionSigningLane,
  NearEd25519LifecycleMetadata
>;

type NearEd25519TransactionOperationPrepareResult = {
  lane: NearTransactionSigningLane;
  transactionLane: SelectedEd25519Lane;
  transactionIntent: TransactionSigningIntent;
  readiness: ThresholdSigningReadinessInput;
  availableLanesGeneration: number;
  metadata: NearEd25519LifecycleMetadata;
};

function createNearTransactionSigningOperationId(): SigningOperationId {
  const randomId = secureRandomBase64Url(32, 'NEAR transaction signing operation IDs');
  return SigningSessionIds.signingOperation(`near-transaction-sign:${randomId}`);
}

function summarizeNearEd25519Lane(lane: AvailableEd25519SigningLane): Record<string, unknown> {
  if (lane.state === 'missing') {
    return {
      state: lane.state,
      curve: lane.curve,
      chain: lane.chain,
    };
  }
  return {
    authMethod: signingLaneAuthMethod(lane.auth),
    walletId: lane.walletId,
    nearAccountId: lane.nearAccountId,
    nearEd25519SigningKeyId: lane.nearEd25519SigningKeyId,
    signerSlot: lane.signerSlot,
    state: lane.state,
    source: lane.source || 'unknown',
    signingGrantId: lane.signingGrantId,
    thresholdSessionId: lane.thresholdSessionId,
    remainingUses: lane.remainingUses,
    expiresAtMs: lane.expiresAtMs,
  };
}

function summarizeNearEd25519AvailableLanes(
  availableLanes: AvailableSigningLanes | null,
): Record<string, unknown> {
  const candidates = availableLanes?.candidates.ed25519.near || [];
  return {
    generation: availableLanes?.generation || 0,
    candidateCount: candidates.length,
    candidates: candidates.map(summarizeNearEd25519Lane),
  };
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

function buildNearTransactionSigningLaneForSelectedLane(args: {
  commandSubject: NearCommandSubject;
  record: ThresholdEd25519SessionRecord;
  selectedLane: SelectedEd25519Lane;
}) {
  const signer = args.selectedLane.identity.signer;
  const walletId = signer.account.wallet.walletId;
  if (String(args.commandSubject.walletSession.walletId) !== String(walletId)) {
    throw new Error('[SigningEngine][near] selected lane wallet does not match command subject');
  }
  const sessionId = String(args.selectedLane.thresholdSessionId || '').trim();
  const signingGrantId = String(args.selectedLane.signingGrantId || '').trim();
  if (!sessionId) {
    throw new Error(
      '[SigningEngine][near] missing threshold session id for transaction auth planning',
    );
  }
  if (!signingGrantId) {
    throw new Error('[SigningEngine][near] missing signing grant id for transaction auth planning');
  }
  if (args.record.source === 'email_otp') {
    if (args.selectedLane.auth.kind !== 'email_otp') {
      throw new Error('[SigningEngine][near] selected Email OTP lane is missing Email OTP auth');
    }
    if (!args.record.emailOtpAuthContext) {
      throw new Error('[SigningEngine][near] selected Email OTP record is missing auth context');
    }
    return buildNearTransactionSigningLane({
      walletId,
      nearAccountId: signer.account.nearAccountId,
      nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
      signerSlot: signer.signerSlot,
      auth: args.selectedLane.auth,
      signingGrantId: SigningSessionIds.signingGrant(signingGrantId),
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session(sessionId),
      retention: emailOtpAuthContextRetention(args.record.emailOtpAuthContext),
      sessionOrigin:
        emailOtpAuthContextReason(args.record.emailOtpAuthContext) === 'login'
          ? 'login'
          : 'per_operation',
    });
  }
  if (args.selectedLane.auth.kind !== 'passkey') {
    throw new Error('[SigningEngine][near] selected passkey lane is missing passkey auth');
  }
  return buildNearTransactionSigningLane({
    walletId,
    nearAccountId: signer.account.nearAccountId,
    nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
    signerSlot: signer.signerSlot,
    auth: args.selectedLane.auth,
    signingGrantId: SigningSessionIds.signingGrant(signingGrantId),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(sessionId),
    storageSource: resolveEd25519PasskeyStorageSource(args.record.source),
  });
}

function assertSigningLaneMatchesSelectedTransactionLane(args: {
  signingLane: NearTransactionSigningLane;
  transactionLane: SelectedEd25519Lane;
}): void {
  if (
    exactSigningLaneIdentityKey(args.signingLane.identity) !==
    exactSigningLaneIdentityKey(args.transactionLane.identity)
  ) {
    throw new Error(
      '[SigningEngine][near] prepared signing lane drifted from selected transaction lane',
    );
  }
}

function transactionReadinessFromPlannerInput(
  readiness: ThresholdSigningReadinessInput,
): TransactionReadiness {
  const status = readiness.readiness.status;
  if (status === 'ready') {
    return {
      status: 'ready',
      remainingUses: Math.max(0, Math.floor(Number(readiness.readiness.remainingUses) || 0)),
      expiresAtMs: Math.max(0, Math.floor(Number(readiness.readiness.expiresAtMs) || 0)),
    };
  }
  if (status === 'expired' || status === 'exhausted' || status === 'budget_unknown') {
    return status === 'budget_unknown'
      ? { status, reason: 'trusted wallet budget status is unavailable' }
      : { status };
  }
  if (status === 'auth_unavailable' || status === 'status_unavailable') {
    return { status, reason: status };
  }
  return { status: 'status_unavailable', reason: status };
}

function requireResolvedNearEd25519SigningLane(
  lane: NearTransactionSigningLane,
): ResolvedEd25519SigningSessionIdentity {
  if (lane.curve !== 'ed25519' || lane.keyKind !== 'threshold_ed25519') {
    throw new Error('[SigningEngine][near] prepared signing lane is not Ed25519');
  }
  if (lane.chainFamily !== 'near') {
    throw new Error('[SigningEngine][near] prepared Ed25519 lane must target NEAR');
  }
  const thresholdSessionId = String(lane.thresholdSessionId || '').trim();
  const signingGrantId = String(lane.signingGrantId || '').trim();
  if (!thresholdSessionId || !signingGrantId) {
    throw new Error('[SigningEngine][near] prepared Ed25519 lane is missing session identity');
  }
  // Resolved lane metadata is copied from the executable lane so challenge, budget,
  // signing, and cleanup cannot rediscover or disagree about session metadata.
  return {
    ...lane,
    curve: 'ed25519',
    keyKind: 'threshold_ed25519',
    chainFamily: 'near',
    signingGrantId: SigningSessionIds.signingGrant(signingGrantId),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(thresholdSessionId),
  };
}

function resolveEd25519PasskeyStorageSource(
  source: ThresholdEd25519SessionStoreSource | undefined,
): Exclude<ThresholdEd25519SessionStoreSource, 'email_otp'> {
  return source && source !== 'email_otp' ? source : 'login';
}

function trustedBudgetStatusAuthFromEd25519WalletSessionState(
  state: ResolvedRouterAbEd25519WalletSessionState,
): SigningSessionBudgetStatusAuth | null {
  const relayerUrl = String(state.relayerUrl || '').trim();
  const thresholdSessionId = String(state.thresholdSessionId || '').trim();
  const walletSessionJwt = String(state.signingWalletSession.auth.walletSessionJwt || '').trim();
  if (!relayerUrl || !thresholdSessionId || !walletSessionJwt) return null;
  return {
    relayerUrl,
    thresholdSessionId,
    walletSessionJwt,
  };
}

function resolveEd25519SigningLane(args: {
  lane: SelectedEd25519Lane;
  record: ThresholdEd25519SessionRecord;
}): Ed25519SigningLane {
  if (args.record.source !== 'email_otp') {
    throw new Error('[SigningEngine][near] Email OTP Ed25519 step-up requires Email OTP record');
  }
  if (args.lane.auth.kind !== 'email_otp') {
    throw new Error(
      '[SigningEngine][near] Email OTP Ed25519 committed lane requires Email OTP auth',
    );
  }
  const walletSessionAuthority = parseRouterAbEd25519WalletSessionAuthorityFromRecord(args.record);
  if (!walletSessionAuthority.ok) {
    throw new Error(
      `[SigningEngine][near] Email OTP Ed25519 committed lane is missing wallet-session authority: ${walletSessionAuthority.reason}`,
    );
  }
  const authLane = resolveEmailOtpAuthLane({
    routeAuth: {
      kind: 'wallet_session',
      jwt: walletSessionAuthority.value.auth.walletSessionJwt,
    },
    thresholdSessionId: walletSessionAuthority.value.thresholdSessionId,
    authorizingSigningGrantId: walletSessionAuthority.value.signingGrantId,
    curve: 'ed25519',
  });
  const authority =
    args.record.emailOtpAuthContext && authLane
      ? buildEmailOtpEd25519SigningSessionAuthority({
          authLane,
          authority: args.record.emailOtpAuthContext.authority,
        })
      : null;
  if (!authority) {
    throw new Error(
      '[SigningEngine][near] Email OTP Ed25519 committed lane is unavailable; unlock wallet again',
    );
  }
  return buildEd25519SigningLane({
    record: args.record,
    authority,
  });
}

async function resolveNearTransactionPlannerReadiness(args: {
  preConfirmDeps: NearTransactionPreConfirmSigningDeps;
  nearAccount: NearCommandSubject['nearAccount'];
  record: ThresholdEd25519SessionRecord;
  operationNowMs: number;
  requiredSignatureUses?: number;
}): Promise<{
  readiness: SigningSessionReadiness;
  expiresAtMs: number;
  remainingUses: number;
}> {
  const sessionId = String(args.record.thresholdSessionId || '').trim();
  const thresholdSessionId = SigningSessionIds.thresholdEd25519Session(sessionId);
  const requiredSignatureUses = Math.max(1, Math.floor(Number(args.requiredSignatureUses) || 1));
  const resolveExpiresAtMs = (): number => args.record.expiresAtMs;
  const resolveRemainingUses = (): number => args.record.remainingUses;
  const buildReadiness = (
    status: SigningSessionReadiness['status'],
    remainingUses = resolveRemainingUses(),
    expiresAtMs = resolveExpiresAtMs(),
  ): {
    readiness: SigningSessionReadiness;
    expiresAtMs: number;
    remainingUses: number;
  } => {
    const normalizedRemainingUses = Math.max(0, Math.floor(Number(remainingUses) || 0));
    const normalizedExpiresAtMs = Math.max(0, Math.floor(Number(expiresAtMs) || 0));
    const readiness: SigningSessionReadiness =
      status === 'ready' || status === 'exhausted'
        ? {
            status,
            thresholdSessionId,
            remainingUses: normalizedRemainingUses,
            expiresAtMs: normalizedExpiresAtMs,
          }
        : status === 'expired'
          ? { status, thresholdSessionId, expiresAtMs: normalizedExpiresAtMs }
          : { status, thresholdSessionId };
    return {
      readiness,
      expiresAtMs: normalizedExpiresAtMs,
      remainingUses: normalizedRemainingUses,
    };
  };

  const emailOtpAuthContext =
    args.record.source === 'email_otp' ? args.record.emailOtpAuthContext : null;
  const isSingleUseEmailOtpRecord = emailOtpAuthContext
    ? emailOtpAuthContextRetention(emailOtpAuthContext) === 'single_use'
    : false;
  const persistedState = classifyRouterAbEd25519PersistedSigningRecord(
    args.record,
    args.operationNowMs,
  );
  if (persistedState.kind === 'expired') {
    return buildReadiness('expired', 0, persistedState.expiresAtMs);
  }
  if (persistedState.kind === 'exhausted') {
    return buildReadiness('exhausted', persistedState.remainingUses, resolveExpiresAtMs());
  }
  if (!sessionId || isSingleUseEmailOtpRecord || persistedState.kind !== 'ready') {
    return buildReadiness('missing_session', 0);
  }

  const liveStatus =
    (await args.preConfirmDeps
      .getWarmThresholdEd25519SessionStatusForSession?.({
        nearAccountId: args.nearAccount.accountId,
        thresholdSessionId: sessionId,
      })
      .catch(() => null)) || null;
  const remainingUses = resolveRemainingUses();
  const expiresAtMs = resolveExpiresAtMs();
  if (liveStatus?.sessionId === sessionId) {
    if (liveStatus.status === 'expired') return buildReadiness('expired', 0);
    if (liveStatus.status === 'exhausted') return buildReadiness('exhausted', 0);
    if (liveStatus.status === 'active') {
      const liveRemainingUses = Math.floor(Number(liveStatus.remainingUses) || 0);
      if (liveRemainingUses < requiredSignatureUses) {
        return buildReadiness('exhausted', liveRemainingUses);
      }
      return buildReadiness(
        'ready',
        liveRemainingUses,
        Math.floor(Number(liveStatus.expiresAtMs) || args.record.expiresAtMs),
      );
    }
  }

  if (remainingUses < requiredSignatureUses) {
    return buildReadiness('exhausted', remainingUses, expiresAtMs);
  }
  return buildReadiness('ready', remainingUses, expiresAtMs);
}

async function resolveNearTransactionWalletAuth(args: {
  commandSubject: NearCommandSubject;
  preparedOperation: PreparedNearEd25519Operation;
}): Promise<{
  signingAuthPlan: SigningAuthPlan;
  signingLane: NearTransactionSigningLane;
}> {
  const preparedOperation = args.preparedOperation;
  const record = preparedOperation.metadata.thresholdSessionRecord;
  if (!record) {
    throw new Error('[SigningEngine][near] signing session is not ready: missing_session');
  }
  const lane = preparedOperation.lane;
  emitSigningLaneResolutionTrace('near', lane, {
    reason: 'near_transaction_auth_planning',
  });

  const nearAccountId = args.commandSubject.nearAccount.accountId;
  const authInput = {
    accountId: nearAccountId,
    intent: SigningOperationIntent.TransactionSign,
    curve: 'ed25519' as const,
  };
  const plan = preparedOperation.signingSessionPlan;
  if (plan.kind === SigningSessionPlanKind.NotReady) {
    console.warn('[SigningEngine][near][ed25519] transaction auth planning not ready', {
      nearAccountId,
      authMethod: signingLaneAuthMethod(lane.auth),
      reason: plan.reason,
      readiness: preparedOperation.readiness.status,
      signingGrantId: lane.signingGrantId,
      thresholdSessionId: lane.thresholdSessionId,
      recordSource: record.source,
      retention: record.emailOtpAuthContext
        ? emailOtpAuthContextRetention(record.emailOtpAuthContext)
        : null,
      remainingUses: preparedOperation.remainingUses,
      expiresAtMs: preparedOperation.expiresAtMs,
    });
    if (plan.reason === 'policy_blocked') {
      throw new Error(
        '[SigningEngine] NEAR operation requires passkey authentication after Email OTP login',
      );
    }
    throw new Error(`[SigningEngine][near] signing session is not ready: ${plan.reason}`);
  }
  const signingAuthPlan = signingAuthPlanFromSigningSessionPlan({
    plan,
    accountId: authInput.accountId,
    intent: authInput.intent,
    curve: authInput.curve,
    expiresAtMs: preparedOperation.expiresAtMs,
    remainingUses: preparedOperation.remainingUses,
  });
  return {
    signingAuthPlan,
    signingLane: lane,
  };
}

function walletSessionJwtForPreparedNearExecution(args: {
  record: ThresholdEd25519SessionRecord | null | undefined;
  emailOtpCommittedLane: Ed25519SigningLane | null;
}): string {
  const record = args.record;
  if (!record) return '';
  if (record.source === 'email_otp') {
    return String(args.emailOtpCommittedLane?.walletSessionAuthority.walletSessionJwt || '').trim();
  }
  const authority = parseRouterAbEd25519WalletSessionAuthorityFromRecord(record);
  return authority.ok ? authority.value.auth.walletSessionJwt : '';
}

function resolvePreparedSigningRequestSessionId(args: {
  providedSessionId?: string;
  identity: ResolvedEd25519SigningSessionIdentity;
}): string {
  const provided = String(args.providedSessionId || '').trim();
  const prepared = String(args.identity.thresholdSessionId || '').trim();
  if (provided && provided !== prepared) {
    throw new Error(
      '[SigningEngine][near] transaction sessionId must match prepared Ed25519 identity',
    );
  }
  return prepared;
}

function resolveAdHocThresholdSessionId(args: {
  deps: NearSigningApiDeps;
  commandSubject: NearCommandSubject;
}): string {
  const nearAccountId = args.commandSubject.nearAccount.accountId;
  const thresholdSessionId = String(
    args.deps.resolveThresholdEd25519SessionIdForNearAccount(nearAccountId) || '',
  ).trim();
  if (!thresholdSessionId) {
    throw new Error(
      `[SigningEngine][near] no Ed25519 signing session exists for ${String(nearAccountId)}`,
    );
  }
  return thresholdSessionId;
}

function validateNearEd25519YaoSigningCapability(args: {
  capability: NearEd25519YaoSigningCapability;
  walletId: WalletId;
  thresholdSessionId: string;
}): NearEd25519YaoSigningCapability {
  const sessionState = args.capability.walletSessionState;
  const metadata = args.capability.activeClient.metadata();
  if (
    String(sessionState.thresholdSessionId) !== args.thresholdSessionId ||
    String(sessionState.signingLane.thresholdSessionId) !== args.thresholdSessionId ||
    metadata.scope.wallet_session_id !== args.thresholdSessionId
  ) {
    throw new Error('[SigningEngine][near] active Ed25519 Yao capability session mismatch');
  }
  if (
    metadata.scope.account_id !== String(args.walletId) ||
    metadata.applicationBinding.wallet_id !== String(args.walletId)
  ) {
    throw new Error('[SigningEngine][near] active Ed25519 Yao capability subject mismatch');
  }
  return args.capability;
}

function resolveActiveNearEd25519YaoSigningCapability(args: {
  deps: NearSigningApiDeps;
  commandSubject: NearCommandSubject;
  thresholdSessionId: string;
}): NearEd25519YaoSigningCapability | null {
  const walletId = toWalletId(args.commandSubject.walletSession.walletId);
  const nearAccountId = toAccountId(args.commandSubject.nearAccount.accountId);
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) {
    throw new Error('[SigningEngine][near] Yao capability requires a threshold session id');
  }
  const capability = args.deps.resolveActiveEd25519YaoSigningCapability({
    walletId,
    nearAccountId,
    thresholdSessionId,
  });
  return capability
    ? validateNearEd25519YaoSigningCapability({
        capability,
        walletId,
        thresholdSessionId,
      })
    : null;
}

function requireActiveNearEd25519YaoSigningCapability(args: {
  deps: NearSigningApiDeps;
  commandSubject: NearCommandSubject;
  thresholdSessionId: string;
}): NearEd25519YaoSigningCapability {
  const capability = resolveActiveNearEd25519YaoSigningCapability(args);
  if (capability) return capability;
  throw new Error(
    `[SigningEngine][near] active Ed25519 Yao capability is unavailable for ${args.thresholdSessionId}`,
  );
}

type RehydrateExactNearEd25519YaoCapabilityArgs = {
  deps: NearSigningApiDeps;
  commandSubject: NearCommandSubject;
  thresholdSessionId: string;
  selectedLane: SelectedEd25519Lane;
};

async function rehydrateExactNearEd25519YaoCapability(
  args: RehydrateExactNearEd25519YaoCapabilityArgs,
): Promise<NearEd25519YaoSigningCapability> {
  const walletId = toWalletId(args.commandSubject.walletSession.walletId);
  const nearAccountId = toAccountId(args.commandSubject.nearAccount.accountId);
  const capability = await args.deps.rehydratePasskeyEd25519YaoCapabilityForSigning({
    walletId,
    nearAccountId,
    laneIdentity: args.selectedLane.identity,
  });
  return validateNearEd25519YaoSigningCapability({
    capability,
    walletId,
    thresholdSessionId: args.thresholdSessionId,
  });
}

function nearEd25519YaoCapabilitySource(args: {
  deps: NearSigningApiDeps;
  commandSubject: NearCommandSubject;
  selectedLane: SelectedEd25519Lane;
}): NearEd25519YaoCapabilitySource {
  const thresholdSessionId = String(args.selectedLane.thresholdSessionId);
  const active = resolveActiveNearEd25519YaoSigningCapability({
    deps: args.deps,
    commandSubject: args.commandSubject,
    thresholdSessionId,
  });
  if (active) {
    return {
      kind: 'active_capability',
      capability: active,
    };
  }
  switch (args.selectedLane.auth.kind) {
    case 'email_otp':
      return { kind: 'email_otp_reconnect' };
    case 'passkey':
      return {
        kind: 'capability_rehydration',
        rehydrate: rehydrateExactNearEd25519YaoCapability.bind(undefined, {
          deps: args.deps,
          commandSubject: args.commandSubject,
          thresholdSessionId,
          selectedLane: args.selectedLane,
        }),
      };
  }
  args.selectedLane.auth satisfies never;
  throw new Error('[SigningEngine][near] unsupported Ed25519 Yao lane authority');
}

async function emailOtpNearEd25519LaneRequiresFreshAuth(args: {
  deps: NearSigningApiDeps;
  commandSubject: NearCommandSubject;
  selectedLane: SelectedEd25519Lane;
}): Promise<boolean> {
  switch (args.selectedLane.auth.kind) {
    case 'passkey':
      return false;
    case 'email_otp': {
      const active = resolveActiveNearEd25519YaoSigningCapability({
        deps: args.deps,
        commandSubject: args.commandSubject,
        thresholdSessionId: args.selectedLane.thresholdSessionId,
      });
      if (active) return false;
      const result = await args.deps.recoverEmailOtpEd25519YaoCapabilitySilentlyForSigning({
        walletId: args.selectedLane.identity.signer.account.wallet.walletId,
        nearAccountId: args.selectedLane.identity.signer.account.nearAccountId,
        signerSlot: args.selectedLane.identity.signer.signerSlot,
        thresholdSessionId: args.selectedLane.thresholdSessionId,
      });
      switch (result.kind) {
        case 'recovered':
          return false;
        case 'reauth_required':
          return true;
      }
      result satisfies never;
      throw new Error('[SigningEngine][near] invalid Email OTP Ed25519 recovery result');
    }
  }
  args.selectedLane.auth satisfies never;
  throw new Error('[SigningEngine][near] unsupported Ed25519 Yao lane authority');
}

function createAdHocNearSigningOperationId(
  deps: NearSigningApiDeps,
  kind: 'delegate' | 'nep413',
): SigningOperationId {
  return SigningSessionIds.signingOperation(deps.createSigningSessionId(`near-${kind}-operation`));
}

function buildPreparedNearTransactionExecutionState(args: {
  preparedSigningSession: PreparedNearEd25519TransactionSigningSession;
  resolvedSessionId: string;
  signingSessionCoordinator: SigningSessionCoordinator;
  passkeyEd25519Reconnect: NearEd25519PasskeyReconnect | null;
  emailOtpEd25519Reconnect: NearEd25519EmailOtpReconnect | null;
}): PreparedNearTransactionExecutionState {
  const budget = args.preparedSigningSession.budget;
  return {
    kind: 'prepared_near_transaction_execution',
    sessionId: args.resolvedSessionId,
    signingSessionPlan: args.preparedSigningSession.preparedOperation.signingSessionPlan,
    signingAuthPlan: args.preparedSigningSession.signingAuthPlan,
    signingLane: args.preparedSigningSession.signingLane,
    initialBudgetAdmittedOperation: budget.kind === 'BudgetAdmitted' ? budget.operation : null,
    signingSessionCoordinator: args.signingSessionCoordinator,
    transactionOperation: args.preparedSigningSession.transactionOperation,
    emailOtpCommittedLane: args.preparedSigningSession.emailOtpCommittedLane || null,
    passkeyEd25519Reconnect: args.passkeyEd25519Reconnect,
    emailOtpEd25519Reconnect: args.emailOtpEd25519Reconnect,
  };
}

function nearEd25519SigningGrantAdmissionQueueKey(args: {
  walletId: WalletId | string;
  nearAccountId: AccountId | string;
  prepared: PreparedNearEd25519TransactionSigningSession;
}): ReturnType<typeof buildSigningGrantAdmissionQueueKey> {
  const projectionVersion =
    args.prepared.budget.kind === 'BudgetAdmitted'
      ? args.prepared.budget.operation.budgetAdmission.budgetIdentity.projectionVersion
      : 'projection-unadmitted';
  return buildSigningGrantAdmissionQueueKey({
    walletId: String(args.walletId),
    curve: 'ed25519',
    signingGrantId: String(args.prepared.signingLane.signingGrantId),
    projectionVersion,
    authorityKey: signingGrantAdmissionAuthorityKeyFromAuth(args.prepared.signingLane.auth),
    targetKey: `near:${String(args.nearAccountId)}`,
  });
}

function buildNearPasskeyEd25519Reconnect(args: {
  deps: NearSigningApiDeps;
  commandSubject: NearCommandSubject;
  ctx: ReturnType<NearSigningApiDeps['getSignerWorkerContext']>;
  thresholdSessionRecord: ThresholdEd25519SessionRecord | null;
  operationId: SigningOperationId;
}): NearEd25519PasskeyReconnect | undefined {
  if (
    !args.thresholdSessionRecord ||
    typeof args.deps.refreshPasskeyEd25519CapabilityForSigning !== 'function'
  ) {
    return undefined;
  }
  const thresholdSessionRecord = args.thresholdSessionRecord;
  return {
    prepare: async ({ requiredSignatureUses }: { requiredSignatureUses: number }) => {
      const sessionBudgetUses = resolveTransactionStepUpSessionUses({
        operationId: args.operationId,
        requiredSignatureUses,
      });
      const rpIdRaw = String(args.ctx.touchIdPrompt.getRpId() || '').trim();
      const thresholdSessionId = String(thresholdSessionRecord.thresholdSessionId || '').trim();
      const signingGrantId = String(thresholdSessionRecord.signingGrantId || '').trim();
      if (!rpIdRaw) {
        throw new Error('[SigningEngine] missing rpId for passkey Ed25519 reauth');
      }
      const rpId = requirePasskeyEd25519ReauthRpId(rpIdRaw);
      const passkeyCredentialIdB64u = String(
        thresholdSessionRecord.passkeyCredentialIdB64u || '',
      ).trim();
      if (!thresholdSessionId || !signingGrantId) {
        throw new Error(
          '[SigningEngine] passkey Ed25519 budget refresh requires exact lifecycle identity',
        );
      }
      const authority = buildPasskeyWalletAuthAuthority({
        walletId: thresholdSessionRecord.walletId,
        rpId,
        credentialIdB64u: passkeyCredentialIdB64u,
      });
      const { policy, sessionPolicyDigest32 } = await buildPasskeyEd25519SessionPolicy({
        nearAccountId: args.commandSubject.nearAccount.accountId,
        nearEd25519SigningKeyId: String(thresholdSessionRecord.nearEd25519SigningKeyId),
        authority,
        relayerKeyId: thresholdSessionRecord.relayerKeyId,
        ...(thresholdSessionRecord.runtimePolicyScope
          ? { runtimePolicyScope: thresholdSessionRecord.runtimePolicyScope }
          : {}),
        routerAbNormalSigning: thresholdSessionRecord.routerAbNormalSigning,
        participantIds: thresholdSessionRecord.participantIds,
        thresholdSessionId,
        signingGrantId,
        remainingUses: sessionBudgetUses,
      });
      return {
        sessionId: policy.thresholdSessionId,
        signingGrantId: policy.signingGrantId,
        sessionPolicyDigest32,
      };
    },
    reconnect: async ({ authorization, requiredSignatureUses }) => {
      const sessionBudgetUses = resolveTransactionStepUpSessionUses({
        operationId: args.operationId,
        requiredSignatureUses,
      });
      const refreshed = await args.deps.refreshPasskeyEd25519CapabilityForSigning!({
        record: thresholdSessionRecord,
        laneIdentity: buildExactPasskeyEd25519RefreshLaneIdentity({
          nearAccountId: args.commandSubject.nearAccount.accountId,
          record: thresholdSessionRecord,
          signerSlot: thresholdSessionRecord.signerSlot,
          sessionId: authorization.plannedPasskeyReconnect.sessionId,
          signingGrantId: authorization.plannedPasskeyReconnect.signingGrantId,
        }),
        policySecretSource: buildThresholdEd25519WebAuthnPrfSecretSource({
          credential: authorization.credential,
          rpId: thresholdSessionRecord.rpId,
        }),
        operationUsesNeeded: sessionBudgetUses,
      });
      return {
        sessionId: refreshed.sessionId,
        activeClient: refreshed.activeClient,
        sessionState: refreshed.walletSessionState,
      };
    },
  };
}

function buildNearEmailOtpEd25519Reconnect(args: {
  deps: NearSigningApiDeps;
  commandSubject: NearCommandSubject;
  committedLane: Ed25519SigningLane | null;
  thresholdSessionRecord: ThresholdEd25519SessionRecord | null;
  operationId: SigningOperationId;
  onEvent: SignTransactionWithActionsInput['onEvent'];
}): NearEd25519EmailOtpReconnect | undefined {
  if (
    !args.committedLane ||
    !args.thresholdSessionRecord ||
    typeof args.deps.requestEmailOtpEd25519SigningChallenge !== 'function' ||
    typeof args.deps.recoverEmailOtpEd25519CapabilityForSigning !== 'function'
  ) {
    return undefined;
  }
  const committedLane = args.committedLane;
  const thresholdSessionRecord = args.thresholdSessionRecord;
  const requestChallenge = async (): Promise<EmailOtpTransactionSigningChallenge> => {
    const challenge = await args.deps.requestEmailOtpEd25519SigningChallenge!({
      walletSession: args.commandSubject.walletSession,
      nearAccountId: args.commandSubject.nearAccount.accountId,
      authLane: committedLane.authLane,
    });
    emitNearSigningEvent(args.onEvent, args.commandSubject.nearAccount.accountId, {
      phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_INPUT_REQUIRED,
      status: 'waiting_for_user',
      interaction: { kind: 'otp_input', overlay: 'show' },
      data: {
        emailHint: challenge.emailHint,
        demoOtpCode: demoEmailOtpCodeFromDelivery(challenge.delivery),
      },
    });
    return challenge;
  };
  return {
    prepare: requestChallenge,
    resend: requestChallenge,
    reconnect: async ({ authorization, requiredSignatureUses }) => {
      const sessionBudgetUses = resolveTransactionStepUpSessionUses({
        operationId: args.operationId,
        requiredSignatureUses,
      });
      const refreshed = await args.deps.recoverEmailOtpEd25519CapabilityForSigning!({
        nearAccountId: args.commandSubject.nearAccount.accountId,
        record: thresholdSessionRecord,
        committedLane,
        challengeId: authorization.challengeId,
        otpCode: authorization.otpCode,
        remainingUses: sessionBudgetUses,
      });
      return {
        sessionId: refreshed.sessionId,
        activeClient: refreshed.activeClient,
        sessionState: refreshed.walletSessionState,
      };
    },
  };
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

function authMethodForThresholdEd25519Record(
  record: ThresholdEd25519SessionRecord,
): 'email_otp' | 'passkey' {
  return record.source === 'email_otp' ? 'email_otp' : 'passkey';
}

function thresholdEd25519RecordMatchesSelectedLane(args: {
  record: ThresholdEd25519SessionRecord;
  selectedLane: SelectedEd25519Lane;
  walletId: WalletId | string;
}): boolean {
  const identity = args.selectedLane.identity;
  const signer = identity.signer;
  const signerWalletId = signer.account.wallet.walletId;
  return (
    String(args.walletId || '').trim() === String(signerWalletId || '').trim() &&
    String(args.record.walletId || '').trim() === String(signerWalletId || '').trim() &&
    String(args.record.nearAccountId || '').trim() ===
      String(signer.account.nearAccountId || '').trim() &&
    String(args.record.nearEd25519SigningKeyId || '').trim() ===
      String(signer.nearEd25519SigningKeyId || '').trim() &&
    Number(args.record.signerSlot) === Number(signer.signerSlot) &&
    authMethodForThresholdEd25519Record(args.record) === signingLaneAuthMethod(identity.auth) &&
    String(args.record.thresholdSessionId || '').trim() ===
      String(identity.thresholdSessionId || '').trim() &&
    String(args.record.signingGrantId || '').trim() === String(identity.signingGrantId || '').trim()
  );
}

function selectNearEd25519TransactionCandidate(args: {
  availableLanes: AvailableSigningLanes | null;
  authSelectionPolicy: TransactionAuthSelectionPolicy | null;
  commandSubject: NearCommandSubject;
  signerSlot: number | undefined;
  operationUsesNeeded: number;
}): NearEd25519SelectedTransactionLane | null {
  const authSelectionPolicy = args.authSelectionPolicy || null;
  if (!authSelectionPolicy) return null;

  const intentState = receiveTransactionIntent(
    nearEd25519TransactionSigningIntent({
      commandSubject: args.commandSubject,
      signerSlot: args.signerSlot,
      authSelectionPolicy,
      operationUsesNeeded: args.operationUsesNeeded,
    }),
  );
  const availableLanesState = recordAvailableSigningLanesRead(intentState, {
    availableLanes: args.availableLanes,
  });
  const selectionState = selectTransactionLaneFromAvailableLanes(availableLanesState);
  if (selectionState.tag === 'LaneSelected') {
    if (
      selectionState.lane.curve !== 'ed25519' ||
      selectionState.availableLane.curve !== 'ed25519'
    ) {
      throw new Error('[SigningEngine][near] Ed25519 selector returned a non-Ed25519 lane');
    }
    return selectionState as NearEd25519SelectedTransactionLane;
  }
  if (selectionState.failure.kind === 'no_candidate') return null;
  throw new Error(
    `[SigningEngine][near] Ed25519 transaction lane selection failed: ${selectionState.failure.kind}`,
  );
}

function nearEd25519TransactionSigningIntent(args: {
  commandSubject: NearCommandSubject;
  signerSlot: number | undefined;
  authSelectionPolicy: TransactionAuthSelectionPolicy;
  operationUsesNeeded: number;
}): NearEd25519TransactionSigningIntent {
  return {
    walletId: toWalletId(args.commandSubject.walletSession.walletId),
    curve: 'ed25519',
    chain: 'near',
    signerSelection: nearEd25519TransactionSignerSelection({
      nearAccountId: args.commandSubject.nearAccount.accountId,
      signerSlot: args.signerSlot,
    }),
    authSelectionPolicy: args.authSelectionPolicy,
    operationUsesNeeded: args.operationUsesNeeded,
  };
}

function nearEd25519TransactionSignerSelection(args: {
  nearAccountId: AccountId;
  signerSlot: number | undefined;
}): NearEd25519TransactionSignerSelection {
  if (args.signerSlot === undefined) {
    return {
      kind: 'near_account',
      nearAccountId: args.nearAccountId,
    };
  }
  const signerSlot = parseSignerSlot(args.signerSlot);
  if (signerSlot === null) {
    throw new Error('[SigningEngine][near] signerSlot must be a positive safe integer');
  }
  return {
    kind: 'signer_slot',
    nearAccountId: args.nearAccountId,
    signerSlot,
  };
}

function selectSelectedEd25519LaneFromAvailableLanes(args: {
  commandSubject: NearCommandSubject;
  availableLanes: AvailableSigningLanes | null;
  signerSlot: number | undefined;
  operationUsesNeeded: number;
}): NearEd25519SelectedTransactionLane | null {
  return selectNearEd25519TransactionCandidate({
    availableLanes: args.availableLanes,
    authSelectionPolicy: { kind: 'any' },
    commandSubject: args.commandSubject,
    signerSlot: args.signerSlot,
    operationUsesNeeded: args.operationUsesNeeded,
  });
}

function assertNearEd25519SelectedLaneMatchesRecord(args: {
  selectedLane: SelectedEd25519Lane | null;
  record: ThresholdEd25519SessionRecord | null;
  walletId: WalletId | string;
  nearAccountId: AccountId;
}): void {
  if (!args.selectedLane || !args.record) return;
  if (
    thresholdEd25519RecordMatchesSelectedLane({
      record: args.record,
      selectedLane: args.selectedLane,
      walletId: args.walletId,
    })
  ) {
    return;
  }
  throw new Error(
    `[SigningEngine][near] available Ed25519 lane identity does not match runtime session record for ${String(args.nearAccountId)}`,
  );
}

async function readNearEd25519RuntimeRecordForSelectedLane(args: {
  deps: NearSigningApiDeps;
  selectedLane: SelectedEd25519Lane | null;
}): Promise<ThresholdEd25519SessionRecord | null> {
  if (!args.selectedLane) return null;
  const record = getStoredThresholdEd25519SessionRecordByThresholdSessionId(
    args.selectedLane.thresholdSessionId,
  );
  if (
    record &&
    thresholdEd25519RecordMatchesSelectedLane({
      record,
      selectedLane: args.selectedLane,
      walletId: args.selectedLane.identity.signer.account.wallet.walletId,
    })
  ) {
    return record;
  }
  return await args.deps.readPersistedEd25519SessionRecordForSigning({
    walletId: args.selectedLane.identity.signer.account.wallet.walletId,
    laneIdentity: args.selectedLane.identity,
  });
}

function publishNearEd25519RuntimeIdentityForRecord(
  record: ThresholdEd25519SessionRecord | null,
): void {
  const thresholdSessionId = String(record?.thresholdSessionId || '').trim();
  const signingGrantId = String(record?.signingGrantId || '').trim();
  if (!record || !thresholdSessionId || !signingGrantId) return;
  publishResolvedIdentity({
    walletId: String(record.walletId),
    authMethod: record.source === 'email_otp' ? 'email_otp' : 'passkey',
    curve: 'ed25519',
    chain: 'near',
    signingGrantId,
    thresholdSessionId,
    updatedAtMs: record.updatedAtMs,
  });
}

async function readNearEd25519AvailableSigningLanes(args: {
  deps: NearSigningApiDeps;
  commandSubject: NearCommandSubject;
  authMethod: 'email_otp' | 'passkey' | null;
}): Promise<AvailableSigningLanes | null> {
  const nearAccountId = args.commandSubject.nearAccount.accountId;
  const walletId = args.commandSubject.walletSession.walletId;
  if (typeof args.deps.readAvailableSigningLanesForSigning !== 'function') {
    throw new Error(
      '[SigningEngine][near] transaction signing requires available signing lanes reader',
    );
  }
  return await args.deps
    .readAvailableSigningLanesForSigning({
      walletId,
      curve: 'ed25519',
      ...(args.authMethod ? { authMethod: args.authMethod } : {}),
    })
    .catch((error) => {
      console.warn('[SigningEngine][near] available signing lanes read failed', {
        nearAccountId,
        error: error instanceof Error ? error.message : String(error || 'unknown error'),
      });
      return null;
    });
}

async function prepareNearEd25519TransactionOperation(args: {
  deps: NearSigningApiDeps;
  commandSubject: NearCommandSubject;
  signingSessionCoordinator: SigningSessionCoordinator;
  availableLanes?: AvailableSigningLanes | null;
  selectedLane: NearEd25519SelectedTransactionLane;
  operationUsesNeeded: number;
}): Promise<NearEd25519TransactionOperationPrepareResult> {
  const nearAccountId = args.commandSubject.nearAccount.accountId;
  const walletId = args.commandSubject.walletSession.walletId;
  const operationNowMs = Date.now();
  const operationUsesNeeded = Math.max(1, Math.floor(Number(args.operationUsesNeeded) || 1));
  const selectedSessionLane = args.selectedLane.lane;
  const recordForLifecycle = await readNearEd25519RuntimeRecordForSelectedLane({
    deps: args.deps,
    selectedLane: selectedSessionLane,
  });
  publishNearEd25519RuntimeIdentityForRecord(recordForLifecycle);
  assertNearEd25519SelectedLaneMatchesRecord({
    selectedLane: selectedSessionLane,
    record: recordForLifecycle,
    walletId,
    nearAccountId,
  });
  if (!selectedSessionLane || !recordForLifecycle) {
    throw new Error('[SigningEngine][near] signing session is not ready: missing_session');
  }
  const lane = buildNearTransactionSigningLaneForSelectedLane({
    commandSubject: args.commandSubject,
    record: recordForLifecycle,
    selectedLane: selectedSessionLane,
  });
  assertSigningLaneMatchesSelectedTransactionLane({
    signingLane: lane,
    transactionLane: args.selectedLane.lane,
  });
  const readiness = await resolveNearTransactionPlannerReadiness({
    preConfirmDeps: {
      getWarmThresholdEd25519SessionStatusForSession:
        args.deps.getWarmThresholdEd25519SessionStatusForSession,
      signingSessionCoordinator: args.signingSessionCoordinator,
      hasUiConfirm: () => Boolean(args.deps.getSignerWorkerContext().touchConfirm),
    },
    nearAccount: args.commandSubject.nearAccount,
    record: recordForLifecycle,
    operationNowMs,
    requiredSignatureUses: operationUsesNeeded,
  });
  if (recordForLifecycle.source === 'email_otp' && readiness.readiness.status !== 'ready') {
    console.warn('[SigningEngine][near][email-otp] Ed25519 pre-confirm readiness is not ready', {
      nearAccountId,
      readiness: readiness.readiness.status,
      thresholdSessionId: recordForLifecycle.thresholdSessionId,
      signingGrantId: recordForLifecycle.signingGrantId,
      retention: recordForLifecycle.emailOtpAuthContext
        ? emailOtpAuthContextRetention(recordForLifecycle.emailOtpAuthContext)
        : null,
      remainingUses: readiness.remainingUses,
      expiresAtMs: readiness.expiresAtMs,
      requiredSignatureUses: operationUsesNeeded,
    });
  }
  emitSigningBoundaryTrace(
    'near',
    createSigningBoundaryTraceEvent({
      event: 'pre_confirm_readiness_checked',
      lane,
      readinessStatus: readiness.readiness.status,
      phase: 'pre_confirm',
    }),
  );
  const transactionReadinessState = classifyTransactionReadiness(
    args.selectedLane,
    transactionReadinessFromPlannerInput({
      readiness: readiness.readiness,
      expiresAtMs: readiness.expiresAtMs,
      remainingUses: readiness.remainingUses,
      usesNeeded: operationUsesNeeded,
    }),
  );
  const transactionOperation = prepareTransactionOperationFromReadiness(transactionReadinessState);
  const identity = requireResolvedNearEd25519SigningLane(lane);
  const walletSessionStateForBudget = resolveRouterAbEd25519WalletSessionStateForOperation({
    record: recordForLifecycle,
    nowMs: operationNowMs,
  });
  const trustedStatusAuth = walletSessionStateForBudget
    ? trustedBudgetStatusAuthFromEd25519WalletSessionState(walletSessionStateForBudget)
    : null;
  const readinessInput = {
    readiness: readiness.readiness,
    expiresAtMs: readiness.expiresAtMs,
    remainingUses: readiness.remainingUses,
    usesNeeded: operationUsesNeeded,
    ...(trustedStatusAuth ? { trustedStatusAuth } : {}),
  };
  return {
    lane,
    transactionLane: args.selectedLane.lane,
    transactionIntent: args.selectedLane.intent,
    readiness: readinessInput,
    availableLanesGeneration: args.availableLanes?.generation || 0,
    metadata: {
      thresholdSessionRecord: recordForLifecycle,
      transactionLane: args.selectedLane.lane,
      transactionOperation,
      transactionReadinessState,
      identity,
      availableLanesGeneration: args.availableLanes?.generation || 0,
      readiness: readinessInput,
    },
  };
}

async function prepareNearEd25519TransactionSigningSession(args: {
  deps: NearSigningApiDeps;
  input: SignTransactionWithActionsInput;
  commandSubject: NearCommandSubject;
  signingSessionCoordinator: SigningSessionCoordinator;
  operationId: SigningOperationId;
  forceFreshAuth?: boolean;
}): Promise<PreparedNearEd25519TransactionSigningSession> {
  const nearAccountId = args.commandSubject.nearAccount.accountId;
  const operationUsesNeeded = requiredNearTransactionSignatureUses(args.input.transaction);
  const availableLanes = await readNearEd25519AvailableSigningLanes({
    deps: args.deps,
    commandSubject: args.commandSubject,
    authMethod: null,
  });
  const selectedLane = selectSelectedEd25519LaneFromAvailableLanes({
    commandSubject: args.commandSubject,
    availableLanes,
    signerSlot: args.input.signerSlot,
    operationUsesNeeded,
  });
  if (!selectedLane) {
    console.warn(
      `[SigningEngine][near][ed25519] exact transaction lane selection failed ${JSON.stringify({
        nearAccountId,
        signerSlot: args.input.signerSlot ?? null,
        requiredSignatureUses: operationUsesNeeded,
        availableLanes: summarizeNearEd25519AvailableLanes(availableLanes),
      })}`,
    );
    throw new Error(
      '[SigningEngine][near] Ed25519 transaction signing requires an exact selected lane',
    );
  }
  const initialAuthSelectionPolicy: TransactionAuthSelectionPolicy = {
    kind: 'account_class',
    authMethod: signingLaneAuthMethod(selectedLane.lane.auth),
  };
  const forceFreshAuth =
    args.forceFreshAuth === true
      ? true
      : await emailOtpNearEd25519LaneRequiresFreshAuth({
          deps: args.deps,
          commandSubject: args.commandSubject,
          selectedLane: selectedLane.lane,
        });

  const preparedTransaction = await prepareTransactionSigningOperation({
    intent: nearEd25519TransactionSigningIntent({
      commandSubject: args.commandSubject,
      signerSlot: args.input.signerSlot,
      authSelectionPolicy: initialAuthSelectionPolicy,
      operationUsesNeeded,
    }),
    coordinator: args.signingSessionCoordinator,
    forceFreshAuth,
    sensitiveOperationPolicy:
      args.input.sensitivePolicy || SENSITIVE_OPERATION_POLICIES.inheritSessionPolicy,
    prepareBudgetIdentity: true,
    onPlannerTrace: (event) => emitSigningPlannerDecisionTrace('near', event),
    lifecycleAdapter: {
      prepare: async () => {
        const lifecycle = await prepareNearEd25519TransactionOperation({
          deps: args.deps,
          commandSubject: args.commandSubject,
          signingSessionCoordinator: args.signingSessionCoordinator,
          availableLanes,
          selectedLane,
          operationUsesNeeded,
        });
        return {
          ...lifecycle,
          metadata: lifecycle.metadata,
        };
      },
    },
  });
  const preparedOperation = preparedTransaction.thresholdOperation as PreparedNearEd25519Operation;
  const transactionOperation = preparedTransaction.transactionOperation;
  const thresholdSessionRecord = preparedOperation.metadata.thresholdSessionRecord;
  const signingLane = preparedOperation.lane;
  const transactionLane = transactionOperation.lane;
  const identity = preparedOperation.metadata.identity;

  const { signingAuthPlan } = await resolveNearTransactionWalletAuth({
    commandSubject: args.commandSubject,
    preparedOperation,
  });
  const emailOtpCommittedLane =
    thresholdSessionRecord?.source === 'email_otp'
      ? resolveEd25519SigningLane({
          lane: transactionLane,
          record: thresholdSessionRecord,
        })
      : null;
  const budget = preparedTransaction.budget;
  return {
    thresholdSessionRecord,
    signingAuthPlan,
    signingLane,
    transactionLane,
    identity,
    resolvedSessionId: resolvePreparedSigningRequestSessionId({
      providedSessionId: args.input.sessionId,
      identity,
    }),
    availableLanesGeneration: preparedOperation.availableLanesGeneration,
    preparedOperation,
    transactionOperation,
    budget,
    ...(emailOtpCommittedLane ? { emailOtpCommittedLane } : {}),
  };
}

export async function signTransactionWithActions(
  deps: NearSigningApiDeps,
  args: SignTransactionWithActionsInput,
  attempt: {
    forceFreshAuth?: boolean;
    operationId?: SigningOperationId;
    retryingFreshAuth?: boolean;
    signingSessionCoordinator?: SigningSessionCoordinator;
  } = {},
): Promise<SignTransactionResult> {
  const nearAccount = args.commandSubject.nearAccount;
  const nearAccountId = toAccountId(nearAccount.accountId);
  const publicOptions: NearTransactionPublicSigningOptions = {
    signerSlot: args.signerSlot,
    confirmationConfigOverride: args.confirmationConfigOverride,
    title: args.title,
    body: args.body,
    onEvent: args.onEvent,
  };
  let operationId = attempt.operationId;
  const ensureOperationId = (): SigningOperationId => {
    operationId = operationId || createNearTransactionSigningOperationId();
    return operationId;
  };
  const confirmationOperationId = ensureOperationId();
  const signingSessionCoordinator =
    attempt.signingSessionCoordinator || deps.signingSessionCoordinator;
  const preparedSigningSession = await prepareNearEd25519TransactionSigningSession({
    deps,
    input: args,
    commandSubject: args.commandSubject,
    signingSessionCoordinator,
    operationId: confirmationOperationId,
    forceFreshAuth: attempt.forceFreshAuth === true,
  });
  const thresholdSessionRecord = preparedSigningSession.thresholdSessionRecord;
  const signingAuthPlan = preparedSigningSession.signingAuthPlan;
  const signingLane = preparedSigningSession.signingLane;
  const transactionLane = preparedSigningSession.transactionLane;
  const resolvedSessionId = preparedSigningSession.resolvedSessionId;
  assertSigningLaneMatchesSelectedTransactionLane({
    signingLane,
    transactionLane,
  });
  try {
    return await withThresholdEd25519CommitQueue({
      deps,
      nearAccountId,
      thresholdSessionId: resolvedSessionId,
      task: async () => {
        const ctx = deps.getSignerWorkerContext();
        const passkeyEd25519Reconnect = buildNearPasskeyEd25519Reconnect({
          deps,
          commandSubject: args.commandSubject,
          ctx,
          thresholdSessionRecord,
          operationId: confirmationOperationId,
        });
        const emailOtpEd25519Reconnect = buildNearEmailOtpEd25519Reconnect({
          deps,
          commandSubject: args.commandSubject,
          committedLane: preparedSigningSession.emailOtpCommittedLane || null,
          thresholdSessionRecord,
          operationId: confirmationOperationId,
          onEvent: publicOptions.onEvent,
        });
        const executionState = buildPreparedNearTransactionExecutionState({
          preparedSigningSession,
          resolvedSessionId,
          signingSessionCoordinator,
          passkeyEd25519Reconnect: passkeyEd25519Reconnect || null,
          emailOtpEd25519Reconnect: emailOtpEd25519Reconnect || null,
        });
        const walletSessionJwt = walletSessionJwtForPreparedNearExecution({
          record: thresholdSessionRecord,
          emailOtpCommittedLane: executionState.emailOtpCommittedLane,
        });
        if (!walletSessionJwt) {
          throw new Error(
            '[SigningEngine][near] prepared Ed25519 session is missing Wallet Session bearer JWT',
          );
        }
        const ed25519SigningBoundary = {
          sessionId: executionState.sessionId,
          walletSessionJwt,
          signingSessionPlan: executionState.signingSessionPlan,
          signingAuthPlan: executionState.signingAuthPlan,
          signingLane: executionState.signingLane,
          initialBudgetAdmittedOperation: executionState.initialBudgetAdmittedOperation,
        };
        const yaoCapabilitySource = nearEd25519YaoCapabilitySource({
          deps,
          commandSubject: args.commandSubject,
          selectedLane: transactionLane,
        });
        const payload: NearTransactionWithActionsPayload = {
          ctx,
          commandSubject: args.commandSubject,
          nearAccount,
          transaction: args.transaction,
          rpcCall: args.rpcCall,
          signerSlot: publicOptions.signerSlot,
          confirmationConfigOverride: publicOptions.confirmationConfigOverride,
          title: publicOptions.title,
          body: publicOptions.body,
          onEvent: publicOptions.onEvent,
          signingOperationId: confirmationOperationId,
          signingSessionCoordinator: executionState.signingSessionCoordinator,
          transactionOperation: executionState.transactionOperation,
          ed25519SigningBoundary,
          yaoCapabilitySource,
          ...(executionState.passkeyEd25519Reconnect
            ? { passkeyEd25519Reconnect: executionState.passkeyEd25519Reconnect }
            : {}),
          ...(executionState.emailOtpEd25519Reconnect
            ? { emailOtpEd25519Reconnect: executionState.emailOtpEd25519Reconnect }
            : {}),
        };
        const result = (await signNearWithUiConfirm({
          chain: 'near',
          kind: 'transactionWithActions',
          payload,
        })) as unknown as SignTransactionResult;
        return result;
      },
    });
  } catch (error: unknown) {
    const alreadyAttemptedFreshAuth =
      signingAuthPlan.kind === SigningAuthPlanKind.PasskeyReauth ||
      signingAuthPlan.kind === SigningAuthPlanKind.EmailOtpReauth;
    const admissionDecision = decideSigningGrantAdmissionError(error);
    if (
      !attempt.retryingFreshAuth &&
      !alreadyAttemptedFreshAuth &&
      thresholdSessionRecord &&
      (isSigningSessionAuthUnavailableError(error) || admissionDecision)
    ) {
      const nextOperationId = operationId || createNearTransactionSigningOperationId();
      if (admissionDecision?.kind === 'wait_and_retry_admission') {
        await waitForSigningGrantAdmissionRetry(admissionDecision.retryAfterMs);
        return await signTransactionWithActions(deps, args, {
          forceFreshAuth: false,
          operationId: nextOperationId,
          retryingFreshAuth: attempt.retryingFreshAuth,
          signingSessionCoordinator,
        });
      }
      const isEmailOtpSession = thresholdSessionRecord.source === 'email_otp';
      const reason = admissionDecision
        ? admissionDecision.reason === 'stale_projection'
          ? 'wallet_signing_budget_stale_projection'
          : 'wallet_signing_budget_exhausted'
        : 'threshold_session_expired';
      emitNearSigningEvent(publicOptions.onEvent, nearAccountId, {
        phase: isEmailOtpSession
          ? SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_CHALLENGE_STARTED
          : SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
        status: 'running',
        message: isEmailOtpSession
          ? 'Signing session needs reauthorization; requesting Email OTP'
          : 'Signing session needs reauthorization; requesting passkey',
        interaction: { kind: 'none', overlay: 'none' },
        data: {
          chain: 'near',
          reason,
        },
      });
      if (admissionDecision?.kind === 'request_fresh_step_up') {
        const queueKey = nearEd25519SigningGrantAdmissionQueueKey({
          walletId: args.commandSubject.walletSession.walletId,
          nearAccountId,
          prepared: preparedSigningSession,
        });
        return await signingSessionCoordinator.runSigningGrantAdmissionRetry({
          queueKey,
          refresh: async () =>
            await signTransactionWithActions(deps, args, {
              forceFreshAuth: true,
              operationId: nextOperationId,
              retryingFreshAuth: true,
              signingSessionCoordinator,
            }),
          retryAfterRefresh: async () =>
            await signTransactionWithActions(deps, args, {
              forceFreshAuth: false,
              operationId: nextOperationId,
              retryingFreshAuth: attempt.retryingFreshAuth,
              signingSessionCoordinator,
            }),
        });
      }
      return await signTransactionWithActions(deps, args, {
        forceFreshAuth: true,
        operationId: nextOperationId,
        retryingFreshAuth: true,
        signingSessionCoordinator,
      });
    }
    throw error;
  }
}

export async function signDelegateAction(
  deps: NearSigningApiDeps,
  args: SignDelegateActionInput,
): Promise<SignDelegateActionResult> {
  const nearAccount = args.commandSubject.nearAccount;
  const nearAccountId = toAccountId(nearAccount.accountId);
  const normalizedRpcCall: RpcCallPayload = {
    nearRpcUrl: args.rpcCall.nearRpcUrl || deps.nearRpcUrl,
    nearAccountId,
  };

  try {
    const thresholdSessionId = resolveAdHocThresholdSessionId({
      deps,
      commandSubject: args.commandSubject,
    });
    const operationId = createAdHocNearSigningOperationId(deps, 'delegate');
    return await withThresholdEd25519CommitQueue({
      deps,
      nearAccountId,
      thresholdSessionId,
      task: async () => {
        const ctx = deps.getSignerWorkerContext();
        const yaoCapability = requireActiveNearEd25519YaoSigningCapability({
          deps,
          commandSubject: args.commandSubject,
          thresholdSessionId,
        });
        return (await signNearWithUiConfirm({
          chain: 'near',
          kind: 'delegateAction',
          payload: {
            ctx,
            commandSubject: args.commandSubject,
            nearAccount,
            delegate: args.delegate,
            rpcCall: normalizedRpcCall,
            signingSessionCoordinator: deps.signingSessionCoordinator,
            signerSlot: args.signerSlot,
            confirmationConfigOverride: args.confirmationConfigOverride,
            title: args.title,
            body: args.body,
            onEvent: args.onEvent,
            operationId,
            ...yaoCapability,
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
    const nearAccount = payload.commandSubject.nearAccount;
    const nearAccountId = toAccountId(nearAccount.accountId);
    const thresholdSessionId = resolveAdHocThresholdSessionId({
      deps,
      commandSubject: payload.commandSubject,
    });
    const operationId = createAdHocNearSigningOperationId(deps, 'nep413');
    const result = await withThresholdEd25519CommitQueue({
      deps,
      nearAccountId,
      thresholdSessionId,
      task: async () => {
        const ctx = deps.getSignerWorkerContext();
        const yaoCapability = requireActiveNearEd25519YaoSigningCapability({
          deps,
          commandSubject: payload.commandSubject,
          thresholdSessionId,
        });
        return (await signNearWithUiConfirm({
          chain: 'near',
          kind: 'nep413',
          payload: {
            ctx,
            commandSubject: payload.commandSubject,
            nearAccount,
            signingSessionCoordinator: deps.signingSessionCoordinator,
            ...yaoCapability,
            payload: {
              message: payload.message,
              recipient: payload.recipient,
              nonce: payload.nonce,
              state: payload.state,
              accountId: nearAccountId,
              signerSlot: payload.signerSlot,
              title: payload.title,
              body: payload.body,
              confirmationConfigOverride: payload.confirmationConfigOverride,
              operationId,
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
      error: message,
    };
  }
}
