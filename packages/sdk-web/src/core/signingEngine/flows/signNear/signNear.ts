import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { parseWebAuthnRpId, type WebAuthnRpId } from '@shared/utils/domainIds';
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
import type { NearTransactionWithActionsPayload } from '../../interfaces/near';
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
  buildOperationUsableThresholdEd25519SessionRecord,
  commitCurrentThresholdEd25519Session,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  requireCommittedThresholdEd25519Session,
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
import {
  exactEd25519SigningLaneIdentityFromSelectedLane,
  exactSigningLaneIdentityKey,
} from '../../session/identity/exactSigningLaneIdentity';
import type {
  AvailableSigningLanes,
  AvailableEd25519SigningLane,
} from '../../session/availability/availableSigningLanes';
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
  isSigningSessionBudgetAdmissionBlockedError,
  SigningSessionCoordinator,
  type SigningSessionReadiness,
} from '../../session/SigningSessionCoordinator';
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
  resolveRouterAbEd25519WalletSessionStateFromRecord,
  type ResolvedRouterAbEd25519WalletSessionState,
} from './shared/routerAbEd25519WalletSessionState';
import {
  buildEd25519SigningLane,
  type Ed25519SigningLane,
} from '../../session/emailOtp/ed25519Warmup';
import { buildEmailOtpEd25519SigningSessionAuthority } from '../../session/emailOtp/ed25519SigningSessionAuthority';
import {
  classifyRouterAbEd25519PersistedSigningRecord,
  parseRouterAbEd25519WalletSessionAuthorityFromRecord,
  routerAbEd25519WorkerMaterialIdentityFromPersistedState,
} from '../../session/routerAbSigningWalletSession';
import { resolveEmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import {
  isEd25519MaterialUnsealAuthorizationRequiredError,
  throwEd25519MaterialRestoreRequired,
} from './shared/ed25519MaterialRestore';
import { hasRouterAbEd25519SigningAuth } from './shared/routerAbWalletSessionCredential';
import {
  receiveTransactionIntent,
  recordAvailableSigningLanesRead,
  selectTransactionLaneFromAvailableLanes,
  type NearEd25519AvailableLane,
  type NearEd25519TransactionMaterial,
  type NearEd25519TransactionReadyAvailableLane,
  type NearEd25519TransactionReadyLane,
  type TransactionLaneSelectedState,
} from '../../session/identity/selectLane';
import {
  classifyTransactionReadiness,
  prepareTransactionOperationFromReadiness,
  prepareTransactionSigningOperation,
  recordExactRestoreAttempt,
  replacePreparedTransactionLane,
  type BudgetAdmittedOperation,
  type NearEd25519TransactionSigningIntent,
  type PreparedTransactionBudgetState,
  type PreparedTransactionOperation,
  type TransactionAuthSelectionPolicy,
  type TransactionSigningIntent,
  type TransactionReadiness,
  type TransactionReadinessClassifiedState,
} from '../../session/operationState/transactionState';
import type {
  NearEd25519EmailOtpStepUpAuthorization,
  NearEd25519PasskeyStepUpAuthorization,
} from './stepUpAuthorization';
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

function resolveMaterialRestoreSessionUses(args: {
  record: ThresholdEd25519SessionRecord;
  requiredSignatureUses: number;
}): number {
  const requiredSignatureUses = Math.max(1, Math.floor(Number(args.requiredSignatureUses) || 1));
  const recordRemainingUses = Math.max(0, Math.floor(Number(args.record.remainingUses) || 0));
  return Math.max(requiredSignatureUses, recordRemainingUses);
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

type NearTransactionConfirmedSigningDeps = {
  requestEmailOtpTransactionSigningChallenge?: NearSigningApiDeps['requestEmailOtpTransactionSigningChallenge'];
  resolveEmailOtpEd25519SigningSessionAuthority?: NearSigningApiDeps['resolveEmailOtpEd25519SigningSessionAuthority'];
  loginWithEmailOtpEd25519CapabilityForSigning?: NearSigningApiDeps['loginWithEmailOtpEd25519CapabilityForSigning'];
};

type NearEd25519EmailOtpSigning = {
  committedLane: Ed25519SigningLane;
  prepare: (args: { requiredSignatureUses: number }) => Promise<{
    challengeId: string;
    emailHint?: string;
  }>;
  resend?: (args: { requiredSignatureUses: number }) => Promise<{
    challengeId: string;
    emailHint?: string;
  }>;
  complete: (
    authorization: NearEd25519EmailOtpStepUpAuthorization,
  ) => Promise<{ sessionId: string; sessionState?: ResolvedRouterAbEd25519WalletSessionState }>;
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
  }) => Promise<{ sessionId: string; sessionState: ResolvedRouterAbEd25519WalletSessionState }>;
};

type NearEd25519PasskeyReconnectMode = 'session_reconnect' | 'material_restore';

type NearEd25519SelectedTransactionLane = TransactionLaneSelectedState<
  SelectedEd25519Lane,
  NearEd25519TransactionReadyAvailableLane,
  Ed25519LaneCandidate,
  NearEd25519TransactionReadyLane
>;

function exactEd25519IdentityFromSelectedLane(lane: SelectedEd25519Lane) {
  return exactEd25519SigningLaneIdentityFromSelectedLane(lane);
}

type NearEd25519Warmup = {
  isPending: () => boolean;
  waitForReady: () => Promise<boolean>;
};

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
  ed25519Warmup?: NearEd25519Warmup;
  emailOtpCommittedLane?: Ed25519SigningLane;
  emailOtpSigning?: NearEd25519EmailOtpSigning;
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
  emailOtpSigning: NearEd25519EmailOtpSigning | null;
  ed25519Warmup: NearEd25519Warmup | null;
  passkeyEd25519Reconnect: NearEd25519PasskeyReconnect | null;
};

type NearEd25519LifecycleMetadata = {
  thresholdSessionRecord: ThresholdEd25519SessionRecord;
  transactionLane: SelectedEd25519Lane;
  transactionOperation: PreparedTransactionOperation<SelectedEd25519Lane>;
  transactionReadinessState: TransactionReadinessClassifiedState;
  identity: ResolvedEd25519SigningSessionIdentity;
  availableLanesGeneration: number;
  readiness: ThresholdSigningReadinessInput;
  ed25519Warmup?: NearEd25519Warmup;
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
    state: lane.state,
    source: lane.source || 'unknown',
    signingGrantId: lane.signingGrantId,
    thresholdSessionId: lane.thresholdSessionId,
    remainingUses: lane.remainingUses,
    expiresAtMs: lane.expiresAtMs,
    materialKind: lane.material.kind,
    hasMaterialIdentity: lane.material.kind !== 'material_pending',
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
      throw new Error(
        '[SigningEngine][near] selected Email OTP record is missing auth context',
      );
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
  return { status: 'missing_hot_material' };
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
    throw new Error('[SigningEngine][near] Email OTP Ed25519 committed lane requires Email OTP auth');
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
  const isSingleUseEmailOtpRecord =
    emailOtpAuthContext
      ? emailOtpAuthContextRetention(emailOtpAuthContext) === 'single_use'
      : false;
  const persistedState = classifyRouterAbEd25519PersistedSigningRecord(args.record);
  const hasRuntimeValidatedWorkerMaterial = persistedState.kind === 'runtime_validated';
  const hasRestoreAvailablePasskeyWorkerMaterial =
    args.record.source !== 'email_otp' &&
    persistedState.kind === 'restore_available' &&
    hasRouterAbEd25519SigningAuth(args.record);
  const hasUnvalidatedPasskeyWorkerMaterial =
    args.record.source !== 'email_otp' &&
    persistedState.kind === 'material_hint_unvalidated' &&
    hasRouterAbEd25519SigningAuth(args.record);
  if (!sessionId || isSingleUseEmailOtpRecord || !hasRouterAbEd25519SigningAuth(args.record)) {
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
  if (hasRuntimeValidatedWorkerMaterial) {
    if (remainingUses < requiredSignatureUses) {
      return buildReadiness('exhausted', remainingUses, expiresAtMs);
    }
    console.info('[SigningEngine][near] using record-backed Ed25519 readiness', {
      nearAccountId: args.nearAccount.accountId,
      thresholdSessionId: sessionId,
      signingGrantId: args.record.signingGrantId,
      source: args.record.source,
      liveStatus: liveStatus?.status || 'not_found',
      remainingUses,
      expiresAtMs,
      requiredSignatureUses,
    });
    return buildReadiness('ready', remainingUses, expiresAtMs);
  }
  if (hasRestoreAvailablePasskeyWorkerMaterial || hasUnvalidatedPasskeyWorkerMaterial) {
    if (liveStatus?.sessionId === sessionId) {
      const liveStatusKind = String(liveStatus.status || '').trim();
      if (liveStatusKind === 'exhausted') return buildReadiness('exhausted', 0);
      if (liveStatusKind === 'expired') return buildReadiness('expired', 0);
      if (liveStatusKind && liveStatusKind !== 'active' && liveStatusKind !== 'budget_unknown') {
        return buildReadiness('missing_session', 0);
      }
    }
    const admittedRemainingUses =
      liveStatus?.sessionId === sessionId && liveStatus.status === 'active'
        ? Math.max(0, Math.floor(Number(liveStatus.remainingUses) || 0))
        : remainingUses;
    const admittedExpiresAtMs =
      liveStatus?.sessionId === sessionId && liveStatus.status === 'active'
        ? Math.floor(Number(liveStatus.expiresAtMs) || expiresAtMs)
        : expiresAtMs;
    if (admittedRemainingUses < requiredSignatureUses) {
      return buildReadiness('exhausted', admittedRemainingUses, admittedExpiresAtMs);
    }
    console.info('[SigningEngine][near] using pending-material Ed25519 warm-session readiness', {
      nearAccountId: args.nearAccount.accountId,
      thresholdSessionId: sessionId,
      signingGrantId: args.record.signingGrantId,
      source: args.record.source,
      reason: persistedState.reason,
      remainingUses: admittedRemainingUses,
      expiresAtMs: admittedExpiresAtMs,
      requiredSignatureUses,
    });
    return buildReadiness('ready', admittedRemainingUses, admittedExpiresAtMs);
  }
  if (liveStatus?.sessionId === sessionId) {
    if (liveStatus.status === 'expired') return buildReadiness('expired', 0);
    if (liveStatus.status === 'exhausted') return buildReadiness('exhausted', 0);
    if (liveStatus.status !== 'active') return buildReadiness('missing_session', 0);
    const remainingUses = Math.floor(Number(liveStatus.remainingUses) || 0);
    if (remainingUses < requiredSignatureUses) return buildReadiness('exhausted', remainingUses);
    return buildReadiness(
      'ready',
      remainingUses,
      Math.floor(Number(liveStatus.expiresAtMs) || args.record.expiresAtMs),
    );
  }

  if (args.preConfirmDeps.hasUiConfirm()) return buildReadiness('missing_session', 0);
  if (remainingUses < requiredSignatureUses)
    return buildReadiness('exhausted', remainingUses, expiresAtMs);
  return buildReadiness('ready', remainingUses, expiresAtMs);
}

async function resolveNearTransactionWalletAuth(args: {
  deps: NearSigningApiDeps;
  confirmedDeps: NearTransactionConfirmedSigningDeps;
  commandSubject: NearCommandSubject;
  preparedOperation: PreparedNearEd25519Operation;
  operationId: SigningOperationId;
  onEvent?: (update: SigningFlowEvent) => void;
}): Promise<{
  signingAuthPlan: SigningAuthPlan;
  signingLane: NearTransactionSigningLane;
  emailOtpSigning?: NearEd25519EmailOtpSigning;
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
  if (signingAuthPlan.kind !== SigningAuthPlanKind.EmailOtpReauth) {
    return {
      signingAuthPlan,
      signingLane: lane,
    };
  }

  let activeChallenge: { challengeId: string; email?: string } | null = null;
  let activeEmailOtpRequiredSignatureUses = 1;
  const committedLane = resolveEd25519SigningLane({
    lane: preparedOperation.metadata.transactionLane,
    record,
  });
  const prepareEmailOtpChallenge = async (prepareArgs: { requiredSignatureUses: number }) => {
    activeEmailOtpRequiredSignatureUses = Math.max(
      1,
      Math.floor(Number(prepareArgs.requiredSignatureUses) || 1),
    );
    if (typeof args.confirmedDeps.requestEmailOtpTransactionSigningChallenge !== 'function') {
      throw new Error('[SigningEngine] Email OTP per-operation NEAR signing is not configured');
    }
    emitNearSigningEvent(args.onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_CHALLENGE_STARTED,
      status: 'running',
      message: 'Sending Email OTP for transaction authorization',
      interaction: { kind: 'none', overlay: 'none' },
    });
    emitSigningBoundaryTrace(
      'near',
      createSigningBoundaryTraceEvent({
        event: 'auth_side_effect_started',
        lane,
        sideEffect: 'email_otp_challenge',
        phase: 'confirmed',
      }),
    );
    const challenge = await args.confirmedDeps.requestEmailOtpTransactionSigningChallenge({
      walletSession: args.commandSubject.walletSession,
      nearAccountId,
      chain: 'near',
      committedLane,
    });
    const challengeId = String(challenge.challengeId || '').trim();
    if (!challengeId) {
      throw new Error('[SigningEngine] Email OTP challenge response did not include challengeId');
    }
    emitNearSigningEvent(args.onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_INPUT_REQUIRED,
      status: 'waiting_for_user',
      message: 'Email OTP challenge ready',
      interaction: { kind: 'otp_input', overlay: 'show' },
      ...(challenge.emailHint ? { data: { emailHint: challenge.emailHint } } : {}),
    });
    activeChallenge = {
      challengeId,
      email: String(challenge.emailHint || '').trim(),
    };
    return {
      challengeId: activeChallenge.challengeId,
      ...(activeChallenge.email ? { emailHint: activeChallenge.email } : {}),
    };
  };
  return {
    signingAuthPlan,
    signingLane: lane,
    emailOtpSigning: {
      committedLane,
      prepare: prepareEmailOtpChallenge,
      resend: prepareEmailOtpChallenge,
      complete: async (authorization: NearEd25519EmailOtpStepUpAuthorization) => {
        const resolvedChallengeId = String(
          authorization.challengeId || activeChallenge?.challengeId || '',
        ).trim();
        if (!resolvedChallengeId) {
          throw new Error('[SigningEngine] Email OTP challenge must be prepared before completion');
        }
        if (
          typeof args.confirmedDeps.loginWithEmailOtpEd25519CapabilityForSigning !== 'function' ||
          !record
        ) {
          throw new Error('[SigningEngine] Email OTP per-operation NEAR signing is not configured');
        }
        const sessionBudgetUses = resolveTransactionStepUpSessionUses({
          operationId: args.operationId,
          requiredSignatureUses: activeEmailOtpRequiredSignatureUses,
        });
        const emailOtpAuthentication =
          await args.confirmedDeps.loginWithEmailOtpEd25519CapabilityForSigning({
            nearAccountId,
            challengeId: resolvedChallengeId,
            otpCode: authorization.otpCode,
            committedLane,
            remainingUses: sessionBudgetUses,
          });
        if (emailOtpAuthentication.record) {
          // OTP step-up mints the replacement Ed25519 runtime lane. Publish it
          // before signing/finalization so budget sync targets the same lane.
          const currentRecord = buildOperationUsableThresholdEd25519SessionRecord(
            emailOtpAuthentication.record,
          );
          if (!currentRecord) {
            throw new Error('[SigningEngine] Email OTP step-up returned unusable Ed25519 session');
          }
          requireCommittedThresholdEd25519Session(
            commitCurrentThresholdEd25519Session({
              record: currentRecord,
              transition: 'step_up',
            }),
          );
        }
        const sessionState = resolveRouterAbEd25519WalletSessionStateFromRecord(
          emailOtpAuthentication.record,
        );
        return {
          sessionId: emailOtpAuthentication.sessionId,
          ...(sessionState ? { sessionState } : {}),
        };
      },
    },
  };
}

function walletSessionJwtForPreparedNearExecution(args: {
  record: ThresholdEd25519SessionRecord | null | undefined;
  emailOtpCommittedLane: Ed25519SigningLane | null;
  emailOtpSigning: NearEd25519EmailOtpSigning | null;
}): string {
  const record = args.record;
  if (!record) return '';
  if (record.source === 'email_otp') {
    return String(
      args.emailOtpCommittedLane?.walletSessionAuthority.walletSessionJwt ||
        args.emailOtpSigning?.committedLane.walletSessionAuthority.walletSessionJwt ||
        '',
    ).trim();
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

function resolveAdHocSigningRequestSessionId(args: {
  deps: NearSigningApiDeps;
  commandSubject: NearCommandSubject;
}): string {
  const nearAccountId = args.commandSubject.nearAccount.accountId;
  const walletId = args.commandSubject.walletSession.walletId;
  if (typeof args.deps.resolveThresholdEd25519SessionId === 'function') {
    const canonical = String(
      args.deps.resolveThresholdEd25519SessionId(walletId) || '',
    ).trim();
    if (canonical) return canonical;
  }
  return args.deps.createSigningSessionId('threshold-ed25519');
}

function buildPreparedNearTransactionExecutionState(args: {
  preparedSigningSession: PreparedNearEd25519TransactionSigningSession;
  resolvedSessionId: string;
  signingSessionCoordinator: SigningSessionCoordinator;
  passkeyEd25519Reconnect: NearEd25519PasskeyReconnect | null;
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
    emailOtpSigning: args.preparedSigningSession.emailOtpSigning || null,
    ed25519Warmup: args.preparedSigningSession.ed25519Warmup || null,
    passkeyEd25519Reconnect: args.passkeyEd25519Reconnect,
  };
}

function assertNeverRouterAbEd25519ReconnectState(value: never): never {
  throw new Error(`Unexpected passkey Ed25519 reconnect state: ${String(value)}`);
}

function requireSignablePasskeyReconnectEd25519SessionState(args: {
  record: ThresholdEd25519SessionRecord;
  thresholdSessionId: string;
}): ResolvedRouterAbEd25519WalletSessionState {
  const sessionState = resolveRouterAbEd25519WalletSessionStateFromRecord(args.record);
  if (sessionState) return sessionState;

  const refreshedRecordState = classifyRouterAbEd25519PersistedSigningRecord(args.record);
  switch (refreshedRecordState.kind) {
    case 'material_hint_unvalidated':
    case 'auth_ready_material_pending':
      throwEd25519MaterialRestoreRequired({
        operation: 'passkey_reconnect',
        thresholdSessionId: args.thresholdSessionId,
        reason: 'pending_material',
      });
    case 'restore_available':
      throwEd25519MaterialRestoreRequired({
        operation: 'passkey_reconnect',
        thresholdSessionId: args.thresholdSessionId,
        reason: 'restore_available',
      });
    case 'runtime_validated':
      throw new Error(
        '[SigningEngine][near] passkey Ed25519 reconnect did not produce signable Router A/B state: unresolved_signable_record',
      );
    case 'non_signing':
    case 'invalid':
      throw new Error(
        `[SigningEngine][near] passkey Ed25519 reconnect did not produce signable Router A/B state: ${refreshedRecordState.reason}`,
      );
    default:
      assertNeverRouterAbEd25519ReconnectState(refreshedRecordState satisfies never);
  }
}

function requirePasskeyReconnectThresholdEd25519SessionRecord(args: {
  record: ThresholdEd25519SessionRecord | undefined;
  thresholdSessionId: string;
}): ThresholdEd25519SessionRecord {
  if (args.record) return args.record;
  throw new Error(
    `[SigningEngine][near] passkey Ed25519 reconnect did not return a session record for ${args.thresholdSessionId}`,
  );
}

function buildNearPasskeyEd25519Reconnect(args: {
  deps: NearSigningApiDeps;
  commandSubject: NearCommandSubject;
  ctx: ReturnType<NearSigningApiDeps['getSignerWorkerContext']>;
  thresholdSessionRecord: ThresholdEd25519SessionRecord | null;
  operationId: SigningOperationId;
  mode: NearEd25519PasskeyReconnectMode;
}): NearEd25519PasskeyReconnect | undefined {
  if (
    !args.thresholdSessionRecord ||
    typeof args.deps.reconnectPasskeyEd25519CapabilityForSigning !== 'function'
  ) {
    return undefined;
  }
  const thresholdSessionRecord = args.thresholdSessionRecord;
  return {
    prepare: async ({ requiredSignatureUses }: { requiredSignatureUses: number }) => {
      const materialRestoreOnly = args.mode === 'material_restore';
      const sessionBudgetUses = materialRestoreOnly
        ? resolveMaterialRestoreSessionUses({
            record: thresholdSessionRecord,
            requiredSignatureUses,
          })
        : resolveTransactionStepUpSessionUses({
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
      if (materialRestoreOnly && !thresholdSessionId) {
        throw new Error('[SigningEngine] missing threshold session id for passkey Ed25519 restore');
      }
      if (!signingGrantId) {
        throw new Error('[SigningEngine] missing signing grant id for passkey Ed25519 reauth');
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
        ...(materialRestoreOnly ? { thresholdSessionId } : {}),
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
      const materialRestoreOnly = args.mode === 'material_restore';
      const sessionBudgetUses = materialRestoreOnly
        ? resolveMaterialRestoreSessionUses({
            record: thresholdSessionRecord,
            requiredSignatureUses,
          })
        : resolveTransactionStepUpSessionUses({
            operationId: args.operationId,
            requiredSignatureUses,
          });
      const refreshed = await args.deps.reconnectPasskeyEd25519CapabilityForSigning!({
        nearAccountId: args.commandSubject.nearAccount.accountId,
        record: thresholdSessionRecord,
        policySecretSource: buildThresholdEd25519WebAuthnPrfSecretSource({
          credential: authorization.credential,
          rpId: thresholdSessionRecord.rpId,
        }),
        usesNeeded: requiredSignatureUses,
        remainingUses: sessionBudgetUses,
        sessionId: authorization.plannedPasskeyReconnect.sessionId,
        signingGrantId: authorization.plannedPasskeyReconnect.signingGrantId,
      });
      const record = requirePasskeyReconnectThresholdEd25519SessionRecord({
        record: refreshed.record,
        thresholdSessionId: refreshed.sessionId,
      });
      const sessionState = requireSignablePasskeyReconnectEd25519SessionState({
        record,
        thresholdSessionId: refreshed.sessionId,
      });
      return {
        sessionId: refreshed.sessionId,
        sessionState,
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
    String(args.record.signingGrantId || '').trim() ===
      String(identity.signingGrantId || '').trim()
  );
}

function selectNearEd25519TransactionCandidate(args: {
  availableLanes: AvailableSigningLanes | null;
  authSelectionPolicy: TransactionAuthSelectionPolicy | null;
  walletId: WalletId | string;
}): NearEd25519SelectedTransactionLane | null {
  const authSelectionPolicy = args.authSelectionPolicy || null;
  if (!authSelectionPolicy) return null;

  const intentState = receiveTransactionIntent(
    nearEd25519TransactionSigningIntent({
      walletId: args.walletId,
      authSelectionPolicy,
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
  walletId: WalletId | string;
  authSelectionPolicy: TransactionAuthSelectionPolicy;
}): NearEd25519TransactionSigningIntent {
  return {
    walletId: toWalletId(args.walletId),
    curve: 'ed25519',
    chain: 'near',
    authSelectionPolicy: args.authSelectionPolicy,
    operationUsesNeeded: 1,
  };
}

function selectSelectedEd25519LaneFromAvailableLanes(args: {
  commandSubject: NearCommandSubject;
  availableLanes: AvailableSigningLanes | null;
}): NearEd25519SelectedTransactionLane | null {
  const walletId = args.commandSubject.walletSession.walletId;
  return selectNearEd25519TransactionCandidate({
    availableLanes: args.availableLanes,
    authSelectionPolicy: { kind: 'any' },
    walletId,
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

function readNearEd25519RuntimeRecordForSelectedLane(args: {
  selectedLane: SelectedEd25519Lane | null;
}): ThresholdEd25519SessionRecord | null {
  if (!args.selectedLane) return null;
  const record = getStoredThresholdEd25519SessionRecordByThresholdSessionId(
    args.selectedLane.thresholdSessionId,
  );
  if (!record) return null;
  return thresholdEd25519RecordMatchesSelectedLane({
    record,
    selectedLane: args.selectedLane,
    walletId: args.selectedLane.identity.signer.account.wallet.walletId,
  })
    ? record
    : null;
}

function ed25519RecordMatchesTransactionMaterial(args: {
  record: ThresholdEd25519SessionRecord;
  material: NearEd25519TransactionMaterial;
}): boolean {
  const persistedState = classifyRouterAbEd25519PersistedSigningRecord(args.record);
  const materialIdentity =
    routerAbEd25519WorkerMaterialIdentityFromPersistedState(persistedState);
  if (!materialIdentity) return false;
  return (
    String(materialIdentity.bindingDigest) === String(args.material.identity.bindingDigest) &&
    String(materialIdentity.materialKeyId) === String(args.material.identity.materialKeyId)
  );
}

function assertSelectedEd25519RestoreMaterialMatchesRecord(args: {
  material: NearEd25519TransactionMaterial;
  selectedLane: SelectedEd25519Lane;
  walletId: WalletId | string;
}): void {
  const record = getStoredThresholdEd25519SessionRecordByThresholdSessionId(
    args.selectedLane.thresholdSessionId,
  );
  if (!record) return;
  if (
    !thresholdEd25519RecordMatchesSelectedLane({
      record,
      selectedLane: args.selectedLane,
      walletId: args.walletId,
    })
  ) {
    throw new Error('[SigningEngine][near] selected Ed25519 restore record identity mismatch');
  }
  if (!ed25519RecordMatchesTransactionMaterial({ record, material: args.material })) {
    throw new Error('[SigningEngine][near] selected Ed25519 restore material identity mismatch');
  }
}

function publishNearEd25519RuntimeIdentityForRecord(
  record: ThresholdEd25519SessionRecord | null,
): void {
  const thresholdSessionId = String(record?.thresholdSessionId || '').trim();
  const signingGrantId = String(record?.signingGrantId || '').trim();
  if (!record || !thresholdSessionId || !signingGrantId) return;
  // This is a command-boundary write: durable seal cleanup can remove restore
  // material while the current tab still has a runtime lane that must be
  // selectable for step-up auth after exhaustion.
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

async function restoreNearEd25519SelectedSigningSession(args: {
  deps: NearSigningApiDeps;
  commandSubject: NearCommandSubject;
  selectedLane: SelectedEd25519Lane | null;
  selectedTransactionLane: NearEd25519TransactionReadyLane | null;
}): Promise<void> {
  const nearAccountId = args.commandSubject.nearAccount.accountId;
  const walletId = args.commandSubject.walletSession.walletId;
  if (typeof args.deps.restorePersistedSessionForSigning !== 'function') return;
  const selectedLane = args.selectedLane;
  if (!selectedLane) {
    console.debug('[SigningEngine][near] Ed25519 restore skipped without selected available lane', {
      nearAccountId,
    });
    return;
  }
  const material = args.selectedTransactionLane?.material || null;
  if (!material) {
    throw new Error('[SigningEngine][near] selected Ed25519 lane is missing material availability');
  }
  const thresholdSessionId = String(selectedLane.thresholdSessionId || '').trim();
  if (material.kind === 'loaded_worker_material') return;
  assertSelectedEd25519RestoreMaterialMatchesRecord({
    material,
    selectedLane,
    walletId,
  });
  await args.deps.restorePersistedSessionForSigning({
    walletId,
    authMethod: signingLaneAuthMethod(selectedLane.auth),
    curve: 'ed25519',
    chain: 'near',
    signingGrantId: selectedLane.signingGrantId,
    thresholdSessionId: selectedLane.thresholdSessionId,
    reason: 'transaction',
    materialRestoreIdentity: {
      kind: 'ed25519_worker_material_restore',
      lane: exactEd25519IdentityFromSelectedLane(selectedLane),
      materialBindingDigest: material.identity.bindingDigest,
      materialKeyId: material.identity.materialKeyId,
    },
  });
}

async function prepareNearEd25519TransactionOperation(args: {
  deps: NearSigningApiDeps;
  commandSubject: NearCommandSubject;
  signingSessionCoordinator: SigningSessionCoordinator;
  ed25519Warmup?: NearEd25519Warmup;
  availableLanes?: AvailableSigningLanes | null;
  selectedLane: NearEd25519SelectedTransactionLane;
  operationUsesNeeded: number;
}): Promise<NearEd25519TransactionOperationPrepareResult> {
  const nearAccountId = args.commandSubject.nearAccount.accountId;
  const walletId = args.commandSubject.walletSession.walletId;
  const operationUsesNeeded = Math.max(1, Math.floor(Number(args.operationUsesNeeded) || 1));
  const selectedSessionLane = args.selectedLane.lane;
  await restoreNearEd25519SelectedSigningSession({
    deps: args.deps,
    commandSubject: args.commandSubject,
    selectedLane: selectedSessionLane,
    selectedTransactionLane: args.selectedLane.selectionCandidate,
  });
  const restoreState = recordExactRestoreAttempt(args.selectedLane, {
    restored: Boolean(selectedSessionLane),
  });
  const recordForLifecycle = readNearEd25519RuntimeRecordForSelectedLane({
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
      hasRouterAbSigningAuth: hasRouterAbEd25519SigningAuth(recordForLifecycle),
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
    restoreState,
    transactionReadinessFromPlannerInput({
      readiness: readiness.readiness,
      expiresAtMs: readiness.expiresAtMs,
      remainingUses: readiness.remainingUses,
      usesNeeded: operationUsesNeeded,
    }),
  );
  const transactionOperation = prepareTransactionOperationFromReadiness(transactionReadinessState);
  const identity = requireResolvedNearEd25519SigningLane(lane);
  const walletSessionStateForBudget =
    resolveRouterAbEd25519WalletSessionStateFromRecord(recordForLifecycle);
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
      ...(args.ed25519Warmup ? { ed25519Warmup: args.ed25519Warmup } : {}),
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
  const walletId = args.commandSubject.walletSession.walletId;
  const operationUsesNeeded = requiredNearTransactionSignatureUses(args.input.transaction);
  const hasPendingEmailOtpEd25519Warmup = (): boolean =>
    args.deps.isEmailOtpEd25519WarmupPending?.({ nearAccountId }) === true;
  if (hasPendingEmailOtpEd25519Warmup()) {
    emitNearSigningEvent(args.input.onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
      status: 'running',
      message: 'Finalizing NEAR signing session',
      interaction: { kind: 'none', overlay: 'none' },
    });
    await args.deps.waitForPendingEmailOtpEd25519Warmup?.({ nearAccountId });
  }
  const ed25519Warmup =
    hasPendingEmailOtpEd25519Warmup() &&
    typeof args.deps.waitForPendingEmailOtpEd25519Warmup === 'function'
      ? {
          isPending: hasPendingEmailOtpEd25519Warmup,
          waitForReady: () =>
            args.deps.waitForPendingEmailOtpEd25519Warmup!({
              nearAccountId,
            }),
        }
      : undefined;
  const availableLanes = await readNearEd25519AvailableSigningLanes({
    deps: args.deps,
    commandSubject: args.commandSubject,
    authMethod: null,
  });
  const selectedLane = selectSelectedEd25519LaneFromAvailableLanes({
    commandSubject: args.commandSubject,
    availableLanes,
  });
  if (!selectedLane) {
    console.warn('[SigningEngine][near][ed25519] exact transaction lane selection failed', {
      nearAccountId,
      requiredSignatureUses: operationUsesNeeded,
      pendingEmailOtpEd25519Warmup: hasPendingEmailOtpEd25519Warmup(),
      availableLanes: summarizeNearEd25519AvailableLanes(availableLanes),
    });
    throw new Error(
      '[SigningEngine][near] Ed25519 transaction signing requires an exact selected lane',
    );
  }
  const initialAuthSelectionPolicy: TransactionAuthSelectionPolicy = {
    kind: 'account_class',
    authMethod: signingLaneAuthMethod(selectedLane.lane.auth),
  };

  const preparedTransaction = await prepareTransactionSigningOperation({
    intent: {
      walletId,
      curve: 'ed25519',
      chain: 'near',
      authSelectionPolicy: initialAuthSelectionPolicy,
      operationUsesNeeded,
    },
    coordinator: args.signingSessionCoordinator,
    forceFreshAuth: args.forceFreshAuth === true,
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
          ...(ed25519Warmup ? { ed25519Warmup } : {}),
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

  const { signingAuthPlan, emailOtpSigning } = await resolveNearTransactionWalletAuth({
    deps: args.deps,
    confirmedDeps: {
      requestEmailOtpTransactionSigningChallenge:
        args.deps.requestEmailOtpTransactionSigningChallenge,
      resolveEmailOtpEd25519SigningSessionAuthority:
        args.deps.resolveEmailOtpEd25519SigningSessionAuthority,
      loginWithEmailOtpEd25519CapabilityForSigning:
        args.deps.loginWithEmailOtpEd25519CapabilityForSigning,
    },
    commandSubject: args.commandSubject,
    preparedOperation,
    operationId: args.operationId,
    onEvent: args.input.onEvent,
  });
  const emailOtpCommittedLane =
    emailOtpSigning?.committedLane ||
    (thresholdSessionRecord?.source === 'email_otp'
      ? resolveEd25519SigningLane({
          lane: transactionLane,
          record: thresholdSessionRecord,
        })
      : null);
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
    ...(preparedOperation.metadata.ed25519Warmup
      ? { ed25519Warmup: preparedOperation.metadata.ed25519Warmup }
      : {}),
    ...(emailOtpCommittedLane ? { emailOtpCommittedLane } : {}),
    ...(emailOtpSigning ? { emailOtpSigning } : {}),
  };
}

export async function signTransactionWithActions(
  deps: NearSigningApiDeps,
  args: SignTransactionWithActionsInput,
  attempt: {
    forceFreshAuth?: boolean;
    materialRestoreOnly?: boolean;
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
          mode: attempt.materialRestoreOnly ? 'material_restore' : 'session_reconnect',
        });
        const executionState = buildPreparedNearTransactionExecutionState({
          preparedSigningSession,
          resolvedSessionId,
          signingSessionCoordinator,
          passkeyEd25519Reconnect: passkeyEd25519Reconnect || null,
        });
        const walletSessionJwt = walletSessionJwtForPreparedNearExecution({
          record: thresholdSessionRecord,
          emailOtpCommittedLane: executionState.emailOtpCommittedLane,
          emailOtpSigning: executionState.emailOtpSigning,
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
          ...(executionState.emailOtpSigning
            ? { emailOtpSigning: executionState.emailOtpSigning }
            : {}),
          signingOperationId: confirmationOperationId,
          signingSessionCoordinator: executionState.signingSessionCoordinator,
          transactionOperation: executionState.transactionOperation,
          ed25519SigningBoundary,
          ...(executionState.ed25519Warmup ? { ed25519Warmup: executionState.ed25519Warmup } : {}),
          ...(executionState.passkeyEd25519Reconnect
            ? { passkeyEd25519Reconnect: executionState.passkeyEd25519Reconnect }
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
      signingAuthPlan.kind === SigningAuthPlanKind.EmailOtpReauth ||
      Boolean(preparedSigningSession.emailOtpSigning);
    const materialUnsealAuthorizationRequired =
      isEd25519MaterialUnsealAuthorizationRequiredError(error);
    if (
      !attempt.retryingFreshAuth &&
      !alreadyAttemptedFreshAuth &&
      thresholdSessionRecord &&
      (isSigningSessionAuthUnavailableError(error) ||
        isSigningSessionBudgetAdmissionBlockedError(error) ||
        materialUnsealAuthorizationRequired)
    ) {
      const isEmailOtpSession = thresholdSessionRecord.source === 'email_otp';
      const reason = isSigningSessionBudgetAdmissionBlockedError(error)
        ? 'wallet_signing_budget_reserved'
        : materialUnsealAuthorizationRequired
          ? 'ed25519_material_unseal_authorization_required'
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
      return await signTransactionWithActions(deps, args, {
        forceFreshAuth: true,
        materialRestoreOnly: materialUnsealAuthorizationRequired,
        operationId: operationId || createNearTransactionSigningOperationId(),
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
    const activeSessionId = resolveAdHocSigningRequestSessionId({
      deps,
      commandSubject: args.commandSubject,
    });
    console.debug('[SigningEngine][delegate] session created', { sessionId: activeSessionId });
    return await withThresholdEd25519CommitQueue({
      deps,
      nearAccountId,
      thresholdSessionId: activeSessionId,
      task: async () => {
        const ctx = deps.getSignerWorkerContext();
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
    const nearAccount = payload.commandSubject.nearAccount;
    const nearAccountId = toAccountId(nearAccount.accountId);
    const activeSessionId = resolveAdHocSigningRequestSessionId({
      deps,
      commandSubject: payload.commandSubject,
    });
    const result = await withThresholdEd25519CommitQueue({
      deps,
      nearAccountId,
      thresholdSessionId: activeSessionId,
      task: async () => {
        const ctx = deps.getSignerWorkerContext();
        return (await signNearWithUiConfirm({
          chain: 'near',
          kind: 'nep413',
          payload: {
            ctx,
            commandSubject: payload.commandSubject,
            nearAccount,
            signingSessionCoordinator: deps.signingSessionCoordinator,
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
      error: message,
    };
  }
}
