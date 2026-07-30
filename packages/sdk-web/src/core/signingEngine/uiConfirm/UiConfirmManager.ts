import type { WarmSessionLanePurpose } from '../session/emailOtp/sealedRuntimePurpose';
/**
 * UiConfirm Manager
 * Owns the worker/main-thread handshake for uiConfirm UI orchestration
 * and the warm-session material cache.
 */

import type {
  SigningSessionSealAuthMethod,
  WarmSessionSealTransportInput,
  WarmSessionStatusBatchResult,
  WarmSessionRehydratePayload,
  WarmSessionRehydrateResult,
  WarmSessionSealAndPersistPayload,
  WarmSessionSealAndPersistDiagnostics,
  WarmSessionSealAndPersistResult,
  UiConfirmManagerConfig,
  UserConfirmWorkerMessage,
  UserConfirmWorkerResponse,
} from '../../types/secure-confirm-worker';
import {
  parseSigningSessionSealKeyVersion,
  type SigningSessionSealKeyVersion,
} from '../session/keyMaterialBrands';
import { BUILD_PATHS } from '../../../../build-paths';
import { resolveWorkerUrl } from '../../walletRuntimePaths';
import {
  acquireSigningSessionRestoreLease,
  buildCurrentSealedSessionRecord,
  deleteDurableSealedSessionRecord as deleteDurableSealedSessionRecordFromStore,
  listExactSealedSessionsForWallet,
  readExactSealedSession,
  releaseSigningSessionRestoreLease,
  updateExactSealedSessionPolicy,
  writeExactSealedSession,
  type BuildCurrentSealedSessionRecordInput,
  type CurrentEd25519RestoreMetadata,
  type CurrentSealedSessionRecord,
  type SigningSessionSealedStoreRecord,
  type SigningSessionSealedRecordFilter,
} from '../session/persistence/sealedSessionStore';
import {
  createDeleteDurableSealedSessionCommand,
  type DeleteDurableSealedSessionCommand,
  type DurableSealedSessionDeleteReason,
} from '../session/persistence/durableSealedSessionCommands';
import {
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  type ThresholdEd25519SessionRecord,
} from '../session/persistence/records';
import { parseRouterAbEd25519WalletSessionAuthorityFromRecord } from '../session/routerAbSigningWalletSession';
import {
  emailOtpAuthContextEmailHashHex,
  emailOtpAuthContextProvider,
  emailOtpAuthContextProviderUserId,
} from '../session/identity/laneIdentity';
import {
  UserConfirmMessageType,
  type UserConfirmDecision,
  type UserConfirmPromptEnvelope,
  type UserConfirmRequest,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import type { UserConfirmProgressEvent } from '../stepUpConfirmation/types';
import { handlePromptFromWorker } from './handlers/handlePromptFromWorker';
import { orchestrateSigningConfirmation } from './handlers/flowOrchestrator';
import type {
  OrchestrateNearSignatureOnlySigningConfirmationParams,
  OrchestrateNearTransactionSigningConfirmationParams,
  OrchestrateSigningConfirmationParams,
  SigningConfirmationResultIntentDigest,
  SigningConfirmationResultSignatureOnly,
  NearTransactionSigningConfirmationResult,
} from '../stepUpConfirmation/confirmOperation';
import { requestRegistrationCredentialConfirmationOnMainThread } from './handlers/flows/requestRegistrationCredentialConfirmation';
import {
  mountConfirmUI,
  type ConfirmUISurfaceSource,
  type MountedConfirmUIHandle,
} from './ui/confirm-ui';
import type {
  OpenRegistrationPreparationModalParams,
  RequestRegistrationCredentialConfirmationParams,
  RequestUserConfirmationOptions,
  ClearAllVolatileWarmSessionMaterialCommand,
  ClearVolatileWarmSessionMaterialCommand,
  WarmSessionPersistedRestorer,
  WarmSessionClaimResult,
  WarmSessionStatusResult,
  UiConfirmContext,
  UiConfirmManager,
  PasskeyMpcSessionPort,
} from './uiConfirm.types';
import {
  discoverPersistedSessionsForWalletCommand,
  restorePersistedSessionForSigningCommand,
} from '../session/sealedRecovery/restoreCoordinator';
import { parseClearVolatileWarmMaterialCommand } from '../session/warmCapabilities/volatileWarmMaterialCommands';
import { restorePasskeyEcdsaSealedRecordForWallet } from '../session/passkey/ecdsaRecovery';
import type {
  DiscoverPersistedSessionsForWalletInput,
  DiscoverPersistedSessionsForWalletResult,
  RestorePersistedSessionForSigningInput,
  RestorePersistedSessionForSigningResult,
  RestorePersistedSessionPurpose,
  RestoreSealedRecordResult,
} from '../session/sealedRecovery/sealedRecovery.types';
import type { SealedRecoveryRecord } from '../session/sealedRecovery/recoveryRecord';
import { sealedRecoveryWalletSessionJwt } from '../session/sealedRecovery/recoveryRecord';
import type { SealedSigningSessionEcdsaRestoreMetadata } from '@shared/utils/signingSessionSeal';
import { walletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEd25519SessionStoreSource } from '../session/identity/laneIdentity';
import {
  SIGNING_SESSION_SEAL_GROUP_ID,
  type SealedSigningSessionWalletSessionAuth,
} from '@shared/utils/signingSessionSeal';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type {
  WarmSessionMaterialWriteDiagnosticBucket,
  WarmSessionMaterialWriteDiagnostics,
} from '../session/passkey/warmSessionMaterialWriter';
import type { PasskeyMpcSessionDurableWorkerPort } from './PasskeyMpcSessionManager';

type PendingWorkerRequest = {
  id: string;
  messageType: string;
  worker: Worker;
  timeoutId: ReturnType<typeof setTimeout>;
  settle?: () => void;
  resolve: (response: UserConfirmWorkerResponse) => void;
  reject: (error: Error) => void;
};

type RegistrationPreparationModalState =
  | { kind: 'closed'; generation: number }
  | { kind: 'opening'; generation: number }
  | { kind: 'open'; generation: number; handle: MountedConfirmUIHandle };

const USER_CONFIRM_WORKER_STARTUP_PING_TIMEOUT_MS = 15_000;

function roundUiConfirmDurationMs(startedAt: number): number {
  return Math.max(0, Math.round(performance.now() - startedAt));
}

function recordWarmSessionMaterialWriteDiagnosticDuration(args: {
  diagnostics: WarmSessionMaterialWriteDiagnostics | undefined;
  bucket: WarmSessionMaterialWriteDiagnosticBucket;
  startedAt: number;
}): void {
  if (!args.diagnostics) return;
  args.diagnostics.recordDuration(args.bucket, roundUiConfirmDurationMs(args.startedAt));
}

function recordWarmSessionSealAndPersistResultDiagnostics(args: {
  diagnostics: WarmSessionMaterialWriteDiagnostics | undefined;
  resultDiagnostics: WarmSessionSealAndPersistDiagnostics | undefined;
}): void {
  if (!args.diagnostics || !args.resultDiagnostics) return;
  args.diagnostics.recordDuration(
    'sealed_record_apply_runtime_setup',
    args.resultDiagnostics.runtimeSetupMs,
  );
  args.diagnostics.recordDuration(
    'sealed_record_apply_client_seal',
    args.resultDiagnostics.clientSealMs,
  );
  args.diagnostics.recordDuration(
    'sealed_record_apply_server_route',
    args.resultDiagnostics.serverSealRouteMs,
  );
  args.diagnostics.recordDuration(
    'sealed_record_apply_client_unseal',
    args.resultDiagnostics.clientUnsealMs,
  );
  args.diagnostics.recordDuration(
    'sealed_record_apply_policy_update',
    args.resultDiagnostics.policyUpdateMs,
  );
}

function ed25519RestoreWalletSessionAuthFields(
  record: ThresholdEd25519SessionRecord,
): SealedSigningSessionWalletSessionAuth | null {
  if (record.thresholdSessionKind === 'jwt') {
    const authority = parseRouterAbEd25519WalletSessionAuthorityFromRecord(record);
    return authority.ok
      ? { sessionKind: 'jwt', walletSessionJwt: authority.value.auth.walletSessionJwt }
      : null;
  }
  return record.thresholdSessionKind === 'cookie' ? { sessionKind: 'cookie' } : null;
}

function requirePasskeyEcdsaRestoreOutcome(
  result: WarmSessionStatusResult | null,
  success: Extract<RestoreSealedRecordResult, 'ready' | 'restored'>,
): RestoreSealedRecordResult {
  if (!result) return 'deferred';
  if (result.ok) return success;
  if (result.code === 'exhausted') return 'ready';
  throw new Error(
    `[UiConfirm] passkey ECDSA sealed-session restore failed (${result.code}): ${result.message}`,
  );
}

type PasskeySealedRecordAccountMetadata = {
  walletId?: string;
  signingRootId?: string;
  signingRootVersion?: string;
  ecdsaRestore?: SigningSessionSealedStoreRecord['ecdsaRestore'];
  ed25519Restore?: CurrentEd25519RestoreMetadata;
};

async function passkeyEcdsaRestoreMetadataFromRecoveryRecord(
  record: Extract<SealedRecoveryRecord, { authMethod: 'passkey' }>,
): Promise<Exclude<SealedSigningSessionEcdsaRestoreMetadata, { source: 'email_otp' }>> {
  return {
    chainTarget: record.chainTarget,
    signingRootId: record.signingRootId,
    signingRootVersion: record.signingRootVersion,
    source: record.source,
    authority: await walletAuthAuthorityRef({ authority: record.authority }),
    roleLocalMaterialRef: record.roleLocalMaterialRef,
    rpId: record.authority.verifier.rpId,
    credentialIdB64u: record.authority.factor.credentialIdB64u,
    sessionKind: 'jwt',
    walletSessionJwt: record.walletSessionAuth.walletSessionJwt,
    keyHandle: record.keyHandle,
    ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
    ethereumAddress: record.ethereumAddress,
    relayerKeyId: record.relayerKeyId,
    clientVerifyingShareB64u: record.clientVerifyingShareB64u,
    thresholdEcdsaPublicKeyB64u: record.thresholdEcdsaPublicKeyB64u,
    participantIds: [...record.participantIds],
    ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
    routerAbEcdsaDerivationNormalSigning: record.routerAbEcdsaDerivationNormalSigning,
    publicCapability: record.publicCapability,
  };
}

type PasskeyExpiryObservation =
  | {
      kind: 'policy';
      expiresAtMs: number;
      remainingUses: number;
    }
  | {
      kind: 'status_code';
      expiresAtMs?: never;
      remainingUses?: never;
    };

function positiveInteger(value: unknown): number {
  const parsed = Math.floor(Number(value));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

function parseOptionalSigningSessionSealKeyVersion(
  value: unknown,
): SigningSessionSealKeyVersion | undefined {
  const raw = String(value || '').trim();
  return raw ? parseSigningSessionSealKeyVersion(raw) : undefined;
}

function firstSigningSessionSealKeyVersion(
  values: readonly unknown[],
): SigningSessionSealKeyVersion | undefined {
  for (const value of values) {
    const parsed = parseOptionalSigningSessionSealKeyVersion(value);
    if (parsed) return parsed;
  }
  return undefined;
}

function ed25519RestoreMetadataMissingFields(
  value:
    | {
        nearAccountId?: unknown;
        nearEd25519SigningKeyId?: unknown;
        rpId?: unknown;
        relayerKeyId?: unknown;
        participantIds?: unknown;
        signerSlot?: unknown;
        routerAbNormalSigning?: unknown;
      }
    | null
    | undefined,
): string[] {
  const missing: string[] = [];
  if (!String(value?.nearAccountId || '').trim()) {
    missing.push('nearAccountId');
  }
  if (!String(value?.nearEd25519SigningKeyId || '').trim()) {
    missing.push('nearEd25519SigningKeyId');
  }
  if (!String(value?.rpId || '').trim()) {
    missing.push('rpId');
  }
  if (!String(value?.relayerKeyId || '').trim()) {
    missing.push('relayerKeyId');
  }
  if (!Array.isArray(value?.participantIds) || value.participantIds.length === 0) {
    missing.push('participantIds');
  }
  if (!positiveInteger(value?.signerSlot)) {
    missing.push('signerSlot');
  }
  if (!value?.routerAbNormalSigning) {
    missing.push('routerAbNormalSigning');
  }
  return missing;
}

type CurrentEd25519RestoreAuthBranch =
  | {
      kind: 'passkey';
      credentialIdB64u: string;
    }
  | {
      kind: 'email_otp';
      provider: 'google' | 'email';
      providerSubjectId: string;
      emailHashHex: string;
    };

function currentEd25519RestoreAuthBranchFromRecord(
  record: ThresholdEd25519SessionRecord,
): CurrentEd25519RestoreAuthBranch | null {
  if (record.source === 'email_otp') {
    if (!record.emailOtpAuthContext) return null;
    const providerSubjectId = emailOtpAuthContextProviderUserId(record.emailOtpAuthContext);
    const provider = emailOtpAuthContextProvider(record.emailOtpAuthContext);
    const emailHashHex = emailOtpAuthContextEmailHashHex(record.emailOtpAuthContext);
    return providerSubjectId && emailHashHex
      ? { kind: 'email_otp', provider, providerSubjectId, emailHashHex }
      : null;
  }
  const credentialIdB64u = String(record.passkeyCredentialIdB64u || '').trim();
  return credentialIdB64u ? { kind: 'passkey', credentialIdB64u } : null;
}

function currentEd25519RestoreMetadataFromSessionRecord(
  record: ThresholdEd25519SessionRecord | null | undefined,
): CurrentEd25519RestoreMetadata | undefined {
  if (!record) return undefined;
  const rpId = String(record.rpId || '').trim();
  const nearAccountId = String(record.nearAccountId || '').trim();
  const nearEd25519SigningKeyId = String(record.nearEd25519SigningKeyId || '').trim();
  const relayerKeyId = String(record.relayerKeyId || '').trim();
  const signerSlot = positiveInteger(record.signerSlot);
  const routerAbNormalSigning = record.routerAbNormalSigning;
  const authBranch = currentEd25519RestoreAuthBranchFromRecord(record);
  const walletSessionAuth = ed25519RestoreWalletSessionAuthFields(record);
  if (
    !rpId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !relayerKeyId ||
    !record.participantIds.length ||
    !signerSlot ||
    !routerAbNormalSigning ||
    !authBranch ||
    !walletSessionAuth
  ) {
    return undefined;
  }
  const commonRestoreMetadata = {
    rpId,
    nearAccountId,
    nearEd25519SigningKeyId,
    relayerKeyId,
    participantIds: record.participantIds,
    ...walletSessionAuth,
    signerSlot,
    ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
    routerAbNormalSigning,
  };
  if (authBranch.kind === 'email_otp') {
    return undefined;
  }
  return {
    ...commonRestoreMetadata,
    credentialIdB64u: authBranch.credentialIdB64u,
  };
}

type WarmSessionSealAuthMethodInput =
  | {
      thresholdSessionId: string;
      curve: 'ed25519';
      authMethod?: SigningSessionSealAuthMethod;
      chainTarget?: never;
    }
  | {
      thresholdSessionId: string;
      curve: 'ecdsa';
      authMethod?: SigningSessionSealAuthMethod;
      chainTarget: ThresholdEcdsaChainTarget;
    };

function assertNever(value: never): never {
  throw new Error(`Unexpected warm-session seal auth source: ${String(value)}`);
}

function sealedAuthMethodForThresholdEd25519Source(
  source: ThresholdEd25519SessionStoreSource,
): SigningSessionSealAuthMethod {
  switch (source) {
    case 'email_otp':
      return SIGNER_AUTH_METHODS.emailOtp;
    case 'login':
    case 'registration':
    case 'add-signer':
    case 'manual-connect':
    case 'bootstrap':
      return SIGNER_AUTH_METHODS.passkey;
    default:
      return assertNever(source);
  }
}

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function stripFunctionsForWorkerMessage<T>(value: T): T {
  if (typeof value === 'function') {
    return undefined as T;
  }
  if (Array.isArray(value)) {
    return value.map((entry) => stripFunctionsForWorkerMessage(entry)) as T;
  }
  if (!isObjectRecord(value)) {
    return value;
  }
  const output: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry === 'function') continue;
    output[key] = stripFunctionsForWorkerMessage(entry);
  }
  return output as T;
}

function maybeCopyEmailOtpResendHandler(args: {
  targetPrompt: unknown;
  sourcePrompt: unknown;
}): unknown {
  if (!isObjectRecord(args.targetPrompt) || !isObjectRecord(args.sourcePrompt)) {
    return args.targetPrompt;
  }
  const onResend = args.sourcePrompt.onResend;
  if (typeof onResend !== 'function') {
    return args.targetPrompt;
  }
  return {
    ...args.targetPrompt,
    onResend,
  };
}

function parseWarmSessionStatusResult(data: unknown): WarmSessionStatusResult | null {
  if (!isObjectRecord(data) || typeof data.ok !== 'boolean') return null;
  if (!data.ok) {
    return {
      ok: false,
      code: typeof data.code === 'string' ? data.code : 'worker_error',
      message: typeof data.message === 'string' ? data.message : 'Warm-session status read failed',
    };
  }
  if (typeof data.remainingUses !== 'number' || typeof data.expiresAtMs !== 'number') return null;
  return {
    ok: true,
    remainingUses: data.remainingUses,
    expiresAtMs: data.expiresAtMs,
  };
}

function parseWarmSessionStatusBatchResult(data: unknown): WarmSessionStatusBatchResult | null {
  if (!isObjectRecord(data) || !Array.isArray(data.results)) return null;
  const results: WarmSessionStatusBatchResult['results'] = [];
  for (const entry of data.results) {
    if (!isObjectRecord(entry) || typeof entry.sessionId !== 'string') return null;
    const result = parseWarmSessionStatusResult(entry.result);
    if (!result) return null;
    results.push({
      sessionId: entry.sessionId,
      result,
    });
  }
  return { results };
}

function parseWarmSessionSealAndPersistDiagnostics(
  data: unknown,
): WarmSessionSealAndPersistDiagnostics | null {
  if (!isObjectRecord(data)) return null;
  return {
    runtimeSetupMs: positiveInteger(data.runtimeSetupMs),
    clientSealMs: positiveInteger(data.clientSealMs),
    serverSealRouteMs: positiveInteger(data.serverSealRouteMs),
    clientUnsealMs: positiveInteger(data.clientUnsealMs),
    policyUpdateMs: positiveInteger(data.policyUpdateMs),
  };
}

function parseWarmSessionSealAndPersistResult(
  data: unknown,
): WarmSessionSealAndPersistResult | null {
  if (!isObjectRecord(data) || typeof data.ok !== 'boolean') return null;
  if (!data.ok) {
    return {
      ok: false,
      code: typeof data.code === 'string' ? data.code : 'worker_error',
      message:
        typeof data.message === 'string' ? data.message : 'Signing-session seal and persist failed',
    };
  }
  if (
    typeof data.sealedSecretB64u !== 'string' ||
    typeof data.remainingUses !== 'number' ||
    typeof data.expiresAtMs !== 'number'
  ) {
    return null;
  }
  const diagnostics = parseWarmSessionSealAndPersistDiagnostics(data.diagnostics);
  return {
    ok: true,
    sealedSecretB64u: data.sealedSecretB64u,
    ...(typeof data.keyVersion === 'string' && data.keyVersion.trim()
      ? { keyVersion: data.keyVersion.trim() }
      : {}),
    remainingUses: data.remainingUses,
    expiresAtMs: data.expiresAtMs,
    ...(diagnostics ? { diagnostics } : {}),
  };
}

function parseWarmSessionClaimResult(data: unknown): WarmSessionClaimResult | null {
  if (!isObjectRecord(data) || typeof data.ok !== 'boolean') return null;
  if (!data.ok) {
    return {
      ok: false,
      code: typeof data.code === 'string' ? data.code : 'worker_error',
      message: typeof data.message === 'string' ? data.message : 'Warm-session claim failed',
    };
  }
  if (
    typeof data.prfFirstB64u !== 'string' ||
    typeof data.remainingUses !== 'number' ||
    typeof data.expiresAtMs !== 'number'
  ) {
    return null;
  }
  return {
    ok: true,
    prfFirstB64u: data.prfFirstB64u,
    remainingUses: data.remainingUses,
    expiresAtMs: data.expiresAtMs,
  };
}

function parseUserConfirmProgressEvent(data: unknown): UserConfirmProgressEvent | null {
  if (!isObjectRecord(data)) return null;
  const requestId = typeof data.requestId === 'string' ? data.requestId.trim() : '';
  const step = typeof data.step === 'number' ? data.step : Number.NaN;
  const phase = typeof data.phase === 'string' ? data.phase : '';
  const status = data.status;
  if (
    !requestId ||
    !Number.isFinite(step) ||
    !phase ||
    (status !== 'running' && status !== 'succeeded' && status !== 'failed')
  ) {
    return null;
  }
  return {
    requestId,
    step,
    phase,
    status,
    ...(typeof data.message === 'string' ? { message: data.message } : {}),
    ...('data' in data ? { data: data.data } : {}),
  };
}

const signingSessionRehydrateSingleFlight = new Map<
  string,
  Promise<WarmSessionStatusResult | null>
>();
const signingSessionSealPersistSingleFlight = new Map<
  string,
  Promise<WarmSessionSealAndPersistResult>
>();
const signingSessionSealDeleteSingleFlight = new Map<string, Promise<void>>();

function makeWarmSessionSingleFlightKey(args: {
  operation: 'rehydrate' | 'persist' | 'delete';
  thresholdSessionId: string;
  authMethod?: SigningSessionSealAuthMethod;
  curve?: 'ed25519' | 'ecdsa';
  walletId?: string;
  chainTarget?: ThresholdEcdsaChainTarget;
  signingGrantId?: string;
}): string {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return '';
  return [
    args.operation,
    String(args.authMethod || '').trim(),
    String(args.curve || '').trim(),
    String(args.walletId || '').trim(),
    args.chainTarget ? thresholdEcdsaChainTargetKey(args.chainTarget) : '',
    String(args.signingGrantId || '').trim(),
    thresholdSessionId,
  ].join('|');
}

/**
 * Concrete implementation for the uiConfirm worker manager ports.
 */
class UiConfirmWorkerManagerImpl implements UiConfirmManager {
  private worker: Worker | null = null;
  private initializationPromise: Promise<void> | null = null;
  private messageId = 0;
  private config: UiConfirmManagerConfig;
  private workerBaseOrigin: string | undefined;
  private context: UiConfirmContext;
  private readonly pendingWorkerRequests = new Map<string, PendingWorkerRequest>();
  private readonly userConfirmProgressListeners = new Map<
    string,
    (progress: UserConfirmProgressEvent) => void
  >();
  private readonly pendingFunctionBearingConfirmRequests = new Map<string, UserConfirmRequest>();
  private readonly boundHandleWorkerMessage = this.handleWorkerMessage.bind(this);
  private readonly boundHandleWorkerError = this.handleWorkerError.bind(this);
  private registrationPreparationModalState: RegistrationPreparationModalState = {
    kind: 'closed',
    generation: 0,
  };

  constructor(
    config: UiConfirmManagerConfig,
    context: UiConfirmContext,
    private readonly passkeyMpcSession: PasskeyMpcSessionDurableWorkerPort,
    private readonly passkeyMpcSessionStatus: Pick<
      PasskeyMpcSessionPort,
      'getWarmSessionStatus'
    >,
  ) {
    this.config = {
      // Default to client-hosted worker file using centralized config
      workerUrl: BUILD_PATHS.RUNTIME.TOUCH_CONFIRM_WORKER,
      workerTimeout: 60_000,
      debug: false,
      signingSessionPersistenceMode: 'none',
      ...config,
    };
    this.context = {
      ...context,
    };
  }

  /** Context used by uiConfirm confirmation flows. */
  getContext(): UiConfirmContext {
    return this.context;
  }

  private async loadEcdsaRoleLocalReadyRecord(
    input: Parameters<UiConfirmContext['loadEcdsaRoleLocalReadyRecord']>[0],
  ): ReturnType<UiConfirmContext['loadEcdsaRoleLocalReadyRecord']> {
    return await this.context.loadEcdsaRoleLocalReadyRecord(input);
  }

  private isSealedRefreshModeEnabled(): boolean {
    return this.config.signingSessionPersistenceMode === 'sealed_refresh_v1';
  }

  private getSealedRefreshNotEnabledError(context: string): {
    ok: false;
    code: string;
    message: string;
  } {
    return {
      ok: false,
      code: 'not_enabled',
      message: `[UiConfirm] ${context} requires signingSessionPersistenceMode="sealed_refresh_v1"`,
    };
  }

  private resolvePasskeySealedRecordPurpose(
    thresholdSessionIdRaw: string,
    explicitCurve?: 'ed25519' | 'ecdsa',
    explicitChainTarget?: ThresholdEcdsaChainTarget,
  ): SigningSessionSealedRecordFilter | null {
    const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
    if (!thresholdSessionId) return null;
    const curve =
      explicitCurve ||
      (getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId)
        ? 'ed25519'
        : undefined) ||
      (explicitChainTarget ? 'ecdsa' : undefined);
    if (!curve) {
      console.warn('[UiConfirm] cannot resolve sealed refresh purpose for passkey session', {
        thresholdSessionId,
      });
      return null;
    }
    if (curve === 'ecdsa') {
      if (!explicitChainTarget) {
        console.warn(
          '[UiConfirm] cannot resolve ECDSA sealed refresh purpose without chain target',
          {
            thresholdSessionId,
          },
        );
        return null;
      }
      return { authMethod: 'passkey', curve, chainTarget: explicitChainTarget };
    }
    return { authMethod: 'passkey', curve };
  }

  private async readPasskeySealedRecord(
    thresholdSessionId: string,
    curve?: 'ed25519' | 'ecdsa',
    chainTarget?: ThresholdEcdsaChainTarget,
  ) {
    const purpose = this.resolvePasskeySealedRecordPurpose(thresholdSessionId, curve, chainTarget);
    if (!purpose) return null;
    return await readExactSealedSession(thresholdSessionId, purpose).catch((error) => {
      console.warn('[UiConfirm] failed to read passkey sealed refresh record', {
        thresholdSessionId,
        purpose,
        error: error instanceof Error ? error.message : String(error || 'unknown error'),
      });
      return null;
    });
  }

  private resolveWarmSessionSealAuthMethod(
    args: WarmSessionSealAuthMethodInput,
  ): SigningSessionSealAuthMethod {
    if (args.curve === 'ed25519') {
      const ed25519Record = getStoredThresholdEd25519SessionRecordByThresholdSessionId(
        args.thresholdSessionId,
      );
      if (!ed25519Record) {
        if (args.authMethod) return args.authMethod;
        throw new Error(
          '[UiConfirm] cannot resolve Ed25519 sealed refresh auth without session record',
        );
      }
      const inferredAuthMethod = sealedAuthMethodForThresholdEd25519Source(ed25519Record.source);
      if (args.authMethod && args.authMethod !== inferredAuthMethod) {
        throw new Error('[UiConfirm] Ed25519 sealed refresh auth does not match session record');
      }
      return inferredAuthMethod;
    }
    if (!args.authMethod) {
      throw new Error('[UiConfirm] ECDSA sealed refresh requires an explicit auth method');
    }
    return args.authMethod;
  }

  private buildPasskeyDurableDeleteCommand(args: {
    thresholdSessionId: string;
    curve?: 'ed25519' | 'ecdsa';
    chainTarget?: ThresholdEcdsaChainTarget;
    deleteReason: DurableSealedSessionDeleteReason;
    preserveResolvedIdentity: boolean;
  }): DeleteDurableSealedSessionCommand | null {
    const thresholdSessionId = String(args.thresholdSessionId || '').trim();
    if (!thresholdSessionId) return null;
    const purpose = this.resolvePasskeySealedRecordPurpose(
      thresholdSessionId,
      args.curve,
      args.chainTarget,
    );
    if (!purpose) return null;
    if (purpose.curve === 'ed25519') {
      return createDeleteDurableSealedSessionCommand({
        durableRecord: {
          authMethod: 'passkey',
          curve: 'ed25519',
          thresholdSessionId,
        },
        deleteReason: args.deleteReason,
        preserveResolvedIdentity: args.preserveResolvedIdentity,
      });
    }
    return createDeleteDurableSealedSessionCommand({
      durableRecord: {
        authMethod: 'passkey',
        curve: 'ecdsa',
        thresholdSessionId,
        chainTarget: purpose.chainTarget,
      },
      deleteReason: args.deleteReason,
      preserveResolvedIdentity: args.preserveResolvedIdentity,
    });
  }

  private async runDurableSealedSessionDelete(
    command: DeleteDurableSealedSessionCommand,
  ): Promise<void> {
    const singleFlightKey =
      command.durableRecord.curve === 'ecdsa'
        ? makeWarmSessionSingleFlightKey({
            operation: 'delete',
            thresholdSessionId: command.durableRecord.thresholdSessionId,
            authMethod: command.durableRecord.authMethod,
            curve: 'ecdsa',
            chainTarget: command.durableRecord.chainTarget,
          })
        : makeWarmSessionSingleFlightKey({
            operation: 'delete',
            thresholdSessionId: command.durableRecord.thresholdSessionId,
            authMethod: command.durableRecord.authMethod,
            curve: 'ed25519',
          });
    const inFlight = signingSessionSealDeleteSingleFlight.get(singleFlightKey);
    if (inFlight) return await inFlight;

    const task = deleteDurableSealedSessionRecordFromStore(command).finally(() => {
      signingSessionSealDeleteSingleFlight.delete(singleFlightKey);
    });
    signingSessionSealDeleteSingleFlight.set(singleFlightKey, task);
    return await task;
  }

  private async deletePasskeyDurableSealedSessionRecord(args: {
    thresholdSessionId: string;
    curve?: 'ed25519' | 'ecdsa';
    chainTarget?: ThresholdEcdsaChainTarget;
    deleteReason: DurableSealedSessionDeleteReason;
    preserveResolvedIdentity: boolean;
  }): Promise<void> {
    const command = this.buildPasskeyDurableDeleteCommand(args);
    if (!command) return;
    await this.runDurableSealedSessionDelete(command).catch(() => undefined);
  }

  private async updatePasskeySealedRecordPolicy(args: {
    thresholdSessionId: string;
    curve?: 'ed25519' | 'ecdsa';
    chainTarget?: ThresholdEcdsaChainTarget;
    expiresAtMs: number;
    remainingUses: number;
  }): Promise<void> {
    const purpose = this.resolvePasskeySealedRecordPurpose(
      args.thresholdSessionId,
      args.curve,
      args.chainTarget,
    );
    if (!purpose) return;
    const existing = await readExactSealedSession(args.thresholdSessionId, purpose).catch(
      () => null,
    );
    if (!existing) return;
    const refreshedMetadata = this.mergePasskeySealedRecordMetadata({
      existing,
      refreshed: {},
    });
    if (existing.curve === 'ecdsa') {
      const walletId = String(refreshedMetadata.walletId || '').trim();
      const relayerUrl = String(existing.relayerUrl || '').trim();
      if (!walletId || !relayerUrl || !refreshedMetadata.ecdsaRestore) {
        throw new Error(
          '[SigningSessionSealedStore] invalid ECDSA sealed session refresh metadata',
        );
      }
      await this.registerSigningSession({
        thresholdSessionId: args.thresholdSessionId,
        sealedSecretB64u: existing.sealedSecretB64u,
        curve: 'ecdsa',
        authMethod: 'passkey',
        signingGrantId: existing.signingGrantId,
        thresholdSessionIds: existing.thresholdSessionIds,
        walletId,
        relayerUrl,
        keyVersion: existing.keyVersion,
        groupId: existing.groupId,
        ecdsaRestore: refreshedMetadata.ecdsaRestore,
        ...(refreshedMetadata.ed25519Restore
          ? { ed25519Restore: refreshedMetadata.ed25519Restore }
          : {}),
        issuedAtMs: existing.issuedAtMs,
        expiresAtMs: args.expiresAtMs,
        remainingUses: args.remainingUses,
        updatedAtMs: Date.now(),
      });
    } else {
      const walletId = String(refreshedMetadata.walletId || '').trim();
      const relayerUrl = String(existing.relayerUrl || '').trim();
      if (!walletId || !relayerUrl || !refreshedMetadata.ed25519Restore) {
        throw new Error(
          '[SigningSessionSealedStore] invalid Ed25519 sealed session refresh metadata',
        );
      }
      await this.registerSigningSession({
        thresholdSessionId: args.thresholdSessionId,
        sealedSecretB64u: existing.sealedSecretB64u,
        curve: 'ed25519',
        authMethod: 'passkey',
        signingGrantId: existing.signingGrantId,
        thresholdSessionIds: existing.thresholdSessionIds,
        walletId,
        ...(refreshedMetadata.signingRootId
          ? { signingRootId: refreshedMetadata.signingRootId }
          : {}),
        ...(refreshedMetadata.signingRootVersion
          ? { signingRootVersion: refreshedMetadata.signingRootVersion }
          : {}),
        relayerUrl,
        keyVersion: existing.keyVersion,
        groupId: existing.groupId,
        ...(refreshedMetadata.ecdsaRestore ? { ecdsaRestore: refreshedMetadata.ecdsaRestore } : {}),
        ed25519Restore: refreshedMetadata.ed25519Restore,
        issuedAtMs: existing.issuedAtMs,
        expiresAtMs: args.expiresAtMs,
        remainingUses: args.remainingUses,
        updatedAtMs: Date.now(),
      });
    }
  }

  private async markPasskeySealedRecordExhausted(args: {
    thresholdSessionId: string;
    curve?: 'ed25519' | 'ecdsa';
    chainTarget?: ThresholdEcdsaChainTarget;
  }): Promise<void> {
    const existing = await this.readPasskeySealedRecord(
      args.thresholdSessionId,
      args.curve,
      args.chainTarget,
    );
    if (!existing) return;
    await this.updatePasskeySealedRecordPolicy({
      thresholdSessionId: args.thresholdSessionId,
      curve: args.curve,
      chainTarget: args.chainTarget,
      expiresAtMs: existing.expiresAtMs,
      remainingUses: 0,
    });
  }

  private async markPasskeySealedRecordExpired(args: {
    thresholdSessionId: string;
    curve?: 'ed25519' | 'ecdsa';
    chainTarget?: ThresholdEcdsaChainTarget;
    observation: PasskeyExpiryObservation;
  }): Promise<void> {
    const existing = await this.readPasskeySealedRecord(
      args.thresholdSessionId,
      args.curve,
      args.chainTarget,
    );
    if (!existing) return;
    const observedExpiresAtMs =
      args.observation.kind === 'policy' ? args.observation.expiresAtMs : existing.expiresAtMs;
    const observedRemainingUses =
      args.observation.kind === 'policy' ? args.observation.remainingUses : existing.remainingUses;
    await this.updatePasskeySealedRecordPolicy({
      thresholdSessionId: args.thresholdSessionId,
      curve: args.curve,
      chainTarget: args.chainTarget,
      expiresAtMs: Math.min(observedExpiresAtMs, Date.now()),
      remainingUses: Math.max(0, observedRemainingUses),
    });
  }

  async recordPasskeyWarmSessionPolicyResult(
    purpose: WarmSessionLanePurpose,
    policyResult: WarmSessionStatusResult | WarmSessionClaimResult,
  ): Promise<void> {
    const args = {
      sessionId: purpose.thresholdSessionId,
      curve: purpose.curve,
      chainTarget: purpose.curve === 'ecdsa' ? purpose.chainTarget : undefined,
      result: policyResult,
    };
    const result = args.result;
    if (result.ok) {
      if (result.remainingUses <= 0 || Date.now() >= result.expiresAtMs) {
        if (result.remainingUses <= 0) {
          await this.updatePasskeySealedRecordPolicy({
            thresholdSessionId: args.sessionId,
            curve: args.curve,
            chainTarget: args.chainTarget,
            expiresAtMs: result.expiresAtMs,
            remainingUses: 0,
          });
          return;
        }
        await this.markPasskeySealedRecordExpired({
          thresholdSessionId: args.sessionId,
          curve: args.curve,
          chainTarget: args.chainTarget,
          observation: {
            kind: 'policy',
            expiresAtMs: result.expiresAtMs,
            remainingUses: result.remainingUses,
          },
        });
        return;
      }
      await this.updatePasskeySealedRecordPolicy({
        thresholdSessionId: args.sessionId,
        curve: args.curve,
        chainTarget: args.chainTarget,
        expiresAtMs: result.expiresAtMs,
        remainingUses: result.remainingUses,
      });
      return;
    }
    if (result.code === 'expired') {
      await this.markPasskeySealedRecordExpired({
        thresholdSessionId: args.sessionId,
        curve: args.curve,
        chainTarget: args.chainTarget,
        observation: { kind: 'status_code' },
      });
    }
    if (result.code === 'exhausted') {
      await this.markPasskeySealedRecordExhausted({
        thresholdSessionId: args.sessionId,
        curve: args.curve,
        chainTarget: args.chainTarget,
      });
    }
  }

  private async recordSessionMaterialRestored(
    purpose: WarmSessionLanePurpose,
    result: WarmSessionStatusResult,
  ): Promise<void> {
    await this.recordPasskeyWarmSessionPolicyResult(purpose, result);
  }

  private async registerSigningSession(
    record: BuildCurrentSealedSessionRecordInput,
  ): Promise<void> {
    const currentRecord = buildCurrentSealedSessionRecord(record);
    if (!currentRecord) {
      throw new Error('[SigningSessionSealedStore] invalid sealed session record write input');
    }
    await writeExactSealedSession(currentRecord);
  }

  private mergePasskeySealedRecordMetadata(args: {
    existing?: CurrentSealedSessionRecord | null;
    refreshed: PasskeySealedRecordAccountMetadata;
  }): PasskeySealedRecordAccountMetadata {
    const existing = args.existing;
    const ed25519Restore = args.refreshed.ed25519Restore || existing?.ed25519Restore;
    return {
      ...(args.refreshed.walletId || existing?.walletId
        ? { walletId: args.refreshed.walletId || existing?.walletId }
        : {}),
      ...(args.refreshed.signingRootId || existing?.signingRootId
        ? { signingRootId: args.refreshed.signingRootId || existing?.signingRootId }
        : {}),
      ...(args.refreshed.signingRootVersion || existing?.signingRootVersion
        ? {
            signingRootVersion: args.refreshed.signingRootVersion || existing?.signingRootVersion,
          }
        : {}),
      ...(args.refreshed.ecdsaRestore || existing?.ecdsaRestore
        ? { ecdsaRestore: args.refreshed.ecdsaRestore || existing?.ecdsaRestore }
        : {}),
      ...(ed25519Restore ? { ed25519Restore } : {}),
    };
  }

  private async resolveSealTransportInput(
    thresholdSessionIdRaw: string,
    explicitTransport: WarmSessionSealTransportInput | null,
    sealedRecordInput: CurrentSealedSessionRecord | null,
  ): Promise<WarmSessionSealTransportInput | null> {
    const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
    if (!thresholdSessionId) return null;
    const ed25519Record =
      getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId);
    const curve =
      explicitTransport?.curve ||
      sealedRecordInput?.curve ||
      (ed25519Record ? 'ed25519' : undefined);
    const authMethod = explicitTransport?.authMethod || sealedRecordInput?.authMethod;
    const sealedRecord =
      sealedRecordInput ||
      (await this.readPasskeySealedRecord(
        thresholdSessionId,
        curve,
        explicitTransport?.curve === 'ecdsa' ? explicitTransport.chainTarget : undefined,
      ));
    const relayerUrl = String(
      explicitTransport?.relayerUrl || sealedRecord?.relayerUrl || ed25519Record?.relayerUrl || '',
    ).trim();
    if (!relayerUrl) return null;
    const explicitWalletSessionJwt = String(explicitTransport?.walletSessionJwt || '').trim();
    const walletSessionJwt = explicitWalletSessionJwt;
    if (authMethod === 'email_otp' && !explicitWalletSessionJwt) {
      return null;
    }
    const signingGrantId = String(
      explicitTransport?.signingGrantId ||
        sealedRecord?.signingGrantId ||
        ed25519Record?.signingGrantId ||
        '',
    ).trim();
    const walletId = String(
      explicitTransport?.walletId || sealedRecord?.walletId || ed25519Record?.walletId || '',
    ).trim();
    const signingSessionSealKeyVersion = firstSigningSessionSealKeyVersion([
      explicitTransport?.signingSessionSealKeyVersion,
      sealedRecord?.keyVersion,
      this.config.signingSessionSealKeyVersion,
    ]);
    const groupId = String(
      explicitTransport?.groupId ||
        sealedRecord?.groupId ||
        this.config.signingSessionSealGroupId ||
        '',
    ).trim();
    if (curve === 'ecdsa') {
      const explicitEcdsaTransport =
        explicitTransport?.curve === 'ecdsa' ? explicitTransport : null;
      const sealedEcdsaRecord = sealedRecord?.curve === 'ecdsa' ? sealedRecord : null;
      const chainTarget =
        explicitEcdsaTransport?.chainTarget || sealedEcdsaRecord?.ecdsaRestore.chainTarget;
      if (!chainTarget) return null;
      const ecdsaBase = {
        curve,
        ...(walletId ? { walletId } : {}),
        chainTarget,
        relayerUrl,
        ...(signingGrantId ? { signingGrantId } : {}),
        ...(signingSessionSealKeyVersion ? { signingSessionSealKeyVersion } : {}),
        ...(groupId ? { groupId } : {}),
      };
      if (authMethod === 'email_otp') {
        if (!walletSessionJwt) return null;
        return {
          ...ecdsaBase,
          authMethod: 'email_otp',
          walletSessionJwt,
        };
      }
      let ecdsaRestore =
        explicitEcdsaTransport?.authMethod !== 'email_otp'
          ? explicitEcdsaTransport?.ecdsaRestore
          : undefined;
      if (!ecdsaRestore && sealedEcdsaRecord?.authMethod === 'passkey') {
        const sealedRestore = sealedEcdsaRecord.ecdsaRestore;
        if (sealedRestore.source !== 'email_otp') {
          ecdsaRestore = sealedRestore;
        }
      }
      if (!ecdsaRestore) return null;
      return {
        ...ecdsaBase,
        ...(authMethod === 'passkey' ? { authMethod } : {}),
        ...(walletSessionJwt ? { walletSessionJwt } : {}),
        ecdsaRestore,
      };
    }
    if (curve !== 'ed25519') return null;
    const ed25519Base = {
      curve,
      ...(walletId ? { walletId } : {}),
      relayerUrl,
      ...(signingGrantId ? { signingGrantId } : {}),
      ...(signingSessionSealKeyVersion ? { signingSessionSealKeyVersion } : {}),
      ...(groupId ? { groupId } : {}),
    } as const;
    if (authMethod === 'email_otp') {
      if (!walletSessionJwt) return null;
      return {
        ...ed25519Base,
        authMethod: 'email_otp',
        walletSessionJwt,
      };
    }
    return {
      ...ed25519Base,
      ...(authMethod === 'passkey' ? { authMethod } : {}),
      ...(walletSessionJwt ? { walletSessionJwt } : {}),
    };
  }

  private buildPasskeySealedRecordAccountMetadata(args: {
    thresholdSessionId: string;
    transport: WarmSessionSealTransportInput;
  }): PasskeySealedRecordAccountMetadata {
    if (args.transport.curve === 'ecdsa') {
      if (args.transport.authMethod === 'email_otp') return {};
      return {
        ...(args.transport.walletId ? { walletId: args.transport.walletId } : {}),
        ecdsaRestore: args.transport.ecdsaRestore,
      };
    }
    const ed25519Record = getStoredThresholdEd25519SessionRecordByThresholdSessionId(
      args.thresholdSessionId,
    );
    const walletId = String(ed25519Record?.walletId || args.transport.walletId || '').trim();
    const ed25519Restore = currentEd25519RestoreMetadataFromSessionRecord(ed25519Record);
    if (ed25519Record && !ed25519Restore) {
      console.warn('[UiConfirm] skipping incomplete Ed25519 durable session metadata', {
        thresholdSessionId: args.thresholdSessionId,
        curve: args.transport.curve,
        walletId: String(ed25519Record.walletId || args.transport.walletId || '').trim(),
        source: ed25519Record.source,
        missingFields: ed25519RestoreMetadataMissingFields(ed25519Record),
      });
    }
    return {
      ...(walletId ? { walletId } : {}),
      ...(ed25519Record?.signingRootId ? { signingRootId: ed25519Record.signingRootId } : {}),
      ...(ed25519Record?.signingRootVersion
        ? { signingRootVersion: ed25519Record.signingRootVersion }
        : {}),
      ...(ed25519Restore ? { ed25519Restore } : {}),
    };
  }

  async ensurePasskeySealedRecordPersisted(args: {
    sessionId: string;
    transport: WarmSessionSealTransportInput;
    diagnostics?: WarmSessionMaterialWriteDiagnostics;
  }): Promise<WarmSessionSealAndPersistResult | null> {
    const thresholdSessionIdRaw = args.sessionId;
    const transport = args.transport;
    const diagnostics = args.diagnostics;
    if (!this.isSealedRefreshModeEnabled()) return null;
    const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
    if (!thresholdSessionId) return null;
    const resolvedTransport = await this.resolveSealTransportInput(
      thresholdSessionId,
      transport || null,
      null,
    );
    if (!resolvedTransport) return null;
    const persisted = await this.persistSigningSessionSealForThresholdSession({
      sessionId: thresholdSessionId,
      transport: resolvedTransport,
      ...(diagnostics ? { diagnostics } : {}),
    });
    return persisted.ok || persisted.code !== 'missing_restore_metadata' ? persisted : null;
  }

  private async restorePasskeySealedRecordForWallet(args: {
    walletId: string;
    record: SealedRecoveryRecord;
    purpose: RestorePersistedSessionPurpose;
  }): Promise<RestoreSealedRecordResult> {
    if (!this.isSealedRefreshModeEnabled()) return 'deferred';
    if (args.purpose.authMethod !== 'passkey') return 'deferred';
    const thresholdSessionId = String(args.purpose.thresholdSessionId || '').trim();
    if (!thresholdSessionId) return 'deferred';
    if (args.record.authMethod !== 'passkey') return 'deferred';
    const passkeyRecord = args.record;
    const curve = 'ecdsa';
    const chainTarget = args.purpose.chainTarget;
    if (!chainTarget) return 'deferred';
    if (!thresholdEcdsaChainTargetsEqual(args.record.chainTarget, chainTarget)) {
      return 'deferred';
    }
    const singleFlightKey = makeWarmSessionSingleFlightKey({
      operation: 'rehydrate',
      thresholdSessionId,
      authMethod: 'passkey',
      curve,
      chainTarget,
      signingGrantId: args.purpose.signingGrantId,
    });

    const inFlight = signingSessionRehydrateSingleFlight.get(singleFlightKey);
    if (inFlight) {
      const result = await inFlight;
      return requirePasskeyEcdsaRestoreOutcome(result, 'ready');
    }

    const task = (async (): Promise<WarmSessionStatusResult | null> => {
      const purpose =
        curve === 'ecdsa'
          ? {
              authMethod: 'passkey' as const,
              curve: 'ecdsa' as const,
              chainTarget: chainTarget!,
            }
          : { authMethod: 'passkey' as const, curve: 'ed25519' as const };
      const sealedRecordFilter: SigningSessionSealedRecordFilter = purpose;
      const deleteInvalidPersistedRecord = async (): Promise<void> => {
        if (curve === 'ecdsa') {
          if (!chainTarget) return;
          await this.deletePasskeyDurableSealedSessionRecord({
            thresholdSessionId,
            curve: 'ecdsa',
            chainTarget,
            deleteReason: 'invalid_persisted_record',
            preserveResolvedIdentity: false,
          });
          return;
        }
        await this.deletePasskeyDurableSealedSessionRecord({
          thresholdSessionId,
          curve: 'ed25519',
          deleteReason: 'invalid_persisted_record',
          preserveResolvedIdentity: false,
        });
      };
      const lease = await acquireSigningSessionRestoreLease({
        thresholdSessionId,
        ...purpose,
      });
      if (!lease) return null;
      try {
        const walletSessionJwt = sealedRecoveryWalletSessionJwt(args.record.walletSessionAuth);
        const ecdsaRestore = await passkeyEcdsaRestoreMetadataFromRecoveryRecord(passkeyRecord);
        const transport = await this.resolveSealTransportInput(
          thresholdSessionId,
          {
            curve,
            authMethod: 'passkey',
            walletId: args.walletId,
            chainTarget,
            relayerUrl: passkeyRecord.relayerUrl,
            signingGrantId: args.purpose.signingGrantId,
            signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(args.record.keyVersion),
            groupId: args.record.groupId,
            ...(walletSessionJwt ? { walletSessionJwt } : {}),
            ecdsaRestore,
          },
          null,
        );
        if (!transport) return null;
        const groupId = String(args.record.groupId || transport.groupId || '').trim();
        if (!groupId) return null;

        if (
          curve !== 'ecdsa' ||
          !chainTarget ||
          args.purpose.curve !== 'ecdsa' ||
          args.purpose.authMethod !== 'passkey' ||
          args.record.authMethod !== 'passkey' ||
          args.record.curve !== 'ecdsa'
        ) {
          return null;
        }
        return await restorePasskeyEcdsaSealedRecordForWallet({
          walletId: args.walletId,
          record: args.record,
          purpose: { ...args.purpose, authMethod: 'passkey' },
          transport,
          groupId,
          rehydrateWarmSessionMaterial: (rehydrateArgs) =>
            this.rehydrateWarmSessionMaterial(rehydrateArgs),
          deletePersistedRecord: deleteInvalidPersistedRecord,
          recordSessionMaterialRestored: async (status) =>
            await this.recordSessionMaterialRestored(
              curve === 'ecdsa' && chainTarget
                ? { curve: 'ecdsa', thresholdSessionId, chainTarget }
                : { curve: 'ed25519', thresholdSessionId },
              status,
            ),
          readWarmSessionStatusFromWorker: async (sessionId) => {
            return await this.passkeyMpcSessionStatus.getWarmSessionStatus({ sessionId });
          },
          updatePersistedPolicy: async (policy) =>
            await updateExactSealedSessionPolicy({
              thresholdSessionId,
              filter: sealedRecordFilter,
              ...policy,
            }),
        });
      } finally {
        await releaseSigningSessionRestoreLease(lease);
      }
    })().finally(() => {
      signingSessionRehydrateSingleFlight.delete(singleFlightKey);
    });

    signingSessionRehydrateSingleFlight.set(singleFlightKey, task);
    const result = await task;
    return requirePasskeyEcdsaRestoreOutcome(result, 'restored');
  }

  sealAndPersistWarmSessionMaterial = async (
    args: WarmSessionSealAndPersistPayload,
  ): Promise<WarmSessionSealAndPersistResult> => {
    if (!this.isSealedRefreshModeEnabled()) {
      return this.getSealedRefreshNotEnabledError('signing-session seal and persist');
    }
    return await this.passkeyMpcSession.sealAndPersistWarmSessionMaterial(args);
  };

  rehydrateWarmSessionMaterial = async (
    args: WarmSessionRehydratePayload,
  ): Promise<WarmSessionRehydrateResult> => {
    if (!this.isSealedRefreshModeEnabled()) {
      return this.getSealedRefreshNotEnabledError('signing-session rehydrate');
    }
    return await this.passkeyMpcSession.rehydrateWarmSessionMaterial(args);
  };

  restorePersistedSessionForSigning = async (
    args: {
      authMethod: 'passkey';
    } & RestorePersistedSessionForSigningInput,
  ): Promise<RestorePersistedSessionForSigningResult> => {
    if (args.authMethod !== 'passkey' || !this.isSealedRefreshModeEnabled()) {
      return { kind: 'completed', attempted: 0, restored: 0, deferred: 0 };
    }
    return await restorePersistedSessionForSigningCommand(args, {
      listExactSealedSessionsForWallet: async (filter) => {
        return await listExactSealedSessionsForWallet({
          walletId: filter.walletId,
          filter:
            filter.curve === 'ecdsa'
              ? {
                  authMethod: filter.authMethod,
                  curve: 'ecdsa',
                  chainTarget: filter.chainTarget,
                }
              : { authMethod: filter.authMethod, curve: 'ed25519' },
        });
      },
      restoreSealedRecordForWallet: (restoreArgs) =>
        this.restorePasskeySealedRecordForWallet({
          walletId: restoreArgs.walletId,
          record: restoreArgs.record,
          purpose: restoreArgs.purpose,
        }),
      onListError: ({ walletId, target, reason, error }) => {
        console.warn('[UiConfirm] passkey signing-session restore list failed', {
          walletId,
          target,
          reason,
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
      },
      onRejectedRecord: ({ walletId, rejection }) => {
        console.warn('[UiConfirm] passkey signing-session restore rejected record', {
          walletId,
          rejection,
        });
      },
    });
  };

  discoverPersistedSessionsForWallet = async (
    args: Parameters<WarmSessionPersistedRestorer['discoverPersistedSessionsForWallet']>[0],
  ): Promise<DiscoverPersistedSessionsForWalletResult> => {
    if (!this.isSealedRefreshModeEnabled()) {
      return { listed: 0, discovered: 0, truncated: 0 };
    }
    return await discoverPersistedSessionsForWalletCommand(
      {
        ...args,
        authMethod: 'passkey',
      },
      {
        listExactSealedSessionsForWallet: async (filter) =>
          await listExactSealedSessionsForWallet({
            walletId: filter.walletId,
            filter:
              filter.curve === 'ecdsa'
                ? {
                    authMethod: 'passkey',
                    curve: 'ecdsa',
                    chainTarget: filter.chainTarget,
                  }
                : { authMethod: 'passkey', curve: 'ed25519' },
          }),
        onListError: ({ walletId, error }) => {
          console.warn('[UiConfirm] passkey account signing-session discovery list failed', {
            walletId,
            error: error instanceof Error ? error.message : String(error || 'unknown error'),
          });
        },
        onRejectedRecord: ({ walletId, rejection }) => {
          console.warn('[UiConfirm] passkey account signing-session discovery rejected record', {
            walletId,
            rejection,
          });
        },
      },
    );
  };

  persistSigningSessionSealForThresholdSession = async (args: {
    sessionId: string;
    transport?: WarmSessionSealTransportInput;
    diagnostics?: WarmSessionMaterialWriteDiagnostics;
  }): Promise<WarmSessionSealAndPersistResult> => {
    if (!this.isSealedRefreshModeEnabled()) {
      return this.getSealedRefreshNotEnabledError('signing-session seal persistence');
    }
    const diagnostics = args.diagnostics;
    const thresholdSessionId = String(args?.sessionId || '').trim();
    if (!thresholdSessionId) {
      return { ok: false, code: 'invalid_args', message: 'Missing threshold sessionId' };
    }
    const resolveTransportStartedAt = performance.now();
    const inferredTransport =
      (await this.resolveSealTransportInput(thresholdSessionId, args?.transport || null, null)) ||
      null;
    recordWarmSessionMaterialWriteDiagnosticDuration({
      diagnostics,
      bucket: 'sealed_record_resolve_transport',
      startedAt: resolveTransportStartedAt,
    });
    const curve = args?.transport?.curve || inferredTransport?.curve;
    if (!curve) {
      console.warn('[UiConfirm] cannot persist sealed refresh without passkey curve', {
        thresholdSessionId,
      });
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Missing curve for signing-session seal persistence',
      };
    }
    const signingGrantId = String(
      args?.transport?.signingGrantId || inferredTransport?.signingGrantId || '',
    ).trim();
    if (!signingGrantId) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Missing signingGrantId for signing-session seal persistence',
      };
    }
    let ecdsaTransportChainTarget: ThresholdEcdsaChainTarget | undefined;
    if (curve === 'ecdsa') {
      if (args.transport?.curve === 'ecdsa') {
        ecdsaTransportChainTarget = args.transport.chainTarget;
      } else if (inferredTransport?.curve === 'ecdsa') {
        ecdsaTransportChainTarget = inferredTransport.chainTarget;
      }
    }
    const resolvedMetadataTransport = args.transport || inferredTransport;
    if (!resolvedMetadataTransport) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Missing transport for signing-session seal persistence',
      };
    }
    const recordMetadata = this.buildPasskeySealedRecordAccountMetadata({
      thresholdSessionId,
      transport: resolvedMetadataTransport,
    });
    if (curve === 'ed25519' && !recordMetadata.ed25519Restore) {
      return {
        ok: false,
        code: 'missing_restore_metadata',
        message: 'Ed25519 signing-session seal persistence requires session restore metadata',
      };
    }
    const chainTarget = curve === 'ecdsa' ? recordMetadata.ecdsaRestore?.chainTarget : undefined;
    const explicitAuthMethod = args.transport?.authMethod || inferredTransport?.authMethod;
    if (curve === 'ecdsa' && !chainTarget) {
      const transportChainTargetKey = ecdsaTransportChainTarget
        ? thresholdEcdsaChainTargetKey(ecdsaTransportChainTarget)
        : 'missing';
      return {
        ok: false,
        code: 'invalid_args',
        message: `Missing concrete ECDSA chain target for signing-session seal persistence (thresholdSessionId=${thresholdSessionId}, transportChainTarget=${transportChainTargetKey})`,
      };
    }
    let purpose: SigningSessionSealedRecordFilter;
    let authMethod: SigningSessionSealAuthMethod;
    if (curve === 'ecdsa') {
      if (!chainTarget) {
        return {
          ok: false,
          code: 'invalid_args',
          message: 'Missing concrete ECDSA chain target for signing-session seal persistence',
        };
      }
      authMethod = this.resolveWarmSessionSealAuthMethod({
        thresholdSessionId,
        curve: 'ecdsa',
        ...(explicitAuthMethod ? { authMethod: explicitAuthMethod } : {}),
        chainTarget,
      });
      purpose = { authMethod, curve: 'ecdsa', chainTarget };
    } else {
      authMethod = this.resolveWarmSessionSealAuthMethod({
        thresholdSessionId,
        curve: 'ed25519',
        ...(explicitAuthMethod ? { authMethod: explicitAuthMethod } : {}),
      });
      purpose = { authMethod, curve: 'ed25519' };
    }
    const singleFlightKey = makeWarmSessionSingleFlightKey({
      operation: 'persist',
      thresholdSessionId,
      authMethod,
      curve,
      ...(chainTarget ? { chainTarget } : {}),
      signingGrantId,
    });
    const inFlight = signingSessionSealPersistSingleFlight.get(singleFlightKey);
    if (inFlight) {
      console.debug('[UiConfirm] joined in-flight sealed refresh persistence', {
        thresholdSessionId,
        authMethod,
        curve,
        signingGrantId,
      });
      return await inFlight;
    }

    const task = (async (): Promise<WarmSessionSealAndPersistResult> => {
      const existingRecordReadStartedAt = performance.now();
      const existingRecord = await readExactSealedSession(thresholdSessionId, purpose).catch(
        (error) => {
          console.warn('[UiConfirm] failed to read sealed refresh record', {
            thresholdSessionId,
            purpose,
            error: error instanceof Error ? error.message : String(error || 'unknown error'),
          });
          return null;
        },
      );
      recordWarmSessionMaterialWriteDiagnosticDuration({
        diagnostics,
        bucket: 'sealed_record_existing_read',
        startedAt: existingRecordReadStartedAt,
      });
      if (existingRecord) {
        const policyReadStartedAt = performance.now();
        const currentPolicy = await this.passkeyMpcSessionStatus.getWarmSessionStatus({
          sessionId: thresholdSessionId,
        }).catch(() => null);
        recordWarmSessionMaterialWriteDiagnosticDuration({
          diagnostics,
          bucket: 'sealed_record_policy_read',
          startedAt: policyReadStartedAt,
        });
        const nextExpiresAtMs = currentPolicy?.ok
          ? currentPolicy.expiresAtMs
          : existingRecord.expiresAtMs;
        const nextRemainingUses = currentPolicy?.ok
          ? currentPolicy.remainingUses
          : existingRecord.remainingUses;
        const refreshedMetadata = this.mergePasskeySealedRecordMetadata({
          existing: existingRecord,
          refreshed: recordMetadata,
        });
        if (existingRecord.curve === 'ecdsa') {
          const walletId = String(refreshedMetadata.walletId || '').trim();
          const relayerUrl = String(existingRecord.relayerUrl || '').trim();
          if (!walletId || !relayerUrl || !refreshedMetadata.ecdsaRestore) {
            throw new Error(
              '[SigningSessionSealedStore] invalid ECDSA persisted-session refresh metadata',
            );
          }
          const registerStartedAt = performance.now();
          await this.registerSigningSession({
            thresholdSessionId,
            sealedSecretB64u: existingRecord.sealedSecretB64u,
            curve: 'ecdsa',
            authMethod,
            signingGrantId,
            thresholdSessionIds: existingRecord.thresholdSessionIds,
            walletId,
            relayerUrl,
            keyVersion: existingRecord.keyVersion,
            groupId: existingRecord.groupId,
            ecdsaRestore: refreshedMetadata.ecdsaRestore,
            ...(refreshedMetadata.ed25519Restore
              ? { ed25519Restore: refreshedMetadata.ed25519Restore }
              : {}),
            issuedAtMs: existingRecord.issuedAtMs,
            expiresAtMs: nextExpiresAtMs,
            remainingUses: nextRemainingUses,
            updatedAtMs: Date.now(),
          });
          recordWarmSessionMaterialWriteDiagnosticDuration({
            diagnostics,
            bucket: 'sealed_record_register',
            startedAt: registerStartedAt,
          });
        } else {
          const walletId = String(refreshedMetadata.walletId || '').trim();
          const relayerUrl = String(existingRecord.relayerUrl || '').trim();
          if (!walletId || !relayerUrl || !refreshedMetadata.ed25519Restore) {
            throw new Error(
              '[SigningSessionSealedStore] invalid Ed25519 persisted-session refresh metadata',
            );
          }
          const registerStartedAt = performance.now();
          await this.registerSigningSession({
            thresholdSessionId,
            sealedSecretB64u: existingRecord.sealedSecretB64u,
            curve: 'ed25519',
            authMethod,
            signingGrantId,
            thresholdSessionIds: existingRecord.thresholdSessionIds,
            walletId,
            ...(refreshedMetadata.signingRootId
              ? { signingRootId: refreshedMetadata.signingRootId }
              : {}),
            ...(refreshedMetadata.signingRootVersion
              ? { signingRootVersion: refreshedMetadata.signingRootVersion }
              : {}),
            relayerUrl,
            keyVersion: existingRecord.keyVersion,
            groupId: existingRecord.groupId,
            ...(refreshedMetadata.ecdsaRestore
              ? { ecdsaRestore: refreshedMetadata.ecdsaRestore }
              : {}),
            ed25519Restore: refreshedMetadata.ed25519Restore,
            issuedAtMs: existingRecord.issuedAtMs,
            expiresAtMs: nextExpiresAtMs,
            remainingUses: nextRemainingUses,
            updatedAtMs: Date.now(),
          });
          recordWarmSessionMaterialWriteDiagnosticDuration({
            diagnostics,
            bucket: 'sealed_record_register',
            startedAt: registerStartedAt,
          });
        }
        return {
          ok: true,
          sealedSecretB64u: existingRecord.sealedSecretB64u,
          ...(existingRecord.keyVersion ? { keyVersion: existingRecord.keyVersion } : {}),
          remainingUses: nextRemainingUses,
          expiresAtMs: nextExpiresAtMs,
        };
      }
      const relayerUrl = String(
        args?.transport?.relayerUrl || inferredTransport?.relayerUrl || '',
      ).trim();
      const walletSessionJwt = String(
        args?.transport?.walletSessionJwt || inferredTransport?.walletSessionJwt || '',
      ).trim();
      const signingSessionSealKeyVersion = firstSigningSessionSealKeyVersion([
        args?.transport?.signingSessionSealKeyVersion,
        inferredTransport?.signingSessionSealKeyVersion,
        this.config.signingSessionSealKeyVersion,
      ]);
      const resolvedGroupId = String(
        args?.transport?.groupId ||
          inferredTransport?.groupId ||
          this.config.signingSessionSealGroupId ||
          '',
      ).trim();

      if (!relayerUrl) {
        return {
          ok: false,
          code: 'invalid_args',
          message: 'Missing relayerUrl for signing-session seal persistence',
        };
      }
      if (resolvedGroupId !== SIGNING_SESSION_SEAL_GROUP_ID) {
        return {
          ok: false,
          code: 'invalid_args',
          message: 'Unsupported groupId for signing-session seal persistence',
        };
      }
      let transport: WarmSessionSealTransportInput;
      if (curve === 'ecdsa') {
        if (!chainTarget) {
          return {
            ok: false,
            code: 'invalid_args',
            message: 'Missing ECDSA chain target for signing-session seal persistence',
          };
        }
        if (authMethod === 'email_otp') {
          if (!walletSessionJwt) {
            return {
              ok: false,
              code: 'invalid_args',
              message: 'Missing Wallet Session JWT for Email OTP seal persistence',
            };
          }
          transport = {
            curve: 'ecdsa',
            authMethod: 'email_otp',
            chainTarget,
            relayerUrl,
            signingGrantId,
            walletSessionJwt,
            ...(signingSessionSealKeyVersion ? { signingSessionSealKeyVersion } : {}),
            groupId: resolvedGroupId,
          };
        } else {
          const passkeyEcdsaRestore =
            recordMetadata.ecdsaRestore?.source !== 'email_otp'
              ? recordMetadata.ecdsaRestore
              : undefined;
          transport = {
            curve: 'ecdsa',
            authMethod: 'passkey',
            chainTarget,
            relayerUrl,
            signingGrantId,
            ...(walletSessionJwt ? { walletSessionJwt } : {}),
            ...(signingSessionSealKeyVersion ? { signingSessionSealKeyVersion } : {}),
            groupId: resolvedGroupId,
            ...(passkeyEcdsaRestore ? { ecdsaRestore: passkeyEcdsaRestore } : {}),
          };
        }
      } else if (authMethod === 'email_otp') {
        if (!walletSessionJwt) {
          return {
            ok: false,
            code: 'invalid_args',
            message: 'Missing Wallet Session JWT for Email OTP seal persistence',
          };
        }
        transport = {
          curve: 'ed25519',
          authMethod: 'email_otp',
          relayerUrl,
          signingGrantId,
          walletSessionJwt,
          ...(signingSessionSealKeyVersion ? { signingSessionSealKeyVersion } : {}),
          groupId: resolvedGroupId,
        };
      } else {
        transport = {
          curve: 'ed25519',
          authMethod: 'passkey',
          relayerUrl,
          signingGrantId,
          ...(walletSessionJwt ? { walletSessionJwt } : {}),
          ...(signingSessionSealKeyVersion ? { signingSessionSealKeyVersion } : {}),
          groupId: resolvedGroupId,
        };
      }
      const applyServerSealStartedAt = performance.now();
      const sealed = await this.sealAndPersistWarmSessionMaterial({
        sessionId: thresholdSessionId,
        transport,
      });
      recordWarmSessionMaterialWriteDiagnosticDuration({
        diagnostics,
        bucket: 'sealed_record_apply_server_seal',
        startedAt: applyServerSealStartedAt,
      });
      recordWarmSessionSealAndPersistResultDiagnostics({
        diagnostics,
        resultDiagnostics: sealed.ok ? sealed.diagnostics : undefined,
      });
      if (!sealed.ok) return sealed;
      const sealedKeyVersion = String(sealed.keyVersion || '').trim();
      if (!sealedKeyVersion) {
        return {
          ok: false,
          code: 'invalid_key_version',
          message: 'Signing-session seal response did not include a key version',
        };
      }

      if (curve === 'ecdsa') {
        const walletId = String(recordMetadata.walletId || '').trim();
        if (!walletId || !recordMetadata.ecdsaRestore) {
          throw new Error('[SigningSessionSealedStore] missing ECDSA seal metadata');
        }
        const persistedAtMs = Date.now();
        const registerStartedAt = performance.now();
        await this.registerSigningSession({
          thresholdSessionId,
          sealedSecretB64u: sealed.sealedSecretB64u,
          curve: 'ecdsa',
          authMethod,
          signingGrantId,
          walletId,
          ecdsaRestore: recordMetadata.ecdsaRestore,
          ...(recordMetadata.ed25519Restore
            ? { ed25519Restore: recordMetadata.ed25519Restore }
            : {}),
          thresholdSessionIds: { ecdsa: thresholdSessionId },
          relayerUrl,
          keyVersion: sealedKeyVersion,
          groupId: resolvedGroupId,
          issuedAtMs: persistedAtMs,
          expiresAtMs: sealed.expiresAtMs,
          remainingUses: sealed.remainingUses,
          updatedAtMs: persistedAtMs,
        });
        recordWarmSessionMaterialWriteDiagnosticDuration({
          diagnostics,
          bucket: 'sealed_record_register',
          startedAt: registerStartedAt,
        });
      } else {
        const walletId = String(recordMetadata.walletId || '').trim();
        if (!walletId || !recordMetadata.ed25519Restore) {
          throw new Error('[SigningSessionSealedStore] missing Ed25519 seal metadata');
        }
        const persistedAtMs = Date.now();
        const registerStartedAt = performance.now();
        await this.registerSigningSession({
          thresholdSessionId,
          sealedSecretB64u: sealed.sealedSecretB64u,
          curve: 'ed25519',
          authMethod,
          signingGrantId,
          walletId,
          ...(recordMetadata.signingRootId ? { signingRootId: recordMetadata.signingRootId } : {}),
          ...(recordMetadata.signingRootVersion
            ? { signingRootVersion: recordMetadata.signingRootVersion }
            : {}),
          ...(recordMetadata.ecdsaRestore ? { ecdsaRestore: recordMetadata.ecdsaRestore } : {}),
          ed25519Restore: recordMetadata.ed25519Restore,
          thresholdSessionIds: { ed25519: thresholdSessionId },
          relayerUrl,
          keyVersion: sealedKeyVersion,
          groupId: resolvedGroupId,
          issuedAtMs: persistedAtMs,
          expiresAtMs: sealed.expiresAtMs,
          remainingUses: sealed.remainingUses,
          updatedAtMs: persistedAtMs,
        });
        recordWarmSessionMaterialWriteDiagnosticDuration({
          diagnostics,
          bucket: 'sealed_record_register',
          startedAt: registerStartedAt,
        });
      }
      const verifyReadStartedAt = performance.now();
      const persistedRecord = await readExactSealedSession(thresholdSessionId, purpose).catch(
        () => null,
      );
      recordWarmSessionMaterialWriteDiagnosticDuration({
        diagnostics,
        bucket: 'sealed_record_verify_read',
        startedAt: verifyReadStartedAt,
      });
      if (!persistedRecord) {
        return {
          ok: false,
          code: 'local_persist_failed',
          message: 'Failed to persist sealed signing-session record locally',
        };
      }
      return sealed;
    })().finally(() => {
      signingSessionSealPersistSingleFlight.delete(singleFlightKey);
    });

    signingSessionSealPersistSingleFlight.set(singleFlightKey, task);
    return await task;
  };

  async requestUserConfirmation(
    request: UserConfirmRequest,
    options?: RequestUserConfirmationOptions,
  ): Promise<UserConfirmDecision> {
    const requestId = typeof request?.requestId === 'string' ? request.requestId.trim() : '';
    if (!requestId) {
      throw new Error('Invalid secure confirmation request: missing requestId');
    }

    const workerReadyStartedAt = performance.now();
    await this.ensureWorkerReady(false);
    const workerReadyMs = roundUiConfirmDurationMs(workerReadyStartedAt);
    if (options?.onProgress) {
      this.userConfirmProgressListeners.set(requestId, options.onProgress);
    }
    this.pendingFunctionBearingConfirmRequests.set(requestId, request);
    const workerSafeRequest = stripFunctionsForWorkerMessage(request);

    try {
      const requestRoundTripStartedAt = performance.now();
      const response = await this.sendMessage({
        type: 'SECURE_CONFIRM_REQUEST',
        id: this.generateMessageId(),
        payload: { request: workerSafeRequest },
      });
      const workerRequestRoundTripMs = roundUiConfirmDurationMs(requestRoundTripStartedAt);
      const responseValidationStartedAt = performance.now();
      if (!response?.success) {
        throw new Error(String(response?.error || 'Secure confirmation request failed'));
      }
      const decision = response?.data as UserConfirmDecision;
      if (!decision || typeof decision !== 'object') {
        throw new Error('Secure confirmation request failed: invalid worker response payload');
      }
      if (String(decision.requestId || '').trim() !== requestId) {
        throw new Error('Secure confirmation request failed: response requestId mismatch');
      }
      const workerResponseValidationMs = roundUiConfirmDurationMs(responseValidationStartedAt);
      if (decision.registrationDiagnostics?.kind !== 'registration_confirmation_diagnostics_v1') {
        return decision;
      }
      return {
        ...decision,
        registrationDiagnostics: {
          ...decision.registrationDiagnostics,
          workerReadyMs,
          workerRequestRoundTripMs,
          workerResponseValidationMs,
        },
      };
    } finally {
      this.userConfirmProgressListeners.delete(requestId);
      this.pendingFunctionBearingConfirmRequests.delete(requestId);
    }
  }

  /**
   * UiConfirm orchestration helper for signing confirmation flows.
   * Runs uiConfirm confirmation flows on the main thread and returns artifacts needed by the signer worker.
   */
  async orchestrateSigningConfirmation(
    params: Extract<OrchestrateSigningConfirmationParams, { kind: 'intentDigest' }>,
  ): Promise<SigningConfirmationResultIntentDigest>;
  async orchestrateSigningConfirmation(
    params: OrchestrateNearTransactionSigningConfirmationParams,
  ): Promise<NearTransactionSigningConfirmationResult>;
  async orchestrateSigningConfirmation(
    params: OrchestrateNearSignatureOnlySigningConfirmationParams,
  ): Promise<SigningConfirmationResultSignatureOnly>;
  async orchestrateSigningConfirmation(
    params: OrchestrateSigningConfirmationParams,
  ): Promise<
    | NearTransactionSigningConfirmationResult
    | SigningConfirmationResultIntentDigest
    | SigningConfirmationResultSignatureOnly
  > {
    return orchestrateSigningConfirmation(params);
  }

  /**
   * UserConfirm helper for registration confirmation.
   * Runs uiConfirm confirmation flows on the main thread and returns registration artifacts.
   */
  async requestRegistrationCredentialConfirmation(
    params: RequestRegistrationCredentialConfirmationParams,
  ) {
    const surface = this.takeRegistrationConfirmationSurface();
    try {
      return await requestRegistrationCredentialConfirmationOnMainThread({
        ctx: this.getContext(),
        surface,
        walletId: params.walletId,
        nearAccountId: params.nearAccountId,
        signerSlot: params.signerSlot,
        confirmerText: params.confirmerText,
        confirmationConfig: params.confirmationConfigOverride,
        challengeB64u: params.challengeB64u,
      });
    } catch (error) {
      if (surface.kind === 'reuse_mounted') {
        surface.handle.close(false);
      }
      throw error;
    }
  }

  private takeRegistrationConfirmationSurface(): ConfirmUISurfaceSource {
    const state = this.registrationPreparationModalState;
    switch (state.kind) {
      case 'closed':
        return { kind: 'mount_new' };
      case 'opening':
        throw new Error('Registration confirmation started before its preparation modal opened');
      case 'open':
        this.registrationPreparationModalState = {
          kind: 'closed',
          generation: state.generation,
        };
        return { kind: 'reuse_mounted', handle: state.handle };
      default:
        return assertNever(state);
    }
  }

  async openRegistrationPreparationModal(
    params: OpenRegistrationPreparationModalParams,
  ): Promise<void> {
    const walletLabel = String(params.walletLabel || '').trim();
    if (!walletLabel) {
      throw new Error('Registration preparation modal requires a wallet label');
    }
    if (!Number.isInteger(params.signerSlot) || params.signerSlot < 1) {
      throw new Error('Registration preparation modal requires a positive signer slot');
    }
    const rpId = String(this.context.touchIdPrompt.getRpId() || '').trim();
    if (!rpId) {
      throw new Error('Registration preparation modal requires an RP ID');
    }

    this.closeRegistrationPreparationModal();
    const generation = this.registrationPreparationModalState.generation + 1;
    this.registrationPreparationModalState = { kind: 'opening', generation };
    const handle = await mountConfirmUI({
      ctx: this.getContext(),
      summary: {
        title: 'Create your passkey',
        body: 'Preparing secure registration…',
      },
      securityContext: {
        rpId,
        passkeyRegistration: {
          kind: 'passkey_registration_confirm_display_v1',
          intendedUserName: walletLabel,
          accountId: walletLabel,
          rpId,
          signerSlot: params.signerSlot,
        },
      },
      loading: true,
      theme: this.context.getTheme?.() ?? 'dark',
      uiMode: 'modal',
      nearAccountIdOverride: walletLabel,
    });
    const state = this.registrationPreparationModalState;
    if (state.kind !== 'opening' || state.generation !== generation) {
      handle.close(false);
      return;
    }
    this.registrationPreparationModalState = { kind: 'open', generation, handle };
  }

  closeRegistrationPreparationModal(): void {
    const state = this.registrationPreparationModalState;
    this.registrationPreparationModalState = {
      kind: 'closed',
      generation: state.generation,
    };
    if (state.kind === 'open') {
      state.handle.close(false);
    }
  }

  setWorkerBaseOrigin(origin: string | undefined): void {
    this.workerBaseOrigin = origin;
  }

  /**
   * Ensure the UserConfirm worker is ready for operations
   * @param requireHealthCheck - Whether to perform health check after initialization
   */
  private async ensureWorkerReady(requireHealthCheck = false): Promise<void> {
    if (this.initializationPromise) {
      await this.initializationPromise;
    } else if (!this.worker) {
      await this.initialize();
    }
    if (!this.worker) {
      throw new Error('UserConfirm worker failed to initialize');
    }
    // Optional health check for critical operations
    if (requireHealthCheck) {
      try {
        const healthResponse = await this.sendMessage(
          {
            type: 'PING',
            id: this.generateMessageId(),
            payload: {},
          },
          3000,
        );

        if (!healthResponse.success) {
          throw new Error('UserConfirm worker failed health check');
        }
      } catch (error) {
        console.error('[UserConfirmWorker] health check failed:', error);
        throw new Error('UserConfirm worker failed health check');
      }
    }
  }

  /**
   * Initialize the UserConfirm worker.
   */
  async initialize(): Promise<void> {
    if (this.initializationPromise) {
      return this.initializationPromise;
    }
    if (this.worker) {
      return;
    }
    // =============================================================
    // This improved error handling ensures that:
    // 1. Initialization failures are properly logged with full details
    // 2. Errors are re-thrown to callers (no silent swallowing)
    // 3. Failed initialization promise is reset for retry
    // 4. Debug logs actually appear in test output
    this.initializationPromise = this.createUserConfirmWorker().catch((error) => {
      console.error('[UserConfirmWorker] initialization failed:', error);
      console.error('[UserConfirmWorker] error details:', {
        message: error.message,
        stack: error.stack,
        name: error.name,
      });
      // Reset promise so initialization can be retried
      this.initializationPromise = null;
      throw error; // Re-throw so callers know it failed
    });

    const result = await this.initializationPromise;
    return result;
  }

  /** Initialize the UserConfirm worker (client-hosted bundle). */
  private async createUserConfirmWorker(): Promise<void> {
    try {
      if (this.worker) {
        const restartedWorker = this.worker;
        this.detachWorkerRouter(restartedWorker);
        restartedWorker.terminate();
        this.worker = null;
        this.rejectPendingWorkerRequestsForWorker(
          restartedWorker,
          new Error('UserConfirm worker was restarted'),
        );
      }

      const relativePath = this.config.workerUrl || BUILD_PATHS.RUNTIME.TOUCH_CONFIRM_WORKER;
      const workerUrlStr = resolveWorkerUrl(relativePath, {
        worker: 'touchConfirm',
        baseOrigin: this.workerBaseOrigin,
      });
      if (this.config.debug) {
        console.debug('[UserConfirmWorker] Worker URL:', workerUrlStr);
      }
      const worker = new Worker(workerUrlStr, {
        type: 'module',
        name: 'Web3AuthnSecureConfirmWorker',
      });
      this.attachWorkerRouter(worker);
      this.worker = worker;
      // Test communication with the Web Worker
      await this.testWebWorkerCommunication();
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`UserConfirm worker initialization failed: ${message}`);
    }
  }

  private attachWorkerRouter(worker: Worker): void {
    worker.addEventListener('message', this.boundHandleWorkerMessage);
    worker.addEventListener('error', this.boundHandleWorkerError);
  }

  private detachWorkerRouter(worker: Worker): void {
    worker.removeEventListener('message', this.boundHandleWorkerMessage);
    worker.removeEventListener('error', this.boundHandleWorkerError);
  }

  private isFromActiveWorker(event: Event): boolean {
    const source = event.currentTarget;
    return source === this.worker && event.target === this.worker;
  }

  private normalizePromptEnvelope(payload: unknown): UserConfirmPromptEnvelope | null {
    if (!payload || typeof payload !== 'object') {
      return null;
    }
    const typedPayload = payload as {
      type?: unknown;
      requestId?: unknown;
      channelToken?: unknown;
      data?: unknown;
    };
    if (typedPayload.type !== UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD) {
      return null;
    }
    if (!typedPayload.data || typeof typedPayload.data !== 'object') {
      return null;
    }
    const request = typedPayload.data as UserConfirmRequest;
    const dataRequestId = typeof request?.requestId === 'string' ? request.requestId.trim() : '';
    const requestId =
      typeof typedPayload.requestId === 'string' ? typedPayload.requestId.trim() : '';
    if (!dataRequestId || !requestId || requestId !== dataRequestId) {
      return null;
    }
    const channelToken =
      typeof typedPayload.channelToken === 'string' ? typedPayload.channelToken.trim() : '';
    if (!channelToken) {
      return null;
    }
    const restoredRequest = this.restoreFunctionBearingConfirmRequestFields(requestId, request);
    return {
      type: UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD,
      requestId,
      channelToken,
      data: restoredRequest,
    };
  }

  private restoreFunctionBearingConfirmRequestFields(
    requestId: string,
    request: UserConfirmRequest,
  ): UserConfirmRequest {
    const original = this.pendingFunctionBearingConfirmRequests.get(requestId);
    if (!original) return request;
    const requestWithUnknownPayload = request as unknown as { payload?: unknown };
    const originalWithUnknownPayload = original as unknown as { payload?: unknown };
    const payload = isObjectRecord(requestWithUnknownPayload.payload)
      ? { ...requestWithUnknownPayload.payload }
      : null;
    const originalPayload = isObjectRecord(originalWithUnknownPayload.payload)
      ? originalWithUnknownPayload.payload
      : null;
    if (!payload || !originalPayload) return request;

    if (payload.emailOtpPrompt || originalPayload.emailOtpPrompt) {
      payload.emailOtpPrompt = maybeCopyEmailOtpResendHandler({
        targetPrompt: payload.emailOtpPrompt,
        sourcePrompt: originalPayload.emailOtpPrompt,
      });
    }

    if (
      typeof originalPayload.onLifecycle === 'function' &&
      typeof payload.onLifecycle !== 'function'
    ) {
      payload.onLifecycle = originalPayload.onLifecycle;
    }

    const signingAuthPlan = payload.signingAuthPlan;
    const originalSigningAuthPlan = originalPayload.signingAuthPlan;
    if (isObjectRecord(signingAuthPlan) && isObjectRecord(originalSigningAuthPlan)) {
      const restoredSigningAuthPlan: Record<string, unknown> = { ...signingAuthPlan };
      restoredSigningAuthPlan.emailOtpPrompt = maybeCopyEmailOtpResendHandler({
        targetPrompt: signingAuthPlan.emailOtpPrompt,
        sourcePrompt: originalSigningAuthPlan.emailOtpPrompt,
      });
      payload.signingAuthPlan = restoredSigningAuthPlan;
    }

    return {
      ...(request as object),
      payload,
    } as unknown as UserConfirmRequest;
  }

  private postPromptEnvelopeError(
    worker: Worker,
    requestId: string,
    channelToken: string,
    message: string,
  ): void {
    worker.postMessage({
      type: UserConfirmMessageType.USER_PASSKEY_CONFIRM_RESPONSE,
      requestId,
      channelToken,
      data: {
        requestId,
        confirmed: false,
        error: message,
      },
    });
  }

  private dispatchUserConfirmProgress(payload: { requestId?: unknown; data?: unknown }): void {
    const progressEvent = parseUserConfirmProgressEvent(payload.data);
    const requestId =
      typeof payload.requestId === 'string' && payload.requestId.trim()
        ? payload.requestId.trim()
        : typeof progressEvent?.requestId === 'string'
          ? progressEvent.requestId.trim()
          : '';
    if (!requestId || !progressEvent) {
      return;
    }
    const listener = this.userConfirmProgressListeners.get(requestId);
    if (!listener) {
      return;
    }
    try {
      listener(progressEvent);
    } catch (error) {
      console.error('[UserConfirmWorker] progress listener failed:', error);
    }
  }

  private handleWorkerMessage(event: MessageEvent): void {
    if (!this.isFromActiveWorker(event)) {
      return;
    }

    const payload = event.data as
      | UserConfirmWorkerResponse
      | {
          type?: unknown;
          requestId?: unknown;
          data?: unknown;
        };

    if (
      (payload as { type?: unknown }).type === UserConfirmMessageType.USER_PASSKEY_CONFIRM_PROGRESS
    ) {
      this.dispatchUserConfirmProgress(payload as { requestId?: unknown; data?: unknown });
      return;
    }

    // Intercept UserConfirm handshake messages from the worker and
    // dispatch them through uiConfirm confirmation flows on the main thread. The decision
    // is sent back to the worker as USER_PASSKEY_CONFIRM_RESPONSE and
    // consumed by awaitUserConfirmationV2; this should not resolve the
    // original request promise.
    const promptEnv = this.normalizePromptEnvelope(payload);
    if (promptEnv) {
      const ctx = this.getContext();
      const sourceWorker = event.currentTarget as Worker | null;
      if (!sourceWorker) {
        console.error(
          '[UserConfirmWorker] missing worker for PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD',
        );
        return;
      }
      void handlePromptFromWorker(ctx, promptEnv, sourceWorker).catch((error) => {
        console.error('[UserConfirmWorker] failed to handle confirmation prompt:', error);
        this.postPromptEnvelopeError(
          sourceWorker,
          promptEnv.requestId,
          promptEnv.channelToken || '',
          'Secure confirmation failed',
        );
      });
      return;
    }

    if (
      (payload as { type?: unknown }).type ===
      UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD
    ) {
      console.error('[UserConfirmWorker] rejected malformed prompt envelope');
      return;
    }

    const response = payload as UserConfirmWorkerResponse;
    const responseId = typeof response?.id === 'string' ? response.id.trim() : '';
    if (!responseId) {
      return;
    }
    const sourceWorker = event.currentTarget as Worker;
    this.resolvePendingWorkerRequest(sourceWorker, responseId, response);
  }

  private handleWorkerError(event: Event): void {
    if (!this.isFromActiveWorker(event)) {
      return;
    }
    const errorEvent = event as ErrorEvent;
    const message = String(
      errorEvent?.message || 'UserConfirm worker encountered an unknown error',
    );
    const error = new Error(`UserConfirm worker failed: ${message}`);
    console.error('[UserConfirmWorker] error:', errorEvent);
    const failedWorker = event.currentTarget;
    if (failedWorker === this.worker && this.worker) {
      this.detachWorkerRouter(this.worker);
      this.worker.terminate();
      this.worker = null;
      this.initializationPromise = null;
    }
    this.rejectPendingWorkerRequestsForWorker(failedWorker as Worker, error);
  }

  private resolvePendingWorkerRequest(
    sourceWorker: Worker,
    id: string,
    response: UserConfirmWorkerResponse,
  ): void {
    const pending = this.pendingWorkerRequests.get(id);
    if (!pending || pending.worker !== sourceWorker) {
      return;
    }
    clearTimeout(pending.timeoutId);
    pending.settle?.();
    this.pendingWorkerRequests.delete(id);
    pending.resolve(response);
  }

  private rejectPendingWorkerRequest(id: string, error: Error): void {
    const pending = this.pendingWorkerRequests.get(id);
    if (!pending) {
      return;
    }
    clearTimeout(pending.timeoutId);
    pending.settle?.();
    this.pendingWorkerRequests.delete(id);
    pending.reject(error);
  }

  private rejectPendingWorkerRequestsForWorker(worker: Worker, error: Error): void {
    for (const req of this.pendingWorkerRequests.values()) {
      if (req.worker !== worker) continue;
      this.pendingWorkerRequests.delete(req.id);
      clearTimeout(req.timeoutId);
      req.settle?.();
      req.reject(error);
    }
  }

  /**
   * Send message to Web Worker and wait for response
   */
  private async sendMessage<TPayload = unknown>(
    message: UserConfirmWorkerMessage<TPayload>,
    customTimeout?: number,
    signal?: AbortSignal,
  ): Promise<UserConfirmWorkerResponse> {
    return new Promise((resolve, reject) => {
      const worker = this.worker;
      if (!worker) {
        reject(new Error('UserConfirm worker not available'));
        return;
      }

      const abortedError = () =>
        new Error(`UserConfirm worker request aborted for message type: ${message.type}`);
      if (signal?.aborted) {
        reject(abortedError());
        return;
      }

      const requestId =
        typeof message.id === 'string' && message.id.trim().length
          ? message.id.trim()
          : this.generateMessageId();
      if (this.pendingWorkerRequests.has(requestId)) {
        reject(new Error(`Duplicate UserConfirm worker request id: ${requestId}`));
        return;
      }

      const timeoutMs = customTimeout ?? this.config.workerTimeout ?? 60_000;
      const timeoutId = setTimeout(() => {
        this.rejectPendingWorkerRequest(
          requestId,
          new Error(
            `UserConfirm worker communication timeout (${timeoutMs}ms) for message type: ${message.type}`,
          ),
        );
      }, timeoutMs);

      let settle: (() => void) | undefined;
      if (signal) {
        const abortHandler = () => {
          this.rejectPendingWorkerRequest(requestId, abortedError());
        };
        signal.addEventListener('abort', abortHandler, { once: true });
        settle = () => {
          signal.removeEventListener('abort', abortHandler);
        };
      }

      this.pendingWorkerRequests.set(requestId, {
        id: requestId,
        messageType: message.type,
        worker,
        timeoutId,
        settle,
        resolve,
        reject,
      });

      try {
        worker.postMessage({ ...message, id: requestId });
      } catch (error: unknown) {
        const normalizedError = error instanceof Error ? error : new Error(String(error));
        this.rejectPendingWorkerRequest(requestId, normalizedError);
      }
    });
  }

  /**
   * Generate unique message ID
   */
  private generateMessageId(): string {
    return `sc_${Date.now()}_${++this.messageId}`;
  }

  /**
   * Test Web Worker communication
   */
  private async testWebWorkerCommunication(): Promise<void> {
    try {
      const pingResponse = await this.sendMessage(
        {
          type: 'PING',
          id: this.generateMessageId(),
          payload: {},
        },
        USER_CONFIRM_WORKER_STARTUP_PING_TIMEOUT_MS,
      );
      if (!pingResponse.success) {
        throw new Error(`UserConfirm worker PING failed: ${pingResponse.error}`);
      }
      return;
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      console.warn('[UserConfirmWorker] testWebWorkerCommunication failed:', message);
      if (this.worker) {
        this.detachWorkerRouter(this.worker);
        this.worker.terminate();
        this.worker = null;
      }
      throw error;
    }
  }
}

export function createUiConfirmManager(
  config: UiConfirmManagerConfig,
  context: UiConfirmContext,
  passkeyMpcSession: PasskeyMpcSessionDurableWorkerPort,
  passkeyMpcSessionStatus: Pick<PasskeyMpcSessionPort, 'getWarmSessionStatus'>,
): UiConfirmManager {
  return new UiConfirmWorkerManagerImpl(
    config,
    context,
    passkeyMpcSession,
    passkeyMpcSessionStatus,
  );
}
