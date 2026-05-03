import {
  getLastSelectedNearAccountProjection,
  getNearAccountProjection,
  listNearAccountProjections,
} from '../accountData/near/accountProjection';
import { buildNearAccountRefs } from '../accountData/near/accountRefs';
import { inferNearChainIdKey } from '../accountData/near/accountRefs';
import { chainFamilyFromNetwork } from '../config/chains';
import { buildNearProfileId } from '../accountData/near/profileId';
import {
  getNearThresholdKeyMaterial,
  storeNearThresholdKeyMaterial,
} from '../accountData/near/keyMaterial';
import type {
  ClientAuthenticatorData,
  ClientUserData,
  StoreUserDataInput,
} from '../accountData/near/types';
import { SIGNER_MATERIAL_FINGERPRINT_METADATA_KEY } from '../indexedDB/accountSignerLifecycle';
import {
  resolveProfileAccountContextFromCandidates,
  selectAccountSigner,
} from '../indexedDB/profileAccountProjection';
import type { ProfileAuthenticatorRecord } from '../indexedDB/passkeyClientDB.types';
import type { NearClient, SignedTransaction } from '../rpcClients/near/NearClient';
import type { NonceCoordinator } from './nonce/NonceCoordinator';
import { toAccountId, type AccountId } from '../types/accountIds';
import type { ActionArgsWasm } from '../types/actions';
import type { AuthenticatorOptions } from '../types/authenticatorOptions';
import type { ConfirmationConfig } from '../types/signer-worker';
import {
  createKeyExportFlowEvent,
  KeyExportEventPhase,
  type CreateKeyExportFlowEventInput,
  type KeyExportFlowEvent,
  type SigningFlowEvent,
} from '../types/sdkSentEvents';
import type {
  EmailOtpAuthPolicy,
  SigningSessionStatus,
  SeamsConfigsReadonly,
  ThemeName,
} from '../types/seams';
import type { WebAuthnAuthenticationCredential, WebAuthnRegistrationCredential } from '../types';
import { buildThresholdEd25519Participants2pV1 } from '@shared/threshold/participants';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  type WalletEmailOtpChannel,
  type WalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import {
  requireThresholdSessionJwt,
  type AppOrThresholdSessionAuth,
} from '@shared/utils/sessionTokens';
import {
  SENSITIVE_OPERATION_POLICIES,
  SIGNER_AUTH_METHODS,
  SIGNER_KINDS,
  SIGNER_SOURCES,
} from '@shared/utils/signerDomain';
import type { UserPreferencesManager } from './api/userPreferences';
import type {
  ThresholdEcdsaCanonicalExportArtifact,
  ThresholdEcdsaSecp256k1KeyRef,
} from './interfaces/signing';
import {
  describeThresholdEcdsaChainTarget,
  thresholdEcdsaChainTargetFromActivationChain,
  thresholdEcdsaActivationChainForTarget,
  type ThresholdEcdsaChainTarget,
  type ThresholdEcdsaActivationChain,
  type ThresholdEcdsaSessionBootstrapResult,
} from './orchestration/thresholdActivation';
import type { SignerWorkerManager } from './workerManager';
import type { EmailOtpWorkerProgressEvent } from './workerManager/workerTypes';
import { buildEmailOtpRoutePlan, type EmailOtpAuthLane } from './emailOtp/authLane';
import type { RegistrationCredentialConfirmationPayload } from './workerManager/validation';
import type {
  TouchConfirmRuntimeBridgePort,
  WarmSessionMaterialClearAll,
  WarmSessionClaimResult,
  WarmSessionStatusResult,
} from './touchConfirm/types';
import type { WarmSessionStatusBatchResult } from '../types/secure-confirm-worker';
import {
  UserConfirmationType,
  type ExportPrivateKeyDisplayEntry,
} from './touchConfirm/shared/confirmTypes';
import { SigningOperationIntent } from './session/signingSession/types';
import type { SigningSessionBudgetStatusAuth } from './session/signingSession/budget';
import type { TouchIdPrompt } from './signers/webauthn/prompt/touchIdPrompt';
import type { WebAuthnAllowCredential } from './signers/webauthn/credentials';
import type { EvmSigningRequest } from './chainAdaptors/evm/types';
import type { EvmSignedResult } from './chainAdaptors/evm/evmAdapter';
import type { TempoSigningRequest } from './chainAdaptors/tempo/types';
import type { TempoSignedResult } from './chainAdaptors/tempo/tempoAdapter';
import { getPrfResultsFromCredential } from './signers/webauthn/credentials/credentialExtensions';
import { bootstrapEcdsaSessionValue } from './api/thresholdLifecycle/thresholdSessionActivation';
import {
  buildThresholdEd25519SeedExportArtifactFromHssReport as buildThresholdEd25519SeedExportArtifactFromHssReportValue,
  completeThresholdEd25519HssClientCeremony as completeThresholdEd25519HssClientCeremonyValue,
  deriveThresholdEd25519ClientVerifyingShareFromCredential as deriveThresholdEd25519ClientVerifyingShareFromCredentialValue,
  deriveThresholdEd25519HssClientInputsFromCredential as deriveThresholdEd25519HssClientInputsFromCredentialValue,
  openThresholdEd25519HssSeedOutput as openThresholdEd25519HssSeedOutputValue,
  prepareThresholdEd25519HssClientCeremonyFromCredential as prepareThresholdEd25519HssClientCeremonyFromCredentialValue,
  runThresholdEd25519HssCeremonyWithSession as runThresholdEd25519HssCeremonyWithSessionValue,
} from './api/thresholdLifecycle/thresholdEd25519Lifecycle';
import {
  persistThresholdEcdsaBootstrapChainAccount as persistThresholdEcdsaBootstrapChainAccountValue,
  type ThresholdEcdsaSmartAccountBootstrapInput,
} from './api/thresholdLifecycle/thresholdEcdsaBootstrapPersistence';
import {
  clearAllThresholdEcdsaSessionRecords as clearAllThresholdEcdsaSessionRecordsValue,
  clearThresholdEcdsaSessionRecordForLane as clearThresholdEcdsaSessionRecordForLaneValue,
  clearThresholdEcdsaSessionRecordForAccount as clearThresholdEcdsaSessionRecordForAccountValue,
  getEmailOtpThresholdEcdsaKeyRefForSigning as getEmailOtpThresholdEcdsaKeyRefForSigningValue,
  getEmailOtpThresholdEcdsaSessionRecordForSigning as getEmailOtpThresholdEcdsaSessionRecordForSigningValue,
  getPasskeyThresholdEcdsaKeyRefForSigning as getPasskeyThresholdEcdsaKeyRefForSigningValue,
  getPasskeyThresholdEcdsaSessionRecordForSigning as getPasskeyThresholdEcdsaSessionRecordForSigningValue,
  getThresholdEcdsaKeyRefForLookup as getThresholdEcdsaKeyRefForLookupValue,
  getThresholdEcdsaSessionRecordForLookup as getThresholdEcdsaSessionRecordForLookupValue,
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId as getStoredThresholdEcdsaSessionRecordByThresholdSessionIdValue,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId as getStoredThresholdEd25519SessionRecordByThresholdSessionIdValue,
  getStoredThresholdEd25519SessionRecordForAccount as getStoredThresholdEd25519SessionRecordForAccountValue,
  getStoredThresholdEd25519SessionRecordForLane as getStoredThresholdEd25519SessionRecordForLaneValue,
  listThresholdEcdsaKeyRefsForLookup as listThresholdEcdsaKeyRefsForLookupValue,
  listThresholdEcdsaSessionRecordsForLookup as listThresholdEcdsaSessionRecordsForLookupValue,
  markThresholdEd25519EmailOtpSessionConsumedForAccount as markThresholdEd25519EmailOtpSessionConsumedForAccountValue,
  markThresholdEcdsaEmailOtpSessionConsumedForAccount as markThresholdEcdsaEmailOtpSessionConsumedForAccountValue,
  THRESHOLD_ECDSA_SESSION_STORE_SOURCES,
  upsertStoredThresholdEcdsaSessionRecord as upsertStoredThresholdEcdsaSessionRecordValue,
  upsertThresholdEcdsaSessionFromBootstrap as upsertThresholdEcdsaSessionFromBootstrapValue,
  type ThresholdEd25519SessionRecord,
  type ThresholdEcdsaEmailOtpAuthContext,
  type ThresholdEcdsaKeyRefLookupResult,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreSource,
} from './api/thresholdLifecycle/thresholdSessionStore';
import {
  scheduleThresholdEcdsaLoginPresignPrefill as scheduleThresholdEcdsaLoginPresignPrefillValue,
  type ThresholdEcdsaLoginPrefillResult,
} from './api/thresholdLifecycle/thresholdEcdsaLoginPrefill';
import { clearThresholdEcdsaClientPresignaturesForLane } from './orchestration/walletOrigin/thresholdEcdsaCoordinator';
import {
  normalizeThresholdRuntimePolicyScope,
  type ThresholdRuntimePolicyScope,
} from './threshold/session/sessionPolicy';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { errorMessage, isUserCancellationError } from '@shared/utils/errors';
import {
  signNear as signNearValue,
  type NearSignIntentRequest,
  type NearSignIntentResult,
  type SignTransactionsWithActionsInput,
} from './api/nearSigning';
import {
  reconcileTempoNonceLane as reconcileTempoNonceLaneValue,
  reportTempoBroadcastAccepted as reportTempoBroadcastAcceptedValue,
  reportTempoBroadcastRejected as reportTempoBroadcastRejectedValue,
  reportTempoDroppedOrReplaced as reportTempoDroppedOrReplacedValue,
  reportTempoFinalized as reportTempoFinalizedValue,
  signTempo as signTempoValue,
  type ReconcileTempoNonceLaneArgs,
  type ReportTempoBroadcastAcceptedArgs,
  type ReportTempoBroadcastRejectedArgs,
  type ReportTempoDroppedOrReplacedArgs,
  type ReportTempoFinalizedArgs,
  type TempoNonceLaneStatus,
} from './api/tempoSigning';
import {
  cacheSigningSessionPrfFirst as cacheSigningSessionPrfFirstValue,
  clearSigningSessionPrfFirstBestEffort as clearSigningSessionPrfFirstBestEffortValue,
  generateSessionId as generateSessionIdValue,
} from './api/session/signingSessionState';
import {
  clearThresholdEcdsaCommitQueue,
  withThresholdEcdsaCommitQueue,
  type ThresholdEcdsaCommitQueueByKey,
} from './api/thresholdLifecycle/thresholdEcdsaCommitQueue';
import {
  clearThresholdEd25519CommitQueue,
  withThresholdEd25519CommitQueue,
  type ThresholdEd25519CommitQueueByKey,
} from './api/thresholdLifecycle/thresholdEd25519CommitQueue';
import { exportNearEd25519SeedArtifactWithUI as exportNearEd25519SeedArtifactWithUIValue } from './api/recovery/privateKeyExportRecovery';
import { getLastLoggedInSignerSlot } from './signers/webauthn/device/signerSlot';
import {
  isExportViewerSessionOpen,
  removeExportViewerHostIfPresent,
} from './touchConfirm/ui/export-viewer-host';
import {
  thresholdEcdsaHssFinalize,
  thresholdEcdsaHssPrepare,
  thresholdEcdsaHssRespond,
} from '../rpcClients/relayer/thresholdEcdsa';
import {
  getAuthenticationCredentialsSerialized as getAuthenticationCredentialsSerializedValue,
  requestRegistrationCredentialConfirmation as requestRegistrationCredentialConfirmationValue,
} from './api/registration/registrationSession';
import {
  atomicStoreRegistrationData as atomicStoreRegistrationDataValue,
  hasPasskeyCredential as hasPasskeyCredentialValue,
  initializeCurrentUser as initializeCurrentUserValue,
  rollbackUserRegistration as rollbackUserRegistrationValue,
  storeAuthenticator as storeAuthenticatorValue,
  storeUserData as storeUserDataValue,
  type StoreAuthenticatorInput,
} from './api/registration/registrationAccountLifecycle';
import { initializeRuntimeBootstrap } from './bootstrap/runtimeBootstrap';
import { createManagerAssembly } from './bootstrap/managerAssembly';
import { verifySealedRefreshStartupParity } from '../rpcClients/relayer/sealedRefreshCapabilities';
import { createWarmSessionCapabilityReader } from './session/warmSigning/capabilityReader';
import { createWarmSessionStatusReader } from './session/warmSigning/statusReader';
import { provisionWarmEd25519Capability } from './session/warmSigning/ed25519Provisioner';
import { provisionWarmEcdsaCapability } from './session/warmSigning/ecdsaProvisioner';
import { assertWarmSessionEcdsaOperationAllowed } from './session/warmSigning/postSignPolicyAdapter';
import {
  claimWarmSessionPrfFirst,
  ensureEcdsaPrfSealPersisted,
} from './session/warmSigning/runtime';
import type { WarmSessionEcdsaCapabilityState } from './session/warmSigning/types';
import type {
  ProvisionWarmEd25519CapabilityArgs,
  ProvisionWarmEd25519CapabilityResult,
  WarmEcdsaSigningSessionStatus,
} from './session/warmSigning/types';
import {
  deriveThresholdEd25519HssClientInputsWasm,
  finalizeThresholdEcdsaHssClientRequestWasm,
  prepareThresholdEcdsaHssClientRequestWasm,
  prepareThresholdEcdsaHssSessionWasm,
  prepareThresholdEd25519HssClientRequestWasm,
  prepareThresholdEd25519HssSessionWasm,
} from './signers/wasm/hssClientSignerWasm';
import {
  createThresholdEcdsaHssHiddenEvalFinalizeMessage,
  encodeThresholdEcdsaHssHiddenEvalRequestMessage,
  parseThresholdEcdsaHssHiddenEvalServerResponseMessage,
} from './threshold/workflows/thresholdEcdsaHssTransport';
import { connectEd25519Session } from './threshold/workflows/connectEd25519Session';
import {
  THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
  THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
} from './orchestration/near/shared/ensureThresholdEd25519HssClientBase';
import {
  createOrchestrationDependencyBundle,
  type OrchestrationDependencyBundle,
} from './bootstrap/orchestrationDependencyFactory';
import { enrollEmailOtpWallet } from '../SeamsPasskey/emailOtp';
import { persistWarmSessionEd25519Capability } from './session/warmSigning/persistence';
import {
  createEmailOtpWalletAuthAdapter,
  createPasskeyWalletAuthAdapter,
  createWalletAuthModeResolver,
  resolveAccountAuthMetadataForSignerSource,
  WalletAuthPlanKind,
  WalletAuthPolicyError,
  type WalletAuthCurve,
  type WalletAuthIntent,
} from './auth';
import {
  EmailOtpThresholdSessionCoordinator,
  type EmailOtpBootstrapRecovery,
} from './emailOtp/EmailOtpThresholdSessionCoordinator';
import type {
  RestorePersistedSessionsForAccountInput,
  RestorePersistedSessionsForAccountResult,
} from './session/restoreCoordinator';
import type {
  ReadSigningSessionSnapshotInput,
  SigningSessionSnapshot,
  SigningSessionSnapshotEcdsaLane,
  SigningSessionSnapshotEd25519Lane,
  SigningSessionSnapshotRuntimeEcdsaRecord,
  SigningSessionSnapshotRuntimeEd25519Record,
  SigningSessionSnapshotRuntimeClaim,
} from './session/snapshotReader';
import {
  ecdsaSnapshotLaneIdentityKey,
  ed25519SnapshotLaneIdentityKey,
  readSigningSessionSnapshot,
  warmStatusToSigningSessionSnapshotRuntimeClaim,
} from './session/snapshotReader';
import {
  emitSigningSessionFlowFailure,
  emitSigningSessionFlowTrace,
} from './session/signingSession/trace';
import {
  listExactSealedSessionsForAccount,
  listResolvedIdentitiesForAccount,
  type SigningSessionSealedStoreRecord,
} from './session/sealedSessionStore';
import { resolveEmailOtpEcdsaWorkerSessionId } from './session/signingSession/readiness';

export type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from './orchestration/thresholdActivation';
export type { EmailOtpBootstrapRecovery } from './emailOtp/EmailOtpThresholdSessionCoordinator';
export type { NearSignIntentRequest, NearSignIntentResult } from './api/nearSigning';
export type { ThresholdEcdsaLoginPrefillResult } from './api/thresholdLifecycle/thresholdEcdsaLoginPrefill';

function buildEmailOtpThresholdEd25519SignerMaterialFingerprint(args: {
  publicKey: string;
  relayerKeyId: string;
  keyVersion: string;
  rpId: string;
  participantIds: number[];
}): string {
  return JSON.stringify({
    kind: SIGNER_KINDS.thresholdEd25519,
    authMethod: SIGNER_AUTH_METHODS.emailOtp,
    publicKey: args.publicKey,
    relayerKeyId: args.relayerKeyId,
    keyVersion: args.keyVersion,
    rpId: args.rpId,
    participantIds: args.participantIds,
  });
}

function createEmailOtpKeyExportRequiresPasskeyError(): WalletAuthPolicyError {
  return new WalletAuthPolicyError({
    code: 'passkey_step_up_required',
    policy: 'export_requires_passkey',
    message: 'Key export requires a passkey-authenticated account.',
  });
}

function isEmailOtpPasskeyStepUpError(error: unknown): boolean {
  const message = String(error instanceof Error ? error.message : error || '');
  return (
    message.includes('requires fresh passkey authentication after Email OTP login') ||
    message.includes('requires passkey authentication after Email OTP login')
  );
}

function isRetryableSealedRefreshCapabilityFetchError(error: unknown): boolean {
  const code =
    error && typeof error === 'object' && 'code' in error
      ? String((error as { code?: unknown }).code || '').trim()
      : '';
  if (
    code === 'sealed_refresh_parity_fetch_failed' ||
    code === 'sealed_refresh_parity_http_error' ||
    code === 'sealed_refresh_parity_aborted'
  ) {
    return true;
  }
  const message = String(error instanceof Error ? error.message : error || '');
  return (
    message.includes('Failed to fetch relayer well-known capabilities') ||
    /Well-known endpoint returned HTTP 5\d\d/.test(message)
  );
}

function hasWarmSessionMaterialClearAll(value: unknown): value is WarmSessionMaterialClearAll {
  return (
    typeof (value as { clearAllWarmSessionMaterial?: unknown })?.clearAllWarmSessionMaterial ===
    'function'
  );
}

function createExportUiRequestId(prefix: string): string {
  const randomPart =
    typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `${prefix}-${randomPart}`;
}

type KeyExportEventCallback = (event: KeyExportFlowEvent) => void;

type ExactNearEd25519ExportLane = {
  curve: 'ed25519';
  chain: 'near';
  nearAccountId: AccountId;
  authMethod: 'email_otp' | 'passkey';
  walletSigningSessionId: string;
  thresholdSessionId: string;
  state: SigningSessionSnapshot['lanes']['ed25519']['near']['state'];
  source: SigningSessionSnapshot['lanes']['ed25519']['near']['source'];
};

type ExactEcdsaExportLane = {
  curve: 'ecdsa';
  chain: 'evm' | 'tempo';
  nearAccountId: AccountId;
  authMethod: 'email_otp' | 'passkey';
  walletSigningSessionId: string;
  thresholdSessionId: string;
  state: SigningSessionSnapshot['lanes']['ecdsa']['evm']['state'];
  source: SigningSessionSnapshot['lanes']['ecdsa']['evm']['source'];
};

type ReadyEcdsaExportMaterial = {
  kind: 'ready';
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
};

type FreshEmailOtpEcdsaExportMaterial = {
  kind: 'fresh_email_otp';
  chainId: number;
  publicKey: string;
  ecdsaThresholdKeyId: string;
  participantIds: number[];
  authSubjectId?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
};

type EcdsaExportMaterial = ReadyEcdsaExportMaterial | FreshEmailOtpEcdsaExportMaterial;

function isConcreteEcdsaExportLane(
  lane: SigningSessionSnapshot['candidates']['ecdsa']['evm'][number] | null | undefined,
): lane is ConcreteEcdsaExportSnapshotLane {
  return (
    Boolean(lane) &&
    lane!.curve === 'ecdsa' &&
    (lane!.chain === 'evm' || lane!.chain === 'tempo') &&
    (lane!.authMethod === 'email_otp' || lane!.authMethod === 'passkey') &&
    Boolean(String(lane!.walletSigningSessionId || '').trim()) &&
    Boolean(String(lane!.thresholdSessionId || '').trim())
  );
}

function isConcreteEd25519ExportLane(
  lane: SigningSessionSnapshotEd25519Lane | null | undefined,
): lane is ConcreteEd25519ExportSnapshotLane {
  return (
    Boolean(lane) &&
    lane!.curve === 'ed25519' &&
    lane!.chain === 'near' &&
    (lane!.authMethod === 'email_otp' || lane!.authMethod === 'passkey') &&
    Boolean(String(lane!.walletSigningSessionId || '').trim()) &&
    Boolean(String(lane!.thresholdSessionId || '').trim())
  );
}

type ConcreteEd25519ExportSnapshotLane = SigningSessionSnapshotEd25519Lane & {
  authMethod: 'email_otp' | 'passkey';
  walletSigningSessionId: string;
  thresholdSessionId: string;
};

type ConcreteEcdsaExportSnapshotLane = SigningSessionSnapshotEcdsaLane & {
  authMethod: 'email_otp' | 'passkey';
  walletSigningSessionId: string;
  thresholdSessionId: string;
};

type ConcreteExportSnapshotLane =
  | ConcreteEd25519ExportSnapshotLane
  | ConcreteEcdsaExportSnapshotLane;

function exportLaneStatePriority(lane: ConcreteExportSnapshotLane): number {
  switch (lane.state) {
    case 'ready':
      return 5;
    case 'restorable':
      return 4;
    case 'deferred':
      return 3;
    case 'expired':
    case 'exhausted':
      return 2;
    case 'missing':
    default:
      return 1;
  }
}

function exportLaneSourcePriority(lane: ConcreteExportSnapshotLane): number {
  switch (lane.source) {
    case 'runtime_and_durable':
      return 3;
    case 'runtime_session_record':
      return 2;
    case 'durable_sealed_record':
      return 1;
    default:
      return 0;
  }
}

function exportLaneUpdatedAtMs(lane: ConcreteExportSnapshotLane): number | null {
  const value = Math.floor(Number(lane.updatedAtMs));
  return Number.isFinite(value) && value > 0 ? value : null;
}

function exportLaneIdentity(lane: ConcreteExportSnapshotLane): string {
  return [
    lane.authMethod,
    lane.curve,
    lane.chain,
    lane.walletSigningSessionId,
    lane.thresholdSessionId,
  ].join(':');
}

function summarizeExportSnapshotLane(lane: ConcreteExportSnapshotLane): Record<string, unknown> {
  return {
    authMethod: lane.authMethod,
    curve: lane.curve,
    chain: lane.chain,
    state: lane.state,
    source: lane.source,
    walletSigningSessionId: lane.walletSigningSessionId,
    thresholdSessionId: lane.thresholdSessionId,
    remainingUses: lane.remainingUses,
    expiresAtMs: lane.expiresAtMs,
    updatedAtMs: lane.updatedAtMs,
  };
}

function bestExportLaneByPriority<TLane extends ConcreteExportSnapshotLane>(
  candidates: readonly TLane[],
  priority: (lane: TLane) => number,
): TLane[] {
  let bestPriority = -Infinity;
  let bestCandidates: TLane[] = [];
  for (const candidate of candidates) {
    const value = priority(candidate);
    if (value > bestPriority) {
      bestPriority = value;
      bestCandidates = [candidate];
      continue;
    }
    if (value === bestPriority) {
      bestCandidates.push(candidate);
    }
  }
  return bestCandidates;
}

function selectNewestExportLaneWhenUnambiguous<TLane extends ConcreteExportSnapshotLane>(
  candidates: readonly TLane[],
): TLane | null {
  let selected: TLane | null = null;
  let selectedUpdatedAtMs = -Infinity;
  let ambiguous = false;
  for (const candidate of candidates) {
    const updatedAtMs = exportLaneUpdatedAtMs(candidate);
    if (updatedAtMs === null) return null;
    if (updatedAtMs > selectedUpdatedAtMs) {
      selected = candidate;
      selectedUpdatedAtMs = updatedAtMs;
      ambiguous = false;
      continue;
    }
    if (updatedAtMs === selectedUpdatedAtMs) {
      ambiguous = true;
    }
  }
  return ambiguous ? null : selected;
}

function selectExactExportSnapshotLane<TLane extends ConcreteExportSnapshotLane>(args: {
  context: string;
  candidates: TLane[];
  authMethod?: 'email_otp' | 'passkey';
}): TLane {
  const traceScope = args.context.includes('ed25519') ? 'near' : 'evm-family';
  const scopedCandidates = args.authMethod
    ? args.candidates.filter((candidate) => candidate.authMethod === args.authMethod)
    : args.candidates;

  if (!scopedCandidates.length) {
    emitSigningSessionFlowFailure(traceScope, {
      stage: 'key_export.exact_lane_no_candidate',
      context: args.context,
      authMethod: args.authMethod,
      totalCandidateCount: args.candidates.length,
      candidates: args.candidates.map(summarizeExportSnapshotLane),
    });
    throw new Error(`[SigningEngine][${args.context}] exact lane selection failed: no_candidate`);
  }

  const candidatesByIdentity = new Map<string, TLane[]>();
  for (const candidate of scopedCandidates) {
    const identity = exportLaneIdentity(candidate);
    candidatesByIdentity.set(identity, [...(candidatesByIdentity.get(identity) || []), candidate]);
  }

  const dedupedCandidates = [...candidatesByIdentity.values()].map((sameIdentityCandidates) => {
    const byState = bestExportLaneByPriority(sameIdentityCandidates, exportLaneStatePriority);
    const bySource = bestExportLaneByPriority(byState, exportLaneSourcePriority);
    return selectNewestExportLaneWhenUnambiguous(bySource) || bySource[0]!;
  });

  const returnSelected = (selectedLane: TLane, reason: string): TLane => {
    emitSigningSessionFlowTrace(traceScope, {
      stage: 'key_export.exact_lane_selected',
      context: args.context,
      authMethod: args.authMethod,
      reason,
      selectedLane: summarizeExportSnapshotLane(selectedLane),
      candidateCount: scopedCandidates.length,
      dedupedCandidateCount: dedupedCandidates.length,
    });
    return selectedLane;
  };

  if (dedupedCandidates.length === 1) {
    return returnSelected(dedupedCandidates[0]!, 'single_exact_identity');
  }

  const bestStateCandidates = bestExportLaneByPriority(dedupedCandidates, exportLaneStatePriority);
  if (bestStateCandidates.length === 1) {
    return returnSelected(bestStateCandidates[0]!, 'best_state');
  }

  const bestSourceCandidates = bestExportLaneByPriority(
    bestStateCandidates,
    exportLaneSourcePriority,
  );
  if (bestSourceCandidates.length === 1) {
    return returnSelected(bestSourceCandidates[0]!, 'best_source');
  }

  const newestCandidate = selectNewestExportLaneWhenUnambiguous(bestSourceCandidates);
  if (newestCandidate) return returnSelected(newestCandidate, 'newest_updated_at');

  emitSigningSessionFlowFailure(traceScope, {
    stage: 'key_export.exact_lane_ambiguous',
    context: args.context,
    authMethod: args.authMethod,
    candidateCount: scopedCandidates.length,
    candidates: scopedCandidates.map(summarizeExportSnapshotLane),
    remainingCandidates: bestSourceCandidates.map(summarizeExportSnapshotLane),
  });
  throw new Error(
    `[SigningEngine][${args.context}] exact lane selection failed: ambiguous_candidates`,
  );
}

function emitKeyExportEvent(
  onEvent: KeyExportEventCallback | undefined,
  input: CreateKeyExportFlowEventInput,
): void {
  if (!onEvent) return;
  try {
    onEvent(createKeyExportFlowEvent(input));
  } catch {}
}

function createKeyExportFlowId(nearAccountId: AccountId | string, chain: string): string {
  return `key-export:${String(nearAccountId)}:${chain}:${createExportUiRequestId('flow')}`;
}

function mapProfileAuthenticatorToClient(
  profileAuthenticator: ProfileAuthenticatorRecord,
  nearAccountId: AccountId,
): ClientAuthenticatorData {
  return {
    nearAccountId,
    signerSlot: profileAuthenticator.signerSlot,
    credentialId: profileAuthenticator.credentialId,
    credentialPublicKey: profileAuthenticator.credentialPublicKey,
    transports: profileAuthenticator.transports,
    name: profileAuthenticator.name,
    registered: profileAuthenticator.registered,
    syncedAt: profileAuthenticator.syncedAt,
  };
}

type WarmSessionStatusOnlyTouchConfirmPort = TouchConfirmRuntimeBridgePort & {
  readWarmSessionStatusOnly?: (args: { sessionId: string }) => Promise<WarmSessionStatusResult>;
  readWarmSessionStatusesOnly?: (args: {
    sessionIds: string[];
  }) => Promise<WarmSessionStatusBatchResult>;
};

/**
 * SigningEngine is the signing composition root:
 * - owns bootstrap/lifecycle for worker managers
 * - exposes direct public signing/session/recovery/persistence methods
 * - keeps only shared runtime/config helpers and orchestration deps internally
 */
export class SigningEngine {
  // Kept as fields for low-level tests that intentionally access internals.
  private readonly touchConfirm: TouchConfirmRuntimeBridgePort;
  private readonly signerWorkerManager: SignerWorkerManager;
  private readonly touchIdPrompt: TouchIdPrompt;
  private readonly userPreferencesManager: UserPreferencesManager;
  private readonly nearClient: NearClient;
  private readonly nonceCoordinator: NonceCoordinator;
  private workerBaseOrigin: string = '';
  private theme: ThemeName = 'dark';
  private readonly thresholdEcdsaBootstrapQueueByAccount: Map<string, Promise<void>> = new Map();
  private readonly thresholdEcdsaCommitQueueByKey: ThresholdEcdsaCommitQueueByKey = new Map();
  private readonly thresholdEd25519CommitQueueByKey: ThresholdEd25519CommitQueueByKey = new Map();
  private readonly emailOtpSessions: EmailOtpThresholdSessionCoordinator;
  private readonly thresholdEcdsaSessionByLane: Map<string, ThresholdEcdsaSessionRecord> =
    new Map();
  private readonly thresholdEcdsaExportArtifactByLane: Map<
    string,
    ThresholdEcdsaCanonicalExportArtifact
  > = new Map();
  private readonly sealedRefreshStartupParityPromise: Promise<void>;
  private sealedRefreshStartupParityError: Error | null = null;
  private readonly orchestrationDeps: OrchestrationDependencyBundle;

  readonly seamsPasskeyConfigs: SeamsConfigsReadonly;

  constructor(seamsPasskeyConfigs: SeamsConfigsReadonly, nearClient: NearClient) {
    this.seamsPasskeyConfigs = seamsPasskeyConfigs;
    this.nearClient = nearClient;
    this.sealedRefreshStartupParityPromise = verifySealedRefreshStartupParity({
      configs: this.seamsPasskeyConfigs,
    }).catch((error: unknown) => {
      this.sealedRefreshStartupParityError =
        error instanceof Error
          ? error
          : new Error(String(error || 'sealed refresh parity check failed'));
    });

    const assembly = createManagerAssembly({
      seamsPasskeyConfigs: this.seamsPasskeyConfigs,
      nearClient: this.nearClient,
      getTheme: () => this.theme,
      getAppearanceTokens: () => this.seamsPasskeyConfigs.ui.appearance?.tokens,
    });

    this.touchIdPrompt = assembly.touchIdPrompt;
    this.userPreferencesManager = assembly.userPreferencesManager;
    this.nonceCoordinator = assembly.nonceCoordinator;
    this.signerWorkerManager = assembly.signerWorkerManager;
    this.emailOtpSessions = new EmailOtpThresholdSessionCoordinator({
      configs: this.seamsPasskeyConfigs,
      signerWorkerManager: this.signerWorkerManager,
      touchIdPrompt: this.touchIdPrompt,
      requestUserConfirmation: (request) => this.touchConfirm.requestUserConfirmation(request),
      getSignerWorkerContext: () =>
        this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
      commitEvmFamilyThresholdEcdsaSessions: (args) =>
        this.commitEvmFamilyThresholdEcdsaSessions(args),
      getThresholdEcdsaKeyRefForLookup: (args) => this.getThresholdEcdsaKeyRefForLookup(args),
      getThresholdEcdsaSessionRecordByThresholdSessionId: (thresholdSessionId) =>
        this.getThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId),
      persistEmailOtpThresholdEd25519LocalMetadata: (args) =>
        this.persistEmailOtpThresholdEd25519LocalMetadata(args),
      persistWarmSessionEd25519Capability: (args) => persistWarmSessionEd25519Capability(args),
      hydrateSigningSession: (args) => this.hydrateSigningSession(args),
    });
    this.touchConfirm = this.createWarmSessionAwareTouchConfirm(assembly.touchConfirm);

    this.orchestrationDeps = createOrchestrationDependencyBundle({
      seamsPasskeyConfigs: this.seamsPasskeyConfigs,
      nearClient: this.nearClient,
      touchIdPrompt: this.touchIdPrompt,
      userPreferencesManager: this.userPreferencesManager,
      nonceCoordinator: assembly.nonceCoordinator,
      touchConfirm: this.touchConfirm,
      getEmailOtpWarmSessionStatus: (sessionId) =>
        this.emailOtpSessions.readWarmSessionStatusOnly(sessionId),
      consumeEmailOtpWarmSessionUses: (args) => this.emailOtpSessions.consumeWarmSessionUses(args),
      getWalletSigningBudgetStatus: (args) => this.readTrustedWalletSigningBudgetStatus(args),
      signerWorkerManager: this.signerWorkerManager,
      getWorkerBaseOrigin: () => this.workerBaseOrigin,
      getTheme: () => this.theme,
      signTempo: (args) => this.signTempo(args),
      extractCosePublicKey: (attestationObjectBase64url: string) =>
        this.extractCosePublicKey(attestationObjectBase64url),
      initializeCurrentUser: (nearAccountId: AccountId, nearClientArg?: NearClient) =>
        this.initializeCurrentUser(nearAccountId, nearClientArg),
      persistThresholdEcdsaBootstrapChainAccount: (args) =>
        this.persistThresholdEcdsaBootstrapChainAccount(args),
      upsertThresholdEcdsaSessionFromBootstrap: (args) =>
        this.upsertThresholdEcdsaSessionFromBootstrap(args),
      getThresholdEcdsaKeyRefForLookup: (args) => this.getThresholdEcdsaKeyRefForLookup(args),
      listThresholdEcdsaKeyRefsForLookup: (args) => this.listThresholdEcdsaKeyRefsForLookup(args),
      getThresholdEcdsaSessionRecordForLookup: (args) =>
        this.getThresholdEcdsaSessionRecordForLookup(args),
      listThresholdEcdsaSessionRecordsForLookup: (args) =>
        this.listThresholdEcdsaSessionRecordsForLookup(args),
      getEmailOtpThresholdEcdsaKeyRefForSigning: (args) =>
        this.getEmailOtpThresholdEcdsaKeyRefForSigning(args),
      getEmailOtpThresholdEcdsaSessionRecordForSigning: (args) =>
        this.getEmailOtpThresholdEcdsaSessionRecordForSigning(args),
      getPasskeyThresholdEcdsaKeyRefForSigning: (args) =>
        this.getPasskeyThresholdEcdsaKeyRefForSigning(args),
      getPasskeyThresholdEcdsaSessionRecordForSigning: (args) =>
        this.getPasskeyThresholdEcdsaSessionRecordForSigning(args),
      requestEmailOtpTransactionSigningChallenge: (args) =>
        this.emailOtpSessions.requestTransactionSigningChallenge(args),
      isEmailOtpEd25519WarmupPending: (args) => this.emailOtpSessions.isEd25519WarmupPending(args),
      waitForPendingEmailOtpEd25519Warmup: (args) =>
        this.emailOtpSessions.waitForPendingEd25519Warmup(args),
      loginWithEmailOtpEd25519CapabilityForSigning: (args) =>
        this.emailOtpSessions.loginWithEd25519CapabilityForSigning(args),
      provisionThresholdEd25519Session: (args) => this.provisionThresholdEd25519Session(args),
      loginWithEmailOtpEcdsaCapabilityForSigning: (args) =>
        this.emailOtpSessions.loginWithEcdsaCapabilityForSigning(args),
      restorePersistedSessionForSigning: (args) =>
        args.authMethod === 'passkey'
          ? this.touchConfirm.restorePersistedSessionForSigning({
              ...args,
              authMethod: 'passkey',
            })
          : this.emailOtpSessions.restorePersistedSessionForSigning(args),
      readSigningSessionSnapshotForSigning: (args) =>
        this.readPersistedSigningSessionSnapshot(args),
      markThresholdEcdsaEmailOtpSessionConsumedForAccount: (args) =>
        this.markThresholdEcdsaEmailOtpSessionConsumedForAccount(args),
      markThresholdEd25519EmailOtpSessionConsumedForAccount: (args) =>
        this.markThresholdEd25519EmailOtpSessionConsumedForAccount(args),
      clearThresholdEcdsaSessionRecordForLane: (args) =>
        this.clearThresholdEcdsaSessionRecordForLane(args),
      provisionThresholdEcdsaSession: (args) => this.bootstrapEcdsaSession(args),
      withThresholdEcdsaCommitQueue: (queueArgs) => this.withThresholdEcdsaCommitQueue(queueArgs),
      withThresholdEd25519CommitQueue: (queueArgs) =>
        this.withThresholdEd25519CommitQueue(queueArgs),
    });

    initializeRuntimeBootstrap({
      seamsPasskeyConfigs: this.seamsPasskeyConfigs,
      userPreferencesManager: this.userPreferencesManager,
      getWorkerBaseOrigin: () => this.workerBaseOrigin,
      setWorkerBaseOrigin: (origin: string) => {
        this.workerBaseOrigin = origin;
        this.signerWorkerManager.setWorkerBaseOrigin(origin);
        this.touchConfirm.setWorkerBaseOrigin?.(origin);
      },
    });
  }

  private createWarmSessionAwareTouchConfirm(
    base: TouchConfirmRuntimeBridgePort,
  ): TouchConfirmRuntimeBridgePort {
    const getWarmSessionStatus = async (args: {
      sessionId: string;
    }): Promise<WarmSessionStatusResult> => {
      const secondary = await this.emailOtpSessions.readWarmSessionStatusOnly(args.sessionId);
      if (secondary.ok || (secondary.code !== 'not_found' && secondary.code !== 'worker_error')) {
        return secondary;
      }
      return await base.getWarmSessionStatus(args);
    };

    const getWarmSessionStatuses = async (args: {
      sessionIds: string[];
    }): Promise<WarmSessionStatusBatchResult> => {
      const secondaryResults = await Promise.all(
        args.sessionIds.map(async (sessionId) => ({
          sessionId,
          result: await this.emailOtpSessions.readWarmSessionStatusOnly(sessionId),
        })),
      );
      const unresolvedSessionIds = secondaryResults
        .filter(
          (entry) =>
            !entry.result.ok &&
            (entry.result.code === 'not_found' || entry.result.code === 'worker_error'),
        )
        .map((entry) => entry.sessionId);
      const primary =
        unresolvedSessionIds.length === 0
          ? { results: [] }
          : typeof base.getWarmSessionStatuses === 'function'
            ? await base.getWarmSessionStatuses({ sessionIds: unresolvedSessionIds })
            : {
                results: await Promise.all(
                  unresolvedSessionIds.map(async (sessionId) => ({
                    sessionId,
                    result: await base.getWarmSessionStatus({ sessionId }),
                  })),
                ),
              };
      const primaryBySessionId = new Map(primary.results.map((entry) => [entry.sessionId, entry]));
      const results = secondaryResults.map((entry) => {
        if (
          entry.result.ok ||
          (entry.result.code !== 'not_found' && entry.result.code !== 'worker_error')
        ) {
          return entry;
        }
        return primaryBySessionId.get(entry.sessionId) || entry;
      });
      return { results };
    };

    const claimWarmSessionMaterial = async (args: {
      sessionId: string;
      uses?: number;
      consume?: boolean;
      curve?: 'ed25519' | 'ecdsa';
      chain?: 'near' | 'tempo' | 'evm';
    }): Promise<WarmSessionClaimResult> => {
      const secondary = await this.emailOtpSessions.claimWarmSessionMaterial(args);
      if (secondary.ok || (secondary.code !== 'not_found' && secondary.code !== 'worker_error')) {
        return secondary;
      }
      return await base.claimWarmSessionMaterial(args);
    };

    const clearWarmSessionMaterial = async (args: { sessionId: string }): Promise<void> => {
      await Promise.all([
        base.clearWarmSessionMaterial(args).catch(() => undefined),
        this.emailOtpSessions.clearWarmSessionMaterial(args.sessionId).catch(() => undefined),
      ]);
    };

    return new Proxy(base, {
      get: (target, prop, receiver) => {
        if (prop === 'getWarmSessionStatus') return getWarmSessionStatus;
        if (prop === 'getWarmSessionStatuses') return getWarmSessionStatuses;
        if (prop === 'claimWarmSessionMaterial') return claimWarmSessionMaterial;
        if (prop === 'clearWarmSessionMaterial') return clearWarmSessionMaterial;
        const value = Reflect.get(target, prop, receiver);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    }) as TouchConfirmRuntimeBridgePort;
  }

  private createWarmSessionStatusOnlyTouchConfirm(
    base: TouchConfirmRuntimeBridgePort,
  ): TouchConfirmRuntimeBridgePort {
    const primary = base as WarmSessionStatusOnlyTouchConfirmPort;
    const readPrimaryWarmSessionStatusOnly = async (args: {
      sessionId: string;
    }): Promise<WarmSessionStatusResult> => {
      if (typeof primary.readWarmSessionStatusOnly !== 'function') {
        return {
          ok: false,
          code: 'status_reader_unavailable',
          message: 'Warm-session status-only reader is unavailable',
        };
      }
      return await primary.readWarmSessionStatusOnly({ sessionId: args.sessionId });
    };
    const readCombinedWarmSessionStatusOnly = async (args: {
      sessionId: string;
    }): Promise<WarmSessionStatusResult> => {
      const secondary = await this.emailOtpSessions.readWarmSessionStatusOnly(args.sessionId);
      if (secondary.ok || (secondary.code !== 'not_found' && secondary.code !== 'worker_error')) {
        return secondary;
      }
      return await readPrimaryWarmSessionStatusOnly(args);
    };
    const readCombinedWarmSessionStatusesOnly = async (args: {
      sessionIds: string[];
    }): Promise<WarmSessionStatusBatchResult> => {
      const normalizedSessionIds = Array.from(
        new Set(
          (Array.isArray(args.sessionIds) ? args.sessionIds : [])
            .map((sessionId) => String(sessionId || '').trim())
            .filter(Boolean),
        ),
      );
      const secondaryResults = await Promise.all(
        normalizedSessionIds.map(async (sessionId) => ({
          sessionId,
          result: await this.emailOtpSessions.readWarmSessionStatusOnly(sessionId),
        })),
      );
      const unresolvedSessionIds = secondaryResults
        .filter(
          (entry) =>
            !entry.result.ok &&
            (entry.result.code === 'not_found' || entry.result.code === 'worker_error'),
        )
        .map((entry) => entry.sessionId);
      const primaryResults =
        unresolvedSessionIds.length === 0
          ? { results: [] }
          : typeof primary.readWarmSessionStatusesOnly === 'function'
            ? await primary.readWarmSessionStatusesOnly({ sessionIds: unresolvedSessionIds })
            : {
                results: await Promise.all(
                  unresolvedSessionIds.map(async (sessionId) => ({
                    sessionId,
                    result: await readPrimaryWarmSessionStatusOnly({ sessionId }),
                  })),
                ),
              };
      const primaryBySessionId = new Map(
        primaryResults.results.map((entry) => [entry.sessionId, entry.result]),
      );
      return {
        results: secondaryResults.map((entry) =>
          entry.result.ok ||
          (entry.result.code !== 'not_found' && entry.result.code !== 'worker_error')
            ? entry
            : {
                sessionId: entry.sessionId,
                result: primaryBySessionId.get(entry.sessionId) || entry.result,
              },
        ),
      };
    };

    return new Proxy(base, {
      get: (target, prop, receiver) => {
        if (prop === 'getWarmSessionStatus') return readCombinedWarmSessionStatusOnly;
        if (prop === 'getWarmSessionStatuses') return readCombinedWarmSessionStatusesOnly;
        const value = Reflect.get(target, prop, receiver);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    }) as TouchConfirmRuntimeBridgePort;
  }

  private async ensureSealedRefreshStartupParity(): Promise<void> {
    await this.sealedRefreshStartupParityPromise;
    if (this.sealedRefreshStartupParityError) {
      throw this.sealedRefreshStartupParityError;
    }
  }

  async assertSealedRefreshStartupParity(): Promise<void> {
    await this.ensureSealedRefreshStartupParity();
  }

  async restorePersistedSessionsForAccount(
    args: RestorePersistedSessionsForAccountInput,
  ): Promise<RestorePersistedSessionsForAccountResult> {
    const walletId = String(toAccountId(args.walletId) || '').trim();
    const empty = { listed: 0, attempted: 0, restored: 0, deferred: 0, skipped: 0, truncated: 0 };
    if (!walletId) return empty;
    const targets = args.authMethod ? [args.authMethod] : (['email_otp', 'passkey'] as const);
    const results = await Promise.all(
      targets.map(async (authMethod) => {
        if (authMethod === 'email_otp') {
          return await this.emailOtpSessions.restorePersistedSessionsForAccount({
            ...args,
            walletId,
            authMethod,
          });
        }
        return (
          (await this.touchConfirm.restorePersistedSessionsForAccount?.({
            ...args,
            walletId,
            authMethod,
          })) ?? empty
        );
      }),
    );
    return results.reduce<RestorePersistedSessionsForAccountResult>(
      (acc, result) => ({
        listed: acc.listed + result.listed,
        attempted: acc.attempted + result.attempted,
        restored: acc.restored + result.restored,
        deferred: acc.deferred + result.deferred,
        skipped: acc.skipped + result.skipped,
        truncated: acc.truncated + result.truncated,
      }),
      empty,
    );
  }

  async readPersistedSigningSessionSnapshot(
    args: ReadSigningSessionSnapshotInput,
  ): Promise<SigningSessionSnapshot> {
    const accountId = String(toAccountId(args.walletId) || '').trim();
    const statusReader = this.createWarmSessionStatusOnlyTouchConfirm(this.touchConfirm);
    const pushRuntimeEcdsaRecord = (
      records: SigningSessionSnapshotRuntimeEcdsaRecord[],
      seen: Set<string>,
      record: SigningSessionSnapshotRuntimeEcdsaRecord,
    ): void => {
      // Tempo and EVM can share the same threshold session id. Runtime snapshot
      // dedupe must preserve the exact lane identity that transaction prepare uses.
      const identityKey = ecdsaSnapshotLaneIdentityKey(record);
      if (!identityKey || seen.has(identityKey)) return;
      seen.add(identityKey);
      records.push(record);
    };

    return await readSigningSessionSnapshot(
      {
        ...args,
        walletId: accountId,
      },
      {
        listSealedRecordsForAccount: async ({ accountId: recordAccountId, filter }) => {
          const listByAuthMethod = async (authMethod: 'email_otp' | 'passkey') => {
            if (filter.curve === 'ecdsa') {
              return await listExactSealedSessionsForAccount({
                accountId: recordAccountId,
                filter: { authMethod, curve: 'ecdsa', chain: filter.chain },
              });
            }
            return await listExactSealedSessionsForAccount({
              accountId: recordAccountId,
              filter: { authMethod, curve: 'ed25519' },
            });
          };
          if (filter.authMethod) {
            return await listByAuthMethod(filter.authMethod);
          }
          const [emailOtpRecords, passkeyRecords] = await Promise.all([
            listByAuthMethod('email_otp'),
            listByAuthMethod('passkey'),
          ]);
          return [...emailOtpRecords, ...passkeyRecords];
        },
        listRuntimeEcdsaRecordsForAccount: async ({ accountId: recordAccountId }) => {
          const records: SigningSessionSnapshotRuntimeEcdsaRecord[] = [];
          const seen = new Set<string>();
          for (const chain of ['tempo', 'evm'] as const) {
            for (const runtimeRecord of this.listThresholdEcdsaSessionRecordsForLookup({
              nearAccountId: recordAccountId,
              chain,
            })) {
              const authMethod = runtimeRecord.source === SIGNER_AUTH_METHODS.emailOtp
                ? 'email_otp'
                : 'passkey';
              if (args.authMethod && args.authMethod !== authMethod) continue;
              pushRuntimeEcdsaRecord(records, seen, {
                authMethod,
                curve: 'ecdsa',
                chain,
                thresholdSessionId: runtimeRecord.thresholdSessionId,
                walletSigningSessionId: runtimeRecord.walletSigningSessionId,
              });
            }
          }
          return records;
        },
        listRuntimeEd25519RecordsForAccount: async ({ accountId: recordAccountId }) => {
          const records: SigningSessionSnapshotRuntimeEd25519Record[] = [];
          const seen = new Set<string>();
          const pushRecord = (record: SigningSessionSnapshotRuntimeEd25519Record): void => {
            const identityKey = ed25519SnapshotLaneIdentityKey(record);
            if (!identityKey || seen.has(identityKey)) return;
            seen.add(identityKey);
            records.push(record);
          };
          for (const identity of listResolvedIdentitiesForAccount({
            walletId: recordAccountId,
            ...(args.authMethod ? { authMethod: args.authMethod } : {}),
            curve: 'ed25519',
          })) {
            pushRecord({
              authMethod: identity.authMethod,
              curve: 'ed25519',
              chain: 'near',
              thresholdSessionId: identity.thresholdSessionId,
              walletSigningSessionId: identity.walletSigningSessionId,
            });
          }
          return records;
        },
        readRuntimeClaimsForSessions: async (sessionIds) => {
          const claims = new Map<string, SigningSessionSnapshotRuntimeClaim | null>();
          await Promise.all(
            sessionIds.map(async (sessionId) => {
              const ecdsaRecord =
                getStoredThresholdEcdsaSessionRecordByThresholdSessionIdValue(sessionId);
              const statusSessionId =
                ecdsaRecord?.source === SIGNER_AUTH_METHODS.emailOtp
                  ? resolveEmailOtpEcdsaWorkerSessionId(ecdsaRecord)
                  : sessionId;
              const status = await statusReader
                .getWarmSessionStatus({ sessionId: statusSessionId })
                .catch(() => null);
              claims.set(
                sessionId,
                status
                  ? warmStatusToSigningSessionSnapshotRuntimeClaim({ sessionId, status })
                  : null,
              );
            }),
          );
          return claims;
        },
      },
    );
  }

  private async ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap(
    args: Parameters<typeof bootstrapEcdsaSessionValue>[1],
  ): Promise<void> {
    try {
      await this.ensureSealedRefreshStartupParity();
    } catch (error: unknown) {
      if (args.source === 'registration') {
        const message = error instanceof Error ? error.message : String(error || 'unknown error');
        console.warn(
          '[threshold-ecdsa] registration bootstrap skipped sealed-refresh startup parity enforcement',
          {
            nearAccountId: String(args.nearAccountId || '').trim(),
            chain: args.chain,
            error: message,
          },
        );
        return;
      }
      if (
        args.operationIntent === SigningOperationIntent.TransactionSign &&
        isRetryableSealedRefreshCapabilityFetchError(error)
      ) {
        const message = error instanceof Error ? error.message : String(error || 'unknown error');
        console.warn(
          '[threshold-ecdsa] transaction bootstrap skipped retryable sealed-refresh capability fetch failure',
          {
            nearAccountId: String(args.nearAccountId || '').trim(),
            chain: args.chain,
            error: message,
          },
        );
        return;
      }
      if (
        args.emailOtpAuthContext?.authMethod === SIGNER_AUTH_METHODS.emailOtp &&
        isRetryableSealedRefreshCapabilityFetchError(error)
      ) {
        const message = error instanceof Error ? error.message : String(error || 'unknown error');
        console.warn(
          '[threshold-ecdsa] Email OTP bootstrap skipped retryable sealed-refresh capability fetch failure',
          {
            nearAccountId: String(args.nearAccountId || '').trim(),
            chain: args.chain,
            error: message,
          },
        );
        return;
      }
      throw error;
    }
  }

  private async ensureSealedRefreshStartupParityForTransactionSigning(args: {
    nearAccountId: string;
    chain: ThresholdEcdsaActivationChain;
  }): Promise<void> {
    try {
      await this.ensureSealedRefreshStartupParity();
    } catch (error: unknown) {
      if (!isRetryableSealedRefreshCapabilityFetchError(error)) throw error;
      const message = error instanceof Error ? error.message : String(error || 'unknown error');
      console.warn(
        '[threshold-ecdsa] transaction signing skipped retryable sealed-refresh capability fetch failure',
        {
          nearAccountId: String(args.nearAccountId || '').trim(),
          chain: args.chain,
          error: message,
        },
      );
    }
  }

  private createWarmSessionCapabilityReader() {
    return createWarmSessionCapabilityReader({
      touchConfirm: this.touchConfirm,
      signingSessionSeal: this.seamsPasskeyConfigs.signing.sessionSeal,
      listThresholdEcdsaSessionRecordsForLookup: ({ nearAccountId, chain }) =>
        this.listThresholdEcdsaSessionRecordsForLookup({
          nearAccountId,
          chain,
        }),
      getEmailOtpWarmSessionStatus: (sessionId) =>
        this.emailOtpSessions.readWarmSessionStatusOnly(sessionId),
    });
  }

  private createWarmSessionStatusReader() {
    return createWarmSessionStatusReader({
      touchConfirm: this.createWarmSessionStatusOnlyTouchConfirm(this.touchConfirm),
      listThresholdEcdsaSessionRecordsForLookup: ({ nearAccountId, chain }) =>
        this.listThresholdEcdsaSessionRecordsForLookup({
          nearAccountId,
          chain,
        }),
      getEmailOtpWarmSessionStatus: (sessionId) =>
        this.emailOtpSessions.readWarmSessionStatusOnly(sessionId),
    });
  }

  private async getWalletSigningBudgetAvailableStatus(args: {
    nearAccountId: AccountId | string;
    walletSigningSessionId?: string;
    targetThresholdSessionIds?: string[];
    targetBackingMaterialSessionIds?: string[];
    trustedStatusAuth?: SigningSessionBudgetStatusAuth;
  }): Promise<SigningSessionStatus | null> {
    const walletSigningSessionId = String(args.walletSigningSessionId || '').trim();
    if (!walletSigningSessionId) return null;
    return await this.orchestrationDeps.signingSessionCoordinator
      .getAvailableStatus({
        nearAccountId: args.nearAccountId,
        walletSigningSessionId,
        targetThresholdSessionIds: args.targetThresholdSessionIds,
        targetBackingMaterialSessionIds: args.targetBackingMaterialSessionIds,
        trustedStatusAuth: args.trustedStatusAuth,
      })
      .catch(() => null);
  }

  private async readTrustedWalletSigningBudgetStatus(args: {
    nearAccountId: AccountId | string;
    walletSigningSessionId?: string;
    targetThresholdSessionIds?: string[];
    trustedStatusAuth?: SigningSessionBudgetStatusAuth;
  }): Promise<SigningSessionStatus | null> {
    const walletSigningSessionId = String(args.walletSigningSessionId || '').trim();
    if (!walletSigningSessionId) return null;
    const trustedStatusAuth = args.trustedStatusAuth;
    const auth =
      trustedStatusAuth &&
      String(trustedStatusAuth.relayerUrl || '').trim() &&
      String(trustedStatusAuth.thresholdSessionId || '').trim()
        ? {
            relayerUrl: String(trustedStatusAuth.relayerUrl || '').trim(),
            thresholdSessionId: String(trustedStatusAuth.thresholdSessionId || '').trim(),
            ...(String(trustedStatusAuth.thresholdSessionJwt || '').trim()
              ? { thresholdSessionJwt: String(trustedStatusAuth.thresholdSessionJwt || '').trim() }
              : {}),
          }
        : this.resolveWalletSigningBudgetStatusAuth({
            nearAccountId: args.nearAccountId,
            walletSigningSessionId,
            targetThresholdSessionIds: args.targetThresholdSessionIds,
          });
    if (!auth?.relayerUrl) return null;
    const response = await fetch(
      joinNormalizedUrl(auth.relayerUrl, '/session/signing-budget/status'),
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(auth.thresholdSessionJwt ? { Authorization: `Bearer ${auth.thresholdSessionJwt}` } : {}),
        },
        credentials: auth.thresholdSessionJwt ? 'omit' : 'include',
        body: JSON.stringify({
          walletSigningSessionId,
          ...(auth.thresholdSessionId ? { thresholdSessionId: auth.thresholdSessionId } : {}),
        }),
      },
    );
    const json = (await response.json().catch(() => null)) as Record<string, unknown> | null;
    if (!response.ok || !json || json.ok === false) {
      if (response.status === 401 || response.status === 403 || response.status === 404) {
        return {
          sessionId: walletSigningSessionId,
          status: 'not_found',
          ...(typeof json?.code === 'string' ? { statusCode: json.code } : {}),
        };
      }
      return null;
    }
    const status = String(json.status || '').trim();
    if (status !== 'active' && status !== 'exhausted' && status !== 'expired') return null;
    const remainingUses = Math.max(0, Math.floor(Number(json.remainingUses) || 0));
    const expiresAtMs = Math.floor(Number(json.expiresAtMs) || 0);
    const projectionVersion = String(json.projectionVersion || '').trim();
    return {
      sessionId: walletSigningSessionId,
      status,
      ...(status === 'active' || status === 'exhausted' ? { remainingUses } : {}),
      ...(expiresAtMs > 0 ? { expiresAtMs } : {}),
      ...(projectionVersion ? { projectionVersion } : {}),
    };
  }

  private resolveWalletSigningBudgetStatusAuth(args: {
    nearAccountId: AccountId | string;
    walletSigningSessionId: string;
    targetThresholdSessionIds?: string[];
  }):
    | {
        relayerUrl: string;
        thresholdSessionId?: string;
        thresholdSessionJwt?: string;
      }
    | null {
    const accountId = toAccountId(args.nearAccountId);
    const walletSigningSessionId = String(args.walletSigningSessionId || '').trim();
    if (!accountId || !walletSigningSessionId) return null;
    const targetThresholdIds = new Set(
      (args.targetThresholdSessionIds || [])
        .map((value) => String(value || '').trim())
        .filter(Boolean),
    );
    const candidates: Array<{
      relayerUrl: string;
      thresholdSessionId: string;
      thresholdSessionJwt?: string;
      exactTarget: boolean;
    }> = [];
    const pushCandidate = (
      record:
        | {
            relayerUrl?: string;
            thresholdSessionId?: string;
            thresholdSessionJwt?: string;
            walletSigningSessionId?: string;
            thresholdSessionKind?: string;
          }
        | null
        | undefined,
    ): void => {
      if (!record) return;
      if (String(record.walletSigningSessionId || '').trim() !== walletSigningSessionId) return;
      const thresholdSessionId = String(record.thresholdSessionId || '').trim();
      const relayerUrl = String(record.relayerUrl || '').trim();
      if (!thresholdSessionId || !relayerUrl) return;
      const exactTarget =
        targetThresholdIds.size === 0 || targetThresholdIds.has(thresholdSessionId);
      if (!exactTarget && targetThresholdIds.size > 0) return;
      const thresholdSessionJwt = String(record.thresholdSessionJwt || '').trim();
      if (!thresholdSessionJwt && record.thresholdSessionKind !== 'cookie') return;
      candidates.push({
        relayerUrl,
        thresholdSessionId,
        ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
        exactTarget,
      });
    };
    for (const targetThresholdSessionId of targetThresholdIds) {
      pushCandidate(
        getStoredThresholdEd25519SessionRecordByThresholdSessionIdValue(
          targetThresholdSessionId,
        ),
      );
      pushCandidate(
        getStoredThresholdEcdsaSessionRecordByThresholdSessionIdValue(
          targetThresholdSessionId,
        ),
      );
    }
    pushCandidate(getStoredThresholdEd25519SessionRecordForAccountValue(accountId));
    for (const chain of ['tempo', 'evm'] as const) {
      for (const record of this.listThresholdEcdsaSessionRecordsForLookup({
        nearAccountId: accountId,
        chain,
      })) {
        pushCandidate(record);
      }
    }
    return (
      candidates.find((candidate) => candidate.exactTarget && candidate.thresholdSessionJwt) ||
      candidates.find((candidate) => candidate.exactTarget) ||
      candidates.find((candidate) => candidate.thresholdSessionJwt) ||
      candidates[0] ||
      null
    );
  }

  private mergeWalletSigningBudgetStatus<TStatus extends SigningSessionStatus>(
    status: TStatus,
    budgetStatus: SigningSessionStatus | null,
  ): TStatus {
    if (!budgetStatus) return status;
    if (budgetStatus.status === 'not_found') return status;
    if (budgetStatus.status !== 'active') {
      return {
        ...status,
        ...budgetStatus,
        sessionId: status.sessionId,
      };
    }
    const budgetRemainingUses = Math.max(0, Math.floor(Number(budgetStatus.remainingUses) || 0));
    const statusExpiresAtMs = Math.floor(Number(status.expiresAtMs) || 0);
    const budgetExpiresAtMs = Math.floor(Number(budgetStatus.expiresAtMs) || 0);
    // Runtime material counters can hit zero before the server-side wallet
    // budget does. The budget route is the trusted policy source; local status
    // only supplies material/auth context.
    return {
      ...status,
      status: 'active',
      remainingUses: budgetRemainingUses,
      expiresAtMs:
        statusExpiresAtMs > 0 && budgetExpiresAtMs > 0
          ? Math.min(statusExpiresAtMs, budgetExpiresAtMs)
          : statusExpiresAtMs || budgetExpiresAtMs,
      ...(budgetStatus.authMethod ? { authMethod: budgetStatus.authMethod } : {}),
      ...(budgetStatus.retention ? { retention: budgetStatus.retention } : {}),
    };
  }

  private async clearEcdsaEphemeralMaterialForWarmSession(args: {
    nearAccountId: AccountId;
    chain: ThresholdEcdsaActivationChain;
    thresholdSessionId?: string;
    source?: ThresholdEcdsaSessionStoreSource;
  }): Promise<void> {
    if (!args.source) return;
    await Promise.resolve(
      this.clearThresholdEcdsaSigningArtifactsForLane({
        nearAccountId: args.nearAccountId,
        chain: args.chain,
        source: args.source,
      }),
    );
    this.clearThresholdEcdsaSessionRecordForLane({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      source: args.source,
    });
  }

  private async withThresholdEcdsaBootstrapQueue<T>(
    nearAccountId: AccountId,
    task: () => Promise<T>,
  ): Promise<T> {
    const accountKey = String(toAccountId(String(nearAccountId || '').trim()));
    const previous =
      this.thresholdEcdsaBootstrapQueueByAccount.get(accountKey) || Promise.resolve();
    const waitForPrevious = previous.catch(() => undefined);

    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const next = waitForPrevious.then(() => gate);
    this.thresholdEcdsaBootstrapQueueByAccount.set(accountKey, next);

    await waitForPrevious;
    try {
      return await task();
    } finally {
      release();
      if (this.thresholdEcdsaBootstrapQueueByAccount.get(accountKey) === next) {
        this.thresholdEcdsaBootstrapQueueByAccount.delete(accountKey);
      }
    }
  }

  prewarmSignerWorkers(): void {
    this.orchestrationDeps.getManagerConvenienceDeps().prewarmSignerWorkers();
  }

  async warmCriticalResources(nearAccountId?: string): Promise<void> {
    await this.ensureSealedRefreshStartupParity();
    await this.orchestrationDeps.getManagerConvenienceDeps().warmCriticalResources(nearAccountId);
  }

  getRpId(): string {
    return this.touchIdPrompt.getRpId();
  }

  getNonceCoordinator(): NonceCoordinator {
    return this.nonceCoordinator;
  }

  setTheme(next: ThemeName): void {
    if (next !== 'light' && next !== 'dark') return;
    this.theme = next;
  }

  getTheme(): ThemeName {
    return this.theme;
  }

  getUserPreferences(): UserPreferencesManager {
    return this.userPreferencesManager;
  }

  async signNear<TRequest extends NearSignIntentRequest>(
    request: TRequest,
  ): Promise<NearSignIntentResult<TRequest>> {
    return await signNearValue(this.orchestrationDeps.nearSigningDeps, request);
  }

  async signTempo(args: {
    nearAccountId: string;
    request: TempoSigningRequest | EvmSigningRequest;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    shouldAbort?: () => boolean;
    onEvent?: (event: SigningFlowEvent) => void;
  }): Promise<TempoSignedResult | EvmSignedResult> {
    await this.ensureSealedRefreshStartupParityForTransactionSigning({
      nearAccountId: args.nearAccountId,
      chain: args.request.chain === 'evm' ? 'evm' : 'tempo',
    });
    return await signTempoValue(this.orchestrationDeps.tempoSigningDeps, args);
  }

  async reportTempoBroadcastAccepted(args: ReportTempoBroadcastAcceptedArgs): Promise<void> {
    await reportTempoBroadcastAcceptedValue(this.orchestrationDeps.tempoSigningDeps, args);
  }

  async reportTempoBroadcastRejected(args: ReportTempoBroadcastRejectedArgs): Promise<void> {
    await reportTempoBroadcastRejectedValue(this.orchestrationDeps.tempoSigningDeps, args);
  }

  async reportTempoFinalized(args: ReportTempoFinalizedArgs): Promise<void> {
    await reportTempoFinalizedValue(this.orchestrationDeps.tempoSigningDeps, args);
  }

  async reportTempoDroppedOrReplaced(args: ReportTempoDroppedOrReplacedArgs): Promise<void> {
    await reportTempoDroppedOrReplacedValue(this.orchestrationDeps.tempoSigningDeps, args);
  }

  async reconcileTempoNonceLane(args: ReconcileTempoNonceLaneArgs): Promise<TempoNonceLaneStatus> {
    return await reconcileTempoNonceLaneValue(this.orchestrationDeps.tempoSigningDeps, args);
  }

  storeUserData(userData: StoreUserDataInput): Promise<void> {
    return storeUserDataValue(
      this.orchestrationDeps.registrationAccountLifecycleDeps,
      userData,
    ).then(() => undefined);
  }

  getAllUsers(): Promise<ClientUserData[]> {
    return listNearAccountProjections(this.orchestrationDeps.indexedDB.clientDB);
  }

  getUserBySignerSlot(
    nearAccountId: AccountId,
    signerSlot: number,
  ): Promise<ClientUserData | null> {
    return getNearAccountProjection(
      this.orchestrationDeps.indexedDB.clientDB,
      nearAccountId,
      signerSlot,
    );
  }

  getLastUser(): Promise<ClientUserData | null> {
    return getLastSelectedNearAccountProjection(this.orchestrationDeps.indexedDB.clientDB);
  }

  getAuthenticatorsByUser(nearAccountId: AccountId): Promise<ClientAuthenticatorData[]> {
    return (async () => {
      const accountId = toAccountId(nearAccountId);
      const context = await resolveProfileAccountContextFromCandidates(
        this.orchestrationDeps.indexedDB.clientDB,
        buildNearAccountRefs(accountId),
      ).catch(() => null);
      if (!context?.profileId) return [];
      const rows = await this.orchestrationDeps.indexedDB.clientDB.listProfileAuthenticators(
        context.profileId,
      );
      return rows.map((row) => mapProfileAuthenticatorToClient(row, accountId));
    })();
  }

  updateLastLogin(nearAccountId: AccountId): Promise<void> {
    return (async () => {
      const accountId = toAccountId(nearAccountId);
      const context = await resolveProfileAccountContextFromCandidates(
        this.orchestrationDeps.indexedDB.clientDB,
        buildNearAccountRefs(accountId),
      ).catch(() => null);
      if (!context?.profileId) return;
      const [lastProfileState, profile] = await Promise.all([
        this.orchestrationDeps.indexedDB.clientDB.getLastProfileState().catch(() => null),
        this.orchestrationDeps.indexedDB.clientDB.getProfile(context.profileId).catch(() => null),
      ]);
      const defaultSignerSlot = Number(profile?.defaultSignerSlot);
      const signerSlot =
        lastProfileState?.profileId === context.profileId
          ? lastProfileState.activeSignerSlot
          : Number.isSafeInteger(defaultSignerSlot) && defaultSignerSlot >= 1
            ? defaultSignerSlot
            : 1;
      await this.orchestrationDeps.indexedDB.clientDB.setLastProfileStateForProfile(
        context.profileId,
        signerSlot,
      );
    })();
  }

  setLastUser(nearAccountId: AccountId, signerSlot: number = 1): Promise<void> {
    return (async () => {
      const normalizedSignerSlot = Number(signerSlot);
      if (!Number.isSafeInteger(normalizedSignerSlot) || normalizedSignerSlot < 1) {
        throw new Error('PasskeyClientDB: signerSlot must be an integer >= 1');
      }
      const accountId = toAccountId(nearAccountId);
      const context = await resolveProfileAccountContextFromCandidates(
        this.orchestrationDeps.indexedDB.clientDB,
        buildNearAccountRefs(accountId),
      ).catch(() => null);
      if (!context?.profileId) {
        throw new Error(
          `PasskeyClientDB: Missing profile/account mapping for NEAR account ${String(accountId)}`,
        );
      }
      await this.orchestrationDeps.indexedDB.clientDB.setLastProfileStateForProfile(
        context.profileId,
        normalizedSignerSlot,
      );
    })();
  }

  initializeCurrentUser(nearAccountId: AccountId, nearClientArg?: NearClient): Promise<void> {
    return initializeCurrentUserValue(this.orchestrationDeps.registrationAccountLifecycleDeps, {
      nearAccountId,
      nearClient: nearClientArg,
    });
  }

  storeAuthenticator(authenticatorData: StoreAuthenticatorInput): Promise<void> {
    return storeAuthenticatorValue(
      this.orchestrationDeps.registrationAccountLifecycleDeps,
      authenticatorData,
    );
  }

  rollbackUserRegistration(nearAccountId: AccountId): Promise<void> {
    return rollbackUserRegistrationValue(
      this.orchestrationDeps.registrationAccountLifecycleDeps,
      nearAccountId,
    );
  }

  hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean> {
    return hasPasskeyCredentialValue(
      this.orchestrationDeps.registrationAccountLifecycleDeps,
      nearAccountId,
    );
  }

  atomicStoreRegistrationData(args: {
    nearAccountId: AccountId;
    credential: WebAuthnRegistrationCredential;
    operationalPublicKey: string;
  }): Promise<void> {
    return atomicStoreRegistrationDataValue(
      this.orchestrationDeps.registrationAccountLifecycleDeps,
      args,
    );
  }

  requestRegistrationCredentialConfirmation(params: {
    nearAccountId: string;
    signerSlot: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
  }): Promise<RegistrationCredentialConfirmationPayload> {
    return requestRegistrationCredentialConfirmationValue(
      this.orchestrationDeps.registrationSessionDeps,
      params,
    );
  }

  getAuthenticationCredentialsSerialized(args: {
    nearAccountId: AccountId;
    challengeB64u: string;
    allowCredentials: WebAuthnAllowCredential[];
    includeSecondPrfOutput?: boolean;
  }): Promise<WebAuthnAuthenticationCredential> {
    return getAuthenticationCredentialsSerializedValue(
      this.orchestrationDeps.registrationSessionDeps,
      args,
    );
  }

  extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array> {
    return this.orchestrationDeps.nearKeyOpsDeps.signingKeyOps.extractCosePublicKey(
      attestationObjectBase64url,
    );
  }

  async exportKeypairWithUI(
    nearAccountId: AccountId,
    options: {
      chain: 'near' | 'evm' | 'tempo';
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
      onEvent?: KeyExportEventCallback;
    },
  ): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
    const flowId = createKeyExportFlowId(nearAccountId, options.chain);
    emitKeyExportEvent(options.onEvent, {
      phase: KeyExportEventPhase.STEP_01_STARTED,
      status: 'running',
      flowId,
      accountId: String(nearAccountId),
      interaction: { kind: 'none', overlay: 'none' },
      data: { chain: options.chain },
    });
    try {
      return await this.exportKeypairWithUIInternal({
        nearAccountId,
        options,
        flowId,
        onEvent: options.onEvent,
      });
    } catch (error: unknown) {
      const cancelled = isUserCancellationError(error);
      emitKeyExportEvent(options.onEvent, {
        phase: cancelled ? KeyExportEventPhase.CANCELLED : KeyExportEventPhase.FAILED,
        status: cancelled ? 'cancelled' : 'failed',
        flowId,
        accountId: String(nearAccountId),
        interaction: { kind: 'none', overlay: 'hide' },
        error: {
          message:
            errorMessage(error) || (cancelled ? 'Key export cancelled' : 'Key export failed'),
        },
        data: { chain: options.chain },
      });
      throw error;
    }
  }

  private async exportKeypairWithUIInternal(args: {
    nearAccountId: AccountId;
    options: {
      chain: 'near' | 'evm' | 'tempo';
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
    flowId: string;
    onEvent?: KeyExportEventCallback;
  }): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
    if (args.options.chain === 'near') {
      const exportLane = await this.restoreNearEd25519SessionForExport({
        nearAccountId: args.nearAccountId,
      });
      const singleKeyHssResult = await this.tryExportNearEd25519SingleKeyHssWithAuthorization({
        nearAccountId: args.nearAccountId,
        exportLane,
        options: {
          variant: args.options.variant,
          theme: args.options.theme,
        },
        flowId: args.flowId,
        onEvent: args.onEvent,
      });
      if (singleKeyHssResult) return singleKeyHssResult;
      throw new Error(
        'NEAR Ed25519 export now requires the canonical single-key HSS export path',
      );
    }

    const exportChain = args.options.chain === 'tempo' ? 'tempo' : 'evm';
    const exportLane = await this.restoreEcdsaSessionForExport({
      nearAccountId: args.nearAccountId,
      chain: exportChain,
    });
    const exportMaterial = await this.resolveEcdsaExportMaterialForLane(exportLane);
    if (exportMaterial.kind === 'fresh_email_otp') {
      return await this.exportThresholdEcdsaKeyWithFreshEmailOtpAuthorization({
        nearAccountId: args.nearAccountId,
        chain: exportChain,
        exportLane,
        material: exportMaterial,
        options: {
          variant: args.options.variant,
          theme: args.options.theme,
        },
        flowId: args.flowId,
        onEvent: args.onEvent,
      });
    }
    return await this.exportThresholdEcdsaKeyWithAuthorization({
      nearAccountId: args.nearAccountId,
      chain: exportChain,
      keyRef: exportMaterial.keyRef,
      exportLane,
      options: {
        variant: args.options.variant,
        theme: args.options.theme,
      },
      flowId: args.flowId,
      onEvent: args.onEvent,
    });
  }

  private async resolveKeyExportAuthMethod(
    nearAccountId: AccountId,
  ): Promise<'email_otp' | 'passkey'> {
    const context = await resolveProfileAccountContextFromCandidates(
      this.orchestrationDeps.indexedDB.clientDB,
      buildNearAccountRefs(toAccountId(nearAccountId)),
    ).catch(() => null);
    if (!context?.profileId) return 'passkey';

    const [profile, activeSigners, lastProfileState] = await Promise.all([
      this.orchestrationDeps.indexedDB.clientDB.getProfile(context.profileId).catch(() => null),
      this.orchestrationDeps.indexedDB.clientDB
        .listAccountSigners({
          chainIdKey: context.accountRef.chainIdKey,
          accountAddress: context.accountRef.accountAddress,
          status: 'active',
        })
        .catch(() => []),
      this.orchestrationDeps.indexedDB.clientDB.getLastProfileState().catch(() => null),
    ]);
    if (!profile || !activeSigners.length) return 'passkey';
    const activeSignerSlot =
      lastProfileState?.profileId === context.profileId
        ? Number(lastProfileState.activeSignerSlot)
        : undefined;
    const selectedSigner = selectAccountSigner({
      profile,
      activeSigners,
      ...(typeof activeSignerSlot === 'number' &&
      Number.isSafeInteger(activeSignerSlot) &&
      activeSignerSlot >= 1
        ? { signerSlot: activeSignerSlot }
        : {}),
    });
    return selectedSigner?.signerAuthMethod === SIGNER_AUTH_METHODS.emailOtp
      ? 'email_otp'
      : 'passkey';
  }

  private async resolveNearEd25519ExportLane(
    args: {
      nearAccountId: AccountId;
      authMethod: 'email_otp' | 'passkey';
    },
  ): Promise<ExactNearEd25519ExportLane> {
    const snapshot = await this.readPersistedSigningSessionSnapshot({
      walletId: args.nearAccountId,
    });
    const concreteCandidates = snapshot.candidates.ed25519.near.filter(
      isConcreteEd25519ExportLane,
    );

    const selected = selectExactExportSnapshotLane({
      context: 'ed25519-export',
      candidates: concreteCandidates,
      authMethod: args.authMethod,
    });
    return {
      curve: 'ed25519',
      chain: 'near',
      nearAccountId: args.nearAccountId,
      authMethod: selected.authMethod,
      walletSigningSessionId: selected.walletSigningSessionId,
      thresholdSessionId: selected.thresholdSessionId,
      state: selected.state,
      source: selected.source,
    };
  }

  private async resolveEcdsaExportLane(args: {
    nearAccountId: AccountId;
    chain: 'evm' | 'tempo';
    authMethod: 'email_otp' | 'passkey';
  }): Promise<ExactEcdsaExportLane> {
    const snapshot = await this.readPersistedSigningSessionSnapshot({
      walletId: args.nearAccountId,
    });
    const concreteCandidates = (snapshot.candidates.ecdsa[args.chain] || []).filter(
      isConcreteEcdsaExportLane,
    );
    const selected = selectExactExportSnapshotLane({
      context: 'ecdsa-export',
      candidates: concreteCandidates,
      authMethod: args.authMethod,
    });
    return {
      curve: 'ecdsa',
      chain: args.chain,
      nearAccountId: args.nearAccountId,
      authMethod: selected.authMethod,
      walletSigningSessionId: selected.walletSigningSessionId,
      thresholdSessionId: selected.thresholdSessionId,
      state: selected.state,
      source: selected.source,
    };
  }

  private async restoreNearEd25519SessionForExport(args: {
    nearAccountId: AccountId;
  }): Promise<ExactNearEd25519ExportLane> {
    const restoreLane = await this.resolveNearEd25519ExportLane({
      nearAccountId: args.nearAccountId,
      authMethod: await this.resolveKeyExportAuthMethod(args.nearAccountId),
    });
    if (
      restoreLane.state === 'ready' ||
      restoreLane.source === 'runtime_session_record' ||
      restoreLane.source === 'runtime_and_durable'
    ) {
      return restoreLane;
    }
    if (restoreLane.authMethod === 'passkey') {
      await this.touchConfirm.restorePersistedSessionForSigning({
        walletId: args.nearAccountId,
        authMethod: 'passkey',
        curve: 'ed25519',
        chain: 'near',
        walletSigningSessionId: restoreLane.walletSigningSessionId,
        thresholdSessionId: restoreLane.thresholdSessionId,
        reason: 'export',
      });
      return restoreLane;
    }
    await this.emailOtpSessions.restorePersistedSessionForSigning({
      walletId: args.nearAccountId,
      authMethod: 'email_otp',
      curve: 'ed25519',
      chain: 'near',
      walletSigningSessionId: restoreLane.walletSigningSessionId,
      thresholdSessionId: restoreLane.thresholdSessionId,
      reason: 'export',
    });
    return restoreLane;
  }

  private async restoreEcdsaSessionForExport(args: {
    nearAccountId: AccountId;
    chain: 'evm' | 'tempo';
  }): Promise<ExactEcdsaExportLane> {
    const restoreLane = await this.resolveEcdsaExportLane({
      ...args,
      authMethod: await this.resolveKeyExportAuthMethod(args.nearAccountId),
    });
    if (
      restoreLane.state === 'ready' ||
      restoreLane.source === 'runtime_session_record' ||
      restoreLane.source === 'runtime_and_durable'
    ) {
      return restoreLane;
    }
    if (restoreLane.authMethod === 'email_otp') {
      // Email OTP key export is a fresh sensitive operation. When the exact lane is only
      // durable/restorable, use its sealed metadata to mint a one-use export lane instead
      // of attempting to rehydrate a possibly exhausted signing-session seal.
      return restoreLane;
    }
    if (restoreLane.authMethod === 'passkey') {
      await this.touchConfirm.restorePersistedSessionForSigning({
        walletId: args.nearAccountId,
        authMethod: 'passkey',
        curve: 'ecdsa',
        chain: args.chain,
        walletSigningSessionId: restoreLane.walletSigningSessionId,
        thresholdSessionId: restoreLane.thresholdSessionId,
        reason: 'export',
      });
      return restoreLane;
    }
    throw new Error('[SigningEngine][ecdsa-export] unsupported export auth method');
  }

  private listEcdsaExportKeyRefsForLane(
    exportLane: ExactEcdsaExportLane,
  ): ThresholdEcdsaSecp256k1KeyRef[] {
    return this.listThresholdEcdsaKeyRefsForLookup({
      nearAccountId: exportLane.nearAccountId,
      chain: exportLane.chain,
      ...(exportLane.authMethod === 'email_otp' ? { source: 'email_otp' as const } : {}),
    }).filter(({ source, keyRef }) => {
      const sourceMatches =
        exportLane.authMethod === 'email_otp' ? source === 'email_otp' : source !== 'email_otp';
      return (
        sourceMatches &&
        String(keyRef.walletSigningSessionId || '').trim() === exportLane.walletSigningSessionId &&
        String(keyRef.thresholdSessionId || '').trim() === exportLane.thresholdSessionId
      );
    }).map(({ keyRef }) => keyRef);
  }

  private resolveEcdsaExportKeyRefForLane(
    exportLane: ExactEcdsaExportLane,
  ): ThresholdEcdsaSecp256k1KeyRef {
    const matches = this.listEcdsaExportKeyRefsForLane(exportLane);
    if (matches.length !== 1) {
      throw new Error(
        `[SigningEngine][ecdsa-export] exact export keyRef not ready for ${exportLane.chain} ${exportLane.authMethod}`,
      );
    }
    return matches[0];
  }

  private listEcdsaExportRecordsForLane(
    exportLane: ExactEcdsaExportLane,
  ): ThresholdEcdsaSessionRecord[] {
    return this.listThresholdEcdsaSessionRecordsForLookup({
      nearAccountId: exportLane.nearAccountId,
      chain: exportLane.chain,
      ...(exportLane.authMethod === 'email_otp' ? { source: 'email_otp' as const } : {}),
    }).filter((record) => {
      const sourceMatches =
        exportLane.authMethod === 'email_otp'
          ? record.source === 'email_otp'
          : record.source !== 'email_otp';
      return (
        sourceMatches &&
        String(record.walletSigningSessionId || '').trim() ===
          exportLane.walletSigningSessionId &&
        String(record.thresholdSessionId || '').trim() === exportLane.thresholdSessionId
      );
    });
  }

  private resolveEcdsaExportRecordForLane(
    exportLane: ExactEcdsaExportLane,
  ): ThresholdEcdsaSessionRecord {
    const matches = this.listEcdsaExportRecordsForLane(exportLane);
    if (matches.length !== 1) {
      throw new Error(
        `[SigningEngine][ecdsa-export] exact export session record not ready for ${exportLane.chain} ${exportLane.authMethod}`,
      );
    }
    return matches[0];
  }

  private isUsableEcdsaExportSessionRecord(record: ThresholdEcdsaSessionRecord): boolean {
    const remainingUses = Math.floor(Number(record.remainingUses));
    const expiresAtMs = Math.floor(Number(record.expiresAtMs));
    const hasJwt = Boolean(String(record.thresholdSessionJwt || '').trim());
    return (
      Number.isFinite(remainingUses) &&
      remainingUses > 0 &&
      (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0 || expiresAtMs > Date.now()) &&
      (record.thresholdSessionKind === 'cookie' || hasJwt)
    );
  }

  private async resolveExactSealedEcdsaExportRecordForLane(
    exportLane: ExactEcdsaExportLane,
  ): Promise<SigningSessionSealedStoreRecord> {
    const matches = (
      await listExactSealedSessionsForAccount({
        accountId: String(exportLane.nearAccountId),
        filter: {
          authMethod: exportLane.authMethod,
          curve: 'ecdsa',
          chain: exportLane.chain,
        },
      })
    ).filter((record) => {
      const walletSigningSessionId = String(record.walletSigningSessionId || '').trim();
      const thresholdSessionId = String(record.thresholdSessionIds.ecdsa || '').trim();
      return (
        walletSigningSessionId === exportLane.walletSigningSessionId &&
        thresholdSessionId === exportLane.thresholdSessionId
      );
    });
    if (matches.length !== 1) {
      throw new Error(
        `[SigningEngine][ecdsa-export] exact sealed export lane not found for ${exportLane.chain} ${exportLane.authMethod}`,
      );
    }
    return matches[0];
  }

  private async resolveFreshEmailOtpEcdsaExportMaterialForLane(
    exportLane: ExactEcdsaExportLane,
  ): Promise<FreshEmailOtpEcdsaExportMaterial> {
    if (exportLane.authMethod !== 'email_otp') {
      throw new Error('[SigningEngine][ecdsa-export] fresh Email OTP export requires Email OTP lane');
    }
    const runtimeRecord = this.listEcdsaExportRecordsForLane(exportLane)[0] || null;
    const sealedRecord = runtimeRecord
      ? null
      : await this.resolveExactSealedEcdsaExportRecordForLane(exportLane);
    const sealedRestore = sealedRecord?.ecdsaRestore;
    const ecdsaThresholdKeyId = String(
      runtimeRecord?.ecdsaThresholdKeyId || sealedRestore?.ecdsaThresholdKeyId || '',
    ).trim();
    if (!ecdsaThresholdKeyId) {
      throw new Error('[SigningEngine][ecdsa-export] exact export lane is missing ECDSA key id');
    }
    const participantIds = (
      runtimeRecord?.participantIds ||
      sealedRestore?.participantIds ||
      []
    )
      .map((participantId) => Math.floor(Number(participantId)))
      .filter((participantId) => Number.isSafeInteger(participantId) && participantId > 0);
    if (!participantIds.length) {
      throw new Error('[SigningEngine][ecdsa-export] exact export lane is missing participants');
    }
    const authSubjectId = String(
      runtimeRecord?.emailOtpAuthContext?.authSubjectId || '',
    ).trim();
    const runtimePolicyScope =
      runtimeRecord?.runtimePolicyScope ||
      normalizeThresholdRuntimePolicyScope(sealedRestore?.runtimePolicyScope);
    return {
      kind: 'fresh_email_otp',
      chainId: this.requireConfiguredEcdsaChainId(exportLane.chain),
      publicKey: ecdsaThresholdKeyId,
      ecdsaThresholdKeyId,
      participantIds,
      ...(authSubjectId ? { authSubjectId } : {}),
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    };
  }

  private async resolveEcdsaExportMaterialForLane(
    exportLane: ExactEcdsaExportLane,
  ): Promise<EcdsaExportMaterial> {
    const keyRefs = this.listEcdsaExportKeyRefsForLane(exportLane);
    const records = this.listEcdsaExportRecordsForLane(exportLane);
    const usableRecords = records.filter((record) => this.isUsableEcdsaExportSessionRecord(record));
    if (keyRefs.length === 1 && usableRecords.length === 1) {
      return { kind: 'ready', keyRef: keyRefs[0] };
    }
    if (exportLane.authMethod === 'email_otp') {
      return await this.resolveFreshEmailOtpEcdsaExportMaterialForLane(exportLane);
    }
    throw new Error(
      `[SigningEngine][ecdsa-export] exact export keyRef not ready for ${exportLane.chain} ${exportLane.authMethod}`,
    );
  }

  private assertEcdsaExportKeyRefMatchesLane(args: {
    keyRef: ThresholdEcdsaSecp256k1KeyRef;
    exportLane: ExactEcdsaExportLane;
  }): void {
    if (String(args.keyRef.walletSigningSessionId || '').trim() !== args.exportLane.walletSigningSessionId) {
      throw new Error('[SigningEngine][ecdsa-export] keyRef wallet session drifted');
    }
    if (String(args.keyRef.thresholdSessionId || '').trim() !== args.exportLane.thresholdSessionId) {
      throw new Error('[SigningEngine][ecdsa-export] keyRef threshold session drifted');
    }
  }

  private assertNearEd25519ExportRecordMatchesLane(args: {
    record: ThresholdEd25519SessionRecord | null | undefined;
    exportLane: ExactNearEd25519ExportLane;
  }): ThresholdEd25519SessionRecord {
    const record = args.record;
    if (!record) {
      throw new Error('[SigningEngine][ed25519-export] exact export session record is not ready');
    }
    const recordAuthMethod =
      record.source === SIGNER_AUTH_METHODS.emailOtp ? 'email_otp' : 'passkey';
    if (recordAuthMethod !== args.exportLane.authMethod) {
      throw new Error('[SigningEngine][ed25519-export] exact export auth method drifted');
    }
    if (
      String(record.walletSigningSessionId || '').trim() !== args.exportLane.walletSigningSessionId
    ) {
      throw new Error('[SigningEngine][ed25519-export] exact export wallet session drifted');
    }
    if (String(record.thresholdSessionId || '').trim() !== args.exportLane.thresholdSessionId) {
      throw new Error('[SigningEngine][ed25519-export] exact export threshold session drifted');
    }
    return record;
  }

  private async exportThresholdEcdsaKeyWithFreshEmailOtpAuthorization(args: {
    nearAccountId: AccountId;
    chain: 'evm' | 'tempo';
    exportLane: ExactEcdsaExportLane;
    material: FreshEmailOtpEcdsaExportMaterial;
    options: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
    flowId: string;
    onEvent?: KeyExportEventCallback;
  }): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
    if (args.exportLane.authMethod !== 'email_otp' || args.material.kind !== 'fresh_email_otp') {
      throw new Error('[SigningEngine][ecdsa-export] fresh export requires Email OTP lane');
    }
    const authorization = await this.emailOtpSessions.requestExportAuthorization({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      publicKey: args.material.publicKey,
      curve: 'ecdsa',
    });
    emitKeyExportEvent(args.onEvent, {
      phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_STARTED,
      status: 'running',
      flowId: args.flowId,
      accountId: String(args.nearAccountId),
      interaction: { kind: 'none', overlay: 'none' },
      data: { chain: args.chain, curve: 'ecdsa' },
    });
    // Exact export keeps the selected ECDSA key identity, but exhausted Email OTP
    // signing-session seals must be replaced by a fresh one-use export lane.
    const artifact = await this.emailOtpSessions.exportEcdsaKeyWithFreshEmailOtpLane({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      chainId: args.material.chainId,
      challengeId: authorization.challengeId,
      otpCode: authorization.otpCode,
      ecdsaThresholdKeyId: args.material.ecdsaThresholdKeyId,
      participantIds: args.material.participantIds,
      ...(args.material.authSubjectId ? { authSubjectId: args.material.authSubjectId } : {}),
      ...(args.material.runtimePolicyScope
        ? { runtimePolicyScope: args.material.runtimePolicyScope }
        : {}),
    });
    emitKeyExportEvent(args.onEvent, {
      phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_SUCCEEDED,
      status: 'succeeded',
      flowId: args.flowId,
      accountId: String(args.nearAccountId),
      interaction: { kind: 'none', overlay: 'none' },
      data: { chain: args.chain, curve: 'ecdsa' },
    });
    await this.showThresholdEcdsaExportViewer({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      publicKeyHex: String(artifact.publicKeyHex || '').trim(),
      privateKeyHex: String(artifact.privateKeyHex || '').trim(),
      ethereumAddress: String(artifact.ethereumAddress || '').trim(),
      variant: args.options.variant,
      theme: args.options.theme,
      flowId: args.flowId,
      onEvent: args.onEvent,
    });
    return {
      accountId: String(args.nearAccountId),
      exportedSchemes: ['secp256k1'],
    };
  }

  private async exportThresholdEcdsaKeyWithAuthorization(args: {
    nearAccountId: AccountId;
    chain: 'evm' | 'tempo';
    keyRef: ThresholdEcdsaSecp256k1KeyRef;
    exportLane: ExactEcdsaExportLane;
    options: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
    flowId: string;
    onEvent?: KeyExportEventCallback;
  }): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
    this.assertEcdsaExportKeyRefMatchesLane({
      keyRef: args.keyRef,
      exportLane: args.exportLane,
    });
    const currentRecord = this.resolveEcdsaExportRecordForLane(args.exportLane);
    const exportPublicKey =
      String(args.keyRef.ecdsaHssExportArtifact?.publicKeyHex || '').trim() ||
      String(args.keyRef.ecdsaThresholdKeyId || '').trim() ||
      String(args.keyRef.ethereumAddress || '').trim() ||
      '(threshold export key)';

    if (currentRecord.source === SIGNER_AUTH_METHODS.emailOtp) {
      const rpId = String(this.getRpId() || '').trim();
      if (!rpId) {
        throw new Error('Missing rpId for threshold-ecdsa Email OTP export');
      }
      const walletSigningSessionId = String(currentRecord.walletSigningSessionId || '').trim();
      if (!walletSigningSessionId) {
        throw new Error('Email OTP ECDSA export requires wallet signing-session identity');
      }
      const exportSigningSessionAuthLane = {
        kind: 'signing_session' as const,
        jwt: requireThresholdSessionJwt(
          String(currentRecord.thresholdSessionJwt || '').trim(),
          'exportThresholdSessionJwt',
        ),
        thresholdSessionId: currentRecord.thresholdSessionId,
        walletSigningSessionId,
        curve: 'ecdsa' as const,
        chain: args.chain,
      };
      const authorization = await this.emailOtpSessions.requestExportAuthorization({
        nearAccountId: args.nearAccountId,
        chain: args.chain,
        publicKey: exportPublicKey,
        curve: 'ecdsa',
        authLane: exportSigningSessionAuthLane,
      });
      emitKeyExportEvent(args.onEvent, {
        phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_STARTED,
        status: 'running',
        flowId: args.flowId,
        accountId: String(args.nearAccountId),
        interaction: { kind: 'none', overlay: 'none' },
        data: { chain: args.chain, curve: 'ecdsa' },
      });
      const artifact = await this.emailOtpSessions.exportEcdsaKeyWithAuthorization({
        nearAccountId: args.nearAccountId,
        chain: args.chain,
        challengeId: authorization.challengeId,
        otpCode: authorization.otpCode,
        record: currentRecord,
        rpId,
        authLane: exportSigningSessionAuthLane,
      });
      emitKeyExportEvent(args.onEvent, {
        phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_SUCCEEDED,
        status: 'succeeded',
        flowId: args.flowId,
        accountId: String(args.nearAccountId),
        interaction: { kind: 'none', overlay: 'none' },
        data: { chain: args.chain, curve: 'ecdsa' },
      });
      await this.showThresholdEcdsaExportViewer({
        nearAccountId: args.nearAccountId,
        chain: args.chain,
        publicKeyHex: String(artifact.publicKeyHex || '').trim(),
        privateKeyHex: String(artifact.privateKeyHex || '').trim(),
        ethereumAddress: String(artifact.ethereumAddress || '').trim(),
        variant: args.options.variant,
        theme: args.options.theme,
        flowId: args.flowId,
        onEvent: args.onEvent,
      });
      return {
        accountId: String(args.nearAccountId),
        exportedSchemes: ['secp256k1'],
      };
    }

    try {
      const capabilityReader = this.createWarmSessionCapabilityReader();
      const statusReader = this.createWarmSessionStatusReader();
      await assertWarmSessionEcdsaOperationAllowed(
        {
          getWarmSession: (nearAccountId) => capabilityReader.getWarmSession(nearAccountId),
          resolveCurrentEcdsaRecord: (recordArgs) =>
            statusReader.resolveCurrentEcdsaRecord(recordArgs),
        },
        {
          nearAccountId: args.nearAccountId,
          chain: args.chain,
          thresholdSessionId: args.keyRef.thresholdSessionId,
          operationLabel: 'threshold-ecdsa key export',
          sensitivePolicy: SENSITIVE_OPERATION_POLICIES.requirePasskey,
        },
      );
    } catch (error: unknown) {
      if (isEmailOtpPasskeyStepUpError(error)) {
        throw createEmailOtpKeyExportRequiresPasskeyError();
      }
      throw error;
    }
    const rpId = String(this.getRpId() || '').trim();
    if (!rpId) {
      throw new Error('Missing rpId for threshold-ecdsa explicit export');
    }
    const thresholdEcdsaKeyRef = args.keyRef;
    const exportCredential = await this.requestThresholdEcdsaExportAuthorization({
      nearAccountId: args.nearAccountId,
      publicKey: exportPublicKey,
      chain: args.chain,
      flowId: args.flowId,
      onEvent: args.onEvent,
    });
    const yClient32LeB64u = this.requirePrfFirstForPrivateKeyExport({
      credential: exportCredential,
      errorContext: 'threshold-ecdsa explicit export',
    });

    emitKeyExportEvent(args.onEvent, {
      phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_STARTED,
      status: 'running',
      flowId: args.flowId,
      accountId: String(args.nearAccountId),
      interaction: { kind: 'none', overlay: 'none' },
      data: { chain: args.chain, curve: 'ecdsa' },
    });

    const cachedArtifact = thresholdEcdsaKeyRef.ecdsaHssExportArtifact;
    if (cachedArtifact) {
      emitKeyExportEvent(args.onEvent, {
        phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_SUCCEEDED,
        status: 'succeeded',
        flowId: args.flowId,
        accountId: String(args.nearAccountId),
        interaction: { kind: 'none', overlay: 'none' },
        data: { chain: args.chain, curve: 'ecdsa', source: 'cached' },
      });
      await this.showThresholdEcdsaExportViewer({
        nearAccountId: args.nearAccountId,
        chain: args.chain,
        publicKeyHex: cachedArtifact.publicKeyHex,
        privateKeyHex: cachedArtifact.privateKeyHex,
        ethereumAddress: cachedArtifact.ethereumAddress,
        variant: args.options.variant,
        theme: args.options.theme,
        flowId: args.flowId,
        onEvent: args.onEvent,
      });
      return {
        accountId: String(args.nearAccountId),
        exportedSchemes: ['secp256k1'],
      };
    }

    const resolveCanonicalExportTransport = async (): Promise<{
      thresholdSessionId: string;
      thresholdSessionJwt: string;
      relayerUrl: string;
      ecdsaThresholdKeyId: string;
      sessionKind: 'jwt' | 'cookie';
    }> => {
      const currentThresholdSessionId = String(
        thresholdEcdsaKeyRef.thresholdSessionId || '',
      ).trim();
      const currentThresholdSessionJwt = String(
        thresholdEcdsaKeyRef.thresholdSessionJwt || '',
      ).trim();
      const currentRelayerUrl = String(thresholdEcdsaKeyRef.relayerUrl || '').trim();
      const currentThresholdKeyId = String(thresholdEcdsaKeyRef.ecdsaThresholdKeyId || '').trim();
      const currentSessionKind =
        thresholdEcdsaKeyRef.thresholdSessionKind === 'cookie' ? 'cookie' : 'jwt';
      if (
        currentThresholdSessionId &&
        currentThresholdSessionJwt &&
        currentRelayerUrl &&
        currentThresholdKeyId
      ) {
        return {
          thresholdSessionId: currentThresholdSessionId,
          thresholdSessionJwt: currentThresholdSessionJwt,
          relayerUrl: currentRelayerUrl,
          ecdsaThresholdKeyId: currentThresholdKeyId,
          sessionKind: currentSessionKind,
        };
      }
      throw new Error(
        '[SigningEngine][ecdsa-export] exact export keyRef is missing canonical transport',
      );
    };

    const { thresholdSessionJwt, relayerUrl, ecdsaThresholdKeyId, sessionKind } =
      await resolveCanonicalExportTransport();

    const signerWorkerCtx =
      this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext();

    const prepare = await thresholdEcdsaHssPrepare(relayerUrl, {
      userId: String(args.nearAccountId),
      rpId,
      operation: 'explicit_key_export',
      ecdsaThresholdKeyId,
      auth: { kind: 'threshold_session', jwt: thresholdSessionJwt },
      sessionKind,
    });
    if (!prepare.ok) {
      throw new Error(
        prepare.error || prepare.message || 'Threshold explicit export prepare failed',
      );
    }
    const ceremonyId = String(prepare.ceremonyId || '').trim();
    const preparedServerSessionB64u = String(prepare.preparedServerSessionB64u || '').trim();
    const serverAssistInitB64u = String(prepare.serverAssistInitB64u || '').trim();
    if (!ceremonyId || !preparedServerSessionB64u || !serverAssistInitB64u) {
      throw new Error('Threshold explicit export prepare response missing staged transport inputs');
    }

    const preparedClientSession = await prepareThresholdEcdsaHssSessionWasm({
      context: {
        nearAccountId: String(args.nearAccountId),
        keyPurpose: 'evm-signing',
        keyVersion: 'v1',
      },
      clientRootShare32B64u: yClient32LeB64u,
      workerCtx: signerWorkerCtx,
    });
    const evaluatorDriverStateB64u = String(
      preparedClientSession.evaluatorDriverStateB64u || '',
    ).trim();
    if (!evaluatorDriverStateB64u) {
      throw new Error(
        'Threshold explicit export client session preparation returned incomplete staged transport data',
      );
    }

    const clientRequest = await prepareThresholdEcdsaHssClientRequestWasm({
      evaluatorDriverStateB64u,
      serverAssistInitMessageB64u: serverAssistInitB64u,
      clientRootShare32B64u: yClient32LeB64u,
      workerCtx: signerWorkerCtx,
    });
    const clientEvalRequestB64u = String(clientRequest.clientEvalRequestB64u || '').trim();
    if (!clientEvalRequestB64u) {
      throw new Error(
        'Threshold explicit export client request preparation returned incomplete staged transport data',
      );
    }

    const requestMessageB64u = encodeThresholdEcdsaHssHiddenEvalRequestMessage({
      ceremonyId,
      preparedServerSessionB64u,
      serverAssistInitB64u,
      clientEvalRequestB64u,
    });

    const respond = await thresholdEcdsaHssRespond(relayerUrl, {
      ceremonyId,
      requestMessageB64u,
      auth: { kind: 'threshold_session', jwt: thresholdSessionJwt },
      sessionKind,
    });
    if (!respond.ok) {
      throw new Error(
        respond.error || respond.message || 'Threshold explicit export respond failed',
      );
    }
    const responseMessageB64u = String(respond.responseMessageB64u || '').trim();
    if (!responseMessageB64u) {
      throw new Error('Threshold explicit export respond response missing responseMessageB64u');
    }
    const responseEnvelope =
      parseThresholdEcdsaHssHiddenEvalServerResponseMessage(responseMessageB64u);
    if (!responseEnvelope) {
      throw new Error(
        'Threshold explicit export respond response did not contain a valid hidden-eval staged payload',
      );
    }
    const serverEvalResponseB64u = String(responseEnvelope.serverEvalResponseB64u || '').trim();
    if (!serverEvalResponseB64u) {
      throw new Error(
        'Threshold explicit export respond response missing hidden-eval serverEvalResponseB64u',
      );
    }

    const clientFinalize = await finalizeThresholdEcdsaHssClientRequestWasm({
      evaluatorDriverStateB64u,
      serverEvalResponseB64u,
      workerCtx: signerWorkerCtx,
    });
    const clientEvalFinalizeB64u = String(clientFinalize.clientEvalFinalizeB64u || '').trim();
    if (!clientEvalFinalizeB64u) {
      throw new Error(
        'Threshold explicit export client finalize preparation returned incomplete staged transport data',
      );
    }

    const clientFinalizeMessageB64u = await createThresholdEcdsaHssHiddenEvalFinalizeMessage({
      ceremonyId,
      requestMessageB64u,
      responseMessageB64u,
      clientEvalFinalizeB64u,
    });

    const finalized = await thresholdEcdsaHssFinalize(relayerUrl, {
      ceremonyId,
      clientFinalizeMessageB64u,
      auth: { kind: 'threshold_session', jwt: thresholdSessionJwt },
      sessionKind,
    });
    if (!finalized.ok) {
      throw new Error(
        finalized.error || finalized.message || 'Threshold explicit export finalize failed',
      );
    }
    const publicKeyHex = String(finalized.canonicalPublicKeyHex || '').trim();
    const privateKeyHex = String(finalized.privateKeyHex || '').trim();
    const ethereumAddress = String(finalized.canonicalEthereumAddress || '').trim();
    if (!publicKeyHex || !privateKeyHex || !ethereumAddress) {
      throw new Error('Threshold explicit export finalize returned incomplete export material');
    }
    emitKeyExportEvent(args.onEvent, {
      phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_SUCCEEDED,
      status: 'succeeded',
      flowId: args.flowId,
      accountId: String(args.nearAccountId),
      interaction: { kind: 'none', overlay: 'none' },
      data: { chain: args.chain, curve: 'ecdsa' },
    });

    await this.showThresholdEcdsaExportViewer({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      publicKeyHex,
      privateKeyHex,
      ethereumAddress,
      variant: args.options.variant,
      theme: args.options.theme,
      flowId: args.flowId,
      onEvent: args.onEvent,
    });
    return {
      accountId: String(args.nearAccountId),
      exportedSchemes: ['secp256k1'],
    };
  }

  exportNearEd25519SeedArtifactWithUI(args: {
    nearAccountId: AccountId;
    seedB64u: string;
    expectedPublicKey: string;
    options: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
  }): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
    return exportNearEd25519SeedArtifactWithUIValue(
      this.orchestrationDeps.privateKeyExportRecoveryDeps,
      args,
    );
  }

  private requirePrfFirstForPrivateKeyExport(args: {
    credential: WebAuthnAuthenticationCredential | undefined;
    errorContext: string;
  }): string {
    const prfFirstB64u = String(getPrfResultsFromCredential(args.credential).first || '').trim();
    if (!prfFirstB64u) {
      throw new Error(`Missing PRF.first output for ${args.errorContext}`);
    }
    return prfFirstB64u;
  }

  private async requestNearEd25519ExportAuthorization(args: {
    nearAccountId: AccountId;
    expectedPublicKey: string;
    flowId: string;
    onEvent?: KeyExportEventCallback;
  }): Promise<WebAuthnAuthenticationCredential> {
    return await this.requestPasskeyExportAuthorization({
      nearAccountId: args.nearAccountId,
      intent: 'ed25519_export',
      curve: 'ed25519',
      flowId: args.flowId,
      onEvent: args.onEvent,
      request: {
        requestId: createExportUiRequestId('export-near-ed25519-auth'),
        type: UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF,
        summary: {
          operation: 'Export Private Key',
          accountId: args.nearAccountId,
          publicKey: args.expectedPublicKey,
          warning: 'Confirm to reveal your NEAR private key export.',
        },
        payload: {
          nearAccountId: args.nearAccountId,
          publicKey: args.expectedPublicKey,
        },
        intentDigest: `export-keys:${args.nearAccountId}:near-ed25519`,
      },
    });
  }

  private async showNearEd25519ExportViewer(args: {
    nearAccountId: AccountId;
    expectedPublicKey: string;
    privateKey?: string;
    variant?: 'drawer' | 'modal';
    theme?: 'dark' | 'light';
    loading?: boolean;
    viewerSessionId?: string;
    flowId: string;
    onEvent?: KeyExportEventCallback;
  }): Promise<void> {
    const keys: ExportPrivateKeyDisplayEntry[] = [
      {
        scheme: 'ed25519',
        label: 'NEAR private key',
        publicKey: args.expectedPublicKey,
        privateKey: String(args.privateKey || '').trim(),
      },
    ];
    await this.touchConfirm.requestUserConfirmation({
      requestId: createExportUiRequestId('export-near-ed25519-view'),
      type: UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI,
      summary: {
        operation: 'Export Private Key',
        accountId: args.nearAccountId,
        publicKey: args.expectedPublicKey,
        warning: 'Anyone with your private key can fully control your account. Never share it.',
      },
      payload: {
        nearAccountId: args.nearAccountId,
        viewerSessionId: args.viewerSessionId,
        publicKey: args.expectedPublicKey,
        keys,
        variant: args.variant,
        theme: args.theme ?? this.theme ?? 'dark',
        loading: args.loading === true,
        onLifecycle: (event) => {
          emitKeyExportEvent(args.onEvent, {
            phase:
              event === 'opened'
                ? KeyExportEventPhase.STEP_04_VIEWER_OPENED
                : KeyExportEventPhase.STEP_05_VIEWER_CLOSED,
            status: event === 'opened' ? 'waiting_for_user' : 'succeeded',
            flowId: args.flowId,
            accountId: String(args.nearAccountId),
            interaction: {
              kind: 'key_export_viewer',
              overlay: event === 'opened' ? 'show' : 'hide',
            },
            data: { chain: 'near', loading: args.loading === true },
          });
          if (event === 'closed') {
            emitKeyExportEvent(args.onEvent, {
              phase: KeyExportEventPhase.STEP_06_COMPLETED,
              status: 'succeeded',
              flowId: args.flowId,
              accountId: String(args.nearAccountId),
              interaction: { kind: 'none', overlay: 'hide' },
              data: { chain: 'near' },
            });
          }
        },
      },
      intentDigest: `export-keys:${args.nearAccountId}:near-ed25519`,
    });
  }

  private async requestThresholdEcdsaExportAuthorization(args: {
    nearAccountId: AccountId;
    publicKey: string;
    chain: 'evm' | 'tempo';
    flowId: string;
    onEvent?: KeyExportEventCallback;
  }): Promise<WebAuthnAuthenticationCredential> {
    return await this.requestPasskeyExportAuthorization({
      nearAccountId: args.nearAccountId,
      intent: 'ecdsa_export',
      curve: 'ecdsa',
      flowId: args.flowId,
      onEvent: args.onEvent,
      request: {
        requestId: createExportUiRequestId('export-threshold-ecdsa-auth'),
        type: UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF,
        summary: {
          operation: 'Export Private Key',
          accountId: args.nearAccountId,
          publicKey: args.publicKey,
          warning:
            args.chain === 'tempo'
              ? 'Confirm to reveal your Tempo private key export.'
              : 'Confirm to reveal your EVM private key export.',
        },
        payload: {
          nearAccountId: args.nearAccountId,
          publicKey: args.publicKey,
        },
        intentDigest: `export-keys:${args.nearAccountId}:${args.chain}:secp256k1`,
      },
    });
  }

  private async requestPasskeyExportAuthorization(args: {
    nearAccountId: AccountId;
    intent: Extract<WalletAuthIntent, 'ed25519_export' | 'ecdsa_export'>;
    curve: WalletAuthCurve;
    flowId: string;
    onEvent?: KeyExportEventCallback;
    request: Parameters<TouchConfirmRuntimeBridgePort['requestUserConfirmation']>[0];
  }): Promise<WebAuthnAuthenticationCredential> {
    const resolver = createWalletAuthModeResolver({
      passkey: createPasskeyWalletAuthAdapter({
        challenge: async () => {
          removeExportViewerHostIfPresent();
          return await this.touchConfirm.requestUserConfirmation(args.request);
        },
        complete: async ({ response }) => {
          const decision = response as Awaited<
            ReturnType<TouchConfirmRuntimeBridgePort['requestUserConfirmation']>
          >;
          if (!decision.confirmed) {
            throw new Error(decision.error || 'User cancelled export request');
          }
          return {
            method: 'passkey',
            webauthnAuthentication: decision.credential,
          };
        },
      }),
      emailOtp: createEmailOtpWalletAuthAdapter({
        challenge: async () => {
          throw createEmailOtpKeyExportRequiresPasskeyError();
        },
        complete: async () => {
          throw createEmailOtpKeyExportRequiresPasskeyError();
        },
      }),
    });
    const plan = await resolver.resolveWalletAuthPlan({
      accountId: args.nearAccountId,
      accountAuth: resolveAccountAuthMetadataForSignerSource(),
      intent: args.intent,
      curve: args.curve,
    });
    if (plan.kind !== WalletAuthPlanKind.PasskeyReauth) {
      throw new WalletAuthPolicyError({
        code: 'passkey_step_up_required',
        policy: 'export_requires_passkey',
        intent: args.intent,
        message: 'Export authorization requires passkey re-authentication',
      });
    }
    emitKeyExportEvent(args.onEvent, {
      phase: KeyExportEventPhase.STEP_02_AUTH_PASSKEY_PROMPT_STARTED,
      status: 'waiting_for_user',
      flowId: args.flowId,
      accountId: String(args.nearAccountId),
      authMethod: 'passkey',
      interaction: { kind: 'passkey_assert', overlay: 'show' },
      data: { intent: args.intent, curve: args.curve },
    });
    const challenge = await plan.challenge();
    const proof = await plan.complete(challenge);
    emitKeyExportEvent(args.onEvent, {
      phase: KeyExportEventPhase.STEP_02_AUTH_PASSKEY_PROMPT_SUCCEEDED,
      status: 'succeeded',
      flowId: args.flowId,
      accountId: String(args.nearAccountId),
      authMethod: 'passkey',
      interaction: { kind: 'passkey_assert', overlay: 'hide' },
      data: { intent: args.intent, curve: args.curve },
    });
    return proof.webauthnAuthentication as WebAuthnAuthenticationCredential;
  }

  private async showThresholdEcdsaExportViewer(args: {
    nearAccountId: AccountId;
    chain: 'evm' | 'tempo';
    publicKeyHex: string;
    privateKeyHex: string;
    ethereumAddress: string;
    variant?: 'drawer' | 'modal';
    theme?: 'dark' | 'light';
    flowId: string;
    onEvent?: KeyExportEventCallback;
  }): Promise<void> {
    const label = args.chain === 'tempo' ? 'Tempo private key' : 'EVM private key';
    const keys: ExportPrivateKeyDisplayEntry[] = [
      {
        scheme: 'secp256k1',
        label,
        publicKey: args.publicKeyHex,
        privateKey: args.privateKeyHex,
        address: args.ethereumAddress,
      },
    ];
    await this.touchConfirm.requestUserConfirmation({
      requestId: createExportUiRequestId('export-threshold-ecdsa-view'),
      type: UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI,
      summary: {
        operation: 'Export Private Key',
        accountId: args.nearAccountId,
        publicKey: args.publicKeyHex,
        warning: 'Anyone with your private key can fully control your account. Never share it.',
      },
      payload: {
        nearAccountId: args.nearAccountId,
        publicKey: args.publicKeyHex,
        keys,
        variant: args.variant,
        theme: args.theme ?? this.theme ?? 'dark',
        onLifecycle: (event) => {
          emitKeyExportEvent(args.onEvent, {
            phase:
              event === 'opened'
                ? KeyExportEventPhase.STEP_04_VIEWER_OPENED
                : KeyExportEventPhase.STEP_05_VIEWER_CLOSED,
            status: event === 'opened' ? 'waiting_for_user' : 'succeeded',
            flowId: args.flowId,
            accountId: String(args.nearAccountId),
            interaction: {
              kind: 'key_export_viewer',
              overlay: event === 'opened' ? 'show' : 'hide',
            },
            data: { chain: args.chain, curve: 'ecdsa' },
          });
          if (event === 'closed') {
            emitKeyExportEvent(args.onEvent, {
              phase: KeyExportEventPhase.STEP_06_COMPLETED,
              status: 'succeeded',
              flowId: args.flowId,
              accountId: String(args.nearAccountId),
              interaction: { kind: 'none', overlay: 'hide' },
              data: { chain: args.chain, curve: 'ecdsa' },
            });
          }
        },
      },
      intentDigest: `export-keys:${args.nearAccountId}:${args.chain}:secp256k1`,
    });
  }

  private async runNearEd25519SingleKeyHssExport(args: {
    signingRootId: string;
    nearAccountId: AccountId;
    keyVersion: string;
    participantIds: number[];
    thresholdSessionId: string;
    thresholdSessionJwt: string;
    relayerUrl: string;
    relayerKeyId: string;
    prfFirstB64u: string;
  }): Promise<{
    preparedSession: Parameters<
      typeof buildThresholdEd25519SeedExportArtifactFromHssReportValue
    >[0]['preparedSession'];
    finalizedReport: Parameters<
      typeof buildThresholdEd25519SeedExportArtifactFromHssReportValue
    >[0]['finalizedReport'];
  }> {
    const clientInputs = await deriveThresholdEd25519HssClientInputsWasm({
      sessionId: `${args.thresholdSessionId}:hss-export-client-inputs`,
      signingRootId: args.signingRootId,
      nearAccountId: args.nearAccountId,
      keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
      keyVersion: args.keyVersion,
      participantIds: args.participantIds,
      derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
      prfFirstB64u: args.prfFirstB64u,
      workerCtx: this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
    });

    const completed = await runThresholdEd25519HssCeremonyWithSessionValue({
      relayerUrl: args.relayerUrl,
      thresholdSessionJwt: args.thresholdSessionJwt,
      relayerKeyId: args.relayerKeyId,
      operation: 'explicit_key_export',
      context: {
        signingRootId: args.signingRootId,
        nearAccountId: args.nearAccountId,
        keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
        keyVersion: args.keyVersion,
        participantIds: args.participantIds,
        derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
      },
      clientInputs,
      workerCtx: this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
    });
    if (!completed.success || !completed.finalizedReport || !completed.preparedSession) {
      throw new Error(completed.error || 'Failed to finalize single-key HSS Ed25519 export ceremony');
    }

    return {
      preparedSession: completed.preparedSession,
      finalizedReport: completed.finalizedReport,
    };
  }

  async exportThresholdEd25519SeedFromHssReport(args: {
    nearAccountId: AccountId;
    preparedSession: Parameters<
      typeof buildThresholdEd25519SeedExportArtifactFromHssReportValue
    >[0]['preparedSession'];
    finalizedReport: Parameters<
      typeof buildThresholdEd25519SeedExportArtifactFromHssReportValue
    >[0]['finalizedReport'];
    expectedPublicKey: string;
    options: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
      onEvent?: KeyExportEventCallback;
    };
  }): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
    const flowId = createKeyExportFlowId(args.nearAccountId, 'near');
    emitKeyExportEvent(args.options.onEvent, {
      phase: KeyExportEventPhase.STEP_01_STARTED,
      status: 'running',
      flowId,
      accountId: String(args.nearAccountId),
      interaction: { kind: 'none', overlay: 'none' },
      data: { chain: 'near', curve: 'ed25519' },
    });
    emitKeyExportEvent(args.options.onEvent, {
      phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_STARTED,
      status: 'running',
      flowId,
      accountId: String(args.nearAccountId),
      interaction: { kind: 'none', overlay: 'none' },
      data: { chain: 'near', curve: 'ed25519' },
    });
    try {
      const artifactResult = await this.buildThresholdEd25519SeedExportArtifactFromHssReport({
        preparedSession: args.preparedSession,
        finalizedReport: args.finalizedReport,
        expectedPublicKey: args.expectedPublicKey,
      });
      if (!artifactResult.success || !artifactResult.artifact) {
        throw new Error(
          artifactResult.error || 'Failed to build single-key HSS Ed25519 seed export artifact',
        );
      }
      emitKeyExportEvent(args.options.onEvent, {
        phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_SUCCEEDED,
        status: 'succeeded',
        flowId,
        accountId: String(args.nearAccountId),
        interaction: { kind: 'none', overlay: 'none' },
        data: { chain: 'near', curve: 'ed25519' },
      });
      await this.showNearEd25519ExportViewer({
        nearAccountId: args.nearAccountId,
        expectedPublicKey: artifactResult.artifact.publicKey,
        privateKey: artifactResult.artifact.privateKey,
        variant: args.options.variant,
        theme: args.options.theme,
        flowId,
        onEvent: args.options.onEvent,
      });
      return {
        accountId: String(args.nearAccountId),
        exportedSchemes: ['ed25519'],
      };
    } catch (error: unknown) {
      const cancelled = isUserCancellationError(error);
      emitKeyExportEvent(args.options.onEvent, {
        phase: cancelled ? KeyExportEventPhase.CANCELLED : KeyExportEventPhase.FAILED,
        status: cancelled ? 'cancelled' : 'failed',
        flowId,
        accountId: String(args.nearAccountId),
        interaction: { kind: 'none', overlay: 'hide' },
        error: {
          message:
            errorMessage(error) || (cancelled ? 'Key export cancelled' : 'Key export failed'),
        },
        data: { chain: 'near', curve: 'ed25519' },
      });
      throw error;
    }
  }

  private async tryExportNearEd25519SingleKeyHssWithAuthorization(args: {
    nearAccountId: AccountId;
    exportLane: ExactNearEd25519ExportLane;
    options: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
    flowId: string;
    onEvent?: KeyExportEventCallback;
  }): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> } | null> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const sessionRecord = this.assertNearEd25519ExportRecordMatchesLane({
      record: getStoredThresholdEd25519SessionRecordForLaneValue({
        nearAccountId,
        authMethod: args.exportLane.authMethod,
        walletSigningSessionId: args.exportLane.walletSigningSessionId,
        thresholdSessionId: args.exportLane.thresholdSessionId,
      }),
      exportLane: args.exportLane,
    });
    const orgId = String(sessionRecord?.runtimePolicyScope?.orgId || '').trim();
    const projectId = String(sessionRecord?.runtimePolicyScope?.projectId || '').trim();
    const envId = String(sessionRecord?.runtimePolicyScope?.envId || '').trim();
    const signingRootVersion = String(
      sessionRecord?.runtimePolicyScope?.signingRootVersion || '',
    ).trim();
    const thresholdSessionId = String(sessionRecord?.thresholdSessionId || '').trim();
    const thresholdSessionJwt = String(sessionRecord?.thresholdSessionJwt || '').trim();
    const relayerUrl = String(sessionRecord?.relayerUrl || '').trim();
    const relayerKeyId = String(sessionRecord?.relayerKeyId || '').trim();
    const participantIds = Array.isArray(sessionRecord?.participantIds)
      ? sessionRecord.participantIds.map((value) => Number(value))
      : [];
    const hasCanonicalRuntimeScope = Boolean(orgId && projectId && envId && signingRootVersion);

    const requireSingleKeyHssExportPrerequisite = (
      condition: boolean,
      message: string,
    ): void => {
      if (condition) return;
      if (hasCanonicalRuntimeScope) {
        throw new Error(message);
      }
    };

    if (
      !orgId ||
      !projectId ||
      !envId ||
      !signingRootVersion ||
      !thresholdSessionId ||
      !thresholdSessionJwt ||
      !relayerUrl ||
      !relayerKeyId ||
      participantIds.length === 0
    ) {
      requireSingleKeyHssExportPrerequisite(
        false,
        'Missing canonical single-key HSS Ed25519 export session prerequisites',
      );
      return null;
    }
    const defaultRuntimePolicyScope: ThresholdRuntimePolicyScope = {
      orgId,
      projectId,
      envId,
      signingRootVersion,
    };
    const defaultSigningRootId =
      signingRootScopeFromRuntimePolicyScope(defaultRuntimePolicyScope).signingRootId;

    const signerSlot = await getLastLoggedInSignerSlot(
      nearAccountId,
      this.orchestrationDeps.indexedDB.clientDB,
    ).catch(() => null as number | null);
    if (signerSlot == null) {
      requireSingleKeyHssExportPrerequisite(
        false,
        'Missing signer slot for single-key HSS Ed25519 export',
      );
      return null;
    }

    const thresholdKeyMaterial = await getNearThresholdKeyMaterial(
      {
        clientDB: this.orchestrationDeps.indexedDB.clientDB,
        accountKeyMaterialDB: this.orchestrationDeps.indexedDB.accountKeyMaterialDB,
      },
      nearAccountId,
      signerSlot,
    ).catch(() => null);
    const keyVersion = String(thresholdKeyMaterial?.keyVersion || '').trim();
    const expectedPublicKey = String(thresholdKeyMaterial?.publicKey || '').trim();
    if (!keyVersion || !expectedPublicKey) {
      requireSingleKeyHssExportPrerequisite(
        false,
        'Missing canonical public key material for single-key HSS Ed25519 export',
      );
      return null;
    }

    const viewerSessionId = createExportUiRequestId('export-near-ed25519-viewer-session');

    try {
      if (sessionRecord?.source === SIGNER_AUTH_METHODS.emailOtp) {
        const walletSigningSessionId = String(sessionRecord.walletSigningSessionId || '').trim();
        if (!walletSigningSessionId) {
          throw new Error('Email OTP Ed25519 export requires wallet signing-session identity');
        }
        const exportSigningSessionAuthLane = {
          kind: 'signing_session' as const,
          jwt: requireThresholdSessionJwt(
            String(sessionRecord.thresholdSessionJwt || '').trim(),
            'exportThresholdSessionJwt',
          ),
          thresholdSessionId,
          walletSigningSessionId,
          curve: 'ed25519' as const,
        };
        const authorization = await this.emailOtpSessions.requestExportAuthorization({
          nearAccountId,
          chain: 'near',
          publicKey: expectedPublicKey,
          curve: 'ed25519',
          authLane: exportSigningSessionAuthLane,
        });
        const exportMaterial = await this.emailOtpSessions.recoverEd25519ExportPrfFirst({
          nearAccountId,
          challengeId: authorization.challengeId,
          otpCode: authorization.otpCode,
          record: sessionRecord,
          authLane: exportSigningSessionAuthLane,
        });
        emitKeyExportEvent(args.onEvent, {
          phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_STARTED,
          status: 'running',
          flowId: args.flowId,
          accountId: String(nearAccountId),
          interaction: { kind: 'none', overlay: 'none' },
          data: { chain: 'near', curve: 'ed25519' },
        });
        const hssTask = this.runNearEd25519SingleKeyHssExport({
          signingRootId: defaultSigningRootId,
          nearAccountId,
          keyVersion,
          participantIds,
          thresholdSessionId,
          thresholdSessionJwt,
          relayerUrl,
          relayerKeyId,
          prfFirstB64u: exportMaterial.prfFirstB64u,
        });
        await this.showNearEd25519ExportViewer({
          nearAccountId,
          expectedPublicKey,
          variant: args.options.variant,
          theme: args.options.theme,
          loading: true,
          viewerSessionId,
          flowId: args.flowId,
          onEvent: args.onEvent,
        });
        const { preparedSession, finalizedReport } = await hssTask;
        const artifactResult = await this.buildThresholdEd25519SeedExportArtifactFromHssReport({
          preparedSession,
          finalizedReport,
          expectedPublicKey,
        });
        if (!artifactResult.success || !artifactResult.artifact) {
          throw new Error(
            artifactResult.error ||
              'Failed to build Email OTP single-key HSS Ed25519 seed export artifact',
          );
        }
        emitKeyExportEvent(args.onEvent, {
          phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_SUCCEEDED,
          status: 'succeeded',
          flowId: args.flowId,
          accountId: String(nearAccountId),
          interaction: { kind: 'none', overlay: 'none' },
          data: { chain: 'near', curve: 'ed25519' },
        });
        if (!isExportViewerSessionOpen(viewerSessionId)) {
          return {
            accountId: nearAccountId,
            exportedSchemes: ['ed25519'],
          };
        }
        await this.showNearEd25519ExportViewer({
          nearAccountId,
          expectedPublicKey: artifactResult.artifact.publicKey,
          privateKey: artifactResult.artifact.privateKey,
          variant: args.options.variant,
          theme: args.options.theme,
          viewerSessionId,
          flowId: args.flowId,
          onEvent: args.onEvent,
        });
        return {
          accountId: nearAccountId,
          exportedSchemes: ['ed25519'],
        };
      }
      const exportCredential = await this.requestNearEd25519ExportAuthorization({
        nearAccountId,
        expectedPublicKey,
        flowId: args.flowId,
        onEvent: args.onEvent,
      });
      const prfFirstB64u = this.requirePrfFirstForPrivateKeyExport({
        credential: exportCredential,
        errorContext: 'single-key HSS Ed25519 export',
      });
      emitKeyExportEvent(args.onEvent, {
        phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_STARTED,
        status: 'running',
        flowId: args.flowId,
        accountId: String(nearAccountId),
        interaction: { kind: 'none', overlay: 'none' },
        data: { chain: 'near', curve: 'ed25519' },
      });
      const hssTask = this.runNearEd25519SingleKeyHssExport({
        signingRootId: defaultSigningRootId,
        nearAccountId,
        keyVersion,
        participantIds,
        thresholdSessionId,
        thresholdSessionJwt,
        relayerUrl,
        relayerKeyId,
        prfFirstB64u,
      });
      await this.showNearEd25519ExportViewer({
        nearAccountId,
        expectedPublicKey,
        variant: args.options.variant,
        theme: args.options.theme,
        loading: true,
        viewerSessionId,
        flowId: args.flowId,
        onEvent: args.onEvent,
      });

      const { preparedSession, finalizedReport } = await hssTask;
      const artifactResult = await this.buildThresholdEd25519SeedExportArtifactFromHssReport({
        preparedSession,
        finalizedReport,
        expectedPublicKey,
      });
      if (!artifactResult.success || !artifactResult.artifact) {
        throw new Error(
          artifactResult.error || 'Failed to build single-key HSS Ed25519 seed export artifact',
        );
      }
      emitKeyExportEvent(args.onEvent, {
        phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_SUCCEEDED,
        status: 'succeeded',
        flowId: args.flowId,
        accountId: String(nearAccountId),
        interaction: { kind: 'none', overlay: 'none' },
        data: { chain: 'near', curve: 'ed25519' },
      });

      if (!isExportViewerSessionOpen(viewerSessionId)) {
        return {
          accountId: nearAccountId,
          exportedSchemes: ['ed25519'],
        };
      }
      await this.showNearEd25519ExportViewer({
        nearAccountId,
        expectedPublicKey: artifactResult.artifact.publicKey,
        privateKey: artifactResult.artifact.privateKey,
        variant: args.options.variant,
        theme: args.options.theme,
        viewerSessionId,
        flowId: args.flowId,
        onEvent: args.onEvent,
      });

      return {
        accountId: nearAccountId,
        exportedSchemes: ['ed25519'],
      };
    } catch (error: unknown) {
      removeExportViewerHostIfPresent();
      throw error;
    }
  }

  signTransactionWithKeyPair(args: {
    nearPrivateKey: string;
    signerAccountId: string;
    receiverId: string;
    nonce: string;
    blockHash: string;
    actions: ActionArgsWasm[];
  }): Promise<{
    signedTransaction: SignedTransaction;
    logs?: string[];
  }> {
    return this.orchestrationDeps.nearKeyOpsDeps.signingKeyOps.signTransactionWithKeyPair({
      nearPrivateKey: args.nearPrivateKey,
      signerAccountId: args.signerAccountId,
      receiverId: args.receiverId,
      nonce: args.nonce,
      blockHash: args.blockHash,
      actions: args.actions,
    });
  }

  generateEphemeralNearKeypair(): Promise<{
    publicKey: string;
    privateKey: string;
  }> {
    return this.orchestrationDeps.nearKeyOpsDeps.signingKeyOps.generateEphemeralNearKeypair();
  }

  async connectEd25519Session(
    args: Omit<ProvisionWarmEd25519CapabilityArgs, 'beforeProvision' | 'assertNotCancelled'>,
  ): Promise<ProvisionWarmEd25519CapabilityResult> {
    const capabilityReader = this.createWarmSessionCapabilityReader();
    return await provisionWarmEd25519Capability(
      {
        getWarmSession: (nearAccountId) => capabilityReader.getWarmSession(nearAccountId),
        provisionThresholdEd25519Session: async (provisionArgs) =>
          await this.provisionThresholdEd25519Session(provisionArgs),
      },
      args,
    );
  }

  async bootstrapEcdsaSession(
    args: Parameters<typeof bootstrapEcdsaSessionValue>[1],
  ): Promise<ThresholdEcdsaSessionBootstrapResult> {
    await this.ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap(args);
    const nearAccountId = toAccountId(args.nearAccountId);
    const chain = args.chain;
    const capabilityReader = this.createWarmSessionCapabilityReader();
    return await provisionWarmEcdsaCapability(
      {
        getWarmSession: (warmSessionAccountId) =>
          capabilityReader.getWarmSession(warmSessionAccountId),
        listThresholdEcdsaKeyRefsForLookup: (readyArgs) =>
          this.listThresholdEcdsaKeyRefsForLookup(readyArgs),
        claimPrfFirstByThresholdSessionId: (claimArgs) =>
          claimWarmSessionPrfFirst({
            touchConfirm: this.touchConfirm,
            thresholdSessionId: claimArgs.thresholdSessionId,
            errorContext: claimArgs.errorContext,
            uses: claimArgs.uses,
            restoreBeforeClaim: async () => {
              if (claimArgs.authMethod !== 'passkey') return;
              const walletSigningSessionId = String(
                claimArgs.walletSigningSessionId || args.walletSigningSessionId || '',
              ).trim();
              if (!walletSigningSessionId) return;
              await this.touchConfirm.restorePersistedSessionForSigning({
                walletId: nearAccountId,
                authMethod: 'passkey',
                curve: 'ecdsa',
                chain,
                walletSigningSessionId,
                thresholdSessionId: claimArgs.thresholdSessionId,
                reason: 'transaction',
              });
            },
          }),
        provisionThresholdEcdsaSession: async (provisionArgs) =>
          await this.provisionThresholdEcdsaSession({
            ...args,
            nearAccountId,
            chain,
            chainId: provisionArgs.chainId,
            ...(provisionArgs.relayerUrl ? { relayerUrl: provisionArgs.relayerUrl } : {}),
            ...(provisionArgs.clientRootShare32
              ? { clientRootShare32: provisionArgs.clientRootShare32 }
              : {}),
            ...(provisionArgs.clientRootShare32B64u
              ? { clientRootShare32B64u: provisionArgs.clientRootShare32B64u }
              : {}),
            ...(provisionArgs.webauthnAuthentication
              ? { webauthnAuthentication: provisionArgs.webauthnAuthentication }
              : {}),
            ...(provisionArgs.ecdsaThresholdKeyId
              ? { ecdsaThresholdKeyId: provisionArgs.ecdsaThresholdKeyId }
              : {}),
            ...(provisionArgs.thresholdRouteAuth
              ? { thresholdRouteAuth: provisionArgs.thresholdRouteAuth }
              : {}),
            ...(provisionArgs.runtimePolicyScope
              ? { runtimePolicyScope: provisionArgs.runtimePolicyScope }
              : {}),
            ...(provisionArgs.runtimeScopeBootstrap
              ? { runtimeScopeBootstrap: provisionArgs.runtimeScopeBootstrap }
              : {}),
            ...(provisionArgs.operationIntent
              ? { operationIntent: provisionArgs.operationIntent }
              : {}),
            ...(provisionArgs.sessionId ? { sessionId: provisionArgs.sessionId } : {}),
            ...(provisionArgs.walletSigningSessionId
              ? { walletSigningSessionId: provisionArgs.walletSigningSessionId }
              : {}),
            ...(Array.isArray(provisionArgs.participantIds) &&
            provisionArgs.participantIds.length > 0
              ? { participantIds: provisionArgs.participantIds }
              : {}),
            ...(provisionArgs.sessionKind ? { sessionKind: provisionArgs.sessionKind } : {}),
            ...(typeof provisionArgs.ttlMs === 'number' ? { ttlMs: provisionArgs.ttlMs } : {}),
            ...(typeof provisionArgs.remainingUses === 'number'
              ? { remainingUses: provisionArgs.remainingUses }
              : {}),
            ...(provisionArgs.smartAccount ? { smartAccount: provisionArgs.smartAccount } : {}),
          }),
      },
      {
        nearAccountId,
        chain,
        chainId: args.chainId,
        source: args.source,
        ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
        participantIds: args.participantIds,
        sessionKind: args.sessionKind,
        sessionId: args.sessionId,
        walletSigningSessionId: args.walletSigningSessionId,
        thresholdRouteAuth: args.thresholdRouteAuth,
        runtimePolicyScope: args.runtimePolicyScope,
        runtimeScopeBootstrap: args.runtimeScopeBootstrap,
        clientRootShare32: args.clientRootShare32,
        clientRootShare32B64u: args.clientRootShare32B64u,
        webauthnAuthentication: args.webauthnAuthentication,
        ttlMs: args.ttlMs,
        remainingUses: args.remainingUses,
        smartAccount: args.smartAccount,
      },
    );
  }

  async loginWithEmailOtpEcdsaCapabilityInternal(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    chainId: number;
    emailOtpAuthPolicy?: EmailOtpAuthPolicy;
    emailOtpAuthReason?: 'login' | 'sign';
    relayUrl?: string;
    challengeId?: string;
    otpCode: string;
    operation?: WalletEmailOtpLoginOperation;
    shamirPrimeB64u?: string;
    appSessionJwt?: string;
    routeAuth?: AppOrThresholdSessionAuth;
    ecdsaThresholdKeyId?: string;
    participantIds?: number[];
    sessionKind?: 'jwt' | 'cookie';
    sessionId?: string;
    walletSigningSessionId?: string;
    ttlMs?: number;
    remainingUses?: number;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
    onProgress?: (progress: EmailOtpWorkerProgressEvent) => void;
  }): Promise<{
    recovery: EmailOtpBootstrapRecovery;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    warmCapability: WarmSessionEcdsaCapabilityState;
  }> {
    return await this.emailOtpSessions.loginWithEcdsaCapabilityInternal(args);
  }

  private resolveEmailOtpEcdsaSigningSessionAuth(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }): {
    record: ThresholdEcdsaSessionRecord;
    authLane: EmailOtpAuthLane;
  } {
    const record = this.getThresholdEcdsaSessionRecordForLookup({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      source: 'email_otp',
    });
    const jwt = String(record.thresholdSessionJwt || '').trim();
    if (!jwt) {
      throw new Error('Email OTP signing-session refresh requires threshold-session auth');
    }
    const walletSigningSessionId = String(record.walletSigningSessionId || '').trim();
    if (!walletSigningSessionId) {
      throw new Error('Email OTP signing-session refresh requires wallet signing-session identity');
    }
    const authLane: EmailOtpAuthLane = {
      kind: 'signing_session',
      jwt,
      thresholdSessionId: record.thresholdSessionId,
      walletSigningSessionId,
      curve: 'ecdsa',
      chain: args.chain,
    };
    return {
      record,
      authLane,
    };
  }

  private requireConfiguredEcdsaChainId(chain: ThresholdEcdsaActivationChain): number {
    const configured = this.seamsPasskeyConfigs.network.chains.find(
      (candidate) => chainFamilyFromNetwork(candidate.network) === chain,
    );
    const chainId = Math.floor(
      Number((configured as { chainId?: unknown } | undefined)?.chainId),
    );
    if (!Number.isSafeInteger(chainId) || chainId < 0) {
      throw new Error(`[SigningEngine] missing configured numeric chainId for ${chain}`);
    }
    return chainId;
  }

  async requestEmailOtpSigningSessionChallenge(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }): Promise<{ challengeId: string; emailHint?: string }> {
    const chain = args.chain;
    const { authLane } = this.resolveEmailOtpEcdsaSigningSessionAuth({
      nearAccountId: args.nearAccountId,
      chain,
    });
    return await this.emailOtpSessions.requestTransactionSigningChallenge({
      nearAccountId: args.nearAccountId,
      chain,
      authLane,
    });
  }

  async refreshEmailOtpSigningSession(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    chainId: number;
    challengeId: string;
    otpCode: string;
    ttlMs?: number;
    remainingUses?: number;
  }): Promise<{
    recovery: EmailOtpBootstrapRecovery;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    warmCapability: WarmSessionEcdsaCapabilityState;
  }> {
    const chain = args.chain;
    const chainId = thresholdEcdsaChainTargetFromActivationChain({
      chain,
      chainId: args.chainId,
    }).chainId;
    const { record, authLane } = this.resolveEmailOtpEcdsaSigningSessionAuth({
      nearAccountId: args.nearAccountId,
      chain,
    });
    const routePlan = buildEmailOtpRoutePlan({
      routeFamily: 'signing_session',
      authLane,
      operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
    });
    return await this.emailOtpSessions.loginWithEcdsaCapabilityInternal({
      nearAccountId: args.nearAccountId,
      chain,
      chainId,
      emailOtpAuthPolicy: 'session',
      emailOtpAuthReason: 'sign',
      challengeId: args.challengeId,
      otpCode: args.otpCode,
      operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
      routePlan,
      ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
      participantIds: record.participantIds,
      sessionKind: record.thresholdSessionKind,
      walletSigningSessionId: record.walletSigningSessionId,
      ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
      ...(typeof args.remainingUses === 'number' ? { remainingUses: args.remainingUses } : {}),
      ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
      ed25519ProvisioningMode: 'await',
    });
  }

  /**
   * Internal Email OTP enrollment bridge.
   * Kept off `SigningEnginePublic` until the Email OTP abstraction is stable.
   */
  async enrollEmailOtpInternal(args: {
    nearAccountId: AccountId | string;
    otpCode: string;
    relayUrl?: string;
    challengeId?: string;
    shamirPrimeB64u?: string;
    appSessionJwt?: string;
    clientSecret32?: Uint8Array;
    otpChannel?: WalletEmailOtpChannel;
  }): Promise<Awaited<ReturnType<typeof enrollEmailOtpWallet>>> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const relayUrl = String(
      args.relayUrl || this.seamsPasskeyConfigs.network.relayer?.url || '',
    ).trim();
    if (!relayUrl) {
      throw new Error('Missing relayer url (configs.network.relayer.url)');
    }
    const shamirPrimeB64u = String(
      args.shamirPrimeB64u || this.seamsPasskeyConfigs.signing.sessionSeal?.shamirPrimeB64u || '',
    ).trim();
    if (!shamirPrimeB64u) {
      throw new Error('Missing shamir prime for Email OTP runtime');
    }
    return await enrollEmailOtpWallet({
      relayUrl,
      walletId: String(nearAccountId),
      userId: String(nearAccountId),
      challengeId: args.challengeId,
      otpCode: args.otpCode,
      shamirPrimeB64u,
      workerCtx: this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
      appSessionJwt: args.appSessionJwt,
      otpChannel: args.otpChannel,
      ...(args.clientSecret32 ? { clientSecret32: args.clientSecret32 } : {}),
    });
  }

  private async persistEmailOtpThresholdEd25519LocalMetadata(args: {
    nearAccountId: AccountId;
    rpId: string;
    relayerUrl: string;
    publicKey: string;
    relayerKeyId: string;
    keyVersion: string;
    participantIds: number[];
  }): Promise<void> {
    const profileId = buildNearProfileId(args.nearAccountId);
    const chainIdKey = inferNearChainIdKey(args.nearAccountId);
    const accountAddress = String(args.nearAccountId);
    const signerId = `threshold-ed25519:${args.relayerKeyId}`;
    const signerMaterialFingerprint = buildEmailOtpThresholdEd25519SignerMaterialFingerprint(args);
    const clientDB = this.orchestrationDeps.indexedDB.clientDB;

    await clientDB.upsertProfile({
      profileId,
      defaultSignerSlot: 1,
    });
    await clientDB.upsertChainAccount({
      profileId,
      chainIdKey,
      accountAddress,
      accountModel: 'near-native',
      isPrimary: true,
    });

    const activation = await clientDB.activateAccountSigner({
      account: {
        profileId,
        chainIdKey,
        accountAddress,
        accountModel: 'near-native',
      },
      signer: {
        signerId,
        signerType: 'threshold',
        signerKind: SIGNER_KINDS.thresholdEd25519,
        signerAuthMethod: SIGNER_AUTH_METHODS.emailOtp,
        signerSource: SIGNER_SOURCES.emailOtpRegistration,
        metadata: {
          operationalPublicKey: args.publicKey,
          relayerKeyId: args.relayerKeyId,
          keyVersion: args.keyVersion,
          rpId: args.rpId,
          participantIds: args.participantIds,
          source: EMAIL_OTP_CHANNEL,
          [SIGNER_MATERIAL_FINGERPRINT_METADATA_KEY]: signerMaterialFingerprint,
        },
      },
      activationPolicy: {
        mode: 'reuse_existing',
        signerId,
        materialFingerprint: signerMaterialFingerprint,
      },
      mutation: { routeThroughOutbox: false },
    });
    const signerSlot = activation.signerSlot;
    await clientDB.upsertProfile({
      profileId,
      defaultSignerSlot: signerSlot,
    });

    await storeNearThresholdKeyMaterial(
      {
        clientDB,
        accountKeyMaterialDB: this.orchestrationDeps.indexedDB.accountKeyMaterialDB,
      },
      {
        nearAccountId: args.nearAccountId,
        signerSlot,
        publicKey: args.publicKey,
        relayerKeyId: args.relayerKeyId,
        keyVersion: args.keyVersion,
        participants: buildThresholdEd25519Participants2pV1({
          clientParticipantId: args.participantIds[0] ?? null,
          relayerParticipantId: args.participantIds[1] ?? null,
          relayerKeyId: args.relayerKeyId,
          relayerUrl: args.relayerUrl,
          clientShareDerivation: 'prf_first_v1',
        }),
        timestamp: Date.now(),
      },
    );
  }

  async enrollAndLoginWithEmailOtpEcdsaCapabilityInternal(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    chainId: number;
    emailOtpAuthPolicy?: EmailOtpAuthPolicy;
    otpCode: string;
    relayUrl?: string;
    challengeId?: string;
    shamirPrimeB64u?: string;
    appSessionJwt?: string;
    routeAuth?: AppOrThresholdSessionAuth;
    ecdsaThresholdKeyId?: string;
    participantIds?: number[];
    sessionKind?: 'jwt' | 'cookie';
    sessionId?: string;
    ttlMs?: number;
    remainingUses?: number;
    clientSecret32?: Uint8Array;
    otpChannel?: WalletEmailOtpChannel;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
    registrationAttemptId?: string;
    onProgress?: (progress: EmailOtpWorkerProgressEvent) => void;
  }): Promise<{
    enrollment: Awaited<ReturnType<typeof enrollEmailOtpWallet>>;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    warmCapability: WarmSessionEcdsaCapabilityState;
  }> {
    return await this.emailOtpSessions.enrollAndLoginWithEcdsaCapabilityInternal(args);
  }

  private async assertWarmThresholdEcdsaCapabilityReady(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }): Promise<WarmSessionEcdsaCapabilityState> {
    const warmSession = await this.createWarmSessionCapabilityReader().getWarmSession(
      args.nearAccountId,
    );
    const capability = warmSession.capabilities.ecdsa[args.chain];
    if (capability.state !== 'ready') {
      throw new Error(
        `[SigningEngine] Email OTP bootstrap did not reach warm-session ready state for ${String(
          args.nearAccountId,
        )} (${args.chain}, state=${capability.state})`,
      );
    }
    return capability;
  }

  private async provisionThresholdEcdsaSession(
    args: Parameters<typeof bootstrapEcdsaSessionValue>[1],
  ): Promise<ThresholdEcdsaSessionBootstrapResult> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const chain = args.chain;
    return await this.withThresholdEcdsaBootstrapQueue(nearAccountId, async () => {
      const bootstrap = await bootstrapEcdsaSessionValue(
        this.orchestrationDeps.thresholdSessionActivationDeps,
        {
          ...args,
          nearAccountId,
          chain,
        },
      );
      const thresholdSessionId = String(
        bootstrap.thresholdEcdsaKeyRef.thresholdSessionId || '',
      ).trim();
      if (thresholdSessionId) {
        const capabilityReader = this.createWarmSessionCapabilityReader();
        await ensureEcdsaPrfSealPersisted({
          touchConfirm: this.touchConfirm,
          thresholdSessionId,
          required: Boolean(args.thresholdRouteAuth),
          errorContext: 'threshold-ecdsa bootstrap seal persistence',
          sealPersistInFlightBySessionId: new Map(),
          resolveSealTransport: (sessionId) =>
            capabilityReader.resolveEcdsaSealTransportByThresholdSessionId(sessionId),
        });
      }
      return bootstrap;
    });
  }

  private async commitWorkerProvisionedThresholdEcdsaSession(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: ThresholdEcdsaSessionStoreSource;
    emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  }): Promise<ThresholdEcdsaSessionBootstrapResult> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const chainId = Math.floor(
      Number(
        args.chain === 'evm'
          ? args.smartAccount?.chainId ?? args.bootstrap.keygen.chainId
          : args.bootstrap.keygen.chainId,
      ),
    );
    if (!Number.isSafeInteger(chainId) || chainId < 0) {
      throw new Error(
        `[SigningEngine] worker-provisioned ${args.chain} threshold ECDSA session is missing numeric chainId`,
      );
    }
    await this.ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap({
      nearAccountId,
      chain: args.chain,
      chainId: thresholdEcdsaChainTargetFromActivationChain({
        chain: args.chain,
        chainId,
      }).chainId,
      source: args.source,
      emailOtpAuthContext: args.emailOtpAuthContext,
      smartAccount: args.smartAccount,
    });
    return await this.withThresholdEcdsaBootstrapQueue(nearAccountId, async () => {
      const ecdsaThresholdKeyId = String(
        args.bootstrap.thresholdEcdsaKeyRef.ecdsaThresholdKeyId || '',
      ).trim();
      if (!ecdsaThresholdKeyId) {
        throw new Error(
          '[SigningEngine] threshold-ecdsa bootstrap did not provide canonical ecdsaThresholdKeyId',
        );
      }
      const walletSigningSessionId = String(
        args.bootstrap.session.walletSigningSessionId ||
          args.bootstrap.thresholdEcdsaKeyRef.walletSigningSessionId ||
          '',
      ).trim();
      const canonicalBootstrap: ThresholdEcdsaSessionBootstrapResult = {
        ...args.bootstrap,
        thresholdEcdsaKeyRef: {
          ...args.bootstrap.thresholdEcdsaKeyRef,
          ecdsaThresholdKeyId,
          ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
        },
        session: {
          ...args.bootstrap.session,
          ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
        },
      };
      await this.persistThresholdEcdsaBootstrapChainAccount({
        nearAccountId,
        chain: args.chain,
        bootstrap: canonicalBootstrap,
        smartAccount: args.smartAccount,
        ensureEmailOtpNearAccountMapping: args.source === SIGNER_AUTH_METHODS.emailOtp,
      });
      this.upsertThresholdEcdsaSessionFromBootstrap({
        nearAccountId,
        chain: args.chain,
        bootstrap: canonicalBootstrap,
        source: args.source,
        ...(args.emailOtpAuthContext ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
      });
      // Email OTP bootstrap material is owned by the emailOtp worker. It must not
      // be persisted through the passkey sealed-refresh path.
      return canonicalBootstrap;
    });
  }

  private async commitEvmFamilyThresholdEcdsaSessions(args: {
    nearAccountId: AccountId | string;
    primaryChain: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: ThresholdEcdsaSessionStoreSource;
    emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  }): Promise<{
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    warmCapability: WarmSessionEcdsaCapabilityState;
  }> {
    const commitLane = async (
      chain: ThresholdEcdsaActivationChain,
    ): Promise<{
      bootstrap: ThresholdEcdsaSessionBootstrapResult;
      warmCapability: WarmSessionEcdsaCapabilityState;
    }> => {
      const bootstrap = await this.commitWorkerProvisionedThresholdEcdsaSession({
        nearAccountId: args.nearAccountId,
        chain,
        bootstrap: args.bootstrap,
        source: args.source,
        ...(args.emailOtpAuthContext ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
        ...(args.smartAccount ? { smartAccount: args.smartAccount } : {}),
      });
      const warmCapability = await this.assertWarmThresholdEcdsaCapabilityReady({
        nearAccountId: args.nearAccountId,
        chain,
      });
      return { bootstrap, warmCapability };
    };

    const primaryStorageChain = thresholdEcdsaActivationChainForTarget(args.primaryChain);
    const evmLane = await commitLane('evm');
    const tempoLane = await commitLane('tempo');
    const primaryLane = primaryStorageChain === 'evm' ? evmLane : tempoLane;

    if (!primaryLane.bootstrap || !primaryLane.warmCapability) {
      throw new Error(
        `[SigningEngine] Email OTP bootstrap did not commit primary threshold ECDSA lane (${describeThresholdEcdsaChainTarget(args.primaryChain)})`,
      );
    }
    return {
      bootstrap: primaryLane.bootstrap,
      warmCapability: primaryLane.warmCapability,
    };
  }

  private async provisionThresholdEd25519Session(
    args: ProvisionWarmEd25519CapabilityArgs,
  ): Promise<ProvisionWarmEd25519CapabilityResult> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const relayerUrl = String(
      args.relayerUrl || this.seamsPasskeyConfigs.network.relayer?.url || '',
    ).trim();
    if (!relayerUrl) {
      throw new Error('Missing relayer url (configs.network.relayer.url)');
    }
    const workerCtx =
      this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext();
    const sessionId =
      String(args.sessionId || '').trim() || generateSessionIdValue('threshold-ed25519');
    return await connectEd25519Session({
      indexedDB: this.orchestrationDeps.indexedDB,
      touchIdPrompt: this.touchIdPrompt,
      prfFirstCache: this.touchConfirm,
      relayerUrl,
      relayerKeyId: args.relayerKeyId,
      ...(args.appSessionJwt ? { appSessionJwt: args.appSessionJwt } : {}),
      ...(args.useAppSessionCookie ? { useAppSessionCookie: args.useAppSessionCookie } : {}),
      ...(args.localPrfCredential ? { localPrfCredential: args.localPrfCredential } : {}),
      ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
      ...(args.runtimeScopeBootstrap ? { runtimeScopeBootstrap: args.runtimeScopeBootstrap } : {}),
      nearAccountId,
      participantIds: args.participantIds,
      sessionKind: args.sessionKind,
      sessionId,
      walletSigningSessionId: args.walletSigningSessionId,
      ttlMs: args.ttlMs,
      remainingUses: args.remainingUses,
      workerCtx,
    });
  }

  upsertThresholdEcdsaSessionFromBootstrap(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: ThresholdEcdsaSessionStoreSource;
    emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  }): void {
    upsertThresholdEcdsaSessionFromBootstrapValue(
      {
        recordsByLane: this.thresholdEcdsaSessionByLane,
        exportArtifactsByLane: this.thresholdEcdsaExportArtifactByLane,
      },
      {
        ...args,
        signingSessionSeal: this.seamsPasskeyConfigs.signing.sessionSeal,
      },
    );
  }

  getThresholdEcdsaKeyRefForLookup(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    source: ThresholdEcdsaSessionStoreSource;
  }): ThresholdEcdsaSecp256k1KeyRef {
    return getThresholdEcdsaKeyRefForLookupValue(
      {
        recordsByLane: this.thresholdEcdsaSessionByLane,
        exportArtifactsByLane: this.thresholdEcdsaExportArtifactByLane,
      },
      args,
    );
  }

  getThresholdEcdsaSessionRecordForLookup(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    source: ThresholdEcdsaSessionStoreSource;
  }): ThresholdEcdsaSessionRecord {
    return getThresholdEcdsaSessionRecordForLookupValue(
      {
        recordsByLane: this.thresholdEcdsaSessionByLane,
      },
      args,
    );
  }

  listThresholdEcdsaSessionRecordsForLookup(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    source?: ThresholdEcdsaSessionStoreSource;
  }): ThresholdEcdsaSessionRecord[] {
    return listThresholdEcdsaSessionRecordsForLookupValue(
      {
        recordsByLane: this.thresholdEcdsaSessionByLane,
        exportArtifactsByLane: this.thresholdEcdsaExportArtifactByLane,
      },
      args,
    );
  }

  getThresholdEcdsaSessionRecordByThresholdSessionId(
    thresholdSessionIdRaw: string,
  ): ThresholdEcdsaSessionRecord | null {
    const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
    if (!thresholdSessionId) return null;
    for (const record of this.thresholdEcdsaSessionByLane.values()) {
      if (String(record.thresholdSessionId || '').trim() === thresholdSessionId) {
        return record;
      }
    }
    return getStoredThresholdEcdsaSessionRecordByThresholdSessionIdValue(thresholdSessionId);
  }

  listThresholdEcdsaKeyRefsForLookup(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    source?: ThresholdEcdsaSessionStoreSource;
  }): ThresholdEcdsaKeyRefLookupResult[] {
    return listThresholdEcdsaKeyRefsForLookupValue(
      {
        recordsByLane: this.thresholdEcdsaSessionByLane,
        exportArtifactsByLane: this.thresholdEcdsaExportArtifactByLane,
      },
      args,
    );
  }

  getEmailOtpThresholdEcdsaKeyRefForSigning(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }): ThresholdEcdsaSecp256k1KeyRef {
    return getEmailOtpThresholdEcdsaKeyRefForSigningValue(
      {
        recordsByLane: this.thresholdEcdsaSessionByLane,
        exportArtifactsByLane: this.thresholdEcdsaExportArtifactByLane,
      },
      args,
    );
  }

  getEmailOtpThresholdEcdsaSessionRecordForSigning(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }): ThresholdEcdsaSessionRecord {
    return getEmailOtpThresholdEcdsaSessionRecordForSigningValue(
      {
        recordsByLane: this.thresholdEcdsaSessionByLane,
      },
      args,
    );
  }

  getPasskeyThresholdEcdsaKeyRefForSigning(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
  }): ThresholdEcdsaSecp256k1KeyRef {
    return getPasskeyThresholdEcdsaKeyRefForSigningValue(
      {
        recordsByLane: this.thresholdEcdsaSessionByLane,
        exportArtifactsByLane: this.thresholdEcdsaExportArtifactByLane,
      },
      args,
    );
  }

  getPasskeyThresholdEcdsaSessionRecordForSigning(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
  }): ThresholdEcdsaSessionRecord {
    return getPasskeyThresholdEcdsaSessionRecordForSigningValue(
      {
        recordsByLane: this.thresholdEcdsaSessionByLane,
      },
      args,
    );
  }

  clearThresholdEcdsaSessionRecordForAccount(nearAccountId: AccountId | string): void {
    clearThresholdEcdsaSessionRecordForAccountValue(
      {
        recordsByLane: this.thresholdEcdsaSessionByLane,
        exportArtifactsByLane: this.thresholdEcdsaExportArtifactByLane,
      },
      nearAccountId,
    );
  }

  clearThresholdEcdsaSessionRecordForLane(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    source?: ThresholdEcdsaSessionStoreSource;
  }): void {
    clearThresholdEcdsaSessionRecordForLaneValue(
      {
        recordsByLane: this.thresholdEcdsaSessionByLane,
        exportArtifactsByLane: this.thresholdEcdsaExportArtifactByLane,
      },
      args,
    );
  }

  markThresholdEcdsaEmailOtpSessionConsumedForAccount(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    uses?: number;
  }): void {
    markThresholdEcdsaEmailOtpSessionConsumedForAccountValue(
      {
        recordsByLane: this.thresholdEcdsaSessionByLane,
        exportArtifactsByLane: this.thresholdEcdsaExportArtifactByLane,
      },
      args,
    );
  }

  upsertStoredThresholdEcdsaSessionRecord(
    record: ThresholdEcdsaSessionRecord,
  ): ThresholdEcdsaSessionRecord {
    return upsertStoredThresholdEcdsaSessionRecordValue(
      {
        recordsByLane: this.thresholdEcdsaSessionByLane,
        exportArtifactsByLane: this.thresholdEcdsaExportArtifactByLane,
      },
      record,
    );
  }

  markThresholdEd25519EmailOtpSessionConsumedForAccount(args: {
    nearAccountId: AccountId | string;
    thresholdSessionId?: string;
    uses?: number;
  }): void {
    markThresholdEd25519EmailOtpSessionConsumedForAccountValue(args);
  }

  clearThresholdEcdsaSigningArtifactsForLane(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    source: ThresholdEcdsaSessionStoreSource;
  }): void {
    const record = this.getThresholdEcdsaSessionRecordForLookup(args);
    clearThresholdEcdsaClientPresignaturesForLane({
      relayerUrl: record.relayerUrl,
      ecdsaThresholdKeyId: String(record.ecdsaThresholdKeyId || '').trim(),
      participantIds: record.participantIds,
    });
  }

  clearAllThresholdEcdsaSessionRecords(): void {
    clearAllThresholdEcdsaSessionRecordsValue({
      recordsByLane: this.thresholdEcdsaSessionByLane,
      exportArtifactsByLane: this.thresholdEcdsaExportArtifactByLane,
    });
  }

  persistThresholdEcdsaBootstrapChainAccount(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
    deployment?: {
      deployed: boolean;
      deploymentTxHash?: string;
    };
    ensureEmailOtpNearAccountMapping?: boolean;
  }): Promise<void> {
    return persistThresholdEcdsaBootstrapChainAccountValue({
      indexedDB: this.orchestrationDeps.indexedDB,
      nearAccountId: toAccountId(args.nearAccountId),
      chain: args.chain,
      bootstrap: args.bootstrap,
      smartAccount: args.smartAccount,
      deployment: args.deployment,
      ensureEmailOtpNearAccountMapping: args.ensureEmailOtpNearAccountMapping,
    });
  }

  getWarmThresholdEd25519SessionStatus(
    nearAccountId: AccountId | string,
  ): Promise<SigningSessionStatus | null> {
    return (async () => {
      const status =
        await this.createWarmSessionStatusReader().getEd25519SigningSessionStatus(nearAccountId);
      const record = getStoredThresholdEd25519SessionRecordForAccountValue(nearAccountId);
      const walletBudgetStatus = await this.getWalletSigningBudgetAvailableStatus({
        nearAccountId,
        walletSigningSessionId: record?.walletSigningSessionId,
      });
      if (!status) return walletBudgetStatus;
      return this.mergeWalletSigningBudgetStatus(status, walletBudgetStatus);
    })();
  }

  getWarmThresholdEcdsaSessionStatus(
    nearAccountId: AccountId | string,
    chain: 'tempo' | 'evm',
    thresholdSessionId: string,
  ): Promise<WarmEcdsaSigningSessionStatus | null> {
    return (async () => {
      const status = await this.createWarmSessionStatusReader().getEcdsaSigningSessionStatus({
        nearAccountId,
        chain,
        thresholdSessionId,
      });
      const walletBudgetStatus = await this.getWalletSigningBudgetAvailableStatus({
        nearAccountId,
        walletSigningSessionId: status?.walletSigningSessionId,
      });
      if (!status) return walletBudgetStatus as WarmEcdsaSigningSessionStatus | null;
      return this.mergeWalletSigningBudgetStatus(status, walletBudgetStatus);
    })();
  }

  listWarmThresholdEcdsaSessionStatuses(
    nearAccountId: AccountId | string,
    chain: 'tempo' | 'evm',
  ): Promise<WarmEcdsaSigningSessionStatus[]> {
    return (async () => {
      const statuses = await this.createWarmSessionStatusReader().listEcdsaSigningSessionStatuses({
        nearAccountId,
        chain,
      });
      return await Promise.all(
        statuses.map(async (status) => {
          const walletBudgetStatus = await this.getWalletSigningBudgetAvailableStatus({
            nearAccountId,
            walletSigningSessionId: status.walletSigningSessionId,
          });
          return this.mergeWalletSigningBudgetStatus(status, walletBudgetStatus);
        }),
      );
    })();
  }

  async scheduleThresholdEcdsaLoginPresignPrefill(args: {
    nearAccountId: AccountId | string;
    chain: 'tempo' | 'evm';
    thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
    minRemainingUsesBeforePrefill?: number;
  }): Promise<ThresholdEcdsaLoginPrefillResult> {
    const chain = args.chain;
    const statusReader = this.createWarmSessionStatusReader();
    return await scheduleThresholdEcdsaLoginPresignPrefillValue(
      {
        getWarmThresholdEcdsaSessionStatus: async (
          nearAccountId: AccountId | string,
          thresholdSessionId: string,
          chain: 'tempo' | 'evm',
        ) => {
          const canonicalSessionId =
            this.orchestrationDeps.resolveCanonicalThresholdEcdsaSessionIdForChain(
              nearAccountId,
              chain,
            );
          if (
            canonicalSessionId &&
            canonicalSessionId !== String(thresholdSessionId || '').trim()
          ) {
            return {
              sessionId: canonicalSessionId,
              status: 'not_found',
            };
          }
          return await statusReader.getEcdsaSigningSessionStatus({
            nearAccountId,
            chain,
            thresholdSessionId,
          });
        },
        getSignerWorkerContext: () =>
          this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
        thresholdEcdsaPresignPoolPolicy:
          this.seamsPasskeyConfigs.signing.thresholdEcdsa.presignPool,
      },
      { ...args, chain },
    );
  }

  async hydrateSigningSession(args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
    transport?: {
      curve?: 'ed25519' | 'ecdsa';
      relayerUrl?: string;
      thresholdSessionJwt?: string;
      keyVersion?: string;
      shamirPrimeB64u?: string;
    };
  }): Promise<void> {
    await cacheSigningSessionPrfFirstValue(this.touchConfirm, args);
  }

  async clearWarmSigningSessions(nearAccountId?: AccountId | string): Promise<void> {
    if (nearAccountId == null && hasWarmSessionMaterialClearAll(this.touchConfirm)) {
      await this.touchConfirm.clearAllWarmSessionMaterial().catch(() => undefined);
      return;
    }

    const sessionIds =
      nearAccountId != null ? this.collectWarmSigningSessionIdsForAccount(nearAccountId) : [];

    await Promise.all(
      sessionIds.map((sessionId) =>
        clearSigningSessionPrfFirstBestEffortValue(this.touchConfirm, sessionId),
      ),
    );
  }

  private async withThresholdEcdsaCommitQueue<T>(args: {
    queueKey: string;
    nearAccountId: AccountId | string;
    enabled: boolean;
    shouldAbort?: () => boolean;
    maxQueueLength?: number;
    queueTimeoutMs?: number;
    task: () => Promise<T>;
  }): Promise<T> {
    return await withThresholdEcdsaCommitQueue({
      queueByKey: this.thresholdEcdsaCommitQueueByKey,
      queueKey: args.queueKey,
      nearAccountId: args.nearAccountId,
      enabled: args.enabled,
      shouldAbort: args.shouldAbort,
      maxQueueLength: args.maxQueueLength,
      queueTimeoutMs: args.queueTimeoutMs,
      task: args.task,
    });
  }

  private async withThresholdEd25519CommitQueue<T>(args: {
    queueKey: string;
    nearAccountId: AccountId | string;
    enabled: boolean;
    shouldAbort?: () => boolean;
    maxQueueLength?: number;
    queueTimeoutMs?: number;
    task: () => Promise<T>;
  }): Promise<T> {
    return await withThresholdEd25519CommitQueue({
      queueByKey: this.thresholdEd25519CommitQueueByKey,
      queueKey: args.queueKey,
      nearAccountId: args.nearAccountId,
      enabled: args.enabled,
      shouldAbort: args.shouldAbort,
      maxQueueLength: args.maxQueueLength,
      queueTimeoutMs: args.queueTimeoutMs,
      task: args.task,
    });
  }

  clearThresholdEcdsaCommitQueue(): void {
    clearThresholdEcdsaCommitQueue(this.thresholdEcdsaCommitQueueByKey);
  }

  clearThresholdEd25519CommitQueue(): void {
    clearThresholdEd25519CommitQueue(this.thresholdEd25519CommitQueueByKey);
  }

  deriveThresholdEd25519ClientVerifyingShareFromCredential(
    args: Parameters<typeof deriveThresholdEd25519ClientVerifyingShareFromCredentialValue>[1],
  ): ReturnType<typeof deriveThresholdEd25519ClientVerifyingShareFromCredentialValue> {
    return deriveThresholdEd25519ClientVerifyingShareFromCredentialValue(
      this.orchestrationDeps.thresholdEd25519LifecycleDeps,
      args,
    );
  }

  deriveThresholdEd25519HssClientInputsFromCredential(
    args: Parameters<typeof deriveThresholdEd25519HssClientInputsFromCredentialValue>[1],
  ): ReturnType<typeof deriveThresholdEd25519HssClientInputsFromCredentialValue> {
    return deriveThresholdEd25519HssClientInputsFromCredentialValue(
      this.orchestrationDeps.thresholdEd25519LifecycleDeps,
      args,
    );
  }

  prepareThresholdEd25519HssClientCeremonyFromCredential(
    args: Parameters<typeof prepareThresholdEd25519HssClientCeremonyFromCredentialValue>[1],
  ): ReturnType<typeof prepareThresholdEd25519HssClientCeremonyFromCredentialValue> {
    return prepareThresholdEd25519HssClientCeremonyFromCredentialValue(
      this.orchestrationDeps.thresholdEd25519LifecycleDeps,
      args,
    );
  }

  prepareThresholdEd25519HssClientRequest(
    args: Omit<Parameters<typeof prepareThresholdEd25519HssClientRequestWasm>[0], 'workerCtx'>,
  ): ReturnType<typeof prepareThresholdEd25519HssClientRequestWasm> {
    return prepareThresholdEd25519HssClientRequestWasm({
      ...args,
      workerCtx: this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
    });
  }

  completeThresholdEd25519HssClientCeremony(
    args: Omit<Parameters<typeof completeThresholdEd25519HssClientCeremonyValue>[0], 'workerCtx'>,
  ): ReturnType<typeof completeThresholdEd25519HssClientCeremonyValue> {
    return completeThresholdEd25519HssClientCeremonyValue({
      ...args,
      workerCtx: this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
    });
  }

  runThresholdEd25519HssCeremonyWithSession(
    args: Omit<Parameters<typeof runThresholdEd25519HssCeremonyWithSessionValue>[0], 'workerCtx'>,
  ): ReturnType<typeof runThresholdEd25519HssCeremonyWithSessionValue> {
    return runThresholdEd25519HssCeremonyWithSessionValue({
      ...args,
      workerCtx: this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
    });
  }

  openThresholdEd25519HssSeedOutput(
    args: Omit<Parameters<typeof openThresholdEd25519HssSeedOutputValue>[0], 'workerCtx'>,
  ): ReturnType<typeof openThresholdEd25519HssSeedOutputValue> {
    return openThresholdEd25519HssSeedOutputValue({
      ...args,
      workerCtx: this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
    });
  }

  buildThresholdEd25519SeedExportArtifactFromHssReport(
    args: Omit<
      Parameters<typeof buildThresholdEd25519SeedExportArtifactFromHssReportValue>[0],
      'workerCtx'
    >,
  ): ReturnType<typeof buildThresholdEd25519SeedExportArtifactFromHssReportValue> {
    return buildThresholdEd25519SeedExportArtifactFromHssReportValue({
      ...args,
      workerCtx: this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
    });
  }

  destroy(): void {
    this.userPreferencesManager.destroy();
    this.nonceCoordinator.clearAll();
    this.clearThresholdEcdsaCommitQueue();
    this.clearAllThresholdEcdsaSessionRecords();
  }

  private collectWarmSigningSessionIdsForAccount(nearAccountId: AccountId | string): string[] {
    const sessionIds = new Set<string>();
    const ed25519SessionId = String(
      getStoredThresholdEd25519SessionRecordForAccountValue(nearAccountId)?.thresholdSessionId ||
        '',
    ).trim();
    if (ed25519SessionId) {
      sessionIds.add(ed25519SessionId);
    }
    for (const chain of ['tempo', 'evm'] as const) {
      for (const source of THRESHOLD_ECDSA_SESSION_STORE_SOURCES) {
        try {
          const ecdsaSessionId = String(
            getThresholdEcdsaSessionRecordForLookupValue(
              {
                recordsByLane: this.thresholdEcdsaSessionByLane,
                exportArtifactsByLane: this.thresholdEcdsaExportArtifactByLane,
              },
              { nearAccountId, chain, source },
            )?.thresholdSessionId || '',
          ).trim();
          if (ecdsaSessionId) {
            sessionIds.add(ecdsaSessionId);
          }
        } catch {}
      }
    }
    return [...sessionIds];
  }
}

/**
 * Boundary-facing API spec for SigningEngine consumers.
 * Keep this narrow and intentional; prefer adding methods here explicitly.
 */
export type SigningEnginePublic = Pick<
  SigningEngine,
  | 'seamsPasskeyConfigs'
  | 'setTheme'
  | 'getUserPreferences'
  | 'getRpId'
  | 'getNonceCoordinator'
  | 'warmCriticalResources'
  | 'assertSealedRefreshStartupParity'
  | 'restorePersistedSessionsForAccount'
  | 'readPersistedSigningSessionSnapshot'
  | 'signNear'
  | 'signTempo'
  | 'reportTempoBroadcastAccepted'
  | 'reportTempoBroadcastRejected'
  | 'reportTempoFinalized'
  | 'reportTempoDroppedOrReplaced'
  | 'reconcileTempoNonceLane'
  | 'storeUserData'
  | 'getAllUsers'
  | 'getUserBySignerSlot'
  | 'getLastUser'
  | 'getAuthenticatorsByUser'
  | 'updateLastLogin'
  | 'setLastUser'
  | 'initializeCurrentUser'
  | 'storeAuthenticator'
  | 'rollbackUserRegistration'
  | 'hasPasskeyCredential'
  | 'atomicStoreRegistrationData'
  | 'requestRegistrationCredentialConfirmation'
  | 'getAuthenticationCredentialsSerialized'
  | 'extractCosePublicKey'
  | 'exportKeypairWithUI'
  | 'exportNearEd25519SeedArtifactWithUI'
  | 'exportThresholdEd25519SeedFromHssReport'
  | 'signTransactionWithKeyPair'
  | 'generateEphemeralNearKeypair'
  | 'connectEd25519Session'
  | 'bootstrapEcdsaSession'
  | 'upsertThresholdEcdsaSessionFromBootstrap'
  | 'getThresholdEcdsaKeyRefForLookup'
  | 'listThresholdEcdsaKeyRefsForLookup'
  | 'getThresholdEcdsaSessionRecordForLookup'
  | 'listThresholdEcdsaSessionRecordsForLookup'
  | 'clearThresholdEcdsaSessionRecordForAccount'
  | 'clearAllThresholdEcdsaSessionRecords'
  | 'persistThresholdEcdsaBootstrapChainAccount'
  | 'getWarmThresholdEd25519SessionStatus'
  | 'getWarmThresholdEcdsaSessionStatus'
  | 'listWarmThresholdEcdsaSessionStatuses'
  | 'scheduleThresholdEcdsaLoginPresignPrefill'
  | 'hydrateSigningSession'
  | 'clearWarmSigningSessions'
  | 'clearThresholdEcdsaCommitQueue'
  | 'deriveThresholdEd25519ClientVerifyingShareFromCredential'
  | 'deriveThresholdEd25519HssClientInputsFromCredential'
  | 'prepareThresholdEd25519HssClientCeremonyFromCredential'
  | 'prepareThresholdEd25519HssClientRequest'
  | 'completeThresholdEd25519HssClientCeremony'
  | 'runThresholdEd25519HssCeremonyWithSession'
  | 'openThresholdEd25519HssSeedOutput'
  | 'buildThresholdEd25519SeedExportArtifactFromHssReport'
>;
