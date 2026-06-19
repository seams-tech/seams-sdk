import type { NormalizedLogger } from '../logger';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import type { EcdsaRelayerHssPublicKey33B64u } from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  parseRouterAbEd25519NormalSigningState,
  type RouterAbEd25519NormalSigningState,
} from '@shared/utils/signingSessionSeal';
import {
  parseRouterAbNormalSigningServerPolicy,
  validateRouterAbNormalSigningServerPolicy,
  type ParseResult,
  type RouterAbNormalSigningServerPolicy,
} from './routerAbNormalSigningPolicy';
import type { SessionClaims } from '../../router/relay';
import type { AccessKeyList } from '../rpcClients/near/NearClient';
import type {
  ThresholdEcdsaIntegratedKeyStore,
  ThresholdEd25519KeyRecord,
  ThresholdEd25519KeyStore,
} from './stores/KeyStore';
import type {
  ThresholdEd25519MpcSessionRecord,
  ThresholdEd25519SessionStore,
} from './stores/SessionStore';
import type {
  RouterAbEcdsaHssPoolFillSessionStore,
  RouterAbEcdsaHssPresignaturePool,
} from './stores/EcdsaSigningStore';
import type {
  Ed25519WalletSessionStore,
  Ed25519WalletSessionRecord,
  WalletSessionBudgetReservationResult,
  WalletSessionBudgetReleaseResult,
  WalletSessionConsumeUsesResult,
} from './stores/WalletSessionStore';
import type {
  ThresholdEd25519KeygenMaterial,
  ThresholdEd25519KeygenStrategy,
} from './keygenStrategy';
import { ThresholdEd25519KeygenStrategyV1 } from './keygenStrategy';
import type {
  VerifyAuthenticationResponse,
  WebAuthnAuthenticationCredential,
  ThresholdEd25519SessionRequest,
  ThresholdEd25519SessionResponse,
  ThresholdEd25519HssCanonicalContext,
  ThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope,
  ThresholdEd25519HssServerVisibleClientRequestEnvelope,
  ThresholdEd25519HssFinalizeForRegistrationRequest,
  ThresholdEd25519HssFinalizeForRegistrationResponse,
  ThresholdEd25519HssFinalizeWithSessionRequest,
  ThresholdEd25519HssFinalizeWithSessionResponse,
  ThresholdEd25519HssPrepareForRegistrationRequest,
  ThresholdEd25519HssPrepareForRegistrationResponse,
  ThresholdEd25519HssPrepareWithSessionRequest,
  ThresholdEd25519HssPrepareWithSessionResponse,
  ThresholdEd25519HssPreparedSessionEnvelope,
  ThresholdEd25519HssPreparedServerSessionEnvelope,
  ThresholdEd25519HssStoredPreparedServerSession,
  ThresholdEd25519HssSessionOperation,
  ThresholdEd25519HssStoredStagedEvaluatorArtifact,
  ThresholdEd25519HssServerInputs,
  ThresholdEd25519HssStoredServerInputs,
  ThresholdEd25519HssRespondForRegistrationRequest,
  ThresholdEd25519HssRespondForRegistrationResponse,
  ThresholdEd25519HssRespondWithSessionRequest,
  ThresholdEd25519HssRespondWithSessionResponse,
  ThresholdEd25519HssStagedEvaluatorArtifactEnvelope,
  Ed25519SessionPolicy,
  EcdsaHssClientBootstrapRequest,
  EcdsaHssExportShareRequest,
  EcdsaHssExportShareResponse,
  EcdsaHssRoleLocalKeyRecord,
  EcdsaHssRouteResult,
  EcdsaHssServerBootstrapResponse,
  ThresholdEcdsaSigningRootMetadata,
  ThresholdEd25519CosignInitRequest,
  ThresholdEd25519CosignInitResponse,
  ThresholdEd25519CosignFinalizeRequest,
  ThresholdEd25519CosignFinalizeResponse,
  ThresholdStoreConfigInput,
} from '../types';
import {
  addSecp256k1PublicKeys33,
  roleLocalThresholdEcdsaHssRelayerBootstrap,
  secp256k1PrivateKey32ToPublicKey33,
  secp256k1PublicKey33ToEthereumAddress,
  validateSecp256k1PublicKey33,
} from './ethSignerWasm';
import { verifyEcdsaClientRootProof } from './ecdsaClientRootProof';
import {
  deriveThresholdEd25519VerifyingShareFromSigningShare,
  deriveThresholdEd25519RegistrationMaterialFromHssFinalize,
  finalizeThresholdEd25519HssServerCeremony,
  prepareThresholdEd25519HssRoleSeparatedServerInputDelivery,
  prepareThresholdEd25519HssServerSession,
  releaseThresholdEd25519HssPreparedServerSession,
  releaseThresholdEd25519HssStagedEvaluatorArtifact,
} from './ed25519HssWasm';
import {
  ensureRelayerKeyIsActiveAccessKey,
  extractAuthorizeSigningPublicKey,
  isObject,
  parseAppSessionClaims,
  parseRouterAbEcdsaHssWalletSessionClaims,
  parseRouterAbEd25519WalletSessionClaims,
  resolveAppSessionWalletIdForWalletScope,
  resolveAppSessionProviderUserIdForWalletScope,
  toNearPublicKeyStr,
  type RouterAbEd25519WalletSessionClaims,
  type RouterAbEcdsaHssWalletSessionClaims,
} from './validation';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { deriveThresholdEcdsaKeyHandle } from '@shared/utils/thresholdEcdsaKeyHandle';
import {
  normalizeThresholdEd25519ParticipantId,
  normalizeThresholdEd25519ParticipantIds,
} from '@shared/threshold/participants';
import {
  normalizeRuntimePolicyScope,
  signingRootScopeFromRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '../thresholdEcdsaChainTarget';
import {
  coerceThresholdNodeRole,
  parseThresholdCoordinatorPeers,
  parseThresholdCoordinatorSharedSecretBytes,
  parseThresholdEd25519ParticipantIds2p,
} from './config';
import { RouterAbEcdsaHssPoolFillHandlers } from './routerAb/ecdsaHssPoolFillHandlers';
import { ThresholdEd25519SigningHandlers } from './signingHandlers';
import { resolveThresholdEd25519RelayerKeyMaterial } from './relayerKeyMaterial';
import {
  deriveEcdsaHssYRelayerFromSigningRootShareResolver,
  deriveEd25519HssServerInputsFromSigningRootShareResolver,
  type FixedSigningRootScope,
  type SigningRootShareResolver,
} from './signingRootShareResolver';
import { randomBytes } from 'node:crypto';
import type {
  ThresholdAnySchemeModule,
  ThresholdEd25519RegistrationKeygenRequest,
  ThresholdEd25519RegistrationKeygenResult,
} from './schemes/types';
import type { ThresholdSchemeId } from './schemes/schemeIds';
import {
  THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
  THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
} from './schemes/schemeIds';
import { createThresholdEd25519Frost2pSchemeModule } from './schemes/ed25519Frost2p';
import { createThresholdSecp256k1Ecdsa2pSchemeModule } from './schemes/secp256k1Ecdsa2p';
import { walletSigningBudgetSessionId } from './walletSigningBudget';
import { secureRandomIdFragment } from './secureRandomId';

type ThresholdEd25519SessionClaims = RouterAbEd25519WalletSessionClaims;
type ThresholdEcdsaSessionClaims = RouterAbEcdsaHssWalletSessionClaims;

type ThresholdEd25519HssSessionError = { ok: false; code?: string; message?: string };
const ED25519_HSS_SERVER_VISIBLE_CLIENT_REQUEST_FORBIDDEN_FIELDS = [
  'evaluatorOtStateB64u',
  'yClientB64u',
  'tauClientB64u',
  'rClientB64u',
  'clientOutputMaskB64u',
  'prfFirstB64u',
  'prfOutputB64u',
  'clientSecretB64u',
  'clientSecret32B64u',
  'yRelayerB64u',
  'tauRelayerB64u',
] as const;

const ED25519_HSS_CLIENT_OWNED_STAGED_ARTIFACT_FORBIDDEN_FIELDS = [
  'stagedEvaluatorArtifactHandle',
  'evaluatorOtStateB64u',
  'xClientBaseB64u',
  'xRelayerBaseB64u',
  'yClientB64u',
  'tauClientB64u',
  'yRelayerB64u',
  'tauRelayerB64u',
  'rClientB64u',
  'clientOutputMaskB64u',
  'prfFirstB64u',
  'prfOutputB64u',
  'clientSecretB64u',
  'clientSecret32B64u',
  'seedOutputMessageB64u',
] as const;

function findOwnField(raw: Record<string, unknown>, fields: readonly string[]): string | undefined {
  return fields.find((field) => Object.prototype.hasOwnProperty.call(raw, field));
}

type ThresholdEd25519HssCeremonyRecord =
  | {
      kind: 'session';
      expiresAtMs: number;
      relayerKeyId: string;
      operation: ThresholdEd25519HssSessionOperation;
      context: ThresholdEd25519HssCanonicalContext;
      preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
      preparedServerSession: ThresholdEd25519HssStoredPreparedServerSession;
      serverInputs?: ThresholdEd25519HssStoredServerInputs;
      evaluationResult?: ThresholdEd25519HssStoredStagedEvaluatorArtifact;
    }
  | {
      kind: 'registration';
      expiresAtMs: number;
      orgId: string;
      newAccountId: string;
      rpId: string;
      context: ThresholdEd25519HssCanonicalContext;
      preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
      preparedServerSession: ThresholdEd25519HssStoredPreparedServerSession;
      serverInputs?: ThresholdEd25519HssStoredServerInputs;
      evaluationResult?: ThresholdEd25519HssStoredStagedEvaluatorArtifact;
    };

type ThresholdEd25519HssCeremonyRecordInput =
  | Omit<Extract<ThresholdEd25519HssCeremonyRecord, { kind: 'session' }>, 'expiresAtMs'>
  | Omit<Extract<ThresholdEd25519HssCeremonyRecord, { kind: 'registration' }>, 'expiresAtMs'>;

type ThresholdEcdsaBootstrapSessionResult =
  | {
      ok: true;
      sessionId: string;
      signingGrantId?: string;
      chainTarget?: ThresholdEcdsaChainTarget;
      ecdsaThresholdKeyId?: string;
      keyHandle?: string;
      expiresAtMs: number;
      expiresAt: string;
      participantIds: number[];
      remainingUses?: number;
      jwt?: string;
    }
  | {
      ok: false;
      code?: string;
      message?: string;
    };

type ThresholdEcdsaWalletSessionRecord = Omit<Ed25519WalletSessionRecord, 'userId'> & {
  walletSessionUserId: string;
};

type ThresholdEcdsaMpcSessionRecord = Omit<ThresholdEd25519MpcSessionRecord, 'userId'> & {
  walletSessionUserId: string;
};

function routerAbNormalSigningBudgetIdempotencyKey(
  input: RouterAbNormalSigningBudgetConsumeInput,
): string {
  return [
    'router-ab-normal-signing',
    input.curve,
    input.phase,
    input.sessionId,
    input.requestId,
  ].join(':');
}

function routerAbBudgetConsumeFailure(
  result: WalletSessionConsumeUsesResult & { ok: false },
): RouterAbNormalSigningBudgetConsumeResult {
  const code = toOptionalTrimmedString(result.code) || 'unauthorized';
  const message = toOptionalTrimmedString(result.message) || 'Wallet Session budget rejected';
  const lowered = message.toLowerCase();
  if (code === 'expired' || lowered.includes('expired')) {
    return { ok: false, status: 409, code: 'expired', message: 'wallet signing session expired' };
  }
  if (code === 'exhausted' || lowered.includes('exhaust')) {
    return {
      ok: false,
      status: 409,
      code: 'exhausted',
      message: 'wallet signing session exhausted',
    };
  }
  if (code === 'not_found') return { ok: false, status: 404, code, message };
  if (code === 'invalid_body') return { ok: false, status: 400, code, message };
  if (code === 'unauthorized') return { ok: false, status: 401, code, message };
  return { ok: false, status: 500, code: 'internal', message };
}

function routerAbBudgetStoreFailure(input: {
  code: string;
  message: string;
}): { ok: false; status: number; code: string; message: string } {
  const code = toOptionalTrimmedString(input.code) || 'wallet_budget_internal';
  const message = toOptionalTrimmedString(input.message) || 'Wallet Session budget rejected';
  switch (code) {
    case 'unauthorized':
      return { ok: false, status: 401, code, message };
    case 'wallet_budget_forbidden':
      return { ok: false, status: 403, code, message };
    case 'wallet_budget_exhausted':
    case 'wallet_budget_in_flight':
    case 'wallet_budget_reservation_mismatch':
      return { ok: false, status: 409, code, message };
    case 'wallet_budget_reservation_expired':
      return { ok: false, status: 410, code, message };
    case 'invalid_budget_request':
    case 'invalid_body':
      return { ok: false, status: 422, code: 'invalid_budget_request', message };
    default:
      return { ok: false, status: 500, code: 'wallet_budget_internal', message };
  }
}

function errorMessage(error: unknown): string {
  return String(
    error && typeof error === 'object' && 'message' in error
      ? (error as { message?: unknown }).message
      : error || '',
  );
}

type ThresholdNearTransactionDispatchResult = {
  rpcResult: unknown;
};

type ThresholdNearTransactionDispatcher = (input: {
  signedTransactionBorshB64u: string;
}) => Promise<ThresholdNearTransactionDispatchResult>;

function isEcdsaHssPublicKeyValidationError(message: string): boolean {
  const normalized = message.toLowerCase();
  return (
    normalized.includes('public key') &&
    (normalized.includes('invalid') ||
      normalized.includes('secp256k1') ||
      normalized.includes('point') ||
      normalized.includes('identity'))
  );
}

function compactDiagnosticValue(value: unknown): string | null {
  const normalized = toOptionalTrimmedString(value);
  if (!normalized) return null;
  return normalized.length <= 16
    ? normalized
    : `${normalized.slice(0, 10)}...${normalized.slice(-6)}`;
}

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).length;
}

function jsonBytes(value: unknown): number {
  return utf8Bytes(JSON.stringify(value));
}

function bytesToLowerHex(bytes: Uint8Array): string {
  return `0x${Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')}`;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

const THRESHOLD_ECDSA_HSS_KEY_PURPOSE_V1 = 'evm-signing';
const THRESHOLD_ECDSA_HSS_KEY_VERSION_V1 = 'v1';
const THRESHOLD_ECDSA_SIGNING_ROOT_VERSION_DEFAULT = 'default';
const THRESHOLD_ECDSA_DERIVATION_VERSION_V1 = 1;
const THRESHOLD_ECDSA_HSS_EXPORT_CLOCK_SKEW_MS = 5 * 60_000;
const THRESHOLD_ECDSA_HSS_EXPORT_CONFIRMATION_DIGEST_VERSION =
  'ecdsa-hss:role-local:product-export-confirmation:v2';
const THRESHOLD_ECDSA_HSS_EXPORT_AUTHORIZATION_DIGEST_VERSION =
  'ecdsa-hss:role-local:product-export-authorization:v2';
const WALLET_SIGNING_BUDGET_RELAYER_KEY_ID = 'wallet-signing-budget';

export type ThresholdEcdsaKeyIdentityMetadata = {
  walletId: string;
  rpId: string;
  keyScope: 'evm-family';
  keyHandle: string;
  ecdsaThresholdKeyId: string;
  relayerKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  participantIds: number[];
  thresholdOwnerAddress: string;
  thresholdEcdsaPublicKeyB64u: string;
};

type EcdsaSigningRootReference = {
  signingRootId: string;
  signingRootVersion?: string;
};

function canonicalEcdsaHssSigningRootVersion(signingRootVersion: unknown): string {
  return toOptionalTrimmedString(signingRootVersion) || 'default';
}

async function deriveThresholdEcdsaHssKeyHandle(input: {
  readonly ecdsaThresholdKeyId: unknown;
  readonly signingRootId: unknown;
  readonly signingRootVersion?: unknown;
}): Promise<string> {
  return String(
    await deriveThresholdEcdsaKeyHandle({
      ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
      signingRootId: input.signingRootId,
      signingRootVersion: input.signingRootVersion,
    }),
  );
}

function createEcdsaSigningRootMetadata(
  signingRootId: string,
  signingRootVersion?: string,
): ThresholdEcdsaSigningRootMetadata {
  return {
    signingRootId,
    ...(signingRootVersion ? { signingRootVersion } : {}),
    walletKeyVersion: THRESHOLD_ECDSA_HSS_KEY_VERSION_V1,
    derivationVersion: THRESHOLD_ECDSA_DERIVATION_VERSION_V1,
  };
}

function ecdsaHssRoleLocalRecordMatchesBootstrap(
  record: EcdsaHssRoleLocalKeyRecord,
  bootstrap: EcdsaHssServerBootstrapResponse,
): boolean {
  return (
    record.walletId === bootstrap.walletId &&
    record.rpId === bootstrap.rpId &&
    record.ecdsaThresholdKeyId === bootstrap.ecdsaThresholdKeyId &&
    record.keyHandle === bootstrap.keyHandle &&
    record.signingRootId === bootstrap.signingRootId &&
    record.signingRootVersion ===
      canonicalEcdsaHssSigningRootVersion(bootstrap.signingRootVersion) &&
    record.keyScope === 'evm-family' &&
    record.relayerKeyId === bootstrap.relayerKeyId &&
    record.contextBinding32B64u === bootstrap.contextBinding32B64u &&
    record.clientPublicKey33B64u === bootstrap.publicIdentity.hssClientSharePublicKey33B64u &&
    record.relayerPublicKey33B64u === bootstrap.publicIdentity.relayerPublicKey33B64u &&
    record.groupPublicKey33B64u === bootstrap.publicIdentity.groupPublicKey33B64u &&
    record.ethereumAddress.toLowerCase() ===
      bootstrap.publicIdentity.ethereumAddress.toLowerCase() &&
    record.groupPublicKey33B64u === bootstrap.thresholdEcdsaPublicKeyB64u &&
    record.ethereumAddress.toLowerCase() === bootstrap.ethereumAddress.toLowerCase() &&
    record.relayerPublicKey33B64u === bootstrap.relayerVerifyingShareB64u
  );
}

function createEcdsaSigningRootReference(input: {
  readonly signingRootId: unknown;
  readonly signingRootVersion?: unknown;
}): EcdsaSigningRootReference | null {
  const signingRootId = toOptionalTrimmedString(input.signingRootId);
  if (!signingRootId) return null;
  const signingRootVersion = toOptionalTrimmedString(input.signingRootVersion);
  return {
    signingRootId,
    ...(signingRootVersion ? { signingRootVersion } : {}),
  };
}

function resolveEcdsaSigningRootFromScope(scope: unknown): EcdsaSigningRootReference | null {
  if (!isObject(scope)) return null;
  try {
    return createEcdsaSigningRootReference(
      signingRootScopeFromRuntimePolicyScope(scope as RuntimePolicyScope),
    );
  } catch {
    return null;
  }
}

function haveSameEcdsaSigningRootMetadata(
  left: Partial<ThresholdEcdsaSigningRootMetadata> | null | undefined,
  right: Partial<ThresholdEcdsaSigningRootMetadata> | null | undefined,
): boolean {
  return Boolean(
    left &&
    right &&
    left.signingRootId === right.signingRootId &&
    left.signingRootVersion === right.signingRootVersion &&
    left.walletKeyVersion === right.walletKeyVersion &&
    left.derivationVersion === right.derivationVersion,
  );
}

function parseThresholdEd25519HssSessionOperation(
  raw: unknown,
): ParseResult<ThresholdEd25519HssSessionOperation> {
  const value = toOptionalTrimmedString(raw);
  switch (value) {
    case 'tx_signing':
    case 'link_device':
    case 'email_recovery':
    case 'warm_session_reconstruction':
    case 'explicit_key_export':
      return { ok: true, value };
    default:
      return {
        ok: false,
        code: 'invalid_body',
        message:
          'operation must be one of tx_signing, link_device, email_recovery, warm_session_reconstruction, explicit_key_export',
      };
  }
}

function thresholdEd25519HssSessionOperationIncludesSeedOutput(
  operation: ThresholdEd25519HssSessionOperation,
): boolean {
  return operation === 'explicit_key_export';
}

function base64UrlPayloadBytes(value: string): number {
  try {
    return base64UrlDecode(String(value || '')).length;
  } catch {
    return 0;
  }
}

function summarizeThresholdEd25519HssCeremonyRecordBytes(
  record: ThresholdEd25519HssCeremonyRecordInput | ThresholdEd25519HssCeremonyRecord,
): Record<string, number> {
  const preparedServerSessionBytes =
    record.preparedServerSession.evaluatorDriverStateBytes.byteLength +
    record.preparedServerSession.garblerDriverStateBytes.byteLength;
  const serverInputsBytes = record.serverInputs
    ? record.serverInputs.yRelayerBytes.byteLength + record.serverInputs.tauRelayerBytes.byteLength
    : 0;
  const evaluationResultBytes =
    'evaluationResult' in record && record.evaluationResult
      ? (record.evaluationResult.stagedEvaluatorArtifactBytes?.byteLength ??
        utf8Bytes(record.evaluationResult.stagedEvaluatorArtifactHandle || ''))
      : 0;
  const totalWithoutEvaluationResult =
    'evaluationResult' in record && record.evaluationResult
      ? (() => {
          const { evaluationResult: _ignored, ...rest } = record;
          return jsonBytes(rest);
        })()
      : jsonBytes(record);
  const base: Record<string, number> = {
    totalBytes: totalWithoutEvaluationResult + evaluationResultBytes,
    contextBytes: jsonBytes(record.context),
    preparedSessionBytes: jsonBytes(record.preparedSession),
    preparedServerSessionBytes,
    serverInputsBytes,
  };
  if (record.kind === 'session') {
    base.relayerKeyIdBytes = utf8Bytes(record.relayerKeyId);
    base.operationBytes = utf8Bytes(record.operation);
  } else {
    base.orgIdBytes = utf8Bytes(record.orgId);
    base.newAccountIdBytes = utf8Bytes(record.newAccountId);
    base.rpIdBytes = utf8Bytes(record.rpId);
  }
  if ('evaluationResult' in record && record.evaluationResult) {
    base.evaluationResultBytes = evaluationResultBytes;
    base.stagedEvaluatorArtifactBytes = evaluationResultBytes;
  }
  return base;
}

function clearThresholdEd25519HssStoredServerInputs(
  serverInputs: ThresholdEd25519HssStoredServerInputs | undefined,
): void {
  if (!serverInputs) return;
  serverInputs.yRelayerBytes.fill(0);
  serverInputs.tauRelayerBytes.fill(0);
}

function summarizeThresholdEd25519HssWasmBreakdown(
  timings:
    | {
        decodeStatesMs: number;
        decodeMessagesMs: number;
        materializeRuntimeMs: number;
        materializeSessionsMs: number;
        ceremonyCoreMs: number;
        ceremonyOtOpenJoinMs?: number;
        ceremonyOtBranchKeyDerivationMs?: number;
        ceremonyOtBranchDecryptMs?: number;
        ceremonyOtPointScalarReconstructionMs?: number;
        ceremonyOtCommitmentVerificationMs?: number;
        ceremonyServerInputOpenMs?: number;
        ceremonyServerInputShareMs?: number;
        ceremonyServerInputCommitmentMs?: number;
        ceremonyServerInputTranscriptMs?: number;
        ceremonyAddStageMs?: number;
        ceremonyMessageScheduleMs?: number;
        ceremonyRoundCoreMs?: number;
        ceremonyOutputProjectorMs?: number;
        ceremonyResultAssemblyMs?: number;
        ceremonyOutputSealingFinalizationMs?: number;
        encodeArtifactMs: number;
      }
    | undefined,
): Record<string, number | string> | null {
  if (!timings) return null;
  const buckets = [
    ['decodeStatesMs', Number(timings.decodeStatesMs || 0)],
    ['decodeMessagesMs', Number(timings.decodeMessagesMs || 0)],
    ['materializeRuntimeMs', Number(timings.materializeRuntimeMs || 0)],
    ['materializeSessionsMs', Number(timings.materializeSessionsMs || 0)],
    ['ceremonyCoreMs', Number(timings.ceremonyCoreMs || 0)],
    ['encodeArtifactMs', Number(timings.encodeArtifactMs || 0)],
  ] as const;
  const [dominantBucket, dominantBucketMs] = buckets.reduce((best, next) =>
    next[1] > best[1] ? next : best,
  );
  const ceremonyBuckets = [
    ['ceremonyAddStageMs', Number(timings.ceremonyAddStageMs || 0)],
    ['ceremonyMessageScheduleMs', Number(timings.ceremonyMessageScheduleMs || 0)],
    ['ceremonyRoundCoreMs', Number(timings.ceremonyRoundCoreMs || 0)],
    ['ceremonyOutputProjectorMs', Number(timings.ceremonyOutputProjectorMs || 0)],
    ['ceremonyOtOpenJoinMs', Number(timings.ceremonyOtOpenJoinMs || 0)],
    ['ceremonyOtBranchKeyDerivationMs', Number(timings.ceremonyOtBranchKeyDerivationMs || 0)],
    ['ceremonyOtBranchDecryptMs', Number(timings.ceremonyOtBranchDecryptMs || 0)],
    [
      'ceremonyOtPointScalarReconstructionMs',
      Number(timings.ceremonyOtPointScalarReconstructionMs || 0),
    ],
    ['ceremonyOtCommitmentVerificationMs', Number(timings.ceremonyOtCommitmentVerificationMs || 0)],
    ['ceremonyServerInputOpenMs', Number(timings.ceremonyServerInputOpenMs || 0)],
    ['ceremonyServerInputShareMs', Number(timings.ceremonyServerInputShareMs || 0)],
    ['ceremonyServerInputCommitmentMs', Number(timings.ceremonyServerInputCommitmentMs || 0)],
    ['ceremonyServerInputTranscriptMs', Number(timings.ceremonyServerInputTranscriptMs || 0)],
    ['ceremonyResultAssemblyMs', Number(timings.ceremonyResultAssemblyMs || 0)],
    [
      'ceremonyOutputSealingFinalizationMs',
      Number(timings.ceremonyOutputSealingFinalizationMs || 0),
    ],
  ] as const;
  const [dominantCeremonyStage, dominantCeremonyStageMs] = ceremonyBuckets.reduce((best, next) =>
    next[1] > best[1] ? next : best,
  );
  const hasMeasuredCeremonyStageBreakdown = dominantCeremonyStageMs > 0;
  return {
    totalMeasuredMs: buckets.reduce((sum, [, value]) => sum + value, 0),
    materializationMs:
      Number(timings.materializeRuntimeMs || 0) + Number(timings.materializeSessionsMs || 0),
    dominantBucket,
    dominantBucketMs,
    dominantCeremonyStage: hasMeasuredCeremonyStageBreakdown
      ? dominantCeremonyStage
      : 'unavailable',
    dominantCeremonyStageMs: hasMeasuredCeremonyStageBreakdown ? dominantCeremonyStageMs : 0,
  };
}

function isEthSignerWasmRuntimeError(messageRaw: string): boolean {
  const message = String(messageRaw || '').toLowerCase();
  return (
    message.includes('eth_signer wasm') ||
    message.includes('initialize eth_signer wasm') ||
    message.includes('not initialized')
  );
}

function parseThresholdEd25519SessionRequest(
  request: ThresholdEd25519SessionRequest,
  participantIds2p: number[],
): ParseResult<{
  relayerKeyId: string;
  nearAccountId: string;
  rpId: string;
  sessionId: string;
  signingGrantId: string;
  runtimePolicyScope?: RuntimePolicyScope;
  routerAbNormalSigning?: RouterAbEd25519NormalSigningState;
  ttlMsRaw: number;
  remainingUsesRaw: number;
  policyParticipantIds: number[] | null;
  expectedOrigin: string | null;
}> {
  const rec = (request || {}) as unknown as Record<string, unknown>;
  const relayerKeyId = toOptionalTrimmedString(rec.relayerKeyId);
  if (!relayerKeyId) {
    return { ok: false, code: 'invalid_body', message: 'relayerKeyId is required' };
  }

  const policyRaw = (rec as { sessionPolicy?: unknown }).sessionPolicy;
  if (!isObject(policyRaw)) {
    return { ok: false, code: 'invalid_body', message: 'sessionPolicy (object) is required' };
  }
  const version = toOptionalTrimmedString((policyRaw as Record<string, unknown>).version);
  if (version !== 'threshold_session_v1') {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'sessionPolicy.version must be threshold_session_v1',
    };
  }
  const nearAccountId = toOptionalTrimmedString(
    (policyRaw as Record<string, unknown>).nearAccountId,
  );
  const rpId = toOptionalTrimmedString((policyRaw as Record<string, unknown>).rpId);
  const sessionId = toOptionalTrimmedString((policyRaw as Record<string, unknown>).sessionId);
  const signingGrantId =
    toOptionalTrimmedString((policyRaw as Record<string, unknown>).signingGrantId) ||
    sessionId;
  const policyRelayerKeyId = toOptionalTrimmedString(
    (policyRaw as Record<string, unknown>).relayerKeyId,
  );
  let runtimePolicyScope: RuntimePolicyScope | undefined;
  if (Object.prototype.hasOwnProperty.call(policyRaw, 'runtimePolicyScope')) {
    try {
      runtimePolicyScope = normalizeRuntimePolicyScope(
        (policyRaw as Record<string, unknown>).runtimePolicyScope,
      );
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'sessionPolicy.runtimePolicyScope must be a valid runtime policy scope',
      };
    }
  }
  let routerAbNormalSigning: RouterAbEd25519NormalSigningState | undefined;
  if (Object.prototype.hasOwnProperty.call(policyRaw, 'routerAbNormalSigning')) {
    try {
      const parsedRouterAbNormalSigning = parseRouterAbEd25519NormalSigningState(
        (policyRaw as Record<string, unknown>).routerAbNormalSigning,
      );
      if (!parsedRouterAbNormalSigning) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'sessionPolicy.routerAbNormalSigning must be a Router A/B normal-signing state',
        };
      }
      routerAbNormalSigning = parsedRouterAbNormalSigning;
    } catch (error) {
      return {
        ok: false,
        code: 'invalid_body',
        message:
          error && typeof error === 'object' && 'message' in error
            ? String((error as { message?: unknown }).message)
            : 'sessionPolicy.routerAbNormalSigning is invalid',
      };
    }
  }
  const ttlMsRaw = Number((policyRaw as Record<string, unknown>).ttlMs);
  const remainingUsesRaw = Number((policyRaw as Record<string, unknown>).remainingUses);
  const expectedOrigin = toOptionalTrimmedString(rec.expected_origin) || null;
  if (!nearAccountId || !rpId || !sessionId || !signingGrantId || !policyRelayerKeyId) {
    return {
      ok: false,
      code: 'invalid_body',
      message:
        'sessionPolicy{nearAccountId,rpId,relayerKeyId,sessionId,signingGrantId} are required',
    };
  }
  if (policyRelayerKeyId !== relayerKeyId) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'sessionPolicy.relayerKeyId must match relayerKeyId',
    };
  }

  const policyHasParticipantIds = Object.prototype.hasOwnProperty.call(policyRaw, 'participantIds');
  const policyParticipantIds = normalizeThresholdEd25519ParticipantIds(
    (policyRaw as Record<string, unknown>).participantIds,
  );
  if (policyHasParticipantIds && !policyParticipantIds) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'sessionPolicy.participantIds must be a non-empty array of positive integers',
    };
  }
  if (policyParticipantIds) {
    if (policyParticipantIds.length < 2) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'sessionPolicy.participantIds must contain at least 2 participant ids',
      };
    }
    for (const id of participantIds2p) {
      if (!policyParticipantIds.includes(id)) {
        return {
          ok: false,
          code: 'unauthorized',
          message: `sessionPolicy.participantIds must include server signer set (expected to include participantIds=[${participantIds2p.join(',')}])`,
        };
      }
    }
  }

  if (!Number.isFinite(ttlMsRaw) || ttlMsRaw <= 0) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'sessionPolicy.ttlMs must be a positive number',
    };
  }
  if (!Number.isFinite(remainingUsesRaw) || remainingUsesRaw <= 0) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'sessionPolicy.remainingUses must be a positive number',
    };
  }

  return {
    ok: true,
    value: {
      relayerKeyId,
      nearAccountId,
      rpId,
      sessionId,
      signingGrantId,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      ...(routerAbNormalSigning ? { routerAbNormalSigning } : {}),
      ttlMsRaw,
      remainingUsesRaw,
      policyParticipantIds: policyParticipantIds || null,
      expectedOrigin,
    },
  };
}

type ThresholdEd25519SessionWalletAuthProof =
  | {
      method: 'app_session';
      claims: ReturnType<typeof parseAppSessionClaims>;
      sessionWalletId: string;
    }
  | {
      method: 'threshold_ecdsa_session';
      claims: ThresholdEcdsaSessionClaims;
    }
  | {
      method: 'passkey';
      webauthnAuthentication: WebAuthnAuthenticationCredential;
    };

function resolveThresholdEd25519SessionWalletAuthProof(input: {
  request: ThresholdEd25519SessionRequest;
  appSessionClaims: ReturnType<typeof parseAppSessionClaims>;
  sessionWalletId: string;
  ecdsaSessionClaims: ThresholdEcdsaSessionClaims | null;
  hasAppSessionAuth: boolean;
  hasEcdsaSessionAuth: boolean;
}): ParseResult<ThresholdEd25519SessionWalletAuthProof> {
  if (input.hasAppSessionAuth) {
    return {
      ok: true,
      value: {
        method: 'app_session',
        claims: input.appSessionClaims,
        sessionWalletId: input.sessionWalletId,
      },
    };
  }

  if (input.ecdsaSessionClaims) {
    if (!input.hasEcdsaSessionAuth) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'threshold-ecdsa session does not match threshold-ed25519 session scope',
      };
    }
    return {
      ok: true,
      value: {
        method: 'threshold_ecdsa_session',
        claims: input.ecdsaSessionClaims,
      },
    };
  }

  if (!input.request.webauthn_authentication) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'webauthn_authentication is required for threshold-ed25519 session mint',
    };
  }

  return {
    ok: true,
    value: {
      method: 'passkey',
      webauthnAuthentication: input.request.webauthn_authentication,
    },
  };
}

function parseThresholdEd25519HssCanonicalContext(
  raw: unknown,
): ParseResult<ThresholdEd25519HssCanonicalContext> {
  if (!isObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'context is required' };
  }
  const signingRootId = toOptionalTrimmedString(raw.signingRootId);
  const nearAccountId = toOptionalTrimmedString(raw.nearAccountId);
  const keyPurpose = toOptionalTrimmedString(raw.keyPurpose);
  const keyVersion = toOptionalTrimmedString(raw.keyVersion);
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds);
  const derivationVersion = Number(raw.derivationVersion);
  if (!signingRootId) {
    return { ok: false, code: 'invalid_body', message: 'context.signingRootId is required' };
  }
  if (!nearAccountId) {
    return { ok: false, code: 'invalid_body', message: 'context.nearAccountId is required' };
  }
  if (!keyPurpose) {
    return { ok: false, code: 'invalid_body', message: 'context.keyPurpose is required' };
  }
  if (!keyVersion) {
    return { ok: false, code: 'invalid_body', message: 'context.keyVersion is required' };
  }
  if (!participantIds || participantIds.length < 2) {
    return { ok: false, code: 'invalid_body', message: 'context.participantIds is required' };
  }
  if (!Number.isFinite(derivationVersion) || derivationVersion < 1) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'context.derivationVersion must be a positive number',
    };
  }
  return {
    ok: true,
    value: {
      signingRootId,
      nearAccountId,
      keyPurpose,
      keyVersion,
      participantIds,
      derivationVersion,
    },
  };
}

function parseThresholdEd25519HssPreparedSessionEnvelope(
  raw: unknown,
): ParseResult<ThresholdEd25519HssPreparedSessionEnvelope> {
  if (!isObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'preparedSession is required' };
  }
  const contextBindingB64u = toOptionalTrimmedString(raw.contextBindingB64u);
  const evaluatorDriverStateB64u = toOptionalTrimmedString(raw.evaluatorDriverStateB64u);
  if (!contextBindingB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'preparedSession.contextBindingB64u is required',
    };
  }
  if (!evaluatorDriverStateB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'preparedSession.evaluatorDriverStateB64u is required',
    };
  }
  return {
    ok: true,
    value: {
      contextBindingB64u,
      evaluatorDriverStateB64u,
    },
  };
}

function parseThresholdEd25519HssServerVisibleClientRequestEnvelope(
  raw: unknown,
): ParseResult<ThresholdEd25519HssServerVisibleClientRequestEnvelope> {
  if (!isObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'clientRequest is required' };
  }
  const clientRequestMessageB64u = toOptionalTrimmedString(raw.clientRequestMessageB64u);
  if (!clientRequestMessageB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'clientRequest.clientRequestMessageB64u is required',
    };
  }
  const forbiddenField = findOwnField(
    raw,
    ED25519_HSS_SERVER_VISIBLE_CLIENT_REQUEST_FORBIDDEN_FIELDS,
  );
  if (forbiddenField) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `clientRequest.${forbiddenField} must stay outside the server-visible request`,
    };
  }
  return {
    ok: true,
    value: { clientRequestMessageB64u },
  };
}

function parseThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope(
  raw: unknown,
): ParseResult<ThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope> {
  if (!isObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'evaluationResult is required' };
  }
  const contextBindingB64u = toOptionalTrimmedString(raw.contextBindingB64u);
  const stagedEvaluatorArtifactB64u = toOptionalTrimmedString(raw.stagedEvaluatorArtifactB64u);
  if (!contextBindingB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'evaluationResult.contextBindingB64u is required',
    };
  }
  if (!stagedEvaluatorArtifactB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'evaluationResult.stagedEvaluatorArtifactB64u is required',
    };
  }
  const forbiddenField = findOwnField(
    raw,
    ED25519_HSS_CLIENT_OWNED_STAGED_ARTIFACT_FORBIDDEN_FIELDS,
  );
  if (forbiddenField) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `evaluationResult.${forbiddenField} must stay outside the client-owned staged artifact`,
    };
  }
  return {
    ok: true,
    value: { contextBindingB64u, stagedEvaluatorArtifactB64u },
  };
}

function haveSameParticipantIds(a: number[], b: number[]): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

export type ThresholdEcdsaKeySelector = {
  kind: 'key_handle';
  keyHandle: string;
  ecdsaThresholdKeyId?: never;
};
type ThresholdEcdsaKeyHandleSelector = ThresholdEcdsaKeySelector;

function parseThresholdEcdsaKeySelector(
  rec: Record<string, unknown>,
  input: {
    required: boolean;
    missingMessage: string;
  },
): ParseResult<ThresholdEcdsaKeyHandleSelector | null> {
  const keyHandle = toOptionalTrimmedString(rec.keyHandle);
  const ecdsaThresholdKeyId = toOptionalTrimmedString(rec.ecdsaThresholdKeyId);
  if (ecdsaThresholdKeyId) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'keyHandle is required for threshold-ecdsa key selection',
    };
  }
  if (!keyHandle) {
    if (!input.required) return { ok: true, value: null };
    return {
      ok: false,
      code: 'invalid_body',
      message: input.missingMessage,
    };
  }
  return { ok: true, value: { kind: 'key_handle', keyHandle } };
}

export type RouterAbSigningWorkerPrivateHttpConfig = {
  signingWorkerBaseUrl: string;
  auth: { kind: 'internal_service_auth_token'; token: string };
};

export type RouterAbEd25519SigningWorkerPrivateMaterial = {
  kind: 'router_ab_ed25519_signing_worker_material_v1';
  account_public_key: string;
  x_server_base_b64u: string;
  signing_worker_material_handle: string;
  activated_at_ms: number;
};

export type RouterAbNormalSigningPrepareReplayReservationInput =
  | {
      curve: 'ed25519';
      phase: 'prepare' | 'presign-pool-prepare';
      sessionId: string;
      requestId: string;
      expiresAtMs: number;
    }
  | {
      curve: 'ecdsa-hss';
      phase: 'prepare';
      sessionId: string;
      requestId: string;
      expiresAtMs: number;
    };

export type RouterAbNormalSigningPrepareReplayReservationResult =
  | { ok: true }
  | { ok: false; status: number; code: string; message: string };

export type RouterAbNormalSigningBudgetConsumeInput =
  | {
      curve: 'ed25519';
      phase: 'finalize';
      sessionId: string;
      signingGrantId: string;
      requestId: string;
    }
  | {
      curve: 'ecdsa-hss';
      phase: 'finalize';
      sessionId: string;
      signingGrantId: string;
      requestId: string;
    };

export type RouterAbNormalSigningBudgetConsumeResult =
  | { ok: true; remainingUses: number }
  | { ok: false; status: number; code: string; message: string };

export type RouterAbNormalSigningBudgetReservationInput =
  | {
      curve: 'ed25519';
      phase: 'prepare';
      sessionId: string;
      signingGrantId: string;
      operationId: string;
      requestDigest: string;
      signatureUses: number;
      expiresAtMs: number;
    }
  | {
      curve: 'ecdsa-hss';
      phase: 'prepare';
      sessionId: string;
      signingGrantId: string;
      operationId: string;
      requestDigest: string;
      signatureUses: number;
      expiresAtMs: number;
    };

export type RouterAbNormalSigningBudgetReservationResult =
  | {
      ok: true;
      reservationId: string;
      remainingUses: number;
      reservedUses: number;
      availableUses: number;
    }
  | { ok: false; status: number; code: string; message: string };

export type RouterAbNormalSigningBudgetCommitInput =
  | {
      curve: 'ed25519';
      phase: 'finalize';
      sessionId: string;
      signingGrantId: string;
      reservationId: string;
      operationId: string;
      requestDigest: string;
    }
  | {
      curve: 'ecdsa-hss';
      phase: 'finalize';
      sessionId: string;
      signingGrantId: string;
      reservationId: string;
      operationId: string;
      requestDigest: string;
    };

export type RouterAbNormalSigningBudgetCommitResult =
  | { ok: true; remainingUses: number }
  | { ok: false; status: number; code: string; message: string };

export type RouterAbNormalSigningBudgetReleaseInput =
  | {
      curve: 'ed25519';
      phase: 'prepare' | 'finalize';
      sessionId: string;
      signingGrantId: string;
      reservationId: string;
    }
  | {
      curve: 'ecdsa-hss';
      phase: 'prepare' | 'finalize';
      sessionId: string;
      signingGrantId: string;
      reservationId: string;
    };

export type RouterAbNormalSigningBudgetReleaseResult =
  | {
      ok: true;
      released: boolean;
      remainingUses: number;
      reservedUses: number;
      availableUses: number;
    }
  | { ok: false; status: number; code: string; message: string };

function resolveRouterAbSigningWorkerPrivateHttpConfig(
  cfg: Record<string, unknown>,
): RouterAbSigningWorkerPrivateHttpConfig | null {
  const signingWorkerBaseUrl =
    toOptionalTrimmedString(cfg.ROUTER_AB_SIGNING_WORKER_URL) ||
    toOptionalTrimmedString(cfg.ROUTER_AB_ECDSA_HSS_POOL_FILL_SIGNING_WORKER_URL) ||
    toOptionalTrimmedString(cfg.SIGNING_WORKER_URL);
  const token =
    toOptionalTrimmedString(cfg.ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET) ||
    toOptionalTrimmedString(cfg.ROUTER_AB_INTERNAL_SERVICE_AUTH_TOKEN);
  if (!signingWorkerBaseUrl && !token) return null;
  if (!signingWorkerBaseUrl) {
    throw new Error(
      'ROUTER_AB_SIGNING_WORKER_URL is required when Router A/B internal service auth is configured',
    );
  }
  if (!token) {
    throw new Error(
      'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET is required when Router A/B SigningWorker URL is configured',
    );
  }
  return {
    signingWorkerBaseUrl,
    auth: { kind: 'internal_service_auth_token', token },
  };
}

export class ThresholdSigningService {
  private readonly logger: NormalizedLogger;
  private readonly keyStore: ThresholdEd25519KeyStore;
  private readonly sessionStore: ThresholdEd25519SessionStore;
  private readonly walletSessionStore: Ed25519WalletSessionStore;
  private readonly ecdsaKeyStore: ThresholdEcdsaIntegratedKeyStore;
  private readonly ecdsaSessionStore: ThresholdEd25519SessionStore;
  private readonly ecdsaWalletSessionStore: Ed25519WalletSessionStore;
  private readonly clientParticipantId: number;
  private readonly relayerParticipantId: number;
  private readonly participantIds2p: number[];
  private readonly keygenStrategy: ThresholdEd25519KeygenStrategy;
  private readonly signingHandlers: ThresholdEd25519SigningHandlers;
  private readonly ecdsaPoolFillSessionStore: RouterAbEcdsaHssPoolFillSessionStore;
  private readonly ecdsaPresignaturePool: RouterAbEcdsaHssPresignaturePool;
  private readonly signingRootShareResolver: SigningRootShareResolver | null;
  private readonly routerAbNormalSigningPolicy: RouterAbNormalSigningServerPolicy;
  private readonly routerAbSigningWorkerPrivateHttp: RouterAbSigningWorkerPrivateHttpConfig | null;
  private readonly routerAbEcdsaHssPoolFillHandlers: RouterAbEcdsaHssPoolFillHandlers;
  private readonly ensureReady: () => Promise<void>;
  private readonly ensureSignerWasm: () => Promise<void>;
  private readonly verifyWebAuthnAuthenticationLite:
    | ((request: {
        nearAccountId: string;
        rpId: string;
        expectedChallenge: string;
        expected_origin: string;
        webauthn_authentication: WebAuthnAuthenticationCredential;
      }) => Promise<VerifyAuthenticationResponse>)
    | null;
  private readonly viewAccessKeyList: (accountId: string) => Promise<AccessKeyList>;
  private readonly dispatchNearTransaction: ThresholdNearTransactionDispatcher;
  private readonly ed25519HssCeremonyTtlMs = 2 * 60_000;
  private readonly ed25519HssCeremonyStore = new Map<string, ThresholdEd25519HssCeremonyRecord>();
  private cachedSchemeModules: Partial<Record<ThresholdSchemeId, ThresholdAnySchemeModule>> | null =
    null;

  readonly ed25519Hss = {
    prepareForRegistration: async (input: {
      orgId: string;
      signingRootId?: string;
      signingRootVersion?: string;
      request: ThresholdEd25519HssPrepareForRegistrationRequest;
    }): Promise<ThresholdEd25519HssPrepareForRegistrationResponse> => {
      return this.ed25519HssPrepareForRegistration(input);
    },
    respondForRegistration: async (input: {
      orgId: string;
      request: ThresholdEd25519HssRespondForRegistrationRequest;
    }): Promise<ThresholdEd25519HssRespondForRegistrationResponse> => {
      return this.ed25519HssRespondForRegistration(input);
    },
    finalizeForRegistration: async (input: {
      orgId: string;
      request: ThresholdEd25519HssFinalizeForRegistrationRequest;
    }): Promise<ThresholdEd25519HssFinalizeForRegistrationResponse> => {
      return this.ed25519HssFinalizeForRegistration(input);
    },
    prepareWithSession: async (input: {
      claims: SessionClaims;
      request: ThresholdEd25519HssPrepareWithSessionRequest;
    }): Promise<ThresholdEd25519HssPrepareWithSessionResponse> => {
      const claims = parseRouterAbEd25519WalletSessionClaims(input.claims);
      if (!claims) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Invalid Wallet Session claims',
        };
      }
      return this.ed25519HssPrepareWithSession({ claims, request: input.request });
    },
    respondWithSession: async (input: {
      claims: SessionClaims;
      request: ThresholdEd25519HssRespondWithSessionRequest;
    }): Promise<ThresholdEd25519HssRespondWithSessionResponse> => {
      const claims = parseRouterAbEd25519WalletSessionClaims(input.claims);
      if (!claims) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Invalid Wallet Session claims',
        };
      }
      return this.ed25519HssRespondWithSession({ claims, request: input.request });
    },
    finalizeWithSession: async (input: {
      claims: SessionClaims;
      request: ThresholdEd25519HssFinalizeWithSessionRequest;
    }): Promise<ThresholdEd25519HssFinalizeWithSessionResponse> => {
      const claims = parseRouterAbEd25519WalletSessionClaims(input.claims);
      if (!claims) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Invalid Wallet Session claims',
        };
      }
      return this.ed25519HssFinalizeWithSession({ claims, request: input.request });
    },
  };

  constructor(input: {
    logger: NormalizedLogger;
    keyStore: ThresholdEd25519KeyStore;
    sessionStore: ThresholdEd25519SessionStore;
    walletSessionStore: Ed25519WalletSessionStore;
    ecdsaKeyStore: ThresholdEcdsaIntegratedKeyStore;
    ecdsaSessionStore: ThresholdEd25519SessionStore;
    ecdsaWalletSessionStore: Ed25519WalletSessionStore;
    ecdsaPoolFillSessionStore: RouterAbEcdsaHssPoolFillSessionStore;
    ecdsaPresignaturePool: RouterAbEcdsaHssPresignaturePool;
    signingRootShareResolver?: SigningRootShareResolver | null;
    config?: ThresholdStoreConfigInput | null;
    ensureReady: () => Promise<void>;
    ensureSignerWasm: () => Promise<void>;
    verifyWebAuthnAuthenticationLite?: (request: {
      nearAccountId: string;
      rpId: string;
      expectedChallenge: string;
      expected_origin: string;
      webauthn_authentication: WebAuthnAuthenticationCredential;
    }) => Promise<VerifyAuthenticationResponse>;
    viewAccessKeyList: (accountId: string) => Promise<AccessKeyList>;
    dispatchNearTransaction: ThresholdNearTransactionDispatcher;
  }) {
    this.logger = input.logger;
    this.keyStore = input.keyStore;
    this.sessionStore = input.sessionStore;
    this.walletSessionStore = input.walletSessionStore;
    this.ecdsaKeyStore = input.ecdsaKeyStore;
    this.ecdsaSessionStore = input.ecdsaSessionStore;
    this.ecdsaWalletSessionStore = input.ecdsaWalletSessionStore;
    this.ecdsaPoolFillSessionStore = input.ecdsaPoolFillSessionStore;
    this.ecdsaPresignaturePool = input.ecdsaPresignaturePool;
    this.signingRootShareResolver = input.signingRootShareResolver || null;
    const cfg = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
    this.routerAbNormalSigningPolicy = parseRouterAbNormalSigningServerPolicy(cfg);

    const nodeRole = coerceThresholdNodeRole(cfg.THRESHOLD_NODE_ROLE);
    const coordinatorSharedSecretBytes = parseThresholdCoordinatorSharedSecretBytes(
      cfg.THRESHOLD_COORDINATOR_SHARED_SECRET_B64U,
    );
    const coordinatorInstanceId = toOptionalTrimmedString(cfg.THRESHOLD_COORDINATOR_INSTANCE_ID);
    const coordinatorPeers = parseThresholdCoordinatorPeers(cfg.THRESHOLD_COORDINATOR_PEERS) || [];
    const relayerCosignerIdRaw = cfg.THRESHOLD_ED25519_RELAYER_COSIGNER_ID;
    const relayerCosignerId =
      relayerCosignerIdRaw === undefined
        ? null
        : normalizeThresholdEd25519ParticipantId(relayerCosignerIdRaw);
    if (nodeRole === 'cosigner' && !relayerCosignerId) {
      throw new Error(
        'THRESHOLD_ED25519_RELAYER_COSIGNER_ID is required when THRESHOLD_NODE_ROLE=cosigner',
      );
    }

    const ids = parseThresholdEd25519ParticipantIds2p({
      THRESHOLD_ED25519_CLIENT_PARTICIPANT_ID: cfg.THRESHOLD_ED25519_CLIENT_PARTICIPANT_ID,
      THRESHOLD_ED25519_RELAYER_PARTICIPANT_ID: cfg.THRESHOLD_ED25519_RELAYER_PARTICIPANT_ID,
    });
    this.clientParticipantId = ids.clientParticipantId;
    this.relayerParticipantId = ids.relayerParticipantId;
    this.participantIds2p = ids.participantIds2p;

    this.ensureReady = input.ensureReady;
    this.ensureSignerWasm = input.ensureSignerWasm;
    this.verifyWebAuthnAuthenticationLite = input.verifyWebAuthnAuthenticationLite || null;
    this.viewAccessKeyList = input.viewAccessKeyList;
    this.dispatchNearTransaction = input.dispatchNearTransaction;
    this.keygenStrategy = new ThresholdEd25519KeygenStrategyV1({
      clientParticipantId: this.clientParticipantId,
      relayerParticipantId: this.relayerParticipantId,
    });
    this.signingHandlers = new ThresholdEd25519SigningHandlers({
      logger: this.logger,
      nodeRole,
      relayerCosignerId,
      coordinatorSharedSecretBytes,
      clientParticipantId: this.clientParticipantId,
      relayerParticipantId: this.relayerParticipantId,
      participantIds2p: this.participantIds2p,
      sessionStore: this.sessionStore,
      ensureReady: this.ensureReady,
      ensureSignerWasm: this.ensureSignerWasm,
    });
    const routerAbSigningWorkerPrivateHttp = resolveRouterAbSigningWorkerPrivateHttpConfig(cfg);
    this.routerAbSigningWorkerPrivateHttp = routerAbSigningWorkerPrivateHttp;

    this.routerAbEcdsaHssPoolFillHandlers = new RouterAbEcdsaHssPoolFillHandlers({
      logger: this.logger,
      nodeRole,
      participantIds2p: this.participantIds2p,
      clientParticipantId: this.clientParticipantId,
      relayerParticipantId: this.relayerParticipantId,
      coordinatorInstanceId: coordinatorInstanceId || null,
      coordinatorPeers,
      sessionStore: {
        readMpcSession: async (sessionId) => await this.readEcdsaMpcSession(sessionId),
        claimMpcSession: async (sessionId, version) =>
          await this.claimEcdsaMpcSession(sessionId, version),
      },
      poolFillSessionStore: this.ecdsaPoolFillSessionStore,
      presignaturePool: this.ecdsaPresignaturePool,
      resolveRoleLocalKeyRecord: async (selector) =>
        this.ecdsaKeyStore.getRoleLocalByKeyHandle(selector.keyHandle),
      ensureReady: this.ensureReady,
      createPoolFillSessionId: () => this.createRouterAbEcdsaHssPoolFillSessionId(),
      routerAbEcdsaHssPoolFill: routerAbSigningWorkerPrivateHttp,
    });
  }

  hasSigningRootShareResolver(): boolean {
    return this.signingRootShareResolver !== null;
  }

  getRouterAbNormalSigningWorkerId(): string {
    return this.routerAbNormalSigningPolicy.signingWorkerId;
  }

  getRouterAbSigningWorkerPrivateHttpConfig(): RouterAbSigningWorkerPrivateHttpConfig | null {
    return this.routerAbSigningWorkerPrivateHttp;
  }

  async reserveRouterAbNormalSigningPrepareReplay(
    input: RouterAbNormalSigningPrepareReplayReservationInput,
  ): Promise<RouterAbNormalSigningPrepareReplayReservationResult> {
    const sessionId = toOptionalTrimmedString(input.sessionId);
    const requestId = toOptionalTrimmedString(input.requestId);
    const expiresAtMs = Number(input.expiresAtMs);
    if (!sessionId || !requestId || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
      return {
        ok: false,
        status: 400,
        code: 'invalid_body',
        message: 'Router A/B normal-signing replay reservation requires session, request id, and expiry',
      };
    }
    const store =
      input.curve === 'ed25519' ? this.walletSessionStore : this.ecdsaWalletSessionStore;
    const replayGuard = await store.reserveReplayGuard(
      ['router-ab-normal-signing', input.curve, input.phase, sessionId].join(':'),
      requestId,
      expiresAtMs,
    );
    if (replayGuard.ok) return { ok: true };
    if (replayGuard.code === 'export_nonce_replay') {
      return {
        ok: false,
        status: 400,
        code: 'one_use_replay_rejected',
        message: 'Router A/B normal-signing prepare request id already used',
      };
    }
    if (replayGuard.code === 'export_authorization_expired') {
      return {
        ok: false,
        status: 400,
        code: 'expired_request',
        message: 'Router A/B normal-signing prepare request is expired',
      };
    }
    return {
      ok: false,
      status: 500,
      code: 'internal',
      message: replayGuard.message,
    };
  }

  async consumeRouterAbNormalSigningBudget(
    input: RouterAbNormalSigningBudgetConsumeInput,
  ): Promise<RouterAbNormalSigningBudgetConsumeResult> {
    const sessionId = toOptionalTrimmedString(input.sessionId);
    const signingGrantId = toOptionalTrimmedString(input.signingGrantId);
    const requestId = toOptionalTrimmedString(input.requestId);
    if (!sessionId || !signingGrantId || !requestId) {
      return {
        ok: false,
        status: 400,
        code: 'invalid_body',
        message: 'Router A/B normal-signing budget consume requires session and request identity',
      };
    }
    const curve = input.curve === 'ed25519' ? 'ed25519' : 'ecdsa';
    const curveStore =
      input.curve === 'ed25519' ? this.walletSessionStore : this.ecdsaWalletSessionStore;
    const consumed = await this.consumeWalletOrCurveSessionUse({
      signingGrantId,
      curve,
      curveSessionId: sessionId,
      curveStore,
      idempotencyKey: routerAbNormalSigningBudgetIdempotencyKey({
        ...input,
        sessionId,
        signingGrantId,
        requestId,
      }),
    });
    if (!consumed.ok) return routerAbBudgetConsumeFailure(consumed);
    return {
      ok: true,
      remainingUses: Math.max(0, Math.floor(Number(consumed.remainingUses) || 0)),
    };
  }

  async reserveRouterAbNormalSigningBudget(
    input: RouterAbNormalSigningBudgetReservationInput,
  ): Promise<RouterAbNormalSigningBudgetReservationResult> {
    const sessionId = toOptionalTrimmedString(input.sessionId);
    const signingGrantId = toOptionalTrimmedString(input.signingGrantId);
    const operationId = toOptionalTrimmedString(input.operationId);
    const requestDigest = toOptionalTrimmedString(input.requestDigest);
    const signatureUses = Math.floor(Number(input.signatureUses));
    const expiresAtMs = Number(input.expiresAtMs);
    if (
      !sessionId ||
      !signingGrantId ||
      !operationId ||
      !requestDigest ||
      !Number.isSafeInteger(signatureUses) ||
      signatureUses <= 0 ||
      !Number.isFinite(expiresAtMs)
    ) {
      return {
        ok: false,
        status: 422,
        code: 'invalid_budget_request',
        message: 'Router A/B budget reservation requires operation, digest, uses, and expiry',
      };
    }
    const curve = input.curve === 'ed25519' ? 'ed25519' : 'ecdsa';
    const curveStore =
      input.curve === 'ed25519' ? this.walletSessionStore : this.ecdsaWalletSessionStore;
    const resolved = await this.resolveWalletOrCurveBudgetStore({
      signingGrantId,
      curve,
      curveSessionId: sessionId,
      curveStore,
    });
    if (!resolved.ok) return routerAbBudgetStoreFailure(resolved);
    const reserved = await resolved.store.reserveUseCountOnce({
      signingGrantId: resolved.budgetSessionId,
      curve,
      thresholdSessionId: sessionId,
      operationId,
      requestDigest,
      signatureUses,
      expiresAtMs,
    });
    if (!reserved.ok) return routerAbBudgetStoreFailure(reserved);
    return {
      ok: true,
      reservationId: reserved.reservation.reservationId,
      remainingUses: reserved.remainingUses,
      reservedUses: reserved.reservedUses,
      availableUses: reserved.availableUses,
    };
  }

  async commitRouterAbNormalSigningBudget(
    input: RouterAbNormalSigningBudgetCommitInput,
  ): Promise<RouterAbNormalSigningBudgetCommitResult> {
    const sessionId = toOptionalTrimmedString(input.sessionId);
    const signingGrantId = toOptionalTrimmedString(input.signingGrantId);
    const reservationId = toOptionalTrimmedString(input.reservationId);
    const operationId = toOptionalTrimmedString(input.operationId);
    const requestDigest = toOptionalTrimmedString(input.requestDigest);
    if (!sessionId || !signingGrantId || !reservationId || !operationId || !requestDigest) {
      return {
        ok: false,
        status: 422,
        code: 'invalid_budget_request',
        message: 'Router A/B budget commit requires reservation, operation, and digest',
      };
    }
    const curve = input.curve === 'ed25519' ? 'ed25519' : 'ecdsa';
    const curveStore =
      input.curve === 'ed25519' ? this.walletSessionStore : this.ecdsaWalletSessionStore;
    const resolved = await this.resolveWalletOrCurveBudgetStore({
      signingGrantId,
      curve,
      curveSessionId: sessionId,
      curveStore,
    });
    if (!resolved.ok) return routerAbBudgetStoreFailure(resolved);
    const committed = await resolved.store.commitReservedUseCountOnce({
      signingGrantId: resolved.budgetSessionId,
      reservationId,
      operationId,
      requestDigest,
    });
    if (!committed.ok) return routerAbBudgetStoreFailure(committed);
    return {
      ok: true,
      remainingUses: Math.max(0, Math.floor(Number(committed.remainingUses) || 0)),
    };
  }

  async releaseRouterAbNormalSigningBudget(
    input: RouterAbNormalSigningBudgetReleaseInput,
  ): Promise<RouterAbNormalSigningBudgetReleaseResult> {
    const sessionId = toOptionalTrimmedString(input.sessionId);
    const signingGrantId = toOptionalTrimmedString(input.signingGrantId);
    const reservationId = toOptionalTrimmedString(input.reservationId);
    if (!sessionId || !signingGrantId || !reservationId) {
      return {
        ok: false,
        status: 422,
        code: 'invalid_budget_request',
        message: 'Router A/B budget release requires session and reservation',
      };
    }
    const curve = input.curve === 'ed25519' ? 'ed25519' : 'ecdsa';
    const curveStore =
      input.curve === 'ed25519' ? this.walletSessionStore : this.ecdsaWalletSessionStore;
    const resolved = await this.resolveWalletOrCurveBudgetStore({
      signingGrantId,
      curve,
      curveSessionId: sessionId,
      curveStore,
    });
    if (!resolved.ok) return routerAbBudgetStoreFailure(resolved);
    const released = await resolved.store.releaseReservedUseCount({
      signingGrantId: resolved.budgetSessionId,
      reservationId,
    });
    if (!released.ok) return routerAbBudgetStoreFailure(released);
    return released;
  }

  async resolveRouterAbEd25519SigningWorkerPrivateMaterial(input: {
    claims: RouterAbEd25519WalletSessionClaims;
  }): Promise<
    | { ok: true; material: RouterAbEd25519SigningWorkerPrivateMaterial }
    | { ok: false; status: number; code: string; message: string }
  > {
    const claims = input.claims;
    const stored = await this.keyStore.get(claims.relayerKeyId);
    if (!stored) {
      return {
        ok: false,
        status: 404,
        code: 'not_found',
        message: 'Router A/B Ed25519 SigningWorker material is not available',
      };
    }
    if (
      stored.nearAccountId !== claims.walletId ||
      stored.rpId !== claims.rpId ||
      stored.publicKey !== claims.relayerKeyId
    ) {
      return {
        ok: false,
        status: 403,
        code: 'forbidden',
        message: 'Router A/B Ed25519 SigningWorker material does not match Wallet Session claims',
      };
    }
    const xServerBaseB64u = toOptionalTrimmedString(stored.relayerSigningShareB64u);
    if (!xServerBaseB64u) {
      return {
        ok: false,
        status: 409,
        code: 'invalid_state',
        message: 'Router A/B Ed25519 SigningWorker material is incomplete',
      };
    }
    const storedRelayerVerifyingShareB64u = toOptionalTrimmedString(
      stored.relayerVerifyingShareB64u,
    );
    if (!storedRelayerVerifyingShareB64u) {
      return {
        ok: false,
        status: 409,
        code: 'invalid_state',
        message: 'Router A/B Ed25519 SigningWorker material is missing verifying-share binding',
      };
    }
    try {
      const derivedRelayerVerifyingShare =
        await deriveThresholdEd25519VerifyingShareFromSigningShare({
          signingShareB64u: xServerBaseB64u,
        });
      const derivedRelayerVerifyingShareB64u = toOptionalTrimmedString(
        derivedRelayerVerifyingShare.verifyingShareB64u,
      );
      if (derivedRelayerVerifyingShareB64u !== storedRelayerVerifyingShareB64u) {
        return {
          ok: false,
          status: 409,
          code: 'invalid_state',
          message: 'Router A/B Ed25519 SigningWorker material verifying-share binding mismatch',
        };
      }
    } catch (error: unknown) {
      return {
        ok: false,
        status: 409,
        code: 'invalid_state',
        message: `Router A/B Ed25519 SigningWorker material verification failed: ${errorMessage(
          error,
        )}`,
      };
    }
    const walletSessionIssuedAtSec = claims.iat;
    if (!Number.isFinite(walletSessionIssuedAtSec) || Number(walletSessionIssuedAtSec) <= 0) {
      return {
        ok: false,
        status: 401,
        code: 'unauthorized',
        message: 'Router A/B Ed25519 Wallet Session JWT is missing issued-at timestamp',
      };
    }
    const activatedAtMs = Math.max(1, Math.floor(Number(walletSessionIssuedAtSec) * 1000));
    return {
      ok: true,
      material: {
        kind: 'router_ab_ed25519_signing_worker_material_v1',
        account_public_key: stored.publicKey,
        x_server_base_b64u: xServerBaseB64u,
        signing_worker_material_handle: `ed25519-hss/${claims.relayerKeyId}/${claims.thresholdSessionId}`,
        activated_at_ms: activatedAtMs,
      },
    };
  }

  private validateRouterAbNormalSigningSessionPolicy(
    requested: RouterAbEd25519NormalSigningState | undefined,
  ): ParseResult<null> {
    return validateRouterAbNormalSigningServerPolicy({
      requested,
      policy: this.routerAbNormalSigningPolicy,
    });
  }

  private createThresholdEd25519HssCeremonyHandle(): string {
    return base64UrlEncode(randomBytes(18));
  }

  private cleanupExpiredThresholdEd25519HssCeremonies(nowMs = Date.now()): void {
    for (const [handle, record] of this.ed25519HssCeremonyStore.entries()) {
      if (record.expiresAtMs <= nowMs) {
        this.releaseThresholdEd25519HssCeremonyResources(record);
        this.ed25519HssCeremonyStore.delete(handle);
      }
    }
  }

  private storeThresholdEd25519HssCeremony(record: ThresholdEd25519HssCeremonyRecordInput): string {
    const nowMs = Date.now();
    this.cleanupExpiredThresholdEd25519HssCeremonies(nowMs);
    const handle = this.createThresholdEd25519HssCeremonyHandle();
    this.ed25519HssCeremonyStore.set(handle, {
      ...record,
      expiresAtMs: nowMs + this.ed25519HssCeremonyTtlMs,
    });
    return handle;
  }

  private getThresholdEd25519HssCeremony(
    handleRaw: unknown,
  ): ParseResult<ThresholdEd25519HssCeremonyRecord> {
    const handle = toOptionalTrimmedString(handleRaw);
    if (!handle) {
      return { ok: false, code: 'invalid_body', message: 'ceremonyHandle is required' };
    }
    this.cleanupExpiredThresholdEd25519HssCeremonies();
    const record = this.ed25519HssCeremonyStore.get(handle);
    if (!record) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'ceremonyHandle is invalid or expired',
      };
    }
    return { ok: true, value: record };
  }

  private deleteThresholdEd25519HssCeremony(handleRaw: unknown): void {
    const handle = toOptionalTrimmedString(handleRaw);
    if (!handle) return;
    const record = this.ed25519HssCeremonyStore.get(handle);
    if (record) {
      this.releaseThresholdEd25519HssCeremonyResources(record);
    }
    this.ed25519HssCeremonyStore.delete(handle);
  }

  private releaseThresholdEd25519HssCeremonyResources(
    record: ThresholdEd25519HssCeremonyRecord,
  ): void {
    clearThresholdEd25519HssStoredServerInputs(record.serverInputs);
    releaseThresholdEd25519HssStagedEvaluatorArtifact(
      record.evaluationResult?.stagedEvaluatorArtifactHandle,
    );
    releaseThresholdEd25519HssPreparedServerSession(
      record.preparedServerSession.preparedSessionHandle,
    );
  }

  private takeThresholdEd25519HssCeremony(
    handleRaw: unknown,
  ): ParseResult<ThresholdEd25519HssCeremonyRecord> {
    const handle = toOptionalTrimmedString(handleRaw);
    if (!handle) {
      return { ok: false, code: 'invalid_body', message: 'ceremonyHandle is required' };
    }
    this.cleanupExpiredThresholdEd25519HssCeremonies();
    const record = this.ed25519HssCeremonyStore.get(handle);
    if (!record) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'ceremonyHandle is invalid or expired',
      };
    }
    this.ed25519HssCeremonyStore.delete(handle);
    return { ok: true, value: record };
  }

  private resolveFixedEcdsaSigningRoot(): EcdsaSigningRootReference | null {
    const fixedScope: FixedSigningRootScope | undefined =
      this.signingRootShareResolver?.fixedSigningRootScope;
    if (!fixedScope) return null;
    return createEcdsaSigningRootReference({
      signingRootId: fixedScope.signingRootId,
      signingRootVersion: fixedScope.signingRootVersion,
    });
  }

  private resolveEcdsaSigningRootFromScopeOrFixed(
    scope: unknown,
  ): EcdsaSigningRootReference | null {
    const scopedSigningRoot = resolveEcdsaSigningRootFromScope(scope);
    if (scopedSigningRoot) return scopedSigningRoot;
    return this.resolveFixedEcdsaSigningRoot();
  }

  private async deriveThresholdEcdsaHssYRelayerForContext(input: {
    hssContext: {
      walletId: string;
      rpId: string;
      ecdsaThresholdKeyId: string;
      signingRootId: string;
      signingRootVersion: string;
      keyPurpose: string;
      keyVersion: string;
    };
    signingRootMetadata: ThresholdEcdsaSigningRootMetadata;
  }): Promise<ParseResult<Uint8Array>> {
    if (!this.signingRootShareResolver) {
      return {
        ok: false,
        code: 'not_configured',
        message: 'threshold-ecdsa requires a signing-root share resolver',
      };
    }

    const derived = await deriveEcdsaHssYRelayerFromSigningRootShareResolver({
      signingRootId: input.signingRootMetadata.signingRootId,
      ...(input.signingRootMetadata.signingRootVersion
        ? { signingRootVersion: input.signingRootMetadata.signingRootVersion }
        : {}),
      resolver: this.signingRootShareResolver,
      context: input.hssContext,
    });
    if (!derived.ok) {
      return {
        ok: false,
        code: derived.code,
        message: `threshold-prf signing-root derivation failed: ${derived.message}`,
      };
    }
    return { ok: true, value: derived.value };
  }

  getSchemeModule(schemeId: ThresholdSchemeId): ThresholdAnySchemeModule | null {
    if (!this.cachedSchemeModules) this.cachedSchemeModules = {};
    const existing = this.cachedSchemeModules[schemeId];
    if (existing) return existing;

    const created: ThresholdAnySchemeModule | null = (() => {
      if (schemeId === THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
        return createThresholdEd25519Frost2pSchemeModule({
          registrationKeygenFromRegistrationMaterial: (request) =>
            this.ed25519RegistrationKeygenFromRegistrationMaterial(request),
          session: (request) => this.ed25519Session(request),
          protocol: {
            internalCosignInit: (request) =>
              this.signingHandlers.thresholdEd25519CosignInit(request),
            internalCosignFinalize: (request) =>
              this.signingHandlers.thresholdEd25519CosignFinalize(request),
          },
        });
      }
      if (schemeId === THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID) {
        return createThresholdSecp256k1Ecdsa2pSchemeModule({
          poolFill: {
            init: (input) =>
              this.routerAbEcdsaHssPoolFillHandlers.routerAbEcdsaHssPresignaturePoolFillInit(input),
            step: (input) =>
              this.routerAbEcdsaHssPoolFillHandlers.routerAbEcdsaHssPresignaturePoolFillStep(input),
          },
          protocol: {},
        });
      }
      return null;
    })();

    if (!created) return null;
    this.cachedSchemeModules[schemeId] = created;
    return created;
  }

  private async resolveRelayerKeyMaterial(input: { relayerKeyId: string }): Promise<
    | {
        ok: true;
        publicKey: string;
        relayerSigningShareB64u: string;
        relayerVerifyingShareB64u: string;
      }
    | { ok: false; code: string; message: string }
  > {
    const startedAt = Date.now();
    const resolved = await resolveThresholdEd25519RelayerKeyMaterial({
      relayerKeyId: input.relayerKeyId,
      keyStore: this.keyStore,
    });
    const durationMs = Date.now() - startedAt;
    if (!resolved.ok) {
      if (resolved.code === 'missing_key') {
        this.logger?.warn?.('[threshold-ed25519] relayer share cache miss', {
          relayerKeyId: input.relayerKeyId,
          durationMs,
        });
      } else {
        this.logger?.error?.('[threshold-ed25519] relayer share cache lookup failed', {
          relayerKeyId: input.relayerKeyId,
          durationMs,
          code: resolved.code,
          message: resolved.message,
        });
      }
      return resolved;
    }
    this.logger?.debug?.('[threshold-ed25519] relayer share cache hit', {
      relayerKeyId: input.relayerKeyId,
      durationMs,
    });
    return resolved;
  }

  private async maybeRepairRelayerKeyMaterialFromSessionHssFinalize(input: {
    claims: ThresholdEd25519SessionClaims;
    context: ThresholdEd25519HssCanonicalContext;
    preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
    serverOutput: { contextBindingB64u: string; xRelayerBaseB64u: string };
  }): Promise<{ repaired: boolean }> {
    const relayerKeyId = toOptionalTrimmedString(input.claims.relayerKeyId);
    const nearAccountId = toOptionalTrimmedString(input.claims.walletId);
    const rpId = toOptionalTrimmedString(input.claims.rpId);
    const keyVersion = toOptionalTrimmedString(input.context.keyVersion);
    const relayerSigningShareB64u = toOptionalTrimmedString(input.serverOutput.xRelayerBaseB64u);
    if (!relayerKeyId || !nearAccountId || !rpId || !keyVersion || !relayerSigningShareB64u) {
      throw new Error('[threshold-ed25519] missing scope while attempting relayer share self-heal');
    }

    const startedAt = Date.now();
    try {
      const relayerVerifyingShare = await deriveThresholdEd25519VerifyingShareFromSigningShare({
        signingShareB64u: relayerSigningShareB64u,
      });
      const relayerVerifyingShareB64u = toOptionalTrimmedString(
        relayerVerifyingShare.verifyingShareB64u,
      );
      if (!relayerVerifyingShareB64u) {
        throw new Error('[threshold-ed25519] relayer share self-heal produced no verifying share');
      }

      const repairedRecord: ThresholdEd25519KeyRecord = {
        nearAccountId,
        rpId,
        publicKey: relayerKeyId,
        relayerSigningShareB64u,
        relayerVerifyingShareB64u,
        keyVersion,
        recoveryExportCapable: true,
      };

      const existing = await this.keyStore.get(relayerKeyId);
      if (existing) {
        if (
          existing.nearAccountId !== nearAccountId ||
          existing.rpId !== rpId ||
          existing.publicKey !== relayerKeyId
        ) {
          throw new Error(
            '[threshold-ed25519] relayer share self-heal refused conflicting key identity',
          );
        }
        const existingSigningShareB64u = toOptionalTrimmedString(
          existing.relayerSigningShareB64u,
        );
        const existingVerifyingShareB64u = toOptionalTrimmedString(
          existing.relayerVerifyingShareB64u,
        );
        if (!existingSigningShareB64u || !existingVerifyingShareB64u) {
          throw new Error(
            '[threshold-ed25519] relayer share self-heal refused incomplete existing key material',
          );
        }
        const derivedExistingVerifyingShare =
          await deriveThresholdEd25519VerifyingShareFromSigningShare({
            signingShareB64u: existingSigningShareB64u,
          });
        if (
          toOptionalTrimmedString(derivedExistingVerifyingShare.verifyingShareB64u) !==
          existingVerifyingShareB64u
        ) {
          throw new Error(
            '[threshold-ed25519] relayer share self-heal refused corrupted existing key material',
          );
        }
        if (
          existing.relayerSigningShareB64u === repairedRecord.relayerSigningShareB64u &&
          existing.relayerVerifyingShareB64u === repairedRecord.relayerVerifyingShareB64u &&
          existing.keyVersion === repairedRecord.keyVersion &&
          existing.recoveryExportCapable === repairedRecord.recoveryExportCapable
        ) {
          return { repaired: false };
        }
        throw new Error(
          '[threshold-ed25519] relayer share self-heal refused conflicting existing key material',
        );
      }

      await this.keyStore.put(relayerKeyId, repairedRecord);
      this.logger?.warn?.('[threshold-ed25519] relayer share self-heal', {
        relayerKeyId,
        nearAccountId,
        rpId,
        keyVersion,
        durationMs: Date.now() - startedAt,
        outcome: 'created_missing',
      });
      return { repaired: true };
    } catch (error: unknown) {
      this.logger?.error?.('[threshold-ed25519] relayer share self-heal failed', {
        relayerKeyId,
        nearAccountId,
        rpId,
        keyVersion,
        durationMs: Date.now() - startedAt,
        outcome: 'failure',
        message: errorMessage(error),
      });
      throw error;
    }
  }

  private clampSessionPolicy(input: { ttlMs: number; remainingUses: number }): {
    ttlMs: number;
    remainingUses: number;
  } {
    const ttlMs = Math.max(0, Math.floor(Number(input.ttlMs) || 0));
    const remainingUses = Math.max(0, Math.floor(Number(input.remainingUses) || 0));
    // Hard caps (server-side). Must stay aligned with client-side policy clamping
    // to keep sessionPolicyDigest32 challenge binding deterministic.
    const MAX_TTL_MS = 30 * 24 * 60 * 60_000; // 30 days
    const MAX_USES = 1_000_000;
    return {
      ttlMs: Math.min(ttlMs, MAX_TTL_MS),
      remainingUses: Math.min(remainingUses, MAX_USES),
    };
  }

  private async computeSessionPolicyDigest32(policy: unknown): Promise<Uint8Array> {
    const json = alphabetizeStringify(policy);
    return await sha256BytesUtf8(json);
  }

  private async putWalletSessionRecord(input: {
    store: Ed25519WalletSessionStore;
    sessionId: string;
    record: Ed25519WalletSessionRecord;
    ttlMs: number;
    remainingUses: number;
  }): Promise<void> {
    await input.store.putSession(input.sessionId, input.record, {
      ttlMs: input.ttlMs,
      remainingUses: input.remainingUses,
    });
  }

  private toThresholdEcdsaWalletSessionRecord(
    record: Ed25519WalletSessionRecord,
  ): ThresholdEcdsaWalletSessionRecord {
    return {
      expiresAtMs: record.expiresAtMs,
      relayerKeyId: record.relayerKeyId,
      walletSessionUserId: record.userId,
      rpId: record.rpId,
      participantIds: record.participantIds,
      ...(record.signingRootId ? { signingRootId: record.signingRootId } : {}),
      ...(record.signingRootVersion ? { signingRootVersion: record.signingRootVersion } : {}),
      ...(record.walletKeyVersion ? { walletKeyVersion: record.walletKeyVersion } : {}),
      ...(typeof record.derivationVersion === 'number'
        ? { derivationVersion: record.derivationVersion }
        : {}),
    };
  }

  private async getEcdsaWalletSession(
    sessionId: string,
  ): Promise<ThresholdEcdsaWalletSessionRecord | null> {
    const record = await this.ecdsaWalletSessionStore.getSession(sessionId);
    return record ? this.toThresholdEcdsaWalletSessionRecord(record) : null;
  }

  private async putEcdsaWalletSessionRecord(input: {
    sessionId: string;
    record: ThresholdEcdsaWalletSessionRecord;
    ttlMs: number;
    remainingUses: number;
  }): Promise<void> {
    await this.putWalletSessionRecord({
      store: this.ecdsaWalletSessionStore,
      sessionId: input.sessionId,
      record: {
        expiresAtMs: input.record.expiresAtMs,
        relayerKeyId: input.record.relayerKeyId,
        userId: input.record.walletSessionUserId,
        rpId: input.record.rpId,
        participantIds: input.record.participantIds,
        ...(input.record.signingRootId ? { signingRootId: input.record.signingRootId } : {}),
        ...(input.record.signingRootVersion
          ? { signingRootVersion: input.record.signingRootVersion }
          : {}),
        ...(input.record.walletKeyVersion
          ? { walletKeyVersion: input.record.walletKeyVersion }
          : {}),
        ...(typeof input.record.derivationVersion === 'number'
          ? { derivationVersion: input.record.derivationVersion }
          : {}),
      },
      ttlMs: input.ttlMs,
      remainingUses: input.remainingUses,
    });
  }

  private toThresholdEcdsaMpcSessionRecord(
    record: ThresholdEd25519MpcSessionRecord,
  ): ThresholdEcdsaMpcSessionRecord {
    return {
      expiresAtMs: record.expiresAtMs,
      ...(record.ecdsaThresholdKeyId ? { ecdsaThresholdKeyId: record.ecdsaThresholdKeyId } : {}),
      ...(record.keyHandle ? { keyHandle: record.keyHandle } : {}),
      relayerKeyId: record.relayerKeyId,
      purpose: record.purpose,
      intentDigestB64u: record.intentDigestB64u,
      signingDigestB64u: record.signingDigestB64u,
      walletSessionUserId: record.userId,
      rpId: record.rpId,
      ...(record.clientVerifyingShareB64u
        ? { clientVerifyingShareB64u: record.clientVerifyingShareB64u }
        : {}),
      participantIds: record.participantIds,
      ...(record.signingRootId ? { signingRootId: record.signingRootId } : {}),
      ...(record.signingRootVersion ? { signingRootVersion: record.signingRootVersion } : {}),
      ...(record.walletKeyVersion ? { walletKeyVersion: record.walletKeyVersion } : {}),
      ...(typeof record.derivationVersion === 'number'
        ? { derivationVersion: record.derivationVersion }
        : {}),
    };
  }

  private async putEcdsaMpcSession(
    sessionId: string,
    record: ThresholdEcdsaMpcSessionRecord,
    ttlMs: number,
  ): Promise<void> {
    await this.ecdsaSessionStore.putMpcSession(
      sessionId,
      {
        expiresAtMs: record.expiresAtMs,
        ...(record.ecdsaThresholdKeyId ? { ecdsaThresholdKeyId: record.ecdsaThresholdKeyId } : {}),
        ...(record.keyHandle ? { keyHandle: record.keyHandle } : {}),
        relayerKeyId: record.relayerKeyId,
        purpose: record.purpose,
        intentDigestB64u: record.intentDigestB64u,
        signingDigestB64u: record.signingDigestB64u,
        userId: record.walletSessionUserId,
        rpId: record.rpId,
        ...(record.clientVerifyingShareB64u
          ? { clientVerifyingShareB64u: record.clientVerifyingShareB64u }
          : {}),
        participantIds: record.participantIds,
        ...(record.signingRootId ? { signingRootId: record.signingRootId } : {}),
        ...(record.signingRootVersion ? { signingRootVersion: record.signingRootVersion } : {}),
        ...(record.walletKeyVersion ? { walletKeyVersion: record.walletKeyVersion } : {}),
        ...(typeof record.derivationVersion === 'number'
          ? { derivationVersion: record.derivationVersion }
          : {}),
      },
      ttlMs,
    );
  }

  private async readEcdsaMpcSession(
    sessionId: string,
  ): Promise<{ record: ThresholdEcdsaMpcSessionRecord; version: string } | null> {
    const result = await this.ecdsaSessionStore.readMpcSession(sessionId);
    return result
      ? {
          record: this.toThresholdEcdsaMpcSessionRecord(result.record),
          version: result.version,
        }
      : null;
  }

  private async claimEcdsaMpcSession(
    sessionId: string,
    version: string,
  ): Promise<
    | { ok: true; record: ThresholdEcdsaMpcSessionRecord }
    | { ok: false; code: 'not_found' | 'expired' | 'version_mismatch' | 'invalid_record' }
  > {
    const result = await this.ecdsaSessionStore.claimMpcSession(sessionId, version);
    return result.ok
      ? { ok: true, record: this.toThresholdEcdsaMpcSessionRecord(result.record) }
      : result;
  }

  private walletSigningBudgetSessionId(input: {
    signingGrantId: string;
    binding: {
      curve: 'ed25519' | 'ecdsa';
      thresholdSessionId: string;
    };
  }): string {
    void input.binding;
    return walletSigningBudgetSessionId(input.signingGrantId);
  }

  private async ensureSigningGrantBudget(input: {
    signingGrantId: string;
    binding: {
      curve: 'ed25519' | 'ecdsa';
      thresholdSessionId: string;
    };
    userId: string;
    rpId: string;
    participantIds: number[];
    ttlMs: number;
    remainingUses: number;
    refreshExisting?: boolean;
  }): Promise<
    | { ok: true; expiresAtMs: number; participantIds: number[] }
    | { ok: false; code: string; message: string }
  > {
    const binding = {
      curve: input.binding.curve,
      thresholdSessionId: toOptionalTrimmedString(input.binding.thresholdSessionId) || '',
    };
    const sessionId = this.walletSigningBudgetSessionId({
      signingGrantId: input.signingGrantId,
      binding,
    });
    if (!binding.thresholdSessionId) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'wallet signing-session budget binding thresholdSessionId is required',
      };
    }
    if (!sessionId) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'signingGrantId is required',
      };
    }
    const existingSession = await this.walletSessionStore.getSession(sessionId);
    if (existingSession) {
      if (existingSession.userId !== input.userId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'signingGrantId already exists for a different user',
        };
      }
      if (existingSession.rpId !== input.rpId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'signingGrantId already exists for a different rpId',
        };
      }
      const sameParticipantIds =
        existingSession.participantIds.length === input.participantIds.length &&
        existingSession.participantIds.every((id, i) => id === input.participantIds[i]);
      if (!sameParticipantIds) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'signingGrantId already exists for a different participant set',
        };
      }
      if (!input.refreshExisting) {
        return {
          ok: true,
          expiresAtMs: existingSession.expiresAtMs,
          participantIds: existingSession.participantIds,
        };
      }
      const expiresAtMs = Date.now() + input.ttlMs;
      // Only mint paths that prove fresh wallet auth can refresh an exhausted
      // wallet budget. Threshold-session-authorized ECDSA bootstraps cannot
      // refill the shared budget by presenting an old JWT.
      await this.putWalletSessionRecord({
        store: this.walletSessionStore,
        sessionId,
        record: {
          expiresAtMs,
          relayerKeyId: WALLET_SIGNING_BUDGET_RELAYER_KEY_ID,
          userId: input.userId,
          rpId: input.rpId,
          participantIds: input.participantIds,
        },
        ttlMs: input.ttlMs,
        remainingUses: input.remainingUses,
      });
      return {
        ok: true,
        expiresAtMs,
        participantIds: existingSession.participantIds,
      };
    }

    const expiresAtMs = Date.now() + input.ttlMs;
    await this.putWalletSessionRecord({
      store: this.walletSessionStore,
      sessionId,
      record: {
        expiresAtMs,
        relayerKeyId: WALLET_SIGNING_BUDGET_RELAYER_KEY_ID,
        userId: input.userId,
        rpId: input.rpId,
        participantIds: input.participantIds,
      },
      ttlMs: input.ttlMs,
      remainingUses: input.remainingUses,
    });
    return { ok: true, expiresAtMs, participantIds: input.participantIds };
  }

  private async consumeWalletOrCurveSessionUse(input: {
    signingGrantId?: string;
    curve: 'ed25519' | 'ecdsa';
    curveSessionId: string;
    curveStore: Ed25519WalletSessionStore;
    idempotencyKey?: string;
  }): Promise<WalletSessionConsumeUsesResult> {
    const walletBudgetSessionId = this.walletSigningBudgetSessionId({
      signingGrantId: input.signingGrantId || '',
      binding: {
        curve: input.curve,
        thresholdSessionId: input.curveSessionId,
      },
    });
    const idempotencyKey = toOptionalTrimmedString(input.idempotencyKey);
    if (walletBudgetSessionId) {
      const walletBudgetSession = await this.walletSessionStore.getSession(walletBudgetSessionId);
      const curveSession = await input.curveStore.getSession(input.curveSessionId);
      if (
        !walletBudgetSession ||
        !curveSession ||
        walletBudgetSession.userId !== curveSession.userId ||
        walletBudgetSession.rpId !== curveSession.rpId ||
        walletBudgetSession.participantIds.length !== curveSession.participantIds.length ||
        !walletBudgetSession.participantIds.every(
          (id, index) => id === curveSession.participantIds[index],
        )
      ) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'wallet signing-session budget does not match this threshold session',
        };
      }
      if (idempotencyKey) {
        return await this.walletSessionStore.consumeUseCountOnce(
          walletBudgetSessionId,
          idempotencyKey,
        );
      }
      // Wallet budgets are shared across curves and runtimes. A consume
      // without an operation-derived idempotency key would reopen overspend
      // races at the authoritative server boundary.
      return {
        ok: false,
        code: 'internal',
        message: 'wallet signing-session budget consume requires an idempotency key',
      };
    }
    if (idempotencyKey) {
      return await input.curveStore.consumeUseCountOnce(input.curveSessionId, idempotencyKey);
    }
    return await input.curveStore.consumeUseCount(input.curveSessionId);
  }

  private async resolveWalletOrCurveBudgetStore(input: {
    signingGrantId?: string;
    curve: 'ed25519' | 'ecdsa';
    curveSessionId: string;
    curveStore: Ed25519WalletSessionStore;
  }): Promise<
    | { ok: true; budgetSessionId: string; store: Ed25519WalletSessionStore }
    | { ok: false; code: string; message: string }
  > {
    const walletBudgetSessionId = this.walletSigningBudgetSessionId({
      signingGrantId: input.signingGrantId || '',
      binding: {
        curve: input.curve,
        thresholdSessionId: input.curveSessionId,
      },
    });
    if (!walletBudgetSessionId) {
      return { ok: true, budgetSessionId: input.curveSessionId, store: input.curveStore };
    }
    const walletBudgetSession = await this.walletSessionStore.getSession(walletBudgetSessionId);
    const curveSession = await input.curveStore.getSession(input.curveSessionId);
    if (
      !walletBudgetSession ||
      !curveSession ||
      walletBudgetSession.userId !== curveSession.userId ||
      walletBudgetSession.rpId !== curveSession.rpId ||
      walletBudgetSession.participantIds.length !== curveSession.participantIds.length ||
      !walletBudgetSession.participantIds.every((id, index) => id === curveSession.participantIds[index])
    ) {
      return {
        ok: false,
        code: 'wallet_budget_forbidden',
        message: 'wallet signing-session budget does not match this threshold session',
      };
    }
    return { ok: true, budgetSessionId: walletBudgetSessionId, store: this.walletSessionStore };
  }

  private async hasConsumedWalletOrCurveSessionUse(input: {
    signingGrantId?: string;
    curve: 'ed25519' | 'ecdsa';
    curveSessionId: string;
    curveStore: Ed25519WalletSessionStore;
    idempotencyKey: string;
  }): Promise<{ ok: true; consumed: boolean } | { ok: false; code: string; message: string }> {
    const idempotencyKey = toOptionalTrimmedString(input.idempotencyKey);
    if (!idempotencyKey) return { ok: true, consumed: false };
    const walletBudgetSessionId = this.walletSigningBudgetSessionId({
      signingGrantId: input.signingGrantId || '',
      binding: {
        curve: input.curve,
        thresholdSessionId: input.curveSessionId,
      },
    });
    if (walletBudgetSessionId) {
      const walletBudgetSession = await this.walletSessionStore.getSession(walletBudgetSessionId);
      const curveSession = await input.curveStore.getSession(input.curveSessionId);
      if (
        !walletBudgetSession ||
        !curveSession ||
        walletBudgetSession.userId !== curveSession.userId ||
        walletBudgetSession.rpId !== curveSession.rpId ||
        walletBudgetSession.participantIds.length !== curveSession.participantIds.length ||
        !walletBudgetSession.participantIds.every(
          (id, index) => id === curveSession.participantIds[index],
        )
      ) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'wallet signing-session budget does not match this threshold session',
        };
      }
      return await this.walletSessionStore.hasConsumedUseCountOnce(
        walletBudgetSessionId,
        idempotencyKey,
      );
    }
    return await input.curveStore.hasConsumedUseCountOnce(input.curveSessionId, idempotencyKey);
  }

  private createRouterAbEcdsaHssPoolFillSessionId(): string {
    return `ecdsa-presign-${secureRandomIdFragment()}`;
  }

  private createThresholdEd25519SigningSessionId(): string {
    return `sign-${secureRandomIdFragment()}`;
  }

  private async resolveEd25519KeygenMaterial(input: {
    nearAccountId: string;
    rpId: string;
    keyVersion: string;
    recoveryExportCapable: true;
    publicKey: string;
    relayerSigningShareB64u: string;
    relayerVerifyingShareB64u: string;
  }): Promise<
    | { ok: true; keyMaterial: ThresholdEd25519KeygenMaterial }
    | { ok: false; code: string; message: string }
  > {
    const keyVersion = toOptionalTrimmedString(input.keyVersion);
    const publicKey = toOptionalTrimmedString(input.publicKey);
    const relayerSigningShareB64u = toOptionalTrimmedString(input.relayerSigningShareB64u);
    const relayerVerifyingShareB64u = toOptionalTrimmedString(input.relayerVerifyingShareB64u);

    if (!keyVersion || !publicKey || !relayerSigningShareB64u || !relayerVerifyingShareB64u) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'threshold-ed25519 keygen requires complete registration material',
      };
    }

    return await this.keygenStrategy.keygenFromRegistrationMaterial({
      keyVersion,
      publicKey,
      relayerSigningShareB64u,
      relayerVerifyingShareB64u,
      recoveryExportCapable: true,
    });
  }

  private async resolveStoredEd25519KeygenMaterial(input: {
    nearAccountId: string;
    rpId: string;
    relayerKeyId: string;
    keyVersion: string;
    recoveryExportCapable: true;
    publicKey: string;
  }): Promise<
    | { ok: true; keyMaterial: ThresholdEd25519KeygenMaterial }
    | { ok: false; code: string; message: string }
  > {
    const nearAccountId = toOptionalTrimmedString(input.nearAccountId);
    const rpId = toOptionalTrimmedString(input.rpId);
    const relayerKeyId = toOptionalTrimmedString(input.relayerKeyId);
    const keyVersion = toOptionalTrimmedString(input.keyVersion);
    const publicKey = toOptionalTrimmedString(input.publicKey);
    if (!nearAccountId || !rpId || !relayerKeyId || !keyVersion || !publicKey) {
      return {
        ok: false,
        code: 'invalid_body',
        message:
          'threshold-ed25519 registration requires relayerKeyId, publicKey, and key metadata',
      };
    }
    const stored = await this.keyStore.get(relayerKeyId);
    if (!stored) {
      return {
        ok: false,
        code: 'not_found',
        message: 'threshold-ed25519 registration material was not prepared on the relay',
      };
    }
    if (
      stored.nearAccountId !== nearAccountId ||
      stored.rpId !== rpId ||
      stored.publicKey !== publicKey ||
      stored.keyVersion !== keyVersion ||
      stored.recoveryExportCapable !== true
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'threshold-ed25519 registration material does not match the prepared relay state',
      };
    }

    return await this.resolveEd25519KeygenMaterial({
      nearAccountId,
      rpId,
      keyVersion,
      recoveryExportCapable: true,
      publicKey,
      relayerSigningShareB64u: stored.relayerSigningShareB64u,
      relayerVerifyingShareB64u: stored.relayerVerifyingShareB64u,
    });
  }

  private async ed25519RegistrationKeygenFromRegistrationMaterial(
    input: ThresholdEd25519RegistrationKeygenRequest,
  ): Promise<ThresholdEd25519RegistrationKeygenResult> {
    try {
      await this.ensureReady();
      const nearAccountId = toOptionalTrimmedString(input.nearAccountId);
      if (!nearAccountId) {
        return { ok: false, code: 'invalid_body', message: 'nearAccountId is required' };
      }
      const rpId = toOptionalTrimmedString(input.rpId);
      if (!rpId) {
        return { ok: false, code: 'invalid_body', message: 'rpId is required' };
      }
      const keyVersion = toOptionalTrimmedString((input as { keyVersion?: unknown }).keyVersion);
      const publicKey = toOptionalTrimmedString((input as { publicKey?: unknown }).publicKey);
      const relayerKeyId = toOptionalTrimmedString(
        (input as { relayerKeyId?: unknown }).relayerKeyId,
      );
      if (!keyVersion || !publicKey || !relayerKeyId) {
        return {
          ok: false,
          code: 'invalid_body',
          message:
            'threshold-ed25519 registration requires relayerKeyId, publicKey, and keyVersion',
        };
      }
      if ((input as { recoveryExportCapable?: unknown }).recoveryExportCapable !== true) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'recoveryExportCapable must be true',
        };
      }

      const keygen = await this.resolveStoredEd25519KeygenMaterial({
        nearAccountId,
        rpId,
        relayerKeyId,
        keyVersion,
        recoveryExportCapable: true,
        publicKey,
      });
      if (!keygen.ok) return keygen;
      const { keyMaterial } = keygen;

      await this.keyStore.put(keyMaterial.relayerKeyId, {
        nearAccountId,
        rpId,
        publicKey: keyMaterial.publicKey,
        relayerSigningShareB64u: keyMaterial.relayerSigningShareB64u,
        relayerVerifyingShareB64u: keyMaterial.relayerVerifyingShareB64u,
        keyVersion: keyMaterial.keyVersion,
        recoveryExportCapable: keyMaterial.recoveryExportCapable,
      });

      return {
        ok: true,
        clientParticipantId: this.clientParticipantId,
        relayerParticipantId: this.relayerParticipantId,
        participantIds: [...this.participantIds2p],
        relayerKeyId: keyMaterial.relayerKeyId,
        publicKey: keyMaterial.publicKey,
        keyVersion: keyMaterial.keyVersion,
        recoveryExportCapable: keyMaterial.recoveryExportCapable,
        relayerVerifyingShareB64u: keyMaterial.relayerVerifyingShareB64u,
      };
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Internal error',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async mintEd25519SessionFromRegistration(input: {
    nearAccountId: string;
    rpId: string;
    relayerKeyId: string;
    sessionPolicy: Ed25519SessionPolicy;
  }): Promise<ThresholdEd25519SessionResponse> {
    try {
      await this.ensureReady();

      const nearAccountId = toOptionalTrimmedString(input.nearAccountId);
      const rpId = toOptionalTrimmedString(input.rpId);
      const relayerKeyId = toOptionalTrimmedString(input.relayerKeyId);
      if (!nearAccountId || !rpId || !relayerKeyId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Missing required ed25519 session bootstrap inputs',
        };
      }

      const policy = (input.sessionPolicy || {}) as Ed25519SessionPolicy;
      const runtimePolicyScope = (() => {
        const raw = policy.runtimePolicyScope;
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
        try {
          return raw as RuntimePolicyScope;
        } catch {
          return undefined;
        }
      })();
      let routerAbNormalSigning: RouterAbEd25519NormalSigningState | undefined;
      if (Object.prototype.hasOwnProperty.call(policy, 'routerAbNormalSigning')) {
        try {
          const parsedRouterAbNormalSigning = parseRouterAbEd25519NormalSigningState(
            policy.routerAbNormalSigning,
          );
          if (!parsedRouterAbNormalSigning) {
            return {
              ok: false,
              code: 'invalid_body',
              message:
                'threshold_ed25519.session_policy.routerAbNormalSigning must be a Router A/B normal-signing state',
            };
          }
          routerAbNormalSigning = parsedRouterAbNormalSigning;
        } catch (error) {
          return {
            ok: false,
            code: 'invalid_body',
            message:
              error && typeof error === 'object' && 'message' in error
                ? String((error as { message?: unknown }).message)
                : 'threshold_ed25519.session_policy.routerAbNormalSigning is invalid',
          };
        }
      }
      const routerAbPolicy = this.validateRouterAbNormalSigningSessionPolicy(routerAbNormalSigning);
      if (!routerAbPolicy.ok) return routerAbPolicy;
      if (String(policy.version || '').trim() !== 'threshold_session_v1') {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy.version must be threshold_session_v1',
        };
      }
      if (String(policy.nearAccountId || '').trim() !== nearAccountId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy.nearAccountId mismatch',
        };
      }
      if (String(policy.rpId || '').trim() !== rpId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy.rpId mismatch',
        };
      }
      if (String(policy.relayerKeyId || '').trim() !== relayerKeyId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy.relayerKeyId mismatch',
        };
      }

      const sessionId = String(policy.sessionId || '').trim();
      if (!sessionId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy.sessionId is required',
        };
      }
      const signingGrantId =
        String(policy.signingGrantId || '').trim() || sessionId;

      const { ttlMs, remainingUses } = this.clampSessionPolicy({
        ttlMs: Number(policy.ttlMs),
        remainingUses: Number(policy.remainingUses),
      });
      if (ttlMs <= 0 || remainingUses <= 0) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy ttlMs/remainingUses must be positive',
        };
      }

      const participantIds = normalizeThresholdEd25519ParticipantIds(policy.participantIds) || [
        ...this.participantIds2p,
      ];
      if (participantIds.length < 2) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy.participantIds must contain at least 2 ids',
        };
      }
      for (const id of this.participantIds2p) {
        if (!participantIds.includes(id)) {
          return {
            ok: false,
            code: 'unauthorized',
            message: `threshold_ed25519.session_policy.participantIds must include server signer set (expected to include participantIds=[${this.participantIds2p.join(',')}])`,
          };
        }
      }

      const relayerKey = await this.resolveRelayerKeyMaterial({
        relayerKeyId,
      });
      if (!relayerKey.ok) {
        return { ok: false, code: relayerKey.code, message: relayerKey.message };
      }

      const existingSession = await this.walletSessionStore.getSession(sessionId);
      if (existingSession) {
        if (existingSession.userId !== nearAccountId) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'threshold sessionId already exists for a different user',
          };
        }
        if (existingSession.relayerKeyId !== relayerKeyId) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'threshold sessionId already exists for a different relayerKeyId',
          };
        }
        if (existingSession.rpId !== rpId) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'threshold sessionId already exists for a different rpId',
          };
        }
        const sameParticipantIds =
          existingSession.participantIds.length === participantIds.length &&
          existingSession.participantIds.every((id, i) => id === participantIds[i]);
        if (!sameParticipantIds) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'threshold sessionId already exists for a different participant set',
          };
        }
        const walletBudget = await this.ensureSigningGrantBudget({
          signingGrantId,
          binding: { curve: 'ed25519', thresholdSessionId: sessionId },
          userId: nearAccountId,
          rpId,
          participantIds: existingSession.participantIds,
          ttlMs,
          remainingUses,
          refreshExisting: false,
        });
        if (!walletBudget.ok) return walletBudget;
        return {
          ok: true,
          sessionId,
          signingGrantId,
          expiresAtMs: walletBudget.expiresAtMs,
          expiresAt: new Date(walletBudget.expiresAtMs).toISOString(),
          participantIds: walletBudget.participantIds,
          ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
          ...(routerAbNormalSigning ? { routerAbNormalSigning } : {}),
        };
      }

      const scope = await ensureRelayerKeyIsActiveAccessKey({
        nearAccountId,
        relayerPublicKey: relayerKey.publicKey,
        viewAccessKeyList: this.viewAccessKeyList,
        maxAttempts: 6,
        initialDelayMs: 60,
      });
      if (!scope.ok) {
        return { ok: false, code: scope.code, message: scope.message };
      }

      const expiresAtMs = Date.now() + ttlMs;
      await this.putWalletSessionRecord({
        store: this.walletSessionStore,
        sessionId,
        record: {
          expiresAtMs,
          relayerKeyId,
          userId: nearAccountId,
          rpId,
          participantIds,
        },
        ttlMs,
        remainingUses,
      });
      const walletBudget = await this.ensureSigningGrantBudget({
        signingGrantId,
        binding: { curve: 'ed25519', thresholdSessionId: sessionId },
        userId: nearAccountId,
        rpId,
        participantIds,
        ttlMs,
        remainingUses,
        refreshExisting: true,
      });
      if (!walletBudget.ok) return walletBudget;

      return {
        ok: true,
        sessionId,
        signingGrantId,
        expiresAtMs: walletBudget.expiresAtMs,
        expiresAt: new Date(walletBudget.expiresAtMs).toISOString(),
        participantIds: walletBudget.participantIds,
        remainingUses,
        ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
        ...(routerAbNormalSigning ? { routerAbNormalSigning } : {}),
      };
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Internal error',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async getEcdsaKeyIdentityMetadata(input: {
    walletId: string;
    rpId: string;
    keySelector: ThresholdEcdsaKeyHandleSelector;
  }): Promise<ThresholdEcdsaKeyIdentityMetadata | null> {
    const walletId = toOptionalTrimmedString(input.walletId);
    const rpId = toOptionalTrimmedString(input.rpId);
    if (!walletId || !rpId) return null;
    const record = await this.ecdsaKeyStore.getRoleLocalByKeyHandle(input.keySelector.keyHandle);
    if (!record) return null;
    const keyHandle = toOptionalTrimmedString(record.keyHandle);
    if (keyHandle !== input.keySelector.keyHandle) return null;
    if (record.walletId !== walletId || record.rpId !== rpId) {
      return null;
    }
    const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
    const recordOwnerAddress = toOptionalTrimmedString(record.ethereumAddress);
    if (!relayerKeyId || !recordOwnerAddress) return null;
    const thresholdOwnerAddress = recordOwnerAddress.toLowerCase();
    return {
      walletId: record.walletId,
      rpId: record.rpId,
      keyScope: 'evm-family',
      keyHandle,
      ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
      relayerKeyId,
      signingRootId: record.signingRootId,
      signingRootVersion: record.signingRootVersion,
      participantIds: [...this.participantIds2p],
      thresholdOwnerAddress,
      thresholdEcdsaPublicKeyB64u: record.groupPublicKey33B64u,
    };
  }

  async verifyEcdsaSigningRootWalletAddress(input: {
    signingRootId: string;
    signingRootVersion: string;
    walletId: string;
    chainTarget: ThresholdEcdsaChainTarget;
    ecdsaThresholdKeyId: string;
    rpId: string;
    clientPublicKey33B64u: string;
    expectedEthereumAddress?: string;
    walletKeyVersion?: string;
  }): Promise<
    | {
        ok: true;
        verified: boolean;
        signingRootId: string;
        signingRootVersion: string;
        walletId: string;
        rpId: string;
        walletKeyVersion: string;
        canonicalPublicKeyHex: string;
        canonicalEthereumAddress: string;
        expectedEthereumAddress?: string;
      }
    | { ok: false; code: string; message: string }
  > {
    const signingRootId = toOptionalTrimmedString(input.signingRootId);
    const signingRootVersion = toOptionalTrimmedString(input.signingRootVersion);
    const walletId = toOptionalTrimmedString(input.walletId);
    const chainTarget = input.chainTarget;
    const ecdsaThresholdKeyId = toOptionalTrimmedString(input.ecdsaThresholdKeyId);
    const rpId = toOptionalTrimmedString(input.rpId);
    const walletKeyVersion =
      toOptionalTrimmedString(input.walletKeyVersion) || THRESHOLD_ECDSA_HSS_KEY_VERSION_V1;
    if (!signingRootId || !signingRootVersion || !walletId || !ecdsaThresholdKeyId || !rpId) {
      return {
        ok: false,
        code: 'invalid_body',
        message:
          'signingRootId, signingRootVersion, walletId, chainTarget, ecdsaThresholdKeyId, and rpId are required',
      };
    }
    if (!this.signingRootShareResolver) {
      return {
        ok: false,
        code: 'not_configured',
        message: 'threshold-ecdsa wallet verification requires a signing-root share resolver',
      };
    }

    const parsedClientPublicKey = await this.parseCompressedSecp256k1PublicKeyB64u({
      fieldName: 'clientPublicKey33B64u',
      value: input.clientPublicKey33B64u,
    });
    if (!parsedClientPublicKey.ok) return parsedClientPublicKey;
    const clientPublicKey33 = base64UrlDecode(parsedClientPublicKey.value);

    const expectedEthereumAddress = toOptionalTrimmedString(input.expectedEthereumAddress);
    let yRelayer32Le: Uint8Array | null = null;
    try {
      const signingRootMetadata = createEcdsaSigningRootMetadata(signingRootId, signingRootVersion);
      const hssContext = {
        walletId,
        rpId,
        ecdsaThresholdKeyId,
        signingRootId,
        signingRootVersion: canonicalEcdsaHssSigningRootVersion(signingRootVersion),
        keyPurpose: THRESHOLD_ECDSA_HSS_KEY_PURPOSE_V1,
        keyVersion: walletKeyVersion,
      };
      const derived = await this.deriveThresholdEcdsaHssYRelayerForContext({
        hssContext,
        signingRootMetadata,
      });
      if (!derived.ok) return derived;
      yRelayer32Le = derived.value;

      const relayerPublicKey33 = await secp256k1PrivateKey32ToPublicKey33(yRelayer32Le);
      const groupPublicKey33 = await addSecp256k1PublicKeys33({
        left33: clientPublicKey33,
        right33: relayerPublicKey33,
      });
      const canonicalEthereumAddress =
        await secp256k1PublicKey33ToEthereumAddress(groupPublicKey33);
      const normalizedExpected = expectedEthereumAddress?.toLowerCase();
      return {
        ok: true,
        verified: normalizedExpected ? canonicalEthereumAddress === normalizedExpected : true,
        signingRootId,
        signingRootVersion,
        walletId,
        rpId,
        walletKeyVersion,
        canonicalPublicKeyHex: bytesToLowerHex(groupPublicKey33),
        canonicalEthereumAddress,
        ...(expectedEthereumAddress ? { expectedEthereumAddress } : {}),
      };
    } finally {
      yRelayer32Le?.fill(0);
    }
  }

  private async parseCompressedSecp256k1PublicKeyB64u(input: {
    value: string;
    fieldName: string;
  }): Promise<ParseResult<string>> {
    let publicKey33: Uint8Array;
    try {
      publicKey33 = base64UrlDecode(input.value);
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: `${input.fieldName} must be valid base64url`,
      };
    }
    if (publicKey33.length !== 33) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `${input.fieldName} must decode to 33 bytes (compressed secp256k1 pubkey)`,
      };
    }
    try {
      await validateSecp256k1PublicKey33(publicKey33);
    } catch (e: unknown) {
      const runtimeMessage = errorMessage(e);
      if (isEthSignerWasmRuntimeError(runtimeMessage)) {
        return {
          ok: false,
          code: 'internal',
          message: runtimeMessage || 'eth_signer WASM runtime error',
        };
      }
      return {
        ok: false,
        code: 'invalid_body',
        message: `${input.fieldName} is not a valid secp256k1 public key`,
      };
    }
    return { ok: true, value: input.value };
  }

  private async ecdsaMintSessionWithoutWebAuthn(input: {
    relayerKeyId: string;
    clientVerifyingShareB64u: string;
    walletSessionUserId: string;
    rpId: string;
    sessionId: string;
    signingGrantId: string;
    ttlMsRaw: number;
    remainingUsesRaw: number;
    policyParticipantIds: number[] | null;
    signingRootMetadata: ThresholdEcdsaSigningRootMetadata;
    refreshExistingWalletBudget?: boolean;
  }): Promise<ThresholdEcdsaBootstrapSessionResult> {
    const {
      relayerKeyId,
      clientVerifyingShareB64u,
      walletSessionUserId,
      rpId,
      sessionId,
      signingGrantId,
      ttlMsRaw,
      remainingUsesRaw,
      policyParticipantIds,
      signingRootMetadata,
      refreshExistingWalletBudget,
    } = input;

    const parsedClientVerifyingShare = await this.parseCompressedSecp256k1PublicKeyB64u({
      value: clientVerifyingShareB64u,
      fieldName: 'clientVerifyingShareB64u',
    });
    if (!parsedClientVerifyingShare.ok) {
      return parsedClientVerifyingShare;
    }

    const { ttlMs, remainingUses } = this.clampSessionPolicy({
      ttlMs: ttlMsRaw,
      remainingUses: remainingUsesRaw,
    });
    const participantIds = policyParticipantIds || [...this.participantIds2p];

    const existingSession = await this.getEcdsaWalletSession(sessionId);
    if (existingSession) {
      if (existingSession.walletSessionUserId !== walletSessionUserId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'threshold sessionId already exists for a different user',
        };
      }
      if (existingSession.relayerKeyId !== relayerKeyId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'threshold sessionId already exists for a different relayerKeyId',
        };
      }
      if (existingSession.rpId !== rpId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'threshold sessionId already exists for a different rpId',
        };
      }
      const sameParticipantIds =
        existingSession.participantIds.length === participantIds.length &&
        existingSession.participantIds.every((id, i) => id === participantIds[i]);
      if (!sameParticipantIds) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'threshold sessionId already exists for a different participant set',
        };
      }
      if (!haveSameEcdsaSigningRootMetadata(existingSession, signingRootMetadata)) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'threshold sessionId already exists for a different signing root',
        };
      }
      const walletBudget = await this.ensureSigningGrantBudget({
        signingGrantId,
        binding: { curve: 'ecdsa', thresholdSessionId: sessionId },
        userId: walletSessionUserId,
        rpId,
        participantIds: existingSession.participantIds,
        ttlMs,
        remainingUses,
        refreshExisting: refreshExistingWalletBudget === true,
      });
      if (!walletBudget.ok) return walletBudget;
      return {
        ok: true,
        sessionId,
        signingGrantId,
        expiresAtMs: walletBudget.expiresAtMs,
        expiresAt: new Date(walletBudget.expiresAtMs).toISOString(),
        participantIds: walletBudget.participantIds,
        remainingUses,
      };
    }

    const expiresAtMs = Date.now() + ttlMs;
    await this.putEcdsaWalletSessionRecord({
      sessionId,
      record: {
        expiresAtMs,
        relayerKeyId,
        walletSessionUserId,
        rpId,
        participantIds,
        ...signingRootMetadata,
      },
      ttlMs,
      remainingUses,
    });
    const walletBudget = await this.ensureSigningGrantBudget({
      signingGrantId,
      binding: { curve: 'ecdsa', thresholdSessionId: sessionId },
      userId: walletSessionUserId,
      rpId,
      participantIds,
      ttlMs,
      remainingUses,
      refreshExisting: refreshExistingWalletBudget === true,
    });
    if (!walletBudget.ok) return walletBudget;

    return {
      ok: true,
      sessionId,
      signingGrantId,
      expiresAtMs: walletBudget.expiresAtMs,
      expiresAt: new Date(walletBudget.expiresAtMs).toISOString(),
      participantIds: walletBudget.participantIds,
      remainingUses,
    };
  }

  async deleteEcdsaHssRoleLocalKeyByBootstrapIdentity(input: {
    ecdsaThresholdKeyId: unknown;
    signingRootId: unknown;
    signingRootVersion?: unknown;
  }): Promise<EcdsaHssRouteResult<{ keyHandle: string }>> {
    try {
      const keyHandle = await deriveThresholdEcdsaHssKeyHandle({
        ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
        signingRootId: input.signingRootId,
        signingRootVersion: input.signingRootVersion,
      });
      await this.ecdsaKeyStore.deleteByKeyHandle(keyHandle);
      return { ok: true, value: { keyHandle } };
    } catch (error) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to delete ECDSA HSS role-local key',
      };
    }
  }

  async verifyEcdsaHssRoleLocalBootstrapPersisted(
    bootstrap: EcdsaHssServerBootstrapResponse,
  ): Promise<EcdsaHssRouteResult<{ keyHandle: string }>> {
    try {
      const keyHandle = await deriveThresholdEcdsaHssKeyHandle({
        ecdsaThresholdKeyId: bootstrap.ecdsaThresholdKeyId,
        signingRootId: bootstrap.signingRootId,
        signingRootVersion: bootstrap.signingRootVersion,
      });
      if (bootstrap.keyHandle !== keyHandle) {
        return {
          ok: false,
          code: 'identity_mismatch',
          message: 'ECDSA HSS bootstrap key handle does not match persisted key identity',
        };
      }
      const record = await this.ecdsaKeyStore.getRoleLocalByKeyHandle(keyHandle);
      if (!record) {
        return {
          ok: false,
          code: 'not_found',
          message: 'ECDSA HSS role-local key not found for registration finalize',
        };
      }
      if (!ecdsaHssRoleLocalRecordMatchesBootstrap(record, bootstrap)) {
        return {
          ok: false,
          code: 'identity_mismatch',
          message: 'ECDSA HSS registration finalize does not match persisted key identity',
        };
      }
      return { ok: true, value: { keyHandle } };
    } catch (error) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to verify ECDSA HSS role-local key',
      };
    }
  }

  async ecdsaHssRoleLocalBootstrap(
    request: EcdsaHssClientBootstrapRequest,
  ): Promise<EcdsaHssRouteResult<EcdsaHssServerBootstrapResponse>> {
    try {
      const signingRootMetadata = createEcdsaSigningRootMetadata(
        request.signingRootId,
        request.signingRootVersion,
      );
      const hssContext = {
        walletId: request.walletId,
        rpId: request.rpId,
        ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
        signingRootId: signingRootMetadata.signingRootId,
        signingRootVersion: canonicalEcdsaHssSigningRootVersion(
          signingRootMetadata.signingRootVersion,
        ),
        keyPurpose: THRESHOLD_ECDSA_HSS_KEY_PURPOSE_V1,
        keyVersion: THRESHOLD_ECDSA_HSS_KEY_VERSION_V1,
      };
      const derivedRelayerShare = await this.deriveThresholdEcdsaHssYRelayerForContext({
        hssContext,
        signingRootMetadata,
      });
      if (!derivedRelayerShare.ok) {
        return {
          ok: false,
          code: 'internal',
          message: derivedRelayerShare.message,
        };
      }
      const hssClientSharePublicKey33 = base64UrlDecode(request.hssClientSharePublicKey33B64u);
      const relayerBootstrap = await roleLocalThresholdEcdsaHssRelayerBootstrap({
        ...hssContext,
        relayerKeyId: request.relayerKeyId,
        yRelayer32Le: derivedRelayerShare.value,
        clientPublicKey33: hssClientSharePublicKey33,
        clientShareRetryCounter: request.clientShareRetryCounter,
      });
      const expectedContextBinding32 = base64UrlDecode(request.contextBinding32B64u);
      if (!bytesEqual(expectedContextBinding32, relayerBootstrap.contextBinding32)) {
        return {
          ok: false,
          code: 'context_mismatch',
          message: 'contextBinding32B64u does not match role-local HSS context',
        };
      }
      const keyHandle = await deriveThresholdEcdsaHssKeyHandle({
        ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
        signingRootId: signingRootMetadata.signingRootId,
        signingRootVersion: signingRootMetadata.signingRootVersion,
      });
      const existing = await this.ecdsaKeyStore.getRoleLocalByKeyHandle(keyHandle);
      if (existing) {
        const signingRootVersion = canonicalEcdsaHssSigningRootVersion(
          signingRootMetadata.signingRootVersion,
        );
        if (existing.relayerKeyId !== request.relayerKeyId) {
          return {
            ok: false,
            code: 'relayer_key_mismatch',
            message: 'relayerKeyId mismatch requires ECDSA HSS re-bootstrap',
          };
        }
        if (
          existing.ecdsaThresholdKeyId !== request.ecdsaThresholdKeyId ||
          existing.keyHandle !== keyHandle ||
          existing.walletId !== request.walletId ||
          existing.rpId !== request.rpId ||
          existing.signingRootId !== signingRootMetadata.signingRootId ||
          existing.signingRootVersion !== signingRootVersion ||
          existing.keyScope !== request.keyScope ||
          existing.contextBinding32B64u !== request.contextBinding32B64u ||
          existing.clientPublicKey33B64u !== request.hssClientSharePublicKey33B64u
        ) {
          return {
            ok: false,
            code: 'identity_mismatch',
            message: 'ECDSA HSS key identity mismatch',
          };
        }
      }
      const session = await this.ecdsaMintSessionWithoutWebAuthn({
        relayerKeyId: request.relayerKeyId,
        clientVerifyingShareB64u: request.hssClientSharePublicKey33B64u,
        walletSessionUserId: request.walletId,
        rpId: request.rpId,
        sessionId: request.sessionId,
        signingGrantId: request.signingGrantId,
        ttlMsRaw: request.ttlMs,
        remainingUsesRaw: request.remainingUses,
        policyParticipantIds: request.participantIds,
        signingRootMetadata,
        refreshExistingWalletBudget: true,
      });
      if (!session.ok) {
        return {
          ok: false,
          code:
            session.code === 'invalid_body' || session.code === 'unauthorized'
              ? session.code
              : 'internal',
          message: session.message || 'threshold-ecdsa role-local session mint failed',
        };
      }
      const nowMs = Date.now();
      const relayerPublicKey33B64u = base64UrlEncode(relayerBootstrap.relayerPublicKey33);
      const groupPublicKey33B64u = base64UrlEncode(relayerBootstrap.groupPublicKey33);
      const ethereumAddress = bytesToLowerHex(relayerBootstrap.ethereumAddress20);
      const publicTranscriptDigest32B64u = base64UrlEncode(
        relayerBootstrap.publicTranscriptDigest32,
      );
      const record = {
        version: 'threshold_ecdsa_hss_role_local_v2',
        ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
        keyHandle,
        walletId: request.walletId,
        rpId: request.rpId,
        signingRootId: signingRootMetadata.signingRootId,
        signingRootVersion: canonicalEcdsaHssSigningRootVersion(
          signingRootMetadata.signingRootVersion,
        ),
        keyScope: 'evm-family',
        relayerKeyId: request.relayerKeyId,
        contextBinding32B64u: request.contextBinding32B64u,
        relayerShare32B64u: base64UrlEncode(relayerBootstrap.relayerShare32),
        relayerPublicKey33B64u,
        clientPublicKey33B64u: request.hssClientSharePublicKey33B64u,
        groupPublicKey33B64u,
        ethereumAddress,
        relayerCaitSithInput: {
          participantId: 2,
          mappedPrivateShare32B64u: base64UrlEncode(relayerBootstrap.relayerMappedPrivateShare32),
          verifyingShare33B64u: relayerPublicKey33B64u,
        },
        publicTranscriptDigest32B64u,
        createdAtMs: existing?.createdAtMs ?? nowMs,
        updatedAtMs: nowMs,
      } satisfies EcdsaHssRoleLocalKeyRecord;
      await this.ecdsaKeyStore.putRoleLocalByKeyHandle(record);
      return {
        ok: true,
        value: {
          formatVersion: 'ecdsa-hss-role-local',
          walletId: request.walletId,
          rpId: request.rpId,
          ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
          relayerKeyId: request.relayerKeyId,
          contextBinding32B64u: request.contextBinding32B64u,
          publicIdentity: {
            hssClientSharePublicKey33B64u: request.hssClientSharePublicKey33B64u,
            relayerPublicKey33B64u: relayerPublicKey33B64u as EcdsaRelayerHssPublicKey33B64u,
            groupPublicKey33B64u,
            ethereumAddress,
          },
          clientShareRetryCounter: request.clientShareRetryCounter,
          relayerShareRetryCounter: relayerBootstrap.relayerShareRetryCounter,
          publicTranscriptDigest32B64u,
          keyHandle,
          signingRootId: signingRootMetadata.signingRootId,
          signingRootVersion: canonicalEcdsaHssSigningRootVersion(
            signingRootMetadata.signingRootVersion,
          ),
          thresholdEcdsaPublicKeyB64u: groupPublicKey33B64u,
          ethereumAddress,
          relayerVerifyingShareB64u: relayerPublicKey33B64u,
          participantIds: session.participantIds,
          sessionId: session.sessionId,
          signingGrantId: session.signingGrantId || request.signingGrantId,
          expiresAtMs: session.expiresAtMs,
          expiresAt: session.expiresAt,
          remainingUses: session.remainingUses ?? request.remainingUses,
        },
      };
    } catch (error) {
      const message = errorMessage(error);
      if (isEcdsaHssPublicKeyValidationError(message)) {
        return {
          ok: false,
          code: 'public_key_invalid',
          message,
        };
      }
      return {
        ok: false,
        code: 'internal',
        message: message || 'threshold-ecdsa role-local bootstrap failed',
      };
    }
  }

  async verifyEcdsaHssRoleLocalClientRootProofForExistingKey(
    request: EcdsaHssClientBootstrapRequest & {
      clientRootProof: NonNullable<EcdsaHssClientBootstrapRequest['clientRootProof']>;
    },
  ): Promise<EcdsaHssRouteResult<{ keyHandle: string }>> {
    try {
      const keyHandle = await deriveThresholdEcdsaHssKeyHandle({
        ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
        signingRootId: request.signingRootId,
        signingRootVersion: request.signingRootVersion,
      });
      const record = await this.ecdsaKeyStore.getRoleLocalByKeyHandle(keyHandle);
      if (!record) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'ECDSA role-local key is not active for bootstrap authorization',
        };
      }
      if (
        record.walletId !== request.walletId ||
        record.rpId !== request.rpId ||
        record.ecdsaThresholdKeyId !== request.ecdsaThresholdKeyId ||
        record.keyHandle !== keyHandle ||
        record.signingRootId !== request.signingRootId ||
        record.signingRootVersion !==
          canonicalEcdsaHssSigningRootVersion(request.signingRootVersion) ||
        record.relayerKeyId !== request.relayerKeyId ||
        record.keyScope !== request.keyScope ||
        record.contextBinding32B64u !== request.contextBinding32B64u ||
        record.clientPublicKey33B64u !== request.hssClientSharePublicKey33B64u
      ) {
        return {
          ok: false,
          code: 'identity_mismatch',
          message: 'ECDSA role-local bootstrap proof does not match persisted key identity',
        };
      }
      const verifiedRootProof = await verifyEcdsaClientRootProof(request.clientRootProof);
      if (!verifiedRootProof.ok) return verifiedRootProof;
      return { ok: true, value: { keyHandle } };
    } catch {
      return { ok: false, code: 'unauthorized', message: 'Invalid client root proof' };
    }
  }

  private async computeEcdsaHssExportConfirmationDigest32(input: {
    request: EcdsaHssExportShareRequest;
  }): Promise<Uint8Array> {
    const { request } = input;
    return await sha256BytesUtf8(
      alphabetizeStringify({
        version: THRESHOLD_ECDSA_HSS_EXPORT_CONFIRMATION_DIGEST_VERSION,
        walletId: request.walletId,
        rpId: request.rpId,
        ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
        relayerKeyId: request.relayerKeyId,
        contextBinding32B64u: request.contextBinding32B64u,
        publicIdentity: request.publicIdentity,
        clientDeviceId: request.clientDeviceId,
        clientSessionId: request.clientSessionId,
        exportRequestNonce32B64u: request.exportRequestNonce32B64u,
        issuedAtUnixMs: request.issuedAtUnixMs,
        expiresAtUnixMs: request.expiresAtUnixMs,
      }),
    );
  }

  private async computeEcdsaHssExportAuthorizationDigest32(input: {
    request: EcdsaHssExportShareRequest;
    keyHandle: string;
    record: EcdsaHssRoleLocalKeyRecord;
    claims: ThresholdEcdsaSessionClaims;
  }): Promise<Uint8Array> {
    const { request, record, claims } = input;
    return await sha256BytesUtf8(
      alphabetizeStringify({
        version: THRESHOLD_ECDSA_HSS_EXPORT_AUTHORIZATION_DIGEST_VERSION,
        operation: 'explicit_key_export',
        keyHandle: input.keyHandle,
        walletId: request.walletId,
        rpId: request.rpId,
        ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
        relayerKeyId: request.relayerKeyId,
        signingRootId: record.signingRootId,
        signingRootVersion: record.signingRootVersion,
        contextBinding32B64u: request.contextBinding32B64u,
        publicIdentity: request.publicIdentity,
        exportRequestNonce32B64u: request.exportRequestNonce32B64u,
        confirmationDigest32B64u: request.confirmationDigest32B64u,
        issuedAtUnixMs: request.issuedAtUnixMs,
        expiresAtUnixMs: request.expiresAtUnixMs,
        clientDeviceId: request.clientDeviceId,
        clientSessionId: request.clientSessionId,
        thresholdSessionId: claims.thresholdSessionId,
        signingGrantId: claims.signingGrantId,
        thresholdExpiresAtMs: claims.thresholdExpiresAtMs,
        participantIds: claims.participantIds,
      }),
    );
  }

  private ecdsaHssExportReplayScope(input: {
    request: EcdsaHssExportShareRequest;
    keyHandle: string;
    claims: ThresholdEcdsaSessionClaims;
  }): string {
    return [
      'ecdsa-hss-export',
      input.request.walletId,
      input.request.rpId,
      input.request.ecdsaThresholdKeyId,
      input.request.relayerKeyId,
      input.keyHandle,
      input.claims.thresholdSessionId,
    ].join(':');
  }

  private ecdsaHssExportReplayKey(request: EcdsaHssExportShareRequest): string {
    return request.exportRequestNonce32B64u;
  }

  async ecdsaHssRoleLocalExportShare(input: {
    request: EcdsaHssExportShareRequest;
    keyHandle: string;
    claims: ThresholdEcdsaSessionClaims;
  }): Promise<EcdsaHssRouteResult<EcdsaHssExportShareResponse>> {
    try {
      const { request } = input;
      const nowMs = Date.now();
      const keyHandle = toOptionalTrimmedString(input.keyHandle);
      if (!keyHandle) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Missing ECDSA HSS key handle',
        };
      }
      const { claims } = input;
      const replayGuard = await this.ecdsaWalletSessionStore.reserveReplayGuard(
        this.ecdsaHssExportReplayScope({ request, keyHandle, claims }),
        this.ecdsaHssExportReplayKey(request),
        request.expiresAtUnixMs,
      );
      if (!replayGuard.ok) {
        return {
          ok: false,
          code:
            replayGuard.code === 'export_nonce_replay'
              ? 'export_nonce_replay'
              : replayGuard.code === 'export_authorization_expired'
                ? 'export_authorization_expired'
                : 'export_authorization_invalid',
          message: replayGuard.message,
        };
      }
      if (request.expiresAtUnixMs <= nowMs) {
        return {
          ok: false,
          code: 'export_authorization_expired',
          message: 'ECDSA HSS export authorization is expired',
        };
      }
      if (request.issuedAtUnixMs > nowMs + THRESHOLD_ECDSA_HSS_EXPORT_CLOCK_SKEW_MS) {
        return {
          ok: false,
          code: 'export_authorization_invalid',
          message: 'ECDSA HSS export authorization issue time is invalid',
        };
      }
      const record = await this.ecdsaKeyStore.getRoleLocalByKeyHandle(keyHandle);
      if (!record) {
        return {
          ok: false,
          code: 'not_found',
          message: 'ECDSA HSS role-local key not found',
        };
      }
      if (
        record.walletId !== request.walletId ||
        record.rpId !== request.rpId ||
        record.ecdsaThresholdKeyId !== request.ecdsaThresholdKeyId ||
        record.relayerKeyId !== request.relayerKeyId ||
        claims.walletId !== request.walletId ||
        claims.rpId !== request.rpId ||
        claims.relayerKeyId !== request.relayerKeyId ||
        claims.keyHandle !== keyHandle
      ) {
        return {
          ok: false,
          code: 'identity_mismatch',
          message: 'ECDSA HSS export request does not match persisted key identity',
        };
      }
      if (record.contextBinding32B64u !== request.contextBinding32B64u) {
        return {
          ok: false,
          code: 'context_mismatch',
          message: 'ECDSA HSS export request context does not match persisted key',
        };
      }
      if (
        record.clientPublicKey33B64u !== request.publicIdentity.hssClientSharePublicKey33B64u ||
        record.relayerPublicKey33B64u !== request.publicIdentity.relayerPublicKey33B64u ||
        record.groupPublicKey33B64u !== request.publicIdentity.groupPublicKey33B64u ||
        record.ethereumAddress.toLowerCase() !==
          request.publicIdentity.ethereumAddress.toLowerCase()
      ) {
        return {
          ok: false,
          code: 'public_key_invalid',
          message: 'ECDSA HSS export request public identity does not match persisted key',
        };
      }
      const expectedConfirmationDigest32 = await this.computeEcdsaHssExportConfirmationDigest32({
        request,
      });
      if (
        !bytesEqual(base64UrlDecode(request.confirmationDigest32B64u), expectedConfirmationDigest32)
      ) {
        return {
          ok: false,
          code: 'export_authorization_invalid',
          message: 'ECDSA HSS export confirmation digest is invalid',
        };
      }
      const expectedAuthorizationDigest32 = await this.computeEcdsaHssExportAuthorizationDigest32({
        request,
        keyHandle,
        record,
        claims,
      });
      if (
        !bytesEqual(
          base64UrlDecode(request.authorizationDigest32B64u),
          expectedAuthorizationDigest32,
        )
      ) {
        return {
          ok: false,
          code: 'export_authorization_invalid',
          message: 'ECDSA HSS export authorization digest is invalid',
        };
      }
      return {
        ok: true,
        value: {
          formatVersion: 'ecdsa-hss-role-local-export',
          walletId: request.walletId,
          rpId: request.rpId,
          ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
          relayerKeyId: request.relayerKeyId,
          contextBinding32B64u: request.contextBinding32B64u,
          publicIdentity: request.publicIdentity,
          exportAuthorizationDigest32B64u: request.authorizationDigest32B64u,
          serverExportShare32B64u: record.relayerShare32B64u,
        },
      };
    } catch (error) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'threshold-ecdsa role-local export share failed',
      };
    }
  }

  private async ed25519Session(
    request: ThresholdEd25519SessionRequest,
  ): Promise<ThresholdEd25519SessionResponse> {
    let context: Record<string, unknown> | null = null;
    try {
      const parsedRequest = parseThresholdEd25519SessionRequest(request, this.participantIds2p);
      if (!parsedRequest.ok) return parsedRequest;
      const {
        relayerKeyId,
        nearAccountId,
        rpId,
        sessionId,
        signingGrantId,
        runtimePolicyScope,
        routerAbNormalSigning,
        ttlMsRaw,
        remainingUsesRaw,
        policyParticipantIds,
      } = parsedRequest.value;
      const routerAbPolicy = this.validateRouterAbNormalSigningSessionPolicy(routerAbNormalSigning);
      if (!routerAbPolicy.ok) return routerAbPolicy;
      context = { nearAccountId, rpId, relayerKeyId, sessionId, signingGrantId };

      await this.ensureReady();

      const appSessionClaims = request.appSessionClaims
        ? parseAppSessionClaims(request.appSessionClaims)
        : null;
      const ecdsaSessionClaims = request.ecdsaSessionClaims
        ? parseRouterAbEcdsaHssWalletSessionClaims(request.ecdsaSessionClaims)
        : null;
      const sessionWalletId =
        toOptionalTrimmedString(appSessionClaims?.walletId) ||
        toOptionalTrimmedString(appSessionClaims?.sub);
      const hasAppSessionAuth = Boolean(appSessionClaims && sessionWalletId === nearAccountId);
      const policySigningRoot = resolveEcdsaSigningRootFromScope(
        request.sessionPolicy?.runtimePolicyScope,
      );
      const ecdsaSigningRoot = resolveEcdsaSigningRootFromScope(
        ecdsaSessionClaims?.runtimePolicyScope,
      );
      const hasEcdsaSessionAuth = Boolean(
        ecdsaSessionClaims &&
        ecdsaSessionClaims.walletId === nearAccountId &&
        ecdsaSessionClaims.rpId === rpId &&
        ecdsaSessionClaims.thresholdExpiresAtMs > Date.now() &&
        (!policySigningRoot ||
          (ecdsaSigningRoot &&
            ecdsaSigningRoot.signingRootId === policySigningRoot.signingRootId &&
            ecdsaSigningRoot.signingRootVersion === policySigningRoot.signingRootVersion)),
      );
      const hasSessionAuth = hasAppSessionAuth || hasEcdsaSessionAuth;
      if (!hasSessionAuth && !this.verifyWebAuthnAuthenticationLite) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Lite WebAuthn verification is not configured on this server',
        };
      }

      const relayerKey = await this.resolveRelayerKeyMaterial({
        relayerKeyId,
      });
      if (!relayerKey.ok) {
        return { ok: false, code: relayerKey.code, message: relayerKey.message };
      }

      const { ttlMs, remainingUses } = this.clampSessionPolicy({
        ttlMs: ttlMsRaw,
        remainingUses: remainingUsesRaw,
      });
      const participantIds = policyParticipantIds || [...this.participantIds2p];
      const normalizedPolicy = {
        version: 'threshold_session_v1',
        nearAccountId,
        rpId,
        relayerKeyId,
        sessionId,
        signingGrantId,
        ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
        ...(routerAbNormalSigning ? { routerAbNormalSigning } : {}),
        ...(policyParticipantIds ? { participantIds: policyParticipantIds } : {}),
        ttlMs,
        remainingUses,
      };
      const sessionPolicyDigest32 = await this.computeSessionPolicyDigest32(normalizedPolicy);
      const expectedChallenge = base64UrlEncode(sessionPolicyDigest32);

      const existingSession = await this.walletSessionStore.getSession(sessionId);
      if (existingSession) {
        if (existingSession.userId !== nearAccountId) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'threshold sessionId already exists for a different user',
          };
        }
        if (existingSession.relayerKeyId !== relayerKeyId) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'threshold sessionId already exists for a different relayerKeyId',
          };
        }
        if (existingSession.rpId !== rpId) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'threshold sessionId already exists for a different rpId',
          };
        }
        const sameParticipantIds =
          existingSession.participantIds.length === participantIds.length &&
          existingSession.participantIds.every((id, i) => id === participantIds[i]);
        if (!sameParticipantIds) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'threshold sessionId already exists for a different participant set',
          };
        }
      }

      const walletAuthProof = resolveThresholdEd25519SessionWalletAuthProof({
        request,
        appSessionClaims,
        sessionWalletId,
        ecdsaSessionClaims,
        hasAppSessionAuth,
        hasEcdsaSessionAuth,
      });
      if (!walletAuthProof.ok) return walletAuthProof;

      if (walletAuthProof.value.method === 'app_session') {
        if (
          walletAuthProof.value.claims?.sub !== nearAccountId &&
          walletAuthProof.value.sessionWalletId !== nearAccountId
        ) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'app session does not match threshold-ed25519 session scope',
          };
        }
      } else if (walletAuthProof.value.method === 'passkey') {
        if (!parsedRequest.value.expectedOrigin) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'expected_origin is required for threshold-ed25519 passkey session mint',
          };
        }
        const verification = await this.verifyWebAuthnAuthenticationLite!({
          nearAccountId,
          rpId,
          expectedChallenge,
          expected_origin: parsedRequest.value.expectedOrigin,
          webauthn_authentication: walletAuthProof.value.webauthnAuthentication,
        });

        if (!verification.success || !verification.verified) {
          return {
            ok: false,
            code: verification.code || 'not_verified',
            message: verification.message || 'Authentication verification failed',
          };
        }

        const scope = await ensureRelayerKeyIsActiveAccessKey({
          nearAccountId,
          relayerPublicKey: relayerKey.publicKey,
          viewAccessKeyList: this.viewAccessKeyList,
          maxAttempts: 6,
          initialDelayMs: 60,
        });
        if (!scope.ok) {
          return { ok: false, code: scope.code, message: scope.message };
        }
      }

      if (existingSession) {
        const walletBudget = await this.ensureSigningGrantBudget({
          signingGrantId,
          binding: { curve: 'ed25519', thresholdSessionId: sessionId },
          userId: nearAccountId,
          rpId,
          participantIds: existingSession.participantIds,
          ttlMs,
          remainingUses,
          refreshExisting: false,
        });
        if (!walletBudget.ok) return walletBudget;
        return {
          ok: true,
          sessionId,
          signingGrantId,
          expiresAtMs: walletBudget.expiresAtMs,
          expiresAt: new Date(walletBudget.expiresAtMs).toISOString(),
          participantIds: walletBudget.participantIds,
          ...(routerAbNormalSigning ? { routerAbNormalSigning } : {}),
        };
      }

      const expiresAtMs = Date.now() + ttlMs;
      await this.putWalletSessionRecord({
        store: this.walletSessionStore,
        sessionId,
        record: {
          expiresAtMs,
          relayerKeyId,
          userId: nearAccountId,
          rpId,
          participantIds,
        },
        ttlMs,
        remainingUses,
      });
      const walletBudget = await this.ensureSigningGrantBudget({
        signingGrantId,
        binding: { curve: 'ed25519', thresholdSessionId: sessionId },
        userId: nearAccountId,
        rpId,
        participantIds,
        ttlMs,
        remainingUses,
        refreshExisting: true,
      });
      if (!walletBudget.ok) return walletBudget;

      return {
        ok: true,
        sessionId,
        signingGrantId,
        expiresAtMs: walletBudget.expiresAtMs,
        expiresAt: new Date(walletBudget.expiresAtMs).toISOString(),
        participantIds: walletBudget.participantIds,
        remainingUses,
        ...(routerAbNormalSigning ? { routerAbNormalSigning } : {}),
      };
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Internal error',
      );
      this.logger?.error?.('[threshold-ed25519] session mint failed', {
        message: msg,
        ...(context || {}),
      });
      return { ok: false, code: 'internal', message: msg };
    }
  }

  private validateThresholdEd25519HssSessionScope(input: {
    claims: ThresholdEd25519SessionClaims;
    relayerKeyId: string;
    context: ThresholdEd25519HssCanonicalContext;
    preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  }): ThresholdEd25519HssSessionError | null {
    const sessionId = toOptionalTrimmedString(input.claims?.thresholdSessionId);
    if (!sessionId) {
      return { ok: false, code: 'unauthorized', message: 'Missing threshold sessionId' };
    }
    const userId = toOptionalTrimmedString(input.claims?.walletId);
    if (!userId) return { ok: false, code: 'unauthorized', message: 'Missing threshold userId' };
    const tokenRelayerKeyId = toOptionalTrimmedString(input.claims?.relayerKeyId);
    if (!tokenRelayerKeyId) {
      return { ok: false, code: 'unauthorized', message: 'Invalid Wallet Session claims' };
    }
    if (input.relayerKeyId !== tokenRelayerKeyId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'relayerKeyId does not match threshold session scope',
      };
    }
    if (Date.now() > input.claims.thresholdExpiresAtMs) {
      return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
    }
    for (const id of this.participantIds2p) {
      if (!input.claims.participantIds.includes(id)) {
        return {
          ok: false,
          code: 'unauthorized',
          message: `Wallet Session does not include server signer set (expected to include participantIds=[${this.participantIds2p.join(',')}])`,
        };
      }
    }
    if (input.context.nearAccountId !== userId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'context.nearAccountId does not match threshold session scope',
      };
    }
    if (!haveSameParticipantIds(input.context.participantIds, input.claims.participantIds)) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'context.participantIds does not match threshold session scope',
      };
    }
    if (!toOptionalTrimmedString(input.preparedSession.contextBindingB64u)) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'preparedSession.contextBindingB64u is required',
      };
    }
    const claimSigningRootId = resolveEcdsaSigningRootFromScope(
      input.claims.runtimePolicyScope,
    )?.signingRootId;
    if (claimSigningRootId && claimSigningRootId !== input.context.signingRootId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'context.signingRootId does not match threshold session scope',
      };
    }
    return null;
  }

  private validateThresholdEd25519HssContextPreparedSessionScope(input: {
    context: ThresholdEd25519HssCanonicalContext;
    preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  }): ThresholdEd25519HssSessionError | null {
    if (!haveSameParticipantIds(input.context.participantIds, this.participantIds2p)) {
      return {
        ok: false,
        code: 'unauthorized',
        message: `threshold-ed25519 HSS context must match server signer set participantIds=[${this.participantIds2p.join(',')}]`,
      };
    }
    if (!toOptionalTrimmedString(input.preparedSession.contextBindingB64u)) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'preparedSession.contextBindingB64u is required',
      };
    }
    return null;
  }

  private validateThresholdEd25519HssRegistrationScope(input: {
    orgId: string;
    newAccountId: string;
    context: ThresholdEd25519HssCanonicalContext;
    preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  }): ThresholdEd25519HssSessionError | null {
    if (!input.orgId) {
      return { ok: false, code: 'unauthorized', message: 'Missing registration orgId' };
    }
    if (!input.context.signingRootId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'context.signingRootId is required',
      };
    }
    if (!input.newAccountId || input.context.nearAccountId !== input.newAccountId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'context.nearAccountId does not match registration scope',
      };
    }
    return this.validateThresholdEd25519HssContextPreparedSessionScope({
      context: input.context,
      preparedSession: input.preparedSession,
    });
  }

  private validateThresholdEd25519HssSigningRootConstraint(input: {
    context: ThresholdEd25519HssCanonicalContext;
    expectedSigningRootId?: unknown;
  }): ThresholdEd25519HssSessionError | null {
    const expectedSigningRootId = toOptionalTrimmedString(input.expectedSigningRootId);
    if (expectedSigningRootId && expectedSigningRootId !== input.context.signingRootId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'context.signingRootId does not match authenticated signing root scope',
      };
    }
    return null;
  }

  private async deriveSigningRootEd25519HssServerInputsForContext(
    context: ThresholdEd25519HssCanonicalContext,
    signingRoot?: { readonly signingRootVersion?: unknown },
  ): Promise<ThresholdEd25519HssCanonicalContext & ThresholdEd25519HssServerInputs> {
    if (!this.signingRootShareResolver) {
      throw new Error('threshold-ed25519 HSS requires a signing-root share resolver');
    }

    const fixedScope = this.signingRootShareResolver.fixedSigningRootScope;
    const signingRootVersion =
      toOptionalTrimmedString(signingRoot?.signingRootVersion) ||
      toOptionalTrimmedString(fixedScope?.signingRootVersion);
    const derived = await deriveEd25519HssServerInputsFromSigningRootShareResolver({
      signingRootId: context.signingRootId,
      ...(signingRootVersion ? { signingRootVersion } : {}),
      resolver: this.signingRootShareResolver,
      context,
    });
    if (!derived.ok) {
      throw new Error(`threshold-prf signing-root derivation failed: ${derived.message}`);
    }
    return derived.value;
  }

  private async ed25519HssPrepareWithSession(input: {
    claims: ThresholdEd25519SessionClaims;
    request: ThresholdEd25519HssPrepareWithSessionRequest;
  }): Promise<ThresholdEd25519HssPrepareWithSessionResponse> {
    try {
      const prepareStartedAt = Date.now();
      const parseStartedAt = Date.now();
      const rec = (input.request || {}) as unknown as Record<string, unknown>;
      const relayerKeyId = toOptionalTrimmedString(rec.relayerKeyId);
      if (!relayerKeyId) {
        return { ok: false, code: 'invalid_body', message: 'relayerKeyId is required' };
      }
      const operation = parseThresholdEd25519HssSessionOperation(rec.operation);
      if (!operation.ok) return operation;
      const context = parseThresholdEd25519HssCanonicalContext(rec.context);
      if (!context.ok) return context;
      const expectedSigningRoot = input.claims.runtimePolicyScope
        ? signingRootScopeFromRuntimePolicyScope(input.claims.runtimePolicyScope)
        : undefined;
      const signingRootConstraintError = this.validateThresholdEd25519HssSigningRootConstraint({
        context: context.value,
        expectedSigningRootId: expectedSigningRoot?.signingRootId,
      });
      if (signingRootConstraintError) return signingRootConstraintError;
      const parseMs = Date.now() - parseStartedAt;

      const ensureReadyStartedAt = Date.now();
      await this.ensureReady();
      if (!this.signingRootShareResolver) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold-ed25519 HSS requires a signing-root share resolver',
        };
      }

      const wasmStartedAt = Date.now();
      let serverInputDeriveMs = 0;
      let serverSessionPrepareTotalMs = 0;
      const [serverInputs, preparedServerSession] = await Promise.all([
        (async () => {
          const startedAt = Date.now();
          try {
            return await this.deriveSigningRootEd25519HssServerInputsForContext(
              context.value,
              expectedSigningRoot,
            );
          } finally {
            serverInputDeriveMs = Date.now() - startedAt;
          }
        })(),
        (async () => {
          const startedAt = Date.now();
          try {
            return await prepareThresholdEd25519HssServerSession({
              context: context.value,
            });
          } finally {
            serverSessionPrepareTotalMs = Date.now() - startedAt;
          }
        })(),
      ]);
      const resolvedPreparedSession: ThresholdEd25519HssPreparedSessionEnvelope = {
        contextBindingB64u: preparedServerSession.contextBindingB64u,
        evaluatorDriverStateB64u: preparedServerSession.evaluatorDriverStateB64u,
      };
      const storedPreparedServerSession: ThresholdEd25519HssStoredPreparedServerSession = {
        preparedSessionHandle: preparedServerSession.preparedSessionHandle,
        evaluatorDriverStateBytes: base64UrlDecode(preparedServerSession.evaluatorDriverStateB64u),
        garblerDriverStateBytes: base64UrlDecode(preparedServerSession.garblerDriverStateB64u),
      };
      const storedServerInputs: ThresholdEd25519HssStoredServerInputs = {
        yRelayerBytes: base64UrlDecode(serverInputs.yRelayerB64u),
        tauRelayerBytes: base64UrlDecode(serverInputs.tauRelayerB64u),
      };
      const scopeError = this.validateThresholdEd25519HssSessionScope({
        claims: input.claims,
        relayerKeyId,
        context: context.value,
        preparedSession: resolvedPreparedSession,
      });
      if (scopeError) return scopeError;
      const ceremonyRecord: ThresholdEd25519HssCeremonyRecordInput = {
        kind: 'session',
        relayerKeyId,
        operation: operation.value,
        context: context.value,
        preparedSession: resolvedPreparedSession,
        preparedServerSession: storedPreparedServerSession,
        serverInputs: storedServerInputs,
      };
      const ceremonyHandle = this.storeThresholdEd25519HssCeremony(ceremonyRecord);
      const responsePayload = {
        ceremonyHandle,
        preparedSession: resolvedPreparedSession,
        clientOtOfferMessageB64u: preparedServerSession.clientOtOfferMessageB64u,
      };

      this.logger?.info?.('[threshold-ed25519] hss prepare timings', {
        relayerKeyId,
        nearAccountId: context.value.nearAccountId,
        requestBytes: jsonBytes(input.request || {}),
        parseMs,
        ensureReadyMs: wasmStartedAt - ensureReadyStartedAt,
        wasmPrepareMs: Date.now() - wasmStartedAt,
        responseBytes: jsonBytes(responsePayload),
        ceremonyHandleBytes: utf8Bytes(ceremonyHandle),
        preparedSessionBytes: jsonBytes(resolvedPreparedSession),
        evaluatorDriverStateBytes: utf8Bytes(resolvedPreparedSession.evaluatorDriverStateB64u),
        evaluatorDriverStatePayloadBytes: base64UrlPayloadBytes(
          resolvedPreparedSession.evaluatorDriverStateB64u,
        ),
        evaluatorDriverStateTransportOverheadBytes:
          utf8Bytes(resolvedPreparedSession.evaluatorDriverStateB64u) -
          base64UrlPayloadBytes(resolvedPreparedSession.evaluatorDriverStateB64u),
        clientOtOfferMessageBytes: utf8Bytes(preparedServerSession.clientOtOfferMessageB64u),
        clientOtOfferMessagePayloadBytes: base64UrlPayloadBytes(
          preparedServerSession.clientOtOfferMessageB64u,
        ),
        clientOtOfferMessageTransportOverheadBytes:
          utf8Bytes(preparedServerSession.clientOtOfferMessageB64u) -
          base64UrlPayloadBytes(preparedServerSession.clientOtOfferMessageB64u),
        ceremonyStateBytes: summarizeThresholdEd25519HssCeremonyRecordBytes(ceremonyRecord),
        totalMs: Date.now() - prepareStartedAt,
      });

      return {
        ok: true,
        ceremonyHandle,
        preparedSession: resolvedPreparedSession,
        clientOtOfferMessageB64u: preparedServerSession.clientOtOfferMessageB64u,
        serverInputDeriveMs,
        serverSessionPrepareTotalMs,
        serverSessionTimings: preparedServerSession.timings,
      };
    } catch (e: unknown) {
      const msg = errorMessage(e);
      this.logger?.error?.('[threshold-ed25519] hss prepare failed', { message: msg });
      return { ok: false, code: 'internal', message: msg };
    }
  }

  private async ed25519HssPrepareForRegistration(input: {
    orgId: string;
    signingRootId?: string;
    signingRootVersion?: string;
    request: ThresholdEd25519HssPrepareForRegistrationRequest;
  }): Promise<ThresholdEd25519HssPrepareForRegistrationResponse> {
    try {
      const prepareStartedAt = Date.now();
      const parseStartedAt = Date.now();
      const rec = (input.request || {}) as unknown as Record<string, unknown>;
      const newAccountId = toOptionalTrimmedString(rec.new_account_id);
      const rpId = toOptionalTrimmedString(rec.rp_id);
      if (!newAccountId) {
        return { ok: false, code: 'invalid_body', message: 'new_account_id is required' };
      }
      if (!rpId) {
        return { ok: false, code: 'invalid_body', message: 'rp_id is required' };
      }
      const context = parseThresholdEd25519HssCanonicalContext(rec.context);
      if (!context.ok) return context;
      const signingRootConstraintError = this.validateThresholdEd25519HssSigningRootConstraint({
        context: context.value,
        expectedSigningRootId: input.signingRootId,
      });
      if (signingRootConstraintError) return signingRootConstraintError;
      const parseMs = Date.now() - parseStartedAt;

      const ensureReadyStartedAt = Date.now();
      await this.ensureReady();
      if (!this.signingRootShareResolver) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold-ed25519 HSS requires a signing-root share resolver',
        };
      }

      const wasmStartedAt = Date.now();
      let serverInputDeriveMs = 0;
      let serverSessionPrepareTotalMs = 0;
      const [serverInputs, preparedServerSession] = await Promise.all([
        (async () => {
          const startedAt = Date.now();
          try {
            return await this.deriveSigningRootEd25519HssServerInputsForContext(context.value, {
              signingRootVersion: input.signingRootVersion,
            });
          } finally {
            serverInputDeriveMs = Date.now() - startedAt;
          }
        })(),
        (async () => {
          const startedAt = Date.now();
          try {
            return await prepareThresholdEd25519HssServerSession({
              context: context.value,
            });
          } finally {
            serverSessionPrepareTotalMs = Date.now() - startedAt;
          }
        })(),
      ]);
      const resolvedPreparedSession: ThresholdEd25519HssPreparedSessionEnvelope = {
        contextBindingB64u: preparedServerSession.contextBindingB64u,
        evaluatorDriverStateB64u: preparedServerSession.evaluatorDriverStateB64u,
      };
      const storedPreparedServerSession: ThresholdEd25519HssStoredPreparedServerSession = {
        preparedSessionHandle: preparedServerSession.preparedSessionHandle,
        evaluatorDriverStateBytes: base64UrlDecode(preparedServerSession.evaluatorDriverStateB64u),
        garblerDriverStateBytes: base64UrlDecode(preparedServerSession.garblerDriverStateB64u),
      };
      const storedServerInputs: ThresholdEd25519HssStoredServerInputs = {
        yRelayerBytes: base64UrlDecode(serverInputs.yRelayerB64u),
        tauRelayerBytes: base64UrlDecode(serverInputs.tauRelayerB64u),
      };
      const scopeError = this.validateThresholdEd25519HssRegistrationScope({
        orgId: toOptionalTrimmedString(input.orgId) || '',
        newAccountId,
        context: context.value,
        preparedSession: resolvedPreparedSession,
      });
      if (scopeError) return scopeError;
      const ceremonyRecord: ThresholdEd25519HssCeremonyRecordInput = {
        kind: 'registration',
        orgId: toOptionalTrimmedString(input.orgId) || '',
        newAccountId,
        rpId,
        context: context.value,
        preparedSession: resolvedPreparedSession,
        preparedServerSession: storedPreparedServerSession,
        serverInputs: storedServerInputs,
      };
      const ceremonyHandle = this.storeThresholdEd25519HssCeremony(ceremonyRecord);
      const responsePayload = {
        ceremonyHandle,
        preparedSession: resolvedPreparedSession,
        clientOtOfferMessageB64u: preparedServerSession.clientOtOfferMessageB64u,
      };

      this.logger?.info?.('[threshold-ed25519][registration] hss prepare timings', {
        nearAccountId: newAccountId,
        requestBytes: jsonBytes(input.request || {}),
        parseMs,
        ensureReadyMs: wasmStartedAt - ensureReadyStartedAt,
        wasmPrepareMs: Date.now() - wasmStartedAt,
        responseBytes: jsonBytes(responsePayload),
        ceremonyHandleBytes: utf8Bytes(ceremonyHandle),
        preparedSessionBytes: jsonBytes(resolvedPreparedSession),
        evaluatorDriverStateBytes: utf8Bytes(resolvedPreparedSession.evaluatorDriverStateB64u),
        evaluatorDriverStatePayloadBytes: base64UrlPayloadBytes(
          resolvedPreparedSession.evaluatorDriverStateB64u,
        ),
        evaluatorDriverStateTransportOverheadBytes:
          utf8Bytes(resolvedPreparedSession.evaluatorDriverStateB64u) -
          base64UrlPayloadBytes(resolvedPreparedSession.evaluatorDriverStateB64u),
        clientOtOfferMessageBytes: utf8Bytes(preparedServerSession.clientOtOfferMessageB64u),
        clientOtOfferMessagePayloadBytes: base64UrlPayloadBytes(
          preparedServerSession.clientOtOfferMessageB64u,
        ),
        clientOtOfferMessageTransportOverheadBytes:
          utf8Bytes(preparedServerSession.clientOtOfferMessageB64u) -
          base64UrlPayloadBytes(preparedServerSession.clientOtOfferMessageB64u),
        ceremonyStateBytes: summarizeThresholdEd25519HssCeremonyRecordBytes(ceremonyRecord),
        totalMs: Date.now() - prepareStartedAt,
      });

      return {
        ok: true,
        ceremonyHandle,
        preparedSession: resolvedPreparedSession,
        clientOtOfferMessageB64u: preparedServerSession.clientOtOfferMessageB64u,
        serverInputDeriveMs,
        serverSessionPrepareTotalMs,
        serverSessionTimings: preparedServerSession.timings,
      };
    } catch (e: unknown) {
      const msg = errorMessage(e);
      this.logger?.error?.('[threshold-ed25519][registration] hss prepare failed', {
        message: msg,
      });
      return { ok: false, code: 'internal', message: msg };
    }
  }

  private async ed25519HssRespondWithSession(input: {
    claims: ThresholdEd25519SessionClaims;
    request: ThresholdEd25519HssRespondWithSessionRequest;
  }): Promise<ThresholdEd25519HssRespondWithSessionResponse> {
    try {
      const respondStartedAt = Date.now();
      const parseStartedAt = Date.now();
      const rec = (input.request || {}) as unknown as Record<string, unknown>;
      const ceremony = this.getThresholdEd25519HssCeremony(rec.ceremonyHandle);
      if (!ceremony.ok) return ceremony;
      if (ceremony.value.kind !== 'session') {
        return { ok: false, code: 'invalid_body', message: 'ceremonyHandle scope mismatch' };
      }
      const clientRequest = parseThresholdEd25519HssServerVisibleClientRequestEnvelope(
        rec.clientRequest,
      );
      if (!clientRequest.ok) return clientRequest;

      const scopeError = this.validateThresholdEd25519HssSessionScope({
        claims: input.claims,
        relayerKeyId: ceremony.value.relayerKeyId,
        context: ceremony.value.context,
        preparedSession: ceremony.value.preparedSession,
      });
      if (scopeError) return scopeError;

      const parseMs = Date.now() - parseStartedAt;
      const serverInputs = ceremony.value.serverInputs;
      if (!serverInputs) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ceremonyHandle no longer retains relayer roots for respond',
        };
      }

      const wasmStartedAt = Date.now();
      const result = await prepareThresholdEd25519HssRoleSeparatedServerInputDelivery({
        operation: ceremony.value.operation,
        preparedServerSession: ceremony.value.preparedServerSession,
        expectedContextBindingB64u: ceremony.value.preparedSession.contextBindingB64u,
        clientRequest: clientRequest.value,
        serverInputs,
      });
      clearThresholdEd25519HssStoredServerInputs(serverInputs);
      delete ceremony.value.serverInputs;
      const wasmRespondMs = Date.now() - wasmStartedAt;
      const responsePayload = {
        ok: true,
        contextBindingB64u: result.serverInputDelivery.contextBindingB64u,
        serverInputDeliveryB64u: result.serverInputDelivery.serverInputDeliveryB64u,
      };

      this.logger?.info?.('[threshold-ed25519] hss respond timings', {
        relayerKeyId: ceremony.value.relayerKeyId,
        nearAccountId: ceremony.value.context.nearAccountId,
        requestBytes: jsonBytes(input.request || {}),
        clientRequestBytes: jsonBytes(clientRequest.value),
        clientRequestMessageBytes: utf8Bytes(clientRequest.value.clientRequestMessageB64u),
        clientRequestMessagePayloadBytes: base64UrlPayloadBytes(
          clientRequest.value.clientRequestMessageB64u,
        ),
        clientRequestMessageTransportOverheadBytes:
          utf8Bytes(clientRequest.value.clientRequestMessageB64u) -
          base64UrlPayloadBytes(clientRequest.value.clientRequestMessageB64u),
        parseMs,
        respondEngine: result.engine,
        wasmRespondMs,
        wasmRespondBreakdownMs: result.timings || null,
        responseBytes: jsonBytes(responsePayload),
        serverInputDeliveryBytes: utf8Bytes(result.serverInputDelivery.serverInputDeliveryB64u),
        serverInputDeliveryPayloadBytes: base64UrlPayloadBytes(
          result.serverInputDelivery.serverInputDeliveryB64u,
        ),
        ceremonyStateBytes: summarizeThresholdEd25519HssCeremonyRecordBytes(ceremony.value),
        totalMs: Date.now() - respondStartedAt,
      });

      return {
        ok: true,
        contextBindingB64u: result.serverInputDelivery.contextBindingB64u,
        serverInputDeliveryB64u: result.serverInputDelivery.serverInputDeliveryB64u,
        ...(result.timings ? { serverInputDeliveryTimings: result.timings } : {}),
      };
    } catch (e: unknown) {
      const msg = errorMessage(e);
      this.logger?.error?.('[threshold-ed25519] hss respond failed', { message: msg });
      return { ok: false, code: 'internal', message: msg };
    }
  }

  private async ed25519HssRespondForRegistration(input: {
    orgId: string;
    request: ThresholdEd25519HssRespondForRegistrationRequest;
  }): Promise<ThresholdEd25519HssRespondForRegistrationResponse> {
    try {
      const respondStartedAt = Date.now();
      const parseStartedAt = Date.now();
      const rec = (input.request || {}) as unknown as Record<string, unknown>;
      const newAccountId = toOptionalTrimmedString(rec.new_account_id);
      const rpId = toOptionalTrimmedString(rec.rp_id);
      if (!newAccountId) {
        return { ok: false, code: 'invalid_body', message: 'new_account_id is required' };
      }
      if (!rpId) {
        return { ok: false, code: 'invalid_body', message: 'rp_id is required' };
      }
      const ceremony = this.getThresholdEd25519HssCeremony(rec.ceremonyHandle);
      if (!ceremony.ok) return ceremony;
      if (ceremony.value.kind !== 'registration') {
        return { ok: false, code: 'invalid_body', message: 'ceremonyHandle scope mismatch' };
      }
      if (ceremony.value.newAccountId !== newAccountId || ceremony.value.rpId !== rpId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ceremonyHandle does not match registration scope',
        };
      }
      const clientRequest = parseThresholdEd25519HssServerVisibleClientRequestEnvelope(
        rec.clientRequest,
      );
      if (!clientRequest.ok) return clientRequest;

      const scopeError = this.validateThresholdEd25519HssRegistrationScope({
        orgId: ceremony.value.orgId,
        newAccountId,
        context: ceremony.value.context,
        preparedSession: ceremony.value.preparedSession,
      });
      if (scopeError) return scopeError;

      const parseMs = Date.now() - parseStartedAt;
      const serverInputs = ceremony.value.serverInputs;
      if (!serverInputs) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ceremonyHandle no longer retains relayer roots for respond',
        };
      }

      const wasmStartedAt = Date.now();
      const result = await prepareThresholdEd25519HssRoleSeparatedServerInputDelivery({
        operation: 'registration',
        preparedServerSession: ceremony.value.preparedServerSession,
        expectedContextBindingB64u: ceremony.value.preparedSession.contextBindingB64u,
        clientRequest: clientRequest.value,
        serverInputs,
      });
      clearThresholdEd25519HssStoredServerInputs(serverInputs);
      delete ceremony.value.serverInputs;
      const wasmRespondMs = Date.now() - wasmStartedAt;
      const responsePayload = {
        ok: true,
        contextBindingB64u: result.serverInputDelivery.contextBindingB64u,
        serverInputDeliveryB64u: result.serverInputDelivery.serverInputDeliveryB64u,
      };

      this.logger?.info?.('[threshold-ed25519][registration] hss respond timings', {
        nearAccountId: newAccountId,
        requestBytes: jsonBytes(input.request || {}),
        clientRequestBytes: jsonBytes(clientRequest.value),
        clientRequestMessageBytes: utf8Bytes(clientRequest.value.clientRequestMessageB64u),
        clientRequestMessagePayloadBytes: base64UrlPayloadBytes(
          clientRequest.value.clientRequestMessageB64u,
        ),
        clientRequestMessageTransportOverheadBytes:
          utf8Bytes(clientRequest.value.clientRequestMessageB64u) -
          base64UrlPayloadBytes(clientRequest.value.clientRequestMessageB64u),
        parseMs,
        respondEngine: result.engine,
        wasmRespondMs,
        wasmRespondBreakdownMs: result.timings || null,
        responseBytes: jsonBytes(responsePayload),
        serverInputDeliveryBytes: utf8Bytes(result.serverInputDelivery.serverInputDeliveryB64u),
        serverInputDeliveryPayloadBytes: base64UrlPayloadBytes(
          result.serverInputDelivery.serverInputDeliveryB64u,
        ),
        ceremonyStateBytes: summarizeThresholdEd25519HssCeremonyRecordBytes(ceremony.value),
        totalMs: Date.now() - respondStartedAt,
      });

      return {
        ok: true,
        contextBindingB64u: result.serverInputDelivery.contextBindingB64u,
        serverInputDeliveryB64u: result.serverInputDelivery.serverInputDeliveryB64u,
        ...(result.timings ? { serverInputDeliveryTimings: result.timings } : {}),
      };
    } catch (e: unknown) {
      const msg = errorMessage(e);
      this.logger?.error?.('[threshold-ed25519][registration] hss respond failed', {
        message: msg,
      });
      return { ok: false, code: 'internal', message: msg };
    }
  }

  private async ed25519HssFinalizeWithSession(input: {
    claims: ThresholdEd25519SessionClaims;
    request: ThresholdEd25519HssFinalizeWithSessionRequest;
  }): Promise<ThresholdEd25519HssFinalizeWithSessionResponse> {
    try {
      const finalizeStartedAt = Date.now();
      const parseStartedAt = Date.now();
      const rec = (input.request || {}) as unknown as Record<string, unknown>;
      const ceremony = this.getThresholdEd25519HssCeremony(rec.ceremonyHandle);
      if (!ceremony.ok) return ceremony;
      if (ceremony.value.kind !== 'session') {
        return { ok: false, code: 'invalid_body', message: 'ceremonyHandle scope mismatch' };
      }
      const evaluationResult = parseThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope(
        rec.evaluationResult,
      );
      if (!evaluationResult.ok) return evaluationResult;
      if (
        evaluationResult.value.contextBindingB64u !==
        ceremony.value.preparedSession.contextBindingB64u
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'evaluationResult context binding mismatch',
        };
      }

      const scopeError = this.validateThresholdEd25519HssSessionScope({
        claims: input.claims,
        relayerKeyId: ceremony.value.relayerKeyId,
        context: ceremony.value.context,
        preparedSession: ceremony.value.preparedSession,
      });
      if (scopeError) return scopeError;

      const parseMs = Date.now() - parseStartedAt;
      const ensureReadyStartedAt = Date.now();
      await this.ensureReady();

      const takenCeremony = this.takeThresholdEd25519HssCeremony(rec.ceremonyHandle);
      if (!takenCeremony.ok) return takenCeremony;
      if (takenCeremony.value.kind !== 'session') {
        return { ok: false, code: 'invalid_body', message: 'ceremonyHandle scope mismatch' };
      }
      try {
        const wasmStartedAt = Date.now();
        const result = await finalizeThresholdEd25519HssServerCeremony({
          operation: takenCeremony.value.operation,
          preparedSession: takenCeremony.value.preparedSession,
          preparedServerSession: takenCeremony.value.preparedServerSession,
          evaluationResult: {
            stagedEvaluatorArtifactBytes: base64UrlDecode(
              evaluationResult.value.stagedEvaluatorArtifactB64u,
            ),
          },
          expectedContextBindingB64u: takenCeremony.value.preparedSession.contextBindingB64u,
        });
        const relayerShareRepairStartedAt = Date.now();
        const repair = await this.maybeRepairRelayerKeyMaterialFromSessionHssFinalize({
          claims: input.claims,
          context: takenCeremony.value.context,
          preparedSession: takenCeremony.value.preparedSession,
          serverOutput: result.serverOutput,
        });
        const responsePayload = {
          finalizedReport: result.finalizedReport,
        };

        this.logger?.info?.('[threshold-ed25519] hss finalize timings', {
          relayerKeyId: ceremony.value.relayerKeyId,
          nearAccountId: ceremony.value.context.nearAccountId,
          requestBytes: jsonBytes(input.request || {}),
          evaluationResultBytes: utf8Bytes(evaluationResult.value.stagedEvaluatorArtifactB64u),
          evaluationResultPayloadBytes: base64UrlPayloadBytes(
            evaluationResult.value.stagedEvaluatorArtifactB64u,
          ),
          parseMs,
          ensureReadyMs: wasmStartedAt - ensureReadyStartedAt,
          wasmFinalizeMs: relayerShareRepairStartedAt - wasmStartedAt,
          relayerShareRepairMs: Date.now() - relayerShareRepairStartedAt,
          responseBytes: jsonBytes(responsePayload),
          finalizedReportBytes: jsonBytes(result.finalizedReport),
          relayerShareRepaired: repair.repaired,
          totalMs: Date.now() - finalizeStartedAt,
        });

        return {
          ok: true,
          finalizedReport: result.finalizedReport,
        };
      } finally {
        this.releaseThresholdEd25519HssCeremonyResources(takenCeremony.value);
      }
    } catch (e: unknown) {
      const msg = errorMessage(e);
      this.logger?.error?.('[threshold-ed25519] hss finalize failed', { message: msg });
      return { ok: false, code: 'internal', message: msg };
    }
  }

  private async ed25519HssFinalizeForRegistration(input: {
    orgId: string;
    request: ThresholdEd25519HssFinalizeForRegistrationRequest;
  }): Promise<ThresholdEd25519HssFinalizeForRegistrationResponse> {
    try {
      const finalizeStartedAt = Date.now();
      const parseStartedAt = Date.now();
      const rec = (input.request || {}) as unknown as Record<string, unknown>;
      const newAccountId = toOptionalTrimmedString(rec.new_account_id);
      const rpId = toOptionalTrimmedString(rec.rp_id);
      if (!newAccountId) {
        return { ok: false, code: 'invalid_body', message: 'new_account_id is required' };
      }
      if (!rpId) {
        return { ok: false, code: 'invalid_body', message: 'rp_id is required' };
      }
      const ceremony = this.getThresholdEd25519HssCeremony(rec.ceremonyHandle);
      if (!ceremony.ok) return ceremony;
      if (ceremony.value.kind !== 'registration') {
        return { ok: false, code: 'invalid_body', message: 'ceremonyHandle scope mismatch' };
      }
      const evaluationResult = parseThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope(
        rec.evaluationResult,
      );
      if (!evaluationResult.ok) return evaluationResult;
      if (
        evaluationResult.value.contextBindingB64u !==
        ceremony.value.preparedSession.contextBindingB64u
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'evaluationResult context binding mismatch',
        };
      }
      if (ceremony.value.newAccountId !== newAccountId || ceremony.value.rpId !== rpId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ceremonyHandle does not match registration scope',
        };
      }

      const scopeError = this.validateThresholdEd25519HssRegistrationScope({
        orgId: ceremony.value.orgId,
        newAccountId,
        context: ceremony.value.context,
        preparedSession: ceremony.value.preparedSession,
      });
      if (scopeError) return scopeError;

      const parseMs = Date.now() - parseStartedAt;

      await this.ensureReady();

      const takenCeremony = this.takeThresholdEd25519HssCeremony(rec.ceremonyHandle);
      if (!takenCeremony.ok) return takenCeremony;
      try {
        const hssFinalizeStartedAt = Date.now();
        const result = await finalizeThresholdEd25519HssServerCeremony({
          operation: 'registration',
          preparedSession: takenCeremony.value.preparedSession,
          preparedServerSession: takenCeremony.value.preparedServerSession,
          evaluationResult: {
            stagedEvaluatorArtifactBytes: base64UrlDecode(
              evaluationResult.value.stagedEvaluatorArtifactB64u,
            ),
          },
          expectedContextBindingB64u: takenCeremony.value.preparedSession.contextBindingB64u,
        });
        const registrationMaterialStartedAt = Date.now();
        const registrationMaterial =
          await deriveThresholdEd25519RegistrationMaterialFromHssFinalize({
            preparedSession: takenCeremony.value.preparedSession,
            preparedServerSession: takenCeremony.value.preparedServerSession,
            keyVersion: takenCeremony.value.context.keyVersion,
            finalizedReport: result.finalizedReport,
            serverOutput: result.serverOutput,
          });
        const keyStorePutStartedAt = Date.now();
        await this.keyStore.put(registrationMaterial.relayerKeyId, {
          nearAccountId: newAccountId,
          rpId,
          publicKey: registrationMaterial.publicKey,
          relayerSigningShareB64u: registrationMaterial.relayerSigningShareB64u,
          relayerVerifyingShareB64u: registrationMaterial.relayerVerifyingShareB64u,
          keyVersion: takenCeremony.value.context.keyVersion,
          recoveryExportCapable: true,
        });
        const keyStorePutMs = Date.now() - keyStorePutStartedAt;
        const responsePayload = {
          publicKey: registrationMaterial.publicKey,
          relayerKeyId: registrationMaterial.relayerKeyId,
          finalizedReport: result.finalizedReport,
        };
        this.logger?.info?.('[threshold-ed25519][registration] hss finalize timings', {
          nearAccountId: newAccountId,
          requestBytes: jsonBytes(input.request || {}),
          evaluationResultBytes: utf8Bytes(evaluationResult.value.stagedEvaluatorArtifactB64u),
          evaluationResultPayloadBytes: base64UrlPayloadBytes(
            evaluationResult.value.stagedEvaluatorArtifactB64u,
          ),
          parseMs,
          hssFinalizeMs: Date.now() - hssFinalizeStartedAt,
          registrationMaterialMs: keyStorePutStartedAt - registrationMaterialStartedAt,
          keyStorePutMs,
          responseBytes: jsonBytes(responsePayload),
          finalizedReportBytes: jsonBytes(result.finalizedReport),
          totalMs: Date.now() - finalizeStartedAt,
        });

        return {
          ok: true,
          publicKey: registrationMaterial.publicKey,
          relayerKeyId: registrationMaterial.relayerKeyId,
          finalizedReport: result.finalizedReport,
          finalizeReportTimings: {
            ...(result.finalizeReportTimings ?? {
              decodeArtifactMs: 0,
              serializedSessionMaterializeMs: 0,
              finalizeReportMs: 0,
              encodeReportMs: 0,
              openServerOutputMs: 0,
              openSeedOutputMs: 0,
              deriveSeedKeypairMs: 0,
              deriveRelayerVerifyingShareMs: 0,
              keyStorePutMs: 0,
            }),
            openSeedOutputMs: registrationMaterial.timings.openSeedOutputMs,
            deriveSeedKeypairMs: registrationMaterial.timings.deriveSeedKeypairMs,
            deriveRelayerVerifyingShareMs:
              registrationMaterial.timings.deriveRelayerVerifyingShareMs,
            keyStorePutMs,
          },
        };
      } finally {
        this.releaseThresholdEd25519HssCeremonyResources(takenCeremony.value);
      }
    } catch (e: unknown) {
      const msg = errorMessage(e);
      this.logger?.error?.('[threshold-ed25519][registration] hss finalize failed', {
        message: msg,
      });
      return { ok: false, code: 'internal', message: msg };
    }
  }

  // Signing round endpoints are exposed via SchemeModule.protocol (see `getSchemeModule`).
}
