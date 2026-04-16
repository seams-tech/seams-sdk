import type { NormalizedLogger } from '../logger';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { SessionClaims } from '../../router/relay';
import type { AccessKeyList } from '@/core/rpcClients/near/NearClient';
import type {
  ThresholdEcdsaIntegratedKeyStore,
  ThresholdEd25519KeyStore,
} from './stores/KeyStore';
import type { ThresholdEd25519SessionStore } from './stores/SessionStore';
import type {
  ThresholdEcdsaPresignSessionStore,
  ThresholdEcdsaPresignaturePool,
  ThresholdEcdsaSigningSessionStore,
} from './stores/EcdsaSigningStore';
import type { Ed25519AuthSessionStore, Ed25519AuthSessionRecord } from './stores/AuthSessionStore';
import type {
  ThresholdEd25519KeygenMaterial,
  ThresholdEd25519KeygenStrategy,
} from './keygenStrategy';
import { ThresholdEd25519KeygenStrategyV1 } from './keygenStrategy';
import type {
  VerifyAuthenticationResponse,
  WebAuthnAuthenticationCredential,
  ThresholdEd25519AuthorizeResponse,
  ThresholdEd25519SessionRequest,
  ThresholdEd25519SessionResponse,
  ThresholdEd25519AuthorizeWithSessionRequest,
  ThresholdEd25519HssCanonicalContext,
  ThresholdEd25519HssClientRequestEnvelope,
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
  ThresholdEcdsaHssFinalizeRequest,
  ThresholdEcdsaHssFinalizeResponse,
  ThresholdEcdsaHssOperation,
  ThresholdEcdsaHssPrepareRequest,
  ThresholdEcdsaHssPrepareResponse,
  ThresholdEcdsaHssRespondRequest,
  ThresholdEcdsaHssRespondResponse,
  ThresholdEcdsaIntegratedKeyRecord,
  EcdsaSessionPolicy,
  ThresholdEcdsaBootstrapSessionPolicy,
  ThresholdEcdsaAuthorizeWithSessionRequest,
  ThresholdEcdsaAuthorizeResponse,
  ThresholdEcdsaSignFinalizeRequest,
  ThresholdEcdsaSignFinalizeResponse,
  ThresholdEcdsaSignInitRequest,
  ThresholdEcdsaSignInitResponse,
  ThresholdEd25519CosignInitRequest,
  ThresholdEd25519CosignInitResponse,
  ThresholdEd25519CosignFinalizeRequest,
  ThresholdEd25519CosignFinalizeResponse,
  ThresholdEd25519SignInitRequest,
  ThresholdEd25519SignInitResponse,
  ThresholdEd25519SignFinalizeRequest,
  ThresholdEd25519SignFinalizeResponse,
  ThresholdEd25519KeyStoreConfigInput,
  ThresholdEcdsaPresignPoolPolicyHint,
} from '../types';
import {
  addSecp256k1PublicKeys33,
  ecdsaHssBootstrapNonExportSign,
  ecdsaHssExplicitExport,
  deriveThresholdSecp256k1RelayerShare,
  finalizeThresholdEcdsaHssServerReport,
  openThresholdEcdsaHssServerOutput,
  prepareThresholdEcdsaHssServerCeremony,
  prepareThresholdEcdsaHssServerSession,
  secp256k1PublicKey33ToEthereumAddress,
  validateSecp256k1PublicKey33,
} from './ethSignerWasm';
import {
  deriveThresholdEd25519HssServerInputs,
  deriveThresholdEd25519VerifyingShareFromSigningShare,
  deriveThresholdEd25519RegistrationMaterialFromHssFinalize,
  finalizeThresholdEd25519HssServerCeremony,
  prepareThresholdEd25519HssServerCeremony,
  prepareThresholdEd25519HssServerSession,
  releaseThresholdEd25519HssPreparedServerSession,
  releaseThresholdEd25519HssStagedEvaluatorArtifact,
} from './ed25519HssWasm';
import {
  threshold_ed25519_compute_delegate_signing_digest,
  threshold_ed25519_compute_near_tx_signing_digests,
  threshold_ed25519_compute_nep413_signing_digest,
} from '../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import {
  ensureRelayerKeyIsActiveAccessKey,
  extractAuthorizeSigningPublicKey,
  isObject,
  normalizeByteArray32,
  parseAppSessionClaims,
  parseThresholdEcdsaSessionClaims,
  parseThresholdEd25519SessionClaims,
  type ThresholdEd25519SessionClaims,
  type ThresholdEcdsaSessionClaims,
  verifyThresholdEd25519AuthorizeSigningPayloadSigningDigestOnly,
} from './validation';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import {
  normalizeThresholdEd25519ParticipantId,
  normalizeThresholdEd25519ParticipantIds,
} from '@shared/threshold/participants';
import {
  coerceThresholdNodeRole,
  parseThresholdCoordinatorPeers,
  parseThresholdCoordinatorSharedSecretBytes,
  parseThresholdEd25519ParticipantIds2p,
  parseThresholdRelayerCosignerThreshold,
  parseThresholdRelayerCosigners,
  validateThresholdEd25519MasterSecretB64u,
  validateThresholdSecp256k1MasterSecretB64u,
} from './config';
import { ThresholdEcdsaSigningHandlers } from './ecdsaSigningHandlers';
import { ThresholdEd25519SigningHandlers } from './signingHandlers';
import { resolveThresholdEd25519RelayerKeyMaterial } from './relayerKeyMaterial';
import {
  computeThresholdEcdsaHssRequestDigestB64u,
  createOpaqueBase64Envelope,
  parseThresholdEcdsaHssHiddenEvalClientRequestEnvelope,
  parseThresholdEcdsaHssHiddenEvalFinalizeEnvelope,
  parseThresholdEcdsaHssHiddenEvalServerResponseEnvelope,
} from './ecdsaHssTransport';
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

type ParseOk<T> = { ok: true; value: T };
type ParseErr = { ok: false; code: string; message: string };
type ParseResult<T> = ParseOk<T> | ParseErr;
type ThresholdEd25519HssSessionError = { ok: false; code?: string; message?: string };

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

type ThresholdEcdsaHssCeremonyRecord = {
  expiresAtMs: number;
  userId: string;
  rpId: string;
  operation: ThresholdEcdsaHssOperation;
  ecdsaThresholdKeyId?: string;
  preparedServerSessionB64u: string;
  serverAssistInitB64u: string;
  keygenSessionId?: string;
  sessionPolicy?: ThresholdEcdsaBootstrapSessionPolicy;
  sessionKind?: 'jwt' | 'cookie';
  webauthnAuthentication?: WebAuthnAuthenticationCredential;
  ed25519SessionClaims?: Record<string, unknown>;
  appSessionClaims?: Record<string, unknown>;
  ecdsaSessionClaims?: Record<string, unknown>;
  requestMessageB64u?: string;
  responseMessageB64u?: string;
};

type ThresholdEcdsaBootstrapSessionResult =
  | {
      ok: true;
      sessionId: string;
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

function errorMessage(error: unknown): string {
  return String(
    error && typeof error === 'object' && 'message' in error
      ? (error as { message?: unknown }).message
      : error || '',
  );
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

const THRESHOLD_ECDSA_HSS_KEY_PURPOSE_V1 = 'evm-signing';
const THRESHOLD_ECDSA_HSS_KEY_VERSION_V1 = 'v1';

type DerivedEcdsaKeyMaterial = {
  participantIds: number[];
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  clientAdditiveShare32B64u: string;
  thresholdEcdsaPublicKeyB64u: string;
  ethereumAddress: string;
  relayerVerifyingShareB64u: string;
  relayerRootShare32B64u: string;
  relayerBackendInputB64u: string;
};

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
      ? record.evaluationResult.stagedEvaluatorArtifactBytes?.byteLength ??
        utf8Bytes(record.evaluationResult.stagedEvaluatorArtifactHandle || '')
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
        ceremonyAddStageMs?: number;
        ceremonyMessageScheduleMs?: number;
        ceremonyRoundCoreMs?: number;
        ceremonyOutputProjectorMs?: number;
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

function parseOptionalBoolean(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') return value;
  const raw = toOptionalTrimmedString(value);
  if (!raw) return undefined;
  const normalized = raw.toLowerCase();
  if (normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on') {
    return true;
  }
  if (normalized === '0' || normalized === 'false' || normalized === 'no' || normalized === 'off') {
    return false;
  }
  return undefined;
}

function parseOptionalIntInRange(value: unknown, min: number, max: number): number | undefined {
  const raw = toOptionalTrimmedString(value);
  if (!raw) return undefined;
  const parsed = Math.floor(Number(raw));
  if (!Number.isFinite(parsed)) return undefined;
  if (parsed < min || parsed > max) return undefined;
  return parsed;
}

function parseThresholdEcdsaPresignPoolPolicyHint(
  config: Record<string, unknown>,
): ThresholdEcdsaPresignPoolPolicyHint | undefined {
  const hint: ThresholdEcdsaPresignPoolPolicyHint = {
    ...(parseOptionalBoolean(config.THRESHOLD_ECDSA_PRESIGN_POOL_HINT_ENABLED) !== undefined
      ? { enabled: parseOptionalBoolean(config.THRESHOLD_ECDSA_PRESIGN_POOL_HINT_ENABLED) }
      : {}),
    ...(parseOptionalIntInRange(config.THRESHOLD_ECDSA_PRESIGN_POOL_HINT_TARGET_DEPTH, 1, 64) !==
    undefined
      ? {
          targetDepth: parseOptionalIntInRange(
            config.THRESHOLD_ECDSA_PRESIGN_POOL_HINT_TARGET_DEPTH,
            1,
            64,
          ),
        }
      : {}),
    ...(parseOptionalIntInRange(config.THRESHOLD_ECDSA_PRESIGN_POOL_HINT_LOW_WATERMARK, 0, 64) !==
    undefined
      ? {
          lowWatermark: parseOptionalIntInRange(
            config.THRESHOLD_ECDSA_PRESIGN_POOL_HINT_LOW_WATERMARK,
            0,
            64,
          ),
        }
      : {}),
    ...(parseOptionalIntInRange(
      config.THRESHOLD_ECDSA_PRESIGN_POOL_HINT_MAX_REFILL_IN_FLIGHT,
      1,
      8,
    ) !== undefined
      ? {
          maxRefillInFlight: parseOptionalIntInRange(
            config.THRESHOLD_ECDSA_PRESIGN_POOL_HINT_MAX_REFILL_IN_FLIGHT,
            1,
            8,
          ),
        }
      : {}),
    ...(parseOptionalIntInRange(
      config.THRESHOLD_ECDSA_PRESIGN_POOL_HINT_REFILL_ATTEMPT_TIMEOUT_MS,
      5_000,
      120_000,
    ) !== undefined
      ? {
          refillAttemptTimeoutMs: parseOptionalIntInRange(
            config.THRESHOLD_ECDSA_PRESIGN_POOL_HINT_REFILL_ATTEMPT_TIMEOUT_MS,
            5_000,
            120_000,
          ),
        }
      : {}),
  };
  return Object.keys(hint).length ? hint : undefined;
}

function parseThresholdEd25519AuthorizeWithSessionRequest(
  request: ThresholdEd25519AuthorizeWithSessionRequest,
): ParseResult<{
  relayerKeyId: string;
  purpose: string;
  signingDigest32: Uint8Array;
  signingPayload: unknown;
}> {
  const rec = (request || {}) as unknown as Record<string, unknown>;
  const relayerKeyId = toOptionalTrimmedString(rec.relayerKeyId);
  if (!relayerKeyId)
    return { ok: false, code: 'invalid_body', message: 'relayerKeyId is required' };
  const purpose = toOptionalTrimmedString(rec.purpose);
  if (!purpose) return { ok: false, code: 'invalid_body', message: 'purpose is required' };
  const signingDigest32 = normalizeByteArray32(rec.signing_digest_32);
  if (!signingDigest32) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'signing_digest_32 (32 bytes) is required for threshold authorization',
    };
  }
  return {
    ok: true,
    value: {
      relayerKeyId,
      purpose,
      signingDigest32,
      signingPayload: rec.signingPayload,
    },
  };
}

function parseThresholdEd25519SessionRequest(
  request: ThresholdEd25519SessionRequest,
  participantIds2p: number[],
): ParseResult<{
  relayerKeyId: string;
  nearAccountId: string;
  rpId: string;
  sessionId: string;
  ttlMsRaw: number;
  remainingUsesRaw: number;
  policyParticipantIds: number[] | null;
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
  const policyRelayerKeyId = toOptionalTrimmedString(
    (policyRaw as Record<string, unknown>).relayerKeyId,
  );
  const ttlMsRaw = Number((policyRaw as Record<string, unknown>).ttlMs);
  const remainingUsesRaw = Number((policyRaw as Record<string, unknown>).remainingUses);
  if (!nearAccountId || !rpId || !sessionId || !policyRelayerKeyId) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'sessionPolicy{nearAccountId,rpId,relayerKeyId,sessionId} are required',
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
      ttlMsRaw,
      remainingUsesRaw,
      policyParticipantIds: policyParticipantIds || null,
    },
  };
}

function parseThresholdEd25519HssCanonicalContext(
  raw: unknown,
): ParseResult<ThresholdEd25519HssCanonicalContext> {
  if (!isObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'context is required' };
  }
  const orgId = toOptionalTrimmedString(raw.orgId);
  const nearAccountId = toOptionalTrimmedString(raw.nearAccountId);
  const keyPurpose = toOptionalTrimmedString(raw.keyPurpose);
  const keyVersion = toOptionalTrimmedString(raw.keyVersion);
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds);
  const derivationVersion = Number(raw.derivationVersion);
  if (!orgId) return { ok: false, code: 'invalid_body', message: 'context.orgId is required' };
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
      orgId,
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

function parseThresholdEd25519HssClientRequestEnvelope(
  raw: unknown,
): ParseResult<ThresholdEd25519HssClientRequestEnvelope> {
  if (!isObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'clientRequest is required' };
  }
  const clientRequestMessageB64u = toOptionalTrimmedString(raw.clientRequestMessageB64u);
  const evaluatorOtStateB64u = toOptionalTrimmedString(raw.evaluatorOtStateB64u);
  if (!clientRequestMessageB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'clientRequest.clientRequestMessageB64u is required',
    };
  }
  if (!evaluatorOtStateB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'clientRequest.evaluatorOtStateB64u is required',
    };
  }
  return {
    ok: true,
    value: { clientRequestMessageB64u, evaluatorOtStateB64u },
  };
}

function haveSameParticipantIds(a: number[], b: number[]): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function parseThresholdEcdsaAuthorizeWithSessionRequest(
  request: ThresholdEcdsaAuthorizeWithSessionRequest,
): ParseResult<{
  ecdsaThresholdKeyId: string;
  purpose: string;
  signingDigest32: Uint8Array;
  signingPayload: unknown;
}> {
  const rec = (request || {}) as unknown as Record<string, unknown>;
  const ecdsaThresholdKeyId = toOptionalTrimmedString(rec.ecdsaThresholdKeyId);
  if (!ecdsaThresholdKeyId) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'ecdsaThresholdKeyId is required',
    };
  }
  const purpose = toOptionalTrimmedString(rec.purpose);
  if (!purpose) return { ok: false, code: 'invalid_body', message: 'purpose is required' };
  const signingDigest32 = normalizeByteArray32(rec.signing_digest_32);
  if (!signingDigest32) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'signing_digest_32 (32 bytes) is required for threshold authorization',
    };
  }
  return {
    ok: true,
    value: {
      ecdsaThresholdKeyId,
      purpose,
      signingDigest32,
      signingPayload: rec.signingPayload,
    },
  };
}

export class ThresholdSigningService {
  private readonly logger: NormalizedLogger;
  private readonly keyStore: ThresholdEd25519KeyStore;
  private readonly sessionStore: ThresholdEd25519SessionStore;
  private readonly authSessionStore: Ed25519AuthSessionStore;
  private readonly ecdsaKeyStore: ThresholdEcdsaIntegratedKeyStore;
  private readonly ecdsaSessionStore: ThresholdEd25519SessionStore;
  private readonly ecdsaAuthSessionStore: Ed25519AuthSessionStore;
  private readonly clientParticipantId: number;
  private readonly relayerParticipantId: number;
  private readonly participantIds2p: number[];
  private readonly ed25519MasterSecretB64u: string | null;
  private readonly secp256k1MasterSecretB64u: string | null;
  private readonly keygenStrategy: ThresholdEd25519KeygenStrategy;
  private readonly signingHandlers: ThresholdEd25519SigningHandlers;
  private readonly ecdsaSigningSessionStore: ThresholdEcdsaSigningSessionStore;
  private readonly ecdsaPresignSessionStore: ThresholdEcdsaPresignSessionStore;
  private readonly ecdsaPresignaturePool: ThresholdEcdsaPresignaturePool;
  private readonly ecdsaPresignPoolPolicyHint: ThresholdEcdsaPresignPoolPolicyHint | undefined;
  private readonly ecdsaSigningHandlers: ThresholdEcdsaSigningHandlers;
  private readonly ensureReady: () => Promise<void>;
  private readonly ensureSignerWasm: () => Promise<void>;
  private readonly verifyWebAuthnAuthenticationLite:
    | ((request: {
        nearAccountId: string;
        rpId: string;
        expectedChallenge: string;
        webauthn_authentication: WebAuthnAuthenticationCredential;
      }) => Promise<VerifyAuthenticationResponse>)
    | null;
  private readonly viewAccessKeyList: (accountId: string) => Promise<AccessKeyList>;
  private readonly ed25519HssCeremonyTtlMs = 2 * 60_000;
  private readonly ed25519HssCeremonyStore = new Map<string, ThresholdEd25519HssCeremonyRecord>();
  private readonly ecdsaHssCeremonyTtlMs = 2 * 60_000;
  private readonly ecdsaHssCeremonyStore = new Map<string, ThresholdEcdsaHssCeremonyRecord>();
  private cachedSchemeModules: Partial<Record<ThresholdSchemeId, ThresholdAnySchemeModule>> | null =
    null;

  readonly ed25519Hss = {
    prepareForRegistration: async (input: {
      orgId: string;
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
      const claims = parseThresholdEd25519SessionClaims(input.claims);
      if (!claims) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Invalid threshold session token claims',
        };
      }
      return this.ed25519HssPrepareWithSession({ claims, request: input.request });
    },
    respondWithSession: async (input: {
      claims: SessionClaims;
      request: ThresholdEd25519HssRespondWithSessionRequest;
    }): Promise<ThresholdEd25519HssRespondWithSessionResponse> => {
      const claims = parseThresholdEd25519SessionClaims(input.claims);
      if (!claims) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Invalid threshold session token claims',
        };
      }
      return this.ed25519HssRespondWithSession({ claims, request: input.request });
    },
    finalizeWithSession: async (input: {
      claims: SessionClaims;
      request: ThresholdEd25519HssFinalizeWithSessionRequest;
    }): Promise<ThresholdEd25519HssFinalizeWithSessionResponse> => {
      const claims = parseThresholdEd25519SessionClaims(input.claims);
      if (!claims) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Invalid threshold session token claims',
        };
      }
      return this.ed25519HssFinalizeWithSession({ claims, request: input.request });
    },
  };

  readonly ecdsaHss = {
    prepare: async (
      request: ThresholdEcdsaHssPrepareRequest,
    ): Promise<ThresholdEcdsaHssPrepareResponse> => {
      return this.ecdsaHssPrepare(request);
    },
    respond: async (
      request: ThresholdEcdsaHssRespondRequest,
    ): Promise<ThresholdEcdsaHssRespondResponse> => {
      return this.ecdsaHssRespond(request);
    },
    finalize: async (
      request: ThresholdEcdsaHssFinalizeRequest,
    ): Promise<ThresholdEcdsaHssFinalizeResponse> => {
      return this.ecdsaHssFinalize(request);
    },
  };

  constructor(input: {
    logger: NormalizedLogger;
    keyStore: ThresholdEd25519KeyStore;
    sessionStore: ThresholdEd25519SessionStore;
    authSessionStore: Ed25519AuthSessionStore;
    ecdsaKeyStore: ThresholdEcdsaIntegratedKeyStore;
    ecdsaSessionStore: ThresholdEd25519SessionStore;
    ecdsaAuthSessionStore: Ed25519AuthSessionStore;
    ecdsaSigningSessionStore: ThresholdEcdsaSigningSessionStore;
    ecdsaPresignSessionStore: ThresholdEcdsaPresignSessionStore;
    ecdsaPresignaturePool: ThresholdEcdsaPresignaturePool;
    config?: ThresholdEd25519KeyStoreConfigInput | null;
    ensureReady: () => Promise<void>;
    ensureSignerWasm: () => Promise<void>;
    verifyWebAuthnAuthenticationLite?: (request: {
      nearAccountId: string;
      rpId: string;
      expectedChallenge: string;
      webauthn_authentication: WebAuthnAuthenticationCredential;
    }) => Promise<VerifyAuthenticationResponse>;
    viewAccessKeyList: (accountId: string) => Promise<AccessKeyList>;
  }) {
    this.logger = input.logger;
    this.keyStore = input.keyStore;
    this.sessionStore = input.sessionStore;
    this.authSessionStore = input.authSessionStore;
    this.ecdsaKeyStore = input.ecdsaKeyStore;
    this.ecdsaSessionStore = input.ecdsaSessionStore;
    this.ecdsaAuthSessionStore = input.ecdsaAuthSessionStore;
    this.ecdsaSigningSessionStore = input.ecdsaSigningSessionStore;
    this.ecdsaPresignSessionStore = input.ecdsaPresignSessionStore;
    this.ecdsaPresignaturePool = input.ecdsaPresignaturePool;
    const cfg = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
    this.ecdsaPresignPoolPolicyHint = parseThresholdEcdsaPresignPoolPolicyHint(cfg);

    const nodeRole = coerceThresholdNodeRole(cfg.THRESHOLD_NODE_ROLE);
    const coordinatorSharedSecretBytes = parseThresholdCoordinatorSharedSecretBytes(
      cfg.THRESHOLD_COORDINATOR_SHARED_SECRET_B64U,
    );
    const coordinatorInstanceId = toOptionalTrimmedString(cfg.THRESHOLD_COORDINATOR_INSTANCE_ID);
    const coordinatorPeers = parseThresholdCoordinatorPeers(cfg.THRESHOLD_COORDINATOR_PEERS) || [];
    const relayerCosigners =
      parseThresholdRelayerCosigners(cfg.THRESHOLD_ED25519_RELAYER_COSIGNERS) || [];
    const relayerCosignerThreshold = parseThresholdRelayerCosignerThreshold(
      cfg.THRESHOLD_ED25519_RELAYER_COSIGNER_T,
    );
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

    this.ed25519MasterSecretB64u = validateThresholdEd25519MasterSecretB64u(
      cfg.THRESHOLD_ED25519_MASTER_SECRET_B64U,
    );
    this.secp256k1MasterSecretB64u = validateThresholdSecp256k1MasterSecretB64u(
      cfg.THRESHOLD_SECP256K1_MASTER_SECRET_B64U,
    );
    this.ensureReady = input.ensureReady;
    this.ensureSignerWasm = input.ensureSignerWasm;
    this.verifyWebAuthnAuthenticationLite = input.verifyWebAuthnAuthenticationLite || null;
    this.viewAccessKeyList = input.viewAccessKeyList;
    this.keygenStrategy = new ThresholdEd25519KeygenStrategyV1({
      clientParticipantId: this.clientParticipantId,
      relayerParticipantId: this.relayerParticipantId,
    });
    this.signingHandlers = new ThresholdEd25519SigningHandlers({
      logger: this.logger,
      nodeRole,
      relayerCosigners,
      relayerCosignerThreshold,
      relayerCosignerId,
      coordinatorSharedSecretBytes,
      clientParticipantId: this.clientParticipantId,
      relayerParticipantId: this.relayerParticipantId,
      participantIds2p: this.participantIds2p,
      sessionStore: this.sessionStore,
      ensureReady: this.ensureReady,
      ensureSignerWasm: this.ensureSignerWasm,
      viewAccessKeyList: this.viewAccessKeyList,
      resolveRelayerKeyMaterial: (args) => this.resolveRelayerKeyMaterial(args),
    });

    this.ecdsaSigningHandlers = new ThresholdEcdsaSigningHandlers({
      logger: this.logger,
      nodeRole,
      participantIds2p: this.participantIds2p,
      clientParticipantId: this.clientParticipantId,
      relayerParticipantId: this.relayerParticipantId,
      secp256k1MasterSecretB64u: this.secp256k1MasterSecretB64u,
      coordinatorInstanceId: coordinatorInstanceId || null,
      coordinatorPeers,
      sessionStore: this.ecdsaSessionStore,
      signingSessionStore: this.ecdsaSigningSessionStore,
      presignSessionStore: this.ecdsaPresignSessionStore,
      presignaturePool: this.ecdsaPresignaturePool,
      resolveIntegratedKeyRecord: async ({ ecdsaThresholdKeyId }) =>
        this.getEcdsaIntegratedKeyRecord(ecdsaThresholdKeyId),
      ensureReady: this.ensureReady,
      createSigningSessionId: () => this.createThresholdEcdsaSigningSessionId(),
      createPresignSessionId: () => this.createThresholdEcdsaPresignSessionId(),
    });
  }

  private createThresholdEd25519HssCeremonyHandle(): string {
    return base64UrlEncode(randomBytes(18));
  }

  private createThresholdEcdsaHssCeremonyHandle(): string {
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

  private cleanupExpiredThresholdEcdsaHssCeremonies(nowMs = Date.now()): void {
    for (const [handle, record] of this.ecdsaHssCeremonyStore.entries()) {
      if (record.expiresAtMs <= nowMs) {
        this.ecdsaHssCeremonyStore.delete(handle);
      }
    }
  }

  private storeThresholdEd25519HssCeremony(
    record: ThresholdEd25519HssCeremonyRecordInput,
  ): string {
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

  private storeThresholdEcdsaHssCeremony(
    record: Omit<ThresholdEcdsaHssCeremonyRecord, 'expiresAtMs'>,
  ): string {
    const nowMs = Date.now();
    this.cleanupExpiredThresholdEcdsaHssCeremonies(nowMs);
    const ceremonyId = this.createThresholdEcdsaHssCeremonyHandle();
    this.ecdsaHssCeremonyStore.set(ceremonyId, {
      ...record,
      expiresAtMs: nowMs + this.ecdsaHssCeremonyTtlMs,
    });
    return ceremonyId;
  }

  private getThresholdEcdsaHssCeremony(
    ceremonyIdRaw: unknown,
  ): ParseResult<ThresholdEcdsaHssCeremonyRecord> {
    const ceremonyId = toOptionalTrimmedString(ceremonyIdRaw);
    if (!ceremonyId) {
      return { ok: false, code: 'invalid_body', message: 'ceremonyId is required' };
    }
    this.cleanupExpiredThresholdEcdsaHssCeremonies();
    const record = this.ecdsaHssCeremonyStore.get(ceremonyId);
    if (!record) {
      return { ok: false, code: 'invalid_body', message: 'ceremonyId is invalid or expired' };
    }
    return { ok: true, value: record };
  }

  private takeThresholdEcdsaHssCeremony(
    ceremonyIdRaw: unknown,
  ): ParseResult<ThresholdEcdsaHssCeremonyRecord> {
    const ceremonyId = toOptionalTrimmedString(ceremonyIdRaw);
    if (!ceremonyId) {
      return { ok: false, code: 'invalid_body', message: 'ceremonyId is required' };
    }
    this.cleanupExpiredThresholdEcdsaHssCeremonies();
    const record = this.ecdsaHssCeremonyStore.get(ceremonyId);
    if (!record) {
      return { ok: false, code: 'invalid_body', message: 'ceremonyId is invalid or expired' };
    }
    this.ecdsaHssCeremonyStore.delete(ceremonyId);
    return { ok: true, value: record };
  }

  private async computeEcdsaThresholdKeyId(input: {
    userId: string;
    rpId: string;
    thresholdEcdsaPublicKeyB64u: string;
  }): Promise<string> {
    const digest32 = await sha256BytesUtf8(
      alphabetizeStringify({
        version: 'threshold_ecdsa_hss_key_id_v1',
        schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
        userId: input.userId,
        rpId: input.rpId,
        thresholdEcdsaPublicKeyB64u: input.thresholdEcdsaPublicKeyB64u,
      }),
    );
    return `ehss-${base64UrlEncode(digest32)}`;
  }

  private async computeEcdsaHssRelayerKeyId(input: {
    userId: string;
    rpId: string;
  }): Promise<string> {
    const digest32 = await sha256BytesUtf8(
      alphabetizeStringify({
        version: 'threshold_ecdsa_hss_relayer_key_id_v1',
        schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
        userId: input.userId,
        rpId: input.rpId,
      }),
    );
    return `ehss-relayer-${base64UrlEncode(digest32)}`;
  }

  private async upsertIntegratedEcdsaKeyRecord(input: {
    userId: string;
    rpId: string;
    clientVerifyingShareB64u: string;
    thresholdEcdsaPublicKeyB64u: string;
    ethereumAddress: string;
    participantIds?: number[];
    relayerKeyId?: string;
    relayerVerifyingShareB64u?: string;
    relayerRootShare32B64u: string;
    relayerBackendInputB64u: string;
  }): Promise<string> {
    const ecdsaThresholdKeyId = await this.computeEcdsaThresholdKeyId({
      userId: input.userId,
      rpId: input.rpId,
      thresholdEcdsaPublicKeyB64u: input.thresholdEcdsaPublicKeyB64u,
    });
    const existing = await this.ecdsaKeyStore.get(ecdsaThresholdKeyId);
    const nowMs = Date.now();
    await this.ecdsaKeyStore.put(ecdsaThresholdKeyId, {
      version: 'threshold_ecdsa_hss_key_v1',
      ecdsaThresholdKeyId,
      userId: input.userId,
      rpId: input.rpId,
      schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
      clientVerifyingShareB64u: input.clientVerifyingShareB64u,
      thresholdEcdsaPublicKeyB64u: input.thresholdEcdsaPublicKeyB64u,
      ethereumAddress: input.ethereumAddress,
      participantIds: Array.isArray(input.participantIds) ? [...input.participantIds] : [],
      ...(toOptionalTrimmedString(input.relayerKeyId)
        ? { relayerKeyId: toOptionalTrimmedString(input.relayerKeyId)! }
        : {}),
      ...(toOptionalTrimmedString(input.relayerVerifyingShareB64u)
        ? {
            relayerVerifyingShareB64u: toOptionalTrimmedString(input.relayerVerifyingShareB64u)!,
          }
        : {}),
      relayerRootShare32B64u: input.relayerRootShare32B64u,
      relayerBackendInputB64u: input.relayerBackendInputB64u,
      createdAtMs: existing?.createdAtMs ?? nowMs,
      updatedAtMs: nowMs,
    });
    return ecdsaThresholdKeyId;
  }

  private async getEcdsaIntegratedKeyRecord(
    ecdsaThresholdKeyIdRaw: string,
  ): Promise<ThresholdEcdsaIntegratedKeyRecord | null> {
    const ecdsaThresholdKeyId = toOptionalTrimmedString(ecdsaThresholdKeyIdRaw);
    if (!ecdsaThresholdKeyId) return null;
    return await this.ecdsaKeyStore.get(ecdsaThresholdKeyId);
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
          authorize: (input) => this.ed25519AuthorizeWithSession(input),
          protocol: {
            signInit: (request) => this.signingHandlers.thresholdEd25519SignInit(request),
            signFinalize: (request) => this.signingHandlers.thresholdEd25519SignFinalize(request),
            internalCosignInit: (request) =>
              this.signingHandlers.thresholdEd25519CosignInit(request),
            internalCosignFinalize: (request) =>
              this.signingHandlers.thresholdEd25519CosignFinalize(request),
          },
        });
      }
      if (schemeId === THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID) {
        return createThresholdSecp256k1Ecdsa2pSchemeModule({
          hss: {
            prepare: (request) => this.ecdsaHssPrepare(request),
            respond: (request) => this.ecdsaHssRespond(request),
            finalize: (request) => this.ecdsaHssFinalize(request),
          },
          authorize: (input) => this.ecdsaAuthorizeWithSession(input),
          presign: {
            init: (input) => this.ecdsaSigningHandlers.ecdsaPresignInit(input),
            step: (input) => this.ecdsaSigningHandlers.ecdsaPresignStep(input),
          },
          protocol: {
            signInit: (
              request: ThresholdEcdsaSignInitRequest,
            ): Promise<ThresholdEcdsaSignInitResponse> =>
              this.ecdsaSigningHandlers.ecdsaSignInit(request),
            signFinalize: (
              request: ThresholdEcdsaSignFinalizeRequest,
            ): Promise<ThresholdEcdsaSignFinalizeResponse> =>
              this.ecdsaSigningHandlers.ecdsaSignFinalize(request),
          },
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
    const nearAccountId = toOptionalTrimmedString(input.claims.sub);
    const rpId = toOptionalTrimmedString(input.claims.rpId);
    const keyVersion = toOptionalTrimmedString(input.context.keyVersion);
    const relayerSigningShareB64u = toOptionalTrimmedString(input.serverOutput.xRelayerBaseB64u);
    if (!relayerKeyId || !nearAccountId || !rpId || !keyVersion || !relayerSigningShareB64u) {
      throw new Error('[threshold-ed25519] missing scope while attempting relayer share self-heal');
    }

    const existing = await this.keyStore.get(relayerKeyId);
    if (existing) {
      return { repaired: false };
    }

    const startedAt = Date.now();
    try {
      const relayerVerifyingShare = await deriveThresholdEd25519VerifyingShareFromSigningShare({
        signingShareB64u: relayerSigningShareB64u,
      });
      await this.keyStore.put(relayerKeyId, {
        nearAccountId,
        rpId,
        publicKey: relayerKeyId,
        relayerSigningShareB64u,
        relayerVerifyingShareB64u: relayerVerifyingShare.verifyingShareB64u,
        keyVersion,
        recoveryExportCapable: true,
      });
      this.logger?.warn?.('[threshold-ed25519] relayer share self-heal', {
        relayerKeyId,
        nearAccountId,
        rpId,
        keyVersion,
        durationMs: Date.now() - startedAt,
        outcome: 'success',
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

  private async putAuthSessionRecord(input: {
    store: Ed25519AuthSessionStore;
    sessionId: string;
    record: Ed25519AuthSessionRecord;
    ttlMs: number;
    remainingUses: number;
  }): Promise<void> {
    await input.store.putSession(input.sessionId, input.record, {
      ttlMs: input.ttlMs,
      remainingUses: input.remainingUses,
    });
  }

  private createThresholdEd25519MpcSessionId(): string {
    const id =
      typeof globalThis.crypto?.randomUUID === 'function'
        ? globalThis.crypto.randomUUID()
        : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    return `mpc-${id}`;
  }

  private createThresholdEcdsaMpcSessionId(): string {
    const id =
      typeof globalThis.crypto?.randomUUID === 'function'
        ? globalThis.crypto.randomUUID()
        : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    return `ecdsa-mpc-${id}`;
  }

  private createThresholdEcdsaSigningSessionId(): string {
    const id =
      typeof globalThis.crypto?.randomUUID === 'function'
        ? globalThis.crypto.randomUUID()
        : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    return `ecdsa-sign-${id}`;
  }

  private createThresholdEcdsaPresignSessionId(): string {
    const id =
      typeof globalThis.crypto?.randomUUID === 'function'
        ? globalThis.crypto.randomUUID()
        : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    return `ecdsa-presign-${id}`;
  }

  private createThresholdEd25519SigningSessionId(): string {
    const id =
      typeof globalThis.crypto?.randomUUID === 'function'
        ? globalThis.crypto.randomUUID()
        : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    return `sign-${id}`;
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
      const runtimeSnapshotScope = (() => {
        const raw = policy.runtimeSnapshotScope;
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
        const orgId = toOptionalTrimmedString((raw as { orgId?: unknown }).orgId);
        const environmentId = toOptionalTrimmedString(
          (raw as { environmentId?: unknown }).environmentId,
        );
        const projectId = toOptionalTrimmedString((raw as { projectId?: unknown }).projectId);
        if (!orgId || !environmentId) return undefined;
        return {
          orgId,
          environmentId,
          ...(projectId ? { projectId } : {}),
        };
      })();
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

      const existingSession = await this.authSessionStore.getSession(sessionId);
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
        return {
          ok: true,
          sessionId,
          expiresAtMs: existingSession.expiresAtMs,
          expiresAt: new Date(existingSession.expiresAtMs).toISOString(),
          participantIds: existingSession.participantIds,
          ...(runtimeSnapshotScope ? { runtimeSnapshotScope } : {}),
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
      await this.putAuthSessionRecord({
        store: this.authSessionStore,
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

      return {
        ok: true,
        sessionId,
        expiresAtMs,
        expiresAt: new Date(expiresAtMs).toISOString(),
        participantIds,
        remainingUses,
        ...(runtimeSnapshotScope ? { runtimeSnapshotScope } : {}),
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

  async bootstrapEcdsaFromRegistrationMaterial(input: {
    userId: string;
    rpId: string;
    clientRootShare32B64u: string;
    sessionPolicy: Record<string, unknown>;
  }): Promise<ThresholdEcdsaHssFinalizeResponse> {
    return await this.bootstrapEcdsaFromClientRootShare({
      userId: input.userId,
      rpId: input.rpId,
      clientRootShare32B64u: input.clientRootShare32B64u,
      sessionPolicy: input.sessionPolicy,
    });
  }

  private parseClientRootShare32(
    clientRootShare32B64uRaw: string,
  ): ParseResult<Uint8Array> {
    const clientRootShare32B64u = String(clientRootShare32B64uRaw || '').trim();
    if (!clientRootShare32B64u) {
      return { ok: false, code: 'invalid_body', message: 'clientRootShare32B64u is required' };
    }
    try {
      const yClient32Le = base64UrlDecode(clientRootShare32B64u);
      if (yClient32Le.length !== 32) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'clientRootShare32B64u must decode to 32 bytes',
        };
      }
      return { ok: true, value: yClient32Le };
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'clientRootShare32B64u must be valid base64url',
      };
    }
  }

  private decodeIntegratedRelayerBackendInput32(
    integratedKey: ThresholdEcdsaIntegratedKeyRecord,
  ): ParseResult<Uint8Array> {
    try {
      const relayerBackendInput32 = base64UrlDecode(integratedKey.relayerBackendInputB64u);
      if (relayerBackendInput32.length !== 32) {
        return {
          ok: false,
          code: 'internal',
          message: 'Persisted relayer backend input must decode to 32 bytes',
        };
      }
      return { ok: true, value: relayerBackendInput32 };
    } catch {
      return {
        ok: false,
        code: 'internal',
        message: 'Persisted relayer backend input is not valid base64url',
      };
    }
  }

  private decodeIntegratedRelayerRootShare32(
    integratedKey: ThresholdEcdsaIntegratedKeyRecord,
  ): ParseResult<Uint8Array> {
    try {
      const relayerRootShare32 = base64UrlDecode(integratedKey.relayerRootShare32B64u);
      if (relayerRootShare32.length !== 32) {
        return {
          ok: false,
          code: 'internal',
          message: 'Persisted relayer root share must decode to 32 bytes',
        };
      }
      return { ok: true, value: relayerRootShare32 };
    } catch {
      return {
        ok: false,
        code: 'internal',
        message: 'Persisted relayer root share is not valid base64url',
      };
    }
  }

  private async deriveEcdsaKeyMaterialFromPersistedBackend(input: {
    userId: string;
    clientRootShare32B64u: string;
    integratedKey: ThresholdEcdsaIntegratedKeyRecord;
  }): Promise<ParseResult<DerivedEcdsaKeyMaterial>> {
    const parsedClientRootShare = this.parseClientRootShare32(input.clientRootShare32B64u);
    if (!parsedClientRootShare.ok) return parsedClientRootShare;
    const parsedRelayerRootShare = this.decodeIntegratedRelayerRootShare32(input.integratedKey);
    if (!parsedRelayerRootShare.ok) return parsedRelayerRootShare;
    const relayerKeyId = toOptionalTrimmedString(input.integratedKey.relayerKeyId);
    if (!relayerKeyId) {
      return {
        ok: false,
        code: 'internal',
        message: 'Persisted threshold-ecdsa key record is missing relayerKeyId',
      };
    }

    const bootstrapped = await ecdsaHssBootstrapNonExportSign({
      nearAccountId: input.userId,
      keyPurpose: THRESHOLD_ECDSA_HSS_KEY_PURPOSE_V1,
      keyVersion: THRESHOLD_ECDSA_HSS_KEY_VERSION_V1,
      yClient32Le: parsedClientRootShare.value,
      yRelayer32Le: parsedRelayerRootShare.value,
    });

    const clientVerifyingShareB64u = base64UrlEncode(bootstrapped.clientPublicKey33);
    const clientAdditiveShare32B64u = base64UrlEncode(bootstrapped.clientAdditiveShare32);
    const thresholdEcdsaPublicKeyB64u = base64UrlEncode(bootstrapped.groupPublicKey33);
    const ethereumAddress = `0x${Array.from(bootstrapped.ethereumAddress20)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')}`;
    const relayerVerifyingShareB64u = base64UrlEncode(bootstrapped.relayerPublicKey33);

    if (clientVerifyingShareB64u !== input.integratedKey.clientVerifyingShareB64u) {
      return {
        ok: false,
        code: 'internal',
        message: 'threshold-ecdsa bootstrap client verifying share does not match integrated key record',
      };
    }
    if (thresholdEcdsaPublicKeyB64u !== input.integratedKey.thresholdEcdsaPublicKeyB64u) {
      return {
        ok: false,
        code: 'internal',
        message: 'threshold-ecdsa bootstrap group public key does not match integrated key record',
      };
    }
    if (ethereumAddress !== input.integratedKey.ethereumAddress) {
      return {
        ok: false,
        code: 'internal',
        message: 'threshold-ecdsa bootstrap ethereumAddress does not match integrated key record',
      };
    }
    if (
      toOptionalTrimmedString(input.integratedKey.relayerVerifyingShareB64u) &&
      relayerVerifyingShareB64u !== input.integratedKey.relayerVerifyingShareB64u
    ) {
      return {
        ok: false,
        code: 'internal',
        message: 'threshold-ecdsa bootstrap relayer verifying share does not match integrated key record',
      };
    }

    return {
      ok: true,
      value: {
        participantIds: [...input.integratedKey.participantIds],
        relayerKeyId,
        clientVerifyingShareB64u,
        clientAdditiveShare32B64u,
        thresholdEcdsaPublicKeyB64u,
        ethereumAddress,
        relayerVerifyingShareB64u,
        relayerRootShare32B64u: input.integratedKey.relayerRootShare32B64u,
        relayerBackendInputB64u: input.integratedKey.relayerBackendInputB64u,
      },
    };
  }

  private async bootstrapEcdsaFromClientRootShare(input: {
    userId: string;
    rpId: string;
    clientRootShare32B64u: string;
    sessionPolicy: Record<string, unknown>;
    ecdsaThresholdKeyId?: string;
  }): Promise<ThresholdEcdsaHssFinalizeResponse> {
    const userId = String(input.userId || '').trim();
    const rpId = String(input.rpId || '').trim();
    const clientRootShare32B64u = String(input.clientRootShare32B64u || '').trim();
    const ecdsaThresholdKeyId = String(input.ecdsaThresholdKeyId || '').trim();
    const sessionPolicy =
      input.sessionPolicy && typeof input.sessionPolicy === 'object' && !Array.isArray(input.sessionPolicy)
        ? (input.sessionPolicy as Record<string, unknown>)
        : null;
    if (!userId || !rpId || !clientRootShare32B64u || !sessionPolicy) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Missing required ecdsa registration bootstrap inputs',
      };
    }
    const integratedKey = ecdsaThresholdKeyId
      ? await this.getEcdsaIntegratedKeyRecord(ecdsaThresholdKeyId)
      : null;
    if (ecdsaThresholdKeyId && !integratedKey) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'ecdsaThresholdKeyId is not active on this server',
      };
    }
    if (integratedKey && (integratedKey.userId !== userId || integratedKey.rpId !== rpId)) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'ecdsaThresholdKeyId does not match threshold bootstrap scope',
      };
    }

    const derived = integratedKey
      ? await this.deriveEcdsaKeyMaterialFromPersistedBackend({
          userId,
          clientRootShare32B64u,
          integratedKey,
        })
      : await this.deriveEcdsaKeyMaterialForFirstBootstrapFromClientRootShare({
          userId,
          rpId,
          clientRootShare32B64u,
        });
    if (!derived.ok) return derived;

    const thresholdEcdsaPublicKeyB64u = toOptionalTrimmedString(derived.value.thresholdEcdsaPublicKeyB64u);
    const ethereumAddress = toOptionalTrimmedString(derived.value.ethereumAddress);
    if (!thresholdEcdsaPublicKeyB64u || !ethereumAddress) {
      return {
        ok: false,
        code: 'internal',
        message: 'threshold-ecdsa registration bootstrap returned incomplete key material',
      };
    }

    const canonicalEcdsaThresholdKeyId =
      integratedKey?.ecdsaThresholdKeyId ||
      (await this.upsertIntegratedEcdsaKeyRecord({
        userId,
        rpId,
        clientVerifyingShareB64u: derived.value.clientVerifyingShareB64u,
        thresholdEcdsaPublicKeyB64u,
        ethereumAddress,
        participantIds: [...derived.value.participantIds],
        relayerKeyId: derived.value.relayerKeyId,
        relayerVerifyingShareB64u: derived.value.relayerVerifyingShareB64u,
        relayerRootShare32B64u: derived.value.relayerRootShare32B64u,
        relayerBackendInputB64u: derived.value.relayerBackendInputB64u,
      }));

    const relayerKeyId = String(derived.value.relayerKeyId || '').trim();
    const requestedRelayerKeyId = String(sessionPolicy.relayerKeyId || '').trim();
    if (requestedRelayerKeyId && requestedRelayerKeyId !== relayerKeyId) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'threshold_ecdsa.session_policy.relayerKeyId mismatch',
      };
    }

    const policy = {
      ...(sessionPolicy as Record<string, unknown>),
      relayerKeyId,
    } as EcdsaSessionPolicy;
    if (String(policy.version || '').trim() !== 'threshold_session_v1') {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'threshold_ecdsa.session_policy.version must be threshold_session_v1',
      };
    }
    if (String(policy.userId || '').trim() !== userId) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'threshold_ecdsa.session_policy.userId mismatch',
      };
    }
    if (String(policy.rpId || '').trim() !== rpId) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'threshold_ecdsa.session_policy.rpId mismatch',
      };
    }
    if (String(policy.relayerKeyId || '').trim() !== relayerKeyId) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'threshold_ecdsa.session_policy.relayerKeyId mismatch',
      };
    }
    const sessionId = String(policy.sessionId || '').trim();
    if (!sessionId) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'threshold_ecdsa.session_policy.sessionId is required',
      };
    }
    const policyParticipantIds =
      normalizeThresholdEd25519ParticipantIds(policy.participantIds) || null;
    const session = await this.ecdsaMintSessionWithoutWebAuthn({
      relayerKeyId,
      clientVerifyingShareB64u: derived.value.clientVerifyingShareB64u,
      userId,
      rpId,
      sessionId,
      ttlMsRaw: Number(policy.ttlMs),
      remainingUsesRaw: Number(policy.remainingUses),
      policyParticipantIds,
    });
    if (!session.ok) return session;

    return {
      ok: true,
      ecdsaThresholdKeyId: canonicalEcdsaThresholdKeyId,
      relayerKeyId: derived.value.relayerKeyId,
      clientVerifyingShareB64u: derived.value.clientVerifyingShareB64u,
      clientAdditiveShare32B64u: derived.value.clientAdditiveShare32B64u,
      thresholdEcdsaPublicKeyB64u,
      ethereumAddress,
      relayerVerifyingShareB64u: derived.value.relayerVerifyingShareB64u,
      participantIds: session.participantIds || derived.value.participantIds,
      sessionId: session.sessionId,
      expiresAtMs: session.expiresAtMs,
      expiresAt: session.expiresAt,
      remainingUses: session.remainingUses,
      jwt: session.jwt,
    };
  }

  private async deriveEcdsaKeyMaterialForFirstBootstrapFromClientRootShare(input: {
    userId: string;
    rpId: string;
    clientRootShare32B64u: string;
  }): Promise<ParseResult<DerivedEcdsaKeyMaterial>> {
    const userId = String(input.userId || '').trim();
    const rpId = String(input.rpId || '').trim();
    const clientRootShare32B64u = String(input.clientRootShare32B64u || '').trim();
    if (!userId) return { ok: false, code: 'invalid_body', message: 'userId is required' };
    if (!rpId) return { ok: false, code: 'invalid_body', message: 'rpId is required' };
    if (!clientRootShare32B64u) {
      return { ok: false, code: 'invalid_body', message: 'clientRootShare32B64u is required' };
    }
    if (!this.secp256k1MasterSecretB64u) {
      return {
        ok: false,
        code: 'not_configured',
        message: 'threshold-secp256k1 keygen requires THRESHOLD_SECP256K1_MASTER_SECRET_B64U',
      };
    }

    let yClient32Le: Uint8Array;
    try {
      yClient32Le = base64UrlDecode(clientRootShare32B64u);
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'clientRootShare32B64u must be valid base64url',
      };
    }
    if (yClient32Le.length !== 32) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'clientRootShare32B64u must decode to 32 bytes',
      };
    }

    const relayerKeyId = await this.computeEcdsaHssRelayerKeyId({ userId, rpId });
    const { relayerSigningShare32 } = await deriveThresholdSecp256k1RelayerShare({
      masterSecretB64u: this.secp256k1MasterSecretB64u,
      relayerKeyId,
    });
    const bootstrapped = await ecdsaHssBootstrapNonExportSign({
      nearAccountId: userId,
      keyPurpose: THRESHOLD_ECDSA_HSS_KEY_PURPOSE_V1,
      keyVersion: THRESHOLD_ECDSA_HSS_KEY_VERSION_V1,
      yClient32Le,
      yRelayer32Le: relayerSigningShare32,
    });

    return {
      ok: true,
      value: {
        participantIds: [...this.participantIds2p],
        relayerKeyId,
        clientVerifyingShareB64u: base64UrlEncode(bootstrapped.clientPublicKey33),
        clientAdditiveShare32B64u: base64UrlEncode(bootstrapped.clientAdditiveShare32),
        thresholdEcdsaPublicKeyB64u: base64UrlEncode(bootstrapped.groupPublicKey33),
        ethereumAddress: `0x${Array.from(bootstrapped.ethereumAddress20)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}`,
        relayerVerifyingShareB64u: base64UrlEncode(bootstrapped.relayerPublicKey33),
        relayerRootShare32B64u: base64UrlEncode(relayerSigningShare32),
        relayerBackendInputB64u: base64UrlEncode(bootstrapped.relayerAdditiveShare32),
      },
    };
  }

  private async deriveEcdsaExplicitExportFromPersistedBackend(input: {
    userId: string;
    clientRootShare32B64u: string;
    integratedKey: ThresholdEcdsaIntegratedKeyRecord;
  }): Promise<
    ParseResult<{
      relayerKeyId: string;
      canonicalPublicKeyHex: string;
      privateKeyHex: string;
      canonicalEthereumAddress: string;
    }>
  > {
    const parsedClientRootShare = this.parseClientRootShare32(input.clientRootShare32B64u);
    if (!parsedClientRootShare.ok) return parsedClientRootShare;
    const parsedRelayerRootShare = this.decodeIntegratedRelayerRootShare32(input.integratedKey);
    if (!parsedRelayerRootShare.ok) return parsedRelayerRootShare;

    const relayerKeyId = toOptionalTrimmedString(input.integratedKey.relayerKeyId);
    if (!relayerKeyId) {
      return {
        ok: false,
        code: 'internal',
        message: 'Persisted threshold-ecdsa key record is missing relayerKeyId',
      };
    }

    const exported = await ecdsaHssExplicitExport({
      nearAccountId: input.userId,
      keyPurpose: THRESHOLD_ECDSA_HSS_KEY_PURPOSE_V1,
      keyVersion: THRESHOLD_ECDSA_HSS_KEY_VERSION_V1,
      yClient32Le: parsedClientRootShare.value,
      yRelayer32Le: parsedRelayerRootShare.value,
    });

    return {
      ok: true,
      value: {
        relayerKeyId,
        canonicalPublicKeyHex: bytesToLowerHex(exported.canonicalPublicKey33),
        privateKeyHex: bytesToLowerHex(exported.canonicalX32),
        canonicalEthereumAddress: bytesToLowerHex(exported.canonicalEthereumAddress20),
      },
    };
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
    userId: string;
    rpId: string;
    sessionId: string;
    ttlMsRaw: number;
    remainingUsesRaw: number;
    policyParticipantIds: number[] | null;
  }): Promise<ThresholdEcdsaBootstrapSessionResult> {
    const {
      relayerKeyId,
      clientVerifyingShareB64u,
      userId,
      rpId,
      sessionId,
      ttlMsRaw,
      remainingUsesRaw,
      policyParticipantIds,
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

    const existingSession = await this.ecdsaAuthSessionStore.getSession(sessionId);
    if (existingSession) {
      if (existingSession.userId !== userId) {
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
      return {
        ok: true,
        sessionId,
        expiresAtMs: existingSession.expiresAtMs,
        expiresAt: new Date(existingSession.expiresAtMs).toISOString(),
        participantIds: existingSession.participantIds,
      };
    }

    const expiresAtMs = Date.now() + ttlMs;
    await this.putAuthSessionRecord({
      store: this.ecdsaAuthSessionStore,
      sessionId,
      record: {
        expiresAtMs,
        relayerKeyId,
        userId,
        rpId,
        participantIds,
      },
      ttlMs,
      remainingUses,
    });

    return {
      ok: true,
      sessionId,
      expiresAtMs,
      expiresAt: new Date(expiresAtMs).toISOString(),
      participantIds,
      remainingUses,
    };
  }

  private async ecdsaHssPrepare(
    request: ThresholdEcdsaHssPrepareRequest,
  ): Promise<ThresholdEcdsaHssPrepareResponse> {
    try {
      const userId = toOptionalTrimmedString(request.userId);
      const rpId = toOptionalTrimmedString(request.rpId);
      const operation = toOptionalTrimmedString(
        request.operation,
      ) as ThresholdEcdsaHssOperation | null;
      if (!userId) return { ok: false, code: 'invalid_body', message: 'userId is required' };
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'rpId is required' };
      if (
        operation !== 'registration_bootstrap' &&
        operation !== 'session_bootstrap' &&
        operation !== 'explicit_key_export'
      ) {
        return { ok: false, code: 'invalid_body', message: 'operation is invalid' };
      }
      if (operation === 'registration_bootstrap') {
        if (!toOptionalTrimmedString(request.keygenSessionId)) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'registration_bootstrap requires keygenSessionId',
          };
        }
        if (!request.webauthn_authentication || typeof request.webauthn_authentication !== 'object') {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'registration_bootstrap requires webauthn_authentication',
          };
        }
      }
      if (operation === 'session_bootstrap') {
        const ecdsaThresholdKeyId = toOptionalTrimmedString(request.ecdsaThresholdKeyId);
        const ed25519Claims = request.ed25519SessionClaims
          ? parseThresholdEd25519SessionClaims(request.ed25519SessionClaims)
          : null;
        const appSessionClaims = request.appSessionClaims
          ? parseAppSessionClaims(request.appSessionClaims)
          : null;
        const sameParticipants = (expected: number[], actual: number[]): boolean =>
          expected.length === actual.length && expected.every((value, index) => value === actual[index]);
        const requestedPolicyParticipantIds = normalizeThresholdEd25519ParticipantIds(
          (request.sessionPolicy as Record<string, unknown> | undefined)?.participantIds,
        );

        if (!ed25519Claims && !appSessionClaims) {
          return {
            ok: false,
            code: 'unauthorized',
            message:
              'session_bootstrap requires an authenticated threshold-ed25519 session or app session',
          };
        }

        if (ed25519Claims) {
          if (ecdsaThresholdKeyId) {
            const integratedKey = await this.getEcdsaIntegratedKeyRecord(ecdsaThresholdKeyId);
            if (!integratedKey) {
              return {
                ok: false,
                code: 'unauthorized',
                message: 'ecdsaThresholdKeyId is not active on this server',
              };
            }
            if (
              integratedKey.userId !== ed25519Claims.sub ||
              integratedKey.rpId !== ed25519Claims.rpId
            ) {
              return {
                ok: false,
                code: 'unauthorized',
                message: 'ecdsaThresholdKeyId does not match threshold session scope',
              };
            }
            if (!sameParticipants(integratedKey.participantIds, ed25519Claims.participantIds)) {
              return {
                ok: false,
                code: 'unauthorized',
                message: 'ecdsaThresholdKeyId does not match threshold session participant set',
              };
            }
          }
        } else if (appSessionClaims) {
          if (!ecdsaThresholdKeyId) {
            return {
              ok: false,
              code: 'invalid_body',
              message: 'session_bootstrap with app session requires ecdsaThresholdKeyId',
            };
          }
          const integratedKey = await this.getEcdsaIntegratedKeyRecord(ecdsaThresholdKeyId);
          if (!integratedKey) {
            return {
              ok: false,
              code: 'unauthorized',
              message: 'ecdsaThresholdKeyId is not active on this server',
            };
          }
          if (appSessionClaims.sub !== userId || integratedKey.userId !== appSessionClaims.sub) {
            return {
              ok: false,
              code: 'unauthorized',
              message: 'app session does not match requested userId',
            };
          }
          if (integratedKey.rpId !== rpId) {
            return {
              ok: false,
              code: 'unauthorized',
              message: 'ecdsaThresholdKeyId does not match requested rpId',
            };
          }
          if (!requestedPolicyParticipantIds || !sameParticipants(integratedKey.participantIds, requestedPolicyParticipantIds)) {
            return {
              ok: false,
              code: 'unauthorized',
              message: 'session_bootstrap app-session path requires sessionPolicy.participantIds to match the active ECDSA signer set',
            };
          }
        }
      }
      if (operation === 'explicit_key_export') {
        if (
          !request.ecdsaSessionClaims ||
          typeof request.ecdsaSessionClaims !== 'object' ||
          Array.isArray(request.ecdsaSessionClaims)
        ) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'explicit_key_export requires an authenticated threshold-ecdsa session',
          };
        }
        const ecdsaClaims = parseThresholdEcdsaSessionClaims(request.ecdsaSessionClaims);
        if (!ecdsaClaims) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'Invalid threshold-ecdsa session claims',
          };
        }
        const ecdsaThresholdKeyId = toOptionalTrimmedString(request.ecdsaThresholdKeyId);
        if (!ecdsaThresholdKeyId) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'explicit_key_export requires ecdsaThresholdKeyId',
          };
        }
        const integratedKey = await this.getEcdsaIntegratedKeyRecord(ecdsaThresholdKeyId);
        if (!integratedKey) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'ecdsaThresholdKeyId is not active on this server',
          };
        }
        if (integratedKey.userId !== ecdsaClaims.sub || integratedKey.rpId !== ecdsaClaims.rpId) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'ecdsaThresholdKeyId does not match threshold session scope',
          };
        }
        if (integratedKey.relayerKeyId !== ecdsaClaims.relayerKeyId) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'ecdsaThresholdKeyId does not match threshold session relayer binding',
          };
        }
        const sameParticipants =
          integratedKey.participantIds.length === ecdsaClaims.participantIds.length &&
          integratedKey.participantIds.every((value, index) => value === ecdsaClaims.participantIds[index]);
        if (!sameParticipants) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'ecdsaThresholdKeyId does not match threshold session participant set',
          };
        }
      }
      if (operation !== 'explicit_key_export' && (!request.sessionPolicy || typeof request.sessionPolicy !== 'object')) {
        return { ok: false, code: 'invalid_body', message: 'sessionPolicy is required' };
      }

      const requestedEcdsaThresholdKeyId = toOptionalTrimmedString(request.ecdsaThresholdKeyId);
      const requiresMasterSecretBootstrapDerivation =
        operation === 'registration_bootstrap' ||
        (operation === 'session_bootstrap' && !requestedEcdsaThresholdKeyId);
      if (requiresMasterSecretBootstrapDerivation && !this.secp256k1MasterSecretB64u) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold-ecdsa requires THRESHOLD_SECP256K1_MASTER_SECRET_B64U',
        };
      }

      let relayerSigningShare32: Uint8Array;
      if (requiresMasterSecretBootstrapDerivation) {
        const relayerKeyId = await this.computeEcdsaHssRelayerKeyId({ userId, rpId });
        const derivedRelayerShare = await deriveThresholdSecp256k1RelayerShare({
          masterSecretB64u: this.secp256k1MasterSecretB64u!,
          relayerKeyId,
        });
        relayerSigningShare32 = derivedRelayerShare.relayerSigningShare32;
      } else {
        const integratedKey = requestedEcdsaThresholdKeyId
          ? await this.getEcdsaIntegratedKeyRecord(requestedEcdsaThresholdKeyId)
          : null;
        if (!integratedKey) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'ecdsaThresholdKeyId is not active on this server',
          };
        }
        const parsedRelayerRootShare = this.decodeIntegratedRelayerRootShare32(integratedKey);
        if (!parsedRelayerRootShare.ok) return parsedRelayerRootShare;
        relayerSigningShare32 = parsedRelayerRootShare.value;
      }
      const preparedSession = await prepareThresholdEcdsaHssServerSession({
        nearAccountId: userId,
        keyPurpose: THRESHOLD_ECDSA_HSS_KEY_PURPOSE_V1,
        keyVersion: THRESHOLD_ECDSA_HSS_KEY_VERSION_V1,
        operation:
          operation === 'registration_bootstrap'
            ? 'registration_bootstrap'
            : operation === 'session_bootstrap'
              ? 'session_bootstrap'
              : 'explicit_key_export',
        yRelayer32Le: relayerSigningShare32,
      });

      const ceremonyId = this.storeThresholdEcdsaHssCeremony({
        userId,
        rpId,
        operation,
        ...(toOptionalTrimmedString(request.ecdsaThresholdKeyId)
          ? { ecdsaThresholdKeyId: toOptionalTrimmedString(request.ecdsaThresholdKeyId)! }
          : {}),
        preparedServerSessionB64u: preparedSession.preparedServerSessionB64u,
        serverAssistInitB64u: preparedSession.serverAssistInitMessageB64u,
        ...(toOptionalTrimmedString(request.keygenSessionId)
          ? { keygenSessionId: toOptionalTrimmedString(request.keygenSessionId)! }
          : {}),
        sessionPolicy: request.sessionPolicy,
        sessionKind: request.sessionKind || 'jwt',
        ...(request.webauthn_authentication
          ? { webauthnAuthentication: request.webauthn_authentication }
          : {}),
        ...(request.ed25519SessionClaims ? { ed25519SessionClaims: request.ed25519SessionClaims } : {}),
        ...(request.appSessionClaims ? { appSessionClaims: request.appSessionClaims } : {}),
        ...(request.ecdsaSessionClaims ? { ecdsaSessionClaims: request.ecdsaSessionClaims } : {}),
      });
      const ceremonyRecord = this.ecdsaHssCeremonyStore.get(ceremonyId);
      if (!ceremonyRecord) {
        return { ok: false, code: 'internal', message: 'failed to persist staged ceremony' };
      }

      return {
        ok: true,
        ceremonyId,
        preparedServerSessionB64u: ceremonyRecord.preparedServerSessionB64u,
        serverAssistInitB64u: ceremonyRecord.serverAssistInitB64u,
      };
    } catch (e: unknown) {
      return { ok: false, code: 'internal', message: errorMessage(e) };
    }
  }

  private async ecdsaHssRespond(
    request: ThresholdEcdsaHssRespondRequest,
  ): Promise<ThresholdEcdsaHssRespondResponse> {
    try {
      const ceremony = this.getThresholdEcdsaHssCeremony(request.ceremonyId);
      if (!ceremony.ok) return ceremony;
      const requestMessageB64u = toOptionalTrimmedString(request.requestMessageB64u);
      if (!requestMessageB64u) {
        return { ok: false, code: 'invalid_body', message: 'requestMessageB64u is required' };
      }
      const stagedRequest = parseThresholdEcdsaHssHiddenEvalClientRequestEnvelope(
        requestMessageB64u,
      );
      if (!stagedRequest) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'requestMessageB64u must contain a valid hidden-eval staged bootstrap payload',
        };
      }
      if (stagedRequest.ceremonyId !== toOptionalTrimmedString(request.ceremonyId)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'requestMessageB64u ceremonyId does not match request ceremonyId',
        };
      }
      if (stagedRequest.preparedServerSessionB64u !== ceremony.value.preparedServerSessionB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'requestMessageB64u preparedServerSessionB64u does not match ceremony state',
        };
      }
      if (stagedRequest.serverAssistInitB64u !== ceremony.value.serverAssistInitB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'requestMessageB64u serverAssistInitB64u does not match ceremony state',
        };
      }
      const serverCeremony = await prepareThresholdEcdsaHssServerCeremony({
        preparedServerSessionB64u: stagedRequest.preparedServerSessionB64u,
        clientEvalRequestB64u: stagedRequest.clientEvalRequestB64u,
        serverAssistInitB64u: stagedRequest.serverAssistInitB64u,
      });
      ceremony.value.requestMessageB64u = requestMessageB64u;
      const requestDigestB64u = await computeThresholdEcdsaHssRequestDigestB64u(requestMessageB64u);
      const responseMessageB64u = createOpaqueBase64Envelope({
        v: 1,
        kind: 'threshold_ecdsa_hss_hidden_eval_server_response_v1',
        ceremonyId: toOptionalTrimmedString(request.ceremonyId),
        requestDigestB64u,
        serverEvalResponseB64u: serverCeremony.serverEvalResponseB64u,
      });
      ceremony.value.responseMessageB64u = responseMessageB64u;
      return {
        ok: true,
        responseMessageB64u,
      };
    } catch (e: unknown) {
      return { ok: false, code: 'internal', message: errorMessage(e) };
    }
  }

  private async ecdsaHssFinalize(
    request: ThresholdEcdsaHssFinalizeRequest,
  ): Promise<ThresholdEcdsaHssFinalizeResponse> {
    try {
      const ceremony = this.takeThresholdEcdsaHssCeremony(request.ceremonyId);
      if (!ceremony.ok) return ceremony;
      const clientFinalizeMessageB64u = toOptionalTrimmedString(request.clientFinalizeMessageB64u);
      if (!clientFinalizeMessageB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'clientFinalizeMessageB64u is required',
        };
      }
      const requestMessageB64u = toOptionalTrimmedString(ceremony.value.requestMessageB64u);
      if (!requestMessageB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ceremonyId has no staged client request',
        };
      }
      const finalizeEnvelope = parseThresholdEcdsaHssHiddenEvalFinalizeEnvelope(
        clientFinalizeMessageB64u,
      );
      if (!finalizeEnvelope) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'clientFinalizeMessageB64u must contain a valid hidden-eval finalize envelope',
        };
      }
      if (finalizeEnvelope.ceremonyId !== toOptionalTrimmedString(request.ceremonyId)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'clientFinalizeMessageB64u ceremonyId does not match request ceremonyId',
        };
      }
      const expectedRequestDigestB64u = await computeThresholdEcdsaHssRequestDigestB64u(
        requestMessageB64u,
      );
      if (finalizeEnvelope.requestDigestB64u !== expectedRequestDigestB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'clientFinalizeMessageB64u is not bound to the staged client request',
        };
      }
      const stagedRequest = parseThresholdEcdsaHssHiddenEvalClientRequestEnvelope(
        requestMessageB64u,
      );
      if (!stagedRequest) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'requestMessageB64u must contain a valid hidden-eval staged bootstrap payload',
        };
      }
      const responseMessageB64u = toOptionalTrimmedString(ceremony.value.responseMessageB64u);
      if (!responseMessageB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ceremonyId has no staged server response',
        };
      }
      const responseEnvelope = parseThresholdEcdsaHssHiddenEvalServerResponseEnvelope(
        responseMessageB64u,
      );
      if (!responseEnvelope) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'stored staged server response is invalid',
        };
      }
      if (responseEnvelope.ceremonyId !== toOptionalTrimmedString(request.ceremonyId)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'stored staged server response ceremonyId does not match request ceremonyId',
        };
      }
      if (responseEnvelope.requestDigestB64u !== expectedRequestDigestB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'stored staged server response is not bound to the staged client request',
        };
      }
      const responseDigestB64u = base64UrlEncode(await sha256BytesUtf8(responseMessageB64u));
      if (finalizeEnvelope.responseDigestB64u !== responseDigestB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'clientFinalizeMessageB64u is not bound to the staged server response',
        };
      }
      const serverOutput = await finalizeThresholdEcdsaHssServerReport({
        preparedServerSessionB64u: ceremony.value.preparedServerSessionB64u,
        clientEvalRequestB64u: stagedRequest.clientEvalRequestB64u,
        clientEvalFinalizeB64u: finalizeEnvelope.clientEvalFinalizeB64u,
        serverEvalResponseB64u: responseEnvelope.serverEvalResponseB64u,
      });
      const openedServerOutput = await openThresholdEcdsaHssServerOutput({
        preparedServerSessionB64u: ceremony.value.preparedServerSessionB64u,
        serverOutputMessageB64u: serverOutput.serverOutputMessageB64u,
      });
      const clientRootShare32B64u = openedServerOutput.yClient32LeB64u;

      if (ceremony.value.operation === 'explicit_key_export') {
        const ecdsaThresholdKeyId = toOptionalTrimmedString(ceremony.value.ecdsaThresholdKeyId);
        if (!ecdsaThresholdKeyId) {
          return {
            ok: false,
            code: 'internal',
            message: 'explicit_key_export ceremony is missing ecdsaThresholdKeyId',
          };
        }
        const integratedKey = await this.getEcdsaIntegratedKeyRecord(ecdsaThresholdKeyId);
        if (!integratedKey) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'ecdsaThresholdKeyId is not active on this server',
          };
        }
        const exported = await this.deriveEcdsaExplicitExportFromPersistedBackend({
          userId: ceremony.value.userId,
          clientRootShare32B64u,
          integratedKey,
        });
        if (!exported.ok) return exported;
        if (exported.value.relayerKeyId !== integratedKey.relayerKeyId) {
          return {
            ok: false,
            code: 'internal',
            message: 'explicit_key_export relayer binding mismatch',
          };
        }
        const integratedPublicKeyHex = bytesToLowerHex(base64UrlDecode(integratedKey.thresholdEcdsaPublicKeyB64u));
        if (exported.value.canonicalPublicKeyHex !== integratedPublicKeyHex) {
          return {
            ok: false,
            code: 'internal',
            message: 'explicit_key_export canonical public key does not match integrated key record',
          };
        }
        if (exported.value.canonicalEthereumAddress !== integratedKey.ethereumAddress) {
          return {
            ok: false,
            code: 'internal',
            message: 'explicit_key_export canonical address does not match integrated key record',
          };
        }
        return {
          ok: true,
          ecdsaThresholdKeyId,
          canonicalPublicKeyHex: exported.value.canonicalPublicKeyHex,
          privateKeyHex: exported.value.privateKeyHex,
          canonicalEthereumAddress: exported.value.canonicalEthereumAddress,
        };
      }

      const bootstrap = await this.bootstrapEcdsaFromClientRootShare({
        userId: ceremony.value.userId,
        rpId: ceremony.value.rpId,
        clientRootShare32B64u,
        ...(toOptionalTrimmedString(ceremony.value.ecdsaThresholdKeyId)
          ? { ecdsaThresholdKeyId: toOptionalTrimmedString(ceremony.value.ecdsaThresholdKeyId)! }
          : {}),
        sessionPolicy: {
          ...(ceremony.value.sessionPolicy as Record<string, unknown>),
          ...(ceremony.value.keygenSessionId
            ? { keygenSessionId: ceremony.value.keygenSessionId }
            : {}),
        },
      });
      if (!bootstrap.ok) return bootstrap;
      if ('canonicalSecp256k1KeyB64u' in ((bootstrap as unknown) as Record<string, unknown>)) {
        return {
          ok: false,
          code: 'internal',
          message: 'non-export threshold-ecdsa finalize produced export-capable output',
        };
      }

      const ecdsaThresholdKeyId = toOptionalTrimmedString(bootstrap.ecdsaThresholdKeyId);
      const thresholdEcdsaPublicKeyB64u = toOptionalTrimmedString(bootstrap.thresholdEcdsaPublicKeyB64u);
      const ethereumAddress = toOptionalTrimmedString(bootstrap.ethereumAddress);
      if (!ecdsaThresholdKeyId || !thresholdEcdsaPublicKeyB64u || !ethereumAddress) {
        return {
          ok: false,
          code: 'internal',
          message: 'threshold-ecdsa hss finalize returned incomplete key identity',
        };
      }

      return {
        ok: true,
        sessionKind: ceremony.value.sessionKind || 'jwt',
        sessionJwtUserId: ceremony.value.userId,
        sessionJwtRpId: ceremony.value.rpId,
        ecdsaThresholdKeyId,
        clientVerifyingShareB64u: bootstrap.clientVerifyingShareB64u,
        clientAdditiveShare32B64u: bootstrap.clientAdditiveShare32B64u,
        thresholdEcdsaPublicKeyB64u,
        ethereumAddress,
        participantIds: bootstrap.participantIds,
        relayerKeyId: bootstrap.relayerKeyId,
        relayerVerifyingShareB64u: bootstrap.relayerVerifyingShareB64u,
        chainId: bootstrap.chainId,
        factory: bootstrap.factory,
        entryPoint: bootstrap.entryPoint,
        salt: bootstrap.salt,
        counterfactualAddress: bootstrap.counterfactualAddress,
        sessionId: bootstrap.sessionId,
        expiresAtMs: bootstrap.expiresAtMs,
        expiresAt: bootstrap.expiresAt,
        remainingUses: bootstrap.remainingUses,
        jwt: bootstrap.jwt,
      };
    } catch (e: unknown) {
      return { ok: false, code: 'internal', message: errorMessage(e) };
    }
  }

  private async ecdsaAuthorizeWithSession(input: {
    claims: ThresholdEcdsaSessionClaims;
    request: ThresholdEcdsaAuthorizeWithSessionRequest;
  }): Promise<ThresholdEcdsaAuthorizeResponse> {
    try {
      const claims = input.claims;
      const sessionId = toOptionalTrimmedString(claims?.sessionId);
      if (!sessionId)
        return { ok: false, code: 'unauthorized', message: 'Missing threshold sessionId' };
      const userId = toOptionalTrimmedString(claims?.sub);
      if (!userId) return { ok: false, code: 'unauthorized', message: 'Missing threshold userId' };

      const tokenRelayerKeyId = toOptionalTrimmedString(claims?.relayerKeyId);
      const tokenRpId = toOptionalTrimmedString(claims?.rpId);
      if (!tokenRelayerKeyId || !tokenRpId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Invalid threshold session token claims',
        };
      }

      const parsedRequest = parseThresholdEcdsaAuthorizeWithSessionRequest(input.request);
      if (!parsedRequest.ok) return parsedRequest;
      const {
        ecdsaThresholdKeyId,
        purpose,
        signingDigest32,
      } = parsedRequest.value;

      await this.ensureReady();

      const participantIds = claims.participantIds;

      const integratedKey = await this.getEcdsaIntegratedKeyRecord(ecdsaThresholdKeyId);
      if (!integratedKey) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'ecdsaThresholdKeyId is not active on this server',
        };
      }
      if (integratedKey.userId !== userId || integratedKey.rpId !== tokenRpId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'ecdsaThresholdKeyId does not match threshold session scope',
        };
      }
      if (!haveSameParticipantIds(integratedKey.participantIds, participantIds)) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'ecdsaThresholdKeyId participantIds do not match threshold session scope',
        };
      }
      const relayerKeyId = toOptionalTrimmedString(integratedKey.relayerKeyId);
      const clientVerifyingShareB64u = toOptionalTrimmedString(
        integratedKey.clientVerifyingShareB64u,
      );
      if (!relayerKeyId || !clientVerifyingShareB64u) {
        return {
          ok: false,
          code: 'internal',
          message: 'ecdsaThresholdKeyId is missing backend signer input',
        };
      }

      if (relayerKeyId !== tokenRelayerKeyId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'relayerKeyId does not match threshold session scope',
        };
      }

      const thresholdExpiresAtMs = claims.thresholdExpiresAtMs;
      if (Date.now() > thresholdExpiresAtMs) {
        return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
      }

      for (const id of this.participantIds2p) {
        if (!participantIds.includes(id)) {
          return {
            ok: false,
            code: 'unauthorized',
            message: `threshold session token does not include server signer set (expected to include participantIds=[${this.participantIds2p.join(',')}])`,
          };
        }
      }

      const consumed = await this.ecdsaAuthSessionStore.consumeUseCount(sessionId);
      if (!consumed.ok) {
        return { ok: false, code: consumed.code, message: consumed.message };
      }

      // Validate the client verifying share and bind relayerKeyId to it.
      let clientVerifyingShareBytes: Uint8Array;
      try {
        clientVerifyingShareBytes = base64UrlDecode(clientVerifyingShareB64u);
      } catch {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'clientVerifyingShareB64u must be valid base64url',
        };
      }
      if (clientVerifyingShareBytes.length !== 33) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'clientVerifyingShareB64u must decode to 33 bytes (compressed secp256k1 pubkey)',
        };
      }
      try {
        await validateSecp256k1PublicKey33(clientVerifyingShareBytes);
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
          message: 'clientVerifyingShareB64u is not a valid secp256k1 public key',
        };
      }

      const signingDigestB64u = base64UrlEncode(signingDigest32);
      const intentDigest32 = await sha256BytesUtf8(
        alphabetizeStringify({
          version: 'threshold_ecdsa_authorize_intent_v1',
          purpose,
          signingDigestB64u,
        }),
      );

      const ttlMs = 60_000;
      const expiresAtMs = Date.now() + ttlMs;
      const mpcSessionId = this.createThresholdEcdsaMpcSessionId();
      await this.ecdsaSessionStore.putMpcSession(
        mpcSessionId,
        {
          expiresAtMs,
          ...(ecdsaThresholdKeyId ? { ecdsaThresholdKeyId } : {}),
          relayerKeyId,
          purpose,
          intentDigestB64u: base64UrlEncode(intentDigest32),
          signingDigestB64u,
          userId,
          rpId: tokenRpId,
          clientVerifyingShareB64u,
          participantIds: [...participantIds],
        },
        ttlMs,
      );

      return {
        ok: true,
        mpcSessionId,
        expiresAt: new Date(expiresAtMs).toISOString(),
        ...(this.ecdsaPresignPoolPolicyHint
          ? { presignPoolPolicy: this.ecdsaPresignPoolPolicyHint }
          : {}),
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
        ttlMsRaw,
        remainingUsesRaw,
        policyParticipantIds,
      } = parsedRequest.value;
      context = { nearAccountId, rpId, relayerKeyId, sessionId };

      await this.ensureReady();

      if (!this.verifyWebAuthnAuthenticationLite) {
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
        ...(policyParticipantIds ? { participantIds: policyParticipantIds } : {}),
        ttlMs,
        remainingUses,
      };
      const sessionPolicyDigest32 = await this.computeSessionPolicyDigest32(normalizedPolicy);
      const expectedChallenge = base64UrlEncode(sessionPolicyDigest32);

      const existingSession = await this.authSessionStore.getSession(sessionId);
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

      const verification = await this.verifyWebAuthnAuthenticationLite({
        nearAccountId,
        rpId,
        expectedChallenge,
        webauthn_authentication: request.webauthn_authentication,
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

      if (existingSession) {
        return {
          ok: true,
          sessionId,
          expiresAtMs: existingSession.expiresAtMs,
          expiresAt: new Date(existingSession.expiresAtMs).toISOString(),
          participantIds: existingSession.participantIds,
        };
      }

      const expiresAtMs = Date.now() + ttlMs;
      await this.putAuthSessionRecord({
        store: this.authSessionStore,
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

      return {
        ok: true,
        sessionId,
        expiresAtMs,
        expiresAt: new Date(expiresAtMs).toISOString(),
        participantIds,
        remainingUses,
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
    const sessionId = toOptionalTrimmedString(input.claims?.sessionId);
    if (!sessionId) {
      return { ok: false, code: 'unauthorized', message: 'Missing threshold sessionId' };
    }
    const userId = toOptionalTrimmedString(input.claims?.sub);
    if (!userId) return { ok: false, code: 'unauthorized', message: 'Missing threshold userId' };
    const tokenRelayerKeyId = toOptionalTrimmedString(input.claims?.relayerKeyId);
    if (!tokenRelayerKeyId) {
      return { ok: false, code: 'unauthorized', message: 'Invalid threshold session token claims' };
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
          message: `threshold session token does not include server signer set (expected to include participantIds=[${this.participantIds2p.join(',')}])`,
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
    const claimOrgId = toOptionalTrimmedString(input.claims.runtimeSnapshotScope?.orgId);
    if (claimOrgId && claimOrgId !== input.context.orgId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'context.orgId does not match threshold session scope',
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
    if (input.context.orgId !== input.orgId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'context.orgId does not match registration scope',
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
      const parseMs = Date.now() - parseStartedAt;

      const ensureReadyStartedAt = Date.now();
      await this.ensureReady();
      if (!this.ed25519MasterSecretB64u) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold-ed25519 HSS requires THRESHOLD_ED25519_MASTER_SECRET_B64U',
        };
      }

      const wasmStartedAt = Date.now();
      const [serverInputs, preparedServerSession] = await Promise.all([
        deriveThresholdEd25519HssServerInputs({
          masterSecretB64u: this.ed25519MasterSecretB64u,
          context: context.value,
        }),
        prepareThresholdEd25519HssServerSession({
          context: context.value,
        }),
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
      };
    } catch (e: unknown) {
      const msg = errorMessage(e);
      this.logger?.error?.('[threshold-ed25519] hss prepare failed', { message: msg });
      return { ok: false, code: 'internal', message: msg };
    }
  }

  private async ed25519HssPrepareForRegistration(input: {
    orgId: string;
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
      const parseMs = Date.now() - parseStartedAt;

      const ensureReadyStartedAt = Date.now();
      await this.ensureReady();
      if (!this.ed25519MasterSecretB64u) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold-ed25519 HSS requires THRESHOLD_ED25519_MASTER_SECRET_B64U',
        };
      }

      const wasmStartedAt = Date.now();
      const [serverInputs, preparedServerSession] = await Promise.all([
        deriveThresholdEd25519HssServerInputs({
          masterSecretB64u: this.ed25519MasterSecretB64u,
          context: context.value,
        }),
        prepareThresholdEd25519HssServerSession({
          context: context.value,
        }),
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
      const clientRequest = parseThresholdEd25519HssClientRequestEnvelope(rec.clientRequest);
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
      const result = await prepareThresholdEd25519HssServerCeremony({
        operation: ceremony.value.operation,
        preparedServerSession: ceremony.value.preparedServerSession,
        expectedContextBindingB64u: ceremony.value.preparedSession.contextBindingB64u,
        clientRequest: clientRequest.value,
        serverInputs,
      });
      clearThresholdEd25519HssStoredServerInputs(serverInputs);
      delete ceremony.value.serverInputs;
      ceremony.value.evaluationResult = result.evaluationResult.stagedEvaluatorArtifactHandle
        ? {
            stagedEvaluatorArtifactHandle: result.evaluationResult.stagedEvaluatorArtifactHandle,
          }
        : {
            stagedEvaluatorArtifactBytes: result.evaluationResult.stagedEvaluatorArtifactBytes!,
          };
      const ceremonyStateWithEvaluation: ThresholdEd25519HssCeremonyRecord = {
        ...ceremony.value,
        evaluationResult: ceremony.value.evaluationResult,
      };
      const wasmRespondMs = Date.now() - wasmStartedAt;
      const responsePayload = {
        ok: true,
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
        evaluatorOtStateBytes: utf8Bytes(clientRequest.value.evaluatorOtStateB64u),
        evaluatorOtStatePayloadBytes: base64UrlPayloadBytes(
          clientRequest.value.evaluatorOtStateB64u,
        ),
        evaluatorOtStateTransportOverheadBytes:
          utf8Bytes(clientRequest.value.evaluatorOtStateB64u) -
          base64UrlPayloadBytes(clientRequest.value.evaluatorOtStateB64u),
        parseMs,
        respondEngine: result.engine,
        wasmRespondMs,
        wasmRespondBreakdownMs: result.timings || null,
        wasmRespondBreakdownSummary:
          result.engine === 'wasm'
            ? summarizeThresholdEd25519HssWasmBreakdown(result.timings)
            : null,
        responseBytes: jsonBytes(responsePayload),
        evaluationResultBytes:
          result.evaluationResult.stagedEvaluatorArtifactBytes?.byteLength ??
          utf8Bytes(result.evaluationResult.stagedEvaluatorArtifactHandle || ''),
        ceremonyStateBytes: summarizeThresholdEd25519HssCeremonyRecordBytes(
          ceremonyStateWithEvaluation,
        ),
        totalMs: Date.now() - respondStartedAt,
      });

      return {
        ok: true,
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
      const clientRequest = parseThresholdEd25519HssClientRequestEnvelope(rec.clientRequest);
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
      const result = await prepareThresholdEd25519HssServerCeremony({
        operation: 'registration',
        preparedServerSession: ceremony.value.preparedServerSession,
        expectedContextBindingB64u: ceremony.value.preparedSession.contextBindingB64u,
        clientRequest: clientRequest.value,
        serverInputs,
      });
      clearThresholdEd25519HssStoredServerInputs(serverInputs);
      delete ceremony.value.serverInputs;
      ceremony.value.evaluationResult = result.evaluationResult.stagedEvaluatorArtifactHandle
        ? {
            stagedEvaluatorArtifactHandle: result.evaluationResult.stagedEvaluatorArtifactHandle,
          }
        : {
            stagedEvaluatorArtifactBytes: result.evaluationResult.stagedEvaluatorArtifactBytes!,
          };
      const ceremonyStateWithEvaluation: ThresholdEd25519HssCeremonyRecord = {
        ...ceremony.value,
        evaluationResult: ceremony.value.evaluationResult,
      };
      const wasmRespondMs = Date.now() - wasmStartedAt;
      const responsePayload = {
        ok: true,
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
        evaluatorOtStateBytes: utf8Bytes(clientRequest.value.evaluatorOtStateB64u),
        evaluatorOtStatePayloadBytes: base64UrlPayloadBytes(
          clientRequest.value.evaluatorOtStateB64u,
        ),
        evaluatorOtStateTransportOverheadBytes:
          utf8Bytes(clientRequest.value.evaluatorOtStateB64u) -
          base64UrlPayloadBytes(clientRequest.value.evaluatorOtStateB64u),
        parseMs,
        respondEngine: result.engine,
        wasmRespondMs,
        wasmRespondBreakdownMs: result.timings || null,
        wasmRespondBreakdownSummary:
          result.engine === 'wasm'
            ? summarizeThresholdEd25519HssWasmBreakdown(result.timings)
            : null,
        responseBytes: jsonBytes(responsePayload),
        evaluationResultBytes:
          result.evaluationResult.stagedEvaluatorArtifactBytes?.byteLength ??
          utf8Bytes(result.evaluationResult.stagedEvaluatorArtifactHandle || ''),
        ceremonyStateBytes: summarizeThresholdEd25519HssCeremonyRecordBytes(
          ceremonyStateWithEvaluation,
        ),
        totalMs: Date.now() - respondStartedAt,
      });

      return {
        ok: true,
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
      const evaluationResult = ceremony.value.evaluationResult;
      if (!evaluationResult) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ceremonyHandle has no staged evaluator artifact',
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
      if (!this.ed25519MasterSecretB64u) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold-ed25519 HSS requires THRESHOLD_ED25519_MASTER_SECRET_B64U',
        };
      }

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
          evaluationResult,
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
          evaluationResultBytes:
            evaluationResult.stagedEvaluatorArtifactBytes?.byteLength ??
            utf8Bytes(evaluationResult.stagedEvaluatorArtifactHandle || ''),
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
      const evaluationResult = ceremony.value.evaluationResult;
      if (!evaluationResult) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ceremonyHandle has no staged evaluator artifact',
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
      if (!this.ed25519MasterSecretB64u) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold-ed25519 HSS requires THRESHOLD_ED25519_MASTER_SECRET_B64U',
        };
      }

      const takenCeremony = this.takeThresholdEd25519HssCeremony(rec.ceremonyHandle);
      if (!takenCeremony.ok) return takenCeremony;
      try {
        const hssFinalizeStartedAt = Date.now();
        const result = await finalizeThresholdEd25519HssServerCeremony({
          operation: 'registration',
          preparedSession: takenCeremony.value.preparedSession,
          preparedServerSession: takenCeremony.value.preparedServerSession,
          evaluationResult,
          expectedContextBindingB64u: takenCeremony.value.preparedSession.contextBindingB64u,
        });
        const registrationMaterialStartedAt = Date.now();
        const registrationMaterial = await deriveThresholdEd25519RegistrationMaterialFromHssFinalize({
          preparedSession: takenCeremony.value.preparedSession,
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
        const responsePayload = {
          publicKey: registrationMaterial.publicKey,
          relayerKeyId: registrationMaterial.relayerKeyId,
        };
        this.logger?.info?.('[threshold-ed25519][registration] hss finalize timings', {
          nearAccountId: newAccountId,
          requestBytes: jsonBytes(input.request || {}),
          evaluationResultBytes:
            evaluationResult.stagedEvaluatorArtifactBytes?.byteLength ??
            utf8Bytes(evaluationResult.stagedEvaluatorArtifactHandle || ''),
          parseMs,
          hssFinalizeMs: Date.now() - hssFinalizeStartedAt,
          registrationMaterialMs: keyStorePutStartedAt - registrationMaterialStartedAt,
          keyStorePutMs: Date.now() - keyStorePutStartedAt,
          responseBytes: jsonBytes(responsePayload),
          finalizedReportBytes: jsonBytes(result.finalizedReport),
          totalMs: Date.now() - finalizeStartedAt,
        });

        return {
          ok: true,
          publicKey: registrationMaterial.publicKey,
          relayerKeyId: registrationMaterial.relayerKeyId,
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

  private async ed25519AuthorizeWithSession(input: {
    claims: ThresholdEd25519SessionClaims;
    request: ThresholdEd25519AuthorizeWithSessionRequest;
  }): Promise<ThresholdEd25519AuthorizeResponse> {
    try {
      const claims = input.claims;
      const sessionId = toOptionalTrimmedString(claims?.sessionId);
      if (!sessionId)
        return { ok: false, code: 'unauthorized', message: 'Missing threshold sessionId' };
      const userId = toOptionalTrimmedString(claims?.sub);
      if (!userId) return { ok: false, code: 'unauthorized', message: 'Missing threshold userId' };

      const tokenRelayerKeyId = toOptionalTrimmedString(claims?.relayerKeyId);
      const tokenRpId = toOptionalTrimmedString(claims?.rpId);
      if (!tokenRelayerKeyId || !tokenRpId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Invalid threshold session token claims',
        };
      }

      const parsedRequest = parseThresholdEd25519AuthorizeWithSessionRequest(input.request);
      if (!parsedRequest.ok) return parsedRequest;
      const { relayerKeyId, purpose, signingDigest32, signingPayload } = parsedRequest.value;

      await this.ensureReady();

      // Always validate relayerKeyId from the signed token claims before consuming a use.
      if (relayerKeyId !== tokenRelayerKeyId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'relayerKeyId does not match threshold session scope',
        };
      }

      const thresholdExpiresAtMs = claims.thresholdExpiresAtMs;
      if (Date.now() > thresholdExpiresAtMs) {
        return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
      }

      const participantIds = claims.participantIds;
      for (const id of this.participantIds2p) {
        if (!participantIds.includes(id)) {
          return {
            ok: false,
            code: 'unauthorized',
            message: `threshold session token does not include server signer set (expected to include participantIds=[${this.participantIds2p.join(',')}])`,
          };
        }
      }

      const consumed = await this.authSessionStore.consumeUseCount(sessionId);
      if (!consumed.ok) {
        return { ok: false, code: consumed.code, message: consumed.message };
      }

      const relayerKey = await this.resolveRelayerKeyMaterial({
        relayerKeyId,
      });
      if (!relayerKey.ok) {
        return { ok: false, code: relayerKey.code, message: relayerKey.message };
      }

      const verifyPayload = await verifyThresholdEd25519AuthorizeSigningPayloadSigningDigestOnly({
        purpose,
        signingPayload,
        signingDigest32,
        userId,
        ensureSignerWasm: this.ensureSignerWasm,
        computeNearTxSigningDigests: threshold_ed25519_compute_near_tx_signing_digests,
        computeDelegateSigningDigest: threshold_ed25519_compute_delegate_signing_digest,
        computeNep413SigningDigest: threshold_ed25519_compute_nep413_signing_digest,
      });
      if (!verifyPayload.ok) {
        return { ok: false, code: verifyPayload.code, message: verifyPayload.message };
      }

      const expectedSigningPublicKey = extractAuthorizeSigningPublicKey(purpose, signingPayload);
      const scope = await ensureRelayerKeyIsActiveAccessKey({
        nearAccountId: userId,
        relayerPublicKey: relayerKey.publicKey,
        ...(expectedSigningPublicKey ? { expectedSigningPublicKey } : {}),
        viewAccessKeyList: this.viewAccessKeyList,
      });
      if (!scope.ok) {
        return { ok: false, code: scope.code, message: scope.message };
      }

      const ttlMs = 60_000;
      const expiresAtMs = Date.now() + ttlMs;
      const mpcSessionId = this.createThresholdEd25519MpcSessionId();
      await this.sessionStore.putMpcSession(
        mpcSessionId,
        {
          expiresAtMs,
          relayerKeyId,
          purpose,
          intentDigestB64u: base64UrlEncode(verifyPayload.intentDigest32),
          signingDigestB64u: base64UrlEncode(signingDigest32),
          userId,
          rpId: tokenRpId,
          participantIds: [...participantIds],
        },
        ttlMs,
      );

      return {
        ok: true,
        mpcSessionId,
        expiresAt: new Date(expiresAtMs).toISOString(),
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

  // Signing round endpoints are exposed via SchemeModule.protocol (see `getSchemeModule`).
}
