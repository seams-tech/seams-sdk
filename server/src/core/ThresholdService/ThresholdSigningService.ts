import type { NormalizedLogger } from '../logger';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { SessionClaims } from '../../router/relay';
import type { AccessKeyList } from '@/core/rpcClients/near/NearClient';
import type { ThresholdEd25519KeyStore } from './stores/KeyStore';
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
  ThresholdEd25519HssEvaluationResultEnvelope,
  ThresholdEd25519HssFinalizeForRegistrationRequest,
  ThresholdEd25519HssFinalizeForRegistrationResponse,
  ThresholdEd25519HssFinalizeWithSessionRequest,
  ThresholdEd25519HssFinalizeWithSessionResponse,
  ThresholdEd25519HssPrepareForRegistrationRequest,
  ThresholdEd25519HssPrepareForRegistrationResponse,
  ThresholdEd25519HssPrepareWithSessionRequest,
  ThresholdEd25519HssPrepareWithSessionResponse,
  ThresholdEd25519HssPreparedSessionEnvelope,
  Ed25519SessionPolicy,
  ThresholdEcdsaKeygenRequest,
  ThresholdEcdsaKeygenResponse,
  ThresholdEcdsaBootstrapRequest,
  ThresholdEcdsaBootstrapResponse,
  EcdsaSessionPolicy,
  ThresholdEcdsaSessionRequest,
  ThresholdEcdsaSessionResponse,
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
  deriveThresholdSecp256k1RelayerShare,
  secp256k1PublicKey33ToEthereumAddress,
  validateSecp256k1PublicKey33,
} from './ethSignerWasm';
import {
  deriveThresholdEd25519VerifyingShareFromSigningShare,
  deriveThresholdEd25519RegistrationMaterialFromHssFinalize,
  finalizeThresholdEd25519HssServerCeremony,
  prepareThresholdEd25519HssServerCeremony,
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

function errorMessage(error: unknown): string {
  return String(
    error && typeof error === 'object' && 'message' in error
      ? (error as { message?: unknown }).message
      : error || '',
  );
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

function parseThresholdEcdsaRegistrationKeygenRequest(request: {
  userId: string;
  rpId: string;
  clientVerifyingShareB64u: string;
}): ParseResult<{
  userId: string;
  rpId: string;
  clientVerifyingShareB64u: string;
}> {
  const rec = (request || {}) as unknown as Record<string, unknown>;
  const userId = toOptionalTrimmedString(rec.userId);
  if (!userId) {
    return { ok: false, code: 'invalid_body', message: 'userId is required' };
  }
  const clientVerifyingShareB64u = toOptionalTrimmedString(rec.clientVerifyingShareB64u);
  if (!clientVerifyingShareB64u) {
    return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u is required' };
  }
  const rpId =
    toOptionalTrimmedString(rec.rpId) ||
    toOptionalTrimmedString((rec as unknown as { rp_id?: unknown }).rp_id);
  if (!rpId) {
    return { ok: false, code: 'invalid_body', message: 'rpId is required' };
  }
  return { ok: true, value: { userId, rpId, clientVerifyingShareB64u } };
}

function parseThresholdEcdsaKeygenRequest(request: ThresholdEcdsaKeygenRequest): ParseResult<{
  userId: string;
  clientVerifyingShareB64u: string;
  rpId: string;
  keygenSessionId: string;
}> {
  const rec = (request || {}) as unknown as Record<string, unknown>;
  const userId = toOptionalTrimmedString(rec.userId);
  if (!userId) {
    return { ok: false, code: 'invalid_body', message: 'userId is required' };
  }
  const clientVerifyingShareB64u = toOptionalTrimmedString(rec.clientVerifyingShareB64u);
  if (!clientVerifyingShareB64u) {
    return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u is required' };
  }
  const rpId =
    toOptionalTrimmedString(rec.rpId) ||
    toOptionalTrimmedString((rec as unknown as { rp_id?: unknown }).rp_id);
  if (!rpId) {
    return { ok: false, code: 'invalid_body', message: 'rpId is required' };
  }
  const keygenSessionId = toOptionalTrimmedString(rec.keygenSessionId);
  if (!keygenSessionId) {
    return { ok: false, code: 'invalid_body', message: 'keygenSessionId is required' };
  }
  return { ok: true, value: { userId, clientVerifyingShareB64u, rpId, keygenSessionId } };
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
  const context = parseThresholdEd25519HssCanonicalContext(raw);
  if (!context.ok) return context;
  const contextBindingB64u = toOptionalTrimmedString(raw.contextBindingB64u);
  const garblerDriverStateB64u = toOptionalTrimmedString(raw.garblerDriverStateB64u);
  const evaluatorDriverStateB64u = toOptionalTrimmedString(raw.evaluatorDriverStateB64u);
  const clientOtOfferMessageB64u = toOptionalTrimmedString(raw.clientOtOfferMessageB64u);
  if (!contextBindingB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'preparedSession.contextBindingB64u is required',
    };
  }
  if (!garblerDriverStateB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'preparedSession.garblerDriverStateB64u is required',
    };
  }
  if (!evaluatorDriverStateB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'preparedSession.evaluatorDriverStateB64u is required',
    };
  }
  if (!clientOtOfferMessageB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'preparedSession.clientOtOfferMessageB64u is required',
    };
  }
  return {
    ok: true,
    value: {
      ...context.value,
      contextBindingB64u,
      garblerDriverStateB64u,
      evaluatorDriverStateB64u,
      clientOtOfferMessageB64u,
    },
  };
}

function parseThresholdEd25519HssClientRequestEnvelope(
  raw: unknown,
): ParseResult<ThresholdEd25519HssClientRequestEnvelope> {
  if (!isObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'clientRequest is required' };
  }
  const contextBindingB64u = toOptionalTrimmedString(raw.contextBindingB64u);
  const clientRequestMessageB64u = toOptionalTrimmedString(raw.clientRequestMessageB64u);
  const evaluatorOtStateB64u = toOptionalTrimmedString(raw.evaluatorOtStateB64u);
  if (!contextBindingB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'clientRequest.contextBindingB64u is required',
    };
  }
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
    value: { contextBindingB64u, clientRequestMessageB64u, evaluatorOtStateB64u },
  };
}

function parseThresholdEd25519HssEvaluationResultEnvelope(
  raw: unknown,
): ParseResult<ThresholdEd25519HssEvaluationResultEnvelope> {
  if (!isObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'evaluationResult is required' };
  }
  const contextBindingB64u = toOptionalTrimmedString(raw.contextBindingB64u);
  const evaluationResultMessageB64u = toOptionalTrimmedString(raw.evaluationResultMessageB64u);
  if (!contextBindingB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'evaluationResult.contextBindingB64u is required',
    };
  }
  if (!evaluationResultMessageB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'evaluationResult.evaluationResultMessageB64u is required',
    };
  }
  return {
    ok: true,
    value: { contextBindingB64u, evaluationResultMessageB64u },
  };
}

function haveSameParticipantIds(a: number[], b: number[]): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function parseThresholdEcdsaAuthorizeWithSessionRequest(
  request: ThresholdEcdsaAuthorizeWithSessionRequest,
): ParseResult<{
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  purpose: string;
  signingDigest32: Uint8Array;
  signingPayload: unknown;
}> {
  const rec = (request || {}) as unknown as Record<string, unknown>;
  const relayerKeyId = toOptionalTrimmedString(rec.relayerKeyId);
  if (!relayerKeyId)
    return { ok: false, code: 'invalid_body', message: 'relayerKeyId is required' };
  const clientVerifyingShareB64u = toOptionalTrimmedString(rec.clientVerifyingShareB64u);
  if (!clientVerifyingShareB64u) {
    return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u is required' };
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
      relayerKeyId,
      clientVerifyingShareB64u,
      purpose,
      signingDigest32,
      signingPayload: rec.signingPayload,
    },
  };
}

function parseThresholdEcdsaSessionRequest(
  request: ThresholdEcdsaSessionRequest,
  participantIds2p: number[],
): ParseResult<{
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  userId: string;
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
  const clientVerifyingShareB64u = toOptionalTrimmedString(rec.clientVerifyingShareB64u);
  if (!clientVerifyingShareB64u) {
    return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u is required' };
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
  const userId = toOptionalTrimmedString((policyRaw as Record<string, unknown>).userId);
  const rpId = toOptionalTrimmedString((policyRaw as Record<string, unknown>).rpId);
  const sessionId = toOptionalTrimmedString((policyRaw as Record<string, unknown>).sessionId);
  const policyRelayerKeyId = toOptionalTrimmedString(
    (policyRaw as Record<string, unknown>).relayerKeyId,
  );
  const ttlMsRaw = Number((policyRaw as Record<string, unknown>).ttlMs);
  const remainingUsesRaw = Number((policyRaw as Record<string, unknown>).remainingUses);
  if (!userId || !rpId || !sessionId || !policyRelayerKeyId) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'sessionPolicy{userId,rpId,relayerKeyId,sessionId} are required',
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
      clientVerifyingShareB64u,
      userId,
      rpId,
      sessionId,
      ttlMsRaw,
      remainingUsesRaw,
      policyParticipantIds: policyParticipantIds || null,
    },
  };
}

function parseThresholdEcdsaBootstrapRequest(
  request: ThresholdEcdsaBootstrapRequest,
  participantIds2p: number[],
): ParseResult<{
  userId: string;
  rpId: string;
  keygenSessionId: string;
  clientVerifyingShareB64u: string;
  sessionId: string;
  ttlMsRaw: number;
  remainingUsesRaw: number;
  policyParticipantIds: number[] | null;
  webauthnAuthentication?: WebAuthnAuthenticationCredential;
  ed25519SessionClaims?: ThresholdEd25519SessionClaims;
}> {
  const hasSameParticipantIds = (left: number[], right: number[]): boolean => {
    return left.length === right.length && left.every((id, index) => id === right[index]);
  };

  const rec = (request || {}) as unknown as Record<string, unknown>;
  const userId = toOptionalTrimmedString(rec.userId);
  if (!userId) {
    return { ok: false, code: 'invalid_body', message: 'userId is required' };
  }
  const rpId =
    toOptionalTrimmedString(rec.rpId) ||
    toOptionalTrimmedString((rec as unknown as { rp_id?: unknown }).rp_id);
  if (!rpId) {
    return { ok: false, code: 'invalid_body', message: 'rpId is required' };
  }
  const keygenSessionId = toOptionalTrimmedString(rec.keygenSessionId);
  if (!keygenSessionId) {
    return { ok: false, code: 'invalid_body', message: 'keygenSessionId is required' };
  }
  const clientVerifyingShareB64u = toOptionalTrimmedString(rec.clientVerifyingShareB64u);
  if (!clientVerifyingShareB64u) {
    return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u is required' };
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

  const policyUserId = toOptionalTrimmedString((policyRaw as Record<string, unknown>).userId);
  const policyRpId = toOptionalTrimmedString((policyRaw as Record<string, unknown>).rpId);
  const sessionId = toOptionalTrimmedString((policyRaw as Record<string, unknown>).sessionId);
  const ttlMsRaw = Number((policyRaw as Record<string, unknown>).ttlMs);
  const remainingUsesRaw = Number((policyRaw as Record<string, unknown>).remainingUses);
  if (!policyUserId || !policyRpId || !sessionId) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'sessionPolicy{userId,rpId,sessionId} are required',
    };
  }
  if (policyUserId !== userId) {
    return { ok: false, code: 'invalid_body', message: 'sessionPolicy.userId must match userId' };
  }
  if (policyRpId !== rpId) {
    return { ok: false, code: 'invalid_body', message: 'sessionPolicy.rpId must match rpId' };
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

  const parsedEd25519SessionClaims = parseThresholdEd25519SessionClaims(
    (rec as { ed25519SessionClaims?: unknown }).ed25519SessionClaims,
  );
  if (parsedEd25519SessionClaims) {
    if (parsedEd25519SessionClaims.sub !== userId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'ed25519SessionClaims.sub must match userId',
      };
    }
    if (parsedEd25519SessionClaims.rpId !== rpId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'ed25519SessionClaims.rpId must match rpId',
      };
    }
    if (parsedEd25519SessionClaims.sessionId !== sessionId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'sessionPolicy.sessionId must match ed25519SessionClaims.sessionId',
      };
    }
    if (Date.now() > parsedEd25519SessionClaims.thresholdExpiresAtMs) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'ed25519 session token expired',
      };
    }
    for (const id of participantIds2p) {
      if (!parsedEd25519SessionClaims.participantIds.includes(id)) {
        return {
          ok: false,
          code: 'unauthorized',
          message: `ed25519 session token does not include server signer set (expected to include participantIds=[${participantIds2p.join(',')}])`,
        };
      }
    }
    if (
      policyParticipantIds &&
      !hasSameParticipantIds(policyParticipantIds, parsedEd25519SessionClaims.participantIds)
    ) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'sessionPolicy.participantIds must match ed25519 session token participantIds',
      };
    }
  }

  const webauthnAuthentication = (
    rec as {
      webauthn_authentication?: unknown;
    }
  ).webauthn_authentication as WebAuthnAuthenticationCredential | undefined;
  if (!parsedEd25519SessionClaims && !webauthnAuthentication) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'webauthn_authentication is required when no ed25519 session claims are provided',
    };
  }

  return {
    ok: true,
    value: {
      userId,
      rpId,
      keygenSessionId,
      clientVerifyingShareB64u,
      sessionId,
      ttlMsRaw,
      remainingUsesRaw,
      policyParticipantIds:
        policyParticipantIds || parsedEd25519SessionClaims?.participantIds || null,
      webauthnAuthentication: parsedEd25519SessionClaims ? undefined : webauthnAuthentication,
      ed25519SessionClaims: parsedEd25519SessionClaims || undefined,
    },
  };
}

export class ThresholdSigningService {
  private readonly logger: NormalizedLogger;
  private readonly keyStore: ThresholdEd25519KeyStore;
  private readonly sessionStore: ThresholdEd25519SessionStore;
  private readonly authSessionStore: Ed25519AuthSessionStore;
  private readonly ecdsaKeyStore: ThresholdEd25519KeyStore;
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
  private cachedSchemeModules: Partial<Record<ThresholdSchemeId, ThresholdAnySchemeModule>> | null =
    null;

  readonly ed25519Hss = {
    prepareForRegistration: async (input: {
      orgId: string;
      request: ThresholdEd25519HssPrepareForRegistrationRequest;
    }): Promise<ThresholdEd25519HssPrepareForRegistrationResponse> => {
      return this.ed25519HssPrepareForRegistration(input);
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

  constructor(input: {
    logger: NormalizedLogger;
    keyStore: ThresholdEd25519KeyStore;
    sessionStore: ThresholdEd25519SessionStore;
    authSessionStore: Ed25519AuthSessionStore;
    ecdsaKeyStore: ThresholdEd25519KeyStore;
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
      ensureReady: this.ensureReady,
      createSigningSessionId: () => this.createThresholdEcdsaSigningSessionId(),
      createPresignSessionId: () => this.createThresholdEcdsaPresignSessionId(),
    });
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
          keygen: (request) => this.ecdsaKeygen(request),
          session: (request) => this.ecdsaSession(request),
          bootstrap: (request) => this.ecdsaBootstrap(request),
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
    const keyVersion =
      toOptionalTrimmedString(input.context.keyVersion) ||
      toOptionalTrimmedString(input.preparedSession.keyVersion);
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

  private async ecdsaKeygen(
    request: ThresholdEcdsaKeygenRequest,
  ): Promise<ThresholdEcdsaKeygenResponse> {
    try {
      const parsedRequest = parseThresholdEcdsaKeygenRequest(request);
      if (!parsedRequest.ok) return parsedRequest;

      await this.ensureReady();

      const { userId, clientVerifyingShareB64u, rpId, keygenSessionId } = parsedRequest.value;
      const webauthnAuthentication = (request as unknown as { webauthn_authentication?: unknown })
        .webauthn_authentication;

      if (!this.verifyWebAuthnAuthenticationLite) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Lite WebAuthn verification is not configured on this server',
        };
      }

      const expectedIntentJson = alphabetizeStringify({
        version: 'threshold_ecdsa_keygen_v1',
        userId,
        rpId,
        keygenSessionId,
      });
      const expectedIntentDigest32 = await sha256BytesUtf8(expectedIntentJson);
      const expectedChallenge = base64UrlEncode(expectedIntentDigest32);

      const verification = await this.verifyWebAuthnAuthenticationLite({
        // NOTE: current WebAuthn stores are keyed by nearAccountId; in the multichain model
        // `userId` should become the stable identifier used by the authenticator store.
        nearAccountId: userId,
        rpId,
        expectedChallenge,
        webauthn_authentication: webauthnAuthentication as any,
      });

      if (!verification.success || !verification.verified) {
        return {
          ok: false,
          code: verification.code || 'not_verified',
          message: verification.message || 'Authentication verification failed',
        };
      }

      return await this.ecdsaKeygenFromClientVerifyingShare({
        userId,
        rpId,
        clientVerifyingShareB64u,
      });
    } catch (e: unknown) {
      this.logger?.error?.('thresholdEcdsaKeygen failed:', e);
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Internal error',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async ecdsaRegistrationKeygenFromClientVerifyingShare(request: {
    userId: string;
    rpId: string;
    clientVerifyingShareB64u: string;
  }): Promise<ThresholdEcdsaKeygenResponse> {
    try {
      const parsed = parseThresholdEcdsaRegistrationKeygenRequest(request);
      if (!parsed.ok) return parsed;

      await this.ensureReady();
      return await this.ecdsaKeygenFromClientVerifyingShare(parsed.value);
    } catch (e: unknown) {
      this.logger?.error?.('thresholdEcdsaRegistrationKeygen failed:', e);
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

  async mintEcdsaSessionFromRegistration(input: {
    userId: string;
    rpId: string;
    relayerKeyId: string;
    clientVerifyingShareB64u: string;
    sessionPolicy: EcdsaSessionPolicy;
  }): Promise<ThresholdEcdsaSessionResponse> {
    const userId = String(input.userId || '').trim();
    const rpId = String(input.rpId || '').trim();
    const relayerKeyId = String(input.relayerKeyId || '').trim();
    const clientVerifyingShareB64u = String(input.clientVerifyingShareB64u || '').trim();
    if (!userId || !rpId || !relayerKeyId || !clientVerifyingShareB64u) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Missing required ecdsa session bootstrap inputs',
      };
    }

    const policy = (input.sessionPolicy || {}) as EcdsaSessionPolicy;
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

    return await this.ecdsaMintSessionWithoutWebAuthn({
      relayerKeyId,
      clientVerifyingShareB64u,
      userId,
      rpId,
      sessionId,
      ttlMsRaw: Number(policy.ttlMs),
      remainingUsesRaw: Number(policy.remainingUses),
      policyParticipantIds,
    });
  }

  private async ecdsaKeygenFromClientVerifyingShare(input: {
    userId: string;
    rpId: string;
    clientVerifyingShareB64u: string;
  }): Promise<ThresholdEcdsaKeygenResponse> {
    const userId = String(input.userId || '').trim();
    const rpId = String(input.rpId || '').trim();
    const clientVerifyingShareB64u = String(input.clientVerifyingShareB64u || '').trim();
    if (!userId) return { ok: false, code: 'invalid_body', message: 'userId is required' };
    if (!rpId) return { ok: false, code: 'invalid_body', message: 'rpId is required' };
    if (!clientVerifyingShareB64u) {
      return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u is required' };
    }

    if (!this.secp256k1MasterSecretB64u) {
      return {
        ok: false,
        code: 'not_configured',
        message: 'threshold-secp256k1 keygen requires THRESHOLD_SECP256K1_MASTER_SECRET_B64U',
      };
    }

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

    let validatedClientPublicKey33: Uint8Array;
    try {
      validatedClientPublicKey33 = await validateSecp256k1PublicKey33(clientVerifyingShareBytes);
    } catch (e: unknown) {
      const runtimeMessage = errorMessage(e);
      if (isEthSignerWasmRuntimeError(runtimeMessage)) {
        return {
          ok: false,
          code: 'internal',
          message: runtimeMessage || 'eth_signer WASM runtime error',
        };
      }
      const prefixHex =
        clientVerifyingShareBytes.length > 0
          ? clientVerifyingShareBytes[0]!.toString(16).padStart(2, '0')
          : '??';
      return {
        ok: false,
        code: 'invalid_body',
        message: `clientVerifyingShareB64u is not a valid secp256k1 public key (decodedLen=${clientVerifyingShareBytes.length}, prefix=0x${prefixHex})`,
      };
    }

    const relayerKeyIdDigest32 = await sha256BytesUtf8(
      alphabetizeStringify({
        version: 'threshold_secp256k1_key_id_v1',
        schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
        userId,
        rpId,
        clientVerifyingShareB64u,
      }),
    );
    const relayerKeyId = `secp-${base64UrlEncode(relayerKeyIdDigest32)}`;

    const { relayerVerifyingShare33 } = await deriveThresholdSecp256k1RelayerShare({
      masterSecretB64u: this.secp256k1MasterSecretB64u,
      relayerKeyId,
    });
    const relayerVerifyingShareB64u = base64UrlEncode(relayerVerifyingShare33);

    const groupPublicKeyBytes = await addSecp256k1PublicKeys33({
      left33: validatedClientPublicKey33,
      right33: relayerVerifyingShare33,
    });
    const groupPublicKeyB64u = base64UrlEncode(groupPublicKeyBytes);

    const ethereumAddress = await secp256k1PublicKey33ToEthereumAddress(groupPublicKeyBytes);

    return {
      ok: true,
      participantIds: [...this.participantIds2p],
      relayerKeyId,
      groupPublicKeyB64u,
      ethereumAddress,
      relayerVerifyingShareB64u,
    };
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
  }): Promise<ThresholdEcdsaSessionResponse> {
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

    if (!this.secp256k1MasterSecretB64u) {
      return {
        ok: false,
        code: 'not_configured',
        message: 'threshold-ecdsa requires THRESHOLD_SECP256K1_MASTER_SECRET_B64U',
      };
    }

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

    const expectedRelayerKeyIdDigest32 = await sha256BytesUtf8(
      alphabetizeStringify({
        version: 'threshold_secp256k1_key_id_v1',
        schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
        userId,
        rpId,
        clientVerifyingShareB64u,
      }),
    );
    const expectedRelayerKeyId = `secp-${base64UrlEncode(expectedRelayerKeyIdDigest32)}`;
    if (relayerKeyId !== expectedRelayerKeyId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'relayerKeyId does not match clientVerifyingShareB64u binding',
      };
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

  private async ecdsaBootstrap(
    request: ThresholdEcdsaBootstrapRequest,
  ): Promise<ThresholdEcdsaBootstrapResponse> {
    let context: Record<string, unknown> | null = null;
    try {
      const parsedRequest = parseThresholdEcdsaBootstrapRequest(request, this.participantIds2p);
      if (!parsedRequest.ok) return parsedRequest;
      const {
        userId,
        rpId,
        keygenSessionId,
        clientVerifyingShareB64u,
        sessionId,
        ttlMsRaw,
        remainingUsesRaw,
        policyParticipantIds,
        webauthnAuthentication,
        ed25519SessionClaims,
      } = parsedRequest.value;
      context = {
        userId,
        rpId,
        keygenSessionId,
        sessionId,
        authMode: ed25519SessionClaims ? 'ed25519-session' : 'webauthn',
      };

      const keygen = ed25519SessionClaims
        ? await this.ecdsaRegistrationKeygenFromClientVerifyingShare({
            userId,
            rpId,
            clientVerifyingShareB64u,
          })
        : await this.ecdsaKeygen({
            userId,
            rpId,
            keygenSessionId,
            clientVerifyingShareB64u,
            webauthn_authentication: webauthnAuthentication as WebAuthnAuthenticationCredential,
          });
      if (!keygen.ok) return keygen;

      const relayerKeyId = toOptionalTrimmedString(keygen.relayerKeyId);
      if (!relayerKeyId) {
        return {
          ok: false,
          code: 'internal',
          message: 'threshold-ecdsa keygen returned empty relayerKeyId',
        };
      }

      const session = await this.ecdsaMintSessionWithoutWebAuthn({
        relayerKeyId,
        clientVerifyingShareB64u,
        userId,
        rpId,
        sessionId,
        ttlMsRaw,
        remainingUsesRaw,
        policyParticipantIds,
      });
      if (!session.ok) return session;

      return {
        ok: true,
        relayerKeyId,
        groupPublicKeyB64u: keygen.groupPublicKeyB64u,
        ethereumAddress: keygen.ethereumAddress,
        relayerVerifyingShareB64u: keygen.relayerVerifyingShareB64u,
        participantIds: session.participantIds || keygen.participantIds,
        sessionId: session.sessionId,
        expiresAtMs: session.expiresAtMs,
        expiresAt: session.expiresAt,
        remainingUses: session.remainingUses,
      };
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Internal error',
      );
      this.logger?.error?.('[threshold-ecdsa] bootstrap failed', {
        message: msg,
        ...(context || {}),
      });
      return { ok: false, code: 'internal', message: msg };
    }
  }

  private async ecdsaSession(
    request: ThresholdEcdsaSessionRequest,
  ): Promise<ThresholdEcdsaSessionResponse> {
    let context: Record<string, unknown> | null = null;
    try {
      const parsedRequest = parseThresholdEcdsaSessionRequest(request, this.participantIds2p);
      if (!parsedRequest.ok) return parsedRequest;
      const {
        relayerKeyId,
        clientVerifyingShareB64u,
        userId,
        rpId,
        sessionId,
        ttlMsRaw,
        remainingUsesRaw,
        policyParticipantIds,
      } = parsedRequest.value;
      context = { userId, rpId, relayerKeyId, sessionId };

      await this.ensureReady();

      if (!this.verifyWebAuthnAuthenticationLite) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Lite WebAuthn verification is not configured on this server',
        };
      }

      if (!this.secp256k1MasterSecretB64u) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold-ecdsa requires THRESHOLD_SECP256K1_MASTER_SECRET_B64U',
        };
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

      const expectedRelayerKeyIdDigest32 = await sha256BytesUtf8(
        alphabetizeStringify({
          version: 'threshold_secp256k1_key_id_v1',
          schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
          userId,
          rpId,
          clientVerifyingShareB64u,
        }),
      );
      const expectedRelayerKeyId = `secp-${base64UrlEncode(expectedRelayerKeyIdDigest32)}`;
      if (relayerKeyId !== expectedRelayerKeyId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'relayerKeyId does not match clientVerifyingShareB64u binding',
        };
      }

      const { ttlMs, remainingUses } = this.clampSessionPolicy({
        ttlMs: ttlMsRaw,
        remainingUses: remainingUsesRaw,
      });
      const participantIds = policyParticipantIds || [...this.participantIds2p];
      const normalizedPolicy = {
        version: 'threshold_session_v1',
        userId,
        rpId,
        relayerKeyId,
        sessionId,
        ...(policyParticipantIds ? { participantIds: policyParticipantIds } : {}),
        ttlMs,
        remainingUses,
      };
      const sessionPolicyDigest32 = await this.computeSessionPolicyDigest32(normalizedPolicy);
      const expectedChallenge = base64UrlEncode(sessionPolicyDigest32);

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

      const verification = await this.verifyWebAuthnAuthenticationLite({
        nearAccountId: userId,
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
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Internal error',
      );
      this.logger?.error?.('[threshold-ecdsa] session mint failed', {
        message: msg,
        ...(context || {}),
      });
      return { ok: false, code: 'internal', message: msg };
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
      const { relayerKeyId, clientVerifyingShareB64u, purpose, signingDigest32 } =
        parsedRequest.value;

      await this.ensureReady();

      if (!this.secp256k1MasterSecretB64u) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold-ecdsa requires THRESHOLD_SECP256K1_MASTER_SECRET_B64U',
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

      const expectedRelayerKeyIdDigest32 = await sha256BytesUtf8(
        alphabetizeStringify({
          version: 'threshold_secp256k1_key_id_v1',
          schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
          userId,
          rpId: tokenRpId,
          clientVerifyingShareB64u,
        }),
      );
      const expectedRelayerKeyId = `secp-${base64UrlEncode(expectedRelayerKeyIdDigest32)}`;
      if (relayerKeyId !== expectedRelayerKeyId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'relayerKeyId does not match clientVerifyingShareB64u binding',
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
    if (input.preparedSession.nearAccountId !== input.context.nearAccountId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'preparedSession.nearAccountId does not match context',
      };
    }
    if (input.preparedSession.orgId !== input.context.orgId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'preparedSession.orgId does not match context',
      };
    }
    if (input.preparedSession.keyPurpose !== input.context.keyPurpose) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'preparedSession.keyPurpose does not match context',
      };
    }
    if (input.preparedSession.keyVersion !== input.context.keyVersion) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'preparedSession.keyVersion does not match context',
      };
    }
    if (
      input.preparedSession.derivationVersion !== input.context.derivationVersion ||
      !haveSameParticipantIds(input.preparedSession.participantIds, input.context.participantIds)
    ) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'preparedSession participant scope does not match context',
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
    if (
      !haveSameParticipantIds(input.context.participantIds, this.participantIds2p) ||
      !haveSameParticipantIds(input.preparedSession.participantIds, this.participantIds2p)
    ) {
      return {
        ok: false,
        code: 'unauthorized',
        message: `threshold-ed25519 HSS context must match server signer set participantIds=[${this.participantIds2p.join(',')}]`,
      };
    }
    if (input.preparedSession.nearAccountId !== input.context.nearAccountId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'preparedSession.nearAccountId does not match context',
      };
    }
    if (input.preparedSession.orgId !== input.context.orgId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'preparedSession.orgId does not match context',
      };
    }
    if (input.preparedSession.keyPurpose !== input.context.keyPurpose) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'preparedSession.keyPurpose does not match context',
      };
    }
    if (input.preparedSession.keyVersion !== input.context.keyVersion) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'preparedSession.keyVersion does not match context',
      };
    }
    if (
      input.preparedSession.derivationVersion !== input.context.derivationVersion ||
      !haveSameParticipantIds(input.preparedSession.participantIds, input.context.participantIds)
    ) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'preparedSession participant scope does not match context',
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
      const rec = (input.request || {}) as unknown as Record<string, unknown>;
      const relayerKeyId = toOptionalTrimmedString(rec.relayerKeyId);
      if (!relayerKeyId) {
        return { ok: false, code: 'invalid_body', message: 'relayerKeyId is required' };
      }
      const context = parseThresholdEd25519HssCanonicalContext(rec.context);
      if (!context.ok) return context;
      const preparedSession = parseThresholdEd25519HssPreparedSessionEnvelope(rec.preparedSession);
      if (!preparedSession.ok) return preparedSession;
      const clientRequest = parseThresholdEd25519HssClientRequestEnvelope(rec.clientRequest);
      if (!clientRequest.ok) return clientRequest;

      const scopeError = this.validateThresholdEd25519HssSessionScope({
        claims: input.claims,
        relayerKeyId,
        context: context.value,
        preparedSession: preparedSession.value,
      });
      if (scopeError) return scopeError;

      if (clientRequest.value.contextBindingB64u !== preparedSession.value.contextBindingB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'clientRequest.contextBindingB64u does not match preparedSession',
        };
      }

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
      const result = await prepareThresholdEd25519HssServerCeremony({
        context: context.value,
        masterSecretB64u: this.ed25519MasterSecretB64u,
        preparedSession: preparedSession.value,
        clientRequest: clientRequest.value,
      });

      this.logger?.info?.('[threshold-ed25519] hss prepare timings', {
        relayerKeyId,
        nearAccountId: context.value.nearAccountId,
        ensureReadyMs: wasmStartedAt - ensureReadyStartedAt,
        wasmPrepareMs: Date.now() - wasmStartedAt,
        totalMs: Date.now() - prepareStartedAt,
      });

      return {
        ok: true,
        serverMessage: result.serverMessage,
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
      const preparedSession = parseThresholdEd25519HssPreparedSessionEnvelope(rec.preparedSession);
      if (!preparedSession.ok) return preparedSession;
      const clientRequest = parseThresholdEd25519HssClientRequestEnvelope(rec.clientRequest);
      if (!clientRequest.ok) return clientRequest;

      const scopeError = this.validateThresholdEd25519HssRegistrationScope({
        orgId: toOptionalTrimmedString(input.orgId) || '',
        newAccountId,
        context: context.value,
        preparedSession: preparedSession.value,
      });
      if (scopeError) return scopeError;

      if (clientRequest.value.contextBindingB64u !== preparedSession.value.contextBindingB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'clientRequest.contextBindingB64u does not match preparedSession',
        };
      }

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
      const result = await prepareThresholdEd25519HssServerCeremony({
        context: context.value,
        masterSecretB64u: this.ed25519MasterSecretB64u,
        preparedSession: preparedSession.value,
        clientRequest: clientRequest.value,
      });

      this.logger?.info?.('[threshold-ed25519][registration] hss prepare timings', {
        nearAccountId: newAccountId,
        ensureReadyMs: wasmStartedAt - ensureReadyStartedAt,
        wasmPrepareMs: Date.now() - wasmStartedAt,
        totalMs: Date.now() - prepareStartedAt,
      });

      return {
        ok: true,
        serverMessage: result.serverMessage,
      };
    } catch (e: unknown) {
      const msg = errorMessage(e);
      this.logger?.error?.('[threshold-ed25519][registration] hss prepare failed', {
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
      const rec = (input.request || {}) as unknown as Record<string, unknown>;
      const relayerKeyId = toOptionalTrimmedString(rec.relayerKeyId);
      if (!relayerKeyId) {
        return { ok: false, code: 'invalid_body', message: 'relayerKeyId is required' };
      }
      const context = parseThresholdEd25519HssCanonicalContext(rec.context);
      if (!context.ok) return context;
      const preparedSession = parseThresholdEd25519HssPreparedSessionEnvelope(rec.preparedSession);
      if (!preparedSession.ok) return preparedSession;
      const evaluationResult = parseThresholdEd25519HssEvaluationResultEnvelope(
        rec.evaluationResult,
      );
      if (!evaluationResult.ok) return evaluationResult;

      const scopeError = this.validateThresholdEd25519HssSessionScope({
        claims: input.claims,
        relayerKeyId,
        context: context.value,
        preparedSession: preparedSession.value,
      });
      if (scopeError) return scopeError;

      if (evaluationResult.value.contextBindingB64u !== preparedSession.value.contextBindingB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'evaluationResult.contextBindingB64u does not match preparedSession',
        };
      }

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
      const result = await finalizeThresholdEd25519HssServerCeremony({
        preparedSession: preparedSession.value,
        evaluationResult: evaluationResult.value,
      });
      const relayerShareRepairStartedAt = Date.now();
      const repair = await this.maybeRepairRelayerKeyMaterialFromSessionHssFinalize({
        claims: input.claims,
        context: context.value,
        preparedSession: preparedSession.value,
        serverOutput: result.serverOutput,
      });

      this.logger?.info?.('[threshold-ed25519] hss finalize timings', {
        relayerKeyId,
        nearAccountId: context.value.nearAccountId,
        ensureReadyMs: wasmStartedAt - ensureReadyStartedAt,
        wasmFinalizeMs: relayerShareRepairStartedAt - wasmStartedAt,
        relayerShareRepairMs: Date.now() - relayerShareRepairStartedAt,
        relayerShareRepaired: repair.repaired,
        totalMs: Date.now() - finalizeStartedAt,
      });

      return {
        ok: true,
        finalizedReport: result.finalizedReport,
      };
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
      const preparedSession = parseThresholdEd25519HssPreparedSessionEnvelope(rec.preparedSession);
      if (!preparedSession.ok) return preparedSession;
      const evaluationResult = parseThresholdEd25519HssEvaluationResultEnvelope(
        rec.evaluationResult,
      );
      if (!evaluationResult.ok) return evaluationResult;

      const scopeError = this.validateThresholdEd25519HssRegistrationScope({
        orgId: toOptionalTrimmedString(input.orgId) || '',
        newAccountId,
        context: context.value,
        preparedSession: preparedSession.value,
      });
      if (scopeError) return scopeError;

      if (evaluationResult.value.contextBindingB64u !== preparedSession.value.contextBindingB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'evaluationResult.contextBindingB64u does not match preparedSession',
        };
      }

      await this.ensureReady();
      if (!this.ed25519MasterSecretB64u) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold-ed25519 HSS requires THRESHOLD_ED25519_MASTER_SECRET_B64U',
        };
      }

      const hssFinalizeStartedAt = Date.now();
      const result = await finalizeThresholdEd25519HssServerCeremony({
        preparedSession: preparedSession.value,
        evaluationResult: evaluationResult.value,
      });
      const registrationMaterialStartedAt = Date.now();
      const registrationMaterial = await deriveThresholdEd25519RegistrationMaterialFromHssFinalize({
        preparedSession: preparedSession.value,
        finalizedReport: result.finalizedReport,
      });
      const keyStorePutStartedAt = Date.now();
      await this.keyStore.put(registrationMaterial.relayerKeyId, {
        nearAccountId: newAccountId,
        rpId,
        publicKey: registrationMaterial.publicKey,
        relayerSigningShareB64u: registrationMaterial.relayerSigningShareB64u,
        relayerVerifyingShareB64u: registrationMaterial.relayerVerifyingShareB64u,
        keyVersion: context.value.keyVersion,
        recoveryExportCapable: true,
      });
      this.logger?.info?.('[threshold-ed25519][registration] hss finalize timings', {
        nearAccountId: newAccountId,
        hssFinalizeMs: Date.now() - hssFinalizeStartedAt,
        registrationMaterialMs: keyStorePutStartedAt - registrationMaterialStartedAt,
        keyStorePutMs: Date.now() - keyStorePutStartedAt,
        totalMs: Date.now() - finalizeStartedAt,
      });

      return {
        ok: true,
        finalizedReport: result.finalizedReport,
        publicKey: registrationMaterial.publicKey,
        relayerKeyId: registrationMaterial.relayerKeyId,
      };
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
