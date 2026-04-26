import { ActionType, type ActionArgsWasm, validateActionArgsWasm } from '@/core/types/actions';
import {
  MinimalNearClient,
  SignedTransaction,
  type AccessKeyList,
} from '@/core/rpcClients/near/NearClient';
import type { FinalExecutionOutcome, TxExecutionStatus } from '@near-js/types';
import { toPublicKeyStringFromSecretKey } from './nearKeys';
import { createAuthServiceConfig } from './config';
import { formatGasToTGas, formatYoctoToNear } from './utils';
import { parseContractExecutionError } from './errors';
import { coerceSignerSlot } from '@shared/utils/signerSlot';
import {
  ensureEd25519Prefix,
  isValidAccountId,
  toOptionalTrimmedString,
} from '@shared/utils/validation';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  isWalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
import {
  EMAIL_OTP_RECOVERY_KEY_COUNT,
  encodeEmailOtpRecoveryWrappedEnrollmentAad,
} from '@shared/utils/emailOtpRecoveryKey';
import {
  buildRecoveryEmailBody,
  buildRecoveryEmailPayload,
  buildRecoveryEmailSubject,
  hashRecoveryEmailPayload,
  type RecoveryEmailPayload,
} from '@shared/utils/recoveryEmail';
import { coerceThresholdNodeRole } from './ThresholdService/config';
import type { ThresholdSigningService as ThresholdSigningServiceType } from './ThresholdService';
import type { ThresholdEd25519RegistrationKeygenResult } from './ThresholdService';
import {
  createThresholdSigningService,
  ensureThresholdEd25519HssWasm,
  THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
} from './ThresholdService';
import { sha256BytesUtf8 } from '@shared/utils/digests';
import initSignerWasm, {
  handle_signer_message,
  WorkerRequestType,
  WorkerResponseType,
  type InitInput,
  type WasmTransaction,
  type WasmSignature,
} from '../../../wasm/near_signer/pkg/wasm_signer_worker.js';

import type {
  AuthServiceConfig,
  AuthServiceConfigInput,
  AccountCreationRequest,
  AccountCreationResult,
  CreateAccountAndRegisterRequest,
  CreateAccountAndRegisterResult,
  CreateAccountAndRegisterSmartAccountTarget,
  OidcExchangeIssuerConfig,
  ThresholdRuntimePolicyScope,
  WebAuthnAuthenticationCredential,
  SignerWasmModuleSupplier,
} from './types';

export type GoogleEmailOtpResolutionMode =
  | 'existing_wallet'
  | 'register_started'
  | 'wallet_id_collision'
  | 'registration_incomplete';

export type GoogleEmailOtpResolutionResult =
  | {
      ok: true;
      mode: 'existing_wallet';
      walletId: string;
      providerSubject: string;
      email?: string;
      hasEmailOtpEnrollment: true;
    }
  | {
      ok: true;
      mode: 'register_started';
      walletId: string;
      providerSubject: string;
      email: string;
      registrationAttemptId: string;
      expiresAtMs: number;
    }
  | {
      ok: false;
      mode: 'wallet_id_collision' | 'registration_incomplete';
      code: 'wallet_id_collision' | 'registration_incomplete';
      walletId?: string;
      providerSubject: string;
      email?: string;
      message: string;
    };

import { EMAIL_DKIM_VERIFIER_CONTRACT_DEFAULT } from './defaultConfigsServer';
import { EmailRecoveryService } from '../email-recovery';
import { SignedDelegate } from '@/core/types/delegate';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { deriveHostedNearAccountId } from './hostedAccountIds';
import {
  type ExecuteSignedDelegateResult,
  executeSignedDelegateWithRelayer,
  type DelegateActionPolicy,
} from '../delegateAction';
import { coerceLogger, type NormalizedLogger } from './logger';
import { errorMessage, toError } from '@shared/utils/errors';
import { base64Decode, base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  createWebAuthnAuthenticatorStore,
  type WebAuthnAuthenticatorRecord,
  type WebAuthnAuthenticatorStore,
} from './WebAuthnAuthenticatorStore';
import {
  createWebAuthnLoginChallengeStore,
  type WebAuthnLoginChallengeStore,
} from './WebAuthnLoginChallengeStore';
import {
  createWebAuthnCredentialBindingStore,
  type WebAuthnCredentialBindingRecord,
  type WebAuthnCredentialBindingStore,
} from './WebAuthnCredentialBindingStore';
import {
  createWebAuthnSyncChallengeStore,
  type WebAuthnSyncChallengeStore,
} from './WebAuthnSyncChallengeStore';
import {
  createEmailOtpWalletEnrollmentStore,
  createEmailOtpRecoveryWrappedEnrollmentEscrowStore,
  createEmailOtpAuthStateStore,
  createEmailOtpChallengeStore,
  createEmailOtpGrantStore,
  createEmailOtpRegistrationAttemptStore,
  createEmailOtpUnlockChallengeStore,
  normalizeEmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  type EmailOtpWalletEnrollmentRecord,
  type EmailOtpWalletEnrollmentStore,
  type EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  type EmailOtpRecoveryWrappedEnrollmentEscrowStore,
  type EmailOtpAuthStateRecord,
  type EmailOtpAuthStateStore,
  type EmailOtpChannel,
  type EmailOtpChallengeAction,
  type EmailOtpChallengeOperation,
  type EmailOtpChallengeRecord,
  type EmailOtpChallengeStore,
  type EmailOtpGrantStore,
  type EmailOtpLoginChallengeOperation,
  type EmailOtpRegistrationAttemptStore,
  type EmailOtpUnlockChallengeStore,
  type GoogleEmailOtpRegistrationAttemptRecord,
} from './EmailOtpStores';
import {
  createSigningSessionSealShamir3PassCipherAdapter,
  resolveSigningSessionSealRateLimitFromEnv,
  type SigningSessionSealRateLimiter,
} from '../threshold/session/signingSessionSeal';
import {
  validateSecp256k1PublicKey33,
  verifySecp256k1RecoverableSignatureAgainstPublicKey33,
} from './ThresholdService/ethSignerWasm';
import {
  createDeviceLinkingSessionStore,
  type DeviceLinkingPreparedLinkedAccountRecord,
  type DeviceLinkingPreparedThresholdEcdsaRecord,
  type DeviceLinkingSessionRecord,
  type DeviceLinkingSessionStore,
} from './DeviceLinkingSessionStore';
import {
  createNearPublicKeyStore,
  type NearPublicKeyKind,
  type NearPublicKeyRecord,
  type NearPublicKeyStore,
} from './NearPublicKeyStore';
import {
  createAccountSignerStore,
  type AccountSignerRecord,
  type AccountSignerStore,
} from './AccountSignerStore';
import {
  createSmartAccountRecoverySubjectStore,
  type SmartAccountRecoverySubjectRecord,
  type SmartAccountRecoverySubjectStore,
} from './SmartAccountRecoverySubjectStore';
import {
  createRecoverySessionStore,
  type RecoverySessionStatus,
  type RecoverySessionStore,
} from './RecoverySessionStore';
import {
  createRecoveryExecutionStore,
  type RecoveryExecutionRecord,
  type RecoveryExecutionStatus,
  type RecoveryExecutionStore,
} from './RecoveryExecutionStore';
import { ensurePostgresSchema, getPostgresUrlFromConfig } from '../storage/postgres';
import {
  createIdentityStore,
  type IdentityStore,
  type LinkIdentityResult,
  type UnlinkIdentityResult,
} from './IdentityStore';
import { buildRegistrationSmartAccountRecords } from './smartAccountRegistrationRecords';
import {
  buildLinkDeviceSmartAccountRecords,
  type LinkedSmartAccountRecord,
} from './smartAccountLinkDeviceRecords';
import {
  buildPreparedRecoverySessionRecord,
  DEFAULT_RECOVERY_SESSION_TTL_MS,
} from './recoverySessionRecords';
import { buildRecoveryExecutionRecord } from './recoveryExecutionRecords';
import { syncCanonicalSmartAccountDeploymentManifest } from '../router/smartAccountDeploymentManifest';

const ACCOUNT_CREATE_BROADCAST_WAIT_UNTIL: TxExecutionStatus = 'EXECUTED_OPTIMISTIC';
const ACCOUNT_CREATE_FAST_KEY_VISIBILITY_CHECK = {
  attempts: 2,
  delayMs: 100,
  finality: 'optimistic' as const,
};
const ACCOUNT_CREATE_BACKGROUND_KEY_VISIBILITY_AUDIT = {
  attempts: 8,
  delayMs: 250,
  finality: 'final' as const,
};

function isObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

function logDuration(timings: Record<string, number>, key: string, startedAtMs: number): void {
  timings[key] = Date.now() - startedAtMs;
}

function decodeBase64UrlOrBase64(input: string, fieldName: string): Uint8Array {
  try {
    return base64UrlDecode(input);
  } catch {
    try {
      return base64Decode(input);
    } catch (err) {
      throw new Error(
        `Invalid ${fieldName}: expected base64url/base64 string (${errorMessage(err) || 'decode failed'})`,
      );
    }
  }
}

function parseClientDataJsonBase64url(clientDataJSONB64u: string): {
  challenge: string;
  origin: string;
  type: string;
} {
  const bytes = decodeBase64UrlOrBase64(
    clientDataJSONB64u,
    'webauthn_authentication.response.clientDataJSON',
  );
  const json = new TextDecoder().decode(bytes);
  const obj = JSON.parse(json) as unknown;
  if (!isObject(obj)) throw new Error('Invalid clientDataJSON: expected object');
  const challenge = typeof obj.challenge === 'string' ? obj.challenge : '';
  const origin = typeof obj.origin === 'string' ? obj.origin : '';
  const type = typeof obj.type === 'string' ? obj.type : '';
  if (!challenge) throw new Error('Invalid clientDataJSON.challenge');
  if (!origin) throw new Error('Invalid clientDataJSON.origin');
  if (!type) throw new Error('Invalid clientDataJSON.type');
  return { challenge, origin, type };
}

function originHostnameOrEmpty(origin: string): string {
  try {
    return new URL(origin).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function isHostWithinRpId(host: string, rpId: string): boolean {
  const h = (host || '').toLowerCase();
  const r = (rpId || '').toLowerCase();
  if (!h || !r) return false;
  return h === r || h.endsWith(`.${r}`);
}

function parseCacheControlMaxAgeSec(cacheControl: string | null): number | null {
  const s = String(cacheControl || '').trim();
  if (!s) return null;
  const m = s.match(/(?:^|,)\s*max-age=(\d+)\s*(?:,|$)/i);
  if (!m) return null;
  const n = Number(m[1]);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.floor(n);
}

function normalizeOidcIssuer(input: string): string {
  const trimmed = String(input || '').trim();
  if (!trimmed) return '';
  return trimmed.endsWith('/') ? trimmed.slice(0, -1) : trimmed;
}

function parseJwtSegmentJson(input: string): Record<string, unknown> | null {
  try {
    const raw = new TextDecoder().decode(base64UrlDecode(input));
    const parsed = raw ? JSON.parse(raw) : null;
    return isObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function parseJwtAud(input: unknown): string[] {
  if (Array.isArray(input)) {
    return input.map((v) => (typeof v === 'string' ? v.trim() : '')).filter(Boolean);
  }
  const single = toOptionalTrimmedString(input);
  return single ? [single] : [];
}

type ThresholdEd25519RegistrationInput = {
  keyVersion: string;
  recoveryExportCapable?: boolean;
  publicKey: string;
  relayerKeyId: string;
  sessionPolicy: Record<string, unknown> | null;
  sessionKind: string;
};

type ThresholdEcdsaBootstrapInput = {
  clientRootShare32B64u: string;
  sessionPolicy: Record<string, unknown> | null;
  sessionKind: string;
};

type ThresholdEd25519BootstrapSession = {
  sessionKind: 'jwt' | 'cookie';
  sessionId: string;
  walletSigningSessionId: string;
  expiresAtMs: number;
  expiresAt?: string;
  participantIds?: number[];
  remainingUses?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  jwt?: string;
};

type ThresholdEcdsaBootstrapSession = {
  sessionKind: 'jwt' | 'cookie';
  sessionId: string;
  walletSigningSessionId: string;
  expiresAtMs: number;
  expiresAt?: string;
  participantIds?: number[];
  remainingUses?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  jwt?: string;
};

function parseThresholdEd25519RegistrationInput(raw: unknown): ThresholdEd25519RegistrationInput {
  const body = isObject(raw) ? (raw as Record<string, unknown>) : null;
  return {
    keyVersion: String(body?.key_version || '').trim(),
    recoveryExportCapable:
      typeof body?.recovery_export_capable === 'boolean'
        ? Boolean(body.recovery_export_capable)
        : undefined,
    publicKey: String(body?.public_key || '').trim(),
    relayerKeyId: String(body?.relayer_key_id || '').trim(),
    sessionPolicy: isObject(body?.session_policy)
      ? (body!.session_policy as Record<string, unknown>)
      : null,
    sessionKind: String(body?.session_kind || '')
      .trim()
      .toLowerCase(),
  };
}

function parseThresholdEcdsaBootstrapInput(raw: unknown): ThresholdEcdsaBootstrapInput {
  const body = isObject(raw) ? (raw as Record<string, unknown>) : null;
  return {
    clientRootShare32B64u: String(body?.client_root_share32_b64u || '').trim(),
    sessionPolicy: isObject(body?.session_policy)
      ? (body!.session_policy as Record<string, unknown>)
      : null,
    sessionKind: String(body?.session_kind || '')
      .trim()
      .toLowerCase(),
  };
}

function buildFullAccessAddKeyAction(publicKey: string): ActionArgsWasm {
  return {
    action_type: ActionType.AddKey,
    public_key: publicKey,
    access_key: JSON.stringify({
      nonce: 0,
      permission: { FullAccess: {} },
    }),
  };
}

function normalizeBootstrapPublicKeys(args: { publicKey: string; recoveryPublicKey?: string }): {
  publicKey: string;
  recoveryPublicKey?: string;
  expectedPublicKeys: string[];
} {
  const publicKey = ensureEd25519Prefix(toOptionalTrimmedString(args.publicKey) || '');
  if (!publicKey) {
    throw new Error('Missing or invalid bootstrap operational public key');
  }
  const recoveryPublicKey = ensureEd25519Prefix(
    toOptionalTrimmedString(args.recoveryPublicKey) || '',
  );
  if (recoveryPublicKey && recoveryPublicKey === publicKey) {
    throw new Error('Bootstrap recovery public key must differ from the operational public key');
  }
  return {
    publicKey,
    ...(recoveryPublicKey ? { recoveryPublicKey } : {}),
    expectedPublicKeys: recoveryPublicKey ? [publicKey, recoveryPublicKey] : [publicKey],
  };
}

function normalizeThresholdRuntimePolicyScope(
  raw: unknown,
): ThresholdRuntimePolicyScope | undefined {
  try {
    return normalizeRuntimePolicyScope(raw);
  } catch {
    return undefined;
  }
}

async function resolveBoundThresholdRuntimePolicyScope(args: {
  bindingStore: WebAuthnCredentialBindingStore;
  userId: string;
  rpId: string;
}): Promise<ThresholdRuntimePolicyScope | undefined> {
  if (typeof args.bindingStore.listByUserId !== 'function') return undefined;
  const bindings = await args.bindingStore.listByUserId({
    userId: args.userId,
    rpId: args.rpId,
  });
  for (const binding of bindings) {
    const scope = normalizeThresholdRuntimePolicyScope(binding.runtimePolicyScope);
    if (scope) return scope;
  }
  return undefined;
}

async function sha256BytesPortable(input: Uint8Array): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle && typeof subtle.digest === 'function') {
    return new Uint8Array(await subtle.digest('SHA-256', input));
  }
  if (typeof process !== 'undefined' && process.versions?.node) {
    const { createHash } = await import('node:crypto');
    return Uint8Array.from(createHash('sha256').update(input).digest());
  }
  throw new Error('SHA-256 digest is unavailable in this runtime');
}

async function resolveExistingThresholdEd25519Binding(args: {
  bindingStore: WebAuthnCredentialBindingStore;
  userId: string;
  rpId: string;
}): Promise<WebAuthnCredentialBindingRecord | undefined> {
  if (typeof args.bindingStore.listByUserId !== 'function') return undefined;
  const bindings = await args.bindingStore.listByUserId({
    userId: args.userId,
    rpId: args.rpId,
  });
  return bindings.find((binding) => {
    return Boolean(
      toOptionalTrimmedString(binding.relayerKeyId) &&
      toOptionalTrimmedString(binding.publicKey) &&
      toOptionalTrimmedString(binding.keyVersion) &&
      binding.recoveryExportCapable === true,
    );
  });
}

function validateThresholdEd25519SessionPolicyBindings(args: {
  requestedSessionPolicy: Record<string, unknown>;
  expectedRelayerKeyId: string;
  expectedNearAccountId: string;
  expectedRpId: string;
}): string | null {
  const requestedPolicyRelayerKeyId = String(args.requestedSessionPolicy.relayerKeyId || '').trim();
  if (requestedPolicyRelayerKeyId && requestedPolicyRelayerKeyId !== args.expectedRelayerKeyId) {
    return 'threshold_ed25519.session_policy.relayerKeyId mismatch';
  }
  const requestedPolicyNearAccountId = String(
    args.requestedSessionPolicy.nearAccountId || '',
  ).trim();
  if (requestedPolicyNearAccountId && requestedPolicyNearAccountId !== args.expectedNearAccountId) {
    return 'threshold_ed25519.session_policy.nearAccountId mismatch';
  }
  const requestedPolicyRpId = String(args.requestedSessionPolicy.rpId || '').trim();
  if (requestedPolicyRpId && requestedPolicyRpId !== args.expectedRpId) {
    return 'threshold_ed25519.session_policy.rpId mismatch';
  }
  return null;
}

function toThresholdEd25519BootstrapSession(session: {
  sessionId?: unknown;
  walletSigningSessionId?: unknown;
  expiresAtMs?: unknown;
  expiresAt?: unknown;
  participantIds?: unknown;
  remainingUses?: unknown;
  runtimePolicyScope?: unknown;
}): ThresholdEd25519BootstrapSession | null {
  const sessionId = String(session.sessionId || '').trim();
  const walletSigningSessionId = String(session.walletSigningSessionId || '').trim();
  const expiresAtMs = Number(session.expiresAtMs);
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(session.runtimePolicyScope);
  if (!sessionId || !walletSigningSessionId || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0)
    return null;
  return {
    sessionKind: 'jwt',
    sessionId,
    walletSigningSessionId,
    expiresAtMs: Number(expiresAtMs),
    ...(typeof session.expiresAt === 'string' && session.expiresAt.trim()
      ? { expiresAt: session.expiresAt.trim() }
      : {}),
    ...(Array.isArray(session.participantIds) ? { participantIds: session.participantIds } : {}),
    ...(Number.isFinite(Number(session.remainingUses))
      ? { remainingUses: Number(session.remainingUses) }
      : {}),
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
  };
}

function toThresholdEcdsaBootstrapSession(session: {
  sessionId?: unknown;
  walletSigningSessionId?: unknown;
  expiresAtMs?: unknown;
  expiresAt?: unknown;
  participantIds?: unknown;
  remainingUses?: unknown;
  runtimePolicyScope?: unknown;
  jwt?: unknown;
}): ThresholdEcdsaBootstrapSession | null {
  const sessionId = String(session.sessionId || '').trim();
  const walletSigningSessionId = String(session.walletSigningSessionId || '').trim();
  const expiresAtMs = Number(session.expiresAtMs);
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(session.runtimePolicyScope);
  if (!sessionId || !walletSigningSessionId || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0)
    return null;
  return {
    sessionKind: 'jwt',
    sessionId,
    walletSigningSessionId,
    expiresAtMs: Number(expiresAtMs),
    ...(typeof session.expiresAt === 'string' && session.expiresAt.trim()
      ? { expiresAt: session.expiresAt.trim() }
      : {}),
    ...(Array.isArray(session.participantIds) ? { participantIds: session.participantIds } : {}),
    ...(Number.isFinite(Number(session.remainingUses))
      ? { remainingUses: Number(session.remainingUses) }
      : {}),
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(typeof session.jwt === 'string' && session.jwt.trim() ? { jwt: session.jwt.trim() } : {}),
  };
}

// =============================
// WASM URL CONSTANTS + HELPERS
// =============================

// Primary location (preserveModules output) when this file is emitted to
// `dist/esm/server/core/AuthService.js`.
const SIGNER_WASM_MAIN_PATH = '../../wasm/near_signer/pkg/wasm_signer_worker_bg.wasm';
// Fallback location (dist/workers copy step) from `dist/esm/server/core`.
const SIGNER_WASM_FALLBACK_PATH = '../../workers/wasm_signer_worker_bg.wasm';
// Source-tree location when AuthService is executed directly from `server/src/core`.
const SIGNER_WASM_SOURCE_PATH = '../../../wasm/near_signer/pkg/wasm_signer_worker_bg.wasm';

function getSignerWasmUrls(logger: NormalizedLogger): URL[] {
  const paths = [SIGNER_WASM_MAIN_PATH, SIGNER_WASM_FALLBACK_PATH, SIGNER_WASM_SOURCE_PATH];
  const resolved: URL[] = [];
  const baseUrl = import.meta.url;

  for (const path of paths) {
    try {
      if (!baseUrl) throw new Error('import.meta.url is undefined');
      resolved.push(new URL(path, baseUrl));
    } catch (err) {
      logger.warn(`Failed to resolve signer WASM relative URL for path "${path}":`, err);
    }
  }

  if (!resolved.length) {
    throw new Error(
      'Unable to resolve signer WASM location from import.meta.url. Provide AuthServiceConfig.signerWasm.moduleOrPath in this runtime.',
    );
  }

  return resolved;
}

function summarizeThresholdStoreConfig(cfg: AuthServiceConfig['thresholdStore']): string {
  if (!cfg) return 'thresholdStore: not configured';

  const nodeRole = coerceThresholdNodeRole(cfg.THRESHOLD_NODE_ROLE);

  const store = (() => {
    if ('kind' in cfg) {
      if (cfg.kind === 'upstash-redis-rest') return 'upstash';
      if (cfg.kind === 'redis-tcp') return 'redis';
      if (cfg.kind === 'postgres') return 'postgres';
      return 'in-memory';
    }
    const upstashUrl = toOptionalTrimmedString(cfg.UPSTASH_REDIS_REST_URL);
    const upstashToken = toOptionalTrimmedString(cfg.UPSTASH_REDIS_REST_TOKEN);
    const redisUrl = toOptionalTrimmedString(cfg.REDIS_URL);
    const postgresUrl = toOptionalTrimmedString(cfg.POSTGRES_URL);
    if (postgresUrl) return 'postgres';
    return upstashUrl || upstashToken ? 'upstash' : redisUrl ? 'redis' : 'in-memory';
  })();

  const hasSigningRootSecretShares = Boolean(
    cfg.signingRootShareResolver ||
    cfg.signingRootSecretResolverAdapters ||
    (cfg.signingRootSecretStore &&
      (cfg.signingRootSecretDecryptAdapter || cfg.signingRootSecretShareKekResolver)),
  );
  const parts = [
    `thresholdStore: configured`,
    `nodeRole=${nodeRole}`,
    `store=${store}`,
    `signingRootSecretShares=${hasSigningRootSecretShares ? 'configured' : 'not_configured'}`,
  ];
  return parts.join(' ');
}

/**
 * Framework-agnostic NEAR account service
 * Core business logic for account creation and registration operations
 */
export class AuthService {
  private config: AuthServiceConfig;
  private isInitialized = false;
  private nearClient: MinimalNearClient;
  private relayerPublicKey: string = '';
  private signerWasmReady = false;
  private readonly logger: NormalizedLogger;
  private thresholdSigningServiceInitialized = false;
  private thresholdSigningService: ThresholdSigningServiceType | null = null;
  private webAuthnAuthenticatorStoreInitialized = false;
  private webAuthnAuthenticatorStore: WebAuthnAuthenticatorStore | null = null;
  private webAuthnLoginChallengeStoreInitialized = false;
  private webAuthnLoginChallengeStore: WebAuthnLoginChallengeStore | null = null;
  private webAuthnCredentialBindingStoreInitialized = false;
  private webAuthnCredentialBindingStore: WebAuthnCredentialBindingStore | null = null;
  private webAuthnSyncChallengeStoreInitialized = false;
  private webAuthnSyncChallengeStore: WebAuthnSyncChallengeStore | null = null;
  private emailOtpChallengeStoreInitialized = false;
  private emailOtpChallengeStore: EmailOtpChallengeStore | null = null;
  private emailOtpGrantStoreInitialized = false;
  private emailOtpGrantStore: EmailOtpGrantStore | null = null;
  private emailOtpWalletEnrollmentStoreInitialized = false;
  private emailOtpWalletEnrollmentStore: EmailOtpWalletEnrollmentStore | null = null;
  private emailOtpRecoveryWrappedEnrollmentEscrowStoreInitialized = false;
  private emailOtpRecoveryWrappedEnrollmentEscrowStore: EmailOtpRecoveryWrappedEnrollmentEscrowStore | null =
    null;
  private emailOtpAuthStateStoreInitialized = false;
  private emailOtpAuthStateStore: EmailOtpAuthStateStore | null = null;
  private emailOtpUnlockChallengeStoreInitialized = false;
  private emailOtpUnlockChallengeStore: EmailOtpUnlockChallengeStore | null = null;
  private emailOtpRegistrationAttemptStoreInitialized = false;
  private emailOtpRegistrationAttemptStore: EmailOtpRegistrationAttemptStore | null = null;
  private emailOtpRateLimiterInitialized = false;
  private emailOtpRateLimiter: SigningSessionSealRateLimiter | null = null;
  private readonly emailOtpMemoryOutbox = new Map<
    string,
    {
      walletId: string;
      userId: string;
      otpChannel: EmailOtpChannel;
      email: string;
      emailHint: string;
      otpCode: string;
      expiresAtMs: number;
    }
  >();
  private deviceLinkingSessionStoreInitialized = false;
  private deviceLinkingSessionStore: DeviceLinkingSessionStore | null = null;
  private nearPublicKeyStoreInitialized = false;
  private nearPublicKeyStore: NearPublicKeyStore | null = null;
  private accountSignerStoreInitialized = false;
  private accountSignerStore: AccountSignerStore | null = null;
  private smartAccountRecoverySubjectStoreInitialized = false;
  private smartAccountRecoverySubjectStore: SmartAccountRecoverySubjectStore | null = null;
  private recoverySessionStoreInitialized = false;
  private recoverySessionStore: RecoverySessionStore | null = null;
  private recoveryExecutionStoreInitialized = false;
  private recoveryExecutionStore: RecoveryExecutionStore | null = null;
  private identityStoreInitialized = false;
  private identityStore: IdentityStore | null = null;
  private storageInitPromise: Promise<void> | null = null;
  private registrationRuntimeWarmPromise: Promise<void> | null = null;
  private googleJwksCache: { keysByKid: Map<string, JsonWebKey>; expiresAtMs: number } | null =
    null;
  private googleJwksFetchPromise: Promise<{
    keysByKid: Map<string, JsonWebKey>;
    expiresAtMs: number;
  }> | null = null;
  private oidcJwksCacheByUrl = new Map<
    string,
    { keysByKid: Map<string, JsonWebKey>; expiresAtMs: number }
  >();
  private oidcJwksFetchPromiseByUrl = new Map<
    string,
    Promise<{ keysByKid: Map<string, JsonWebKey>; expiresAtMs: number }>
  >();

  // Transaction queue to prevent nonce conflicts
  private transactionQueue: Promise<any> = Promise.resolve();
  private queueStats = { pending: 0, completed: 0, failed: 0 };

  // DKIM/TEE email recovery logic (delegated to EmailRecoveryService)
  public readonly emailRecovery: EmailRecoveryService | null = null;

  constructor(config: AuthServiceConfigInput) {
    this.config = createAuthServiceConfig(config);
    this.logger = coerceLogger(this.config.logger);
    this.nearClient = new MinimalNearClient(this.config.nearRpcUrl);
    this.emailRecovery = new EmailRecoveryService({
      relayerAccount: this.config.relayerAccount,
      relayerPrivateKey: this.config.relayerPrivateKey,
      networkId: this.config.networkId,
      emailDkimVerifierContract: EMAIL_DKIM_VERIFIER_CONTRACT_DEFAULT,
      nearClient: this.nearClient,
      logger: this.config.logger,
      ensureSignerAndRelayerAccount: () => this._ensureSignerAndRelayerAccount(),
      queueTransaction: <T>(fn: () => Promise<T>, label: string) =>
        this.queueTransaction(fn, label),
      fetchTxContext: (accountId: string, publicKey: string) =>
        this.fetchTxContext(accountId, publicKey),
      signWithPrivateKey: (input) => this.signWithPrivateKey(input),
      getRelayerPublicKey: () => this.relayerPublicKey,
    });

    // Log effective configuration at construction time so operators can
    // verify wiring immediately when the service is created.
    this.logger.info(`
    AuthService initialized with:
    • networkId: ${this.config.networkId}
    • nearRpcUrl: ${this.config.nearRpcUrl}
    • relayerAccount: ${this.config.relayerAccount}
    • accountInitialBalance: ${this.config.accountInitialBalance} (${formatYoctoToNear(this.config.accountInitialBalance)} NEAR)
    • createAccountAndRegisterGas: ${this.config.createAccountAndRegisterGas} (${formatGasToTGas(this.config.createAccountAndRegisterGas)})
    • ${summarizeThresholdStoreConfig(this.config.thresholdStore)}
    ${
      this.config.googleOidc?.clientIds?.length
        ? `• googleOidc: ${this.config.googleOidc.clientIds.length} clientId(s)`
        : `• googleOidc: not configured`
    }
    ${
      this.config.oidcExchange?.issuers?.length
        ? `• oidcExchange: ${this.config.oidcExchange.issuers.length} issuer(s)`
        : `• oidcExchange: not configured`
    }
    `);
  }

  /**
   * Initializes backing storage (e.g. Postgres schema) when configured.
   * Safe to call multiple times; initialization is memoized.
   */
  async initStorage(): Promise<void> {
    if (this.storageInitPromise) return this.storageInitPromise;

    this.storageInitPromise = (async () => {
      if (!this.config.thresholdStore) return;

      const cfg = this.config.thresholdStore as unknown as Record<string, unknown>;
      const kind = toOptionalTrimmedString((cfg as any).kind);
      const postgresUrl = getPostgresUrlFromConfig(cfg);

      const usePostgres = kind === 'postgres' || (!kind && Boolean(postgresUrl));
      if (!usePostgres) return;
      if (!postgresUrl) throw new Error('Postgres store selected but POSTGRES_URL is not set');

      await ensurePostgresSchema({ postgresUrl, logger: this.logger });
    })();

    return this.storageInitPromise;
  }

  async getRelayerAccount(): Promise<{ accountId: string; publicKey: string }> {
    await this._ensureSignerAndRelayerAccount();
    return {
      accountId: this.config.relayerAccount,
      publicKey: this.relayerPublicKey,
    };
  }

  /**
   * Lightweight config accessor (no RPC) for diagnostics and well-known endpoints.
   * This is safe to call even when the relayer account has not been warmed/validated yet.
   */
  getConfiguredRelayerAccount(): string {
    return this.config.relayerAccount;
  }

  isGoogleOidcConfigured(): boolean {
    return Boolean(this.config.googleOidc?.clientIds?.length);
  }

  getGoogleOidcPublicConfig(): { configured: boolean; clientId?: string } {
    const clientId = String(this.config.googleOidc?.clientIds?.[0] || '').trim();
    return {
      configured: Boolean(clientId),
      ...(clientId ? { clientId } : {}),
    };
  }

  private isRelayerSubaccount(accountId: string): boolean {
    const relayerAccount = String(this.config.relayerAccount || '').trim();
    return !!relayerAccount && accountId.endsWith(`.${relayerAccount}`);
  }

  private isHostedHmacReadableRelayerSubaccount(accountId: string): boolean {
    const relayerAccount = String(this.config.relayerAccount || '').trim();
    if (!relayerAccount || !accountId.endsWith(`.${relayerAccount}`)) return false;
    const slug = accountId.slice(0, -(relayerAccount.length + 1));
    return /^[a-z]+-[a-z]+-[a-z0-9]{10}$/.test(slug);
  }

  private resolveHostedAccountScope(input?: ThresholdRuntimePolicyScope): {
    projectId: string;
    envId: string;
  } {
    const orgId = toOptionalTrimmedString(input?.orgId);
    const projectId = toOptionalTrimmedString(input?.projectId);
    const envId = toOptionalTrimmedString(input?.envId);
    if (orgId && projectId && envId) {
      return { projectId, envId };
    }
    throw new Error(
      'runtimePolicyScope.orgId, runtimePolicyScope.projectId, and runtimePolicyScope.envId are required for hosted wallet id derivation',
    );
  }

  private async deriveHostedOidcWalletId(input: {
    providerSubject?: string;
    sub?: string;
    email?: string;
    authProvider: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    collisionCounter?: number;
  }): Promise<string> {
    const subject = toOptionalTrimmedString(input.providerSubject ?? input.sub);
    const email = toOptionalTrimmedString(input.email);
    if (!subject && !email) {
      throw new Error('Cannot derive hosted wallet id without provider subject or verified email');
    }
    const scope = this.resolveHostedAccountScope(input.runtimePolicyScope);
    return deriveHostedNearAccountId({
      accountIdDerivationSecret: this.readConfigValue('ACCOUNT_ID_DERIVATION_SECRET'),
      relayerAccount: this.config.relayerAccount,
      projectId: scope.projectId,
      envId: scope.envId,
      authProvider: input.authProvider,
      ...(subject ? { providerSubject: subject } : {}),
      ...(email ? { verifiedEmail: email } : {}),
      ...(input.collisionCounter ? { collisionCounter: input.collisionCounter } : {}),
    });
  }

  async resolveOidcWalletId(input: {
    providerSubject?: string;
    sub?: string;
    email?: string;
    accountMode?: unknown;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
  }): Promise<string> {
    const providerSubject = toOptionalTrimmedString(input.providerSubject ?? input.sub);
    if (!providerSubject) {
      throw new Error('Cannot resolve OIDC wallet id without provider subject');
    }

    if (providerSubject.startsWith('google:')) {
      const resolution = await this.resolveGoogleEmailOtpSession(input);
      if (resolution.ok) return resolution.walletId;
      const error = new Error(resolution.message) as Error & { code?: string };
      error.code = resolution.code;
      throw error;
    }

    const walletSubject = `wallet:${providerSubject}`;
    const identity = this.getIdentityStore();
    const linkedWalletId = await identity.getUserIdBySubject(walletSubject);
    if (linkedWalletId && isValidAccountId(linkedWalletId)) return linkedWalletId;

    return await this.deriveHostedOidcWalletId({
      providerSubject,
      sub: input.sub,
      email: input.email,
      authProvider: 'oidc',
      ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
    });
  }

  private async cleanupGoogleEmailOtpRegistrationAttempts(nowMs = Date.now()): Promise<void> {
    await this.getEmailOtpRegistrationAttemptStore().deleteExpired(nowMs);
  }

  private async createGoogleEmailOtpRegistrationAttempt(input: {
    providerSubject: string;
    email: string;
    walletId: string;
    authProvider: string;
    collisionCounter: number;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
  }): Promise<GoogleEmailOtpRegistrationAttemptRecord> {
    const now = Date.now();
    await this.cleanupGoogleEmailOtpRegistrationAttempts(now);
    const attempt: GoogleEmailOtpRegistrationAttemptRecord = {
      version: 'google_email_otp_registration_attempt_v1',
      attemptId: this.generateOpaqueId(18),
      providerSubject: input.providerSubject,
      email: input.email,
      walletId: input.walletId,
      authProvider: input.authProvider,
      accountIdSlugVersion: 'hmac_readable_v1',
      collisionCounter: input.collisionCounter,
      state: 'started',
      createdAtMs: now,
      updatedAtMs: now,
      expiresAtMs: now + 30 * 60 * 1000,
      ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
    };
    await this.getEmailOtpRegistrationAttemptStore().put(attempt);
    return attempt;
  }

  private async findResumableGoogleEmailOtpRegistrationAttempt(input: {
    providerSubject: string;
    email: string;
  }): Promise<GoogleEmailOtpRegistrationAttemptRecord | null> {
    const now = Date.now();
    await this.cleanupGoogleEmailOtpRegistrationAttempts(now);
    const attempt = await this.getEmailOtpRegistrationAttemptStore().findStartedBySubjectEmail({
      providerSubject: input.providerSubject,
      email: input.email,
      nowMs: now,
    });
    if (attempt) {
      if (!this.isHostedHmacReadableRelayerSubaccount(attempt.walletId)) {
        attempt.state = 'failed';
        attempt.failureCode = 'non_hmac_readable_wallet_id';
        attempt.updatedAtMs = now;
        await this.getEmailOtpRegistrationAttemptStore().put(attempt);
        return null;
      }
      attempt.updatedAtMs = now;
      await this.getEmailOtpRegistrationAttemptStore().put(attempt);
    }
    return attempt;
  }

  async resolveGoogleEmailOtpSession(input: {
    providerSubject?: string;
    sub?: string;
    email?: string;
    accountMode?: unknown;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    rerollRegistrationAttempt?: unknown;
  }): Promise<GoogleEmailOtpResolutionResult> {
    const providerSubject = toOptionalTrimmedString(input.providerSubject ?? input.sub);
    if (!providerSubject || !providerSubject.startsWith('google:')) {
      throw new Error('Cannot resolve Google Email OTP session without Google provider subject');
    }
    const accountMode = toOptionalTrimmedString(input.accountMode)?.toLowerCase();
    if (accountMode !== 'register' && accountMode !== 'login') {
      throw new Error('Google Email OTP accountMode must be register or login');
    }
    const email = toOptionalTrimmedString(input.email)?.toLowerCase() || '';
    const orgId = toOptionalTrimmedString(input.runtimePolicyScope?.orgId) || '';
    if (!orgId) {
      throw new Error('Google Email OTP requires orgId tenant scope');
    }
    const walletSubject = `wallet:${providerSubject}`;
    const identity = this.getIdentityStore();
    const linkedWalletId = await identity.getUserIdBySubject(walletSubject);
    const linkedIsUsableRelayerWallet = !!(
      linkedWalletId &&
      isValidAccountId(linkedWalletId) &&
      this.isRelayerSubaccount(linkedWalletId)
    );
    const linkedIsHostedHmacReadableWallet = !!(
      linkedWalletId && this.isHostedHmacReadableRelayerSubaccount(linkedWalletId)
    );

    if (accountMode === 'login') {
      if (!linkedIsUsableRelayerWallet || !linkedIsHostedHmacReadableWallet) {
        const error = new Error('Email OTP enrollment not found') as Error & { code?: string };
        error.code = 'not_found';
        throw error;
      }
      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId: linkedWalletId,
        orgId,
        providerUserId: providerSubject,
      });
      if (!enrollment.ok) {
        const error = new Error(enrollment.message) as Error & { code?: string };
        error.code = enrollment.code;
        throw error;
      }
      return {
        ok: true,
        mode: 'existing_wallet',
        walletId: linkedWalletId,
        providerSubject,
        ...(email ? { email } : {}),
        hasEmailOtpEnrollment: true,
      };
    }

    if (!email) {
      throw new Error('Email is required to register a Google Email OTP wallet id');
    }

    const rerollRegistrationAttempt =
      input.rerollRegistrationAttempt === true ||
      String(input.rerollRegistrationAttempt || '')
        .trim()
        .toLowerCase() === 'true';
    let minCollisionCounter = 0;
    const resumableAttempt = await this.findResumableGoogleEmailOtpRegistrationAttempt({
      providerSubject,
      email,
    });
    if (resumableAttempt) {
      if (rerollRegistrationAttempt) {
        minCollisionCounter = Math.max(0, resumableAttempt.collisionCounter + 1);
        resumableAttempt.state = 'failed';
        resumableAttempt.failureCode = 'rerolled_by_user';
        resumableAttempt.updatedAtMs = Date.now();
        await this.getEmailOtpRegistrationAttemptStore().put(resumableAttempt);
      } else {
        return {
          ok: true,
          mode: 'register_started',
          walletId: resumableAttempt.walletId,
          providerSubject,
          email,
          registrationAttemptId: resumableAttempt.attemptId,
          expiresAtMs: resumableAttempt.expiresAtMs,
        };
      }
    }

    if (linkedIsUsableRelayerWallet && linkedIsHostedHmacReadableWallet) {
      const enrollment = await this.readEmailOtpEnrollment({ walletId: linkedWalletId, orgId });
      if (enrollment.ok) {
        return {
          ok: true,
          mode: 'existing_wallet',
          walletId: linkedWalletId,
          providerSubject,
          email,
          hasEmailOtpEnrollment: true,
        };
      }
      return {
        ok: false,
        mode: 'registration_incomplete',
        code: 'registration_incomplete',
        walletId: linkedWalletId,
        providerSubject,
        email,
        message:
          'Google Email OTP registration is incomplete for this wallet. Retry after cleaning stale local registration state.',
      };
    }

    const nowMs = Date.now();
    const authProvider = 'google_oidc';
    let walletId = '';
    let collisionCounter = 0;
    for (let attempt = minCollisionCounter; attempt < minCollisionCounter + 10; attempt++) {
      const candidate = await this.deriveHostedOidcWalletId({
        providerSubject,
        email,
        authProvider,
        ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
        ...(attempt ? { collisionCounter: attempt } : {}),
      });
      const inUseByLiveAttempt =
        await this.getEmailOtpRegistrationAttemptStore().hasLiveStartedWalletAttempt({
          walletId: candidate,
          nowMs,
        });
      if (!inUseByLiveAttempt) {
        walletId = candidate;
        collisionCounter = attempt;
        break;
      }
    }
    if (!walletId) {
      return {
        ok: false,
        mode: 'registration_incomplete',
        code: 'registration_incomplete',
        providerSubject,
        email,
        message: 'Unable to allocate a fresh Google Email OTP registration attempt',
      };
    }
    const existingSubjects = await identity.listSubjectsByUserId(walletId);
    const linkedToDifferentWalletSubject = existingSubjects.some(
      (subject) => subject.startsWith('wallet:') && subject !== walletSubject,
    );
    if (linkedToDifferentWalletSubject) {
      return {
        ok: false,
        mode: 'wallet_id_collision',
        code: 'wallet_id_collision',
        walletId,
        providerSubject,
        email,
        message: 'Email OTP wallet id is already linked to a different Google account',
      };
    }

    const attempt = await this.createGoogleEmailOtpRegistrationAttempt({
      providerSubject,
      email,
      walletId,
      authProvider,
      collisionCounter,
      ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
    });
    return {
      ok: true,
      mode: 'register_started',
      walletId,
      providerSubject,
      email,
      registrationAttemptId: attempt.attemptId,
      expiresAtMs: attempt.expiresAtMs,
    };
  }

  async completeGoogleEmailOtpRegistrationAttempt(input: {
    registrationAttemptId?: unknown;
    walletId?: unknown;
  }): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
    const registrationAttemptId = toOptionalTrimmedString(input.registrationAttemptId);
    if (!registrationAttemptId) return { ok: true };
    const walletId = toOptionalTrimmedString(input.walletId);
    const attempt = await this.getEmailOtpRegistrationAttemptStore().get(registrationAttemptId);
    if (!attempt) {
      return {
        ok: false,
        code: 'registration_incomplete',
        message: 'Google Email OTP registration attempt expired or was not found',
      };
    }
    if (attempt.expiresAtMs <= Date.now()) {
      attempt.state = 'expired';
      attempt.updatedAtMs = Date.now();
      await this.getEmailOtpRegistrationAttemptStore().put(attempt);
      return {
        ok: false,
        code: 'registration_incomplete',
        message: 'Google Email OTP registration attempt expired',
      };
    }
    if (walletId !== attempt.walletId) {
      return {
        ok: false,
        code: 'wallet_identity_mismatch',
        message: 'registrationAttemptId does not match walletId',
      };
    }
    const identity = this.getIdentityStore();
    const linked = await identity.linkSubjectToUserId({
      userId: attempt.walletId,
      subject: `wallet:${attempt.providerSubject}`,
      allowMoveIfSoleIdentity: true,
    });
    if (!linked.ok) {
      attempt.state = 'failed';
      attempt.failureCode = linked.code;
      attempt.updatedAtMs = Date.now();
      await this.getEmailOtpRegistrationAttemptStore().put(attempt);
      return {
        ok: false,
        code: linked.code,
        message: linked.message,
      };
    }
    attempt.state = 'active';
    attempt.updatedAtMs = Date.now();
    await this.getEmailOtpRegistrationAttemptStore().put(attempt);
    return { ok: true };
  }

  async recordGoogleEmailOtpRegistrationAttemptPublicKey(input: {
    registrationAttemptId?: unknown;
    walletId?: unknown;
    finalizedPublicKey?: unknown;
  }): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
    const registrationAttemptId = toOptionalTrimmedString(input.registrationAttemptId);
    if (!registrationAttemptId) return { ok: true };
    const walletId = toOptionalTrimmedString(input.walletId);
    const finalizedPublicKey = toOptionalTrimmedString(input.finalizedPublicKey);
    const attempt = await this.getEmailOtpRegistrationAttemptStore().get(registrationAttemptId);
    if (!attempt) {
      return {
        ok: false,
        code: 'registration_incomplete',
        message: 'Google Email OTP registration attempt expired or was not found',
      };
    }
    if (attempt.expiresAtMs <= Date.now()) {
      attempt.state = 'expired';
      attempt.updatedAtMs = Date.now();
      await this.getEmailOtpRegistrationAttemptStore().put(attempt);
      return {
        ok: false,
        code: 'registration_incomplete',
        message: 'Google Email OTP registration attempt expired',
      };
    }
    if (walletId !== attempt.walletId) {
      return {
        ok: false,
        code: 'wallet_identity_mismatch',
        message: 'registrationAttemptId does not match walletId',
      };
    }
    if (attempt.state !== 'started' && attempt.state !== 'active') {
      return {
        ok: false,
        code: 'registration_incomplete',
        message: 'Google Email OTP registration attempt is no longer active',
      };
    }
    if (finalizedPublicKey) attempt.finalizedPublicKey = finalizedPublicKey;
    attempt.updatedAtMs = Date.now();
    await this.getEmailOtpRegistrationAttemptStore().put(attempt);
    return { ok: true };
  }

  async failGoogleEmailOtpRegistrationAttempt(input: {
    registrationAttemptId?: unknown;
    walletId?: unknown;
    failureCode?: unknown;
  }): Promise<void> {
    const registrationAttemptId = toOptionalTrimmedString(input.registrationAttemptId);
    if (!registrationAttemptId) return;
    const attempt = await this.getEmailOtpRegistrationAttemptStore().get(registrationAttemptId);
    if (!attempt) return;
    const walletId = toOptionalTrimmedString(input.walletId);
    if (walletId && walletId !== attempt.walletId) return;
    attempt.state = 'failed';
    attempt.failureCode = toOptionalTrimmedString(input.failureCode) || 'failed';
    attempt.updatedAtMs = Date.now();
    await this.getEmailOtpRegistrationAttemptStore().put(attempt);
  }

  async cleanupGoogleEmailOtpDevRegistrationState(input: {
    providerSubject?: unknown;
    walletId?: unknown;
    nowMs?: unknown;
  }): Promise<
    | {
        ok: true;
        providerSubject: string;
        expiredRegistrationAttemptsDeleted: number;
        linkedWalletId?: string;
        orphanedWalletMappingRemoved: boolean;
        orphanedWalletMappingSkippedReason?:
          | 'no_linked_wallet'
          | 'wallet_id_mismatch'
          | 'not_relayer_subaccount'
          | 'active_email_otp_enrollment';
      }
    | { ok: false; code: string; message: string }
  > {
    if (this.isProductionEnvironment()) {
      return {
        ok: false,
        code: 'not_found',
        message: 'Google Email OTP dev cleanup is not available',
      };
    }

    const providerSubject = toOptionalTrimmedString(input.providerSubject);
    if (!providerSubject || !providerSubject.startsWith('google:')) {
      return { ok: false, code: 'invalid_body', message: 'Missing Google provider subject' };
    }

    const requestedWalletId = toOptionalTrimmedString(input.walletId);
    const nowMsRaw = typeof input.nowMs === 'number' ? input.nowMs : Number(input.nowMs);
    const nowMs = Number.isFinite(nowMsRaw) && nowMsRaw > 0 ? Math.floor(nowMsRaw) : Date.now();
    const expiredRegistrationAttemptsDeleted =
      await this.getEmailOtpRegistrationAttemptStore().deleteExpired(nowMs);

    const identity = this.getIdentityStore();
    const subject = `wallet:${providerSubject}`;
    const linkedWalletId = await identity.getUserIdBySubject(subject);
    if (!linkedWalletId) {
      return {
        ok: true,
        providerSubject,
        expiredRegistrationAttemptsDeleted,
        orphanedWalletMappingRemoved: false,
        orphanedWalletMappingSkippedReason: 'no_linked_wallet',
      };
    }

    if (requestedWalletId && requestedWalletId !== linkedWalletId) {
      return {
        ok: true,
        providerSubject,
        expiredRegistrationAttemptsDeleted,
        linkedWalletId,
        orphanedWalletMappingRemoved: false,
        orphanedWalletMappingSkippedReason: 'wallet_id_mismatch',
      };
    }

    if (!isValidAccountId(linkedWalletId) || !this.isRelayerSubaccount(linkedWalletId)) {
      return {
        ok: true,
        providerSubject,
        expiredRegistrationAttemptsDeleted,
        linkedWalletId,
        orphanedWalletMappingRemoved: false,
        orphanedWalletMappingSkippedReason: 'not_relayer_subaccount',
      };
    }

    const activeEnrollment = await this.getEmailOtpWalletEnrollmentStore().get(linkedWalletId);
    if (activeEnrollment) {
      return {
        ok: true,
        providerSubject,
        expiredRegistrationAttemptsDeleted,
        linkedWalletId,
        orphanedWalletMappingRemoved: false,
        orphanedWalletMappingSkippedReason: 'active_email_otp_enrollment',
      };
    }
    const deleted = await identity.deleteSubjectLinkForDevCleanup({
      userId: linkedWalletId,
      subject,
    });
    if (!deleted.ok && deleted.code !== 'not_found') return deleted;

    return {
      ok: true,
      providerSubject,
      expiredRegistrationAttemptsDeleted,
      linkedWalletId,
      orphanedWalletMappingRemoved: deleted.ok,
    };
  }

  isOidcExchangeConfigured(): boolean {
    return Boolean(this.config.oidcExchange?.issuers?.length);
  }

  async warmRegistrationRuntime(): Promise<void> {
    if (this.registrationRuntimeWarmPromise) return this.registrationRuntimeWarmPromise;

    this.registrationRuntimeWarmPromise = (async () => {
      const warmStartedAt = Date.now();
      await this.initStorage();

      const relayerWarmStartedAt = Date.now();
      await this.getRelayerAccount();
      this.logger.info(
        `[AuthService] registration runtime relayer/signer warm completed in ${
          Date.now() - relayerWarmStartedAt
        }ms`,
      );

      const thresholdWarmStartedAt = Date.now();
      const threshold = this.getThresholdSigningService();
      if (threshold) {
        await ensureThresholdEd25519HssWasm();
      }
      this.logger.info(
        `[AuthService] registration runtime threshold warm completed in ${
          Date.now() - thresholdWarmStartedAt
        }ms`,
      );

      const storeWarmStartedAt = Date.now();
      this.getWebAuthnAuthenticatorStore();
      this.getWebAuthnCredentialBindingStore();
      this.getNearPublicKeyStore();
      this.logger.info(
        `[AuthService] registration runtime storage warm completed in ${
          Date.now() - storeWarmStartedAt
        }ms`,
      );

      this.logger.info(
        `[AuthService] registration runtime warm completed in ${Date.now() - warmStartedAt}ms`,
      );
    })();

    try {
      await this.registrationRuntimeWarmPromise;
    } catch (error) {
      this.registrationRuntimeWarmPromise = null;
      throw error;
    }
  }

  async viewAccessKeyList(accountId: string): Promise<AccessKeyList> {
    await this._ensureSignerAndRelayerAccount();
    return this.nearClient.viewAccessKeyList(accountId);
  }

  /**
   * Lazily constructs the threshold signing service when `thresholdStore` is configured.
   * Routers may call this to auto-enable `/threshold-ed25519/*` endpoints.
   */
  getThresholdSigningService(): ThresholdSigningServiceType | null {
    if (this.thresholdSigningServiceInitialized) return this.thresholdSigningService;
    this.thresholdSigningServiceInitialized = true;

    if (!this.config.thresholdStore) {
      this.thresholdSigningService = null;
      return null;
    }

    this.thresholdSigningService = createThresholdSigningService({
      authService: this,
      thresholdStore: this.config.thresholdStore,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.thresholdSigningService;
  }

  /**
   * Explicit injection seam for environments that need AuthService and the threshold
   * service to share one already-constructed instance, such as E2E harnesses.
   */
  setThresholdSigningService(service: ThresholdSigningServiceType | null): void {
    this.thresholdSigningServiceInitialized = true;
    this.thresholdSigningService = service;
  }

  private getWebAuthnAuthenticatorStore(): WebAuthnAuthenticatorStore {
    if (this.webAuthnAuthenticatorStoreInitialized && this.webAuthnAuthenticatorStore) {
      return this.webAuthnAuthenticatorStore;
    }
    if (this.webAuthnAuthenticatorStoreInitialized) {
      // Defensive: should never happen, but avoids returning null.
      this.webAuthnAuthenticatorStore = createWebAuthnAuthenticatorStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.webAuthnAuthenticatorStore;
    }

    this.webAuthnAuthenticatorStoreInitialized = true;
    this.webAuthnAuthenticatorStore = createWebAuthnAuthenticatorStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.webAuthnAuthenticatorStore;
  }

  private getWebAuthnLoginChallengeStore(): WebAuthnLoginChallengeStore {
    if (this.webAuthnLoginChallengeStoreInitialized && this.webAuthnLoginChallengeStore) {
      return this.webAuthnLoginChallengeStore;
    }
    if (this.webAuthnLoginChallengeStoreInitialized) {
      // Defensive: should never happen, but avoids returning null.
      this.webAuthnLoginChallengeStore = createWebAuthnLoginChallengeStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.webAuthnLoginChallengeStore;
    }

    this.webAuthnLoginChallengeStoreInitialized = true;
    this.webAuthnLoginChallengeStore = createWebAuthnLoginChallengeStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.webAuthnLoginChallengeStore;
  }

  private getWebAuthnCredentialBindingStore(): WebAuthnCredentialBindingStore {
    if (this.webAuthnCredentialBindingStoreInitialized && this.webAuthnCredentialBindingStore) {
      return this.webAuthnCredentialBindingStore;
    }
    if (this.webAuthnCredentialBindingStoreInitialized) {
      // Defensive: should never happen, but avoids returning null.
      this.webAuthnCredentialBindingStore = createWebAuthnCredentialBindingStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.webAuthnCredentialBindingStore;
    }

    this.webAuthnCredentialBindingStoreInitialized = true;
    this.webAuthnCredentialBindingStore = createWebAuthnCredentialBindingStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.webAuthnCredentialBindingStore;
  }

  private getWebAuthnSyncChallengeStore(): WebAuthnSyncChallengeStore {
    if (this.webAuthnSyncChallengeStoreInitialized && this.webAuthnSyncChallengeStore) {
      return this.webAuthnSyncChallengeStore;
    }
    if (this.webAuthnSyncChallengeStoreInitialized) {
      // Defensive: should never happen, but avoids returning null.
      this.webAuthnSyncChallengeStore = createWebAuthnSyncChallengeStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.webAuthnSyncChallengeStore;
    }

    this.webAuthnSyncChallengeStoreInitialized = true;
    this.webAuthnSyncChallengeStore = createWebAuthnSyncChallengeStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.webAuthnSyncChallengeStore;
  }

  private getEmailOtpChallengeStore(): EmailOtpChallengeStore {
    if (this.emailOtpChallengeStoreInitialized && this.emailOtpChallengeStore) {
      return this.emailOtpChallengeStore;
    }
    if (this.emailOtpChallengeStoreInitialized) {
      this.emailOtpChallengeStore = createEmailOtpChallengeStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.emailOtpChallengeStore;
    }
    this.emailOtpChallengeStoreInitialized = true;
    this.emailOtpChallengeStore = createEmailOtpChallengeStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.emailOtpChallengeStore;
  }

  private getEmailOtpGrantStore(): EmailOtpGrantStore {
    if (this.emailOtpGrantStoreInitialized && this.emailOtpGrantStore) {
      return this.emailOtpGrantStore;
    }
    if (this.emailOtpGrantStoreInitialized) {
      this.emailOtpGrantStore = createEmailOtpGrantStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.emailOtpGrantStore;
    }
    this.emailOtpGrantStoreInitialized = true;
    this.emailOtpGrantStore = createEmailOtpGrantStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.emailOtpGrantStore;
  }

  private getEmailOtpWalletEnrollmentStore(): EmailOtpWalletEnrollmentStore {
    if (this.emailOtpWalletEnrollmentStoreInitialized && this.emailOtpWalletEnrollmentStore) {
      return this.emailOtpWalletEnrollmentStore;
    }
    if (this.emailOtpWalletEnrollmentStoreInitialized) {
      this.emailOtpWalletEnrollmentStore = createEmailOtpWalletEnrollmentStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.emailOtpWalletEnrollmentStore;
    }
    this.emailOtpWalletEnrollmentStoreInitialized = true;
    this.emailOtpWalletEnrollmentStore = createEmailOtpWalletEnrollmentStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.emailOtpWalletEnrollmentStore;
  }

  private getEmailOtpRecoveryWrappedEnrollmentEscrowStore(): EmailOtpRecoveryWrappedEnrollmentEscrowStore {
    if (
      this.emailOtpRecoveryWrappedEnrollmentEscrowStoreInitialized &&
      this.emailOtpRecoveryWrappedEnrollmentEscrowStore
    ) {
      return this.emailOtpRecoveryWrappedEnrollmentEscrowStore;
    }
    if (this.emailOtpRecoveryWrappedEnrollmentEscrowStoreInitialized) {
      this.emailOtpRecoveryWrappedEnrollmentEscrowStore =
        createEmailOtpRecoveryWrappedEnrollmentEscrowStore({
          config: this.config.thresholdStore || null,
          logger: this.logger,
          isNode: this.isNodeEnvironment(),
        });
      return this.emailOtpRecoveryWrappedEnrollmentEscrowStore;
    }
    this.emailOtpRecoveryWrappedEnrollmentEscrowStoreInitialized = true;
    this.emailOtpRecoveryWrappedEnrollmentEscrowStore =
      createEmailOtpRecoveryWrappedEnrollmentEscrowStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
    return this.emailOtpRecoveryWrappedEnrollmentEscrowStore;
  }

  private getEmailOtpAuthStateStore(): EmailOtpAuthStateStore {
    if (this.emailOtpAuthStateStoreInitialized && this.emailOtpAuthStateStore) {
      return this.emailOtpAuthStateStore;
    }
    if (this.emailOtpAuthStateStoreInitialized) {
      this.emailOtpAuthStateStore = createEmailOtpAuthStateStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.emailOtpAuthStateStore;
    }
    this.emailOtpAuthStateStoreInitialized = true;
    this.emailOtpAuthStateStore = createEmailOtpAuthStateStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.emailOtpAuthStateStore;
  }

  private getEmailOtpUnlockChallengeStore(): EmailOtpUnlockChallengeStore {
    if (this.emailOtpUnlockChallengeStoreInitialized && this.emailOtpUnlockChallengeStore) {
      return this.emailOtpUnlockChallengeStore;
    }
    if (this.emailOtpUnlockChallengeStoreInitialized) {
      this.emailOtpUnlockChallengeStore = createEmailOtpUnlockChallengeStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.emailOtpUnlockChallengeStore;
    }
    this.emailOtpUnlockChallengeStoreInitialized = true;
    this.emailOtpUnlockChallengeStore = createEmailOtpUnlockChallengeStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.emailOtpUnlockChallengeStore;
  }

  private getEmailOtpRegistrationAttemptStore(): EmailOtpRegistrationAttemptStore {
    if (this.emailOtpRegistrationAttemptStoreInitialized && this.emailOtpRegistrationAttemptStore) {
      return this.emailOtpRegistrationAttemptStore;
    }
    if (this.emailOtpRegistrationAttemptStoreInitialized) {
      this.emailOtpRegistrationAttemptStore = createEmailOtpRegistrationAttemptStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.emailOtpRegistrationAttemptStore;
    }
    this.emailOtpRegistrationAttemptStoreInitialized = true;
    this.emailOtpRegistrationAttemptStore = createEmailOtpRegistrationAttemptStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.emailOtpRegistrationAttemptStore;
  }

  private isProductionEnvironment(): boolean {
    const raw = String((globalThis as any)?.process?.env?.NODE_ENV || '')
      .trim()
      .toLowerCase();
    return raw === 'production';
  }

  private readConfigValue(name: string): string {
    const fromStoreConfig = toOptionalTrimmedString(
      (this.config.thresholdStore as Record<string, unknown> | null | undefined)?.[name],
    );
    if (fromStoreConfig) return fromStoreConfig;
    return toOptionalTrimmedString((globalThis as any)?.process?.env?.[name]) || '';
  }

  private readEmailOtpConfigValue(name: string): string {
    return this.readConfigValue(name);
  }

  private getEmailOtpRateLimiter(): SigningSessionSealRateLimiter {
    if (this.emailOtpRateLimiterInitialized && this.emailOtpRateLimiter) {
      return this.emailOtpRateLimiter;
    }
    const limiterKind =
      (this.readEmailOtpConfigValue('EMAIL_OTP_RATE_LIMITER_KIND') as
        | 'in-memory'
        | 'upstash-redis-rest'
        | 'redis-tcp'
        | '') || null;
    const limiter = resolveSigningSessionSealRateLimitFromEnv({
      limiterKind,
      upstashUrl: this.readEmailOtpConfigValue('EMAIL_OTP_RATE_LIMIT_UPSTASH_URL') || null,
      upstashToken: this.readEmailOtpConfigValue('EMAIL_OTP_RATE_LIMIT_UPSTASH_TOKEN') || null,
      redisUrl: this.readEmailOtpConfigValue('EMAIL_OTP_RATE_LIMIT_REDIS_URL') || null,
      keyPrefix: this.readEmailOtpConfigValue('EMAIL_OTP_RATE_LIMIT_KEY_PREFIX') || 'email-otp:v2:',
      limit: 1,
      windowMs: 1,
    }).limiter;
    this.emailOtpRateLimiterInitialized = true;
    this.emailOtpRateLimiter = limiter;
    return limiter;
  }

  private resolveEmailOtpRateLimitPolicies(): {
    challenge: { limit: number; windowMs: number };
    verify: { limit: number; windowMs: number };
    grant: { limit: number; windowMs: number };
    recoveryKeyAttempt: { limit: number; windowMs: number };
  } {
    const parseConfiguredInt = (
      name: string,
      raw: string,
      defaultValue: number,
      min: number,
      max: number,
    ): number => {
      const normalized = String(raw || '').trim();
      if (!normalized) return defaultValue;
      const n = Number(normalized);
      if (!Number.isFinite(n)) {
        throw new Error(`${name} must be a finite number`);
      }
      if (n < min || n > max) {
        throw new Error(`${name} must be between ${min} and ${max}`);
      }
      return Math.floor(n);
    };
    const production = this.isProductionEnvironment();
    const challengeDefault = production
      ? { limit: 5, windowMs: 5 * 60_000 }
      : { limit: 100, windowMs: 60_000 };
    const verifyDefault = production
      ? { limit: 10, windowMs: 5 * 60_000 }
      : { limit: 100, windowMs: 60_000 };
    const grantDefault = production
      ? { limit: 8, windowMs: 5 * 60_000 }
      : { limit: 100, windowMs: 60_000 };
    const recoveryKeyAttemptDefault = production
      ? { limit: 10, windowMs: 5 * 60_000 }
      : { limit: 100, windowMs: 60_000 };
    return {
      challenge: {
        limit: parseConfiguredInt(
          'EMAIL_OTP_CHALLENGE_RATE_LIMIT_MAX',
          this.readEmailOtpConfigValue('EMAIL_OTP_CHALLENGE_RATE_LIMIT_MAX'),
          challengeDefault.limit,
          1,
          500,
        ),
        windowMs: parseConfiguredInt(
          'EMAIL_OTP_CHALLENGE_RATE_LIMIT_WINDOW_MS',
          this.readEmailOtpConfigValue('EMAIL_OTP_CHALLENGE_RATE_LIMIT_WINDOW_MS'),
          challengeDefault.windowMs,
          1_000,
          24 * 60 * 60_000,
        ),
      },
      verify: {
        limit: parseConfiguredInt(
          'EMAIL_OTP_VERIFY_RATE_LIMIT_MAX',
          this.readEmailOtpConfigValue('EMAIL_OTP_VERIFY_RATE_LIMIT_MAX'),
          verifyDefault.limit,
          1,
          1000,
        ),
        windowMs: parseConfiguredInt(
          'EMAIL_OTP_VERIFY_RATE_LIMIT_WINDOW_MS',
          this.readEmailOtpConfigValue('EMAIL_OTP_VERIFY_RATE_LIMIT_WINDOW_MS'),
          verifyDefault.windowMs,
          1_000,
          24 * 60 * 60_000,
        ),
      },
      grant: {
        limit: parseConfiguredInt(
          'EMAIL_OTP_GRANT_RATE_LIMIT_MAX',
          this.readEmailOtpConfigValue('EMAIL_OTP_GRANT_RATE_LIMIT_MAX'),
          grantDefault.limit,
          1,
          1000,
        ),
        windowMs: parseConfiguredInt(
          'EMAIL_OTP_GRANT_RATE_LIMIT_WINDOW_MS',
          this.readEmailOtpConfigValue('EMAIL_OTP_GRANT_RATE_LIMIT_WINDOW_MS'),
          grantDefault.windowMs,
          1_000,
          24 * 60 * 60_000,
        ),
      },
      recoveryKeyAttempt: {
        limit: parseConfiguredInt(
          'EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_MAX',
          this.readEmailOtpConfigValue('EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_MAX'),
          recoveryKeyAttemptDefault.limit,
          1,
          1000,
        ),
        windowMs: parseConfiguredInt(
          'EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_WINDOW_MS',
          this.readEmailOtpConfigValue('EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_WINDOW_MS'),
          recoveryKeyAttemptDefault.windowMs,
          1_000,
          24 * 60 * 60_000,
        ),
      },
    };
  }

  private async consumeEmailOtpRateLimit(args: {
    scope: 'challenge' | 'verify' | 'grant' | 'recoveryKeyAttempt';
    action?: EmailOtpChallengeAction | typeof WALLET_EMAIL_OTP_ACTIONS.unseal;
    userId?: string;
    walletId?: string;
    orgId?: string;
    clientIp?: string;
  }): Promise<
    | { ok: true }
    | {
        ok: false;
        code: 'rate_limited';
        message: string;
        retryAfterMs?: number;
        resetAtMs?: number;
      }
  > {
    const limiter = this.getEmailOtpRateLimiter();
    const policy = this.resolveEmailOtpRateLimitPolicies()[args.scope];
    const keySuffix = `scope=${args.scope}:action=${args.action || 'default'}:limit=${policy.limit}:windowMs=${policy.windowMs}`;
    const keys = [
      args.clientIp ? `${keySuffix}:ip:${args.clientIp}` : '',
      args.userId ? `${keySuffix}:user:${args.userId}` : '',
      args.walletId ? `${keySuffix}:wallet:${args.walletId}` : '',
      args.orgId ? `${keySuffix}:org:${args.orgId}` : '',
    ].filter(Boolean);
    for (const key of keys) {
      const consumed = await limiter.consume({
        key,
        limit: policy.limit,
        windowMs: policy.windowMs,
        nowMs: Date.now(),
      });
      if (!consumed.ok) {
        return {
          ok: false,
          code: 'rate_limited',
          message: 'Email OTP rate limit exceeded',
          ...(typeof consumed.retryAfterMs === 'number'
            ? { retryAfterMs: consumed.retryAfterMs }
            : {}),
          ...(typeof consumed.resetAtMs === 'number' ? { resetAtMs: consumed.resetAtMs } : {}),
        };
      }
    }
    return { ok: true };
  }

  private resolveEmailOtpConfig(): {
    deliveryMode: 'email_provider' | 'log' | 'memory';
    challengeTtlMs: number;
    grantTtlMs: number;
    maxAttempts: number;
    lockoutTtlMs: number;
    codeLength: number;
    devOutboxEnabled: boolean;
    maxActiveChallengesPerContext: number;
  } {
    const deliveryModeRaw = this.readEmailOtpConfigValue('EMAIL_OTP_DELIVERY_MODE').toLowerCase();
    let deliveryMode: 'email_provider' | 'log' | 'memory';
    if (!deliveryModeRaw) {
      deliveryMode = 'memory';
    } else if (
      deliveryModeRaw === 'email_provider' ||
      deliveryModeRaw === 'log' ||
      deliveryModeRaw === 'memory'
    ) {
      deliveryMode = deliveryModeRaw;
    } else {
      throw new Error('EMAIL_OTP_DELIVERY_MODE must be one of email_provider, log, or memory');
    }
    const parseConfiguredInt = (
      name: string,
      raw: string,
      defaultValue: number,
      min: number,
      max: number,
    ): number => {
      const normalized = String(raw || '').trim();
      if (!normalized) return defaultValue;
      const n = Number(normalized);
      if (!Number.isFinite(n)) {
        throw new Error(`${name} must be a finite number`);
      }
      if (n < min || n > max) {
        throw new Error(`${name} must be between ${min} and ${max}`);
      }
      return Math.floor(n);
    };
    const challengeTtlMs = parseConfiguredInt(
      'EMAIL_OTP_CHALLENGE_TTL_MS',
      this.readEmailOtpConfigValue('EMAIL_OTP_CHALLENGE_TTL_MS'),
      5 * 60_000,
      30_000,
      15 * 60_000,
    );
    const grantTtlMs = parseConfiguredInt(
      'EMAIL_OTP_GRANT_TTL_MS',
      this.readEmailOtpConfigValue('EMAIL_OTP_GRANT_TTL_MS'),
      30_000,
      10_000,
      5 * 60_000,
    );
    const maxAttempts = parseConfiguredInt(
      'EMAIL_OTP_MAX_ATTEMPTS',
      this.readEmailOtpConfigValue('EMAIL_OTP_MAX_ATTEMPTS'),
      5,
      1,
      10,
    );
    const lockoutTtlMs = parseConfiguredInt(
      'EMAIL_OTP_LOCKOUT_TTL_MS',
      this.readEmailOtpConfigValue('EMAIL_OTP_LOCKOUT_TTL_MS'),
      15 * 60_000,
      60_000,
      24 * 60 * 60_000,
    );
    const codeLength = parseConfiguredInt(
      'EMAIL_OTP_CODE_LENGTH',
      this.readEmailOtpConfigValue('EMAIL_OTP_CODE_LENGTH'),
      6,
      6,
      8,
    );
    const maxActiveChallengesPerContext = parseConfiguredInt(
      'EMAIL_OTP_MAX_ACTIVE_CHALLENGES_PER_CONTEXT',
      this.readEmailOtpConfigValue('EMAIL_OTP_MAX_ACTIVE_CHALLENGES_PER_CONTEXT'),
      5,
      1,
      20,
    );
    const devOutboxEnabledRaw = this.readEmailOtpConfigValue('EMAIL_OTP_DEV_OUTBOX_ENABLED');
    if (
      devOutboxEnabledRaw &&
      !['1', 'true', 'yes', 'on', '0', 'false', 'no', 'off'].includes(
        devOutboxEnabledRaw.toLowerCase(),
      )
    ) {
      throw new Error('EMAIL_OTP_DEV_OUTBOX_ENABLED must be a boolean flag when provided');
    }
    const devOutboxEnabled =
      deliveryMode === 'memory' &&
      !this.isProductionEnvironment() &&
      (devOutboxEnabledRaw
        ? ['1', 'true', 'yes', 'on'].includes(devOutboxEnabledRaw.toLowerCase())
        : true);
    return {
      deliveryMode,
      challengeTtlMs,
      grantTtlMs,
      maxAttempts,
      lockoutTtlMs,
      codeLength,
      devOutboxEnabled,
      maxActiveChallengesPerContext,
    };
  }

  private createEmailOtpShamirCipher() {
    // Local/dev bootstrap path only. Production should source the active Email OTP
    // seal material from a KMS/HSM boundary before constructing this adapter.
    const keyVersion = this.readConfigValue('SIGNING_SESSION_SEAL_KEY_VERSION');
    const shamirPrimeB64u = this.readConfigValue('SIGNING_SESSION_SHAMIR_P_B64U');
    const serverEncryptExponentB64u = this.readConfigValue('SIGNING_SESSION_SEAL_E_S_B64U');
    const serverDecryptExponentB64u = this.readConfigValue('SIGNING_SESSION_SEAL_D_S_B64U');
    if (
      !keyVersion ||
      !shamirPrimeB64u ||
      !serverEncryptExponentB64u ||
      !serverDecryptExponentB64u
    ) {
      return {
        ok: false as const,
        code: 'not_configured',
        message:
          'Email OTP unseal requires SIGNING_SESSION_SEAL_KEY_VERSION, SIGNING_SESSION_SHAMIR_P_B64U, SIGNING_SESSION_SEAL_E_S_B64U, and SIGNING_SESSION_SEAL_D_S_B64U',
      };
    }
    try {
      return {
        ok: true as const,
        keyVersion,
        cipher: createSigningSessionSealShamir3PassCipherAdapter({
          currentKeyVersion: keyVersion,
          keys: [
            {
              keyVersion,
              shamirPrimeB64u,
              serverEncryptExponentB64u,
              serverDecryptExponentB64u,
            },
          ],
        }),
      };
    } catch (error: unknown) {
      return {
        ok: false as const,
        code: 'not_configured',
        message: errorMessage(error) || 'Email OTP Shamir configuration is invalid',
      };
    }
  }

  private generateNumericOtp(length: number): string {
    if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
      throw new Error('crypto.getRandomValues is unavailable in this runtime');
    }
    const bytes = crypto.getRandomValues(new Uint8Array(length));
    let code = '';
    for (const byte of bytes) code += String(byte % 10);
    return code;
  }

  private generateOpaqueId(byteLength = 16): string {
    if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
      throw new Error('crypto.getRandomValues is unavailable in this runtime');
    }
    return base64UrlEncode(crypto.getRandomValues(new Uint8Array(byteLength)));
  }

  private maskEmail(email: string): string {
    const trimmed = String(email || '')
      .trim()
      .toLowerCase();
    const atIndex = trimmed.indexOf('@');
    if (atIndex <= 0 || atIndex === trimmed.length - 1) return 'hidden';
    const local = trimmed.slice(0, atIndex);
    const domain = trimmed.slice(atIndex + 1);
    const maskedLocal =
      local.length <= 2 ? `${local[0] || '*'}*` : `${local[0]}***${local.slice(-1)}`;
    const domainParts = domain.split('.');
    const domainName = domainParts[0] || '';
    const maskedDomainName =
      domainName.length <= 2
        ? `${domainName[0] || '*'}*`
        : `${domainName[0]}***${domainName.slice(-1)}`;
    return `${maskedLocal}@${[maskedDomainName, ...domainParts.slice(1)].join('.')}`;
  }

  private async deliverEmailOtpCode(input: {
    challengeId: string;
    walletId: string;
    userId: string;
    otpChannel: EmailOtpChannel;
    email: string;
    otpCode: string;
    expiresAtMs: number;
  }): Promise<
    | { ok: true; deliveryMode: 'email_provider' | 'log' | 'memory'; emailHint: string }
    | { ok: false; code: string; message: string; lockedUntilMs?: number }
  > {
    const config = this.resolveEmailOtpConfig();
    if (this.isProductionEnvironment() && config.deliveryMode !== 'email_provider') {
      return {
        ok: false,
        code: 'email_otp_delivery_not_allowed',
        message: `Email OTP delivery mode ${config.deliveryMode} is disabled in production`,
      };
    }

    const emailHint = this.maskEmail(input.email);
    const logDevelopmentOtpCode = (deliveryMode: 'log' | 'memory') => {
      this.logger.warn('[email-otp] development OTP code', {
        challengeId: input.challengeId,
        walletId: input.walletId,
        userId: input.userId,
        otpChannel: input.otpChannel,
        deliveryMode,
        emailHint,
        devOtpCode: input.otpCode,
        expiresAtMs: input.expiresAtMs,
      });
    };
    if (config.deliveryMode === 'email_provider') {
      return {
        ok: false,
        code: 'not_implemented',
        message: 'Email OTP email_provider delivery is not implemented yet',
      };
    }

    if (config.deliveryMode === 'memory') {
      this.emailOtpMemoryOutbox.set(input.challengeId, {
        walletId: input.walletId,
        userId: input.userId,
        otpChannel: input.otpChannel,
        email: input.email,
        emailHint,
        otpCode: input.otpCode,
        expiresAtMs: input.expiresAtMs,
      });
      logDevelopmentOtpCode('memory');
      return { ok: true, deliveryMode: 'memory', emailHint };
    }

    logDevelopmentOtpCode('log');
    return { ok: true, deliveryMode: 'log', emailHint };
  }

  private getIdentityStore(): IdentityStore {
    if (this.identityStoreInitialized && this.identityStore) {
      return this.identityStore;
    }
    if (this.identityStoreInitialized) {
      this.identityStore = createIdentityStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.identityStore;
    }

    this.identityStoreInitialized = true;
    this.identityStore = createIdentityStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.identityStore;
  }

  async listIdentities(input: {
    userId: string;
  }): Promise<{ ok: boolean; subjects?: string[]; code?: string; message?: string }> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const store = this.getIdentityStore();
      const subjects = await store.listSubjectsByUserId(userId);
      return { ok: true, subjects };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to list identities',
      };
    }
  }

  async linkIdentity(input: {
    userId: string;
    subject: string;
    allowMoveIfSoleIdentity?: boolean;
  }): Promise<LinkIdentityResult> {
    try {
      const store = this.getIdentityStore();
      return await store.linkSubjectToUserId({
        userId: input.userId,
        subject: input.subject,
        allowMoveIfSoleIdentity: Boolean(input.allowMoveIfSoleIdentity),
      });
    } catch (e: unknown) {
      return { ok: false, code: 'internal', message: errorMessage(e) || 'Failed to link identity' };
    }
  }

  async unlinkIdentity(input: { userId: string; subject: string }): Promise<UnlinkIdentityResult> {
    try {
      const store = this.getIdentityStore();
      return await store.unlinkSubjectFromUserId({ userId: input.userId, subject: input.subject });
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to unlink identity',
      };
    }
  }

  async getOrCreateAppSessionVersion(input: {
    userId: string;
  }): Promise<
    | { ok: true; appSessionVersion: string }
    | { ok: false; code: 'invalid_args' | 'internal'; message: string }
  > {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const store = this.getIdentityStore();
      const appSessionVersion = await store.ensureAppSessionVersionByUserId(userId);
      return { ok: true, appSessionVersion };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to ensure app session version',
      };
    }
  }

  async rotateAppSessionVersion(input: {
    userId: string;
  }): Promise<
    | { ok: true; appSessionVersion: string }
    | { ok: false; code: 'invalid_args' | 'internal'; message: string }
  > {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const store = this.getIdentityStore();
      const appSessionVersion = await store.rotateAppSessionVersionByUserId(userId);
      return { ok: true, appSessionVersion };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to rotate app session version',
      };
    }
  }

  async validateAppSessionVersion(input: { userId: string; appSessionVersion: string }): Promise<
    | { ok: true }
    | {
        ok: false;
        code: 'invalid_session_version' | 'unauthorized' | 'internal';
        message: string;
      }
  > {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
      if (!userId || !appSessionVersion) {
        return { ok: false, code: 'unauthorized', message: 'Invalid app session' };
      }
      const store = this.getIdentityStore();
      const current = await store.getAppSessionVersionByUserId(userId);
      if (!current || current !== appSessionVersion) {
        return { ok: false, code: 'invalid_session_version', message: 'App session revoked' };
      }
      return { ok: true };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to validate app session version',
      };
    }
  }

  private getDeviceLinkingSessionStore(): DeviceLinkingSessionStore {
    if (this.deviceLinkingSessionStoreInitialized && this.deviceLinkingSessionStore) {
      return this.deviceLinkingSessionStore;
    }
    if (this.deviceLinkingSessionStoreInitialized) {
      // Defensive: should never happen, but avoids returning null.
      this.deviceLinkingSessionStore = createDeviceLinkingSessionStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.deviceLinkingSessionStore;
    }

    this.deviceLinkingSessionStoreInitialized = true;
    this.deviceLinkingSessionStore = createDeviceLinkingSessionStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.deviceLinkingSessionStore;
  }

  private getNearPublicKeyStore(): NearPublicKeyStore {
    if (this.nearPublicKeyStoreInitialized && this.nearPublicKeyStore) {
      return this.nearPublicKeyStore;
    }
    if (this.nearPublicKeyStoreInitialized) {
      // Defensive: should never happen, but avoids returning null.
      this.nearPublicKeyStore = createNearPublicKeyStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.nearPublicKeyStore;
    }
    this.nearPublicKeyStoreInitialized = true;
    this.nearPublicKeyStore = createNearPublicKeyStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.nearPublicKeyStore;
  }

  async recordNearPublicKeyMetadata(input: {
    userId?: unknown;
    publicKey?: unknown;
    kind: NearPublicKeyKind;
    signerSlot?: unknown;
    credentialIdB64u?: unknown;
    rpId?: unknown;
    addedTxHash?: unknown;
    removedAtMs?: unknown;
    source?: string;
  }): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
    const userId = toOptionalTrimmedString(input.userId);
    const publicKey = toOptionalTrimmedString(input.publicKey);
    if (!userId || !publicKey) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'userId and publicKey are required',
      };
    }

    const now = Date.now();
    const signerSlotRaw =
      typeof input.signerSlot === 'number' ? input.signerSlot : Number(input.signerSlot);
    const removedAtMsRaw =
      typeof input.removedAtMs === 'number' ? input.removedAtMs : Number(input.removedAtMs);
    const credentialIdB64u = toOptionalTrimmedString(input.credentialIdB64u);
    const rpId = toOptionalTrimmedString(input.rpId);
    const addedTxHash = toOptionalTrimmedString(input.addedTxHash);
    const record: NearPublicKeyRecord = {
      version: 'near_public_key_v1',
      userId,
      publicKey,
      kind: input.kind,
      ...(Number.isFinite(signerSlotRaw) && signerSlotRaw >= 1
        ? { signerSlot: Math.floor(signerSlotRaw) }
        : {}),
      ...(credentialIdB64u ? { credentialIdB64u } : {}),
      ...(rpId ? { rpId } : {}),
      createdAtMs: now,
      updatedAtMs: now,
      ...(addedTxHash ? { addedTxHash } : {}),
      ...(Number.isFinite(removedAtMsRaw) && removedAtMsRaw > 0
        ? { removedAtMs: Math.floor(removedAtMsRaw) }
        : {}),
    };

    try {
      await this.getNearPublicKeyStore().put(record);
      return { ok: true };
    } catch (error: unknown) {
      const source = toOptionalTrimmedString(input.source) || 'near-public-key-metadata';
      const message = errorMessage(error) || 'Failed to persist NEAR public key metadata';
      this.logger.warn(`[AuthService] ${source} failed for ${userId}`, error);
      return { ok: false, code: 'internal', message };
    }
  }

  private getAccountSignerStore(): AccountSignerStore {
    if (this.accountSignerStoreInitialized && this.accountSignerStore) {
      return this.accountSignerStore;
    }
    if (this.accountSignerStoreInitialized) {
      this.accountSignerStore = createAccountSignerStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.accountSignerStore;
    }
    this.accountSignerStoreInitialized = true;
    this.accountSignerStore = createAccountSignerStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.accountSignerStore;
  }

  private getSmartAccountRecoverySubjectStore(): SmartAccountRecoverySubjectStore {
    if (this.smartAccountRecoverySubjectStoreInitialized && this.smartAccountRecoverySubjectStore) {
      return this.smartAccountRecoverySubjectStore;
    }
    if (this.smartAccountRecoverySubjectStoreInitialized) {
      this.smartAccountRecoverySubjectStore = createSmartAccountRecoverySubjectStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.smartAccountRecoverySubjectStore;
    }
    this.smartAccountRecoverySubjectStoreInitialized = true;
    this.smartAccountRecoverySubjectStore = createSmartAccountRecoverySubjectStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.smartAccountRecoverySubjectStore;
  }

  private getRecoverySessionStore(): RecoverySessionStore {
    if (this.recoverySessionStoreInitialized && this.recoverySessionStore) {
      return this.recoverySessionStore;
    }
    if (this.recoverySessionStoreInitialized) {
      this.recoverySessionStore = createRecoverySessionStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.recoverySessionStore;
    }
    this.recoverySessionStoreInitialized = true;
    this.recoverySessionStore = createRecoverySessionStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.recoverySessionStore;
  }

  private getRecoveryExecutionStore(): RecoveryExecutionStore {
    if (this.recoveryExecutionStoreInitialized && this.recoveryExecutionStore) {
      return this.recoveryExecutionStore;
    }
    if (this.recoveryExecutionStoreInitialized) {
      this.recoveryExecutionStore = createRecoveryExecutionStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.recoveryExecutionStore;
    }
    this.recoveryExecutionStoreInitialized = true;
    this.recoveryExecutionStore = createRecoveryExecutionStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.recoveryExecutionStore;
  }

  async listAccountSignersByUser(input: {
    userId: string;
  }): Promise<
    | { ok: true; records: Awaited<ReturnType<AccountSignerStore['listByUserId']>> }
    | { ok: false; code: 'invalid_args' | 'internal'; message: string }
  > {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const store = this.getAccountSignerStore();
      const records = await store.listByUserId(userId);
      return { ok: true, records };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to list account signers',
      };
    }
  }

  async listAccountSignersByAccount(input: {
    chainIdKey: string;
    accountAddress: string;
  }): Promise<
    | { ok: true; records: Awaited<ReturnType<AccountSignerStore['listByAccount']>> }
    | { ok: false; code: 'invalid_args' | 'internal'; message: string }
  > {
    try {
      const chainIdKey = toOptionalTrimmedString(input.chainIdKey);
      const accountAddress = toOptionalTrimmedString(input.accountAddress);
      if (!chainIdKey || !accountAddress) {
        return { ok: false, code: 'invalid_args', message: 'Missing account signer account key' };
      }
      const store = this.getAccountSignerStore();
      const records = await store.listByAccount({ chainIdKey, accountAddress });
      return { ok: true, records };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to list account signers by account',
      };
    }
  }

  async putAccountSigner(
    input: AccountSignerRecord,
  ): Promise<
    | { ok: true; record: AccountSignerRecord }
    | { ok: false; code: 'invalid_args' | 'internal'; message: string }
  > {
    try {
      const store = this.getAccountSignerStore();
      await store.put(input);
      return { ok: true, record: input };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to write account signer',
      };
    }
  }

  async listSmartAccountRecoverySubjects(input: { nearAccountId: string }): Promise<
    | {
        ok: true;
        records: Awaited<ReturnType<SmartAccountRecoverySubjectStore['listByNearAccountId']>>;
      }
    | { ok: false; code: 'invalid_args' | 'internal'; message: string }
  > {
    try {
      const nearAccountId = toOptionalTrimmedString(input.nearAccountId);
      if (!nearAccountId) {
        return { ok: false, code: 'invalid_args', message: 'Missing nearAccountId' };
      }
      const store = this.getSmartAccountRecoverySubjectStore();
      const records = await store.listByNearAccountId(nearAccountId);
      return { ok: true, records };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to list smart-account recovery subjects',
      };
    }
  }

  async getSmartAccountRecoverySubjectByAccount(input: {
    chainIdKey: string;
    accountAddress: string;
  }): Promise<
    | { ok: true; record: Awaited<ReturnType<SmartAccountRecoverySubjectStore['getByAccount']>> }
    | { ok: false; code: 'invalid_args' | 'internal'; message: string }
  > {
    try {
      const chainIdKey = toOptionalTrimmedString(input.chainIdKey);
      const accountAddress = toOptionalTrimmedString(input.accountAddress);
      if (!chainIdKey || !accountAddress) {
        return {
          ok: false,
          code: 'invalid_args',
          message: 'Missing smart-account recovery subject key',
        };
      }
      const store = this.getSmartAccountRecoverySubjectStore();
      const record = await store.getByAccount({ chainIdKey, accountAddress });
      return { ok: true, record };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to read smart-account recovery subject',
      };
    }
  }

  async putSmartAccountRecoverySubject(
    input: SmartAccountRecoverySubjectRecord,
  ): Promise<
    | { ok: true; record: SmartAccountRecoverySubjectRecord }
    | { ok: false; code: 'invalid_args' | 'internal'; message: string }
  > {
    try {
      const store = this.getSmartAccountRecoverySubjectStore();
      await store.put(input);
      return { ok: true, record: input };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to write smart-account recovery subject',
      };
    }
  }

  async getRecoverySession(input: {
    sessionId: string;
  }): Promise<
    | { ok: true; record: Awaited<ReturnType<RecoverySessionStore['get']>> }
    | { ok: false; code: 'invalid_args' | 'internal'; message: string }
  > {
    try {
      const sessionId = toOptionalTrimmedString(input.sessionId);
      if (!sessionId) return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
      const store = this.getRecoverySessionStore();
      const record = await store.get(sessionId);
      return { ok: true, record };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to read recovery session',
      };
    }
  }

  async updateRecoverySessionStatus(input: {
    sessionId: string;
    status: RecoverySessionStatus;
    metadataPatch?: Record<string, unknown> | null;
  }): Promise<
    | { ok: true; record: NonNullable<Awaited<ReturnType<RecoverySessionStore['get']>>> }
    | { ok: false; code: 'invalid_args' | 'internal'; message: string }
  > {
    try {
      const sessionId = toOptionalTrimmedString(input.sessionId);
      const status = toOptionalTrimmedString(input.status) as RecoverySessionStatus | null;
      if (
        !sessionId ||
        !status ||
        (status !== 'prepared' &&
          status !== 'verified' &&
          status !== 'near_recovered' &&
          status !== 'evm_recovering' &&
          status !== 'completed' &&
          status !== 'failed' &&
          status !== 'cancelled')
      ) {
        return { ok: false, code: 'invalid_args', message: 'Invalid recovery session update' };
      }

      const store = this.getRecoverySessionStore();
      const existing = await store.get(sessionId);
      if (!existing) {
        return {
          ok: false,
          code: 'invalid_args',
          message: `Unknown recovery session: ${sessionId}`,
        };
      }

      const record = {
        ...existing,
        status,
        updatedAtMs: Date.now(),
        ...(input.metadataPatch
          ? {
              metadata: {
                ...(existing.metadata || {}),
                ...input.metadataPatch,
              },
            }
          : existing.metadata
            ? { metadata: { ...existing.metadata } }
            : {}),
      };
      await store.put(record);
      return { ok: true, record };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to update recovery session',
      };
    }
  }

  async getRecoveryExecution(input: {
    sessionId: string;
    chainIdKey: string;
    accountAddress: string;
    action: string;
  }): Promise<
    | { ok: true; record: Awaited<ReturnType<RecoveryExecutionStore['get']>> }
    | { ok: false; code: 'invalid_args' | 'internal'; message: string }
  > {
    try {
      const sessionId = toOptionalTrimmedString(input.sessionId);
      const chainIdKey = toOptionalTrimmedString(input.chainIdKey);
      const accountAddress = toOptionalTrimmedString(input.accountAddress);
      const action = toOptionalTrimmedString(input.action);
      if (!sessionId || !chainIdKey || !accountAddress || !action) {
        return { ok: false, code: 'invalid_args', message: 'Missing recovery execution key' };
      }
      const store = this.getRecoveryExecutionStore();
      const record = await store.get({
        sessionId,
        chainIdKey,
        accountAddress,
        action,
      });
      return { ok: true, record };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to read recovery execution',
      };
    }
  }

  async listRecoveryExecutions(input: {
    sessionId: string;
  }): Promise<
    | { ok: true; records: Awaited<ReturnType<RecoveryExecutionStore['listBySessionId']>> }
    | { ok: false; code: 'invalid_args' | 'internal'; message: string }
  > {
    try {
      const sessionId = toOptionalTrimmedString(input.sessionId);
      if (!sessionId) return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
      const store = this.getRecoveryExecutionStore();
      const records = await store.listBySessionId(sessionId);
      return { ok: true, records };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to list recovery executions',
      };
    }
  }

  async listRecoveryExecutionsByStatus(input: {
    status: RecoveryExecutionStatus;
    action?: string;
    updatedBeforeMs?: number;
    limit?: number;
  }): Promise<
    | { ok: true; records: Awaited<ReturnType<RecoveryExecutionStore['listByStatus']>> }
    | { ok: false; code: 'invalid_args' | 'internal'; message: string }
  > {
    try {
      const status = input.status;
      const action = toOptionalTrimmedString(input.action);
      const updatedBeforeMsRaw = Number(input.updatedBeforeMs);
      const updatedBeforeMs =
        Number.isFinite(updatedBeforeMsRaw) && updatedBeforeMsRaw > 0
          ? Math.floor(updatedBeforeMsRaw)
          : undefined;
      if (typeof input.updatedBeforeMs !== 'undefined' && typeof updatedBeforeMs === 'undefined') {
        return {
          ok: false,
          code: 'invalid_args',
          message: 'updatedBeforeMs must be a positive integer',
        };
      }
      const limitRaw = Number(input.limit);
      const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.floor(limitRaw) : undefined;
      if (typeof input.limit !== 'undefined' && typeof limit === 'undefined') {
        return { ok: false, code: 'invalid_args', message: 'limit must be a positive integer' };
      }
      const store = this.getRecoveryExecutionStore();
      const records = await store.listByStatus({
        status,
        ...(action ? { action } : {}),
        ...(typeof updatedBeforeMs === 'number' ? { updatedBeforeMs } : {}),
        ...(typeof limit === 'number' ? { limit } : {}),
      });
      return { ok: true, records };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to list recovery executions by status',
      };
    }
  }

  async recordRecoveryExecution(input: {
    sessionId: string;
    chainIdKey: string;
    accountAddress: string;
    action: string;
    status: RecoveryExecutionStatus;
    transactionHash?: string;
    errorCode?: string;
    errorMessage?: string;
    metadata?: Record<string, unknown>;
  }): Promise<
    | { ok: true; record: RecoveryExecutionRecord }
    | { ok: false; code: 'invalid_args' | 'internal'; message: string }
  > {
    try {
      const sessionId = toOptionalTrimmedString(input.sessionId);
      const chainIdKey = toOptionalTrimmedString(input.chainIdKey);
      const accountAddress = toOptionalTrimmedString(input.accountAddress);
      const action = toOptionalTrimmedString(input.action);
      if (!sessionId || !chainIdKey || !accountAddress || !action) {
        return { ok: false, code: 'invalid_args', message: 'Missing recovery execution fields' };
      }

      const recoverySession = await this.getRecoverySessionStore().get(sessionId);
      if (!recoverySession) {
        return {
          ok: false,
          code: 'invalid_args',
          message: `Unknown recovery session: ${sessionId}`,
        };
      }

      const store = this.getRecoveryExecutionStore();
      const existing = await store.get({
        sessionId,
        chainIdKey,
        accountAddress,
        action,
      });
      const nowMs = Date.now();
      const record = buildRecoveryExecutionRecord({
        sessionId,
        userId: recoverySession.userId,
        nearAccountId: recoverySession.nearAccountId,
        chainIdKey,
        accountAddress,
        action,
        status: input.status,
        createdAtMs: existing?.createdAtMs ?? nowMs,
        nowMs,
        transactionHash: input.transactionHash,
        errorCode: input.errorCode,
        errorMessage: input.errorMessage,
        metadata: input.metadata,
      });
      if (!record) {
        return {
          ok: false,
          code: 'invalid_args',
          message: 'Invalid recovery execution payload',
        };
      }

      await store.put(record);
      return { ok: true, record };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to persist recovery execution',
      };
    }
  }

  private async persistRegistrationSmartAccountRecords(input: {
    userId: string;
    nearAccountId: string;
    signerSlot: number;
    credentialIdB64u: string;
    rpId: string;
    thresholdEcdsaKeygen: {
      ecdsaThresholdKeyId?: string;
      relayerKeyId: string;
      thresholdEcdsaPublicKeyB64u: string;
      ethereumAddress: string;
      participantIds?: number[];
    };
    smartAccountTargets?: CreateAccountAndRegisterSmartAccountTarget[];
    nowMs: number;
  }): Promise<void> {
    const records = buildRegistrationSmartAccountRecords({
      userId: input.userId,
      nearAccountId: input.nearAccountId,
      signerSlot: input.signerSlot,
      credentialIdB64u: input.credentialIdB64u,
      rpId: input.rpId,
      ecdsaThresholdKeyId: input.thresholdEcdsaKeygen.ecdsaThresholdKeyId,
      relayerKeyId: input.thresholdEcdsaKeygen.relayerKeyId,
      thresholdEcdsaPublicKeyB64u: input.thresholdEcdsaKeygen.thresholdEcdsaPublicKeyB64u,
      thresholdOwnerAddress: input.thresholdEcdsaKeygen.ethereumAddress,
      participantIds: input.thresholdEcdsaKeygen.participantIds,
      smartAccountTargets: input.smartAccountTargets,
      nowMs: input.nowMs,
    });

    if (records.accountSigners.length === 0 && records.recoverySubjects.length === 0) {
      return;
    }

    const signerStore = this.getAccountSignerStore();
    const recoverySubjectStore = this.getSmartAccountRecoverySubjectStore();

    for (const record of records.accountSigners) {
      await signerStore.put(record);
    }
    for (const record of records.recoverySubjects) {
      await recoverySubjectStore.put(record);
    }
    for (const record of records.recoverySubjects) {
      await syncCanonicalSmartAccountDeploymentManifest({
        authService: this,
        chainIdKey: record.chainIdKey,
        accountAddress: record.accountAddress,
        materializedAtMs: input.nowMs,
      });
    }
  }

  async txStatus(txHash: string, senderAccountId: string): Promise<FinalExecutionOutcome> {
    await this._ensureSignerAndRelayerAccount();
    return this.nearClient.txStatus(txHash, senderAccountId);
  }

  private async _ensureSignerAndRelayerAccount(): Promise<void> {
    if (this.isInitialized) {
      return;
    }

    // Derive public key from configured relayer private key
    try {
      this.relayerPublicKey = toPublicKeyStringFromSecretKey(this.config.relayerPrivateKey);
    } catch (e) {
      this.logger.warn(
        'Failed to derive public key from relayerPrivateKey; ensure it is in ed25519:<base58> format',
      );
      this.relayerPublicKey = '';
    }

    // Prepare signer WASM for transaction building/signing
    await this.ensureSignerWasm();
    this.isInitialized = true;
  }

  private async ensureSignerWasm(): Promise<void> {
    if (this.signerWasmReady) return;
    const override = this.config.signerWasm?.moduleOrPath;
    if (override) {
      try {
        const moduleOrPath = await this.resolveSignerWasmOverride(override);
        await initSignerWasm({ module_or_path: moduleOrPath as InitInput });
        this.signerWasmReady = true;
        return;
      } catch (e) {
        this.logger.error('Failed to initialize signer WASM via provided override:', e);
        throw e;
      }
    }

    let candidates: URL[];
    try {
      candidates = getSignerWasmUrls(this.logger);
    } catch (err) {
      this.logger.error('Failed to resolve signer WASM URLs:', err);
      throw err;
    }

    try {
      if (this.isNodeEnvironment()) {
        await this.initSignerWasmForNode(candidates);
        this.signerWasmReady = true;
        return;
      }

      let lastError: unknown = null;
      for (const candidate of candidates) {
        try {
          await initSignerWasm({ module_or_path: candidate as InitInput });
          this.signerWasmReady = true;
          return;
        } catch (err) {
          lastError = err;
          this.logger.warn(
            `Failed to initialize signer WASM from ${candidate.toString()}, trying next candidate...`,
          );
        }
      }

      throw lastError ?? new Error('Unable to initialize signer WASM from any candidate URL');
    } catch (e) {
      this.logger.error('Failed to initialize signer WASM:', e);
      throw e instanceof Error ? e : new Error(String(e));
    }
  }

  private isNodeEnvironment(): boolean {
    // Detect true Node.js, not Cloudflare Workers with nodejs_compat polyfills.
    const processObj = (globalThis as unknown as { process?: { versions?: { node?: string } } })
      .process;
    const isNode = Boolean(processObj?.versions?.node);
    // Cloudflare Workers expose WebSocketPair and may polyfill process.
    const webSocketPair = (globalThis as unknown as { WebSocketPair?: unknown }).WebSocketPair;
    const nav = (globalThis as unknown as { navigator?: { userAgent?: unknown } }).navigator;
    const isCloudflareWorker =
      typeof webSocketPair !== 'undefined' ||
      (typeof nav?.userAgent === 'string' && nav.userAgent.includes('Cloudflare-Workers'));
    return isNode && !isCloudflareWorker;
  }

  private async resolveSignerWasmOverride(override: SignerWasmModuleSupplier): Promise<InitInput> {
    const candidate =
      typeof override === 'function'
        ? await (override as () => InitInput | Promise<InitInput>)()
        : await override;

    if (!candidate) {
      throw new Error('Signer WASM override resolved to an empty value');
    }

    return candidate;
  }

  /**
   * Initialize signer WASM in Node by loading the wasm file from disk.
   * Tries multiple candidate locations and falls back to path-based init if needed.
   */
  private async initSignerWasmForNode(candidates: URL[]): Promise<void> {
    const { fileURLToPath } = await import('node:url');
    const { readFile } = await import('node:fs/promises');

    // 1) Try reading and compiling bytes
    for (const url of candidates) {
      try {
        const filePath = fileURLToPath(url);
        const bytes = await readFile(filePath);
        // Ensure we pass an ArrayBuffer (not Buffer / SharedArrayBuffer) for WebAssembly.compile
        const ab = new ArrayBuffer(bytes.byteLength);
        new Uint8Array(ab).set(bytes);
        const module = await WebAssembly.compile(ab);
        await initSignerWasm({ module_or_path: module });
        return;
      } catch {} // throw at end of function
    }

    // 2) Fallback: pass file path directly (supported in some environments)
    for (const url of candidates) {
      try {
        const filePath = fileURLToPath(url);
        await initSignerWasm({ module_or_path: filePath as unknown as InitInput });
        return;
      } catch {} // throw at end of function
    }

    throw new Error('[AuthService] Failed to initialize signer WASM from filesystem candidates');
  }

  /**
   * ===== Registration & authentication =====
   *
   * Helpers for creating accounts, registering WebAuthn credentials,
   * and verifying authentication responses.
   */

  /**
   * Create a new account with the specified balance
   */
  async createAccount(request: AccountCreationRequest): Promise<AccountCreationResult> {
    await this._ensureSignerAndRelayerAccount();

    return this.queueTransaction(async () => {
      try {
        if (!isValidAccountId(request.accountId)) {
          throw new Error(`Invalid account ID format: ${request.accountId}`);
        }

        // Check if account already exists
        this.logger.info(`Checking if account ${request.accountId} already exists...`);
        const accountExists = await this.checkAccountExists(request.accountId);
        if (accountExists) {
          throw new Error(
            `Account ${request.accountId} already exists. Cannot create duplicate account.`,
          );
        }
        this.logger.info(`Account ${request.accountId} is available for creation`);

        const initialBalance = this.config.accountInitialBalance;
        const { publicKey, recoveryPublicKey, expectedPublicKeys } = normalizeBootstrapPublicKeys({
          publicKey: request.publicKey,
          recoveryPublicKey: request.recoveryPublicKey,
        });

        this.logger.info(`Creating account: ${request.accountId}`);
        this.logger.info(`Initial balance: ${initialBalance} yoctoNEAR`);

        // Build actions for CreateAccount + Transfer + AddKey(FullAccess) for bootstrap keys.
        const actions: ActionArgsWasm[] = [
          { action_type: ActionType.CreateAccount },
          { action_type: ActionType.Transfer, deposit: String(initialBalance) },
          buildFullAccessAddKeyAction(publicKey),
          ...(recoveryPublicKey ? [buildFullAccessAddKeyAction(recoveryPublicKey)] : []),
        ];

        actions.forEach(validateActionArgsWasm);

        // Fetch nonce and block hash for relayer
        const { nextNonce, blockHash } = await this.fetchTxContext(
          this.config.relayerAccount,
          this.relayerPublicKey,
        );

        // Sign with relayer private key using WASM
        const signed = await this.signWithPrivateKey({
          nearPrivateKey: this.config.relayerPrivateKey,
          signerAccountId: this.config.relayerAccount,
          receiverId: request.accountId,
          nonce: nextNonce,
          blockHash: blockHash,
          actions,
        });

        // Broadcast quickly, then perform one explicit key-visibility check against final state.
        const createAccountBroadcastStartedAt = Date.now();
        const result = await this.nearClient.sendTransaction(
          signed,
          ACCOUNT_CREATE_BROADCAST_WAIT_UNTIL,
        );
        this.logger.info(
          `Account creation for ${request.accountId} reached ${ACCOUNT_CREATE_BROADCAST_WAIT_UNTIL} in ${
            Date.now() - createAccountBroadcastStartedAt
          }ms`,
        );
        const createAccountKeyCheckStartedAt = Date.now();
        const keysVerified = await this.verifyAccountAccessKeysPresent(
          request.accountId,
          expectedPublicKeys,
          ACCOUNT_CREATE_FAST_KEY_VISIBILITY_CHECK,
        );
        this.logger.info(
          `Account creation for ${request.accountId} key visibility verified=${keysVerified} in ${
            Date.now() - createAccountKeyCheckStartedAt
          }ms`,
        );
        if (!keysVerified) {
          this.logger.warn(
            recoveryPublicKey
              ? 'Bootstrap committed before both access keys were visible on final state; scheduling background audit'
              : 'Bootstrap committed before the operational access key was visible on final state; scheduling background audit',
          );
          this.scheduleAccountAccessKeyVisibilityAudit({
            accountId: request.accountId,
            expectedPublicKeys,
            contextLabel: `Account creation for ${request.accountId}`,
          });
        }

        this.logger.info(`Account creation completed: ${result.transaction.hash}`);
        const nearAmount = (Number(BigInt(initialBalance)) / 1e24).toFixed(6);
        return {
          success: true,
          transactionHash: result.transaction.hash,
          accountId: request.accountId,
          message: `Account ${request.accountId} created with ${nearAmount} NEAR initial balance`,
        };
      } catch (error: any) {
        this.logger.error(`Account creation failed for ${request.accountId}:`, error);
        const msg = errorMessage(error) || 'Unknown account creation error';
        return {
          success: false,
          error: msg,
          message: `Failed to create account ${request.accountId}: ${msg}`,
        };
      }
    }, `create account ${request.accountId}`);
  }

  /**
   * Create a new NEAR subaccount and register a WebAuthn authenticator in relay-private storage.
   *
   * Notes:
   * - WebAuthn-only: the registration challenge is derived deterministically from `{ accountId, signer_slot }`.
   * - Contract-free: no on-chain WebAuthn verifier is used.
   */
  async createAccountAndRegisterUser(
    request: CreateAccountAndRegisterRequest,
  ): Promise<CreateAccountAndRegisterResult> {
    await this._ensureSignerAndRelayerAccount();

    return this.queueTransaction(async () => {
      try {
        const registrationStartedAt = Date.now();
        const registrationTimings: Record<string, number> = {};
        const accountId = String(request?.new_account_id || '').trim();
        if (!isValidAccountId(accountId))
          throw new Error(`Invalid account ID format: ${accountId}`);

        const relayerAccount = String(this.config.relayerAccount || '').trim();
        const expectedSuffix = relayerAccount ? `.${relayerAccount}` : '';
        if (!relayerAccount || !expectedSuffix || !accountId.endsWith(expectedSuffix)) {
          throw new Error(
            `new_account_id must be a subaccount of relayerAccount (${relayerAccount})`,
          );
        }

        const thresholdEd25519Registration = parseThresholdEd25519RegistrationInput(
          (request as any)?.threshold_ed25519,
        );
        const thresholdEcdsaClientRootShare32B64u = String(
          (request as any)?.threshold_ecdsa?.client_root_share32_b64u || '',
        ).trim();
        const thresholdEd25519SessionPolicy = thresholdEd25519Registration.sessionPolicy;
        const thresholdEcdsaSessionPolicy = (request as any)?.threshold_ecdsa?.session_policy;
        const thresholdEd25519SessionKind = thresholdEd25519Registration.sessionKind;
        const thresholdEcdsaSessionKind = String(
          (request as any)?.threshold_ecdsa?.session_kind || '',
        )
          .trim()
          .toLowerCase();
        let thresholdKeygen: Extract<
          ThresholdEd25519RegistrationKeygenResult,
          { ok: true }
        > | null = null;
        let thresholdEcdsaKeygen: {
          ecdsaThresholdKeyId?: string;
          signingRootId: string;
          signingRootVersion?: string;
          clientVerifyingShareB64u: string;
          clientAdditiveShare32B64u: string;
          relayerKeyId: string;
          thresholdEcdsaPublicKeyB64u: string;
          ethereumAddress: string;
          relayerVerifyingShareB64u: string;
          participantIds?: number[];
        } | null = null;
        let thresholdEd25519Session: ThresholdEd25519BootstrapSession | null = null;
        let thresholdEcdsaSession: ThresholdEcdsaBootstrapSession | null = null;

        const rpId = String(
          (request as unknown as { rp_id?: unknown; rpId?: unknown })?.rp_id ??
            (request as unknown as { rpId?: unknown })?.rpId ??
            '',
        ).trim();
        if (!rpId) throw new Error('Missing rp_id');

        if (thresholdEd25519Registration.relayerKeyId) {
          if (!thresholdEd25519SessionPolicy || typeof thresholdEd25519SessionPolicy !== 'object') {
            throw new Error('threshold_ed25519.session_policy is required');
          }
          if (thresholdEd25519SessionKind !== 'jwt') {
            throw new Error('threshold_ed25519.session_kind must be jwt');
          }
          if (
            !thresholdEd25519Registration.keyVersion ||
            !thresholdEd25519Registration.publicKey ||
            !thresholdEd25519Registration.relayerKeyId
          ) {
            throw new Error('threshold_ed25519 registration material is incomplete');
          }
          if (thresholdEd25519Registration.recoveryExportCapable !== true) {
            throw new Error('threshold_ed25519.recovery_export_capable must be true');
          }
        }
        if (thresholdEcdsaClientRootShare32B64u) {
          if (!thresholdEcdsaSessionPolicy || typeof thresholdEcdsaSessionPolicy !== 'object') {
            throw new Error('threshold_ecdsa.session_policy is required');
          }
          if (thresholdEcdsaSessionKind !== 'jwt') {
            throw new Error('threshold_ecdsa.session_kind must be jwt');
          }
        }

        const thresholdService = this.getThresholdSigningService();
        if (
          (thresholdEd25519Registration.relayerKeyId || thresholdEcdsaClientRootShare32B64u) &&
          !thresholdService
        ) {
          throw new Error('threshold signing is not configured on this server');
        }

        if (thresholdEd25519Registration.relayerKeyId) {
          const thresholdEd25519KeygenStartedAt = Date.now();
          const schemeAny = thresholdService!.getSchemeModule(
            THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
          );
          if (!schemeAny || schemeAny.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
            throw new Error(
              `threshold scheme ${THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID} is not enabled on this server`,
            );
          }
          const out = await schemeAny.registration.keygenFromRegistrationMaterial({
            nearAccountId: accountId,
            rpId,
            keyVersion: thresholdEd25519Registration.keyVersion,
            recoveryExportCapable: true,
            publicKey: thresholdEd25519Registration.publicKey,
            relayerKeyId: thresholdEd25519Registration.relayerKeyId,
          });
          if (!out.ok) {
            throw new Error(out.message || 'threshold-ed25519 registration keygen failed');
          }
          thresholdKeygen = out;
          logDuration(
            registrationTimings,
            'thresholdEd25519RegistrationMaterialMs',
            thresholdEd25519KeygenStartedAt,
          );
        }

        if (thresholdEcdsaClientRootShare32B64u) {
          const thresholdEcdsaKeygenStartedAt = Date.now();
          const out = await thresholdService!.bootstrapEcdsaFromRegistrationMaterial({
            userId: accountId,
            rpId,
            clientRootShare32B64u: thresholdEcdsaClientRootShare32B64u,
            sessionPolicy: thresholdEcdsaSessionPolicy as Record<string, unknown>,
          });
          if (!out.ok) {
            throw new Error(out.message || 'threshold-ecdsa registration keygen failed');
          }

          const ecdsaThresholdKeyId = String(out.ecdsaThresholdKeyId || '').trim();
          const signingRootId = String(out.signingRootId || '').trim();
          const signingRootVersion = String(out.signingRootVersion || '').trim();
          const relayerKeyId = String(out.relayerKeyId || '').trim();
          const thresholdEcdsaPublicKeyB64u = String(out.thresholdEcdsaPublicKeyB64u || '').trim();
          const ethereumAddress = String(out.ethereumAddress || '').trim();
          const relayerVerifyingShareB64u = String(out.relayerVerifyingShareB64u || '').trim();
          if (
            !ecdsaThresholdKeyId ||
            !signingRootId ||
            !relayerKeyId ||
            !thresholdEcdsaPublicKeyB64u ||
            !ethereumAddress ||
            !relayerVerifyingShareB64u
          ) {
            throw new Error('threshold-ecdsa registration keygen returned incomplete key material');
          }
          thresholdEcdsaKeygen = {
            ecdsaThresholdKeyId,
            signingRootId,
            ...(signingRootVersion ? { signingRootVersion } : {}),
            clientVerifyingShareB64u: String(out.clientVerifyingShareB64u || '').trim(),
            clientAdditiveShare32B64u: String(out.clientAdditiveShare32B64u || '').trim(),
            relayerKeyId,
            thresholdEcdsaPublicKeyB64u,
            ethereumAddress,
            relayerVerifyingShareB64u,
            ...(Array.isArray(out.participantIds) ? { participantIds: out.participantIds } : {}),
          };
          logDuration(
            registrationTimings,
            'thresholdEcdsaRegistrationMaterialMs',
            thresholdEcdsaKeygenStartedAt,
          );
          const normalizedSession = toThresholdEcdsaBootstrapSession(out);
          if (!normalizedSession) {
            throw new Error('threshold-ecdsa registration session bootstrap failed');
          }
          thresholdEcdsaSession = normalizedSession;
          logDuration(
            registrationTimings,
            'thresholdEcdsaSessionMintMs',
            thresholdEcdsaKeygenStartedAt,
          );
        }

        const { publicKey: newPublicKey, expectedPublicKeys } = normalizeBootstrapPublicKeys({
          publicKey: String(thresholdKeygen?.publicKey || '').trim(),
        });
        if (!newPublicKey) {
          throw new Error('threshold_ed25519 registration key material is required');
        }

        const signerSlot = (() => {
          const raw =
            (request as unknown as { signer_slot?: unknown; signerSlot?: unknown })?.signer_slot ??
            (request as unknown as { signerSlot?: unknown })?.signerSlot ??
            1;
          const n = typeof raw === 'number' ? raw : Number(raw);
          return Number.isFinite(n) && n > 0 ? Math.floor(n) : 1;
        })();

        const expectedOrigin = String(
          (request as unknown as { expected_origin?: unknown; expectedOrigin?: unknown })
            ?.expected_origin ??
            (request as unknown as { expectedOrigin?: unknown })?.expectedOrigin ??
            '',
        ).trim();

        const cred = request.webauthn_registration as any;
        if (!cred || typeof cred !== 'object') throw new Error('Missing webauthn_registration');

        // 1) Verify the registration ceremony (standard WebAuthn) off-chain.
        const expectedIntent = `register:${accountId}:${signerSlot}`;
        const expectedChallenge = base64UrlEncode(await sha256BytesUtf8(expectedIntent));

        const clientData = parseClientDataJsonBase64url(
          String(cred.response?.clientDataJSON || ''),
        );
        if (clientData.type !== 'webauthn.create') {
          throw new Error(
            'Invalid webauthn_registration.clientDataJSON.type (expected webauthn.create)',
          );
        }
        if (clientData.challenge !== expectedChallenge) {
          throw new Error('Registration challenge mismatch');
        }
        const originHost = originHostnameOrEmpty(clientData.origin);
        if (!isHostWithinRpId(originHost, rpId)) {
          throw new Error('WebAuthn origin is not within rpId');
        }

        const mod = await import('@simplewebauthn/server');
        const verifyRegistrationResponse = (mod as any).verifyRegistrationResponse as
          | undefined
          | ((args: any) => Promise<any>);
        if (typeof verifyRegistrationResponse !== 'function') {
          throw new Error('WebAuthn registration verifier is unavailable in this runtime');
        }

        // Require a concrete origin when possible (routers should pass the request Origin header).
        const expectedOriginStrict = expectedOrigin || clientData.origin;
        const verification = await verifyRegistrationResponse({
          response: cred,
          expectedChallenge,
          expectedOrigin: expectedOriginStrict,
          expectedRPID: rpId,
          requireUserVerification: false,
        });
        if (!verification?.verified) {
          throw new Error('Registration verification failed');
        }

        // 2) Create the on-chain account as a subaccount of the relayer signer.
        // In the lite architecture, account creation is done directly (no WebAuthn contract call).
        const accountExists = await this.checkAccountExists(accountId);
        if (accountExists) {
          throw new Error(`Account ${accountId} already exists. Cannot create duplicate account.`);
        }

        const actions: ActionArgsWasm[] = [
          {
            action_type: ActionType.CreateAccount,
          },
          {
            action_type: ActionType.Transfer,
            deposit: String(this.config.accountInitialBalance),
          },
          buildFullAccessAddKeyAction(newPublicKey),
        ];
        actions.forEach(validateActionArgsWasm);

        const { nextNonce, blockHash } = await this.fetchTxContext(
          relayerAccount,
          this.relayerPublicKey,
        );
        const signed = await this.signWithPrivateKey({
          nearPrivateKey: this.config.relayerPrivateKey,
          signerAccountId: relayerAccount,
          receiverId: accountId,
          nonce: nextNonce,
          blockHash,
          actions,
        });
        // Reach execution quickly, then perform one authoritative final key-visibility check.
        const atomicRegistrationBroadcastStartedAt = Date.now();
        const result = await this.nearClient.sendTransaction(
          signed,
          ACCOUNT_CREATE_BROADCAST_WAIT_UNTIL,
        );
        this.logger.info(
          `Atomic registration account creation for ${accountId} reached ${ACCOUNT_CREATE_BROADCAST_WAIT_UNTIL} in ${
            Date.now() - atomicRegistrationBroadcastStartedAt
          }ms`,
        );
        logDuration(
          registrationTimings,
          'nearAccountCreateBroadcastMs',
          atomicRegistrationBroadcastStartedAt,
        );
        const atomicRegistrationKeyCheckStartedAt = Date.now();
        const bootstrapKeysVerified = await this.verifyAccountAccessKeysPresent(
          accountId,
          expectedPublicKeys,
          ACCOUNT_CREATE_FAST_KEY_VISIBILITY_CHECK,
        );
        this.logger.info(
          `Atomic registration account creation for ${accountId} key visibility verified=${bootstrapKeysVerified} in ${
            Date.now() - atomicRegistrationKeyCheckStartedAt
          }ms`,
        );
        logDuration(
          registrationTimings,
          'nearAccessKeyVisibilityMs',
          atomicRegistrationKeyCheckStartedAt,
        );
        if (!bootstrapKeysVerified) {
          this.logger.warn(
            `Atomic registration committed for ${accountId} before the operational access key was visible on final state; scheduling background audit`,
          );
          this.scheduleAccountAccessKeyVisibilityAudit({
            accountId,
            expectedPublicKeys,
            contextLabel: `Atomic registration account creation for ${accountId}`,
          });
        }

        // 3) Persist the authenticator privately on the relay.
        const credentialIdB64u = String(
          verification?.registrationInfo?.credential?.id || '',
        ).trim();
        const credentialPublicKey = verification?.registrationInfo?.credential?.publicKey as
          | Uint8Array
          | undefined;
        const counter = verification?.registrationInfo?.credential?.counter as number | undefined;

        if (!credentialIdB64u || !credentialPublicKey) {
          throw new Error(
            'Registration verification did not return credential public key material',
          );
        }

        const store = this.getWebAuthnAuthenticatorStore();
        const now = Date.now();
        const authenticatorStoreStartedAt = Date.now();
        await store.put(accountId, {
          version: 'webauthn_authenticator_v1',
          credentialIdB64u,
          credentialPublicKeyB64u: base64UrlEncode(credentialPublicKey),
          counter: Number.isFinite(counter) && counter! >= 0 ? Math.floor(counter!) : 0,
          createdAtMs: now,
          updatedAtMs: now,
        });
        logDuration(registrationTimings, 'authenticatorStoreMs', authenticatorStoreStartedAt);

        // 4) Persist passkey→account binding for sync/link/recovery flows.
        // This is relay-private storage (no on-chain authenticator registry dependence).
        const bindingStore = this.getWebAuthnCredentialBindingStore();
        const binding: WebAuthnCredentialBindingRecord = {
          version: 'webauthn_credential_binding_v1',
          rpId,
          credentialIdB64u,
          userId: accountId,
          signerSlot,
          publicKey: newPublicKey,
          ...(thresholdKeygen ? { relayerKeyId: thresholdKeygen.relayerKeyId } : {}),
          ...(thresholdKeygen ? { keyVersion: thresholdKeygen.keyVersion } : {}),
          ...(thresholdKeygen
            ? { recoveryExportCapable: thresholdKeygen.recoveryExportCapable }
            : {}),
          ...(thresholdKeygen ? { clientParticipantId: thresholdKeygen.clientParticipantId } : {}),
          ...(thresholdKeygen
            ? { relayerParticipantId: thresholdKeygen.relayerParticipantId }
            : {}),
          ...(thresholdKeygen ? { participantIds: thresholdKeygen.participantIds } : {}),
          ...(normalizeThresholdRuntimePolicyScope(
            (thresholdEd25519SessionPolicy as Record<string, unknown> | undefined)
              ?.runtimePolicyScope,
          )
            ? {
                runtimePolicyScope: normalizeThresholdRuntimePolicyScope(
                  (thresholdEd25519SessionPolicy as Record<string, unknown> | undefined)
                    ?.runtimePolicyScope,
                ),
              }
            : {}),
          createdAtMs: now,
          updatedAtMs: now,
        };
        const bindingStoreStartedAt = Date.now();
        await bindingStore.put(binding);
        logDuration(registrationTimings, 'credentialBindingStoreMs', bindingStoreStartedAt);

        if (thresholdKeygen && thresholdEd25519SessionPolicy) {
          const thresholdEd25519SessionStartedAt = Date.now();
          const requestedThresholdEd25519PolicyRelayerKeyId = String(
            (thresholdEd25519SessionPolicy as Record<string, unknown>)?.relayerKeyId || '',
          ).trim();
          if (
            requestedThresholdEd25519PolicyRelayerKeyId &&
            requestedThresholdEd25519PolicyRelayerKeyId !== thresholdKeygen.relayerKeyId
          ) {
            throw new Error('threshold_ed25519.session_policy.relayerKeyId mismatch');
          }
          const thresholdEd25519PolicyWithRelayerKeyId = {
            ...(thresholdEd25519SessionPolicy as Record<string, unknown>),
            relayerKeyId: thresholdKeygen.relayerKeyId,
          } as any;
          const session = await thresholdService!.mintEd25519SessionFromRegistration({
            nearAccountId: accountId,
            rpId,
            relayerKeyId: thresholdKeygen.relayerKeyId,
            sessionPolicy: thresholdEd25519PolicyWithRelayerKeyId,
          });
          if (!session.ok || !session.sessionId || !Number.isFinite(Number(session.expiresAtMs))) {
            throw new Error(
              session.message ||
                session.code ||
                'threshold-ed25519 registration session bootstrap failed',
            );
          }
          const normalizedSession = toThresholdEd25519BootstrapSession(session);
          if (!normalizedSession) {
            throw new Error('threshold-ed25519 registration session bootstrap failed');
          }
          thresholdEd25519Session = normalizedSession;
          logDuration(
            registrationTimings,
            'thresholdEd25519SessionMintMs',
            thresholdEd25519SessionStartedAt,
          );
        }

        // Best-effort: persist NEAR public key metadata for UI surfaces.
        // This is not required for account correctness, so keep it off the blocking path.
        void (async () => {
          const nearPublicKeyMetadataStartedAt = Date.now();
          const recorded = await this.recordNearPublicKeyMetadata({
            userId: accountId,
            publicKey: newPublicKey,
            kind: 'threshold',
            signerSlot,
            rpId,
            credentialIdB64u,
            source: 'atomic registration NEAR public key metadata persistence',
          });
          if (recorded.ok) {
            this.logger.info('[AuthService] atomic registration async persistence', {
              nearAccountId: accountId,
              nearPublicKeyMetadataMs: Date.now() - nearPublicKeyMetadataStartedAt,
            });
          }
        })();

        if (thresholdEcdsaKeygen) {
          const smartAccountPersistenceStartedAt = Date.now();
          await this.persistRegistrationSmartAccountRecords({
            userId: accountId,
            nearAccountId: accountId,
            signerSlot,
            credentialIdB64u,
            rpId,
            thresholdEcdsaKeygen,
            smartAccountTargets: (request as any)?.threshold_ecdsa?.smart_account_targets,
            nowMs: now,
          });
          logDuration(
            registrationTimings,
            'thresholdEcdsaSmartAccountPersistenceMs',
            smartAccountPersistenceStartedAt,
          );
        }

        this.logger.info(`Registration completed: ${result.transaction.hash}`);
        this.logger.info('[AuthService] atomic registration timings', {
          nearAccountId: accountId,
          ...registrationTimings,
          totalMs: Date.now() - registrationStartedAt,
        });
        return {
          success: true,
          transactionHash: result.transaction.hash,
          ...(thresholdKeygen
            ? {
                thresholdEd25519: {
                  keyVersion: thresholdKeygen.keyVersion,
                  recoveryExportCapable: thresholdKeygen.recoveryExportCapable,
                  relayerKeyId: thresholdKeygen.relayerKeyId,
                  publicKey: newPublicKey,
                  clientParticipantId: thresholdKeygen.clientParticipantId,
                  relayerParticipantId: thresholdKeygen.relayerParticipantId,
                  participantIds: thresholdKeygen.participantIds,
                  ...(thresholdEd25519Session ? { session: thresholdEd25519Session } : {}),
                },
              }
            : {}),
          ...(thresholdEcdsaKeygen
            ? {
                thresholdEcdsa: {
                  ...thresholdEcdsaKeygen,
                  ...(thresholdEcdsaSession ? { session: thresholdEcdsaSession } : {}),
                },
              }
            : {}),
          message: `Account ${accountId} created and registered successfully`,
        };
      } catch (error: any) {
        this.logger.error(`Atomic registration failed for ${request.new_account_id}:`, error);
        const msg = errorMessage(error) || 'Unknown atomic registration error';
        return {
          success: false,
          error: msg,
          message: `Failed to create and register account ${request.new_account_id}: ${msg}`,
        };
      }
    }, `atomic create and register ${request.new_account_id}`);
  }

  /**
   * Standard WebAuthn assertion verification for lite flows.
   *
   * This verifies:
   * - the assertion signature against the credential public key stored in relay-private storage,
   * - the RP ID hash against `rpId`,
   * - the challenge against `expectedChallenge` (base64url string),
   * - and that `clientDataJSON.origin` is within the RP ID domain.
   *
   * Notes:
   * - This intentionally does not involve on-chain challenge proofs or `verify_authentication_response`.
   * - Replay protection is handled by upstream protocol bindings (e.g., unique sessionPolicyDigest32 via sessionId).
   */
  async verifyWebAuthnAuthenticationLite(input: {
    nearAccountId: string;
    rpId: string;
    expectedChallenge: string;
    webauthn_authentication: WebAuthnAuthenticationCredential;
    expected_origin?: string;
  }): Promise<{ success: boolean; verified: boolean; code?: string; message?: string }> {
    try {
      await this._ensureSignerAndRelayerAccount();

      const nearAccountId = String(input.nearAccountId || '').trim();
      const rpId = String(input.rpId || '').trim();
      const expectedChallenge = String(input.expectedChallenge || '').trim();
      const expectedOriginOverride = toOptionalTrimmedString(input.expected_origin);
      const cred = input.webauthn_authentication as any;

      if (!nearAccountId)
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: 'Missing nearAccountId',
        };
      if (!rpId)
        return { success: false, verified: false, code: 'invalid_body', message: 'Missing rpId' };
      if (!expectedChallenge)
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: 'Missing expectedChallenge',
        };
      if (!cred || typeof cred !== 'object')
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: 'Missing webauthn_authentication',
        };

      let clientData: { challenge: string; origin: string; type: string };
      try {
        clientData = parseClientDataJsonBase64url(String(cred.response?.clientDataJSON || ''));
      } catch (e: unknown) {
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: errorMessage(e) || 'Invalid webauthn_authentication.response.clientDataJSON',
        };
      }
      const originHost = originHostnameOrEmpty(clientData.origin);
      if (!isHostWithinRpId(originHost, rpId)) {
        return {
          success: false,
          verified: false,
          code: 'invalid_origin',
          message: 'WebAuthn origin is not within rpId',
        };
      }

      const credentialId = String(cred.id || '').trim();
      const rawId = String(cred.rawId || '').trim();
      const chosen = rawId || credentialId;
      if (!chosen) {
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: 'Missing webauthn_authentication.id/rawId',
        };
      }

      let credentialIDBytes: Uint8Array;
      try {
        credentialIDBytes = decodeBase64UrlOrBase64(chosen, 'webauthn_authentication.rawId');
      } catch (e: unknown) {
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: errorMessage(e) || 'Invalid credential rawId',
        };
      }
      const credentialIdB64u = base64UrlEncode(credentialIDBytes);

      const store = this.getWebAuthnAuthenticatorStore();
      const matched = await store.get(nearAccountId, credentialIdB64u);
      if (!matched) {
        return {
          success: false,
          verified: false,
          code: 'unknown_credential',
          message: 'Credential is not registered for user',
        };
      }

      // Lazy import to avoid forcing Node-only deps into non-Node runtimes unless used.
      const mod = await import('@simplewebauthn/server');
      const verifyAuthenticationResponse = (mod as any).verifyAuthenticationResponse as
        | undefined
        | ((args: any) => Promise<any>);
      if (typeof verifyAuthenticationResponse !== 'function') {
        return {
          success: false,
          verified: false,
          code: 'unsupported',
          message: 'WebAuthn verifier is unavailable in this runtime',
        };
      }

      let credentialPublicKeyBytes: Uint8Array;
      try {
        credentialPublicKeyBytes = decodeBase64UrlOrBase64(
          matched.credentialPublicKeyB64u,
          'authenticator.credentialPublicKeyB64u',
        );
      } catch (e: unknown) {
        return {
          success: false,
          verified: false,
          code: 'internal',
          message: `Stored credential public key is invalid: ${errorMessage(e) || 'decode failed'}`,
        };
      }

      const credential = {
        id: credentialIdB64u,
        publicKey:
          typeof Buffer !== 'undefined'
            ? Buffer.from(credentialPublicKeyBytes)
            : credentialPublicKeyBytes,
        counter: matched.counter,
      };

      let verification: any;
      try {
        verification = await verifyAuthenticationResponse({
          response: cred,
          expectedChallenge,
          expectedOrigin: expectedOriginOverride || clientData.origin,
          expectedRPID: rpId,
          credential,
          requireUserVerification: false,
        });
      } catch (e: unknown) {
        return {
          success: false,
          verified: false,
          code: 'invalid_assertion',
          message: errorMessage(e) || 'Authentication assertion verification threw',
        };
      }

      if (!verification?.verified) {
        return {
          success: false,
          verified: false,
          code: 'not_verified',
          message: 'Authentication verification failed',
        };
      }

      const newCounter = (() => {
        const v = (verification as { authenticationInfo?: { newCounter?: unknown } })
          ?.authenticationInfo?.newCounter;
        const n = typeof v === 'number' ? v : Number(v);
        return Number.isFinite(n) && n >= 0 ? Math.floor(n) : null;
      })();

      // Persist signature counter updates to harden against assertion replay.
      // Note: some authenticators do not implement counters (always 0); in that case, replay defense must come from one-time challenges.
      if (newCounter !== null) {
        try {
          const latest = await store.get(nearAccountId, credentialIdB64u);
          if (latest && newCounter > latest.counter) {
            await store.put(nearAccountId, {
              ...latest,
              credentialPublicKeyB64u: matched.credentialPublicKeyB64u,
              counter: newCounter,
              updatedAtMs: Date.now(),
            });
          }
        } catch (e: unknown) {
          return {
            success: false,
            verified: false,
            code: 'internal',
            message: `Failed to persist authenticator counter: ${errorMessage(e) || 'store error'}`,
          };
        }
      }

      return { success: true, verified: true };
    } catch (e: unknown) {
      const msg = errorMessage(e) || 'Verification failed';
      this.logger.error('[webauthn] verifyWebAuthnAuthenticationLite internal error', {
        message: msg,
        nearAccountId: String(input?.nearAccountId || ''),
        rpId: String(input?.rpId || ''),
      });
      return { success: false, verified: false, code: 'internal', message: msg };
    }
  }

  /**
   * List WebAuthn authenticators for the given user.
   *
   * This is relay-private state (no on-chain authenticator registry).
   * Intended for UI surfaces like "Linked Devices" in the SDK.
   */
  async listWebAuthnAuthenticatorsForUser(input: { userId: string; rpId?: string }): Promise<{
    ok: boolean;
    code?: string;
    message?: string;
    authenticators?: Array<{
      credentialIdB64u: string;
      signerSlot?: number;
      publicKey?: string;
      createdAtMs?: number;
      updatedAtMs?: number;
    }>;
  }> {
    try {
      const userId = String(input.userId || '').trim();
      const rpId = String(input.rpId || '').trim();
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };

      const authStore = this.getWebAuthnAuthenticatorStore();
      const bindingStore = this.getWebAuthnCredentialBindingStore();

      if (typeof authStore.list !== 'function') {
        return {
          ok: false,
          code: 'not_supported',
          message: 'Authenticator listing is not supported by this store',
        };
      }
      if (typeof bindingStore.listByUserId !== 'function') {
        return {
          ok: false,
          code: 'not_supported',
          message: 'Credential binding listing is not supported by this store',
        };
      }

      const [authenticators, bindings] = await Promise.all([
        authStore.list(userId),
        bindingStore.listByUserId({ userId, ...(rpId ? { rpId } : {}) }),
      ]);

      const authByCid = new Map<string, WebAuthnAuthenticatorRecord>();
      for (const a of authenticators || []) {
        authByCid.set(String(a.credentialIdB64u || '').trim(), a);
      }

      const merged = (bindings || []).map((b) => {
        const cid = String(b.credentialIdB64u || '').trim();
        const a = authByCid.get(cid);
        return {
          credentialIdB64u: cid,
          signerSlot: b.signerSlot,
          publicKey: b.publicKey,
          createdAtMs: a?.createdAtMs ?? b.createdAtMs,
          updatedAtMs: a?.updatedAtMs ?? b.updatedAtMs,
        };
      });

      merged.sort((x, y) => (Number(x.signerSlot || 0) || 0) - (Number(y.signerSlot || 0) || 0));

      return { ok: true, authenticators: merged };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to list authenticators',
      };
    }
  }

  async listNearPublicKeysForUser(input: { userId: string }): Promise<{
    ok: boolean;
    code?: string;
    message?: string;
    keys?: Array<{
      publicKey: string;
      kind: NearPublicKeyKind;
      signerSlot?: number;
      createdAtMs?: number;
      updatedAtMs?: number;
      rpId?: string;
      credentialIdB64u?: string;
    }>;
  }> {
    try {
      const userId = String(input.userId || '').trim();
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };

      const store = this.getNearPublicKeyStore();
      if (typeof store.listByUserId !== 'function') {
        return {
          ok: false,
          code: 'not_supported',
          message: 'Key listing is not supported by this store',
        };
      }

      const records = await store.listByUserId(userId);
      const keys = (records || []).map((r) => ({
        publicKey: r.publicKey,
        kind: r.kind,
        ...(typeof r.signerSlot === 'number' ? { signerSlot: r.signerSlot } : {}),
        createdAtMs: r.createdAtMs,
        updatedAtMs: r.updatedAtMs,
        ...(r.rpId ? { rpId: r.rpId } : {}),
        ...(r.credentialIdB64u ? { credentialIdB64u: r.credentialIdB64u } : {}),
      }));
      return { ok: true, keys };
    } catch (e: unknown) {
      return { ok: false, code: 'internal', message: errorMessage(e) || 'Failed to list keys' };
    }
  }

  async createWebAuthnLoginOptions(request: {
    userId?: unknown;
    user_id?: unknown;
    rpId?: unknown;
    rp_id?: unknown;
    ttlMs?: unknown;
    ttl_ms?: unknown;
  }): Promise<{
    ok: boolean;
    challengeId?: string;
    challengeB64u?: string;
    expiresAtMs?: number;
    code?: string;
    message?: string;
  }> {
    try {
      const userId = String(request?.userId ?? request?.user_id ?? '').trim();
      const rpId = String(request?.rpId ?? request?.rp_id ?? '').trim();
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!isValidAccountId(userId))
        return { ok: false, code: 'invalid_body', message: 'Invalid userId' };
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'Missing rpId' };

      const ttlMsRaw = request?.ttlMs ?? request?.ttl_ms;
      const ttlMs = (() => {
        const n = typeof ttlMsRaw === 'number' ? ttlMsRaw : Number(ttlMsRaw);
        if (!Number.isFinite(n) || n <= 0) return 5 * 60_000;
        return Math.floor(n);
      })();
      const ttlMsClamped = Math.min(Math.max(ttlMs, 10_000), 10 * 60_000);

      if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
        return {
          ok: false,
          code: 'unsupported',
          message: 'crypto.getRandomValues is unavailable in this runtime',
        };
      }

      const createdAtMs = Date.now();
      const expiresAtMs = createdAtMs + ttlMsClamped;
      const challengeId = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
      const challengeB64u = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));

      const store = this.getWebAuthnLoginChallengeStore();
      await store.put({
        version: 'webauthn_login_challenge_v1',
        challengeId,
        userId,
        rpId,
        challengeB64u,
        createdAtMs,
        expiresAtMs,
      });

      return { ok: true, challengeId, challengeB64u, expiresAtMs };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to create login options',
      };
    }
  }

  async verifyWebAuthnLogin(request: {
    challengeId?: unknown;
    challenge_id?: unknown;
    webauthn_authentication?: unknown;
    expected_origin?: string;
  }): Promise<{
    ok: boolean;
    verified?: boolean;
    userId?: string;
    rpId?: string;
    code?: string;
    message?: string;
  }> {
    try {
      const challengeId = String(request?.challengeId ?? request?.challenge_id ?? '').trim();
      if (!challengeId) return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };

      const store = this.getWebAuthnLoginChallengeStore();
      const record = await store.consume(challengeId);
      if (!record) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_expired_or_invalid',
          message: 'Login challenge expired or invalid',
        };
      }

      const verification = await this.verifyWebAuthnAuthenticationLite({
        nearAccountId: record.userId,
        rpId: record.rpId,
        expectedChallenge: record.challengeB64u,
        webauthn_authentication: request?.webauthn_authentication as any,
        expected_origin: request.expected_origin,
      });

      if (!verification.success || !verification.verified) {
        return {
          ok: false,
          verified: false,
          code: verification.code || 'not_verified',
          message: verification.message || 'Authentication verification failed',
        };
      }

      // Best-effort: ensure identity map includes this user's NEAR account id.
      // This enables provider linking flows to treat `near:{accountId}` as a stable identity.
      try {
        const identity = this.getIdentityStore();
        await identity.linkSubjectToUserId({
          userId: record.userId,
          subject: `near:${record.userId}`,
        });
      } catch {}

      return { ok: true, verified: true, userId: record.userId, rpId: record.rpId };
    } catch (e: unknown) {
      return {
        ok: false,
        verified: false,
        code: 'internal',
        message: errorMessage(e) || 'Login verification failed',
      };
    }
  }

  async createEmailOtpUnlockChallenge(request: {
    walletId?: unknown;
    orgId?: unknown;
    ttlMs?: unknown;
    ttl_ms?: unknown;
  }): Promise<
    | {
        ok: true;
        walletId: string;
        challengeId: string;
        challengeB64u: string;
        expiresAtMs: number;
        unlockKeyVersion: string;
      }
    | { ok: false; code: string; message: string; lockedUntilMs?: number }
  > {
    try {
      const walletId = toOptionalTrimmedString(request.walletId);
      const orgId = toOptionalTrimmedString(request.orgId) || undefined;
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!isValidAccountId(walletId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid walletId' };
      }

      const activeEnrollment = await this.readActiveEmailOtpEnrollment({ walletId, orgId });
      if (!activeEnrollment.ok) return activeEnrollment;
      const enrollment = activeEnrollment.enrollment;

      const ttlMsRaw = request.ttlMs ?? request.ttl_ms;
      const ttlMs = (() => {
        const n = typeof ttlMsRaw === 'number' ? ttlMsRaw : Number(ttlMsRaw);
        if (!Number.isFinite(n) || n <= 0) return 5 * 60_000;
        return Math.floor(n);
      })();
      const ttlMsClamped = Math.min(Math.max(ttlMs, 10_000), 10 * 60_000);

      if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
        return {
          ok: false,
          code: 'unsupported',
          message: 'crypto.getRandomValues is unavailable in this runtime',
        };
      }

      const createdAtMs = Date.now();
      const expiresAtMs = createdAtMs + ttlMsClamped;
      const challengeId = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
      const challengeB64u = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
      await this.getEmailOtpUnlockChallengeStore().put({
        version: 'email_otp_unlock_challenge_v1',
        challengeId,
        walletId: enrollment.walletId,
        userId: enrollment.providerUserId,
        orgId: enrollment.orgId,
        challengeB64u,
        createdAtMs,
        expiresAtMs,
      });

      return {
        ok: true,
        walletId: enrollment.walletId,
        challengeId,
        challengeB64u,
        expiresAtMs,
        unlockKeyVersion: enrollment.unlockKeyVersion,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to create Email OTP unlock challenge',
      };
    }
  }

  async verifyEmailOtpUnlockProof(request: {
    walletId?: unknown;
    orgId?: unknown;
    challengeId?: unknown;
    unlockProof?: unknown;
  }): Promise<
    | {
        ok: true;
        verified: true;
        userId: string;
        walletId: string;
        unlockKeyVersion: string;
      }
    | { ok: false; verified: false; code: string; message: string }
  > {
    try {
      const walletId = toOptionalTrimmedString(request.walletId);
      const orgId = toOptionalTrimmedString(request.orgId) || undefined;
      const challengeId = toOptionalTrimmedString(request.challengeId);
      if (!walletId)
        return { ok: false, verified: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!isValidAccountId(walletId)) {
        return { ok: false, verified: false, code: 'invalid_body', message: 'Invalid walletId' };
      }
      if (!challengeId) {
        return { ok: false, verified: false, code: 'invalid_body', message: 'Missing challengeId' };
      }
      if (
        !request.unlockProof ||
        typeof request.unlockProof !== 'object' ||
        Array.isArray(request.unlockProof)
      ) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof is required',
        };
      }

      const providedPublicKey = toOptionalTrimmedString(
        (request.unlockProof as Record<string, unknown>).publicKey,
      );
      const signatureB64u = toOptionalTrimmedString(
        (request.unlockProof as Record<string, unknown>).signature,
      );
      if (!providedPublicKey) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.publicKey is required',
        };
      }
      if (!signatureB64u) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.signature is required',
        };
      }

      const challengeRecord = await this.getEmailOtpUnlockChallengeStore().consume(challengeId);
      if (!challengeRecord) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_expired_or_invalid',
          message: 'Email OTP unlock challenge expired or invalid',
        };
      }
      if (Date.now() > challengeRecord.expiresAtMs) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_expired_or_invalid',
          message: 'Email OTP unlock challenge expired or invalid',
        };
      }
      if (challengeRecord.walletId !== walletId) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_binding_mismatch',
          message: 'Email OTP unlock challenge is not valid for this walletId',
        };
      }

      const activeEnrollment = await this.readActiveEmailOtpEnrollment({ walletId, orgId });
      if (!activeEnrollment.ok) {
        return {
          ok: false,
          verified: false,
          code: activeEnrollment.code,
          message: activeEnrollment.message,
        };
      }
      const enrollment = activeEnrollment.enrollment;
      if (
        challengeRecord.userId !== enrollment.providerUserId ||
        challengeRecord.orgId !== enrollment.orgId
      ) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_binding_mismatch',
          message: 'Email OTP unlock challenge is not valid for this enrollment',
        };
      }

      let publicKey33: Uint8Array;
      try {
        publicKey33 = base64UrlDecode(providedPublicKey);
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.publicKey must be valid base64url',
        };
      }
      if (publicKey33.length !== 33) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.publicKey must decode to 33 bytes',
        };
      }
      try {
        await validateSecp256k1PublicKey33(publicKey33);
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.publicKey is not a valid secp256k1 public key',
        };
      }

      let signature65: Uint8Array;
      try {
        signature65 = base64UrlDecode(signatureB64u);
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.signature must be valid base64url',
        };
      }
      if (signature65.length !== 65) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.signature must decode to 65 bytes',
        };
      }

      const enrolledPublicKey = base64UrlDecode(enrollment.clientUnlockPublicKeyB64u);
      if (
        enrolledPublicKey.length !== publicKey33.length ||
        !enrolledPublicKey.every((value, index) => value === publicKey33[index])
      ) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_unlock_proof',
          message: 'unlockProof.publicKey does not match the enrolled clientUnlockPublicKeyB64u',
        };
      }

      let challengeDigest32: Uint8Array;
      try {
        challengeDigest32 = base64UrlDecode(challengeRecord.challengeB64u);
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'internal',
          message: 'Stored unlock challenge digest was invalid',
        };
      }
      if (challengeDigest32.length !== 32) {
        return {
          ok: false,
          verified: false,
          code: 'internal',
          message: 'Stored unlock challenge digest must decode to 32 bytes',
        };
      }

      try {
        await verifySecp256k1RecoverableSignatureAgainstPublicKey33(
          challengeDigest32,
          signature65,
          publicKey33,
        );
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'invalid_unlock_proof',
          message: 'unlockProof.signature did not verify against unlockProof.publicKey',
        };
      }

      const nowMs = Date.now();
      await this.putEmailOtpAuthStateForEnrollment(enrollment, {
        lastEmailOtpLoginAtMs: nowMs,
      });

      return {
        ok: true,
        verified: true,
        userId: enrollment.walletId,
        walletId: enrollment.walletId,
        unlockKeyVersion: enrollment.unlockKeyVersion,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        verified: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to verify Email OTP unlock proof',
      };
    }
  }

  private async pruneExpiredEmailOtpChallenges(
    challengeStore: EmailOtpChallengeStore,
    nowMs: number,
  ): Promise<void> {
    const deleted = await challengeStore.deleteExpired(nowMs);
    for (const record of deleted) {
      this.emailOtpMemoryOutbox.delete(record.challengeId);
    }
  }

  private async enforceEmailOtpActiveChallengeLimit(input: {
    challengeStore: EmailOtpChallengeStore;
    userId: string;
    walletId: string;
    orgId?: string;
    otpChannel: EmailOtpChannel;
    sessionHash: string;
    appSessionVersion: string;
    action: EmailOtpChallengeAction;
    operation: EmailOtpChallengeOperation;
    nowMs: number;
    maxActiveChallenges: number;
  }): Promise<void> {
    const maxActive = Math.max(1, Math.floor(input.maxActiveChallenges));
    while (
      (await input.challengeStore.countActiveByContext({
        userId: input.userId,
        walletId: input.walletId,
        ...(input.orgId ? { orgId: input.orgId } : {}),
        otpChannel: input.otpChannel,
        sessionHash: input.sessionHash,
        appSessionVersion: input.appSessionVersion,
        action: input.action,
        operation: input.operation,
        nowMs: input.nowMs,
      })) >= maxActive
    ) {
      const deleted = await input.challengeStore.deleteOldestActiveByContext({
        userId: input.userId,
        walletId: input.walletId,
        ...(input.orgId ? { orgId: input.orgId } : {}),
        otpChannel: input.otpChannel,
        sessionHash: input.sessionHash,
        appSessionVersion: input.appSessionVersion,
        action: input.action,
        operation: input.operation,
        nowMs: input.nowMs,
      });
      if (!deleted) break;
      this.emailOtpMemoryOutbox.delete(deleted.challengeId);
    }
  }

  private async readEmailOtpAuthStateForEnrollment(
    enrollmentRecord: EmailOtpWalletEnrollmentRecord,
  ): Promise<
    | { ok: true; state: EmailOtpAuthStateRecord | null }
    | { ok: false; code: string; message: string }
  > {
    const state = await this.getEmailOtpAuthStateStore().get(enrollmentRecord.walletId);
    if (!state) return { ok: true, state: null };
    if (
      state.orgId !== enrollmentRecord.orgId ||
      state.providerUserId !== enrollmentRecord.providerUserId
    ) {
      return {
        ok: false,
        code: 'auth_state_enrollment_mismatch',
        message: 'Email OTP auth state does not match the active enrollment',
      };
    }
    return { ok: true, state };
  }

  private async putEmailOtpAuthStateForEnrollment(
    enrollmentRecord: EmailOtpWalletEnrollmentRecord,
    patch: Partial<
      Pick<
        EmailOtpAuthStateRecord,
        | 'otpFailureCount'
        | 'lastOtpFailureAtMs'
        | 'otpLockedUntilMs'
        | 'lastEmailOtpLoginAtMs'
        | 'lastStrongAuthAtMs'
      >
    >,
  ): Promise<EmailOtpAuthStateRecord> {
    const nowMs = Date.now();
    const existing = await this.getEmailOtpAuthStateStore().get(enrollmentRecord.walletId);
    if (
      existing &&
      (existing.orgId !== enrollmentRecord.orgId ||
        existing.providerUserId !== enrollmentRecord.providerUserId)
    ) {
      throw new Error('Email OTP auth state does not match the active enrollment');
    }
    const next: EmailOtpAuthStateRecord = {
      version: 'email_otp_auth_state_v1',
      walletId: enrollmentRecord.walletId,
      providerUserId: enrollmentRecord.providerUserId,
      orgId: enrollmentRecord.orgId,
      createdAtMs: existing?.createdAtMs ?? nowMs,
      updatedAtMs: nowMs,
      ...(existing?.otpFailureCount != null ? { otpFailureCount: existing.otpFailureCount } : {}),
      ...(existing?.lastOtpFailureAtMs ? { lastOtpFailureAtMs: existing.lastOtpFailureAtMs } : {}),
      ...(existing?.otpLockedUntilMs ? { otpLockedUntilMs: existing.otpLockedUntilMs } : {}),
      ...(existing?.lastEmailOtpLoginAtMs
        ? { lastEmailOtpLoginAtMs: existing.lastEmailOtpLoginAtMs }
        : {}),
      ...(existing?.lastStrongAuthAtMs ? { lastStrongAuthAtMs: existing.lastStrongAuthAtMs } : {}),
      ...patch,
    };
    await this.getEmailOtpAuthStateStore().put(next);
    return next;
  }

  private async createEmailOtpChallengeWithAction(request: {
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    email?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
    operation?: unknown;
    action: EmailOtpChallengeAction;
  }): Promise<
    | {
        ok: true;
        challenge: {
          challengeId: string;
          issuedAtMs: number;
          expiresAtMs: number;
          userId: string;
          walletId: string;
          orgId: string;
          otpChannel: EmailOtpChannel;
          sessionHash: string;
          appSessionVersion: string;
          action: EmailOtpChallengeAction;
          operation: EmailOtpChallengeOperation;
        };
        delivery: {
          mode: 'email_provider' | 'log' | 'memory';
          emailHint: string;
        };
      }
    | {
        ok: false;
        code: string;
        message: string;
        lockedUntilMs?: number;
        retryAfterMs?: number;
        resetAtMs?: number;
      }
  > {
    try {
      const userId = toOptionalTrimmedString(request.userId);
      const walletId = toOptionalTrimmedString(request.walletId);
      const orgId = toOptionalTrimmedString(request.orgId) || '';
      const email = toOptionalTrimmedString(request.email)?.toLowerCase() || '';
      const otpChannel = toOptionalTrimmedString(request.otpChannel);
      const sessionHash = toOptionalTrimmedString(request.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(request.appSessionVersion);
      const clientIp = toOptionalTrimmedString(request.clientIp) || undefined;
      const action = request.action;
      const operationRaw = toOptionalTrimmedString(request.operation);
      let operation: EmailOtpChallengeOperation;
      if (operationRaw && isWalletEmailOtpLoginOperation(operationRaw)) {
        operation = operationRaw;
      } else if (operationRaw === WALLET_EMAIL_OTP_REGISTRATION_OPERATION) {
        operation = WALLET_EMAIL_OTP_REGISTRATION_OPERATION;
      } else {
        operation =
          action === WALLET_EMAIL_OTP_ACTIONS.registration
            ? WALLET_EMAIL_OTP_REGISTRATION_OPERATION
            : WALLET_EMAIL_OTP_UNLOCK_OPERATION;
      }
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (otpChannel !== EMAIL_OTP_CHANNEL) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'otpChannel must be email_otp',
        };
      }
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }
      const activeEnrollment =
        action !== WALLET_EMAIL_OTP_ACTIONS.registration
          ? await this.readActiveEmailOtpEnrollment({ walletId, orgId })
          : null;
      if (activeEnrollment && !activeEnrollment.ok) return activeEnrollment;
      const existingEnrollment = activeEnrollment?.ok ? activeEnrollment.enrollment : null;
      const existingAuthStateResult = existingEnrollment
        ? await this.readEmailOtpAuthStateForEnrollment(existingEnrollment)
        : { ok: true as const, state: null };
      if (!existingAuthStateResult.ok) return existingAuthStateResult;
      const existingAuthState = existingAuthStateResult.state;
      const challengeEmail =
        action === WALLET_EMAIL_OTP_ACTIONS.registration
          ? email
          : existingEnrollment?.verifiedEmail || '';
      if (!challengeEmail) {
        return {
          ok: false,
          code: 'recovery_email_missing',
          message: 'Current app session does not include a recovery email',
        };
      }
      if (existingAuthState?.otpLockedUntilMs && existingAuthState.otpLockedUntilMs > Date.now()) {
        return {
          ok: false,
          code: 'otp_locked_out',
          message: 'Email OTP is temporarily locked for this wallet',
          lockedUntilMs: existingAuthState.otpLockedUntilMs,
        };
      }
      const rateLimit = await this.consumeEmailOtpRateLimit({
        scope: 'challenge',
        action,
        userId,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;
      if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
        return {
          ok: false,
          code: 'unsupported',
          message: 'crypto.getRandomValues is unavailable in this runtime',
        };
      }

      const otpConfig = this.resolveEmailOtpConfig();
      const issuedAtMs = Date.now();
      const expiresAtMs = issuedAtMs + otpConfig.challengeTtlMs;
      const challengeId = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
      const otpCode = this.generateNumericOtp(otpConfig.codeLength);
      const challengeStore = this.getEmailOtpChallengeStore();
      await this.pruneExpiredEmailOtpChallenges(challengeStore, issuedAtMs);
      await this.enforceEmailOtpActiveChallengeLimit({
        challengeStore,
        userId,
        walletId,
        orgId,
        otpChannel: EMAIL_OTP_CHANNEL,
        sessionHash,
        appSessionVersion,
        action,
        operation,
        nowMs: issuedAtMs,
        maxActiveChallenges: otpConfig.maxActiveChallengesPerContext,
      });

      const challengeRecord: EmailOtpChallengeRecord = {
        version: 'email_otp_challenge_v1' as const,
        challengeId,
        userId,
        walletId,
        orgId,
        otpChannel: EMAIL_OTP_CHANNEL,
        email: challengeEmail,
        otpCode,
        sessionHash,
        appSessionVersion,
        action,
        operation,
        createdAtMs: issuedAtMs,
        expiresAtMs,
        attemptCount: 0,
        maxAttempts: otpConfig.maxAttempts,
      };
      await challengeStore.put(challengeRecord);
      const persistedChallenge = await challengeStore.get(challengeId);
      if (!persistedChallenge) {
        return {
          ok: false,
          code: 'internal',
          message: 'Email OTP challenge could not be persisted',
        };
      }

      const delivery = await this.deliverEmailOtpCode({
        challengeId,
        walletId,
        userId,
        otpChannel: EMAIL_OTP_CHANNEL,
        email: challengeEmail,
        otpCode,
        expiresAtMs,
      });
      if (!delivery.ok) {
        await challengeStore.del(challengeId);
        this.emailOtpMemoryOutbox.delete(challengeId);
        return delivery;
      }

      return {
        ok: true,
        challenge: {
          challengeId,
          issuedAtMs,
          expiresAtMs,
          userId,
          walletId,
          orgId,
          otpChannel: EMAIL_OTP_CHANNEL,
          sessionHash,
          appSessionVersion,
          action,
          operation,
        },
        delivery: {
          mode: delivery.deliveryMode,
          emailHint: delivery.emailHint,
        },
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to create Email OTP challenge',
      };
    }
  }

  async createEmailOtpChallenge(request: {
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    email?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
    operation?: unknown;
  }): Promise<
    | {
        ok: true;
        challenge: {
          challengeId: string;
          issuedAtMs: number;
          expiresAtMs: number;
          userId: string;
          walletId: string;
          orgId: string;
          otpChannel: EmailOtpChannel;
          sessionHash: string;
          appSessionVersion: string;
          action: typeof WALLET_EMAIL_OTP_ACTIONS.login;
          operation: EmailOtpLoginChallengeOperation;
        };
        delivery: {
          mode: 'email_provider' | 'log' | 'memory';
          emailHint: string;
        };
      }
    | { ok: false; code: string; message: string }
  > {
    const result = await this.createEmailOtpChallengeWithAction({
      ...request,
      action: WALLET_EMAIL_OTP_ACTIONS.login,
    });
    if (!result.ok) return result;
    const operation =
      result.challenge.operation === WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION ||
      result.challenge.operation === WALLET_EMAIL_OTP_EXPORT_OPERATION
        ? result.challenge.operation
        : WALLET_EMAIL_OTP_UNLOCK_OPERATION;
    return {
      ok: true,
      challenge: { ...result.challenge, action: WALLET_EMAIL_OTP_ACTIONS.login, operation },
      delivery: result.delivery,
    };
  }

  async createEmailOtpEnrollmentChallenge(request: {
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    email?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
    operation?: unknown;
  }): Promise<
    | {
        ok: true;
        challenge: {
          challengeId: string;
          issuedAtMs: number;
          expiresAtMs: number;
          userId: string;
          walletId: string;
          orgId: string;
          otpChannel: EmailOtpChannel;
          sessionHash: string;
          appSessionVersion: string;
          action: typeof WALLET_EMAIL_OTP_ACTIONS.registration;
          operation: typeof WALLET_EMAIL_OTP_REGISTRATION_OPERATION;
        };
        delivery: {
          mode: 'email_provider' | 'log' | 'memory';
          emailHint: string;
        };
      }
    | { ok: false; code: string; message: string }
  > {
    const result = await this.createEmailOtpChallengeWithAction({
      ...request,
      action: WALLET_EMAIL_OTP_ACTIONS.registration,
    });
    if (!result.ok) return result;
    return {
      ok: true,
      challenge: {
        ...result.challenge,
        action: WALLET_EMAIL_OTP_ACTIONS.registration,
        operation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
      },
      delivery: result.delivery,
    };
  }

  async createEmailOtpDeviceRecoveryChallenge(request: {
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    email?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
  }): Promise<
    | {
        ok: true;
        challenge: {
          challengeId: string;
          issuedAtMs: number;
          expiresAtMs: number;
          userId: string;
          walletId: string;
          orgId: string;
          otpChannel: EmailOtpChannel;
          sessionHash: string;
          appSessionVersion: string;
          action: typeof WALLET_EMAIL_OTP_ACTIONS.deviceRecovery;
          operation: typeof WALLET_EMAIL_OTP_UNLOCK_OPERATION;
        };
        delivery: {
          mode: 'email_provider' | 'log' | 'memory';
          emailHint: string;
        };
      }
    | { ok: false; code: string; message: string }
  > {
    const result = await this.createEmailOtpChallengeWithAction({
      ...request,
      action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    });
    if (!result.ok) return result;
    return {
      ok: true,
      challenge: {
        ...result.challenge,
        action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
        operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
      },
      delivery: result.delivery,
    };
  }

  private async verifyEmailOtpChallengeCode(request: {
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    challengeId?: unknown;
    otpCode?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
    expectedAction: EmailOtpChallengeAction;
    expectedOperation?: EmailOtpChallengeOperation;
  }): Promise<
    | {
        ok: true;
        challengeId: string;
        userId: string;
        walletId: string;
        orgId: string;
        email?: string;
        otpChannel: EmailOtpChannel;
      }
    | {
        ok: false;
        code: string;
        message: string;
        attemptsRemaining?: number;
        lockedUntilMs?: number;
      }
  > {
    try {
      const userId = toOptionalTrimmedString(request.userId);
      const walletId = toOptionalTrimmedString(request.walletId);
      const orgId = toOptionalTrimmedString(request.orgId) || '';
      const challengeId = toOptionalTrimmedString(request.challengeId);
      const otpCode = toOptionalTrimmedString(request.otpCode);
      const otpChannel = toOptionalTrimmedString(request.otpChannel);
      const sessionHash = toOptionalTrimmedString(request.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(request.appSessionVersion);
      const clientIp = toOptionalTrimmedString(request.clientIp) || undefined;
      const expectedAction = request.expectedAction;
      const expectedOperation = request.expectedOperation;
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (!challengeId) return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };
      if (!otpCode) return { ok: false, code: 'invalid_body', message: 'Missing otpCode' };
      if (otpChannel !== EMAIL_OTP_CHANNEL) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'otpChannel must be email_otp',
        };
      }
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }
      const rateLimit = await this.consumeEmailOtpRateLimit({
        scope: 'verify',
        action: expectedAction,
        userId,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const activeEnrollment =
        expectedAction !== WALLET_EMAIL_OTP_ACTIONS.registration
          ? await this.readActiveEmailOtpEnrollment({ walletId, orgId })
          : null;
      if (activeEnrollment && !activeEnrollment.ok) return activeEnrollment;
      const enrollment = activeEnrollment?.ok
        ? activeEnrollment.enrollment
        : await this.getEmailOtpWalletEnrollmentStore().get(walletId);
      if (enrollment && enrollment.orgId !== orgId) {
        return {
          ok: false,
          code: 'tenant_scope_mismatch',
          message: 'Email OTP enrollment does not match the requested orgId',
        };
      }
      const authStateResult = enrollment
        ? await this.readEmailOtpAuthStateForEnrollment(enrollment)
        : { ok: true as const, state: null };
      if (!authStateResult.ok) return authStateResult;
      const authState = authStateResult.state;
      const activeLockoutUntilMs =
        authState?.otpLockedUntilMs && authState.otpLockedUntilMs > Date.now()
          ? authState.otpLockedUntilMs
          : undefined;
      if (activeLockoutUntilMs) {
        return {
          ok: false,
          code: 'otp_locked_out',
          message: 'Email OTP is temporarily locked for this wallet',
          lockedUntilMs: activeLockoutUntilMs,
        };
      }

      const challengeStore = this.getEmailOtpChallengeStore();
      const nowMs = Date.now();
      await this.pruneExpiredEmailOtpChallenges(challengeStore, nowMs);
      let record = await challengeStore.get(challengeId);
      if (!record) {
        record = await challengeStore.findActiveByContext({
          userId,
          walletId,
          orgId,
          otpChannel: EMAIL_OTP_CHANNEL,
          sessionHash,
          appSessionVersion,
          action: expectedAction,
          operation: expectedOperation || WALLET_EMAIL_OTP_UNLOCK_OPERATION,
          otpCode,
          nowMs,
        });
        if (!record) {
          this.logger.warn('[email-otp] challenge record not found during verification', {
            challengeId,
            walletId,
            userId,
            otpChannel: EMAIL_OTP_CHANNEL,
            action: expectedAction,
          });
          return {
            ok: false,
            code: 'challenge_expired_or_invalid',
            message: 'Email OTP challenge expired or invalid',
          };
        }
      }

      if (nowMs > record.expiresAtMs) {
        await challengeStore.del(record.challengeId);
        this.emailOtpMemoryOutbox.delete(record.challengeId);
        return {
          ok: false,
          code: 'challenge_expired_or_invalid',
          message: 'Email OTP challenge expired or invalid',
        };
      }

      const bindingMismatch =
        record.userId !== userId ||
        record.walletId !== walletId ||
        record.otpChannel !== EMAIL_OTP_CHANNEL ||
        record.action !== expectedAction ||
        (expectedOperation ? record.operation !== expectedOperation : false) ||
        record.sessionHash !== sessionHash ||
        record.appSessionVersion !== appSessionVersion ||
        String(record.orgId || '') !== String(orgId || '');
      if (bindingMismatch) {
        return {
          ok: false,
          code: 'challenge_binding_mismatch',
          message: 'Email OTP challenge is not valid for the current app session',
        };
      }

      if (record.otpCode !== otpCode) {
        const matchingRecord = await challengeStore.findActiveByContext({
          userId,
          walletId,
          orgId,
          otpChannel: EMAIL_OTP_CHANNEL,
          sessionHash,
          appSessionVersion,
          action: expectedAction,
          operation: expectedOperation || record.operation,
          otpCode,
          nowMs,
        });
        if (matchingRecord) {
          record = matchingRecord;
        }
      }

      if (record.otpCode !== otpCode) {
        const nextAttemptCount = record.attemptCount + 1;
        const otpConfig = this.resolveEmailOtpConfig();
        const nextLockedUntilMs =
          nextAttemptCount >= record.maxAttempts ? Date.now() + otpConfig.lockoutTtlMs : undefined;
        if (enrollment) {
          const nowMsForFailure = Date.now();
          const nextFailureCount = Number(authState?.otpFailureCount || 0) + 1;
          await this.putEmailOtpAuthStateForEnrollment(enrollment, {
            otpFailureCount: nextFailureCount,
            lastOtpFailureAtMs: nowMsForFailure,
            ...(nextLockedUntilMs ? { otpLockedUntilMs: nextLockedUntilMs } : {}),
          });
        }
        if (nextAttemptCount >= record.maxAttempts) {
          await challengeStore.del(record.challengeId);
          this.emailOtpMemoryOutbox.delete(record.challengeId);
          return {
            ok: false,
            code: 'otp_attempts_exhausted',
            message: 'Email OTP challenge exceeded the maximum number of attempts',
            attemptsRemaining: 0,
            ...(nextLockedUntilMs ? { lockedUntilMs: nextLockedUntilMs } : {}),
          };
        }

        await challengeStore.put({
          ...record,
          attemptCount: nextAttemptCount,
        });
        return {
          ok: false,
          code: 'invalid_otp',
          message: 'OTP code is invalid',
          attemptsRemaining: record.maxAttempts - nextAttemptCount,
        };
      }

      await challengeStore.del(record.challengeId);
      this.emailOtpMemoryOutbox.delete(record.challengeId);

      if (enrollment) {
        const hadOtpFailureState =
          Number(authState?.otpFailureCount || 0) > 0 ||
          authState?.lastOtpFailureAtMs != null ||
          authState?.otpLockedUntilMs != null;
        if (hadOtpFailureState) {
          await this.putEmailOtpAuthStateForEnrollment(enrollment, {
            otpFailureCount: 0,
            lastOtpFailureAtMs: undefined,
            otpLockedUntilMs: undefined,
          });
        }
      }

      return {
        ok: true,
        challengeId: record.challengeId,
        userId,
        walletId,
        orgId,
        ...(record.email ? { email: record.email } : {}),
        otpChannel: EMAIL_OTP_CHANNEL,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to verify Email OTP challenge',
      };
    }
  }

  async verifyEmailOtpChallenge(request: {
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    challengeId?: unknown;
    otpCode?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
    operation?: unknown;
  }): Promise<
    | {
        ok: true;
        challengeId: string;
        loginGrant: string;
        grantExpiresAtMs: number;
        otpChannel: EmailOtpChannel;
      }
    | {
        ok: false;
        code: string;
        message: string;
        attemptsRemaining?: number;
        lockedUntilMs?: number;
      }
  > {
    const operationRaw = toOptionalTrimmedString(request.operation);
    const verified = await this.verifyEmailOtpChallengeCode({
      ...request,
      expectedAction: WALLET_EMAIL_OTP_ACTIONS.login,
      expectedOperation:
        operationRaw === WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION ||
        operationRaw === WALLET_EMAIL_OTP_EXPORT_OPERATION
          ? operationRaw
          : WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    });
    if (!verified.ok) return verified;
    if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
      return {
        ok: false,
        code: 'unsupported',
        message: 'crypto.getRandomValues is unavailable in this runtime',
      };
    }
    const otpConfig = this.resolveEmailOtpConfig();
    const grantToken = base64UrlEncode(crypto.getRandomValues(new Uint8Array(24)));
    const issuedAtMs = Date.now();
    const grantExpiresAtMs = issuedAtMs + otpConfig.grantTtlMs;
    await this.getEmailOtpGrantStore().put({
      version: 'email_otp_grant_v1',
      grantToken,
      userId: verified.userId,
      walletId: verified.walletId,
      orgId: verified.orgId,
      challengeId: verified.challengeId,
      otpChannel: verified.otpChannel,
      sessionHash: String(request.sessionHash || '').trim(),
      appSessionVersion: String(request.appSessionVersion || '').trim(),
      action: WALLET_EMAIL_OTP_ACTIONS.unseal,
      issuedAtMs,
      expiresAtMs: grantExpiresAtMs,
    });
    return {
      ok: true,
      challengeId: verified.challengeId,
      loginGrant: grantToken,
      grantExpiresAtMs,
      otpChannel: verified.otpChannel,
    };
  }

  async verifyEmailOtpDeviceRecoveryChallenge(request: {
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    challengeId?: unknown;
    otpCode?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
  }): Promise<
    | {
        ok: true;
        challengeId: string;
        otpChannel: EmailOtpChannel;
        recoveryConsumeGrant: string;
        recoveryConsumeGrantExpiresAtMs: number;
        recoveryWrappedEnrollmentEscrows: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[];
        enrollment: {
          walletId: string;
          providerUserId: string;
          orgId: string;
          enrollmentId: string;
          enrollmentVersion: string;
          enrollmentSealKeyVersion: string;
          signingRootId: string;
          signingRootVersion: string;
          recoveryWrappedEnrollmentEscrowCount: number;
        };
      }
    | {
        ok: false;
        code: string;
        message: string;
        attemptsRemaining?: number;
        lockedUntilMs?: number;
      }
  > {
    const verified = await this.verifyEmailOtpChallengeCode({
      ...request,
      expectedAction: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
      expectedOperation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    });
    if (!verified.ok) return verified;
    const enrollment = await this.readActiveEmailOtpEnrollment({
      walletId: verified.walletId,
      orgId: verified.orgId,
      providerUserId: verified.userId,
    });
    if (!enrollment.ok) return enrollment;
    const recoveryWrappedEnrollmentEscrows =
      await this.getEmailOtpRecoveryWrappedEnrollmentEscrowStore().listActiveByWallet(
        verified.walletId,
      );
    const scopedRecoveryWrappedEnrollmentEscrows = recoveryWrappedEnrollmentEscrows.filter(
      (record) => this.emailOtpRecoveryEscrowMatchesEnrollment(record, enrollment.enrollment),
    );
    if (scopedRecoveryWrappedEnrollmentEscrows.length <= 0) {
      return {
        ok: false,
        code: 'recovery_wrapped_escrows_missing',
        message: 'No active Email OTP recovery-wrapped enrollment escrows are available',
      };
    }
    if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
      return {
        ok: false,
        code: 'unsupported',
        message: 'crypto.getRandomValues is unavailable in this runtime',
      };
    }
    const otpConfig = this.resolveEmailOtpConfig();
    const recoveryConsumeGrant = base64UrlEncode(crypto.getRandomValues(new Uint8Array(24)));
    const issuedAtMs = Date.now();
    const recoveryConsumeGrantExpiresAtMs = issuedAtMs + otpConfig.grantTtlMs;
    await this.getEmailOtpGrantStore().put({
      version: 'email_otp_grant_v1',
      grantToken: recoveryConsumeGrant,
      userId: verified.userId,
      walletId: verified.walletId,
      orgId: verified.orgId,
      challengeId: verified.challengeId,
      otpChannel: verified.otpChannel,
      sessionHash: String(request.sessionHash || '').trim(),
      appSessionVersion: String(request.appSessionVersion || '').trim(),
      action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
      issuedAtMs,
      expiresAtMs: recoveryConsumeGrantExpiresAtMs,
    });
    return {
      ok: true,
      challengeId: verified.challengeId,
      otpChannel: verified.otpChannel,
      recoveryConsumeGrant,
      recoveryConsumeGrantExpiresAtMs,
      recoveryWrappedEnrollmentEscrows: scopedRecoveryWrappedEnrollmentEscrows,
      enrollment: {
        walletId: enrollment.enrollment.walletId,
        providerUserId: enrollment.enrollment.providerUserId,
        orgId: enrollment.enrollment.orgId,
        enrollmentId: enrollment.enrollment.enrollmentId,
        enrollmentVersion: enrollment.enrollment.enrollmentVersion,
        enrollmentSealKeyVersion: enrollment.enrollment.enrollmentSealKeyVersion,
        signingRootId: enrollment.enrollment.signingRootId,
        signingRootVersion: enrollment.enrollment.signingRootVersion,
        recoveryWrappedEnrollmentEscrowCount:
          enrollment.enrollment.recoveryWrappedEnrollmentEscrowCount,
      },
    };
  }

  private async validateEmailOtpEnrollmentMaterial(request: {
    recoveryWrappedEnrollmentEscrows?: unknown;
    enrollmentSealKeyVersion?: unknown;
    clientUnlockPublicKeyB64u?: unknown;
    unlockKeyVersion?: unknown;
    thresholdEcdsaClientVerifyingShareB64u?: unknown;
  }): Promise<
    | {
        ok: true;
        recoveryWrappedEnrollmentEscrows: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[];
        enrollmentSealKeyVersion: string;
        clientUnlockPublicKeyB64u: string;
        unlockKeyVersion: string;
        thresholdEcdsaClientVerifyingShareB64u: string;
      }
    | { ok: false; code: string; message: string }
  > {
    const enrollmentSealKeyVersion = toOptionalTrimmedString(request.enrollmentSealKeyVersion);
    const rawRecoveryWrappedEnrollmentEscrows = Array.isArray(
      request.recoveryWrappedEnrollmentEscrows,
    )
      ? request.recoveryWrappedEnrollmentEscrows
      : [];
    const recoveryWrappedEnrollmentEscrows = rawRecoveryWrappedEnrollmentEscrows
      .map((record) => normalizeEmailOtpRecoveryWrappedEnrollmentEscrowRecord(record))
      .filter((record): record is EmailOtpRecoveryWrappedEnrollmentEscrowRecord => Boolean(record));
    const clientUnlockPublicKeyB64u = toOptionalTrimmedString(request.clientUnlockPublicKeyB64u);
    const unlockKeyVersion = toOptionalTrimmedString(request.unlockKeyVersion);
    const thresholdEcdsaClientVerifyingShareB64u = toOptionalTrimmedString(
      request.thresholdEcdsaClientVerifyingShareB64u,
    );
    if (
      rawRecoveryWrappedEnrollmentEscrows.length !== EMAIL_OTP_RECOVERY_KEY_COUNT ||
      recoveryWrappedEnrollmentEscrows.length !== EMAIL_OTP_RECOVERY_KEY_COUNT
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} recovery-wrapped enrollment escrows are required`,
      };
    }
    if (!enrollmentSealKeyVersion) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'enrollmentSealKeyVersion is required',
      };
    }
    const escrowSetValidation = await this.validateEmailOtpRecoveryWrappedEnrollmentEscrowSet(
      recoveryWrappedEnrollmentEscrows,
    );
    if (!escrowSetValidation.ok) return escrowSetValidation;
    if (!clientUnlockPublicKeyB64u) {
      return { ok: false, code: 'invalid_body', message: 'clientUnlockPublicKeyB64u is required' };
    }
    if (!unlockKeyVersion) {
      return { ok: false, code: 'invalid_body', message: 'unlockKeyVersion is required' };
    }
    if (!thresholdEcdsaClientVerifyingShareB64u) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'thresholdEcdsaClientVerifyingShareB64u is required',
      };
    }

    let unlockPublicKeyBytes: Uint8Array;
    try {
      unlockPublicKeyBytes = base64UrlDecode(clientUnlockPublicKeyB64u);
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'clientUnlockPublicKeyB64u must be valid base64url',
      };
    }
    if (unlockPublicKeyBytes.length !== 33) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'clientUnlockPublicKeyB64u must decode to 33 bytes (compressed secp256k1 pubkey)',
      };
    }
    try {
      await validateSecp256k1PublicKey33(unlockPublicKeyBytes);
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'clientUnlockPublicKeyB64u is not a valid secp256k1 public key',
      };
    }

    let clientVerifyingShareBytes: Uint8Array;
    try {
      clientVerifyingShareBytes = base64UrlDecode(thresholdEcdsaClientVerifyingShareB64u);
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'thresholdEcdsaClientVerifyingShareB64u must be valid base64url',
      };
    }
    if (clientVerifyingShareBytes.length !== 33) {
      return {
        ok: false,
        code: 'invalid_body',
        message:
          'thresholdEcdsaClientVerifyingShareB64u must decode to 33 bytes (compressed secp256k1 pubkey)',
      };
    }
    try {
      await validateSecp256k1PublicKey33(clientVerifyingShareBytes);
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'thresholdEcdsaClientVerifyingShareB64u is not a valid secp256k1 public key',
      };
    }

    return {
      ok: true,
      recoveryWrappedEnrollmentEscrows,
      enrollmentSealKeyVersion,
      clientUnlockPublicKeyB64u,
      unlockKeyVersion,
      thresholdEcdsaClientVerifyingShareB64u,
    };
  }

  private async validateEmailOtpRecoveryWrappedEnrollmentEscrowSet(
    records: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[],
  ): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
    const recoveryKeyIds = new Set<string>();
    const nonceB64us = new Set<string>();
    const first = records[0];
    if (!first) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} recovery-wrapped enrollment escrows are required`,
      };
    }

    for (const record of records) {
      if (recoveryKeyIds.has(record.recoveryKeyId)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery-wrapped enrollment escrow recoveryKeyId values must be unique',
        };
      }
      recoveryKeyIds.add(record.recoveryKeyId);

      if (nonceB64us.has(record.nonceB64u)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery-wrapped enrollment escrow nonce values must be unique',
        };
      }
      nonceB64us.add(record.nonceB64u);

      if (
        record.walletId !== first.walletId ||
        record.userId !== first.userId ||
        record.authSubjectId !== first.authSubjectId ||
        record.authMethod !== first.authMethod ||
        record.enrollmentId !== first.enrollmentId ||
        record.enrollmentVersion !== first.enrollmentVersion ||
        record.enrollmentSealKeyVersion !== first.enrollmentSealKeyVersion ||
        record.signingRootId !== first.signingRootId ||
        record.signingRootVersion !== first.signingRootVersion
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery-wrapped enrollment escrow metadata must share one enrollment scope',
        };
      }

      const expectedAadHashB64u = base64UrlEncode(
        await sha256BytesPortable(
          encodeEmailOtpRecoveryWrappedEnrollmentAad({
            walletId: record.walletId,
            userId: record.userId,
            authSubjectId: record.authSubjectId,
            authMethod: record.authMethod,
            enrollmentId: record.enrollmentId,
            enrollmentVersion: record.enrollmentVersion,
            enrollmentSealKeyVersion: record.enrollmentSealKeyVersion,
            signingRootId: record.signingRootId,
            signingRootVersion: record.signingRootVersion,
            recoveryKeyId: record.recoveryKeyId,
          }),
        ),
      );
      if (record.aadHashB64u !== expectedAadHashB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery-wrapped enrollment escrow aadHashB64u does not match metadata',
        };
      }
    }

    if (
      recoveryKeyIds.size !== EMAIL_OTP_RECOVERY_KEY_COUNT ||
      nonceB64us.size !== EMAIL_OTP_RECOVERY_KEY_COUNT
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} distinct recovery-wrapped enrollment escrows are required`,
      };
    }

    return { ok: true };
  }

  private emailOtpRecoveryEscrowMatchesEnrollment(
    record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
    enrollment: EmailOtpWalletEnrollmentRecord,
  ): boolean {
    return (
      record.walletId === enrollment.walletId &&
      record.userId === enrollment.providerUserId &&
      record.authSubjectId === enrollment.providerUserId &&
      record.enrollmentId === enrollment.enrollmentId &&
      record.enrollmentVersion === enrollment.enrollmentVersion &&
      record.enrollmentSealKeyVersion === enrollment.enrollmentSealKeyVersion &&
      record.signingRootId === enrollment.signingRootId &&
      record.signingRootVersion === enrollment.signingRootVersion
    );
  }

  async verifyEmailOtpEnrollment(request: {
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    challengeId?: unknown;
    otpCode?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
    recoveryWrappedEnrollmentEscrows?: unknown;
    enrollmentSealKeyVersion?: unknown;
    clientUnlockPublicKeyB64u?: unknown;
    unlockKeyVersion?: unknown;
    thresholdEcdsaClientVerifyingShareB64u?: unknown;
    googleEmailOtpRegistrationAttemptId?: unknown;
  }): Promise<
    | {
        ok: true;
        walletId: string;
        otpChannel: EmailOtpChannel;
        enrollment: {
          createdAtMs: number;
          updatedAtMs: number;
          enrollmentSealKeyVersion: string;
          unlockKeyVersion: string;
        };
      }
    | {
        ok: false;
        code: string;
        message: string;
        attemptsRemaining?: number;
        lockedUntilMs?: number;
      }
  > {
    const verified = await this.verifyEmailOtpChallengeCode({
      ...request,
      expectedAction: WALLET_EMAIL_OTP_ACTIONS.registration,
    });
    if (!verified.ok) return verified;
    const verifiedEmail = toOptionalTrimmedString(verified.email)?.toLowerCase();
    if (!verifiedEmail) {
      return {
        ok: false,
        code: 'internal',
        message: 'Email OTP enrollment verification did not include a verified email',
      };
    }
    const enrollmentMaterial = await this.validateEmailOtpEnrollmentMaterial(request);
    if (!enrollmentMaterial.ok) return enrollmentMaterial;
    const orgId = toOptionalTrimmedString(verified.orgId) || '';
    if (!orgId) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Email OTP enrollment requires orgId tenant scope',
      };
    }
    const existing = await this.getEmailOtpWalletEnrollmentStore().get(verified.walletId);
    const existingState = await this.getEmailOtpAuthStateStore().get(verified.walletId);
    const nowMs = Date.now();
    const enrollmentScope = enrollmentMaterial.recoveryWrappedEnrollmentEscrows[0];
    if (!enrollmentScope) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} recovery-wrapped enrollment escrows are required`,
      };
    }
    for (const record of enrollmentMaterial.recoveryWrappedEnrollmentEscrows) {
      if (
        record.walletId !== verified.walletId ||
        record.userId !== verified.userId ||
        record.authSubjectId !== verified.userId ||
        record.enrollmentSealKeyVersion !== enrollmentMaterial.enrollmentSealKeyVersion ||
        record.recoveryKeyStatus !== 'active'
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery-wrapped enrollment escrow metadata does not match enrollment',
        };
      }
    }
    const enrollmentRecord: EmailOtpWalletEnrollmentRecord = {
      version: 'email_otp_wallet_enrollment_v1',
      walletId: verified.walletId,
      providerUserId: verified.userId,
      orgId,
      verifiedEmail,
      enrollmentId: enrollmentScope.enrollmentId,
      enrollmentVersion: enrollmentScope.enrollmentVersion,
      enrollmentSealKeyVersion: enrollmentMaterial.enrollmentSealKeyVersion,
      signingRootId: enrollmentScope.signingRootId,
      signingRootVersion: enrollmentScope.signingRootVersion,
      recoveryWrappedEnrollmentEscrowCount:
        enrollmentMaterial.recoveryWrappedEnrollmentEscrows.length,
      clientUnlockPublicKeyB64u: enrollmentMaterial.clientUnlockPublicKeyB64u,
      unlockKeyVersion: enrollmentMaterial.unlockKeyVersion,
      thresholdEcdsaClientVerifyingShareB64u:
        enrollmentMaterial.thresholdEcdsaClientVerifyingShareB64u,
      createdAtMs: existing?.createdAtMs ?? nowMs,
      updatedAtMs: nowMs,
    };
    await this.getEmailOtpWalletEnrollmentStore().put(enrollmentRecord);
    const recoveryWrappedEnrollmentEscrowStore =
      this.getEmailOtpRecoveryWrappedEnrollmentEscrowStore();
    for (const record of enrollmentMaterial.recoveryWrappedEnrollmentEscrows) {
      await recoveryWrappedEnrollmentEscrowStore.put({
        ...record,
        updatedAtMs: nowMs,
      });
    }
    const activeRecoveryWrappedEnrollmentEscrowCount = (
      await recoveryWrappedEnrollmentEscrowStore.listActiveByWallet(verified.walletId)
    ).filter(
      (record) =>
        record.recoveryKeyStatus === 'active' &&
        this.emailOtpRecoveryEscrowMatchesEnrollment(record, enrollmentRecord),
    ).length;
    if (activeRecoveryWrappedEnrollmentEscrowCount !== EMAIL_OTP_RECOVERY_KEY_COUNT) {
      return {
        ok: false,
        code: 'internal',
        message: `Email OTP enrollment persisted ${activeRecoveryWrappedEnrollmentEscrowCount} active recovery-wrapped escrows; expected ${EMAIL_OTP_RECOVERY_KEY_COUNT}`,
      };
    }
    await this.getEmailOtpAuthStateStore().put({
      version: 'email_otp_auth_state_v1',
      walletId: enrollmentRecord.walletId,
      providerUserId: enrollmentRecord.providerUserId,
      orgId: enrollmentRecord.orgId,
      createdAtMs:
        existingState &&
        existingState.providerUserId === enrollmentRecord.providerUserId &&
        existingState.orgId === enrollmentRecord.orgId
          ? existingState.createdAtMs
          : nowMs,
      updatedAtMs: nowMs,
      otpFailureCount: 0,
      lastOtpFailureAtMs: undefined,
      otpLockedUntilMs: undefined,
      ...(existingState?.lastEmailOtpLoginAtMs &&
      existingState.providerUserId === enrollmentRecord.providerUserId &&
      existingState.orgId === enrollmentRecord.orgId
        ? { lastEmailOtpLoginAtMs: existingState.lastEmailOtpLoginAtMs }
        : {}),
      ...(existingState?.lastStrongAuthAtMs &&
      existingState.providerUserId === enrollmentRecord.providerUserId &&
      existingState.orgId === enrollmentRecord.orgId
        ? { lastStrongAuthAtMs: existingState.lastStrongAuthAtMs }
        : {}),
    });
    const completedRegistration = await this.completeGoogleEmailOtpRegistrationAttempt({
      registrationAttemptId: request.googleEmailOtpRegistrationAttemptId,
      walletId: verified.walletId,
    });
    if (!completedRegistration.ok) return completedRegistration;
    return {
      ok: true,
      walletId: verified.walletId,
      otpChannel: verified.otpChannel,
      enrollment: {
        createdAtMs: existing?.createdAtMs ?? nowMs,
        updatedAtMs: nowMs,
        enrollmentSealKeyVersion: enrollmentMaterial.enrollmentSealKeyVersion,
        unlockKeyVersion: enrollmentMaterial.unlockKeyVersion,
      },
    };
  }

  async readEmailOtpEnrollment(request: { walletId?: unknown; orgId: unknown }): Promise<
    | {
        ok: true;
        enrollment: EmailOtpWalletEnrollmentRecord;
      }
    | { ok: false; code: string; message: string }
  > {
    const walletId = toOptionalTrimmedString(request.walletId);
    const orgId = toOptionalTrimmedString(request.orgId);
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
    const enrollment = await this.getEmailOtpWalletEnrollmentStore().get(walletId);
    if (!enrollment) {
      return { ok: false, code: 'not_found', message: 'Email OTP enrollment not found' };
    }
    if (enrollment.orgId !== orgId) {
      return {
        ok: false,
        code: 'tenant_scope_mismatch',
        message: 'Email OTP enrollment does not match the requested orgId',
      };
    }
    return { ok: true, enrollment };
  }

  async readActiveEmailOtpEnrollment(request: {
    walletId?: unknown;
    orgId: unknown;
    providerUserId?: unknown;
  }): Promise<
    | {
        ok: true;
        enrollment: EmailOtpWalletEnrollmentRecord;
      }
    | { ok: false; code: string; message: string }
  > {
    const walletId = toOptionalTrimmedString(request.walletId);
    const orgId = toOptionalTrimmedString(request.orgId);
    const providerUserId = toOptionalTrimmedString(request.providerUserId) || undefined;
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
    const enrollment = await this.getEmailOtpWalletEnrollmentStore().get(walletId);
    if (!enrollment) {
      return { ok: false, code: 'not_found', message: 'Email OTP enrollment not found' };
    }
    if (enrollment.orgId !== orgId) {
      return {
        ok: false,
        code: 'tenant_scope_mismatch',
        message: 'Email OTP enrollment does not match the requested orgId',
      };
    }
    if (providerUserId && enrollment.providerUserId !== providerUserId) {
      return {
        ok: false,
        code: 'provider_identity_mismatch',
        message: 'Email OTP enrollment does not match the requested provider user',
      };
    }
    return { ok: true, enrollment };
  }

  async isEmailOtpStrongAuthRequired(request: { walletId?: unknown }): Promise<
    | {
        ok: true;
        required: boolean;
        walletId: string;
        lastEmailOtpLoginAtMs?: number;
        lastStrongAuthAtMs?: number;
      }
    | { ok: false; code: string; message: string }
  > {
    const walletId = toOptionalTrimmedString(request.walletId);
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    const enrollment = await this.getEmailOtpWalletEnrollmentStore().get(walletId);
    if (!enrollment) {
      return { ok: true, required: false, walletId };
    }
    const authState = await this.readEmailOtpAuthStateForEnrollment(enrollment);
    if (!authState.ok) return authState;
    const state = authState.state;
    if (!state) {
      return { ok: true, required: false, walletId };
    }
    const lastEmailOtpLoginAtMs =
      typeof state.lastEmailOtpLoginAtMs === 'number' ? state.lastEmailOtpLoginAtMs : undefined;
    const lastStrongAuthAtMs =
      typeof state.lastStrongAuthAtMs === 'number' ? state.lastStrongAuthAtMs : undefined;
    return {
      ok: true,
      required: Boolean(
        lastEmailOtpLoginAtMs &&
        (!lastStrongAuthAtMs || lastEmailOtpLoginAtMs > lastStrongAuthAtMs),
      ),
      walletId,
      ...(lastEmailOtpLoginAtMs ? { lastEmailOtpLoginAtMs } : {}),
      ...(lastStrongAuthAtMs ? { lastStrongAuthAtMs } : {}),
    };
  }

  async markEmailOtpStrongAuthSatisfied(request: {
    walletId?: unknown;
  }): Promise<
    | { ok: true; walletId: string; lastStrongAuthAtMs?: number }
    | { ok: false; code: string; message: string }
  > {
    const walletId = toOptionalTrimmedString(request.walletId);
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    const enrollment = await this.getEmailOtpWalletEnrollmentStore().get(walletId);
    if (!enrollment) return { ok: true, walletId };
    const nowMs = Date.now();
    await this.putEmailOtpAuthStateForEnrollment(enrollment, {
      lastStrongAuthAtMs: nowMs,
    });
    return { ok: true, walletId, lastStrongAuthAtMs: nowMs };
  }

  async consumeEmailOtpGrant(request: {
    loginGrant?: unknown;
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
  }): Promise<
    | {
        ok: true;
        challengeId: string;
        otpChannel: EmailOtpChannel;
      }
    | { ok: false; code: string; message: string }
  > {
    try {
      const loginGrant = toOptionalTrimmedString(request.loginGrant);
      const userId = toOptionalTrimmedString(request.userId);
      const walletId = toOptionalTrimmedString(request.walletId);
      const orgId = toOptionalTrimmedString(request.orgId) || '';
      const otpChannel = toOptionalTrimmedString(request.otpChannel);
      const sessionHash = toOptionalTrimmedString(request.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(request.appSessionVersion);
      const clientIp = toOptionalTrimmedString(request.clientIp) || undefined;
      if (!loginGrant) {
        return { ok: false, code: 'invalid_body', message: 'Missing loginGrant' };
      }
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (otpChannel !== EMAIL_OTP_CHANNEL) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'otpChannel must be email_otp',
        };
      }
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }
      const rateLimit = await this.consumeEmailOtpRateLimit({
        scope: 'grant',
        userId,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const record = await this.getEmailOtpGrantStore().consume(loginGrant);
      if (!record) {
        return {
          ok: false,
          code: 'login_grant_invalid_or_expired',
          message: 'Login grant is invalid or expired',
        };
      }

      if (Date.now() > record.expiresAtMs) {
        return {
          ok: false,
          code: 'login_grant_invalid_or_expired',
          message: 'Login grant is invalid or expired',
        };
      }
      if (record.action !== WALLET_EMAIL_OTP_ACTIONS.unseal) {
        return {
          ok: false,
          code: 'login_grant_invalid_or_expired',
          message: 'Login grant is invalid or expired',
        };
      }

      const bindingMismatch =
        record.userId !== userId ||
        record.walletId !== walletId ||
        record.otpChannel !== EMAIL_OTP_CHANNEL ||
        record.sessionHash !== sessionHash ||
        record.appSessionVersion !== appSessionVersion ||
        record.orgId !== orgId;
      if (bindingMismatch) {
        return {
          ok: false,
          code: 'recovery_grant_binding_mismatch',
          message: 'Recovery grant is not valid for the current app session',
        };
      }

      return {
        ok: true,
        challengeId: record.challengeId,
        otpChannel: EMAIL_OTP_CHANNEL,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to consume Email OTP grant',
      };
    }
  }

  async consumeEmailOtpRecoveryKey(request: {
    recoveryConsumeGrant?: unknown;
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    recoveryKeyId?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
  }): Promise<
    | {
        ok: true;
        walletId: string;
        recoveryKeyId: string;
        consumedAtMs: number;
        activeRecoveryWrappedEnrollmentEscrowCount: number;
      }
    | { ok: false; code: string; message: string }
  > {
    try {
      const recoveryConsumeGrant = toOptionalTrimmedString(request.recoveryConsumeGrant);
      const userId = toOptionalTrimmedString(request.userId);
      const walletId = toOptionalTrimmedString(request.walletId);
      const orgId = toOptionalTrimmedString(request.orgId) || '';
      const recoveryKeyId = toOptionalTrimmedString(request.recoveryKeyId);
      const sessionHash = toOptionalTrimmedString(request.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(request.appSessionVersion);
      const clientIp = toOptionalTrimmedString(request.clientIp) || undefined;
      if (!recoveryConsumeGrant) {
        return { ok: false, code: 'invalid_body', message: 'Missing recoveryConsumeGrant' };
      }
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (!recoveryKeyId) {
        return { ok: false, code: 'invalid_body', message: 'Missing recoveryKeyId' };
      }
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }
      const rateLimit = await this.consumeEmailOtpRateLimit({
        scope: 'grant',
        userId,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const record = await this.getEmailOtpGrantStore().consume(recoveryConsumeGrant);
      if (!record || Date.now() > record.expiresAtMs) {
        return {
          ok: false,
          code: 'recovery_consume_grant_invalid_or_expired',
          message: 'Recovery consume grant is invalid or expired',
        };
      }
      if (record.action !== WALLET_EMAIL_OTP_ACTIONS.deviceRecovery) {
        return {
          ok: false,
          code: 'recovery_consume_grant_invalid_or_expired',
          message: 'Recovery consume grant is invalid or expired',
        };
      }

      const bindingMismatch =
        record.userId !== userId ||
        record.walletId !== walletId ||
        record.otpChannel !== EMAIL_OTP_CHANNEL ||
        record.sessionHash !== sessionHash ||
        record.appSessionVersion !== appSessionVersion ||
        record.orgId !== orgId;
      if (bindingMismatch) {
        return {
          ok: false,
          code: 'recovery_grant_binding_mismatch',
          message: 'Recovery grant is not valid for the current app session',
        };
      }

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId,
        orgId,
        providerUserId: userId,
      });
      if (!enrollment.ok) return enrollment;

      const recoveryWrappedEnrollmentEscrowStore =
        this.getEmailOtpRecoveryWrappedEnrollmentEscrowStore();
      const recoveryRecord = await recoveryWrappedEnrollmentEscrowStore.get({
        walletId,
        recoveryKeyId,
      });
      if (!recoveryRecord || recoveryRecord.recoveryKeyStatus !== 'active') {
        return {
          ok: false,
          code: 'recovery_key_not_active',
          message: 'Recovery key is not active',
        };
      }
      if (!this.emailOtpRecoveryEscrowMatchesEnrollment(recoveryRecord, enrollment.enrollment)) {
        return {
          ok: false,
          code: 'recovery_key_binding_mismatch',
          message: 'Recovery key is not valid for this Email OTP enrollment',
        };
      }

      const consumedAtMs = Date.now();
      await recoveryWrappedEnrollmentEscrowStore.put({
        ...recoveryRecord,
        recoveryKeyStatus: 'consumed',
        consumedAtMs,
        updatedAtMs: consumedAtMs,
      });
      const activeRecoveryWrappedEnrollmentEscrowCount = (
        await recoveryWrappedEnrollmentEscrowStore.listActiveByWallet(walletId)
      ).filter((activeRecord) =>
        this.emailOtpRecoveryEscrowMatchesEnrollment(activeRecord, enrollment.enrollment),
      ).length;

      return {
        ok: true,
        walletId,
        recoveryKeyId,
        consumedAtMs,
        activeRecoveryWrappedEnrollmentEscrowCount,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to consume Email OTP recovery key',
      };
    }
  }

  async recordEmailOtpRecoveryKeyAttemptFailure(request: {
    recoveryConsumeGrant?: unknown;
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
  }): Promise<
    | {
        ok: true;
        walletId: string;
        recordedAtMs: number;
      }
    | { ok: false; code: string; message: string; retryAfterMs?: number; resetAtMs?: number }
  > {
    try {
      const recoveryConsumeGrant = toOptionalTrimmedString(request.recoveryConsumeGrant);
      const userId = toOptionalTrimmedString(request.userId);
      const walletId = toOptionalTrimmedString(request.walletId);
      const orgId = toOptionalTrimmedString(request.orgId) || '';
      const sessionHash = toOptionalTrimmedString(request.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(request.appSessionVersion);
      const clientIp = toOptionalTrimmedString(request.clientIp) || undefined;
      if (!recoveryConsumeGrant) {
        return { ok: false, code: 'invalid_body', message: 'Missing recoveryConsumeGrant' };
      }
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }

      const record = await this.getEmailOtpGrantStore().get(recoveryConsumeGrant);
      if (!record || Date.now() > record.expiresAtMs) {
        if (record && Date.now() > record.expiresAtMs) {
          await this.getEmailOtpGrantStore().del(recoveryConsumeGrant);
        }
        return {
          ok: false,
          code: 'recovery_consume_grant_invalid_or_expired',
          message: 'Recovery consume grant is invalid or expired',
        };
      }
      if (record.action !== WALLET_EMAIL_OTP_ACTIONS.deviceRecovery) {
        return {
          ok: false,
          code: 'recovery_consume_grant_invalid_or_expired',
          message: 'Recovery consume grant is invalid or expired',
        };
      }

      const bindingMismatch =
        record.userId !== userId ||
        record.walletId !== walletId ||
        record.otpChannel !== EMAIL_OTP_CHANNEL ||
        record.sessionHash !== sessionHash ||
        record.appSessionVersion !== appSessionVersion ||
        record.orgId !== orgId;
      if (bindingMismatch) {
        return {
          ok: false,
          code: 'recovery_grant_binding_mismatch',
          message: 'Recovery grant is not valid for the current app session',
        };
      }

      const rateLimit = await this.consumeEmailOtpRateLimit({
        scope: 'recoveryKeyAttempt',
        action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
        userId,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId,
        orgId,
        providerUserId: userId,
      });
      if (!enrollment.ok) return enrollment;

      const activeRecoveryWrappedEnrollmentEscrowCount = (
        await this.getEmailOtpRecoveryWrappedEnrollmentEscrowStore().listActiveByWallet(walletId)
      ).filter((activeRecord) =>
        this.emailOtpRecoveryEscrowMatchesEnrollment(activeRecord, enrollment.enrollment),
      ).length;
      if (activeRecoveryWrappedEnrollmentEscrowCount <= 0) {
        return {
          ok: false,
          code: 'recovery_wrapped_escrows_missing',
          message: 'No active Email OTP recovery-wrapped enrollment escrows are available',
        };
      }

      return {
        ok: true,
        walletId,
        recordedAtMs: Date.now(),
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to record Email OTP recovery-key failure',
      };
    }
  }

  async readEmailOtpOutboxEntry(request: {
    challengeId?: unknown;
    userId?: unknown;
    walletId?: unknown;
  }): Promise<
    | {
        ok: true;
        challengeId: string;
        walletId: string;
        userId: string;
        otpChannel: EmailOtpChannel;
        emailHint: string;
        otpCode: string;
        expiresAtMs: number;
      }
    | { ok: false; code: string; message: string }
  > {
    const config = this.resolveEmailOtpConfig();
    if (!config.devOutboxEnabled) {
      return {
        ok: false,
        code: 'not_found',
        message: 'Email OTP dev outbox is not enabled',
      };
    }

    const challengeId = toOptionalTrimmedString(request.challengeId);
    const userId = toOptionalTrimmedString(request.userId);
    const walletId = toOptionalTrimmedString(request.walletId);
    if (!challengeId) return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };
    if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };

    const entry = this.emailOtpMemoryOutbox.get(challengeId);
    if (!entry) {
      return { ok: false, code: 'not_found', message: 'Email OTP outbox entry was not found' };
    }
    if (entry.userId !== userId || entry.walletId !== walletId) {
      return {
        ok: false,
        code: 'not_found',
        message: 'Email OTP outbox entry was not found',
      };
    }
    if (Date.now() > entry.expiresAtMs) {
      this.emailOtpMemoryOutbox.delete(challengeId);
      return { ok: false, code: 'not_found', message: 'Email OTP outbox entry expired' };
    }
    return {
      ok: true,
      challengeId,
      walletId,
      userId,
      otpChannel: entry.otpChannel,
      emailHint: entry.emailHint,
      otpCode: entry.otpCode,
      expiresAtMs: entry.expiresAtMs,
    };
  }

  async removeEmailOtpServerSeal(request: {
    wrappedCiphertext?: unknown;
  }): Promise<
    | { ok: true; ciphertext: string; enrollmentSealKeyVersion: string }
    | { ok: false; code: string; message: string }
  > {
    try {
      const wrappedCiphertext = toOptionalTrimmedString(request.wrappedCiphertext);
      if (!wrappedCiphertext) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Missing wrappedCiphertext',
        };
      }
      const shamir = this.createEmailOtpShamirCipher();
      if (!shamir.ok) return shamir;
      const removed = await shamir.cipher.run({
        operation: 'remove-server-seal',
        thresholdSessionId: 'email-otp-unseal',
        ciphertext: wrappedCiphertext,
        keyVersion: shamir.keyVersion,
        auth: { userId: 'email_otp', claims: {} },
      });
      if (!removed.ok) return removed;
      return {
        ok: true,
        ciphertext: removed.ciphertext,
        enrollmentSealKeyVersion: removed.keyVersion || shamir.keyVersion,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to remove Email OTP server seal',
      };
    }
  }

  async applyEmailOtpServerSeal(request: {
    wrappedCiphertext?: unknown;
  }): Promise<
    | { ok: true; ciphertext: string; enrollmentSealKeyVersion: string }
    | { ok: false; code: string; message: string }
  > {
    try {
      const wrappedCiphertext = toOptionalTrimmedString(request.wrappedCiphertext);
      if (!wrappedCiphertext) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Missing wrappedCiphertext',
        };
      }
      const shamir = this.createEmailOtpShamirCipher();
      if (!shamir.ok) return shamir;
      const applied = await shamir.cipher.run({
        operation: 'apply-server-seal',
        thresholdSessionId: 'email-otp-enroll',
        ciphertext: wrappedCiphertext,
        keyVersion: shamir.keyVersion,
        auth: { userId: 'email_otp', claims: {} },
      });
      if (!applied.ok) return applied;
      return {
        ok: true,
        ciphertext: applied.ciphertext,
        enrollmentSealKeyVersion: applied.keyVersion || shamir.keyVersion,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to apply Email OTP server seal',
      };
    }
  }

  private async getGoogleJwks(): Promise<{
    keysByKid: Map<string, JsonWebKey>;
    expiresAtMs: number;
  }> {
    const now = Date.now();
    if (this.googleJwksCache && now < this.googleJwksCache.expiresAtMs) {
      return this.googleJwksCache;
    }
    if (this.googleJwksFetchPromise) return this.googleJwksFetchPromise;

    this.googleJwksFetchPromise = (async () => {
      const resp = await fetch('https://www.googleapis.com/oauth2/v3/certs');
      const text = await resp.text();
      if (!resp.ok) {
        throw new Error(
          `Google OIDC certs fetch failed (HTTP ${resp.status}): ${text.slice(0, 200)}`,
        );
      }
      let json: unknown;
      try {
        json = text ? JSON.parse(text) : null;
      } catch {
        throw new Error('Google OIDC certs returned non-JSON response');
      }
      if (!isObject(json)) {
        throw new Error('Google OIDC certs returned invalid JSON shape');
      }
      const keysRaw = (json as { keys?: unknown }).keys;
      if (!Array.isArray(keysRaw)) {
        throw new Error('Google OIDC certs missing "keys" array');
      }
      const keysByKid = new Map<string, JsonWebKey>();
      for (const rawKey of keysRaw) {
        if (!isObject(rawKey)) continue;
        const kid = toOptionalTrimmedString((rawKey as { kid?: unknown }).kid);
        const kty = toOptionalTrimmedString((rawKey as { kty?: unknown }).kty);
        const use = toOptionalTrimmedString((rawKey as { use?: unknown }).use);
        const alg = toOptionalTrimmedString((rawKey as { alg?: unknown }).alg);
        const n = toOptionalTrimmedString((rawKey as { n?: unknown }).n);
        const e = toOptionalTrimmedString((rawKey as { e?: unknown }).e);
        if (!kid || kty !== 'RSA' || use !== 'sig' || alg !== 'RS256' || !n || !e) continue;
        keysByKid.set(kid, rawKey as unknown as JsonWebKey);
      }
      if (!keysByKid.size) {
        throw new Error('Google OIDC certs returned no usable RSA keys');
      }

      const maxAgeSec = parseCacheControlMaxAgeSec(resp.headers.get('cache-control')) || 60 * 60;
      const expiresAtMs = now + maxAgeSec * 1000;
      const value = { keysByKid, expiresAtMs };
      this.googleJwksCache = value;
      return value;
    })();

    try {
      return await this.googleJwksFetchPromise;
    } finally {
      this.googleJwksFetchPromise = null;
    }
  }

  private async getOidcJwksByUrl(jwksUrl: string): Promise<{
    keysByKid: Map<string, JsonWebKey>;
    expiresAtMs: number;
  }> {
    const url = String(jwksUrl || '').trim();
    if (!url) throw new Error('Missing OIDC JWKS URL');

    const now = Date.now();
    const cached = this.oidcJwksCacheByUrl.get(url) || null;
    if (cached && now < cached.expiresAtMs) return cached;

    const inflight = this.oidcJwksFetchPromiseByUrl.get(url) || null;
    if (inflight) return inflight;

    const fetchPromise = (async () => {
      const resp = await fetch(url);
      const text = await resp.text();
      if (!resp.ok) {
        throw new Error(`OIDC JWKS fetch failed (HTTP ${resp.status}): ${text.slice(0, 200)}`);
      }
      let json: unknown;
      try {
        json = text ? JSON.parse(text) : null;
      } catch {
        throw new Error('OIDC JWKS returned non-JSON response');
      }
      if (!isObject(json)) {
        throw new Error('OIDC JWKS returned invalid JSON shape');
      }
      const keysRaw = (json as { keys?: unknown }).keys;
      if (!Array.isArray(keysRaw)) {
        throw new Error('OIDC JWKS missing "keys" array');
      }
      const keysByKid = new Map<string, JsonWebKey>();
      for (const rawKey of keysRaw) {
        if (!isObject(rawKey)) continue;
        const kid = toOptionalTrimmedString((rawKey as { kid?: unknown }).kid);
        const kty = toOptionalTrimmedString((rawKey as { kty?: unknown }).kty);
        const use = toOptionalTrimmedString((rawKey as { use?: unknown }).use);
        const alg = toOptionalTrimmedString((rawKey as { alg?: unknown }).alg);
        const n = toOptionalTrimmedString((rawKey as { n?: unknown }).n);
        const e = toOptionalTrimmedString((rawKey as { e?: unknown }).e);
        if (!kid || kty !== 'RSA' || !n || !e) continue;
        if (use && use !== 'sig') continue;
        if (alg && alg !== 'RS256') continue;
        keysByKid.set(kid, rawKey as unknown as JsonWebKey);
      }
      if (!keysByKid.size) {
        throw new Error('OIDC JWKS returned no usable RSA keys');
      }

      const maxAgeSec = parseCacheControlMaxAgeSec(resp.headers.get('cache-control')) || 60 * 60;
      const expiresAtMs = now + maxAgeSec * 1000;
      const value = { keysByKid, expiresAtMs };
      this.oidcJwksCacheByUrl.set(url, value);
      return value;
    })();

    this.oidcJwksFetchPromiseByUrl.set(url, fetchPromise);
    try {
      return await fetchPromise;
    } finally {
      this.oidcJwksFetchPromiseByUrl.delete(url);
    }
  }

  async verifyOidcJwtExchange(request: { token?: unknown }): Promise<{
    ok: boolean;
    verified?: boolean;
    userId?: string;
    providerSubject?: string;
    iss?: string;
    aud?: string[];
    sub?: string;
    email?: string;
    name?: string;
    given_name?: string;
    family_name?: string;
    code?: string;
    message?: string;
  }> {
    try {
      const cfg = this.config.oidcExchange;
      const issuers = Array.isArray(cfg?.issuers) ? cfg.issuers : [];
      if (!issuers.length) {
        return {
          ok: false,
          verified: false,
          code: 'not_configured',
          message: 'OIDC exchange is not configured on this server',
        };
      }

      const token = toOptionalTrimmedString(request?.token);
      if (!token) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'exchange.token is required',
        };
      }
      if (typeof crypto === 'undefined' || !crypto.subtle) {
        return {
          ok: false,
          verified: false,
          code: 'unsupported',
          message: 'WebCrypto (crypto.subtle) is unavailable in this runtime',
        };
      }

      const parts = token.split('.');
      if (parts.length !== 3) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'exchange.token must be a JWT (3 segments)',
        };
      }
      const [headerB64u, payloadB64u, signatureB64u] = parts;
      const header = parseJwtSegmentJson(headerB64u);
      if (!header) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'Invalid exchange.token header encoding',
        };
      }
      const payload = parseJwtSegmentJson(payloadB64u);
      if (!payload) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'Invalid exchange.token payload encoding',
        };
      }

      const kid = toOptionalTrimmedString(header.kid);
      const alg = toOptionalTrimmedString(header.alg);
      if (!kid) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'exchange.token header.kid is required',
        };
      }
      if (alg !== 'RS256') {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'exchange.token header.alg must be RS256',
        };
      }

      const iss = normalizeOidcIssuer(toOptionalTrimmedString(payload.iss) || '');
      if (!iss) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_claims',
          message: 'Missing exchange.token iss',
        };
      }
      const issuerConfig = issuers.find((candidate: OidcExchangeIssuerConfig) => {
        return normalizeOidcIssuer(candidate.issuer) === iss;
      });
      if (!issuerConfig) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_issuer',
          message: 'exchange.token issuer is not allowed',
        };
      }

      const aud = parseJwtAud(payload.aud);
      if (!aud.length) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_claims',
          message: 'Missing exchange.token aud',
        };
      }
      const allowedAud = new Set(issuerConfig.audiences || []);
      const audOk = aud.some((value) => allowedAud.has(value));
      if (!audOk) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_audience',
          message: 'exchange.token audience mismatch',
        };
      }

      const sub = toOptionalTrimmedString(payload.sub);
      if (!sub) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_claims',
          message: 'Missing exchange.token sub',
        };
      }

      const jwks = await this.getOidcJwksByUrl(issuerConfig.jwksUrl);
      const jwk = jwks.keysByKid.get(kid);
      if (!jwk) {
        return {
          ok: false,
          verified: false,
          code: 'unknown_kid',
          message: 'Unknown OIDC key id (kid)',
        };
      }

      let signatureBytes: Uint8Array;
      try {
        signatureBytes = base64UrlDecode(signatureB64u);
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'Invalid exchange.token signature encoding',
        };
      }

      const dataBytes = new TextEncoder().encode(`${headerB64u}.${payloadB64u}`);
      const key = await crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify'],
      );
      const verified = await crypto.subtle.verify(
        { name: 'RSASSA-PKCS1-v1_5' },
        key,
        signatureBytes,
        dataBytes,
      );
      if (!verified) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_signature',
          message: 'Invalid exchange.token signature',
        };
      }

      const clockSkewInput = Number(cfg?.clockSkewSec);
      const clockSkewSec = Number.isFinite(clockSkewInput)
        ? Math.max(0, Math.floor(clockSkewInput))
        : 60;
      const nowSec = Math.floor(Date.now() / 1000);
      const exp = Number(payload.exp);
      if (!Number.isFinite(exp) || exp <= 0) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_claims',
          message: 'Invalid exchange.token exp',
        };
      }
      if (nowSec > exp + clockSkewSec) {
        return {
          ok: false,
          verified: false,
          code: 'expired',
          message: 'exchange.token is expired',
        };
      }
      const nbfRaw = payload.nbf;
      if (nbfRaw !== undefined) {
        const nbf = Number(nbfRaw);
        if (!Number.isFinite(nbf)) {
          return {
            ok: false,
            verified: false,
            code: 'invalid_claims',
            message: 'Invalid exchange.token nbf',
          };
        }
        if (nowSec + clockSkewSec < nbf) {
          return {
            ok: false,
            verified: false,
            code: 'not_yet_valid',
            message: 'exchange.token is not yet valid',
          };
        }
      }
      const iatRaw = payload.iat;
      if (iatRaw !== undefined) {
        const iat = Number(iatRaw);
        if (!Number.isFinite(iat)) {
          return {
            ok: false,
            verified: false,
            code: 'invalid_claims',
            message: 'Invalid exchange.token iat',
          };
        }
        if (iat > nowSec + clockSkewSec) {
          return {
            ok: false,
            verified: false,
            code: 'not_yet_valid',
            message: 'exchange.token issued-at is in the future',
          };
        }
      }

      const subjectPrefix = toOptionalTrimmedString(issuerConfig.subjectPrefix) || `oidc:${iss}:`;
      const providerSubject = `${subjectPrefix}${sub}`;
      const email = toOptionalTrimmedString(payload?.email);
      const name = toOptionalTrimmedString(payload?.name);
      const givenName = toOptionalTrimmedString(payload?.given_name);
      const familyName = toOptionalTrimmedString(payload?.family_name);

      let userId = providerSubject;
      try {
        const identity = this.getIdentityStore();
        const linked = await identity.getUserIdBySubject(providerSubject);
        if (linked) userId = linked;
        await identity.linkSubjectToUserId({
          userId,
          subject: providerSubject,
          allowMoveIfSoleIdentity: false,
        });
      } catch {}

      return {
        ok: true,
        verified: true,
        userId,
        providerSubject,
        iss,
        aud,
        sub,
        ...(email ? { email } : {}),
        ...(name ? { name } : {}),
        ...(givenName ? { given_name: givenName } : {}),
        ...(familyName ? { family_name: familyName } : {}),
      };
    } catch (e: unknown) {
      return {
        ok: false,
        verified: false,
        code: 'internal',
        message: errorMessage(e) || 'OIDC exchange verification failed',
      };
    }
  }

  async verifyGoogleLogin(request: { idToken?: unknown; id_token?: unknown }): Promise<{
    ok: boolean;
    verified?: boolean;
    userId?: string;
    providerSubject?: string;
    sub?: string;
    email?: string;
    name?: string;
    given_name?: string;
    family_name?: string;
    emailVerified?: boolean;
    hostedDomain?: string;
    code?: string;
    message?: string;
  }> {
    try {
      const googleCfg = this.config.googleOidc;
      if (!googleCfg?.clientIds?.length) {
        return {
          ok: false,
          verified: false,
          code: 'not_configured',
          message: 'Google OIDC is not configured on this server',
        };
      }

      const idToken = toOptionalTrimmedString(request.idToken ?? request.id_token);
      if (!idToken)
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'id_token is required',
        };

      if (typeof crypto === 'undefined' || !crypto.subtle) {
        return {
          ok: false,
          verified: false,
          code: 'unsupported',
          message: 'WebCrypto (crypto.subtle) is unavailable in this runtime',
        };
      }

      const parts = idToken.split('.');
      if (parts.length !== 3) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'id_token must be a JWT (3 segments)',
        };
      }
      const [headerB64u, payloadB64u, signatureB64u] = parts;

      let header: any;
      let payload: any;
      try {
        header = JSON.parse(new TextDecoder().decode(base64UrlDecode(headerB64u)));
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'Invalid id_token header encoding',
        };
      }
      try {
        payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64u)));
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'Invalid id_token payload encoding',
        };
      }

      const kid = toOptionalTrimmedString(header?.kid);
      const alg = toOptionalTrimmedString(header?.alg);
      if (!kid)
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'id_token header.kid is required',
        };
      if (alg !== 'RS256')
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'id_token header.alg must be RS256',
        };

      const jwks = await this.getGoogleJwks();
      const jwk = jwks.keysByKid.get(kid);
      if (!jwk) {
        return {
          ok: false,
          verified: false,
          code: 'unknown_kid',
          message: 'Unknown Google key id (kid)',
        };
      }

      let signatureBytes: Uint8Array;
      try {
        signatureBytes = base64UrlDecode(signatureB64u);
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'Invalid id_token signature encoding',
        };
      }

      const dataBytes = new TextEncoder().encode(`${headerB64u}.${payloadB64u}`);
      const key = await crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify'],
      );
      const verified = await crypto.subtle.verify(
        { name: 'RSASSA-PKCS1-v1_5' },
        key,
        signatureBytes,
        dataBytes,
      );
      if (!verified) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_signature',
          message: 'Invalid Google id_token signature',
        };
      }

      const iss = toOptionalTrimmedString(payload?.iss);
      if (iss !== 'https://accounts.google.com' && iss !== 'accounts.google.com') {
        return {
          ok: false,
          verified: false,
          code: 'invalid_issuer',
          message: 'Invalid Google id_token issuer',
        };
      }

      const nowSec = Math.floor(Date.now() / 1000);
      const expRaw = payload?.exp;
      const exp = typeof expRaw === 'number' ? expRaw : Number(expRaw);
      if (!Number.isFinite(exp) || exp <= 0) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_claims',
          message: 'Invalid Google id_token exp',
        };
      }
      if (nowSec >= exp) {
        return {
          ok: false,
          verified: false,
          code: 'expired',
          message: 'Google id_token is expired',
        };
      }
      const nbfRaw = payload?.nbf;
      if (nbfRaw !== undefined) {
        const nbf = typeof nbfRaw === 'number' ? nbfRaw : Number(nbfRaw);
        if (!Number.isFinite(nbf)) {
          return {
            ok: false,
            verified: false,
            code: 'invalid_claims',
            message: 'Invalid Google id_token nbf',
          };
        }
        if (nowSec < nbf) {
          return {
            ok: false,
            verified: false,
            code: 'not_yet_valid',
            message: 'Google id_token is not yet valid',
          };
        }
      }

      const audRaw = payload?.aud;
      const aud = Array.isArray(audRaw)
        ? audRaw.map((v) => (typeof v === 'string' ? v.trim() : '')).filter(Boolean)
        : [toOptionalTrimmedString(audRaw) || ''].filter(Boolean);
      if (!aud.length) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_claims',
          message: 'Missing Google id_token aud',
        };
      }
      const allowedAudSet = new Set(googleCfg.clientIds);
      const audOk = aud.some((a) => allowedAudSet.has(a));
      if (!audOk) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_audience',
          message: 'Google id_token audience mismatch',
        };
      }

      const sub = toOptionalTrimmedString(payload?.sub);
      if (!sub)
        return {
          ok: false,
          verified: false,
          code: 'invalid_claims',
          message: 'Missing Google id_token sub',
        };

      const hostedDomain = toOptionalTrimmedString(payload?.hd);
      if (googleCfg.hostedDomains?.length) {
        const allowHd = new Set((googleCfg.hostedDomains || []).map((d) => d.toLowerCase()));
        if (!hostedDomain || !allowHd.has(hostedDomain.toLowerCase())) {
          return {
            ok: false,
            verified: false,
            code: 'invalid_hosted_domain',
            message: 'Google hosted domain is not allowed',
          };
        }
      }

      const email = toOptionalTrimmedString(payload?.email);
      const name = toOptionalTrimmedString(payload?.name);
      const givenName = toOptionalTrimmedString(payload?.given_name);
      const familyName = toOptionalTrimmedString(payload?.family_name);
      const emailVerifiedRaw = payload?.email_verified;
      const emailVerified =
        typeof emailVerifiedRaw === 'boolean'
          ? emailVerifiedRaw
          : typeof emailVerifiedRaw === 'string'
            ? emailVerifiedRaw.trim().toLowerCase() === 'true'
            : undefined;

      const providerSubject = `google:${sub}`;
      let userId = providerSubject;
      try {
        const identity = this.getIdentityStore();
        const linked = await identity.getUserIdBySubject(providerSubject);
        if (linked) userId = linked;
        await identity.linkSubjectToUserId({
          userId,
          subject: providerSubject,
          allowMoveIfSoleIdentity: false,
        });
      } catch {}

      return {
        ok: true,
        verified: true,
        userId,
        providerSubject,
        sub,
        ...(email ? { email } : {}),
        ...(name ? { name } : {}),
        ...(givenName ? { given_name: givenName } : {}),
        ...(familyName ? { family_name: familyName } : {}),
        ...(typeof emailVerified === 'boolean' ? { emailVerified } : {}),
        ...(hostedDomain ? { hostedDomain } : {}),
      };
    } catch (e: unknown) {
      return {
        ok: false,
        verified: false,
        code: 'internal',
        message: errorMessage(e) || 'Google OIDC verification failed',
      };
    }
  }

  async createWebAuthnSyncAccountOptions(request: {
    rp_id?: unknown;
    account_id?: unknown;
    ttl_ms?: unknown;
    ttlMs?: unknown;
  }): Promise<{
    ok: boolean;
    challengeId?: string;
    challengeB64u?: string;
    credentialIds?: string[];
    expiresAtMs?: number;
    code?: string;
    message?: string;
  }> {
    try {
      const rpId = String(request?.rp_id || '').trim();
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'Missing rp_id' };
      const expectedUserId = toOptionalTrimmedString(request?.account_id);
      if (expectedUserId && !isValidAccountId(expectedUserId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid account_id' };
      }

      const ttlMsRaw = request?.ttlMs ?? request?.ttl_ms;
      const ttlMs = (() => {
        const n = typeof ttlMsRaw === 'number' ? ttlMsRaw : Number(ttlMsRaw);
        if (!Number.isFinite(n) || n <= 0) return 5 * 60_000;
        return Math.floor(n);
      })();
      const ttlMsClamped = Math.min(Math.max(ttlMs, 10_000), 10 * 60_000);

      if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
        return {
          ok: false,
          code: 'unsupported',
          message: 'crypto.getRandomValues is unavailable in this runtime',
        };
      }

      const createdAtMs = Date.now();
      const expiresAtMs = createdAtMs + ttlMsClamped;
      const challengeId = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
      const challengeB64u = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
      let credentialIds: string[] | undefined;

      if (expectedUserId) {
        const bindingStore = this.getWebAuthnCredentialBindingStore();
        if (typeof bindingStore.listByUserId !== 'function') {
          return {
            ok: false,
            code: 'not_supported',
            message: 'Credential listing is not supported by this store',
          };
        }
        const bindings = await bindingStore.listByUserId({ userId: expectedUserId, rpId });
        const seen = new Set<string>();
        credentialIds = [];
        for (const binding of bindings) {
          const credentialId = String(binding.credentialIdB64u || '').trim();
          if (!credentialId || seen.has(credentialId)) continue;
          seen.add(credentialId);
          credentialIds.push(credentialId);
        }
      }

      const store = this.getWebAuthnSyncChallengeStore();
      await store.put({
        version: 'webauthn_sync_challenge_v1',
        challengeId,
        rpId,
        ...(expectedUserId ? { expectedUserId } : {}),
        challengeB64u,
        createdAtMs,
        expiresAtMs,
      });

      return {
        ok: true,
        challengeId,
        challengeB64u,
        ...(credentialIds ? { credentialIds } : {}),
        expiresAtMs,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to create sync account options',
      };
    }
  }

  async verifyWebAuthnSyncAccount(request: {
    challengeId?: unknown;
    challenge_id?: unknown;
    webauthn_authentication?: unknown;
    expected_origin?: string;
    threshold_ed25519?: unknown;
  }): Promise<{
    ok: boolean;
    verified?: boolean;
    accountId?: string;
    rpId?: string;
    signerSlot?: number;
    publicKey?: string;
    relayerKeyId?: string;
    credentialIdB64u?: string;
    credentialPublicKeyB64u?: string;
    thresholdEd25519?: {
      relayerKeyId: string;
      publicKey: string;
      keyVersion?: string;
      recoveryExportCapable?: boolean;
      clientParticipantId?: number;
      relayerParticipantId?: number;
      participantIds?: number[];
      session?: {
        sessionKind: 'jwt' | 'cookie';
        sessionId: string;
        walletSigningSessionId: string;
        expiresAtMs: number;
        expiresAt?: string;
        participantIds?: number[];
        remainingUses?: number;
        jwt?: string;
      };
    };
    code?: string;
    message?: string;
  }> {
    try {
      const challengeId = String(request?.challengeId ?? request?.challenge_id ?? '').trim();
      if (!challengeId) return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };

      const store = this.getWebAuthnSyncChallengeStore();
      const challenge = await store.consume(challengeId);
      if (!challenge) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_expired_or_invalid',
          message: 'Sync challenge expired or invalid',
        };
      }

      const thresholdEd25519Bootstrap = parseThresholdEd25519RegistrationInput(
        (request as any)?.threshold_ed25519,
      );
      const thresholdEd25519SessionPolicy = thresholdEd25519Bootstrap.sessionPolicy;
      const thresholdEd25519SessionKind = thresholdEd25519Bootstrap.sessionKind;
      if (thresholdEd25519SessionPolicy && !isObject(thresholdEd25519SessionPolicy)) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy is required',
        };
      }
      if (thresholdEd25519SessionKind && thresholdEd25519SessionKind !== 'jwt') {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_kind must be jwt',
        };
      }

      const cred = request?.webauthn_authentication as any;
      const credentialId = String(cred?.id || '').trim();
      const rawId = String(cred?.rawId || '').trim();
      const chosen = rawId || credentialId;
      if (!chosen) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'Missing webauthn_authentication.id/rawId',
        };
      }

      const credentialIDBytes = decodeBase64UrlOrBase64(chosen, 'webauthn_authentication.rawId');
      const credentialIdB64u = base64UrlEncode(credentialIDBytes);

      const bindingStore = this.getWebAuthnCredentialBindingStore();
      const binding = await bindingStore.get(challenge.rpId, credentialIdB64u);
      if (!binding) {
        return {
          ok: false,
          verified: false,
          code: 'unknown_credential',
          message: 'Credential is not registered on this relay',
        };
      }
      if (challenge.expectedUserId && binding.userId !== challenge.expectedUserId) {
        return {
          ok: false,
          verified: false,
          code: 'unknown_credential',
          message: `Credential is not registered for account ${challenge.expectedUserId}`,
        };
      }

      const verification = await this.verifyWebAuthnAuthenticationLite({
        nearAccountId: binding.userId,
        rpId: binding.rpId,
        expectedChallenge: challenge.challengeB64u,
        webauthn_authentication: request?.webauthn_authentication as any,
        expected_origin: request.expected_origin,
      });

      if (!verification.success || !verification.verified) {
        return {
          ok: false,
          verified: false,
          code: verification.code || 'not_verified',
          message: verification.message || 'Authentication verification failed',
        };
      }

      const authStore = this.getWebAuthnAuthenticatorStore();
      const auth = await authStore.get(binding.userId, credentialIdB64u);
      if (!auth) {
        return {
          ok: false,
          verified: false,
          code: 'unknown_credential',
          message: 'Credential is not registered for user',
        };
      }

      const thresholdEd25519 = binding.relayerKeyId
        ? {
            relayerKeyId: binding.relayerKeyId,
            publicKey: binding.publicKey,
            ...(binding.keyVersion ? { keyVersion: binding.keyVersion } : {}),
            ...(typeof binding.recoveryExportCapable === 'boolean'
              ? { recoveryExportCapable: binding.recoveryExportCapable }
              : {}),
            ...(typeof binding.clientParticipantId === 'number'
              ? { clientParticipantId: binding.clientParticipantId }
              : {}),
            ...(typeof binding.relayerParticipantId === 'number'
              ? { relayerParticipantId: binding.relayerParticipantId }
              : {}),
            ...(Array.isArray(binding.participantIds)
              ? { participantIds: binding.participantIds }
              : {}),
          }
        : undefined;

      let thresholdEd25519Session: ThresholdEd25519BootstrapSession | undefined;
      if (thresholdEd25519SessionPolicy) {
        const thresholdService = this.getThresholdSigningService();
        if (!thresholdService) {
          return {
            ok: false,
            verified: false,
            code: 'not_configured',
            message: 'Threshold signing is not configured on this server',
          };
        }
        const relayerKeyId = String(binding.relayerKeyId || '').trim();
        if (!relayerKeyId) {
          return {
            ok: false,
            verified: false,
            code: 'invalid_body',
            message: 'Credential is not bound to threshold key material',
          };
        }
        const requestedSessionPolicy = thresholdEd25519SessionPolicy as Record<string, unknown>;
        const runtimePolicyScope =
          normalizeThresholdRuntimePolicyScope(requestedSessionPolicy.runtimePolicyScope) ||
          normalizeThresholdRuntimePolicyScope(binding.runtimePolicyScope);
        const policyBindingError = validateThresholdEd25519SessionPolicyBindings({
          requestedSessionPolicy,
          expectedRelayerKeyId: relayerKeyId,
          expectedNearAccountId: binding.userId,
          expectedRpId: binding.rpId,
        });
        if (policyBindingError) {
          return {
            ok: false,
            verified: false,
            code: 'invalid_body',
            message: policyBindingError,
          };
        }

        const session = await thresholdService.mintEd25519SessionFromRegistration({
          nearAccountId: binding.userId,
          rpId: binding.rpId,
          relayerKeyId,
          sessionPolicy: {
            ...requestedSessionPolicy,
            nearAccountId: binding.userId,
            rpId: binding.rpId,
            relayerKeyId,
            ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
          } as any,
        });
        if (!session.ok || !session.sessionId || !Number.isFinite(Number(session.expiresAtMs))) {
          return {
            ok: false,
            verified: false,
            code: session.code || 'internal',
            message: session.message || 'threshold-ed25519 session bootstrap failed',
          };
        }
        const normalizedSession = toThresholdEd25519BootstrapSession(session);
        if (!normalizedSession) {
          return {
            ok: false,
            verified: false,
            code: 'internal',
            message: 'threshold-ed25519 session bootstrap failed',
          };
        }
        thresholdEd25519Session = normalizedSession;
      }

      return {
        ok: true,
        verified: true,
        accountId: binding.userId,
        rpId: binding.rpId,
        signerSlot: binding.signerSlot,
        publicKey: binding.publicKey,
        ...(binding.relayerKeyId ? { relayerKeyId: binding.relayerKeyId } : {}),
        credentialIdB64u,
        credentialPublicKeyB64u: auth.credentialPublicKeyB64u,
        ...(thresholdEd25519
          ? {
              thresholdEd25519: {
                ...thresholdEd25519,
                ...(thresholdEd25519Session ? { session: thresholdEd25519Session } : {}),
              },
            }
          : {}),
      };
    } catch (e: unknown) {
      return {
        ok: false,
        verified: false,
        code: 'internal',
        message: errorMessage(e) || 'Sync verification failed',
      };
    }
  }

  async getLinkDeviceSession(request: {
    session_id?: unknown;
    sessionId?: unknown;
  }): Promise<
    { ok: true; session: DeviceLinkingSessionRecord } | { ok: false; code: string; message: string }
  > {
    try {
      const sessionId = String(request?.session_id ?? request?.sessionId ?? '').trim();
      if (!sessionId || !/^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/.test(sessionId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid sessionId' };
      }

      const store = this.getDeviceLinkingSessionStore();
      const session = await store.get(sessionId);
      if (!session)
        return { ok: false, code: 'not_found', message: 'Unknown or expired link-device session' };
      return { ok: true, session };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to load link-device session',
      };
    }
  }

  async registerLinkDeviceSession(request: {
    session_id?: unknown;
    sessionId?: unknown;
    device2_public_key?: unknown;
    device2PublicKey?: unknown;
    expires_at_ms?: unknown;
    expiresAtMs?: unknown;
  }): Promise<
    { ok: true; session: DeviceLinkingSessionRecord } | { ok: false; code: string; message: string }
  > {
    try {
      const sessionId = String(request?.session_id ?? request?.sessionId ?? '').trim();
      if (!sessionId || !/^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/.test(sessionId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid sessionId' };
      }

      const device2PublicKey = String(
        request?.device2_public_key ?? request?.device2PublicKey ?? '',
      ).trim();
      if (!device2PublicKey || !device2PublicKey.startsWith('ed25519:')) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Invalid device2PublicKey (expected ed25519:...)',
        };
      }

      const now = Date.now();
      const requestedExpiresRaw = request?.expires_at_ms ?? request?.expiresAtMs;
      const requestedExpires =
        typeof requestedExpiresRaw === 'number' ? requestedExpiresRaw : Number(requestedExpiresRaw);
      const ttlMs = 15 * 60_000;
      const maxTtlMs = 60 * 60_000;
      const baseExpires = now + ttlMs;
      const expiresAtMs =
        Number.isFinite(requestedExpires) && requestedExpires > now
          ? Math.min(Math.floor(requestedExpires), now + maxTtlMs)
          : baseExpires;

      const store = this.getDeviceLinkingSessionStore();
      const existing = await store.get(sessionId);
      if (existing?.device2PublicKey && existing.device2PublicKey !== device2PublicKey) {
        return { ok: false, code: 'conflict', message: 'Session public key mismatch' };
      }

      const session: DeviceLinkingSessionRecord = {
        version: 'device_linking_session_v1',
        sessionId,
        device2PublicKey,
        createdAtMs: existing?.createdAtMs ?? now,
        expiresAtMs: Math.max(existing?.expiresAtMs ?? 0, expiresAtMs),
        ...(existing?.claimedAtMs ? { claimedAtMs: existing.claimedAtMs } : {}),
        ...(existing?.accountId ? { accountId: existing.accountId } : {}),
        ...(existing?.signerSlot ? { signerSlot: existing.signerSlot } : {}),
        ...(existing?.addKeyTxHash ? { addKeyTxHash: existing.addKeyTxHash } : {}),
        ...(existing?.preparedThresholdEcdsa
          ? { preparedThresholdEcdsa: existing.preparedThresholdEcdsa }
          : {}),
        ...(existing?.preparedLinkedAccounts
          ? { preparedLinkedAccounts: existing.preparedLinkedAccounts }
          : {}),
      };

      await store.put(session);
      this.logger.info('[link-device] session registered', {
        sessionId,
        device2PublicKey,
        expiresAtMs: session.expiresAtMs,
        hasExisting: !!existing,
        storeKind: String((this.config.thresholdStore as any)?.kind || ''),
      });
      return { ok: true, session };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to register link-device session',
      };
    }
  }

  async claimLinkDeviceSession(request: {
    session_id?: unknown;
    sessionId?: unknown;
    account_id?: unknown;
    accountId?: unknown;
    device2_public_key?: unknown;
    device2PublicKey?: unknown;
    signer_slot?: unknown;
    signerSlot?: unknown;
    add_key_tx_hash?: unknown;
    addKeyTxHash?: unknown;
  }): Promise<
    { ok: true; session: DeviceLinkingSessionRecord } | { ok: false; code: string; message: string }
  > {
    try {
      await this._ensureSignerAndRelayerAccount();

      const sessionId = String(request?.session_id ?? request?.sessionId ?? '').trim();
      if (!sessionId || !/^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/.test(sessionId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid sessionId' };
      }

      const accountId = String(request?.account_id ?? request?.accountId ?? '').trim();
      if (!accountId || !isValidAccountId(accountId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid accountId' };
      }

      const device2PublicKey = String(
        request?.device2_public_key ?? request?.device2PublicKey ?? '',
      ).trim();
      if (!device2PublicKey || !device2PublicKey.startsWith('ed25519:')) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Invalid device2PublicKey (expected ed25519:...)',
        };
      }

      const addKeyTxHash =
        String(request?.add_key_tx_hash ?? request?.addKeyTxHash ?? '').trim() || undefined;

      const keys = await this.nearClient.viewAccessKeyList(accountId);
      const hasKey =
        Array.isArray(keys?.keys) &&
        keys.keys.some((k: any) => String(k?.public_key || '').trim() === device2PublicKey);
      if (!hasKey) {
        return {
          ok: false,
          code: 'missing_access_key',
          message:
            'device2 public key is not present on account (ensure AddKey has been submitted and propagated)',
        };
      }

      const store = this.getDeviceLinkingSessionStore();
      const existing = await store.get(sessionId);
      if (existing?.accountId && existing.accountId !== accountId) {
        return {
          ok: false,
          code: 'conflict',
          message: 'Session is already claimed by a different accountId',
        };
      }
      if (existing?.device2PublicKey && existing.device2PublicKey !== device2PublicKey) {
        return { ok: false, code: 'conflict', message: 'Session public key mismatch' };
      }

      const fallbackSignerSlot = coerceSignerSlot(
        request?.signer_slot ?? request?.signerSlot ?? existing?.signerSlot ?? 2,
        { min: 1, fallback: 2 },
      );
      let signerSlot = fallbackSignerSlot;
      try {
        const bindingStore = this.getWebAuthnCredentialBindingStore();
        if (bindingStore.getMaxSignerSlot) {
          const maxSignerSlot = await bindingStore.getMaxSignerSlot({ userId: accountId });
          if (typeof maxSignerSlot === 'number' && maxSignerSlot >= signerSlot) {
            signerSlot = maxSignerSlot + 1;
          }
        }
      } catch {
        // ignore and keep fallback
      }

      const now = Date.now();
      const ttlMs = 15 * 60_000;
      const expiresAtMs = Math.max(existing?.expiresAtMs ?? 0, now + ttlMs);

      const session: DeviceLinkingSessionRecord = {
        version: 'device_linking_session_v1',
        sessionId,
        device2PublicKey,
        createdAtMs: existing?.createdAtMs ?? now,
        expiresAtMs,
        claimedAtMs: now,
        accountId,
        signerSlot,
        ...(addKeyTxHash ? { addKeyTxHash } : {}),
        ...(existing?.preparedThresholdEcdsa
          ? { preparedThresholdEcdsa: existing.preparedThresholdEcdsa }
          : {}),
        ...(existing?.preparedLinkedAccounts
          ? { preparedLinkedAccounts: existing.preparedLinkedAccounts }
          : {}),
      };

      await store.put(session);

      // Best-effort: persist the ephemeral (device2) key metadata. This key is expected to be deleted
      // by Device2 during completion, but storing it helps UIs classify access keys while linking is in flight.
      await this.recordNearPublicKeyMetadata({
        userId: accountId,
        publicKey: device2PublicKey,
        kind: 'ephemeral',
        signerSlot,
        ...(addKeyTxHash ? { addedTxHash: addKeyTxHash } : {}),
        source: 'link-device ephemeral NEAR public key metadata persistence',
      });

      this.logger.info('[link-device] session claimed', {
        sessionId,
        accountId,
        device2PublicKey,
        signerSlot,
        addKeyTxHash: addKeyTxHash || '',
        storeKind: String((this.config.thresholdStore as any)?.kind || ''),
      });
      return { ok: true, session };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to claim link-device session',
      };
    }
  }

  async prepareLinkDevice(request: {
    account_id?: unknown;
    accountId?: unknown;
    session_id?: unknown;
    sessionId?: unknown;
    signer_slot?: unknown;
    signerSlot?: unknown;
    threshold_ed25519?: unknown;
    threshold_ecdsa?: unknown;
    rp_id?: unknown;
    webauthn_registration?: unknown;
    expected_origin?: string;
  }): Promise<
    | {
        ok: true;
        accountId: string;
        signerSlot: number;
        credentialIdB64u: string;
        thresholdEd25519: {
          relayerKeyId: string;
          publicKey: string;
          keyVersion?: string;
          recoveryExportCapable?: boolean;
          clientParticipantId?: number;
          relayerParticipantId?: number;
          participantIds?: number[];
          session?: {
            sessionKind: 'jwt' | 'cookie';
            sessionId: string;
            walletSigningSessionId: string;
            expiresAtMs: number;
            expiresAt?: string;
            participantIds?: number[];
            remainingUses?: number;
            runtimePolicyScope?: ThresholdRuntimePolicyScope;
            jwt?: string;
          };
        };
        thresholdEcdsa?: {
          relayerKeyId: string;
          thresholdEcdsaPublicKeyB64u: string;
          ethereumAddress: string;
          relayerVerifyingShareB64u: string;
          participantIds?: number[];
          session?: {
            sessionKind: 'jwt' | 'cookie';
            sessionId: string;
            walletSigningSessionId: string;
            expiresAtMs: number;
            expiresAt?: string;
            participantIds?: number[];
            remainingUses?: number;
            runtimePolicyScope?: ThresholdRuntimePolicyScope;
            jwt?: string;
          };
        };
        linkedAccounts?: LinkedSmartAccountRecord[];
      }
    | { ok: false; code: string; message: string }
  > {
    try {
      await this._ensureSignerAndRelayerAccount();

      const accountId = String(request?.account_id ?? request?.accountId ?? '').trim();
      if (!accountId || !isValidAccountId(accountId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid accountId' };
      }
      const sessionId = String(request?.session_id ?? request?.sessionId ?? '').trim() || undefined;

      const rpId = String(request?.rp_id || '').trim();
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'Missing rp_id' };

      const signerSlot = (() => {
        const raw = request?.signer_slot ?? request?.signerSlot ?? 2;
        const n = typeof raw === 'number' ? raw : Number(raw);
        return Number.isFinite(n) && n >= 1 ? Math.floor(n) : 2;
      })();
      const thresholdEd25519Bootstrap = parseThresholdEd25519RegistrationInput(
        (request as any)?.threshold_ed25519,
      );
      const thresholdEd25519SessionPolicy = thresholdEd25519Bootstrap.sessionPolicy;
      if (
        (request as any)?.threshold_ed25519?.session_policy != null &&
        !thresholdEd25519SessionPolicy
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy must be an object',
        };
      }
      const thresholdEd25519SessionKind = thresholdEd25519Bootstrap.sessionKind;
      if (thresholdEd25519SessionKind && thresholdEd25519SessionKind !== 'jwt') {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_kind must be jwt',
        };
      }
      if (!thresholdEd25519SessionPolicy && thresholdEd25519SessionKind) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy is required when session_kind is provided',
        };
      }

      const thresholdEcdsaBootstrap = parseThresholdEcdsaBootstrapInput(
        (request as any)?.threshold_ecdsa,
      );
      const thresholdEcdsaClientRootShare32B64u = thresholdEcdsaBootstrap.clientRootShare32B64u;
      const thresholdEcdsaRequested =
        (request as any)?.threshold_ecdsa != null || Boolean(thresholdEcdsaClientRootShare32B64u);
      if (thresholdEcdsaRequested && !thresholdEcdsaClientRootShare32B64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Missing threshold_ecdsa.client_root_share32_b64u',
        };
      }
      const thresholdEcdsaSessionPolicy = thresholdEcdsaBootstrap.sessionPolicy;
      if (
        (request as any)?.threshold_ecdsa?.session_policy != null &&
        !thresholdEcdsaSessionPolicy
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ecdsa.session_policy must be an object',
        };
      }
      const thresholdEcdsaSessionKind = thresholdEcdsaBootstrap.sessionKind;
      if (thresholdEcdsaSessionKind && thresholdEcdsaSessionKind !== 'jwt') {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ecdsa.session_kind must be jwt',
        };
      }
      if (!thresholdEcdsaSessionPolicy && thresholdEcdsaSessionKind) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ecdsa.session_policy is required when session_kind is provided',
        };
      }

      const cred = request.webauthn_registration as any;
      if (!cred || typeof cred !== 'object')
        return { ok: false, code: 'invalid_body', message: 'Missing webauthn_registration' };

      // NOTE: We reuse the same deterministic registration intent schema as account creation:
      // `sha256("register:<accountId>:<signerSlot>")`. This keeps client-side plumbing simple
      // (reuses existing SecureConfirm registration helpers).
      const expectedIntent = `register:${accountId}:${signerSlot}`;
      const expectedChallenge = base64UrlEncode(await sha256BytesUtf8(expectedIntent));

      const clientData = parseClientDataJsonBase64url(String(cred.response?.clientDataJSON || ''));
      if (clientData.type !== 'webauthn.create') {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Invalid webauthn_registration.clientDataJSON.type (expected webauthn.create)',
        };
      }
      if (clientData.challenge !== expectedChallenge) {
        return {
          ok: false,
          code: 'challenge_mismatch',
          message: 'Registration challenge mismatch',
        };
      }
      const originHost = originHostnameOrEmpty(clientData.origin);
      if (!isHostWithinRpId(originHost, rpId)) {
        return { ok: false, code: 'invalid_origin', message: 'WebAuthn origin is not within rpId' };
      }

      const mod = await import('@simplewebauthn/server');
      const verifyRegistrationResponse = (mod as any).verifyRegistrationResponse as
        | undefined
        | ((args: any) => Promise<any>);
      if (typeof verifyRegistrationResponse !== 'function') {
        return {
          ok: false,
          code: 'unsupported',
          message: 'WebAuthn registration verifier is unavailable in this runtime',
        };
      }

      const expectedOriginStrict = request.expected_origin || clientData.origin;
      const registration = await verifyRegistrationResponse({
        response: cred,
        expectedChallenge,
        expectedOrigin: expectedOriginStrict,
        expectedRPID: rpId,
        requireUserVerification: false,
      });
      if (!registration?.verified) {
        return { ok: false, code: 'not_verified', message: 'Registration verification failed' };
      }

      const threshold = this.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Threshold signing is not configured on this server',
        };
      }
      const bindingStore = this.getWebAuthnCredentialBindingStore();
      const existingRuntimePolicyScope = await resolveBoundThresholdRuntimePolicyScope({
        bindingStore,
        userId: accountId,
        rpId,
      });
      const existingThresholdEd25519Binding = await resolveExistingThresholdEd25519Binding({
        bindingStore,
        userId: accountId,
        rpId,
      });
      if (!existingThresholdEd25519Binding) {
        return {
          ok: false,
          code: 'not_found',
          message: 'No existing threshold-ed25519 key binding found for account',
        };
      }
      let thresholdEcdsaKeygen:
        | {
            ecdsaThresholdKeyId?: string;
            signingRootId: string;
            signingRootVersion?: string;
            clientVerifyingShareB64u: string;
            clientAdditiveShare32B64u: string;
            relayerKeyId: string;
            thresholdEcdsaPublicKeyB64u: string;
            ethereumAddress: string;
            relayerVerifyingShareB64u: string;
            participantIds?: number[];
          }
        | undefined;
      let thresholdEcdsaSession: ThresholdEcdsaBootstrapSession | undefined;
      const keygen = {
        relayerKeyId: String(existingThresholdEd25519Binding.relayerKeyId || '').trim(),
        publicKey: existingThresholdEd25519Binding.publicKey,
        keyVersion: String(existingThresholdEd25519Binding.keyVersion || '').trim(),
        recoveryExportCapable:
          existingThresholdEd25519Binding.recoveryExportCapable === true ? true : undefined,
        clientParticipantId: existingThresholdEd25519Binding.clientParticipantId,
        relayerParticipantId: existingThresholdEd25519Binding.relayerParticipantId,
        participantIds: existingThresholdEd25519Binding.participantIds,
      };
      if (
        !keygen.relayerKeyId ||
        !keygen.publicKey ||
        !keygen.keyVersion ||
        keygen.recoveryExportCapable !== true
      ) {
        return {
          ok: false,
          code: 'not_found',
          message: 'Existing threshold-ed25519 binding is incomplete',
        };
      }
      let thresholdEd25519Session: ThresholdEd25519BootstrapSession | undefined;
      if (thresholdEd25519SessionPolicy) {
        const requestedSessionPolicy = thresholdEd25519SessionPolicy as Record<string, unknown>;
        const runtimePolicyScope =
          normalizeThresholdRuntimePolicyScope(requestedSessionPolicy.runtimePolicyScope) ||
          existingRuntimePolicyScope;
        const policyBindingError = validateThresholdEd25519SessionPolicyBindings({
          requestedSessionPolicy,
          expectedRelayerKeyId: keygen.relayerKeyId,
          expectedNearAccountId: accountId,
          expectedRpId: rpId,
        });
        if (policyBindingError) {
          return {
            ok: false,
            code: 'invalid_body',
            message: policyBindingError,
          };
        }

        const session = await threshold.mintEd25519SessionFromRegistration({
          nearAccountId: accountId,
          rpId,
          relayerKeyId: keygen.relayerKeyId,
          sessionPolicy: {
            ...requestedSessionPolicy,
            nearAccountId: accountId,
            rpId,
            relayerKeyId: keygen.relayerKeyId,
            ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
          } as any,
        });
        if (!session.ok || !session.sessionId || !Number.isFinite(Number(session.expiresAtMs))) {
          return {
            ok: false,
            code: session.code || 'internal',
            message: session.message || 'threshold-ed25519 link-device bootstrap failed',
          };
        }
        const normalizedSession = toThresholdEd25519BootstrapSession(session);
        if (!normalizedSession) {
          return {
            ok: false,
            code: 'internal',
            message: 'threshold-ed25519 link-device bootstrap failed',
          };
        }
        thresholdEd25519Session = normalizedSession;
      }

      if (thresholdEcdsaClientRootShare32B64u) {
        const out = await threshold.bootstrapEcdsaFromRegistrationMaterial({
          userId: accountId,
          rpId,
          clientRootShare32B64u: thresholdEcdsaClientRootShare32B64u,
          sessionPolicy: thresholdEcdsaSessionPolicy as Record<string, unknown>,
        });
        if (!out.ok) {
          return {
            ok: false,
            code: out.code || 'internal',
            message: out.message || 'threshold-ecdsa link-device bootstrap failed',
          };
        }
        const ecdsaThresholdKeyId = String(out.ecdsaThresholdKeyId || '').trim();
        const signingRootId = String(out.signingRootId || '').trim();
        const signingRootVersion = String(out.signingRootVersion || '').trim();
        const relayerKeyId = String(out.relayerKeyId || '').trim();
        const thresholdEcdsaPublicKeyB64u = String(out.thresholdEcdsaPublicKeyB64u || '').trim();
        const ethereumAddress = String(out.ethereumAddress || '').trim();
        const relayerVerifyingShareB64u = String(out.relayerVerifyingShareB64u || '').trim();
        if (
          !ecdsaThresholdKeyId ||
          !signingRootId ||
          !relayerKeyId ||
          !thresholdEcdsaPublicKeyB64u ||
          !ethereumAddress ||
          !relayerVerifyingShareB64u
        ) {
          return {
            ok: false,
            code: 'internal',
            message: 'threshold-ecdsa link-device bootstrap returned incomplete key material',
          };
        }
        thresholdEcdsaKeygen = {
          ecdsaThresholdKeyId,
          signingRootId,
          ...(signingRootVersion ? { signingRootVersion } : {}),
          clientVerifyingShareB64u: String(out.clientVerifyingShareB64u || '').trim(),
          clientAdditiveShare32B64u: String(out.clientAdditiveShare32B64u || '').trim(),
          relayerKeyId,
          thresholdEcdsaPublicKeyB64u,
          ethereumAddress,
          relayerVerifyingShareB64u,
          ...(Array.isArray(out.participantIds) ? { participantIds: out.participantIds } : {}),
        };
        const normalizedSession = toThresholdEcdsaBootstrapSession(out);
        if (!normalizedSession) {
          return {
            ok: false,
            code: 'internal',
            message: 'threshold-ecdsa link-device bootstrap failed',
          };
        }
        thresholdEcdsaSession = normalizedSession;
      }

      const credentialIdB64u = String(registration?.registrationInfo?.credential?.id || '').trim();
      const credentialPublicKey = registration?.registrationInfo?.credential?.publicKey as
        | Uint8Array
        | undefined;
      const counter = registration?.registrationInfo?.credential?.counter as number | undefined;

      if (!credentialIdB64u || !credentialPublicKey) {
        return {
          ok: false,
          code: 'internal',
          message: 'Registration verification did not return credential public key material',
        };
      }

      const now = Date.now();

      const authStore = this.getWebAuthnAuthenticatorStore();
      await authStore.put(accountId, {
        version: 'webauthn_authenticator_v1',
        credentialIdB64u,
        credentialPublicKeyB64u: base64UrlEncode(credentialPublicKey),
        counter: Number.isFinite(counter) && counter! >= 0 ? Math.floor(counter!) : 0,
        createdAtMs: now,
        updatedAtMs: now,
      });

      await bindingStore.put({
        version: 'webauthn_credential_binding_v1',
        rpId,
        credentialIdB64u,
        userId: accountId,
        signerSlot,
        publicKey: keygen.publicKey,
        relayerKeyId: keygen.relayerKeyId,
        clientParticipantId: keygen.clientParticipantId,
        relayerParticipantId: keygen.relayerParticipantId,
        participantIds: keygen.participantIds,
        ...(thresholdEd25519Session?.runtimePolicyScope || existingRuntimePolicyScope
          ? {
              runtimePolicyScope:
                thresholdEd25519Session?.runtimePolicyScope || existingRuntimePolicyScope,
            }
          : {}),
        createdAtMs: now,
        updatedAtMs: now,
      });

      // Best-effort: persist key metadata for UI surfaces like "Linked Devices".
      await this.recordNearPublicKeyMetadata({
        userId: accountId,
        publicKey: keygen.publicKey,
        kind: 'threshold',
        signerSlot,
        rpId,
        credentialIdB64u,
        source: 'WebAuthn registration NEAR public key metadata persistence',
      });

      let linkedAccounts: LinkedSmartAccountRecord[] | undefined;
      if (thresholdEcdsaKeygen) {
        const recoverySubjects =
          await this.getSmartAccountRecoverySubjectStore().listByNearAccountId(accountId);
        const built = buildLinkDeviceSmartAccountRecords({
          userId: accountId,
          signerSlot,
          credentialIdB64u,
          rpId,
          relayerKeyId: thresholdEcdsaKeygen.relayerKeyId,
          thresholdEcdsaPublicKeyB64u: thresholdEcdsaKeygen.thresholdEcdsaPublicKeyB64u,
          thresholdOwnerAddress: thresholdEcdsaKeygen.ethereumAddress,
          participantIds: thresholdEcdsaKeygen.participantIds,
          recoverySubjects,
          nowMs: now,
        });
        const signerStore = this.getAccountSignerStore();
        for (const record of built.accountSigners) {
          await signerStore.put(record);
        }
        for (const account of built.linkedAccounts) {
          await syncCanonicalSmartAccountDeploymentManifest({
            authService: this,
            chainIdKey: account.chainIdKey,
            accountAddress: account.accountAddress,
            materializedAtMs: now,
          });
        }
        linkedAccounts = built.linkedAccounts;
      }

      if (sessionId) {
        const sessionStore = this.getDeviceLinkingSessionStore();
        const existingSession = await sessionStore.get(sessionId);
        if (!existingSession) {
          return {
            ok: false,
            code: 'not_found',
            message: 'Unknown or expired link-device session',
          };
        }
        if (existingSession.accountId && existingSession.accountId !== accountId) {
          return {
            ok: false,
            code: 'conflict',
            message: 'Link-device session accountId mismatch',
          };
        }

        const preparedThresholdEcdsa: DeviceLinkingPreparedThresholdEcdsaRecord | undefined =
          thresholdEcdsaKeygen
            ? {
                clientVerifyingShareB64u: thresholdEcdsaKeygen.clientVerifyingShareB64u,
                clientAdditiveShare32B64u: thresholdEcdsaKeygen.clientAdditiveShare32B64u,
                relayerKeyId: thresholdEcdsaKeygen.relayerKeyId,
                thresholdEcdsaPublicKeyB64u: thresholdEcdsaKeygen.thresholdEcdsaPublicKeyB64u,
                ethereumAddress: thresholdEcdsaKeygen.ethereumAddress,
                ...(Array.isArray(thresholdEcdsaKeygen.participantIds)
                  ? { participantIds: thresholdEcdsaKeygen.participantIds }
                  : {}),
              }
            : undefined;
        const preparedLinkedAccounts: DeviceLinkingPreparedLinkedAccountRecord[] | undefined =
          linkedAccounts?.map((account) => ({
            chainIdKey: account.chainIdKey,
            chain: account.chain,
            chainId: account.chainId,
            accountAddress: account.accountAddress,
            accountModel: account.accountModel,
            ...(account.factory ? { factory: account.factory } : {}),
            ...(account.entryPoint ? { entryPoint: account.entryPoint } : {}),
            ...(account.salt ? { salt: account.salt } : {}),
            ...(account.counterfactualAddress
              ? { counterfactualAddress: account.counterfactualAddress }
              : {}),
          })) || undefined;

        await sessionStore.put({
          ...existingSession,
          ...(preparedThresholdEcdsa ? { preparedThresholdEcdsa } : {}),
          ...(preparedLinkedAccounts ? { preparedLinkedAccounts } : {}),
        });
      }

      return {
        ok: true,
        accountId,
        signerSlot,
        credentialIdB64u,
        thresholdEd25519: {
          relayerKeyId: keygen.relayerKeyId,
          publicKey: keygen.publicKey,
          ...(keygen.keyVersion ? { keyVersion: keygen.keyVersion } : {}),
          ...(typeof keygen.recoveryExportCapable === 'boolean'
            ? { recoveryExportCapable: keygen.recoveryExportCapable }
            : {}),
          clientParticipantId: keygen.clientParticipantId,
          relayerParticipantId: keygen.relayerParticipantId,
          participantIds: keygen.participantIds,
          ...(thresholdEd25519Session ? { session: thresholdEd25519Session } : {}),
        },
        ...(thresholdEcdsaKeygen
          ? {
              thresholdEcdsa: {
                ...thresholdEcdsaKeygen,
                ...(thresholdEcdsaSession ? { session: thresholdEcdsaSession } : {}),
              },
            }
          : {}),
        ...(linkedAccounts ? { linkedAccounts } : {}),
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Link device preparation failed',
      };
    }
  }

  async prepareEmailRecovery(request: {
    account_id?: unknown;
    accountId?: unknown;
    request_id?: unknown;
    requestId?: unknown;
    signer_slot?: unknown;
    signerSlot?: unknown;
    threshold_ed25519?: unknown;
    threshold_ecdsa?: unknown;
    rp_id?: unknown;
    webauthn_registration?: unknown;
    expected_origin?: string;
  }): Promise<
    | {
        ok: true;
        accountId: string;
        requestId: string;
        signerSlot: number;
        credentialIdB64u: string;
        thresholdEd25519: {
          relayerKeyId: string;
          publicKey: string;
          keyVersion?: string;
          recoveryExportCapable?: boolean;
          clientParticipantId?: number;
          relayerParticipantId?: number;
          participantIds?: number[];
          session?: {
            sessionKind: 'jwt' | 'cookie';
            sessionId: string;
            walletSigningSessionId: string;
            expiresAtMs: number;
            expiresAt?: string;
            participantIds?: number[];
            remainingUses?: number;
            runtimePolicyScope?: ThresholdRuntimePolicyScope;
            jwt?: string;
          };
        };
        thresholdEcdsa?: {
          relayerKeyId: string;
          thresholdEcdsaPublicKeyB64u: string;
          ethereumAddress: string;
          relayerVerifyingShareB64u: string;
          participantIds?: number[];
          session?: {
            sessionKind: 'jwt' | 'cookie';
            sessionId: string;
            walletSigningSessionId: string;
            expiresAtMs: number;
            expiresAt?: string;
            participantIds?: number[];
            remainingUses?: number;
            runtimePolicyScope?: ThresholdRuntimePolicyScope;
            jwt?: string;
          };
        };
        recoverySession: {
          sessionId: string;
          status: 'prepared';
          expiresAtMs: number;
          deadlineEpochSeconds: number;
          payloadHash: string;
        };
        recoveryEmail: {
          subject: string;
          body: string;
          payload: RecoveryEmailPayload;
          payloadHash: string;
          deadlineEpochSeconds: number;
        };
      }
    | { ok: false; code: string; message: string }
  > {
    try {
      await this._ensureSignerAndRelayerAccount();

      const accountId = String(request?.account_id ?? request?.accountId ?? '').trim();
      if (!accountId || !isValidAccountId(accountId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid accountId' };
      }

      const requestId = String(request?.request_id ?? request?.requestId ?? '').trim();
      if (!requestId || !/^[A-Za-z0-9_-]{3,64}$/.test(requestId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid requestId' };
      }

      const rpId = String(request?.rp_id || '').trim();
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'Missing rp_id' };

      const signerSlot = (() => {
        const raw = request?.signer_slot ?? request?.signerSlot ?? 1;
        const n = typeof raw === 'number' ? raw : Number(raw);
        return Number.isFinite(n) && n >= 1 ? Math.floor(n) : 1;
      })();

      const thresholdEd25519Bootstrap = parseThresholdEd25519RegistrationInput(
        (request as any)?.threshold_ed25519,
      );
      const thresholdEd25519SessionPolicy = thresholdEd25519Bootstrap.sessionPolicy;
      if (
        (request as any)?.threshold_ed25519?.session_policy != null &&
        !thresholdEd25519SessionPolicy
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy must be an object',
        };
      }
      const thresholdEd25519SessionKind = thresholdEd25519Bootstrap.sessionKind;
      if (thresholdEd25519SessionKind && thresholdEd25519SessionKind !== 'jwt') {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_kind must be jwt',
        };
      }
      if (!thresholdEd25519SessionPolicy && thresholdEd25519SessionKind) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy is required when session_kind is provided',
        };
      }

      const thresholdEcdsaBootstrap = parseThresholdEcdsaBootstrapInput(
        (request as any)?.threshold_ecdsa,
      );
      const thresholdEcdsaClientRootShare32B64u = thresholdEcdsaBootstrap.clientRootShare32B64u;
      const thresholdEcdsaRequested =
        (request as any)?.threshold_ecdsa != null || Boolean(thresholdEcdsaClientRootShare32B64u);
      if (!thresholdEcdsaRequested || !thresholdEcdsaClientRootShare32B64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message:
            'Email recovery requires threshold_ecdsa.client_root_share32_b64u to bind the recovered EVM owner',
        };
      }
      const thresholdEcdsaSessionPolicy = thresholdEcdsaBootstrap.sessionPolicy;
      if (
        (request as any)?.threshold_ecdsa?.session_policy != null &&
        !thresholdEcdsaSessionPolicy
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ecdsa.session_policy must be an object',
        };
      }
      const thresholdEcdsaSessionKind = thresholdEcdsaBootstrap.sessionKind;
      if (thresholdEcdsaSessionKind && thresholdEcdsaSessionKind !== 'jwt') {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ecdsa.session_kind must be jwt',
        };
      }
      if (!thresholdEcdsaSessionPolicy && thresholdEcdsaSessionKind) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ecdsa.session_policy is required when session_kind is provided',
        };
      }

      const cred = request.webauthn_registration as any;
      if (!cred || typeof cred !== 'object')
        return { ok: false, code: 'invalid_body', message: 'Missing webauthn_registration' };

      // Reuse the canonical deterministic registration challenge schema.
      // Email recovery authorization happens out-of-band (DKIM/TEE), so we don't
      // need to bind the WebAuthn registration challenge to the email `requestId`.
      const expectedIntent = `register:${accountId}:${signerSlot}`;
      const expectedChallenge = base64UrlEncode(await sha256BytesUtf8(expectedIntent));

      const clientData = parseClientDataJsonBase64url(String(cred.response?.clientDataJSON || ''));
      if (clientData.type !== 'webauthn.create') {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Invalid webauthn_registration.clientDataJSON.type (expected webauthn.create)',
        };
      }
      if (clientData.challenge !== expectedChallenge) {
        return {
          ok: false,
          code: 'challenge_mismatch',
          message: 'Registration challenge mismatch',
        };
      }
      const originHost = originHostnameOrEmpty(clientData.origin);
      if (!isHostWithinRpId(originHost, rpId)) {
        return { ok: false, code: 'invalid_origin', message: 'WebAuthn origin is not within rpId' };
      }

      const mod = await import('@simplewebauthn/server');
      const verifyRegistrationResponse = (mod as any).verifyRegistrationResponse as
        | undefined
        | ((args: any) => Promise<any>);
      if (typeof verifyRegistrationResponse !== 'function') {
        return {
          ok: false,
          code: 'unsupported',
          message: 'WebAuthn registration verifier is unavailable in this runtime',
        };
      }

      const expectedOriginStrict = request.expected_origin || clientData.origin;
      const registration = await verifyRegistrationResponse({
        response: cred,
        expectedChallenge,
        expectedOrigin: expectedOriginStrict,
        expectedRPID: rpId,
        requireUserVerification: false,
      });
      if (!registration?.verified) {
        return { ok: false, code: 'not_verified', message: 'Registration verification failed' };
      }

      const threshold = this.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Threshold signing is not configured on this server',
        };
      }
      const bindingStore = this.getWebAuthnCredentialBindingStore();
      const existingRuntimePolicyScope = await resolveBoundThresholdRuntimePolicyScope({
        bindingStore,
        userId: accountId,
        rpId,
      });
      const existingThresholdEd25519Binding = await resolveExistingThresholdEd25519Binding({
        bindingStore,
        userId: accountId,
        rpId,
      });
      if (!existingThresholdEd25519Binding) {
        return {
          ok: false,
          code: 'not_found',
          message: 'No existing threshold-ed25519 key binding found for account',
        };
      }
      let thresholdEcdsaKeygen:
        | {
            ecdsaThresholdKeyId?: string;
            signingRootId: string;
            signingRootVersion?: string;
            clientVerifyingShareB64u: string;
            clientAdditiveShare32B64u: string;
            relayerKeyId: string;
            thresholdEcdsaPublicKeyB64u: string;
            ethereumAddress: string;
            relayerVerifyingShareB64u: string;
            participantIds?: number[];
          }
        | undefined;
      let thresholdEcdsaSession: ThresholdEcdsaBootstrapSession | undefined;
      const keygen = {
        relayerKeyId: String(existingThresholdEd25519Binding.relayerKeyId || '').trim(),
        publicKey: existingThresholdEd25519Binding.publicKey,
        keyVersion: String(existingThresholdEd25519Binding.keyVersion || '').trim(),
        recoveryExportCapable:
          existingThresholdEd25519Binding.recoveryExportCapable === true ? true : undefined,
        clientParticipantId: existingThresholdEd25519Binding.clientParticipantId,
        relayerParticipantId: existingThresholdEd25519Binding.relayerParticipantId,
        participantIds: existingThresholdEd25519Binding.participantIds,
      };
      if (
        !keygen.relayerKeyId ||
        !keygen.publicKey ||
        !keygen.keyVersion ||
        keygen.recoveryExportCapable !== true
      ) {
        return {
          ok: false,
          code: 'not_found',
          message: 'Existing threshold-ed25519 binding is incomplete',
        };
      }
      let thresholdEd25519Session: ThresholdEd25519BootstrapSession | undefined;
      if (thresholdEd25519SessionPolicy) {
        const requestedSessionPolicy = thresholdEd25519SessionPolicy as Record<string, unknown>;
        const runtimePolicyScope =
          normalizeThresholdRuntimePolicyScope(requestedSessionPolicy.runtimePolicyScope) ||
          existingRuntimePolicyScope;
        const policyBindingError = validateThresholdEd25519SessionPolicyBindings({
          requestedSessionPolicy,
          expectedRelayerKeyId: keygen.relayerKeyId,
          expectedNearAccountId: accountId,
          expectedRpId: rpId,
        });
        if (policyBindingError) {
          return {
            ok: false,
            code: 'invalid_body',
            message: policyBindingError,
          };
        }

        const session = await threshold.mintEd25519SessionFromRegistration({
          nearAccountId: accountId,
          rpId,
          relayerKeyId: keygen.relayerKeyId,
          sessionPolicy: {
            ...requestedSessionPolicy,
            nearAccountId: accountId,
            rpId,
            relayerKeyId: keygen.relayerKeyId,
            ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
          } as any,
        });
        if (!session.ok || !session.sessionId || !Number.isFinite(Number(session.expiresAtMs))) {
          return {
            ok: false,
            code: session.code || 'internal',
            message: session.message || 'threshold-ed25519 email-recovery bootstrap failed',
          };
        }
        const normalizedSession = toThresholdEd25519BootstrapSession(session);
        if (!normalizedSession) {
          return {
            ok: false,
            code: 'internal',
            message: 'threshold-ed25519 email-recovery bootstrap failed',
          };
        }
        thresholdEd25519Session = normalizedSession;
      }

      if (thresholdEcdsaClientRootShare32B64u) {
        const out = await threshold.bootstrapEcdsaFromRegistrationMaterial({
          userId: accountId,
          rpId,
          clientRootShare32B64u: thresholdEcdsaClientRootShare32B64u,
          sessionPolicy: thresholdEcdsaSessionPolicy as Record<string, unknown>,
        });
        if (!out.ok) {
          return {
            ok: false,
            code: out.code || 'internal',
            message: out.message || 'threshold-ecdsa email-recovery bootstrap failed',
          };
        }
        const ecdsaThresholdKeyId = String(out.ecdsaThresholdKeyId || '').trim();
        const signingRootId = String(out.signingRootId || '').trim();
        const signingRootVersion = String(out.signingRootVersion || '').trim();
        const relayerKeyId = String(out.relayerKeyId || '').trim();
        const thresholdEcdsaPublicKeyB64u = String(out.thresholdEcdsaPublicKeyB64u || '').trim();
        const ethereumAddress = String(out.ethereumAddress || '').trim();
        const relayerVerifyingShareB64u = String(out.relayerVerifyingShareB64u || '').trim();
        if (
          !ecdsaThresholdKeyId ||
          !signingRootId ||
          !relayerKeyId ||
          !thresholdEcdsaPublicKeyB64u ||
          !ethereumAddress ||
          !relayerVerifyingShareB64u
        ) {
          return {
            ok: false,
            code: 'internal',
            message: 'threshold-ecdsa email-recovery bootstrap returned incomplete key material',
          };
        }
        thresholdEcdsaKeygen = {
          ecdsaThresholdKeyId,
          signingRootId,
          ...(signingRootVersion ? { signingRootVersion } : {}),
          clientVerifyingShareB64u: String(out.clientVerifyingShareB64u || '').trim(),
          clientAdditiveShare32B64u: String(out.clientAdditiveShare32B64u || '').trim(),
          relayerKeyId,
          thresholdEcdsaPublicKeyB64u,
          ethereumAddress,
          relayerVerifyingShareB64u,
          ...(Array.isArray(out.participantIds) ? { participantIds: out.participantIds } : {}),
        };
        const normalizedSession = toThresholdEcdsaBootstrapSession(out);
        if (!normalizedSession) {
          return {
            ok: false,
            code: 'internal',
            message: 'threshold-ecdsa email-recovery bootstrap failed',
          };
        }
        thresholdEcdsaSession = normalizedSession;
      }

      const credentialIdB64u = String(registration?.registrationInfo?.credential?.id || '').trim();
      const credentialPublicKey = registration?.registrationInfo?.credential?.publicKey as
        | Uint8Array
        | undefined;
      const counter = registration?.registrationInfo?.credential?.counter as number | undefined;

      if (!credentialIdB64u || !credentialPublicKey) {
        return {
          ok: false,
          code: 'internal',
          message: 'Registration verification did not return credential public key material',
        };
      }

      const now = Date.now();
      const recoverySessionExpiresAtMs = now + DEFAULT_RECOVERY_SESSION_TTL_MS;
      const recoveryDeadlineEpochSeconds = Math.floor(recoverySessionExpiresAtMs / 1000);

      const authStore = this.getWebAuthnAuthenticatorStore();
      await authStore.put(accountId, {
        version: 'webauthn_authenticator_v1',
        credentialIdB64u,
        credentialPublicKeyB64u: base64UrlEncode(credentialPublicKey),
        counter: Number.isFinite(counter) && counter! >= 0 ? Math.floor(counter!) : 0,
        createdAtMs: now,
        updatedAtMs: now,
      });

      await bindingStore.put({
        version: 'webauthn_credential_binding_v1',
        rpId,
        credentialIdB64u,
        userId: accountId,
        signerSlot,
        publicKey: keygen.publicKey,
        relayerKeyId: keygen.relayerKeyId,
        clientParticipantId: keygen.clientParticipantId,
        relayerParticipantId: keygen.relayerParticipantId,
        participantIds: keygen.participantIds,
        ...(thresholdEd25519Session?.runtimePolicyScope || existingRuntimePolicyScope
          ? {
              runtimePolicyScope:
                thresholdEd25519Session?.runtimePolicyScope || existingRuntimePolicyScope,
            }
          : {}),
        createdAtMs: now,
        updatedAtMs: now,
      });

      if (!thresholdEcdsaKeygen?.ethereumAddress) {
        return {
          ok: false,
          code: 'internal',
          message: 'Threshold ECDSA recovery bootstrap did not return an Ethereum owner address',
        };
      }

      const recoveryEmailPayload = buildRecoveryEmailPayload({
        nearAccountId: accountId,
        recoverySessionId: requestId,
        newNearPublicKey: keygen.publicKey,
        newEvmOwnerAddress: thresholdEcdsaKeygen.ethereumAddress,
        deadlineEpochSeconds: recoveryDeadlineEpochSeconds,
        scope: 'all-linked-evm-accounts',
      });
      const recoveryEmailPayloadHash = await hashRecoveryEmailPayload(recoveryEmailPayload);
      const recoveryEmailSubject = buildRecoveryEmailSubject(recoveryEmailPayload);
      const recoveryEmailBody = buildRecoveryEmailBody(recoveryEmailPayload);

      const recoverySessionRecord = buildPreparedRecoverySessionRecord({
        sessionId: requestId,
        userId: accountId,
        nearAccountId: accountId,
        signerSlot,
        newNearPublicKey: keygen.publicKey,
        newEvmOwnerAddress: thresholdEcdsaKeygen.ethereumAddress,
        recoveryDeadlineEpochSeconds,
        recoveryEmailPayloadHash,
        scope: 'all-linked-evm-accounts',
        expiresAtMs: recoverySessionExpiresAtMs,
        metadata: {
          rpId,
          credentialIdB64u,
          recoveryEmail: {
            subject: recoveryEmailSubject,
            body: recoveryEmailBody,
          },
          thresholdEd25519: {
            relayerKeyId: keygen.relayerKeyId,
            ...(thresholdEd25519Session ? { sessionId: thresholdEd25519Session.sessionId } : {}),
          },
          ...(thresholdEcdsaKeygen
            ? {
                thresholdEcdsa: {
                  relayerKeyId: thresholdEcdsaKeygen.relayerKeyId,
                  ethereumAddress: thresholdEcdsaKeygen.ethereumAddress,
                  ...(thresholdEcdsaSession ? { sessionId: thresholdEcdsaSession.sessionId } : {}),
                },
              }
            : {}),
        },
      });
      if (!recoverySessionRecord) {
        return {
          ok: false,
          code: 'internal',
          message: 'Failed to build recovery session record',
        };
      }
      await this.getRecoverySessionStore().put(recoverySessionRecord);

      return {
        ok: true,
        accountId,
        requestId,
        signerSlot,
        credentialIdB64u,
        thresholdEd25519: {
          relayerKeyId: keygen.relayerKeyId,
          publicKey: keygen.publicKey,
          ...(keygen.keyVersion ? { keyVersion: keygen.keyVersion } : {}),
          ...(typeof keygen.recoveryExportCapable === 'boolean'
            ? { recoveryExportCapable: keygen.recoveryExportCapable }
            : {}),
          clientParticipantId: keygen.clientParticipantId,
          relayerParticipantId: keygen.relayerParticipantId,
          participantIds: keygen.participantIds,
          ...(thresholdEd25519Session ? { session: thresholdEd25519Session } : {}),
        },
        ...(thresholdEcdsaKeygen
          ? {
              thresholdEcdsa: {
                ...thresholdEcdsaKeygen,
                ...(thresholdEcdsaSession ? { session: thresholdEcdsaSession } : {}),
              },
            }
          : {}),
        recoverySession: {
          sessionId: recoverySessionRecord.sessionId,
          status: 'prepared',
          expiresAtMs: recoverySessionRecord.expiresAtMs,
          deadlineEpochSeconds: recoverySessionRecord.recoveryDeadlineEpochSeconds,
          payloadHash: recoverySessionRecord.recoveryEmailPayloadHash,
        },
        recoveryEmail: {
          subject: recoveryEmailSubject,
          body: recoveryEmailBody,
          payload: recoveryEmailPayload,
          payloadHash: recoveryEmailPayloadHash,
          deadlineEpochSeconds: recoveryDeadlineEpochSeconds,
        },
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Email recovery preparation failed',
      };
    }
  }

  /**
   * Account existence helper used by registration flows.
   */
  async checkAccountExists(accountId: string): Promise<boolean> {
    await this._ensureSignerAndRelayerAccount();
    const isNotFound = (m: string) => /does not exist|UNKNOWN_ACCOUNT|unknown\s+account/i.test(m);
    const isRetryable = (m: string) =>
      /server error|internal|temporar|timeout|too many requests|429|empty response|rpc request failed/i.test(
        m,
      );
    const attempts = 3;
    let lastErr: Error | null = null;
    for (let i = 1; i <= attempts; i++) {
      try {
        const view = await this.nearClient.viewAccount(accountId);
        return !!view;
      } catch (error: unknown) {
        const err = toError(error);
        lastErr = err;
        const msg = err.message;
        const details = (err as { details?: unknown }).details;
        let detailsBlob = '';
        if (details) {
          try {
            detailsBlob = typeof details === 'string' ? details : JSON.stringify(details);
          } catch {
            detailsBlob = '';
          }
        }
        const combined = `${msg}\n${detailsBlob}`;
        if (isNotFound(combined)) return false;
        if (isRetryable(msg) && i < attempts) {
          const backoff = 150 * Math.pow(2, i - 1);
          await new Promise((r) => setTimeout(r, backoff));
          continue;
        }
        // As a safety valve for flaky RPCs, treat persistent retryable errors as not-found
        if (isRetryable(msg)) {
          this.logger.warn(
            `[AuthService] Assuming account '${accountId}' not found after retryable RPC errors:`,
            msg,
          );
          return false;
        }
        this.logger.error(`Error checking account existence for ${accountId}:`, err);
        throw err;
      }
    }
    throw lastErr || new Error('Unknown error');
  }

  /**
   * ===== Delegate actions & transaction execution =====
   *
   * Flows that build and submit on-chain transactions, including NEP-461
   * SignedDelegate meta-transactions.
   */

  /**
   * Execute a NEP-461 SignedDelegate by wrapping it in an outer transaction
   * from the relayer account. This method is intended to be called by
   * example relayers (Node/Cloudflare) once a SignedDelegate has been
   * produced by the signer worker and returned to the application.
   *
   * Notes:
   * - Signature and hash computation are performed by the signer worker.
   *   This method focuses on expiry/policy enforcement and meta-tx submission.
   * - Nonce/replay protection is left to the integrator; see docs for guidance.
   */
  async executeSignedDelegate(input: {
    hash: string;
    signedDelegate: SignedDelegate;
    policy?: DelegateActionPolicy;
  }): Promise<ExecuteSignedDelegateResult> {
    await this._ensureSignerAndRelayerAccount();

    if (!input?.hash || !input?.signedDelegate) {
      return {
        ok: false,
        code: 'invalid_delegate_request',
        error: 'hash and signedDelegate are required',
      };
    }

    const senderId = input.signedDelegate?.delegateAction?.senderId ?? 'unknown-sender';

    return this.queueTransaction(
      () =>
        executeSignedDelegateWithRelayer({
          nearClient: this.nearClient,
          relayerAccount: this.config.relayerAccount,
          relayerPublicKey: this.relayerPublicKey,
          relayerPrivateKey: this.config.relayerPrivateKey,
          hash: input.hash,
          signedDelegate: input.signedDelegate,
          policy: input.policy,
          signWithPrivateKey: (args) => this.signWithPrivateKey(args),
        }),
      `execute signed delegate for ${senderId}`,
    );
  }

  // === Internal helpers for signing & RPC ===
  private async verifyAccountAccessKeysPresent(
    accountId: string,
    expectedPublicKeys: string[],
    opts?: { attempts?: number; delayMs?: number; finality?: 'optimistic' | 'final' },
  ): Promise<boolean> {
    const unique = Array.from(
      new Set(expectedPublicKeys.map((k) => ensureEd25519Prefix(k)).filter(Boolean)),
    );
    if (!unique.length) return false;

    const attempts = Math.max(1, Math.floor(opts?.attempts ?? 4));
    const delayMs = Math.max(50, Math.floor(opts?.delayMs ?? 250));
    const finality = opts?.finality ?? 'final';

    for (let i = 0; i < attempts; i += 1) {
      try {
        const accessKeyList = await this.nearClient.viewAccessKeyList(accountId, { finality });
        const keys = accessKeyList.keys
          .map((k) => ensureEd25519Prefix(String(k?.public_key || '').trim()))
          .filter(Boolean);
        if (unique.every((expected) => keys.includes(expected))) return true;
      } catch {
        // tolerate transient RPC lag during finality propagation
      }
      if (i < attempts - 1) {
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }

    return false;
  }

  private scheduleAccountAccessKeyVisibilityAudit(input: {
    accountId: string;
    expectedPublicKeys: string[];
    contextLabel: string;
  }): void {
    void (async () => {
      const startedAt = Date.now();
      const verified = await this.verifyAccountAccessKeysPresent(
        input.accountId,
        input.expectedPublicKeys,
        ACCOUNT_CREATE_BACKGROUND_KEY_VISIBILITY_AUDIT,
      );
      if (verified) {
        this.logger.info(
          `${input.contextLabel} final key visibility verified=true in ${Date.now() - startedAt}ms`,
        );
        return;
      }
      this.logger.warn(
        `${input.contextLabel} final key visibility is still pending after ${
          Date.now() - startedAt
        }ms`,
      );
    })().catch((error: unknown) => {
      this.logger.warn(`${input.contextLabel} final key visibility audit failed`, error);
    });
  }

  private async fetchTxContext(
    accountId: string,
    publicKey: string,
  ): Promise<{ nextNonce: string; blockHash: string }> {
    // Access key (if missing, assume nonce=0)
    let nonce = 0n;
    try {
      const ak = await this.nearClient.viewAccessKey(accountId, publicKey);
      nonce = BigInt(ak?.nonce ?? 0);
    } catch {
      nonce = 0n;
    }
    // Block
    const block = await this.nearClient.viewBlock({ finality: 'final' });
    const txBlockHash = block.header.hash;
    const nextNonce = (nonce + 1n).toString();
    return { nextNonce, blockHash: txBlockHash };
  }

  private async signWithPrivateKey(input: {
    nearPrivateKey: string;
    signerAccountId: string;
    receiverId: string;
    nonce: string;
    blockHash: string;
    actions: ActionArgsWasm[];
  }): Promise<SignedTransaction> {
    await this.ensureSignerWasm();
    const message = {
      type: WorkerRequestType.SignTransactionWithKeyPair,
      payload: {
        nearPrivateKey: input.nearPrivateKey,
        signerAccountId: input.signerAccountId,
        receiverId: input.receiverId,
        nonce: input.nonce,
        blockHash: input.blockHash,
        actions: input.actions,
      },
    };
    // uses wasm signer worker's SignTransactionWithKeyPair action (no WebAuthn/signing session required)
    let response: unknown;
    try {
      response = await handle_signer_message(message);
    } catch (e: unknown) {
      const msg = errorMessage(e);
      // Log payload for debugging (redacting private key)
      this.logger.error('Signer WASM rejected message:', {
        error: msg,
        payload: JSON.stringify(message, (key, value) =>
          key === 'nearPrivateKey' ? '[REDACTED]' : value,
        ),
      });

      // This specific error is intentionally redacted inside the WASM worker.
      // When it occurs in production, it's commonly due to a JS/WASM version mismatch
      // (the JS message schema changed but an old worker wasm is still deployed).
      if (msg.includes('Invalid payload for SIGN_TRANSACTION_WITH_KEYPAIR')) {
        throw new Error(
          `Signer WASM rejected SIGN_TRANSACTION_WITH_KEYPAIR payload: ${msg}. Rebuild + redeploy the relayer so the bundled \`wasm_signer_worker.js\` and \`wasm_signer_worker_bg.wasm\` come from the same build.`,
        );
      }
      throw e instanceof Error ? e : new Error(msg || 'Signing failed');
    }
    const { transaction, signature, borshBytes } =
      extractFirstSignedTransactionFromWorkerResponse(response);

    return new SignedTransaction({
      transaction: transaction,
      signature: signature,
      borsh_bytes: borshBytes,
    });
  }

  /**
   * Queue transactions to prevent nonce conflicts
   */
  private async queueTransaction<T>(operation: () => Promise<T>, description: string): Promise<T> {
    this.queueStats.pending++;
    this.logger.debug(
      `[AuthService] Queueing: ${description} (pending: ${this.queueStats.pending})`,
    );

    this.transactionQueue = this.transactionQueue
      .then(async () => {
        try {
          this.logger.debug(`[AuthService] Executing: ${description}`);
          const result = await operation();
          this.queueStats.completed++;
          this.queueStats.pending--;
          this.logger.debug(
            `[AuthService] Completed: ${description} (pending: ${this.queueStats.pending})`,
          );
          return result;
        } catch (error: any) {
          this.queueStats.failed++;
          this.queueStats.pending--;
          this.logger.error(
            `[AuthService] Failed: ${description} (failed: ${this.queueStats.failed}):`,
            errorMessage(error) || 'unknown error',
          );
          throw error;
        }
      })
      .catch((error) => {
        throw error;
      });

    return this.transactionQueue;
  }
}

interface WorkerSignedTransactionPayload {
  transaction: WasmTransaction;
  signature: WasmSignature;
  borshBytes?: number[];
  borsh_bytes?: number[];
}

function extractFirstSignedTransactionFromWorkerResponse(response: any): {
  transaction: WasmTransaction;
  signature: WasmSignature;
  borshBytes: number[];
} {
  const res = (typeof response === 'string' ? JSON.parse(response) : response) as
    | {
        type?: WorkerResponseType;
        payload?: { signedTransactions?: WorkerSignedTransactionPayload[]; error?: string };
      }
    | undefined;

  if (res?.type !== WorkerResponseType.SignTransactionWithKeyPairSuccess) {
    const errMsg = res?.payload?.error || 'Signing failed';
    throw new Error(errMsg);
  }

  const payload = res?.payload;
  const signedTxs = (payload?.signedTransactions ?? []) as WorkerSignedTransactionPayload[];
  if (!Array.isArray(signedTxs) || signedTxs.length === 0) {
    throw new Error('No signed transaction returned');
  }
  const first = signedTxs[0];
  const borshBytes = first?.borshBytes ?? first?.borsh_bytes;
  if (!Array.isArray(borshBytes)) {
    throw new Error('Missing borsh bytes');
  }
  return {
    transaction: first.transaction,
    signature: first.signature,
    borshBytes,
  };
}
