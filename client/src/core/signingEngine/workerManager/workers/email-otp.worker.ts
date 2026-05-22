import { initializeWasm, resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { errorMessage } from '@shared/utils/errors';
import { requireTrimmedString, toOptionalTrimmedNonEmptyString } from '@shared/utils/validation';
import {
  joinNormalizedUrl,
  normalizeNonNegativeInteger,
  normalizeOptionalNonEmptyString,
  normalizeOptionalTrimmedString,
  normalizePositiveInteger,
} from '@shared/utils/normalize';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  type WalletEmailOtpChannel,
} from '@shared/utils/emailOtpDomain';
import {
  ECDSA_HSS_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION,
  computeEcdsaHssRoleLocalFirstBootstrapRootProofDigest32,
  computeEcdsaHssRoleLocalRelayerKeyId,
  computeEcdsaHssRoleLocalThresholdKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  EMAIL_OTP_HKDF_SALTS,
  emailOtpEd25519RestoreInfoFields,
  emailOtpSigningSessionRestoreRootInfoFields,
  emailOtpThresholdEd25519HssInfoFields,
  encodeSigningSessionHkdfTuple,
} from '@shared/utils/signingSessionSeal';
import {
  thresholdEcdsaHssRoleLocalBootstrap,
  thresholdEcdsaHssRoleLocalExportShare,
  type ThresholdEcdsaHssRoleLocalBootstrapRequest,
  type ThresholdEcdsaHssRouteAuth,
} from '@/core/rpcClients/relayer/thresholdEcdsa';
import {
  decodeJwtPayloadRecord,
  type AppOrThresholdSessionAuth,
} from '@shared/utils/sessionTokens';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import {
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  toWalletSubjectId,
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEcdsaHssSessionPolicy,
  generateThresholdSessionId,
  generateWalletSigningSessionId,
  normalizeThresholdRuntimePolicyScope,
  parseThresholdRuntimePolicyScopeFromJwt,
  type ThresholdRuntimePolicyScope,
} from '@/core/signingEngine/threshold/sessionPolicy';
import {
  type ThresholdEcdsaHssRoleLocalClientState,
} from '@/core/signingEngine/interfaces/signing';
import {
  type EcdsaThresholdKeyId,
  type EmailOtpExistingKeyBootstrap,
  type EmailOtpRegistrationBootstrap,
  type SessionBootstrap,
  toEcdsaHssThresholdKeyId,
  toWalletSessionUserId,
  type WalletSessionUserId,
} from '@/core/signingEngine/session/identity/emailOtpHssIdentity';
import {
  buildSessionBootstrapKeyContext,
  buildEvmFamilyEcdsaSessionLanePolicy,
  deriveBaseEcdsaSubjectIdFromWalletId,
  type EvmFamilyEcdsaSessionLanePolicy,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import initEthSigner, {
  init_eth_signer,
  secp256k1_private_key_32_to_public_key_33,
  sign_secp256k1_recoverable,
} from '../../../../../../wasm/eth_signer/pkg/eth_signer.js';
import initHssClientSigner, {
  threshold_ecdsa_hss_role_local_client_bootstrap,
  threshold_ecdsa_hss_role_local_export_artifact,
} from '../../../../../../wasm/hss_client_signer/pkg/hss_client_signer.js';
import initEmailOtpRuntime, {
  derive_email_otp_ecdsa_client_root_share32_from_secret32,
  derive_email_otp_unlock_auth_seed_from_secret32,
  init_email_otp_runtime,
} from '../../../../../../wasm/email_otp_runtime/pkg/email_otp_runtime.js';
import initNearSignerRecoveryWasm, {
  email_recovery_chacha20poly1305_decrypt,
  email_recovery_chacha20poly1305_encrypt,
  init_worker as init_near_signer_recovery_worker,
} from '../../../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import { WorkerControlMessage, type EmailOtpWorkerProgressCode } from '../workerTypes';
import { postEmailOtpJson } from './email-otp/fetch';
import { getShamir3PassRuntime } from './shamir3pass/runtime';
import {
  authLaneToRouteAuth,
  emailOtpRoutePath,
  normalizeEmailOtpRoutePlan,
  type EmailOtpRoutePlan,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import {
  deleteEmailOtpDeviceEnrollmentEscrowRecord,
  readEmailOtpDeviceEnrollmentEscrowRecord,
  readSingleEmailOtpDeviceEnrollmentEscrowRecordForWallet,
  writeEmailOtpDeviceEnrollmentEscrowRecord,
} from './email-otp/deviceEnrollmentEscrowStore';
import {
  EMAIL_OTP_RECOVERY_WRAP_ALG,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
  encodeEmailOtpRecoveryWrappedEnrollmentAad,
  generateEmailOtpRecoveryKeySet,
  unwrapEmailOtpDeviceEnrollmentEscrow,
  wrapEmailOtpDeviceEnrollmentEscrow,
  type EmailOtpRecoveryWrapMetadata,
} from '@shared/utils/emailOtpRecoveryKey';

const EMAIL_OTP_UNLOCK_KEY_VERSION = 'email-otp-unlock-v1';
const EMAIL_OTP_DEVICE_ENROLLMENT_VERSION = '1';
const EMAIL_OTP_DEVICE_ENROLLMENT_SIGNING_ROOT_ID = 'email_otp_default_signing_root';
const EMAIL_OTP_DEVICE_ENROLLMENT_SIGNING_ROOT_VERSION = 'default';
const ECDSA_HSS_EXPORT_CONFIRMATION_DIGEST_VERSION =
  'ecdsa-hss:role-local:product-export-confirmation:v1';
const ECDSA_HSS_EXPORT_AUTHORIZATION_DIGEST_VERSION =
  'ecdsa-hss:role-local:product-export-authorization:v1';
const ECDSA_HSS_EXPORT_AUTH_TTL_MS = 60_000;
const ECDSA_HSS_KEY_PURPOSE = 'evm-signing';
const ECDSA_HSS_KEY_VERSION = 'v1';
const ECDSA_HSS_SIGNING_ROOT_VERSION_DEFAULT = 'default';

function emailOtpDeviceEnrollmentId(walletId: string, authSubjectId: string): string {
  return `email-otp-device-enrollment-v1:${walletId}:${authSubjectId}`;
}

function readJwtPayloadObject(jwtRaw: unknown): Record<string, unknown> | null {
  const jwt = String(jwtRaw || '').trim();
  if (!jwt) return null;
  const parts = jwt.split('.');
  if (parts.length < 2) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[1] || '')));
    return payload && typeof payload === 'object' && !Array.isArray(payload)
      ? (payload as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function readAppSessionUserIdFromRoutePlan(routePlan: EmailOtpRoutePlan): string {
  const lane = routePlan.authLane;
  if (lane.kind !== 'app_session') return '';
  const payload = readJwtPayloadObject(lane.jwt);
  return readOptionalString(payload?.sub) || '';
}

function resolveEmailOtpAuthSubjectId(args: {
  walletId: string;
  userId?: unknown;
  routePlan: EmailOtpRoutePlan;
}): string {
  const sessionUserId = readAppSessionUserIdFromRoutePlan(args.routePlan);
  if (sessionUserId) return sessionUserId;
  return readOptionalString(args.userId) || args.walletId;
}

type EmailOtpRecoveryWrappedEnrollmentEscrowPayload = {
  version: 'email_otp_recovery_wrapped_enrollment_escrow_v1';
  alg: typeof EMAIL_OTP_RECOVERY_WRAP_ALG;
  secretKind: typeof EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND;
  escrowKind: typeof EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND;
  walletId: string;
  userId: string;
  authSubjectId: string;
  authMethod: 'google_sso_email_otp';
  enrollmentId: string;
  enrollmentVersion: string;
  enrollmentSealKeyVersion: string;
  signingRootId: string;
  signingRootVersion: string;
  recoveryKeyId: string;
  recoveryKeyStatus: 'active';
  nonceB64u: string;
  wrappedDeviceEnrollmentEscrowB64u: string;
  aadHashB64u: string;
  issuedAtMs: number;
  updatedAtMs: number;
};

type EmailOtpWorkerRequest =
  | {
      id: string;
      type: 'requestEmailOtpChallenge';
      payload: {
        relayUrl: string;
        walletId: string;
        routePlan: EmailOtpRoutePlan;
        otpChannel?: WalletEmailOtpChannel;
      };
    }
  | {
      id: string;
      type: 'requestEmailOtpEnrollmentChallenge';
      payload: {
        relayUrl: string;
        walletId: string;
        routePlan: EmailOtpRoutePlan;
        otpChannel?: WalletEmailOtpChannel;
      };
    }
  | {
      id: string;
      type: 'enrollEmailOtpWallet';
      payload: {
        relayUrl: string;
        walletId: string;
        userId?: string;
        challengeId?: string;
        otpCode: string;
        shamirPrimeB64u: string;
        routePlan: EmailOtpRoutePlan;
        otpChannel?: WalletEmailOtpChannel;
        clientSecret32?: ArrayBuffer;
      };
    }
  | {
      id: string;
      type: 'verifyEmailOtpCode';
      payload: {
        relayUrl: string;
        walletId: string;
        challengeId: string;
        otpCode: string;
        routePlan: EmailOtpRoutePlan;
        otpChannel?: WalletEmailOtpChannel;
      };
    }
  | {
      id: string;
      type: 'restoreEmailOtpDeviceEnrollmentEscrow';
      payload: {
        relayUrl: string;
        walletId: string;
        userId?: string;
        challengeId: string;
        otpCode: string;
        recoveryKey: string;
        shamirPrimeB64u: string;
        routePlan: EmailOtpRoutePlan;
        otpChannel?: WalletEmailOtpChannel;
      };
    }
  | {
      id: string;
      type: 'removeEmailOtpDeviceEnrollmentEscrowFromDevice';
      payload: {
        walletId: string;
        userId?: string;
        enrollmentId?: string;
      };
    }
  | {
      id: string;
      type: 'loginWithEmailOtpWallet';
      payload: {
        relayUrl: string;
        walletId: string;
        userId?: string;
        challengeId?: string;
        otpCode: string;
        shamirPrimeB64u: string;
        routePlan: EmailOtpRoutePlan;
        otpChannel?: WalletEmailOtpChannel;
        runtimePolicyScope?: ThresholdRuntimePolicyScope;
      };
    }
  | {
      id: string;
      type: 'bootstrapEmailOtpEcdsaSessionsFromClientRootShare';
      payload: {
        relayUrl: string;
        walletId: string;
        subjectId: WalletSubjectId;
        walletSessionUserId: string;
        userId?: string;
        rpId: string;
        clientRootShare32B64u: string;
        chainTarget: ThresholdEcdsaChainTarget;
        publicationChainTargets: ThresholdEcdsaChainTarget[];
        keyHandle?: string;
        roleLocalKeyIdentity?: {
          ecdsaThresholdKeyId: string;
          signingRootId: string;
          signingRootVersion: string;
          relayerKeyId: string;
        };
        participantIds?: number[];
        sessionKind?: 'jwt' | 'cookie';
        sessionId?: string;
        walletSigningSessionId?: string;
        routeAuth?: AppOrThresholdSessionAuth;
        ttlMs?: number;
        remainingUses?: number;
        runtimePolicyScope?: ThresholdRuntimePolicyScope;
        includeEcdsaExportArtifact?: boolean;
      };
    }
  | {
      id: string;
      type: 'recoverEmailOtpEd25519ExportPrfFirst';
      payload: {
        relayUrl: string;
        walletId: string;
        userId?: string;
        challengeId: string;
        otpCode: string;
        shamirPrimeB64u: string;
        routePlan: EmailOtpRoutePlan;
        otpChannel?: WalletEmailOtpChannel;
        runtimePolicyScope?: ThresholdRuntimePolicyScope;
      };
    }
  | {
      id: string;
      type: 'getEmailOtpWarmSessionStatus';
      payload: {
        sessionId: string;
      };
    }
  | {
      id: string;
      type: 'claimEmailOtpWarmSessionMaterial';
      payload: {
        sessionId: string;
        uses?: number;
        consume?: boolean;
      };
    }
  | {
      id: string;
      type: 'consumeEmailOtpWarmSessionUses';
      payload: {
        sessionId: string;
        uses?: number;
      };
    }
  | {
      id: string;
      type: 'sealEmailOtpWarmSessionMaterial';
      payload: {
        sessionId: string;
        transport: {
          relayerUrl: string;
          thresholdSessionAuthToken?: string;
          keyVersion?: string;
          shamirPrimeB64u?: string;
        };
      };
    }
  | {
      id: string;
      type: 'rehydrateEmailOtpEcdsaWarmSessionMaterial';
      payload: {
        sealedSecretB64u: string;
        remainingUses: number;
        expiresAtMs: number;
        transport: {
          relayerUrl: string;
          thresholdSessionAuthToken?: string;
          keyVersion?: string;
          shamirPrimeB64u?: string;
        };
        restore: {
          sessionId: string;
          walletId: string;
          rpId: string;
          chainTarget: ThresholdEcdsaChainTarget;
          walletSigningSessionId: string;
          keyHandle: string;
          relayerKeyId: string;
          participantIds: number[];
          sessionKind?: 'jwt' | 'cookie';
          runtimePolicyScope?: ThresholdRuntimePolicyScope;
          ed25519?: {
            sessionId: string;
            signingRootId: string;
            signingRootVersion?: string;
            relayerKeyId: string;
            participantIds: number[];
          };
        };
      };
    }
  | {
      id: string;
      type: 'claimEmailOtpEcdsaSigningShare';
      payload: {
        sessionId: string;
      };
    }
  | {
      id: string;
      type: 'clearEmailOtpWarmSessionMaterial';
      payload: {
        sessionId: string;
      };
    }
  | {
      id: string;
      type: 'exportThresholdEcdsaHssKeyWithEmailOtpAuthorization';
      payload: {
        relayUrl: string;
        walletId: string;
        userId: string;
        challengeId: string;
        otpCode: string;
        shamirPrimeB64u: string;
        routePlan: EmailOtpRoutePlan;
        rpId: string;
        thresholdSessionAuthToken?: string;
        sessionKind?: 'jwt' | 'cookie';
        subjectId: WalletSubjectId;
        ecdsaThresholdKeyId: string;
        signingRootId: string;
        signingRootVersion?: string;
        relayerKeyId: string;
        roleLocalState: ThresholdEcdsaHssRoleLocalClientState;
        thresholdSessionId: string;
        walletSigningSessionId: string;
        thresholdExpiresAtMs: number;
        participantIds: number[];
        keyHandle: string;
        runtimePolicyScope?: ThresholdRuntimePolicyScope;
      };
    };

type WorkerErrorPayload = {
  message: string;
  code?: string;
  coreCode?: string;
};

type EmailOtpWarmSessionEntry = {
  clientRootShare32: Uint8Array;
  signingSessionSecret32: Uint8Array;
  clientAdditiveShare32?: Uint8Array;
  expiresAtMs: number;
  remainingUses: number;
};

type EmailOtpWarmSessionStatusResult =
  | { ok: true; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

type EmailOtpWarmSessionClaimResult =
  | { ok: true; prfFirstB64u: string; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

type EmailOtpWarmSessionConsumeResult =
  | { ok: true; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

type EmailOtpWarmSessionSealResult =
  | {
      ok: true;
      sealedSecretB64u: string;
      keyVersion?: string;
      remainingUses: number;
      expiresAtMs: number;
    }
  | { ok: false; code: string; message: string };

type EmailOtpEcdsaWarmSessionRehydrateResult =
  | {
      ok: true;
      bootstrap: ThresholdEcdsaSessionBootstrapResult;
      remainingUses: number;
      expiresAtMs: number;
      ed25519RestoreSeedB64u?: string;
    }
  | { ok: false; code: string; message: string };

type ExactEmailOtpEcdsaWarmSessionEd25519Restore = {
  sessionId: string;
  signingRootId: string;
  signingRootVersion?: string;
  relayerKeyId: string;
  participantIds: number[];
};

type ExactEmailOtpEcdsaWarmSessionRestore = {
  sessionId: string;
  walletId: string;
  userId: string;
  rpId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  walletSigningSessionId: string;
  keyHandle: string;
  keyContext: ReturnType<typeof buildSessionBootstrapKeyContext>;
  relayerKeyId: string;
  participantIds: number[];
  sessionKind: 'jwt' | 'cookie';
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  ed25519?: ExactEmailOtpEcdsaWarmSessionEd25519Restore;
};

type ExactEmailOtpEcdsaWarmSessionTransport = {
  relayerUrl: string;
  thresholdSessionAuthToken?: string;
  keyVersion?: string;
  shamirPrimeB64u: string;
};

type ExactEmailOtpEcdsaWarmSessionRehydrateArgs = {
  sealedSecretB64u: string;
  remainingUses: number;
  expiresAtMs: number;
  transport: ExactEmailOtpEcdsaWarmSessionTransport;
  restore: ExactEmailOtpEcdsaWarmSessionRestore;
};

type ParseEmailOtpEcdsaWarmSessionRehydrateArgsResult =
  | { kind: 'parsed'; value: ExactEmailOtpEcdsaWarmSessionRehydrateArgs }
  | { kind: 'error'; error: EmailOtpEcdsaWarmSessionRehydrateResult };

type SigningSessionSealTransport = {
  relayerUrl: string;
  thresholdSessionAuthToken?: string;
  keyVersion?: string;
  shamirPrimeB64u?: string;
};

type SigningSessionSealRouteResult =
  | {
      ok: true;
      ciphertext: string;
      keyVersion?: string;
      expiresAtMs?: number;
      remainingUses?: number;
    }
  | { ok: false; code: string; message: string };

type EmailOtpEcdsaSigningShareClaimResult =
  | { ok: true; clientSigningShare32: ArrayBuffer; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

type EmailOtpThresholdEcdsaBootstrapResult = ThresholdEcdsaSessionBootstrapResult & {
  emailOtpClientAdditiveShare32: Uint8Array;
};

const emailOtpWarmSessions = new Map<string, EmailOtpWarmSessionEntry>();
const signingSessionSealApplyInFlight = new Map<string, Promise<EmailOtpWarmSessionSealResult>>();
const signingSessionSealRemoveInFlight = new Map<
  string,
  Promise<EmailOtpEcdsaWarmSessionRehydrateResult>
>();
const SIGNING_SESSION_SEAL_BASE_PATH = '/threshold/signing-session-seal';

function parseEmailOtpEcdsaWarmSessionRehydrateArgs(args: {
  sealedSecretB64u: string;
  remainingUses: number;
  expiresAtMs: number;
  transport: SigningSessionSealTransport;
  restore: {
    sessionId: string;
    walletId: string;
    rpId: string;
    chainTarget: ThresholdEcdsaChainTarget;
    walletSigningSessionId: string;
    keyHandle: string;
    relayerKeyId: string;
    participantIds: number[];
    sessionKind?: 'jwt' | 'cookie';
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    ed25519?: {
      sessionId: string;
      signingRootId: string;
      signingRootVersion?: string;
      relayerKeyId: string;
      participantIds: number[];
    };
  };
}): ParseEmailOtpEcdsaWarmSessionRehydrateArgsResult {
  const sessionId = normalizeOptionalTrimmedString(args.restore.sessionId);
  if (!sessionId) {
    return {
      kind: 'error',
      error: { ok: false, code: 'invalid_args', message: 'Missing threshold sessionId' },
    };
  }
  const sealedSecretB64u = normalizeOptionalTrimmedString(args.sealedSecretB64u);
  if (!sealedSecretB64u) {
    return {
      kind: 'error',
      error: { ok: false, code: 'invalid_args', message: 'Missing sealedSecretB64u' },
    };
  }
  const shamirPrimeB64u = normalizeOptionalNonEmptyString(args.transport.shamirPrimeB64u);
  if (!shamirPrimeB64u) {
    return {
      kind: 'error',
      error: {
        ok: false,
        code: 'invalid_args',
        message: 'Missing shamirPrimeB64u for signing-session restore',
      },
    };
  }
  const participantIds = normalizeThresholdEd25519ParticipantIds(args.restore.participantIds);
  if (!participantIds) {
    return {
      kind: 'error',
      error: { ok: false, code: 'invalid_args', message: 'Missing participantIds for ECDSA restore' },
    };
  }
  const walletId = readString(args.restore.walletId, 'walletId');
  const rpId = readString(args.restore.rpId, 'rpId');
  let ed25519Restore: ExactEmailOtpEcdsaWarmSessionEd25519Restore | undefined;
  if (args.restore.ed25519) {
    const ed25519ParticipantIds = normalizeThresholdEd25519ParticipantIds(
      args.restore.ed25519.participantIds,
    );
    if (!ed25519ParticipantIds) {
      return {
        kind: 'error',
        error: {
          ok: false,
          code: 'invalid_args',
          message: 'Missing participantIds for Ed25519 restore',
        },
      };
    }
    ed25519Restore = {
      sessionId: readString(args.restore.ed25519.sessionId, 'ed25519.sessionId'),
      signingRootId: readString(args.restore.ed25519.signingRootId, 'ed25519.signingRootId'),
      ...(args.restore.ed25519.signingRootVersion
        ? { signingRootVersion: args.restore.ed25519.signingRootVersion }
        : {}),
      relayerKeyId: readString(args.restore.ed25519.relayerKeyId, 'ed25519.relayerKeyId'),
      participantIds: ed25519ParticipantIds,
    };
  }
  return {
    kind: 'parsed',
    value: {
      sealedSecretB64u,
      remainingUses: Math.max(0, Math.floor(Number(args.remainingUses) || 0)),
      expiresAtMs: Math.max(0, Math.floor(Number(args.expiresAtMs) || 0)),
      transport: {
        relayerUrl: readString(args.transport.relayerUrl, 'relayerUrl'),
        ...(args.transport.thresholdSessionAuthToken
          ? { thresholdSessionAuthToken: args.transport.thresholdSessionAuthToken }
          : {}),
        ...(args.transport.keyVersion ? { keyVersion: args.transport.keyVersion } : {}),
        shamirPrimeB64u,
      },
      restore: {
        sessionId,
        walletId,
        userId: walletId,
        rpId,
        chainTarget: args.restore.chainTarget,
        walletSigningSessionId: readString(
          args.restore.walletSigningSessionId,
          'walletSigningSessionId',
        ),
        keyHandle: readString(args.restore.keyHandle, 'keyHandle'),
        keyContext: buildSessionBootstrapKeyContext({
          walletId,
          rpId,
          participantIds,
        }),
        relayerKeyId: readString(args.restore.relayerKeyId, 'relayerKeyId'),
        participantIds,
        sessionKind: args.restore.sessionKind || 'jwt',
        ...(args.restore.runtimePolicyScope
          ? { runtimePolicyScope: args.restore.runtimePolicyScope }
          : {}),
        ...(ed25519Restore ? { ed25519: ed25519Restore } : {}),
      },
    },
  };
}

function asWorkerErrorPayload(err: unknown): WorkerErrorPayload {
  if (err && typeof err === 'object') {
    const message =
      typeof (err as { message?: unknown }).message === 'string'
        ? String((err as { message?: string }).message).trim()
        : '';
    const code =
      typeof (err as { code?: unknown }).code === 'string'
        ? String((err as { code?: string }).code).trim()
        : '';
    const coreCode =
      typeof (err as { coreCode?: unknown }).coreCode === 'string'
        ? String((err as { coreCode?: string }).coreCode).trim()
        : '';
    return {
      message: message || errorMessage(err),
      ...(code ? { code } : {}),
      ...(coreCode ? { coreCode } : {}),
    };
  }
  return { message: errorMessage(err) };
}

function readString(value: unknown, label: string): string {
  return requireTrimmedString(value, label);
}

function readOptionalString(value: unknown): string | undefined {
  return toOptionalTrimmedNonEmptyString(value);
}

function randomB64u32(): string {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi || typeof cryptoApi.getRandomValues !== 'function') {
    throw new Error('crypto.getRandomValues is required for threshold ECDSA export');
  }
  return base64UrlEncode(cryptoApi.getRandomValues(new Uint8Array(32)));
}

async function digestB64u(input: unknown): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(input)));
}

function readRoutePlan(value: unknown, label: string): EmailOtpRoutePlan {
  const plan = normalizeEmailOtpRoutePlan(value);
  if (!plan) throw new Error(`${label} requires Email OTP routePlan`);
  return plan;
}

function readEcdsaPublicationChainTargets(args: {
  primaryChainTarget: ThresholdEcdsaChainTarget;
  publicationChainTargets: unknown;
}): ThresholdEcdsaChainTarget[] {
  if (!Array.isArray(args.publicationChainTargets) || !args.publicationChainTargets.length) {
    throw new Error('Email OTP ECDSA bootstrap requires publicationChainTargets');
  }
  const targets = args.publicationChainTargets.map((target) =>
    thresholdEcdsaChainTargetFromRequest(target),
  );
  if (!thresholdEcdsaChainTargetsEqual(targets[0], args.primaryChainTarget)) {
    throw new Error('Email OTP ECDSA primary target must be first publication target');
  }
  const seen = new Set<string>();
  for (const target of targets) {
    const key = thresholdEcdsaChainTargetKey(target);
    if (seen.has(key)) {
      throw new Error(`Email OTP ECDSA duplicate publication target: ${key}`);
    }
    seen.add(key);
  }
  return targets;
}

function routePlanSessionAuth(plan: EmailOtpRoutePlan): AppOrThresholdSessionAuth | undefined {
  return authLaneToRouteAuth(plan.authLane);
}

function parseSigningSessionSealTransport(value: unknown): SigningSessionSealTransport | null {
  const transport = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!transport) return null;
  const relayerUrl = normalizeOptionalNonEmptyString(transport.relayerUrl);
  if (!relayerUrl) return null;
  const thresholdSessionAuthToken = normalizeOptionalNonEmptyString(
    transport.thresholdSessionAuthToken,
  );
  const keyVersion = normalizeOptionalNonEmptyString(transport.keyVersion);
  const shamirPrimeB64u = normalizeOptionalNonEmptyString(transport.shamirPrimeB64u);
  return {
    relayerUrl,
    ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
    ...(keyVersion ? { keyVersion } : {}),
    ...(shamirPrimeB64u ? { shamirPrimeB64u } : {}),
  };
}

function parseSigningSessionSealRouteResult(value: unknown): SigningSessionSealRouteResult {
  const result = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!result || typeof result.ok !== 'boolean') {
    return {
      ok: false,
      code: 'invalid_response',
      message: 'Invalid signing-session seal response',
    };
  }
  if (!result.ok) {
    return {
      ok: false,
      code: typeof result.code === 'string' ? result.code : 'request_failed',
      message:
        typeof result.message === 'string' ? result.message : 'Signing-session seal request failed',
    };
  }
  const ciphertext = normalizeOptionalTrimmedString(result.ciphertext);
  if (!ciphertext) {
    return {
      ok: false,
      code: 'invalid_response',
      message: 'Missing ciphertext in signing-session seal response',
    };
  }
  const keyVersion = normalizeOptionalNonEmptyString(result.keyVersion);
  const expiresAtMs = normalizePositiveInteger(result.expiresAtMs);
  const remainingUses = normalizeNonNegativeInteger(result.remainingUses);
  return {
    ok: true,
    ciphertext,
    ...(keyVersion ? { keyVersion } : {}),
    ...(expiresAtMs != null ? { expiresAtMs } : {}),
    ...(remainingUses != null ? { remainingUses } : {}),
  };
}

function makeSigningSessionSealSingleFlightKey(args: {
  operation: 'apply-server-seal' | 'remove-server-seal';
  sessionId: string;
  relayerUrl: string;
  keyVersion?: string;
  shamirPrimeB64u?: string;
  payloadB64u?: string;
}): string {
  const operation =
    args.operation === 'remove-server-seal' ? 'remove-server-seal' : 'apply-server-seal';
  return [
    operation,
    normalizeOptionalTrimmedString(args.sessionId) || '',
    normalizeOptionalTrimmedString(args.relayerUrl) || '',
    normalizeOptionalNonEmptyString(args.keyVersion) || '',
    normalizeOptionalNonEmptyString(args.shamirPrimeB64u) || '',
    normalizeOptionalNonEmptyString(args.payloadB64u) || '',
  ].join('|');
}

async function callSigningSessionSealRoute(args: {
  operation: 'apply-server-seal' | 'remove-server-seal';
  transport: SigningSessionSealTransport;
  thresholdSessionId: string;
  ciphertext: string;
  keyVersion?: string;
}): Promise<SigningSessionSealRouteResult> {
  const operation =
    args.operation === 'remove-server-seal' ? 'remove-server-seal' : 'apply-server-seal';
  const url = joinNormalizedUrl(
    args.transport.relayerUrl,
    `${SIGNING_SESSION_SEAL_BASE_PATH}/${operation}`,
  );
  try {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const thresholdSessionAuthToken = normalizeOptionalNonEmptyString(
      args.transport.thresholdSessionAuthToken,
    );
    const keyVersion = normalizeOptionalNonEmptyString(args.keyVersion);
    if (thresholdSessionAuthToken) headers.Authorization = `Bearer ${thresholdSessionAuthToken}`;
    const response = await fetch(url, {
      method: 'POST',
      credentials: thresholdSessionAuthToken ? 'omit' : 'include',
      headers,
      body: JSON.stringify({
        thresholdSessionId: args.thresholdSessionId,
        ciphertext: args.ciphertext,
        ...(keyVersion ? { keyVersion } : {}),
      }),
    });
    const data = await response.json().catch(() => null);
    const parsed = parseSigningSessionSealRouteResult(data);
    if (!response.ok && parsed.ok) {
      return {
        ok: false,
        code: 'http_error',
        message: `Signing-session seal route returned HTTP ${response.status}`,
      };
    }
    return parsed;
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'network_error',
      message:
        error instanceof Error
          ? error.message
          : String(error || 'Signing-session seal request failed'),
    };
  }
}

function resolvePolicyFromServerAndLocal(args: {
  localRemainingUses: number;
  localExpiresAtMs: number;
  serverRemainingUses?: number;
  serverExpiresAtMs?: number;
}):
  | { ok: true; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string } {
  const localRemainingUses = Math.max(0, Math.floor(Number(args.localRemainingUses) || 0));
  const localExpiresAtMs = Math.max(0, Math.floor(Number(args.localExpiresAtMs) || 0));
  const serverRemainingUses =
    normalizeNonNegativeInteger(args.serverRemainingUses) ?? localRemainingUses;
  const serverExpiresAtMs = normalizePositiveInteger(args.serverExpiresAtMs) || localExpiresAtMs;
  const remainingUses = Math.min(localRemainingUses, serverRemainingUses);
  const expiresAtMs = Math.min(localExpiresAtMs, serverExpiresAtMs);
  if (remainingUses <= 0) {
    return {
      ok: false,
      code: 'exhausted',
      message: 'Email OTP warm-session material exhausted',
    };
  }
  if (expiresAtMs <= Date.now()) {
    return {
      ok: false,
      code: 'expired',
      message: 'Email OTP warm-session material expired',
    };
  }
  return { ok: true, remainingUses, expiresAtMs };
}

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}

async function deriveEmailOtpEd25519PrfFirstB64u(args: {
  clientSecret32: Uint8Array;
  walletId: string;
  userId: string;
}): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error('crypto.subtle is unavailable for Email OTP Ed25519 derivation');
  }
  const salt = new TextEncoder().encode(EMAIL_OTP_HKDF_SALTS.thresholdEd25519Hss);
  const info = encodeSigningSessionHkdfTuple(emailOtpThresholdEd25519HssInfoFields(args));
  const key = await subtle.importKey('raw', args.clientSecret32, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, 256);
  const seed32 = new Uint8Array(bits);
  try {
    return base64UrlEncode(seed32);
  } finally {
    zeroizeBytes(seed32);
  }
}

async function hkdfSha256Bytes(args: {
  ikm: Uint8Array;
  salt: string;
  fields: string[];
}): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error('crypto.subtle is unavailable for Email OTP signing-session restore');
  }
  const salt = new TextEncoder().encode(args.salt);
  const info = encodeSigningSessionHkdfTuple(args.fields);
  const key = await subtle.importKey('raw', args.ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(
    await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, 256),
  );
}

async function deriveEmailOtpEd25519RestoreSeedB64u(args: {
  signingSessionSecret32: Uint8Array;
  walletId: string;
  userId: string;
  signingRootId: string;
  signingRootVersion?: string;
  walletSigningSessionId: string;
  ed25519ThresholdSessionId: string;
  relayerKeyId: string;
  participantIds?: number[];
}): Promise<string> {
  const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds);
  if (!participantIds) {
    throw new Error('Email OTP Ed25519 restore requires participantIds');
  }
  let sessionRestoreRoot: Uint8Array | null = await hkdfSha256Bytes({
    ikm: args.signingSessionSecret32,
    salt: EMAIL_OTP_HKDF_SALTS.signingSessionRestoreRoot,
    fields: emailOtpSigningSessionRestoreRootInfoFields(args),
  });
  let ed25519RestoreSeed32: Uint8Array | null = null;
  try {
    ed25519RestoreSeed32 = await hkdfSha256Bytes({
      ikm: sessionRestoreRoot,
      salt: EMAIL_OTP_HKDF_SALTS.thresholdEd25519RestoreSeed,
      fields: emailOtpEd25519RestoreInfoFields({
        ...args,
        participantIds,
      }),
    });
    return base64UrlEncode(ed25519RestoreSeed32);
  } finally {
    zeroizeBytes(sessionRestoreRoot);
    zeroizeBytes(ed25519RestoreSeed32);
    sessionRestoreRoot = null;
    ed25519RestoreSeed32 = null;
  }
}

function deleteEmailOtpWarmSession(sessionId: string): void {
  const entry = emailOtpWarmSessions.get(sessionId);
  if (entry) {
    zeroizeBytes(entry.clientRootShare32);
    zeroizeBytes(entry.signingSessionSecret32);
    zeroizeBytes(entry.clientAdditiveShare32);
    emailOtpWarmSessions.delete(sessionId);
  }
}

function readEmailOtpWarmSessionStatus(sessionIdRaw: unknown): EmailOtpWarmSessionStatusResult {
  const sessionId = String(sessionIdRaw || '').trim();
  if (!sessionId) {
    return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
  }
  const entry = emailOtpWarmSessions.get(sessionId);
  if (!entry) {
    return {
      ok: false,
      code: 'not_found',
      message: 'Email OTP warm-session material is not available',
    };
  }
  if (Date.now() >= entry.expiresAtMs) {
    deleteEmailOtpWarmSession(sessionId);
    return {
      ok: false,
      code: 'expired',
      message: 'Email OTP warm-session material expired',
    };
  }
  if (entry.remainingUses <= 0) {
    deleteEmailOtpWarmSession(sessionId);
    return {
      ok: false,
      code: 'exhausted',
      message: 'Email OTP warm-session material exhausted',
    };
  }
  return {
    ok: true,
    remainingUses: entry.remainingUses,
    expiresAtMs: entry.expiresAtMs,
  };
}

function putEmailOtpWarmSessionMaterial(args: {
  sessionId: string;
  clientRootShare32: Uint8Array;
  signingSessionSecret32: Uint8Array;
  clientAdditiveShare32?: Uint8Array;
  expiresAtMs: number;
  remainingUses: number;
}): void {
  const sessionId = readString(args.sessionId, 'sessionId');
  const expiresAtMs = Math.floor(Number(args.expiresAtMs) || 0);
  const remainingUses = Math.floor(Number(args.remainingUses) || 0);
  if (!(args.clientRootShare32 instanceof Uint8Array) || args.clientRootShare32.length !== 32) {
    throw new Error('clientRootShare32 must contain 32 bytes');
  }
  if (
    !(args.signingSessionSecret32 instanceof Uint8Array) ||
    args.signingSessionSecret32.length !== 32
  ) {
    throw new Error('signingSessionSecret32 must contain 32 bytes');
  }
  if (
    args.clientAdditiveShare32 &&
    (!(args.clientAdditiveShare32 instanceof Uint8Array) ||
      args.clientAdditiveShare32.length !== 32)
  ) {
    throw new Error('clientAdditiveShare32 must contain 32 bytes');
  }
  if (expiresAtMs <= Date.now() || remainingUses <= 0) {
    throw new Error('Invalid Email OTP warm-session ttl or remainingUses');
  }
  deleteEmailOtpWarmSession(sessionId);
  emailOtpWarmSessions.set(sessionId, {
    clientRootShare32: Uint8Array.from(args.clientRootShare32),
    signingSessionSecret32: Uint8Array.from(args.signingSessionSecret32),
    ...(args.clientAdditiveShare32
      ? { clientAdditiveShare32: Uint8Array.from(args.clientAdditiveShare32) }
      : {}),
    expiresAtMs,
    remainingUses,
  });
}

function claimEmailOtpWarmSessionMaterial(args: {
  sessionId: string;
  uses?: number;
  consume?: boolean;
}): EmailOtpWarmSessionClaimResult {
  const sessionId = String(args.sessionId || '').trim();
  const status = readEmailOtpWarmSessionStatus(sessionId);
  if (!status.ok) return status;
  const entry = emailOtpWarmSessions.get(sessionId);
  if (!entry) {
    return {
      ok: false,
      code: 'not_found',
      message: 'Email OTP warm-session material is not available',
    };
  }
  const uses = Math.max(1, Math.floor(Number(args.uses) || 1));
  if (entry.remainingUses < uses) {
    return {
      ok: false,
      code: 'exhausted',
      message: 'Email OTP warm-session material exhausted',
    };
  }
  const prfFirstB64u = base64UrlEncode(entry.clientRootShare32);
  const consume = args.consume !== false;
  if (consume) {
    entry.remainingUses -= uses;
  }
  const remainingUses = entry.remainingUses;
  const expiresAtMs = entry.expiresAtMs;
  if (consume) {
    if (remainingUses <= 0) {
      deleteEmailOtpWarmSession(sessionId);
    } else {
      emailOtpWarmSessions.set(sessionId, entry);
    }
  }
  return {
    ok: true,
    prfFirstB64u,
    remainingUses,
    expiresAtMs,
  };
}

function consumeEmailOtpWarmSessionUses(args: {
  sessionId: string;
  uses?: number;
}): EmailOtpWarmSessionConsumeResult {
  const sessionId = String(args.sessionId || '').trim();
  const status = readEmailOtpWarmSessionStatus(sessionId);
  if (!status.ok) return status;
  const entry = emailOtpWarmSessions.get(sessionId);
  if (!entry) {
    return {
      ok: false,
      code: 'not_found',
      message: 'Email OTP warm-session material is not available',
    };
  }
  const uses = Math.max(1, Math.floor(Number(args.uses) || 1));
  if (entry.remainingUses < uses) {
    return {
      ok: false,
      code: 'exhausted',
      message: 'Email OTP warm-session material exhausted',
    };
  }
  entry.remainingUses -= uses;
  const remainingUses = entry.remainingUses;
  const expiresAtMs = entry.expiresAtMs;
  if (remainingUses <= 0) {
    deleteEmailOtpWarmSession(sessionId);
  } else {
    emailOtpWarmSessions.set(sessionId, entry);
  }
  return {
    ok: true,
    remainingUses,
    expiresAtMs,
  };
}

async function sealEmailOtpWarmSessionMaterial(args: {
  sessionId: string;
  transport: SigningSessionSealTransport;
}): Promise<EmailOtpWarmSessionSealResult> {
  const sessionId = String(args.sessionId || '').trim();
  if (!sessionId) {
    return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
  }
  const shamirPrimeB64u = normalizeOptionalNonEmptyString(args.transport.shamirPrimeB64u);
  if (!shamirPrimeB64u) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing shamirPrimeB64u for signing-session seal',
    };
  }
  const status = readEmailOtpWarmSessionStatus(sessionId);
  if (!status.ok) return status;
  const entry = emailOtpWarmSessions.get(sessionId);
  if (!entry) {
    return {
      ok: false,
      code: 'not_found',
      message: 'Email OTP warm-session material is not available',
    };
  }
  const payloadB64u = base64UrlEncode(entry.signingSessionSecret32);
  const singleFlightKey = makeSigningSessionSealSingleFlightKey({
    operation: 'apply-server-seal',
    sessionId,
    relayerUrl: args.transport.relayerUrl,
    keyVersion: args.transport.keyVersion,
    shamirPrimeB64u,
    payloadB64u,
  });
  const inFlight = signingSessionSealApplyInFlight.get(singleFlightKey);
  if (inFlight) return await inFlight;

  const task = (async (): Promise<EmailOtpWarmSessionSealResult> => {
    try {
      const runtime = await getShamir3PassRuntime();
      const clientKeyHandle = await runtime.createClientKeyHandle({ shamirPrimeB64u });
      try {
        const clientEncryptedCiphertext = await runtime.addClientSealBytesWithKeyHandle({
          ciphertext: entry.signingSessionSecret32,
          keyHandle: clientKeyHandle.keyHandle,
        });
        const applied = await callSigningSessionSealRoute({
          operation: 'apply-server-seal',
          transport: args.transport,
          thresholdSessionId: sessionId,
          ciphertext: readString(clientEncryptedCiphertext, 'clientEncryptedCiphertext'),
          keyVersion: args.transport.keyVersion,
        });
        if (!applied.ok) return applied;
        const sealedSecretB64u = await runtime.removeClientSealWithKeyHandle({
          ciphertextB64u: applied.ciphertext,
          keyHandle: clientKeyHandle.keyHandle,
        });
        const policy = resolvePolicyFromServerAndLocal({
          localRemainingUses: entry.remainingUses,
          localExpiresAtMs: entry.expiresAtMs,
          serverRemainingUses: applied.remainingUses,
          serverExpiresAtMs: applied.expiresAtMs,
        });
        if (!policy.ok) {
          deleteEmailOtpWarmSession(sessionId);
          return policy;
        }
        emailOtpWarmSessions.set(sessionId, {
          clientRootShare32: entry.clientRootShare32,
          signingSessionSecret32: entry.signingSessionSecret32,
          ...(entry.clientAdditiveShare32
            ? { clientAdditiveShare32: entry.clientAdditiveShare32 }
            : {}),
          remainingUses: policy.remainingUses,
          expiresAtMs: policy.expiresAtMs,
        });
        const keyVersion = normalizeOptionalNonEmptyString(applied.keyVersion);
        return {
          ok: true,
          sealedSecretB64u: readString(sealedSecretB64u, 'sealedSecretB64u'),
          ...(keyVersion ? { keyVersion } : {}),
          remainingUses: policy.remainingUses,
          expiresAtMs: policy.expiresAtMs,
        };
      } finally {
        await runtime
          .destroyClientKeyHandle({ keyHandle: clientKeyHandle.keyHandle })
          .catch(() => undefined);
      }
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message:
          error instanceof Error
            ? error.message
            : String(error || 'Failed to apply signing-session seal'),
      };
    }
  })().finally(() => {
    signingSessionSealApplyInFlight.delete(singleFlightKey);
  });

  signingSessionSealApplyInFlight.set(singleFlightKey, task);
  return await task;
}

async function rehydrateEmailOtpEcdsaWarmSessionMaterial(args: {
  sealedSecretB64u: string;
  remainingUses: number;
  expiresAtMs: number;
  transport: SigningSessionSealTransport;
  restore: {
    sessionId: string;
    walletId: string;
    rpId: string;
    chainTarget: ThresholdEcdsaChainTarget;
    walletSigningSessionId: string;
    keyHandle: string;
    relayerKeyId: string;
    participantIds: number[];
    sessionKind?: 'jwt' | 'cookie';
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    ed25519?: {
      sessionId: string;
      signingRootId: string;
      signingRootVersion?: string;
      relayerKeyId: string;
      participantIds: number[];
    };
  };
}): Promise<EmailOtpEcdsaWarmSessionRehydrateResult> {
  const parsed = parseEmailOtpEcdsaWarmSessionRehydrateArgs(args);
  if (parsed.kind === 'error') return parsed.error;
  const {
    sealedSecretB64u,
    remainingUses: localRemainingUses,
    expiresAtMs: localExpiresAtMs,
    transport,
    restore,
  } = parsed.value;
  const sessionId = restore.sessionId;
  if (localRemainingUses <= 0) {
    return { ok: false, code: 'exhausted', message: 'Email OTP signing-session seal exhausted' };
  }
  if (localExpiresAtMs <= Date.now()) {
    return { ok: false, code: 'expired', message: 'Email OTP signing-session seal expired' };
  }
  const singleFlightKey = makeSigningSessionSealSingleFlightKey({
    operation: 'remove-server-seal',
    sessionId,
    relayerUrl: transport.relayerUrl,
    keyVersion: transport.keyVersion,
    shamirPrimeB64u: transport.shamirPrimeB64u,
    payloadB64u: sealedSecretB64u,
  });
  const inFlight = signingSessionSealRemoveInFlight.get(singleFlightKey);
  if (inFlight) return await inFlight;

  const task = (async (): Promise<EmailOtpEcdsaWarmSessionRehydrateResult> => {
    let signingSessionSecret32: Uint8Array | null = null;
    let clientRootShare32: Uint8Array | null = null;
    let emailOtpClientAdditiveShare32: Uint8Array | null = null;
    let serverRemainingUses: number | undefined;
    let serverExpiresAtMs: number | undefined;
    try {
      const runtime = await getShamir3PassRuntime();
      const clientKeyHandle = await runtime.createClientKeyHandle({
        shamirPrimeB64u: transport.shamirPrimeB64u,
      });
      try {
        const clientEncryptedCiphertext = await runtime.addClientSealWithKeyHandle({
          ciphertextB64u: sealedSecretB64u,
          keyHandle: clientKeyHandle.keyHandle,
        });
        const removed = await callSigningSessionSealRoute({
          operation: 'remove-server-seal',
          transport,
          thresholdSessionId: sessionId,
          ciphertext: readString(clientEncryptedCiphertext, 'clientEncryptedCiphertext'),
          keyVersion: transport.keyVersion,
        });
        if (!removed.ok) return removed;
        serverRemainingUses = removed.remainingUses;
        serverExpiresAtMs = removed.expiresAtMs;
        signingSessionSecret32 = await runtime.removeClientSealWithKeyHandleToBytes({
          ciphertextB64u: removed.ciphertext,
          keyHandle: clientKeyHandle.keyHandle,
        });
      } finally {
        await runtime
          .destroyClientKeyHandle({ keyHandle: clientKeyHandle.keyHandle })
          .catch(() => undefined);
      }

      if (signingSessionSecret32.length !== 32) {
        return {
          ok: false,
          code: 'invalid_response',
          message: 'Signing-session secret must decode to 32 bytes',
        };
      }
      const ed25519RestoreSeedB64u = restore.ed25519
        ? await deriveEmailOtpEd25519RestoreSeedB64u({
            signingSessionSecret32,
            walletId: restore.walletId,
            userId: restore.userId,
            signingRootId: restore.ed25519.signingRootId,
            signingRootVersion: restore.ed25519.signingRootVersion,
            walletSigningSessionId: restore.walletSigningSessionId,
            ed25519ThresholdSessionId: restore.ed25519.sessionId,
            relayerKeyId: restore.ed25519.relayerKeyId,
            participantIds: restore.ed25519.participantIds,
          })
        : '';
      clientRootShare32 = Uint8Array.from(signingSessionSecret32);
      const policy = resolvePolicyFromServerAndLocal({
        localRemainingUses,
        localExpiresAtMs,
        serverRemainingUses,
        serverExpiresAtMs,
      });
      if (!policy.ok) return policy;
      const routeAuth: AppOrThresholdSessionAuth | undefined = transport
        .thresholdSessionAuthToken
        ? { kind: 'threshold_session', jwt: transport.thresholdSessionAuthToken }
        : undefined;
      if (!routeAuth && restore.sessionKind !== 'cookie') {
        return {
          ok: false,
          code: 'invalid_args',
          message: 'Missing threshold-session auth for Email OTP ECDSA restore',
        };
      }
      const lanePolicy = buildEvmFamilyEcdsaSessionLanePolicy({
        chainTarget: restore.chainTarget,
        thresholdSessionId: sessionId,
        walletSigningSessionId: restore.walletSigningSessionId,
        thresholdSessionKind: restore.sessionKind,
        ttlMs: Math.max(1, policy.expiresAtMs - Date.now()),
        remainingUses: policy.remainingUses,
        ...(restore.runtimePolicyScope ? { runtimePolicyScope: restore.runtimePolicyScope } : {}),
      });
      const workerBootstrap = await runThresholdEcdsaAuthorizationBootstrapFromClientRootShare({
        relayUrl: transport.relayerUrl,
        clientRootShare32,
        operation: 'session_bootstrap',
        keyHandle: restore.keyHandle,
        keyContext: restore.keyContext,
        lanePolicy,
        routeAuth,
      });
      const restoredKeyHandle = readString(
        workerBootstrap.thresholdEcdsaKeyRef.keyHandle,
        'thresholdEcdsaKeyRef.keyHandle',
      );
      if (restoredKeyHandle !== restore.keyHandle) {
        return {
          ok: false,
          code: 'invalid_response',
          message: 'Email OTP ECDSA restore returned a different keyHandle',
        };
      }
      const { emailOtpClientAdditiveShare32: additiveShare32, ...bootstrap } = workerBootstrap;
      emailOtpClientAdditiveShare32 = additiveShare32;
      const resolvedRemainingUses = Math.min(
        policy.remainingUses,
        Math.max(0, Math.floor(Number(bootstrap.session?.remainingUses) || policy.remainingUses)),
      );
      const resolvedExpiresAtMs = Math.min(
        policy.expiresAtMs,
        Math.max(0, Math.floor(Number(bootstrap.session?.expiresAtMs) || policy.expiresAtMs)),
      );
      putEmailOtpWarmSessionMaterial({
        sessionId: readString(bootstrap.session?.sessionId || sessionId, 'thresholdSessionId'),
        clientRootShare32,
        signingSessionSecret32,
        clientAdditiveShare32: emailOtpClientAdditiveShare32,
        expiresAtMs: resolvedExpiresAtMs,
        remainingUses: resolvedRemainingUses,
      });
      return {
        ok: true,
        bootstrap,
        remainingUses: resolvedRemainingUses,
        expiresAtMs: resolvedExpiresAtMs,
        ...(ed25519RestoreSeedB64u ? { ed25519RestoreSeedB64u } : {}),
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message:
          error instanceof Error
            ? error.message
            : String(error || 'Failed to rehydrate Email OTP signing session'),
      };
    } finally {
      zeroizeBytes(signingSessionSecret32);
      zeroizeBytes(clientRootShare32);
      zeroizeBytes(emailOtpClientAdditiveShare32);
      signingSessionSealRemoveInFlight.delete(singleFlightKey);
    }
  })();

  signingSessionSealRemoveInFlight.set(singleFlightKey, task);
  return await task;
}

function claimEmailOtpEcdsaSigningShare(
  sessionIdRaw: unknown,
): EmailOtpEcdsaSigningShareClaimResult {
  const sessionId = String(sessionIdRaw || '').trim();
  const status = readEmailOtpWarmSessionStatus(sessionId);
  if (!status.ok) return status;
  const entry = emailOtpWarmSessions.get(sessionId);
  if (!entry?.clientAdditiveShare32) {
    return {
      ok: false,
      code: 'not_found',
      message: 'Email OTP ECDSA signing material is not available',
    };
  }
  const clientSigningShare32 = Uint8Array.from(entry.clientAdditiveShare32);
  entry.remainingUses -= 1;
  const remainingUses = entry.remainingUses;
  const expiresAtMs = entry.expiresAtMs;
  if (remainingUses <= 0) {
    deleteEmailOtpWarmSession(sessionId);
  } else {
    emailOtpWarmSessions.set(sessionId, entry);
  }
  return {
    ok: true,
    clientSigningShare32: clientSigningShare32.buffer,
    remainingUses,
    expiresAtMs,
  };
}

function requireFixed32ArrayBuffer(value: unknown, label: string): Uint8Array {
  if (!(value instanceof ArrayBuffer)) {
    throw new Error(`${label} must be an ArrayBuffer`);
  }
  const bytes = new Uint8Array(value);
  if (bytes.length !== 32) {
    throw new Error(`${label} must contain 32 bytes`);
  }
  return bytes;
}

function generateRandomSecret32(): Uint8Array {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi || typeof cryptoApi.getRandomValues !== 'function') {
    throw new Error('crypto.getRandomValues is unavailable in this runtime');
  }
  return cryptoApi.getRandomValues(new Uint8Array(32));
}

function generateEmailOtpRecoveryKeyId(index: number): string {
  const cryptoApi = globalThis.crypto;
  const random = new Uint8Array(16);
  if (!cryptoApi || typeof cryptoApi.getRandomValues !== 'function') {
    throw new Error('crypto.getRandomValues is unavailable in this runtime');
  }
  cryptoApi.getRandomValues(random);
  return `email-otp-recovery-key-v1-${index + 1}-${base64UrlEncode(random)}`;
}

async function sha256Bytes(input: Uint8Array): Promise<Uint8Array> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', input);
  return new Uint8Array(digest);
}

const ethSignerWasmUrl = resolveWasmUrl('eth_signer.wasm', 'Email OTP');
const hssClientSignerWasmUrl = resolveWasmUrl('hss_client_signer_bg.wasm', 'Email OTP HSS');
const emailOtpRuntimeWasmUrl = resolveWasmUrl('email_otp_runtime_bg.wasm', 'Email OTP Runtime');
const nearSignerRecoveryWasmUrl = resolveWasmUrl(
  'wasm_signer_worker_bg.wasm',
  'Email OTP Recovery Wrap',
);
let ethSignerInitPromise: Promise<void> | null = null;
let hssClientSignerInitPromise: Promise<void> | null = null;
let emailOtpRuntimeInitPromise: Promise<void> | null = null;
let nearSignerRecoveryInitPromise: Promise<void> | null = null;

async function ensureEthSignerWasm(): Promise<void> {
  if (ethSignerInitPromise) return ethSignerInitPromise;
  ethSignerInitPromise = (async () => {
    await initializeWasm({
      workerName: 'Email OTP',
      wasmUrl: ethSignerWasmUrl,
      initFunction: initEthSigner as unknown as (wasmModule?: unknown) => Promise<void>,
      validateFunction: () => init_eth_signer(),
    });
  })();
  return ethSignerInitPromise;
}

async function ensureHssClientSignerWasm(): Promise<void> {
  if (hssClientSignerInitPromise) return hssClientSignerInitPromise;
  hssClientSignerInitPromise = (async () => {
    await initializeWasm({
      workerName: 'Email OTP HSS',
      wasmUrl: hssClientSignerWasmUrl,
      initFunction: initHssClientSigner as unknown as (wasmModule?: unknown) => Promise<void>,
    });
  })();
  return hssClientSignerInitPromise;
}

async function ensureEmailOtpRuntimeWasm(): Promise<void> {
  if (emailOtpRuntimeInitPromise) return emailOtpRuntimeInitPromise;
  emailOtpRuntimeInitPromise = (async () => {
    await initializeWasm({
      workerName: 'Email OTP Runtime',
      wasmUrl: emailOtpRuntimeWasmUrl,
      initFunction: initEmailOtpRuntime as unknown as (wasmModule?: unknown) => Promise<void>,
      validateFunction: () => init_email_otp_runtime(),
    });
  })();
  return emailOtpRuntimeInitPromise;
}

async function ensureNearSignerRecoveryWasm(): Promise<void> {
  if (nearSignerRecoveryInitPromise) return nearSignerRecoveryInitPromise;
  nearSignerRecoveryInitPromise = (async () => {
    await initializeWasm({
      workerName: 'Email OTP Recovery Wrap',
      wasmUrl: nearSignerRecoveryWasmUrl,
      initFunction: initNearSignerRecoveryWasm as unknown as (
        wasmModule?: unknown,
      ) => Promise<void>,
      validateFunction: () => init_near_signer_recovery_worker(),
    });
  })();
  return nearSignerRecoveryInitPromise;
}

async function createEmailOtpRecoveryWrappedEnrollmentEscrows(args: {
  walletId: string;
  userId: string;
  enrollmentId: string;
  enrollmentVersion: string;
  enrollmentSealKeyVersion: string;
  signingRootId: string;
  signingRootVersion: string;
  encSB64u: string;
}): Promise<{
  recoveryKeys: string[];
  recoveryWrappedEnrollmentEscrows: EmailOtpRecoveryWrappedEnrollmentEscrowPayload[];
}> {
  await ensureNearSignerRecoveryWasm();
  const recoveryKeys = generateEmailOtpRecoveryKeySet();
  const encS = base64UrlDecode(args.encSB64u);
  const issuedAtMs = Date.now();
  const recoveryWrappedEnrollmentEscrows: EmailOtpRecoveryWrappedEnrollmentEscrowPayload[] = [];
  try {
    for (let index = 0; index < recoveryKeys.length; index += 1) {
      const recoveryKeyId = generateEmailOtpRecoveryKeyId(index);
      const metadata: EmailOtpRecoveryWrapMetadata = {
        walletId: args.walletId,
        userId: args.userId,
        authSubjectId: args.userId,
        authMethod: 'google_sso_email_otp',
        enrollmentId: args.enrollmentId,
        enrollmentVersion: args.enrollmentVersion,
        enrollmentSealKeyVersion: args.enrollmentSealKeyVersion,
        signingRootId: args.signingRootId,
        signingRootVersion: args.signingRootVersion,
        recoveryKeyId,
      };
      const wrapped = await wrapEmailOtpDeviceEnrollmentEscrow({
        recoveryKey: recoveryKeys[index],
        metadata,
        encS,
        chacha20poly1305: {
          encrypt: async (input) =>
            email_recovery_chacha20poly1305_encrypt(
              input.key32,
              input.nonce12,
              input.aad,
              input.plaintext,
            ),
          decrypt: async () => {
            throw new Error('Email OTP enrollment recovery wrapping does not decrypt');
          },
        },
      });
      const aad = encodeEmailOtpRecoveryWrappedEnrollmentAad(metadata);
      try {
        recoveryWrappedEnrollmentEscrows.push({
          version: 'email_otp_recovery_wrapped_enrollment_escrow_v1',
          alg: EMAIL_OTP_RECOVERY_WRAP_ALG,
          secretKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
          escrowKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
          walletId: args.walletId,
          userId: args.userId,
          authSubjectId: args.userId,
          authMethod: 'google_sso_email_otp',
          enrollmentId: args.enrollmentId,
          enrollmentVersion: args.enrollmentVersion,
          enrollmentSealKeyVersion: args.enrollmentSealKeyVersion,
          signingRootId: args.signingRootId,
          signingRootVersion: args.signingRootVersion,
          recoveryKeyId,
          recoveryKeyStatus: 'active',
          nonceB64u: base64UrlEncode(wrapped.nonce12),
          wrappedDeviceEnrollmentEscrowB64u: base64UrlEncode(wrapped.ciphertext),
          aadHashB64u: base64UrlEncode(await sha256Bytes(aad)),
          issuedAtMs,
          updatedAtMs: issuedAtMs,
        });
      } finally {
        zeroizeBytes(aad);
      }
    }
    return { recoveryKeys, recoveryWrappedEnrollmentEscrows };
  } finally {
    zeroizeBytes(encS);
  }
}

function parseEmailOtpRecoveryWrappedEnrollmentEscrowPayload(
  value: unknown,
): EmailOtpRecoveryWrappedEnrollmentEscrowPayload | null {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  if (!obj) return null;
  const record: EmailOtpRecoveryWrappedEnrollmentEscrowPayload = {
    version: readString(
      obj.version,
      'recoveryWrappedEnrollmentEscrow.version',
    ) as 'email_otp_recovery_wrapped_enrollment_escrow_v1',
    alg: readString(
      obj.alg,
      'recoveryWrappedEnrollmentEscrow.alg',
    ) as typeof EMAIL_OTP_RECOVERY_WRAP_ALG,
    secretKind: readString(
      obj.secretKind,
      'recoveryWrappedEnrollmentEscrow.secretKind',
    ) as typeof EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
    escrowKind: readString(
      obj.escrowKind,
      'recoveryWrappedEnrollmentEscrow.escrowKind',
    ) as typeof EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
    walletId: readString(obj.walletId, 'recoveryWrappedEnrollmentEscrow.walletId'),
    userId: readString(obj.userId, 'recoveryWrappedEnrollmentEscrow.userId'),
    authSubjectId: readString(obj.authSubjectId, 'recoveryWrappedEnrollmentEscrow.authSubjectId'),
    authMethod: readString(
      obj.authMethod,
      'recoveryWrappedEnrollmentEscrow.authMethod',
    ) as 'google_sso_email_otp',
    enrollmentId: readString(obj.enrollmentId, 'recoveryWrappedEnrollmentEscrow.enrollmentId'),
    enrollmentVersion: readString(
      obj.enrollmentVersion,
      'recoveryWrappedEnrollmentEscrow.enrollmentVersion',
    ),
    enrollmentSealKeyVersion: readString(
      obj.enrollmentSealKeyVersion,
      'recoveryWrappedEnrollmentEscrow.enrollmentSealKeyVersion',
    ),
    signingRootId: readString(obj.signingRootId, 'recoveryWrappedEnrollmentEscrow.signingRootId'),
    signingRootVersion: readString(
      obj.signingRootVersion,
      'recoveryWrappedEnrollmentEscrow.signingRootVersion',
    ),
    recoveryKeyId: readString(obj.recoveryKeyId, 'recoveryWrappedEnrollmentEscrow.recoveryKeyId'),
    recoveryKeyStatus: readString(
      obj.recoveryKeyStatus,
      'recoveryWrappedEnrollmentEscrow.recoveryKeyStatus',
    ) as 'active',
    nonceB64u: readString(obj.nonceB64u, 'recoveryWrappedEnrollmentEscrow.nonceB64u'),
    wrappedDeviceEnrollmentEscrowB64u: readString(
      obj.wrappedDeviceEnrollmentEscrowB64u,
      'recoveryWrappedEnrollmentEscrow.wrappedDeviceEnrollmentEscrowB64u',
    ),
    aadHashB64u: readString(obj.aadHashB64u, 'recoveryWrappedEnrollmentEscrow.aadHashB64u'),
    issuedAtMs: Math.floor(Number(obj.issuedAtMs)),
    updatedAtMs: Math.floor(Number(obj.updatedAtMs)),
  };
  if (record.version !== 'email_otp_recovery_wrapped_enrollment_escrow_v1') return null;
  if (record.alg !== EMAIL_OTP_RECOVERY_WRAP_ALG) return null;
  if (record.secretKind !== EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND) return null;
  if (record.escrowKind !== EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND) return null;
  if (record.authMethod !== 'google_sso_email_otp') return null;
  if (record.recoveryKeyStatus !== 'active') return null;
  if (!Number.isFinite(record.issuedAtMs) || record.issuedAtMs <= 0) return null;
  if (!Number.isFinite(record.updatedAtMs) || record.updatedAtMs <= 0) return null;
  return record;
}

async function writeAndVerifyEmailOtpDeviceEnrollmentEscrowRecord(
  record: Parameters<typeof writeEmailOtpDeviceEnrollmentEscrowRecord>[0],
  errorMessage: string,
): Promise<void> {
  await writeEmailOtpDeviceEnrollmentEscrowRecord(record);
  const persisted = await readEmailOtpDeviceEnrollmentEscrowRecord({
    walletId: record.walletId,
    authSubjectId: record.authSubjectId,
    enrollmentId: record.enrollmentId,
  });
  if (
    !persisted ||
    persisted.encSB64u !== record.encSB64u ||
    persisted.enrollmentSealKeyVersion !== record.enrollmentSealKeyVersion ||
    persisted.signingRootId !== record.signingRootId ||
    persisted.signingRootVersion !== record.signingRootVersion
  ) {
    throw new Error(errorMessage);
  }
}

async function reportEmailOtpRecoveryKeyAttemptFailure(args: {
  relayUrl: string;
  routeAuth: ReturnType<typeof routePlanSessionAuth>;
  walletId: string;
  recoveryConsumeGrant: string;
}): Promise<void> {
  await postEmailOtpJson({
    relayUrl: args.relayUrl,
    route: '/wallet/email-otp/recovery-key/attempt-failed',
    ...(args.routeAuth ? { sessionAuth: args.routeAuth } : {}),
    body: {
      walletId: args.walletId,
      recoveryConsumeGrant: args.recoveryConsumeGrant,
    },
  });
}

async function restoreEmailOtpDeviceEnrollmentEscrowFromRecoveryKey(args: {
  relayUrl: string;
  walletId: string;
  userId?: unknown;
  challengeId: string;
  otpCode: string;
  recoveryKey: string;
  shamirPrimeB64u: string;
  routePlan: EmailOtpRoutePlan;
}): Promise<{
  walletId: string;
  userId: string;
  authSubjectId: string;
  enrollmentId: string;
  enrollmentVersion: string;
  enrollmentSealKeyVersion: string;
  signingRootId: string;
  signingRootVersion: string;
  recoveryKeyId: string;
  activeRecoveryWrappedEnrollmentEscrowCount: number;
}> {
  await ensureNearSignerRecoveryWasm();
  const relayUrl = readString(args.relayUrl, 'relayUrl');
  const walletId = readString(args.walletId, 'walletId');
  const requestedUserId = resolveEmailOtpAuthSubjectId({
    walletId,
    userId: args.userId,
    routePlan: args.routePlan,
  });
  const routeAuth = routePlanSessionAuth(args.routePlan);
  const response = await postEmailOtpJson({
    relayUrl,
    route: '/wallet/email-otp/recovery-wrapped-escrows',
    ...(routeAuth ? { sessionAuth: routeAuth } : {}),
    body: {
      walletId,
      challengeId: readString(args.challengeId, 'challengeId'),
      otpCode: readString(args.otpCode, 'otpCode'),
      otpChannel: EMAIL_OTP_CHANNEL,
    },
  });
  const rawRecords = Array.isArray(response.recoveryWrappedEnrollmentEscrows)
    ? response.recoveryWrappedEnrollmentEscrows
    : [];
  const recoveryConsumeGrant = readString(response.recoveryConsumeGrant, 'recoveryConsumeGrant');
  const records = rawRecords
    .map((record) => parseEmailOtpRecoveryWrappedEnrollmentEscrowPayload(record))
    .filter((record): record is EmailOtpRecoveryWrappedEnrollmentEscrowPayload => Boolean(record));
  if (records.length <= 0) {
    throw new Error('No active Email OTP recovery-wrapped enrollment escrows are available');
  }

  let sawRecoveryKeyUnwrapFailure = false;
  for (const record of records) {
    if (record.walletId !== walletId) continue;
    if (requestedUserId && record.userId !== requestedUserId) continue;
    const metadata: EmailOtpRecoveryWrapMetadata = {
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
    };
    const aad = encodeEmailOtpRecoveryWrappedEnrollmentAad(metadata);
    let encS: Uint8Array | null = null;
    try {
      const aadHashB64u = base64UrlEncode(await sha256Bytes(aad));
      if (aadHashB64u !== record.aadHashB64u) continue;
      encS = await unwrapEmailOtpDeviceEnrollmentEscrow({
        recoveryKey: readString(args.recoveryKey, 'recoveryKey'),
        metadata,
        wrapped: {
          alg: record.alg,
          nonce12: base64UrlDecode(record.nonceB64u),
          ciphertext: base64UrlDecode(record.wrappedDeviceEnrollmentEscrowB64u),
        },
        chacha20poly1305: {
          encrypt: async () => {
            throw new Error('Email OTP enrollment recovery restore does not encrypt');
          },
          decrypt: async (input) =>
            email_recovery_chacha20poly1305_decrypt(
              input.key32,
              input.nonce12,
              input.aad,
              input.ciphertext,
            ),
        },
      });
      await writeAndVerifyEmailOtpDeviceEnrollmentEscrowRecord(
        {
          walletId: record.walletId,
          userId: record.userId,
          authSubjectId: record.authSubjectId,
          enrollmentId: record.enrollmentId,
          enrollmentVersion: record.enrollmentVersion,
          enrollmentSealKeyVersion: record.enrollmentSealKeyVersion,
          signingRootId: record.signingRootId,
          signingRootVersion: record.signingRootVersion,
          shamirPrimeB64u: readString(args.shamirPrimeB64u, 'shamirPrimeB64u'),
          encSB64u: base64UrlEncode(encS),
          issuedAtMs: Date.now(),
          updatedAtMs: Date.now(),
        },
        'Email OTP recovery did not persist device-local enc_s(S)',
      );
      const consumeResponse = await postEmailOtpJson({
        relayUrl,
        route: '/wallet/email-otp/recovery-key/consume',
        ...(routeAuth ? { sessionAuth: routeAuth } : {}),
        body: {
          walletId,
          recoveryKeyId: record.recoveryKeyId,
          recoveryConsumeGrant,
        },
      });
      const activeRecoveryWrappedEnrollmentEscrowCount = Number(
        consumeResponse.activeRecoveryWrappedEnrollmentEscrowCount,
      );
      return {
        walletId: record.walletId,
        userId: record.userId,
        authSubjectId: record.authSubjectId,
        enrollmentId: record.enrollmentId,
        enrollmentVersion: record.enrollmentVersion,
        enrollmentSealKeyVersion: record.enrollmentSealKeyVersion,
        signingRootId: record.signingRootId,
        signingRootVersion: record.signingRootVersion,
        recoveryKeyId: record.recoveryKeyId,
        activeRecoveryWrappedEnrollmentEscrowCount: Number.isFinite(
          activeRecoveryWrappedEnrollmentEscrowCount,
        )
          ? activeRecoveryWrappedEnrollmentEscrowCount
          : records.length - 1,
      };
    } catch {
      if (encS) throw new Error('Email OTP recovery restore failed after successful unwrap');
      sawRecoveryKeyUnwrapFailure = true;
      continue;
    } finally {
      zeroizeBytes(aad);
      zeroizeBytes(encS);
    }
  }

  if (sawRecoveryKeyUnwrapFailure) {
    await reportEmailOtpRecoveryKeyAttemptFailure({
      relayUrl,
      routeAuth,
      walletId,
      recoveryConsumeGrant,
    });
  }
  throw new Error('Email OTP recovery unwrap failed');
}

async function removeEmailOtpDeviceEnrollmentEscrowFromDevice(args: {
  walletId: string;
  userId?: unknown;
  enrollmentId?: unknown;
}): Promise<{
  walletId: string;
  authSubjectId: string;
  enrollmentId: string;
  removed: true;
}> {
  const walletId = readString(args.walletId, 'walletId');
  const authSubjectId = readOptionalString(args.userId) || walletId;
  const enrollmentId =
    readOptionalString(args.enrollmentId) || emailOtpDeviceEnrollmentId(walletId, authSubjectId);
  await deleteEmailOtpDeviceEnrollmentEscrowRecord({
    walletId,
    authSubjectId,
    enrollmentId,
  });
  return {
    walletId,
    authSubjectId,
    enrollmentId,
    removed: true,
  };
}

async function deriveEmailOtpEcdsaClientRootShare32InWorker(args: {
  clientSecret32: Uint8Array;
  walletId: string;
  userId: string;
  derivationPath?: string;
}): Promise<Uint8Array> {
  await ensureEmailOtpRuntimeWasm();
  return derive_email_otp_ecdsa_client_root_share32_from_secret32(
    args.clientSecret32,
    String(args.walletId || '').trim(),
    String(args.userId || '').trim(),
    String(args.derivationPath || '').trim() || undefined,
  );
}

async function deriveEmailOtpUnlockAuthSeedInWorker(args: {
  clientSecret32: Uint8Array;
  walletId: string;
}): Promise<Uint8Array> {
  await ensureEmailOtpRuntimeWasm();
  return derive_email_otp_unlock_auth_seed_from_secret32(
    args.clientSecret32,
    String(args.walletId || '').trim(),
  );
}

function generateKeygenSessionId(): string {
  const id =
    typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `tecdsa-keygen-${id}`;
}

async function removeClientSealToBytes(args: {
  runtime: Awaited<ReturnType<typeof getShamir3PassRuntime>>;
  keyHandle: string;
  ciphertextB64u: string;
}): Promise<Uint8Array> {
  return await args.runtime.removeClientSealWithKeyHandleToBytes({
    ciphertextB64u: args.ciphertextB64u,
    keyHandle: args.keyHandle,
  });
}

async function addClientSealFromBytes(args: {
  runtime: Awaited<ReturnType<typeof getShamir3PassRuntime>>;
  keyHandle: string;
  ciphertext: Uint8Array;
}): Promise<string> {
  return readString(
    await args.runtime.addClientSealBytesWithKeyHandle({
      ciphertext: args.ciphertext,
      keyHandle: args.keyHandle,
    }),
    'wrappedCiphertext',
  );
}

async function completeEmailOtpUnlockFromSecret32(args: {
  relayUrl: string;
  walletId: string;
  orgId?: string;
  userId?: string;
  clientSecret32: Uint8Array;
}): Promise<{
  clientRootShare32: Uint8Array;
  unlockChallengeId: string;
  unlockChallengeB64u: string;
  clientUnlockPublicKeyB64u: string;
  unlockSignatureB64u: string;
}> {
  await ensureEthSignerWasm();
  const walletId = readString(args.walletId, 'walletId');
  const userId = String(args.userId || walletId).trim() || walletId;
  const challenge = await postEmailOtpJson({
    relayUrl: readString(args.relayUrl, 'relayUrl'),
    route: '/wallet/unlock/challenge',
    body: {
      unlockBackend: 'email_otp',
      walletId,
      ...(readOptionalString(args.orgId) ? { orgId: readOptionalString(args.orgId) } : {}),
    },
  });
  const unlockChallengeId = readString(challenge.challengeId, 'challengeId');
  const unlockChallengeB64u = readString(challenge.challengeB64u, 'challengeB64u');
  let challengeDigest32: Uint8Array | null = base64UrlDecode(unlockChallengeB64u);
  if (challengeDigest32.length !== 32) {
    zeroizeBytes(challengeDigest32);
    throw new Error('wallet/unlock/challenge challengeB64u must decode to 32 bytes');
  }

  let unlockPrivateKey32: Uint8Array | null = null;
  let clientRootShare32: Uint8Array | null = null;
  let unlockPublicKey33: Uint8Array | null = null;
  let unlockSignature65: Uint8Array | null = null;
  try {
    unlockPrivateKey32 = await deriveEmailOtpUnlockAuthSeedInWorker({
      clientSecret32: args.clientSecret32,
      walletId,
    });
    unlockPublicKey33 = secp256k1_private_key_32_to_public_key_33(unlockPrivateKey32) as Uint8Array;
    unlockSignature65 = sign_secp256k1_recoverable(
      challengeDigest32,
      unlockPrivateKey32,
    ) as Uint8Array;

    const clientUnlockPublicKeyB64u = base64UrlEncode(unlockPublicKey33);
    const unlockSignatureB64u = base64UrlEncode(unlockSignature65);

    await postEmailOtpJson({
      relayUrl: readString(args.relayUrl, 'relayUrl'),
      route: '/wallet/unlock/verify',
      body: {
        unlockBackend: 'email_otp',
        walletId,
        ...(readOptionalString(args.orgId) ? { orgId: readOptionalString(args.orgId) } : {}),
        challengeId: unlockChallengeId,
        unlockProof: {
          publicKey: clientUnlockPublicKeyB64u,
          signature: unlockSignatureB64u,
        },
      },
    });

    clientRootShare32 = await deriveEmailOtpEcdsaClientRootShare32InWorker({
      clientSecret32: args.clientSecret32,
      walletId,
      userId,
    });

    return {
      clientRootShare32,
      unlockChallengeId,
      unlockChallengeB64u,
      clientUnlockPublicKeyB64u,
      unlockSignatureB64u,
    };
  } finally {
    zeroizeBytes(challengeDigest32);
    zeroizeBytes(unlockPrivateKey32);
    zeroizeBytes(unlockPublicKey33);
    zeroizeBytes(unlockSignature65);
  }
}

async function completeEmailOtpEnrollmentFromSecret32(args: {
  relayUrl: string;
  walletId: string;
  userId?: string;
  challengeId?: string;
  otpCode: string;
  shamirPrimeB64u: string;
  routePlan: EmailOtpRoutePlan;
  clientSecret32?: Uint8Array;
  returnClientRootShare32?: boolean;
  returnClientSecret32?: boolean;
  onProgress?: (code: EmailOtpWorkerProgressCode) => void;
}): Promise<{
  thresholdEcdsaClientVerifyingShareB64u: string;
  thresholdEd25519PrfFirstB64u: string;
  recoveryKeys: string[];
  challengeId: string;
  otpChannel: WalletEmailOtpChannel;
  enrollmentSealKeyVersion: string;
  clientUnlockPublicKeyB64u: string;
  unlockKeyVersion: string;
  clientRootShare32?: Uint8Array;
  clientSecret32?: Uint8Array;
}> {
  await ensureEthSignerWasm();
  const runtime = await getShamir3PassRuntime();
  const relayUrl = readString(args.relayUrl, 'relayUrl');
  const walletId = readString(args.walletId, 'walletId');
  const userId = resolveEmailOtpAuthSubjectId({
    walletId,
    userId: args.userId,
    routePlan: args.routePlan,
  });
  const shamirPrimeB64u = readString(args.shamirPrimeB64u, 'shamirPrimeB64u');
  const otpCode = readString(args.otpCode, 'otpCode');
  const keyHandle = readString(
    (await runtime.createClientKeyHandle({ shamirPrimeB64u })).keyHandle,
    'keyHandle',
  );
  let clientSecret32: Uint8Array | null = args.clientSecret32
    ? Uint8Array.from(args.clientSecret32)
    : generateRandomSecret32();
  let thresholdClientRootShare32: Uint8Array | null = null;
  let unlockPrivateKey32: Uint8Array | null = null;
  let thresholdEcdsaClientVerifyingShare33: Uint8Array | null = null;
  let unlockPublicKey33: Uint8Array | null = null;
  let thresholdEd25519PrfFirstB64u = '';
  try {
    const sessionAuth = routePlanSessionAuth(args.routePlan);
    let challengeId = readOptionalString(args.challengeId);
    if (!challengeId) {
      const challenge = await postEmailOtpJson({
        relayUrl,
        route: emailOtpRoutePath(args.routePlan, 'challenge'),
        ...(sessionAuth ? { sessionAuth } : {}),
        body: {
          walletId,
          otpChannel: EMAIL_OTP_CHANNEL,
        },
      });
      challengeId = readString(
        (challenge.challenge as Record<string, unknown>)?.challengeId,
        'challengeId',
      );
    }
    const wrappedCiphertext = await addClientSealFromBytes({
      runtime,
      keyHandle,
      ciphertext: clientSecret32,
    });
    const applied = await postEmailOtpJson({
      relayUrl,
      route: emailOtpRoutePath(args.routePlan, 'seal'),
      ...(sessionAuth ? { sessionAuth } : {}),
      body: {
        walletId,
        wrappedCiphertext,
      },
    });
    const enrollmentSealKeyVersion = readString(
      applied.enrollmentSealKeyVersion,
      'enrollmentSealKeyVersion',
    );
    const clientCiphertext = readString(applied.ciphertext, 'ciphertext');
    const enrollmentEscrowCiphertextB64u = readString(
      await runtime.removeClientSealWithKeyHandle({
        ciphertextB64u: clientCiphertext,
        keyHandle,
      }),
      'enrollmentEscrowCiphertextB64u',
    );

    thresholdClientRootShare32 = await deriveEmailOtpEcdsaClientRootShare32InWorker({
      clientSecret32,
      walletId,
      userId,
    });
    thresholdEd25519PrfFirstB64u = await deriveEmailOtpEd25519PrfFirstB64u({
      clientSecret32,
      walletId,
      userId,
    });
    unlockPrivateKey32 = await deriveEmailOtpUnlockAuthSeedInWorker({
      clientSecret32,
      walletId,
    });
    unlockPublicKey33 = secp256k1_private_key_32_to_public_key_33(unlockPrivateKey32) as Uint8Array;
    thresholdEcdsaClientVerifyingShare33 = secp256k1_private_key_32_to_public_key_33(
      thresholdClientRootShare32,
    ) as Uint8Array;
    const clientUnlockPublicKeyB64u = base64UrlEncode(unlockPublicKey33);
    const thresholdEcdsaClientVerifyingShareB64u = base64UrlEncode(
      thresholdEcdsaClientVerifyingShare33,
    );
    const enrollmentId = emailOtpDeviceEnrollmentId(walletId, userId);
    const enrollmentVersion = EMAIL_OTP_DEVICE_ENROLLMENT_VERSION;
    const signingRootId = EMAIL_OTP_DEVICE_ENROLLMENT_SIGNING_ROOT_ID;
    const signingRootVersion = EMAIL_OTP_DEVICE_ENROLLMENT_SIGNING_ROOT_VERSION;
    const { recoveryKeys, recoveryWrappedEnrollmentEscrows } =
      await createEmailOtpRecoveryWrappedEnrollmentEscrows({
        walletId,
        userId,
        enrollmentId,
        enrollmentVersion,
        enrollmentSealKeyVersion,
        signingRootId,
        signingRootVersion,
        encSB64u: enrollmentEscrowCiphertextB64u,
      });

    await writeAndVerifyEmailOtpDeviceEnrollmentEscrowRecord(
      {
        walletId,
        userId,
        authSubjectId: userId,
        enrollmentId,
        enrollmentVersion,
        enrollmentSealKeyVersion,
        signingRootId,
        signingRootVersion,
        encSB64u: enrollmentEscrowCiphertextB64u,
        shamirPrimeB64u,
      },
      'Email OTP enrollment did not persist device-local enc_s(S)',
    );
    await postEmailOtpJson({
      relayUrl,
      route: emailOtpRoutePath(args.routePlan, 'finalize'),
      ...(sessionAuth ? { sessionAuth } : {}),
      body: {
        walletId,
        challengeId,
        otpCode,
        otpChannel: EMAIL_OTP_CHANNEL,
        recoveryWrappedEnrollmentEscrows,
        enrollmentSealKeyVersion,
        clientUnlockPublicKeyB64u,
        unlockKeyVersion: EMAIL_OTP_UNLOCK_KEY_VERSION,
        thresholdEcdsaClientVerifyingShareB64u,
      },
    });
    args.onProgress?.('otp.verify.succeeded');
    args.onProgress?.('signer.email_otp.enroll.started');
    args.onProgress?.('signer.email_otp.enroll.succeeded');

    const returnedClientRootShare32 =
      args.returnClientRootShare32 && thresholdClientRootShare32
        ? thresholdClientRootShare32
        : null;
    if (returnedClientRootShare32) {
      thresholdClientRootShare32 = null;
    }
    const returnedClientSecret32 =
      args.returnClientSecret32 && clientSecret32 ? clientSecret32 : null;
    if (returnedClientSecret32) {
      clientSecret32 = null;
    }

    return {
      thresholdEcdsaClientVerifyingShareB64u,
      thresholdEd25519PrfFirstB64u,
      recoveryKeys,
      challengeId,
      otpChannel: EMAIL_OTP_CHANNEL,
      enrollmentSealKeyVersion,
      clientUnlockPublicKeyB64u,
      unlockKeyVersion: EMAIL_OTP_UNLOCK_KEY_VERSION,
      ...(returnedClientRootShare32 ? { clientRootShare32: returnedClientRootShare32 } : {}),
      ...(returnedClientSecret32 ? { clientSecret32: returnedClientSecret32 } : {}),
    };
  } finally {
    zeroizeBytes(clientSecret32);
    zeroizeBytes(thresholdClientRootShare32);
    zeroizeBytes(unlockPrivateKey32);
    zeroizeBytes(thresholdEcdsaClientVerifyingShare33);
    zeroizeBytes(unlockPublicKey33);
    await runtime.destroyClientKeyHandle({ keyHandle }).catch(() => undefined);
    clientSecret32 = null;
  }
}

async function loginWithEmailOtpAndRecoverClientRootShare(args: {
  relayUrl: string;
  walletId: string;
  orgId?: string;
  userId?: string;
  challengeId?: string;
  otpCode: string;
  shamirPrimeB64u: string;
  routePlan: EmailOtpRoutePlan;
  returnClientSecret32?: boolean;
  onProgress?: (code: EmailOtpWorkerProgressCode) => void;
}): Promise<{
  clientSecret32?: Uint8Array;
  clientRootShare32: Uint8Array;
  thresholdEd25519PrfFirstB64u: string;
  challengeId: string;
  enrollmentSealKeyVersion: string;
  unlockChallengeId: string;
  unlockChallengeB64u: string;
  clientUnlockPublicKeyB64u: string;
  unlockSignatureB64u: string;
}> {
  const runtime = await getShamir3PassRuntime();
  const relayUrl = readString(args.relayUrl, 'relayUrl');
  const walletId = readString(args.walletId, 'walletId');
  const shamirPrimeB64u = readString(args.shamirPrimeB64u, 'shamirPrimeB64u');
  const keyHandle = readString(
    (await runtime.createClientKeyHandle({ shamirPrimeB64u })).keyHandle,
    'keyHandle',
  );
  let clientSecret32: Uint8Array | null = null;
  try {
    const sessionAuth = routePlanSessionAuth(args.routePlan);
    let challengeId = readOptionalString(args.challengeId);
    if (!challengeId) {
      const challenge = await postEmailOtpJson({
        relayUrl,
        route: emailOtpRoutePath(args.routePlan, 'challenge'),
        ...(sessionAuth ? { sessionAuth } : {}),
        body: {
          walletId,
          otpChannel: EMAIL_OTP_CHANNEL,
          operation: args.routePlan.operation,
        },
      });
      challengeId = readString(
        (challenge.challenge as Record<string, unknown>)?.challengeId,
        'challengeId',
      );
    }
    let userId = resolveEmailOtpAuthSubjectId({
      walletId,
      userId: args.userId,
      routePlan: args.routePlan,
    });
    let localEnrollmentEscrow = await readEmailOtpDeviceEnrollmentEscrowRecord({
      walletId,
      authSubjectId: userId,
      enrollmentId: emailOtpDeviceEnrollmentId(walletId, userId),
    });
    if (!localEnrollmentEscrow) {
      localEnrollmentEscrow = await readSingleEmailOtpDeviceEnrollmentEscrowRecordForWallet({
        walletId,
      });
      if (localEnrollmentEscrow) {
        userId = localEnrollmentEscrow.authSubjectId;
      }
    }
    if (!localEnrollmentEscrow) {
      throw new Error('Email OTP device-local enc_s(S) is missing; recovery is required');
    }
    const wrappedCiphertext = readString(
      await runtime.addClientSealWithKeyHandle({
        ciphertextB64u: localEnrollmentEscrow.encSB64u,
        keyHandle,
      }),
      'wrappedCiphertext',
    );
    let unsealed: Record<string, unknown>;
    if (args.routePlan.routeFamily === 'login') {
      unsealed = await postEmailOtpJson({
        relayUrl,
        route: emailOtpRoutePath(args.routePlan, 'verifyAndUnseal'),
        ...(sessionAuth ? { sessionAuth } : {}),
        body: {
          walletId,
          challengeId,
          otpCode: readString(args.otpCode, 'otpCode'),
          otpChannel: EMAIL_OTP_CHANNEL,
          operation: args.routePlan.operation,
          wrappedCiphertext,
        },
      });
      args.onProgress?.('otp.verify.succeeded');
    } else {
      const verified = await postEmailOtpJson({
        relayUrl,
        route: emailOtpRoutePath(args.routePlan, 'verify'),
        ...(sessionAuth ? { sessionAuth } : {}),
        body: {
          walletId,
          challengeId,
          otpCode: readString(args.otpCode, 'otpCode'),
          otpChannel: EMAIL_OTP_CHANNEL,
          operation: args.routePlan.operation,
        },
      });
      const verifiedEnrollmentSealKeyVersion = readOptionalString(
        verified.enrollmentSealKeyVersion,
      );
      if (
        verifiedEnrollmentSealKeyVersion &&
        localEnrollmentEscrow.enrollmentSealKeyVersion !== verifiedEnrollmentSealKeyVersion
      ) {
        throw new Error('Email OTP device-local enc_s(S) metadata mismatch; recovery is required');
      }
      const loginGrant = readString(verified.loginGrant, 'loginGrant');
      args.onProgress?.('otp.verify.succeeded');
      unsealed = await postEmailOtpJson({
        relayUrl,
        route: emailOtpRoutePath(args.routePlan, 'unseal'),
        ...(sessionAuth ? { sessionAuth } : {}),
        body: {
          walletId,
          loginGrant,
          wrappedCiphertext,
        },
      });
    }
    const enrollmentSealKeyVersion = readString(
      unsealed.enrollmentSealKeyVersion,
      'enrollmentSealKeyVersion',
    );
    if (localEnrollmentEscrow.enrollmentSealKeyVersion !== enrollmentSealKeyVersion) {
      throw new Error('Email OTP device-local enc_s(S) metadata mismatch; recovery is required');
    }
    const clientCiphertext = readString(unsealed.ciphertext, 'ciphertext');
    clientSecret32 = await removeClientSealToBytes({
      runtime,
      ciphertextB64u: clientCiphertext,
      keyHandle,
    });
    const unlocked = await completeEmailOtpUnlockFromSecret32({
      relayUrl,
      walletId,
      ...(readOptionalString(args.orgId) ? { orgId: readOptionalString(args.orgId) } : {}),
      userId,
      clientSecret32,
    });
    const thresholdEd25519PrfFirstB64u = await deriveEmailOtpEd25519PrfFirstB64u({
      clientSecret32,
      walletId,
      userId,
    });
    const returnedClientSecret32 =
      args.returnClientSecret32 && clientSecret32 ? clientSecret32 : null;
    if (returnedClientSecret32) {
      clientSecret32 = null;
    }
    return {
      ...(returnedClientSecret32 ? { clientSecret32: returnedClientSecret32 } : {}),
      clientRootShare32: unlocked.clientRootShare32,
      thresholdEd25519PrfFirstB64u,
      challengeId,
      enrollmentSealKeyVersion,
      unlockChallengeId: unlocked.unlockChallengeId,
      unlockChallengeB64u: unlocked.unlockChallengeB64u,
      clientUnlockPublicKeyB64u: unlocked.clientUnlockPublicKeyB64u,
      unlockSignatureB64u: unlocked.unlockSignatureB64u,
    };
  } finally {
    zeroizeBytes(clientSecret32);
    await runtime.destroyClientKeyHandle({ keyHandle }).catch(() => undefined);
  }
}

type ThresholdEcdsaEmailOtpBootstrapFromClientRootShareArgs = {
  relayUrl: string;
  clientRootShare32: Uint8Array;
  routeAuth?: AppOrThresholdSessionAuth;
  onProgress?: (code: EmailOtpWorkerProgressCode) => void;
} & (
  | (EmailOtpRegistrationBootstrap & {
      walletSessionUserId: WalletSessionUserId;
      subjectId: WalletSubjectId;
      rpId: string;
      participantIds?: number[];
      sessionKind?: 'jwt' | 'cookie';
      chainTarget: ThresholdEcdsaChainTarget;
      sessionId?: string;
      walletSigningSessionId?: string;
      runtimePolicyScope?: ThresholdRuntimePolicyScope;
      ttlMs?: number;
      remainingUses?: number;
    })
  | (EmailOtpExistingKeyBootstrap & {
      walletSessionUserId: WalletSessionUserId;
      subjectId: WalletSubjectId;
      rpId: string;
      roleLocalKeyIdentity?: {
        ecdsaThresholdKeyId: EcdsaThresholdKeyId;
        signingRootId: string;
        signingRootVersion: string;
        relayerKeyId: string;
      };
      participantIds?: number[];
      sessionKind?: 'jwt' | 'cookie';
      chainTarget: ThresholdEcdsaChainTarget;
      sessionId?: string;
      walletSigningSessionId?: string;
      runtimePolicyScope?: ThresholdRuntimePolicyScope;
      ttlMs?: number;
      remainingUses?: number;
    })
  | SessionBootstrap
);

function requireThresholdEcdsaHssKeyHandle(keyHandle: string, operation: string): string {
  const normalized = readOptionalString(keyHandle);
  if (!normalized) {
    throw new Error(`Threshold ECDSA ${operation} requires keyHandle`);
  }
  return normalized;
}

function relayerKeyIdFromRouteAuth(auth: ThresholdEcdsaHssRouteAuth | undefined): string {
  if (!auth || (auth.kind !== 'threshold_session' && auth.kind !== 'app_session')) return '';
  const payload = decodeJwtPayloadRecord(auth.jwt);
  return readOptionalString(payload?.relayerKeyId) || '';
}

async function runThresholdEcdsaAuthorizationBootstrapFromClientRootShare(
  args: ThresholdEcdsaEmailOtpBootstrapFromClientRootShareArgs,
): Promise<EmailOtpThresholdEcdsaBootstrapResult> {
  await ensureHssClientSignerWasm();
  const relayerUrl = readString(args.relayUrl, 'relayUrl');
  const exactSessionBootstrap = args.operation === 'session_bootstrap';
  const walletSessionUserId = exactSessionBootstrap
    ? toWalletSessionUserId(args.keyContext.walletId)
    : args.walletSessionUserId;
  const subjectId = exactSessionBootstrap
    ? deriveBaseEcdsaSubjectIdFromWalletId(args.keyContext.walletId)
    : args.subjectId;
  const rpId = exactSessionBootstrap
    ? String(args.keyContext.rpId).trim()
    : readString(args.rpId, 'rpId');
  const chainTarget = exactSessionBootstrap ? args.lanePolicy.chainTarget : args.chainTarget;
  const chainId = Math.floor(Number(chainTarget.chainId));
  if (!Number.isSafeInteger(chainId) || chainId < 0) {
    throw new Error('chainTarget.chainId must be a non-negative safe integer');
  }
  const operation = args.operation;
  const keyHandle = exactSessionBootstrap
    ? String(args.keyHandle || '').trim()
    : String('keyHandle' in args ? args.keyHandle || '' : '').trim();
  const sessionKind = exactSessionBootstrap
    ? args.lanePolicy.thresholdSessionKind
    : args.sessionKind || 'jwt';
  const routeAuth: ThresholdEcdsaHssRouteAuth | undefined =
    args.routeAuth || (sessionKind === 'cookie' ? { kind: 'cookie' } : undefined);
  if (!routeAuth) {
    throw new Error('routeAuth is required for JWT threshold bootstrap sessions');
  }
  const keygenSessionId = generateKeygenSessionId();
  const requestedSessionId = exactSessionBootstrap
    ? String(args.lanePolicy.thresholdSessionId).trim()
    : String(args.sessionId || '').trim();
  const requestedWalletSigningSessionId = exactSessionBootstrap
    ? String(args.lanePolicy.walletSigningSessionId).trim()
    : String(args.walletSigningSessionId || '').trim();
  const sessionId = requestedSessionId || generateThresholdSessionId();
  const walletSigningSessionId =
    requestedWalletSigningSessionId || generateWalletSigningSessionId();
  if (
    operation === 'session_bootstrap' &&
    (!keyHandle || !requestedSessionId || !requestedWalletSigningSessionId)
  ) {
    throw new Error(
      'Threshold ECDSA session bootstrap requires keyHandle, sessionId, and walletSigningSessionId',
    );
  }
  const participantIds = exactSessionBootstrap
    ? args.keyContext.participantIds.map((participantId) => Number(participantId))
    : normalizeThresholdEd25519ParticipantIds(args.participantIds);
  const runtimePolicyScope = exactSessionBootstrap
    ? args.lanePolicy.runtimePolicyScope
    : args.runtimePolicyScope;

  args.onProgress?.('signer.ecdsa.bootstrap.started');
  const sessionPolicy = buildEcdsaHssSessionPolicy({
    walletSessionUserId,
    subjectId,
    rpId,
    chainTarget,
    ...(keyHandle ? { keyHandle } : {}),
    sessionId,
    walletSigningSessionId,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(participantIds ? { participantIds } : {}),
    ttlMs: exactSessionBootstrap ? args.lanePolicy.ttlMs : args.ttlMs,
    remainingUses: exactSessionBootstrap ? args.lanePolicy.remainingUses : args.remainingUses,
  });
  const ttlMs = sessionPolicy.ttlMs;
  const remainingUses = sessionPolicy.remainingUses;
  const runRoleLocalBootstrap = async (roleLocalArgs: {
    ecdsaThresholdKeyId: EcdsaThresholdKeyId;
    signingRootId: string;
    signingRootVersion: string;
    relayerKeyId: string;
    includeClientRootProof: boolean;
  }): Promise<EmailOtpThresholdEcdsaBootstrapResult> => {
    args.onProgress?.('signer.ecdsa.bootstrap.started');
    const clientBootstrap = threshold_ecdsa_hss_role_local_client_bootstrap({
      walletSessionUserId,
      subjectId,
      ecdsaThresholdKeyId: roleLocalArgs.ecdsaThresholdKeyId,
      signingRootId: roleLocalArgs.signingRootId,
      signingRootVersion: roleLocalArgs.signingRootVersion,
      keyPurpose: ECDSA_HSS_KEY_PURPOSE,
      keyVersion: ECDSA_HSS_KEY_VERSION,
      clientRootShare32: args.clientRootShare32,
    }) as {
      contextBinding32B64u?: unknown;
      clientShare32B64u?: unknown;
      clientPublicKey33B64u?: unknown;
      clientShareRetryCounter?: unknown;
      mappedPrivateShare32B64u?: unknown;
      verifyingShare33B64u?: unknown;
    };
    const contextBinding32B64u = readString(
      clientBootstrap.contextBinding32B64u,
      'contextBinding32B64u',
    );
    const clientShare32B64u = readString(clientBootstrap.clientShare32B64u, 'clientShare32B64u');
    const clientPublicKey33B64u = readString(
      clientBootstrap.clientPublicKey33B64u,
      'clientPublicKey33B64u',
    );
    const mappedPrivateShare32B64u = readString(
      clientBootstrap.mappedPrivateShare32B64u,
      'mappedPrivateShare32B64u',
    );
    const verifyingShare33B64u = readString(
      clientBootstrap.verifyingShare33B64u,
      'verifyingShare33B64u',
    );
    const clientShareRetryCounter = Math.floor(Number(clientBootstrap.clientShareRetryCounter));
    if (!Number.isSafeInteger(clientShareRetryCounter) || clientShareRetryCounter < 0) {
      throw new Error('clientShareRetryCounter must be a non-negative safe integer');
    }
    const bootstrapIdentity = {
      walletSessionUserId,
      rpId,
      subjectId,
      ecdsaThresholdKeyId: roleLocalArgs.ecdsaThresholdKeyId,
      signingRootId: roleLocalArgs.signingRootId,
      signingRootVersion: roleLocalArgs.signingRootVersion,
      keyScope: 'evm-family' as const,
      relayerKeyId: roleLocalArgs.relayerKeyId,
      clientPublicKey33B64u,
      clientShareRetryCounter,
      contextBinding32B64u,
      requestId: keygenSessionId,
      sessionId,
      walletSigningSessionId,
      ttlMs,
      remainingUses,
      participantIds: participantIds || [1, 2],
    };
    const proofDigest32 = roleLocalArgs.includeClientRootProof
      ? await computeEcdsaHssRoleLocalFirstBootstrapRootProofDigest32(bootstrapIdentity)
      : null;
    const clientRootProof = proofDigest32
      ? {
          version: ECDSA_HSS_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION,
          digest32B64u: base64UrlEncode(proofDigest32),
          signature65B64u: base64UrlEncode(
            sign_secp256k1_recoverable(proofDigest32, args.clientRootShare32) as Uint8Array,
          ),
        }
      : undefined;

    const bootstrapRequestBase = {
      formatVersion: 'ecdsa-hss-role-local',
      walletSessionUserId,
      rpId,
      subjectId,
      ecdsaThresholdKeyId: roleLocalArgs.ecdsaThresholdKeyId,
      signingRootId: roleLocalArgs.signingRootId,
      signingRootVersion: roleLocalArgs.signingRootVersion,
      keyScope: 'evm-family',
      relayerKeyId: roleLocalArgs.relayerKeyId,
      clientPublicKey33B64u,
      clientShareRetryCounter,
      contextBinding32B64u,
      requestId: keygenSessionId,
      sessionId,
      walletSigningSessionId,
      ttlMs,
      remainingUses,
      participantIds: participantIds || [1, 2],
      auth: routeAuth,
      sessionKind,
    } satisfies ThresholdEcdsaHssRoleLocalBootstrapRequest;
    const bootstrapRequest = clientRootProof
      ? ({
          ...bootstrapRequestBase,
          clientRootProof,
        } satisfies ThresholdEcdsaHssRoleLocalBootstrapRequest)
      : bootstrapRequestBase;
    const bootstrap = await thresholdEcdsaHssRoleLocalBootstrap(relayerUrl, bootstrapRequest);
    if (!bootstrap.ok) {
      throw new Error(
        bootstrap.error ||
          bootstrap.message ||
          bootstrap.code ||
          'Threshold role-local bootstrap failed',
      );
    }
    args.onProgress?.('signer.ecdsa.bootstrap.succeeded');

    const value = bootstrap.value;
    const resolvedParticipantIds =
      normalizeThresholdEd25519ParticipantIds(value.participantIds) || participantIds;
    if (!resolvedParticipantIds) {
      throw new Error('Threshold role-local bootstrap response missing participantIds');
    }
    const emailOtpClientAdditiveShare32 = base64UrlDecode(clientShare32B64u);
    if (emailOtpClientAdditiveShare32.length !== 32) {
      zeroizeBytes(emailOtpClientAdditiveShare32);
      throw new Error('clientShare32B64u must decode to 32 bytes');
    }
    const nowMs = Date.now();
    const ecdsaHssRoleLocalClientState: ThresholdEcdsaHssRoleLocalClientState = {
      kind: 'role_local_ready',
      artifactKind: 'ecdsa-hss-role-local-client-state',
      contextBinding32B64u,
      clientShare32B64u,
      clientPublicKey33B64u,
      clientShareRetryCounter,
      relayerPublicKey33B64u: value.publicIdentity.relayerPublicKey33B64u,
      groupPublicKey33B64u: value.publicIdentity.groupPublicKey33B64u,
      ethereumAddress: value.publicIdentity.ethereumAddress,
      clientCaitSithInput: {
        participantId: 1,
        mappedPrivateShare32B64u,
        verifyingShare33B64u,
      },
      createdAtMs: nowMs,
      updatedAtMs: nowMs,
    };
    const clientAdditiveShareHandle = {
      kind: 'email_otp_worker_session' as const,
      sessionId: value.sessionId,
    };
    const thresholdSessionAuthToken =
      readOptionalString(value.jwt) ||
      (routeAuth.kind === 'threshold_session' ? readOptionalString(routeAuth.jwt) : undefined);
    return {
      thresholdEcdsaKeyRef: {
        type: 'threshold-ecdsa-secp256k1',
        userId: walletSessionUserId,
        chainTarget,
        relayerUrl,
        keyHandle: value.keyHandle,
        ecdsaThresholdKeyId: value.ecdsaThresholdKeyId,
        signingRootId: value.signingRootId,
        signingRootVersion: value.signingRootVersion,
        backendBinding: {
          relayerKeyId: value.relayerKeyId,
          clientVerifyingShareB64u: clientPublicKey33B64u,
          clientAdditiveShareHandle,
          ecdsaHssRoleLocalClientState,
        },
        participantIds: resolvedParticipantIds,
        thresholdEcdsaPublicKeyB64u: value.thresholdEcdsaPublicKeyB64u,
        ethereumAddress: value.ethereumAddress,
        relayerVerifyingShareB64u: value.relayerVerifyingShareB64u,
        thresholdSessionKind: sessionKind,
        ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
        thresholdSessionId: value.sessionId,
        walletSigningSessionId: value.walletSigningSessionId,
      },
      keygen: {
        ok: true,
        keygenSessionId,
        rpId,
        ecdsaThresholdKeyId: value.ecdsaThresholdKeyId,
        clientVerifyingShareB64u: clientPublicKey33B64u,
        relayerKeyId: value.relayerKeyId,
        thresholdEcdsaPublicKeyB64u: value.thresholdEcdsaPublicKeyB64u,
        ethereumAddress: value.ethereumAddress,
        relayerVerifyingShareB64u: value.relayerVerifyingShareB64u,
        participantIds: resolvedParticipantIds,
        chainId,
      },
      session: {
        ok: true,
        sessionId: value.sessionId,
        walletSigningSessionId: value.walletSigningSessionId,
        expiresAtMs: value.expiresAtMs,
        remainingUses: value.remainingUses,
        ...(thresholdSessionAuthToken ? { jwt: thresholdSessionAuthToken } : {}),
        clientVerifyingShareB64u: clientPublicKey33B64u,
      },
      emailOtpClientAdditiveShare32,
    };
  };

  const roleLocalRelayerKeyId = relayerKeyIdFromRouteAuth(routeAuth);
  if (exactSessionBootstrap && roleLocalRelayerKeyId) {
    return await runRoleLocalBootstrap({
      ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId(args.keyContext.ecdsaThresholdKeyId),
      signingRootId: readString(args.keyContext.signingRootId, 'signingRootId'),
      signingRootVersion: readString(args.keyContext.signingRootVersion, 'signingRootVersion'),
      relayerKeyId: roleLocalRelayerKeyId,
      includeClientRootProof: false,
    });
  }

  const existingKeyRoleLocalIdentity =
    !exactSessionBootstrap &&
    operation === 'email_otp_bootstrap' &&
    keyHandle &&
    'roleLocalKeyIdentity' in args
      ? args.roleLocalKeyIdentity
      : undefined;
  if (existingKeyRoleLocalIdentity) {
    return await runRoleLocalBootstrap({
      ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId(
        existingKeyRoleLocalIdentity.ecdsaThresholdKeyId,
      ),
      signingRootId: readString(existingKeyRoleLocalIdentity.signingRootId, 'signingRootId'),
      signingRootVersion: readString(
        existingKeyRoleLocalIdentity.signingRootVersion,
        'signingRootVersion',
      ),
      relayerKeyId: readString(existingKeyRoleLocalIdentity.relayerKeyId, 'relayerKeyId'),
      includeClientRootProof: true,
    });
  }

  if (
    !exactSessionBootstrap &&
    operation === 'email_otp_bootstrap' &&
    !keyHandle &&
    runtimePolicyScope
  ) {
    const signingRootScope = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope);
    const signingRootId = readString(signingRootScope.signingRootId, 'signingRootId');
    const signingRootVersion = readString(
      signingRootScope.signingRootVersion,
      'signingRootVersion',
    );
    const ecdsaThresholdKeyId = toEcdsaHssThresholdKeyId(
      await computeEcdsaHssRoleLocalThresholdKeyId({
        walletSessionUserId,
        rpId,
        subjectId,
        signingRootId,
        signingRootVersion,
      }),
    );
    return await runRoleLocalBootstrap({
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      relayerKeyId: await computeEcdsaHssRoleLocalRelayerKeyId({
        walletSessionUserId,
        rpId,
      }),
      includeClientRootProof: true,
    });
  }

  throw new Error(
    'Threshold ECDSA Email OTP bootstrap requires concrete role-local key identity',
  );
}

async function runEmailOtpEcdsaPublicationBootstrapsFromClientRootShare(args: {
  relayUrl: string;
  walletSessionUserId: string;
  subjectId: WalletSubjectId;
  rpId: string;
  clientRootShare32: Uint8Array;
  publicationChainTargets: ThresholdEcdsaChainTarget[];
  keyHandle?: string;
  roleLocalKeyIdentity?: {
    ecdsaThresholdKeyId: EcdsaThresholdKeyId;
    signingRootId: string;
    signingRootVersion: string;
    relayerKeyId: string;
  };
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  walletSigningSessionId?: string;
  routeAuth?: AppOrThresholdSessionAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  ttlMs?: number;
  remainingUses?: number;
  onProgress?: (code: EmailOtpWorkerProgressCode) => void;
}): Promise<ThresholdEcdsaSessionBootstrapResult[]> {
  const publicationChainTargets = args.publicationChainTargets;
  if (!publicationChainTargets.length) {
    throw new Error('Email OTP ECDSA bootstrap requires at least one publication target');
  }
  if (publicationChainTargets.length > 1 && String(args.sessionId || '').trim()) {
    throw new Error('Email OTP multi-target ECDSA bootstrap requires per-target session ids');
  }
  const walletSigningSessionId =
    String(args.walletSigningSessionId || '').trim() || generateWalletSigningSessionId();
  let canonicalKeyHandle = String(args.keyHandle || '').trim();
  let canonicalRoleLocalKeyIdentity:
    | {
        ecdsaThresholdKeyId: EcdsaThresholdKeyId;
        signingRootId: string;
        signingRootVersion: string;
        relayerKeyId: string;
      }
    | null = args.roleLocalKeyIdentity
    ? {
        ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId(
          args.roleLocalKeyIdentity.ecdsaThresholdKeyId,
        ),
        signingRootId: readString(args.roleLocalKeyIdentity.signingRootId, 'signingRootId'),
        signingRootVersion: readString(
          args.roleLocalKeyIdentity.signingRootVersion,
          'signingRootVersion',
        ),
        relayerKeyId: readString(args.roleLocalKeyIdentity.relayerKeyId, 'relayerKeyId'),
      }
    : null;
  const bootstraps: ThresholdEcdsaSessionBootstrapResult[] = [];

  for (const chainTarget of publicationChainTargets) {
    const walletSessionUserId = toWalletSessionUserId(args.walletSessionUserId);
    const workerBootstrap: EmailOtpThresholdEcdsaBootstrapResult = canonicalKeyHandle
      ? await runThresholdEcdsaAuthorizationBootstrapFromClientRootShare({
          relayUrl: args.relayUrl,
          walletSessionUserId,
          subjectId: args.subjectId,
          rpId: args.rpId,
          clientRootShare32: args.clientRootShare32,
          operation: 'email_otp_bootstrap',
          keyHandle: canonicalKeyHandle,
          ...(canonicalRoleLocalKeyIdentity
            ? { roleLocalKeyIdentity: canonicalRoleLocalKeyIdentity }
            : {}),
          participantIds: args.participantIds,
          sessionKind: args.sessionKind,
          ...(publicationChainTargets.length === 1 && args.sessionId
            ? { sessionId: args.sessionId }
            : {}),
          walletSigningSessionId,
          chainTarget,
          ...(args.routeAuth ? { routeAuth: args.routeAuth } : {}),
          ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
          ttlMs: args.ttlMs,
          remainingUses: args.remainingUses,
          onProgress: args.onProgress,
        })
      : await runThresholdEcdsaAuthorizationBootstrapFromClientRootShare({
          relayUrl: args.relayUrl,
          walletSessionUserId,
          subjectId: args.subjectId,
          rpId: args.rpId,
          clientRootShare32: args.clientRootShare32,
          operation: 'email_otp_bootstrap',
          participantIds: args.participantIds,
          sessionKind: args.sessionKind,
          ...(publicationChainTargets.length === 1 && args.sessionId
            ? { sessionId: args.sessionId }
            : {}),
          walletSigningSessionId,
          chainTarget,
          ...(args.routeAuth ? { routeAuth: args.routeAuth } : {}),
          ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
          ttlMs: args.ttlMs,
          remainingUses: args.remainingUses,
          onProgress: args.onProgress,
        });
    const { emailOtpClientAdditiveShare32, ...bootstrap }: EmailOtpThresholdEcdsaBootstrapResult =
      workerBootstrap;
    let signingSessionSecret32: Uint8Array | null = Uint8Array.from(args.clientRootShare32);
    try {
      putEmailOtpWarmSessionMaterial({
        sessionId: readString(bootstrap.session?.sessionId, 'thresholdSessionId'),
        clientRootShare32: args.clientRootShare32,
        signingSessionSecret32,
        clientAdditiveShare32: emailOtpClientAdditiveShare32,
        expiresAtMs: Math.floor(Number(bootstrap.session?.expiresAtMs) || 0),
        remainingUses: Math.floor(Number(bootstrap.session?.remainingUses) || 0),
      });
      bootstraps.push(bootstrap);
      const returnedKeyHandle = readString(bootstrap.thresholdEcdsaKeyRef.keyHandle, 'keyHandle');
      if (canonicalKeyHandle && returnedKeyHandle !== canonicalKeyHandle) {
        throw new Error('Email OTP ECDSA publication returned inconsistent key handles');
      }
      canonicalKeyHandle = returnedKeyHandle;
      canonicalRoleLocalKeyIdentity = {
        ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId(
          bootstrap.thresholdEcdsaKeyRef.ecdsaThresholdKeyId,
        ),
        signingRootId: readString(bootstrap.thresholdEcdsaKeyRef.signingRootId, 'signingRootId'),
        signingRootVersion: readString(
          bootstrap.thresholdEcdsaKeyRef.signingRootVersion,
          'signingRootVersion',
        ),
        relayerKeyId: readString(
          bootstrap.thresholdEcdsaKeyRef.backendBinding?.relayerKeyId,
          'relayerKeyId',
        ),
      };
    } finally {
      zeroizeBytes(signingSessionSecret32);
      zeroizeBytes(emailOtpClientAdditiveShare32);
      signingSessionSecret32 = null;
    }
  }
  return bootstraps;
}

async function runThresholdEcdsaRoleLocalExportFromClientRootShare(args: {
  relayUrl: string;
  userId: string;
  subjectId?: WalletSubjectId;
  rpId: string;
  clientRootShare32: Uint8Array;
  keyHandle: string;
  relayerKeyId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion?: string;
  roleLocalState: ThresholdEcdsaHssRoleLocalClientState;
  thresholdSessionId: string;
  walletSigningSessionId: string;
  thresholdExpiresAtMs: number;
  participantIds: number[];
  thresholdSessionAuthToken?: string;
  sessionKind?: 'jwt' | 'cookie';
}): Promise<{
  publicKeyHex: string;
  privateKeyHex: string;
  ethereumAddress: string;
}> {
  await ensureHssClientSignerWasm();
  const relayerUrl = readString(args.relayUrl, 'relayUrl');
  const userId = readString(args.userId, 'userId');
  const walletSessionUserId = toWalletSessionUserId(userId);
  const subjectId = toWalletSubjectId(args.subjectId || userId);
  const rpId = readString(args.rpId, 'rpId');
  const keyHandle = requireThresholdEcdsaHssKeyHandle(args.keyHandle, 'explicit export');
  const ecdsaThresholdKeyId = toEcdsaHssThresholdKeyId(args.ecdsaThresholdKeyId);
  const signingRootId = readString(args.signingRootId, 'signingRootId');
  const signingRootVersion = readString(
    args.signingRootVersion || ECDSA_HSS_SIGNING_ROOT_VERSION_DEFAULT,
    'signingRootVersion',
  );
  const thresholdSessionId = readString(args.thresholdSessionId, 'thresholdSessionId');
  const walletSigningSessionId = readString(
    args.walletSigningSessionId,
    'walletSigningSessionId',
  );
  const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds);
  if (!participantIds) {
    throw new Error('threshold export requires participantIds');
  }
  const thresholdSessionAuthToken = readOptionalString(args.thresholdSessionAuthToken);
  const sessionKind = args.sessionKind || 'jwt';
  if (!thresholdSessionAuthToken && sessionKind !== 'cookie') {
    throw new Error('thresholdSessionAuthToken is required for JWT threshold export sessions');
  }
  const routeAuth: ThresholdEcdsaHssRouteAuth | undefined = thresholdSessionAuthToken
    ? { kind: 'threshold_session', jwt: thresholdSessionAuthToken }
    : sessionKind === 'cookie'
      ? { kind: 'cookie' }
      : undefined;
  if (!routeAuth) {
    throw new Error('threshold export requires route auth');
  }
  const issuedAtUnixMs = Date.now();
  const expiresAtUnixMs = Math.min(
    issuedAtUnixMs + ECDSA_HSS_EXPORT_AUTH_TTL_MS,
    Math.floor(Number(args.thresholdExpiresAtMs)),
  );
  if (!Number.isFinite(expiresAtUnixMs) || expiresAtUnixMs <= issuedAtUnixMs) {
    throw new Error('threshold export session is expired');
  }
  const relayerKeyId = readString(args.relayerKeyId, 'relayerKeyId');
  const publicIdentity = {
    clientPublicKey33B64u: args.roleLocalState.clientPublicKey33B64u,
    relayerPublicKey33B64u: args.roleLocalState.relayerPublicKey33B64u,
    groupPublicKey33B64u: args.roleLocalState.groupPublicKey33B64u,
    ethereumAddress: args.roleLocalState.ethereumAddress,
  };
  const exportRequestNonce32B64u = randomB64u32();
  const confirmationDigest32B64u = await digestB64u({
    version: ECDSA_HSS_EXPORT_CONFIRMATION_DIGEST_VERSION,
    walletSessionUserId,
    rpId,
    subjectId,
    ecdsaThresholdKeyId,
    relayerKeyId,
    contextBinding32B64u: args.roleLocalState.contextBinding32B64u,
    publicIdentity,
    clientDeviceId: walletSigningSessionId,
    clientSessionId: thresholdSessionId,
    exportRequestNonce32B64u,
    issuedAtUnixMs,
    expiresAtUnixMs,
  });
  const authorizationDigest32B64u = await digestB64u({
    version: ECDSA_HSS_EXPORT_AUTHORIZATION_DIGEST_VERSION,
    operation: 'explicit_key_export',
    keyHandle,
    walletSessionUserId,
    rpId,
    subjectId,
    ecdsaThresholdKeyId,
    relayerKeyId,
    signingRootId,
    signingRootVersion,
    contextBinding32B64u: args.roleLocalState.contextBinding32B64u,
    publicIdentity,
    exportRequestNonce32B64u,
    confirmationDigest32B64u,
    issuedAtUnixMs,
    expiresAtUnixMs,
    clientDeviceId: walletSigningSessionId,
    clientSessionId: thresholdSessionId,
    thresholdSessionId,
    walletSigningSessionId,
    thresholdExpiresAtMs: args.thresholdExpiresAtMs,
    participantIds,
  });
  const exportShare = await thresholdEcdsaHssRoleLocalExportShare(relayerUrl, {
    formatVersion: 'ecdsa-hss-role-local-export',
    walletSessionUserId,
    rpId,
    subjectId,
    ecdsaThresholdKeyId,
    relayerKeyId,
    contextBinding32B64u: args.roleLocalState.contextBinding32B64u,
    publicIdentity,
    exportRequestNonce32B64u,
    confirmationDigest32B64u,
    authorizationDigest32B64u,
    issuedAtUnixMs,
    expiresAtUnixMs,
    clientDeviceId: walletSigningSessionId,
    clientSessionId: thresholdSessionId,
    auth: routeAuth,
    sessionKind,
  });
  if (!exportShare.ok) {
    throw new Error(
      exportShare.error || exportShare.message || exportShare.code || 'Threshold export share failed',
    );
  }
  const artifact = threshold_ecdsa_hss_role_local_export_artifact({
    walletSessionUserId,
    subjectId,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    keyPurpose: ECDSA_HSS_KEY_PURPOSE,
    keyVersion: ECDSA_HSS_KEY_VERSION,
    clientRootShare32: args.clientRootShare32,
    serverExportShare32B64u: exportShare.value.serverExportShare32B64u,
    contextBinding32B64u: args.roleLocalState.contextBinding32B64u,
    clientPublicKey33B64u: args.roleLocalState.clientPublicKey33B64u,
    relayerPublicKey33B64u: args.roleLocalState.relayerPublicKey33B64u,
    groupPublicKey33B64u: args.roleLocalState.groupPublicKey33B64u,
    ethereumAddress: args.roleLocalState.ethereumAddress,
    clientShareRetryCounter: args.roleLocalState.clientShareRetryCounter,
  }) as { publicKeyHex?: unknown; privateKeyHex?: unknown; ethereumAddress?: unknown };
  return {
    publicKeyHex: readString(artifact.publicKeyHex, 'publicKeyHex'),
    privateKeyHex: readString(artifact.privateKeyHex, 'privateKeyHex'),
    ethereumAddress: readString(artifact.ethereumAddress, 'ethereumAddress'),
  };
}

async function attachOptionalEcdsaExportArtifactToPrimaryBootstrap(args: {
  includeEcdsaExportArtifact?: boolean;
  primaryBootstrap: ThresholdEcdsaSessionBootstrapResult;
  relayerUrl: string;
  userId: string;
  rpId: string;
  clientRootShare32: Uint8Array;
  sessionKind?: 'jwt' | 'cookie';
}): Promise<
  | {
      artifactKind: 'ecdsa-hss-secp256k1-key-v1';
      chainTarget: ThresholdEcdsaChainTarget;
      signingRootId: string;
      signingRootVersion?: string;
      publicKeyHex: string;
      privateKeyHex: string;
      ethereumAddress: string;
    }
  | undefined
> {
  if (!args.includeEcdsaExportArtifact) return undefined;
  const roleLocalState =
    args.primaryBootstrap.thresholdEcdsaKeyRef.backendBinding?.ecdsaHssRoleLocalClientState;
  if (!roleLocalState) {
    throw new Error('Email OTP ECDSA export requires role-local HSS client state');
  }
  const artifact = {
    artifactKind: 'ecdsa-hss-secp256k1-key-v1' as const,
    chainTarget: args.primaryBootstrap.thresholdEcdsaKeyRef.chainTarget,
    signingRootId: readString(
      args.primaryBootstrap.thresholdEcdsaKeyRef.signingRootId,
      'signingRootId',
    ),
    ...(args.primaryBootstrap.thresholdEcdsaKeyRef.signingRootVersion
      ? {
          signingRootVersion: args.primaryBootstrap.thresholdEcdsaKeyRef.signingRootVersion,
        }
      : {}),
    ...(await runThresholdEcdsaRoleLocalExportFromClientRootShare({
      relayUrl: args.relayerUrl,
      userId: args.userId,
      subjectId: toWalletSubjectId(args.userId),
      rpId: args.rpId,
      clientRootShare32: args.clientRootShare32,
      keyHandle: readString(args.primaryBootstrap.thresholdEcdsaKeyRef.keyHandle, 'keyHandle'),
      relayerKeyId: readString(
        args.primaryBootstrap.thresholdEcdsaKeyRef.backendBinding?.relayerKeyId,
        'relayerKeyId',
      ),
      ecdsaThresholdKeyId: readString(
        args.primaryBootstrap.thresholdEcdsaKeyRef.ecdsaThresholdKeyId,
        'ecdsaThresholdKeyId',
      ),
      signingRootId: readString(
        args.primaryBootstrap.thresholdEcdsaKeyRef.signingRootId,
        'signingRootId',
      ),
      signingRootVersion: args.primaryBootstrap.thresholdEcdsaKeyRef.signingRootVersion,
      roleLocalState,
      thresholdSessionId: readString(args.primaryBootstrap.session.sessionId, 'thresholdSessionId'),
      walletSigningSessionId: readString(
        args.primaryBootstrap.session.walletSigningSessionId,
        'walletSigningSessionId',
      ),
      thresholdExpiresAtMs: args.primaryBootstrap.session.expiresAtMs,
      participantIds: args.primaryBootstrap.thresholdEcdsaKeyRef.participantIds || [],
      thresholdSessionAuthToken: args.primaryBootstrap.session.jwt,
      sessionKind: args.sessionKind,
    })),
  };
  args.primaryBootstrap.thresholdEcdsaKeyRef.ecdsaHssExportArtifact = artifact;
  return artifact;
}

function postToMainThread(message: unknown, transfer?: Transferable[]): void {
  (
    self as unknown as { postMessage: (message: unknown, transfer?: Transferable[]) => void }
  ).postMessage(message, transfer);
}

function postEmailOtpWorkerProgress(id: string, code: EmailOtpWorkerProgressCode): void {
  postToMainThread({ id, progress: true, payload: { code } });
}

setTimeout(() => {
  postToMainThread({ type: WorkerControlMessage.WORKER_READY, ready: true });
}, 0);

self.addEventListener('message', async (event: MessageEvent) => {
  const msg = event.data as EmailOtpWorkerRequest;
  if (!msg?.id || !msg?.type) return;

  try {
    switch (msg.type) {
      case 'requestEmailOtpChallenge': {
        const routePlan = readRoutePlan(msg.payload.routePlan, 'requestEmailOtpChallenge');
        const sessionAuth = routePlanSessionAuth(routePlan);
        const response = await postEmailOtpJson({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          route: emailOtpRoutePath(routePlan, 'challenge'),
          ...(sessionAuth ? { sessionAuth } : {}),
          body: {
            walletId: readString(msg.payload.walletId, 'walletId'),
            otpChannel: EMAIL_OTP_CHANNEL,
            operation: routePlan.operation,
          },
        });
        const challenge = response.challenge as Record<string, unknown>;
        const delivery = response.delivery as Record<string, unknown> | undefined;
        const expiresAtMs = Number(challenge?.expiresAtMs);
        const emailHint = String(delivery?.emailHint || '').trim();
        postToMainThread({
          id: msg.id,
          ok: true,
          result: {
            challengeId: readString(challenge?.challengeId, 'challengeId'),
            otpChannel: EMAIL_OTP_CHANNEL,
            ...(emailHint ? { emailHint } : {}),
            ...(Number.isFinite(expiresAtMs) ? { expiresAtMs } : {}),
          },
        });
        return;
      }
      case 'requestEmailOtpEnrollmentChallenge': {
        const routePlan = readRoutePlan(
          msg.payload.routePlan,
          'requestEmailOtpEnrollmentChallenge',
        );
        const sessionAuth = routePlanSessionAuth(routePlan);
        const response = await postEmailOtpJson({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          route: emailOtpRoutePath(routePlan, 'challenge'),
          ...(sessionAuth ? { sessionAuth } : {}),
          body: {
            walletId: readString(msg.payload.walletId, 'walletId'),
            otpChannel: EMAIL_OTP_CHANNEL,
          },
        });
        const challenge = response.challenge as Record<string, unknown>;
        const delivery = response.delivery as Record<string, unknown> | undefined;
        const expiresAtMs = Number(challenge?.expiresAtMs);
        const emailHint = String(delivery?.emailHint || '').trim();
        postToMainThread({
          id: msg.id,
          ok: true,
          result: {
            challengeId: readString(challenge?.challengeId, 'challengeId'),
            otpChannel: EMAIL_OTP_CHANNEL,
            ...(emailHint ? { emailHint } : {}),
            ...(Number.isFinite(expiresAtMs) ? { expiresAtMs } : {}),
          },
        });
        return;
      }
      case 'enrollEmailOtpWallet': {
        const routePlan = readRoutePlan(msg.payload.routePlan, 'enrollEmailOtpWallet');
        const result = await completeEmailOtpEnrollmentFromSecret32({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          walletId: readString(msg.payload.walletId, 'walletId'),
          userId: msg.payload.userId,
          challengeId: msg.payload.challengeId,
          otpCode: readString(msg.payload.otpCode, 'otpCode'),
          shamirPrimeB64u: readString(msg.payload.shamirPrimeB64u, 'shamirPrimeB64u'),
          routePlan,
          returnClientRootShare32: true,
          onProgress: (code) => postEmailOtpWorkerProgress(msg.id, code),
          ...(msg.payload.clientSecret32 instanceof ArrayBuffer
            ? {
                clientSecret32: requireFixed32ArrayBuffer(
                  msg.payload.clientSecret32,
                  'clientSecret32',
                ),
              }
            : {}),
        });
        postToMainThread({
          id: msg.id,
          ok: true,
          result: {
            thresholdEcdsaClientVerifyingShareB64u: result.thresholdEcdsaClientVerifyingShareB64u,
            thresholdEd25519PrfFirstB64u: result.thresholdEd25519PrfFirstB64u,
            recoveryKeys: result.recoveryKeys,
            challengeId: result.challengeId,
            otpChannel: result.otpChannel,
            enrollmentSealKeyVersion: result.enrollmentSealKeyVersion,
            clientUnlockPublicKeyB64u: result.clientUnlockPublicKeyB64u,
            unlockKeyVersion: result.unlockKeyVersion,
            clientRootShare32B64u: base64UrlEncode(
              (() => {
                if (!(result.clientRootShare32 instanceof Uint8Array)) {
                  throw new Error(
                    'Email OTP enrollment did not return client root share for bootstrap',
                  );
                }
                return result.clientRootShare32;
              })(),
            ),
          },
        });
        zeroizeBytes(result.clientRootShare32);
        return;
      }
      case 'verifyEmailOtpCode': {
        const routePlan = readRoutePlan(msg.payload.routePlan, 'verifyEmailOtpCode');
        const sessionAuth = routePlanSessionAuth(routePlan);
        const response = await postEmailOtpJson({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          route: emailOtpRoutePath(routePlan, 'verify'),
          ...(sessionAuth ? { sessionAuth } : {}),
          body: {
            walletId: readString(msg.payload.walletId, 'walletId'),
            challengeId: readString(msg.payload.challengeId, 'challengeId'),
            otpCode: readString(msg.payload.otpCode, 'otpCode'),
            otpChannel: EMAIL_OTP_CHANNEL,
            operation: routePlan.operation,
          },
        });
        postToMainThread({
          id: msg.id,
          ok: true,
          result: {
            loginGrant: readString(response.loginGrant, 'loginGrant'),
            otpChannel: EMAIL_OTP_CHANNEL,
            ...(readOptionalString(response.enrollmentSealKeyVersion)
              ? { enrollmentSealKeyVersion: readOptionalString(response.enrollmentSealKeyVersion) }
              : {}),
          },
        });
        return;
      }
      case 'restoreEmailOtpDeviceEnrollmentEscrow': {
        const routePlan = readRoutePlan(
          msg.payload.routePlan,
          'restoreEmailOtpDeviceEnrollmentEscrow',
        );
        const result = await restoreEmailOtpDeviceEnrollmentEscrowFromRecoveryKey({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          walletId: readString(msg.payload.walletId, 'walletId'),
          userId: msg.payload.userId,
          challengeId: readString(msg.payload.challengeId, 'challengeId'),
          otpCode: readString(msg.payload.otpCode, 'otpCode'),
          recoveryKey: readString(msg.payload.recoveryKey, 'recoveryKey'),
          shamirPrimeB64u: readString(msg.payload.shamirPrimeB64u, 'shamirPrimeB64u'),
          routePlan,
        });
        postToMainThread({
          id: msg.id,
          ok: true,
          result,
        });
        return;
      }
      case 'removeEmailOtpDeviceEnrollmentEscrowFromDevice': {
        const result = await removeEmailOtpDeviceEnrollmentEscrowFromDevice({
          walletId: readString(msg.payload.walletId, 'walletId'),
          userId: msg.payload.userId,
          enrollmentId: msg.payload.enrollmentId,
        });
        postToMainThread({
          id: msg.id,
          ok: true,
          result,
        });
        return;
      }
      case 'loginWithEmailOtpWallet': {
        const routePlan = readRoutePlan(msg.payload.routePlan, 'loginWithEmailOtpWallet');
        const routeAuth = routePlanSessionAuth(routePlan);
        const runtimePolicyScope =
          normalizeThresholdRuntimePolicyScope(msg.payload.runtimePolicyScope) ||
          parseThresholdRuntimePolicyScopeFromJwt(routeAuth?.jwt);
        const result = await loginWithEmailOtpAndRecoverClientRootShare({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          walletId: readString(msg.payload.walletId, 'walletId'),
          ...(runtimePolicyScope?.orgId ? { orgId: runtimePolicyScope.orgId } : {}),
          userId: msg.payload.userId,
          challengeId: msg.payload.challengeId,
          otpCode: readString(msg.payload.otpCode, 'otpCode'),
          shamirPrimeB64u: readString(msg.payload.shamirPrimeB64u, 'shamirPrimeB64u'),
          routePlan,
          onProgress: (code) => postEmailOtpWorkerProgress(msg.id, code),
        });
        try {
          postToMainThread({
            id: msg.id,
            ok: true,
            result: {
              recovery: {
                challengeId: result.challengeId,
                enrollmentSealKeyVersion: result.enrollmentSealKeyVersion,
                unlockChallengeId: result.unlockChallengeId,
                unlockChallengeB64u: result.unlockChallengeB64u,
                clientUnlockPublicKeyB64u: result.clientUnlockPublicKeyB64u,
                unlockSignatureB64u: result.unlockSignatureB64u,
                thresholdEd25519PrfFirstB64u: result.thresholdEd25519PrfFirstB64u,
              },
              clientRootShare32B64u: base64UrlEncode(result.clientRootShare32),
            },
          });
        } finally {
          zeroizeBytes(result.clientRootShare32);
        }
        return;
      }
      case 'recoverEmailOtpEd25519ExportPrfFirst': {
        const routePlan = readRoutePlan(
          msg.payload.routePlan,
          'recoverEmailOtpEd25519ExportPrfFirst',
        );
        if (routePlan.operation !== WALLET_EMAIL_OTP_EXPORT_OPERATION) {
          throw new Error('Email OTP Ed25519 export recovery requires export_key routePlan');
        }
        const routeAuth = routePlanSessionAuth(routePlan);
        const runtimePolicyScope =
          normalizeThresholdRuntimePolicyScope(msg.payload.runtimePolicyScope) ||
          parseThresholdRuntimePolicyScopeFromJwt(routeAuth?.jwt);
        const result = await loginWithEmailOtpAndRecoverClientRootShare({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          walletId: readString(msg.payload.walletId, 'walletId'),
          ...(runtimePolicyScope?.orgId ? { orgId: runtimePolicyScope.orgId } : {}),
          userId: msg.payload.userId,
          challengeId: readString(msg.payload.challengeId, 'challengeId'),
          otpCode: readString(msg.payload.otpCode, 'otpCode'),
          shamirPrimeB64u: readString(msg.payload.shamirPrimeB64u, 'shamirPrimeB64u'),
          routePlan,
          onProgress: (code) => postEmailOtpWorkerProgress(msg.id, code),
        });
        try {
          postToMainThread({
            id: msg.id,
            ok: true,
            result: {
              challengeId: result.challengeId,
              thresholdEd25519PrfFirstB64u: result.thresholdEd25519PrfFirstB64u,
            },
          });
        } finally {
          zeroizeBytes(result.clientRootShare32);
        }
        return;
      }
      case 'bootstrapEmailOtpEcdsaSessionsFromClientRootShare': {
        let clientRootShare32: Uint8Array | null = null;
        try {
          const relayerUrl = readString(msg.payload.relayUrl, 'relayUrl');
          const walletId = readString(msg.payload.walletId, 'walletId');
          const walletSessionUserId = readString(
            msg.payload.walletSessionUserId,
            'walletSessionUserId',
          );
          const userId = readOptionalString(msg.payload.userId) || walletId;
          const rpId = readString(msg.payload.rpId, 'rpId');
          const publicationChainTargets = readEcdsaPublicationChainTargets({
            primaryChainTarget: msg.payload.chainTarget,
            publicationChainTargets: msg.payload.publicationChainTargets,
          });
          clientRootShare32 = base64UrlDecode(
            readString(msg.payload.clientRootShare32B64u, 'clientRootShare32B64u'),
          );
          const bootstraps = await runEmailOtpEcdsaPublicationBootstrapsFromClientRootShare({
            relayUrl: relayerUrl,
            walletSessionUserId,
            subjectId: toWalletSubjectId(msg.payload.subjectId),
            rpId,
            clientRootShare32,
            publicationChainTargets,
            keyHandle: msg.payload.keyHandle,
            ...(msg.payload.roleLocalKeyIdentity
              ? {
                  roleLocalKeyIdentity: {
                    ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId(
                      msg.payload.roleLocalKeyIdentity.ecdsaThresholdKeyId,
                    ),
                    signingRootId: readString(
                      msg.payload.roleLocalKeyIdentity.signingRootId,
                      'roleLocalKeyIdentity.signingRootId',
                    ),
                    signingRootVersion: readString(
                      msg.payload.roleLocalKeyIdentity.signingRootVersion,
                      'roleLocalKeyIdentity.signingRootVersion',
                    ),
                    relayerKeyId: readString(
                      msg.payload.roleLocalKeyIdentity.relayerKeyId,
                      'roleLocalKeyIdentity.relayerKeyId',
                    ),
                  },
                }
              : {}),
            participantIds: msg.payload.participantIds,
            sessionKind: msg.payload.sessionKind,
            sessionId: msg.payload.sessionId,
            walletSigningSessionId: msg.payload.walletSigningSessionId,
            routeAuth: msg.payload.routeAuth,
            runtimePolicyScope: msg.payload.runtimePolicyScope,
            ttlMs: msg.payload.ttlMs,
            remainingUses: msg.payload.remainingUses,
            onProgress: (code) => postEmailOtpWorkerProgress(msg.id, code),
          });
          const primaryBootstrap = bootstraps[0];
          if (!primaryBootstrap) {
            throw new Error('Email OTP ECDSA bootstrap returned no publication lanes');
          }
          const ecdsaHssExportArtifact = await attachOptionalEcdsaExportArtifactToPrimaryBootstrap({
            includeEcdsaExportArtifact: msg.payload.includeEcdsaExportArtifact,
            primaryBootstrap,
            relayerUrl,
            userId: walletSessionUserId,
            rpId,
            clientRootShare32,
            sessionKind: msg.payload.sessionKind,
          });
          postToMainThread({
            id: msg.id,
            ok: true,
            result: {
              bootstraps,
              ...(ecdsaHssExportArtifact ? { ecdsaHssExportArtifact } : {}),
            },
          });
        } finally {
          zeroizeBytes(clientRootShare32);
          clientRootShare32 = null;
        }
        return;
      }
      case 'getEmailOtpWarmSessionStatus': {
        postToMainThread({
          id: msg.id,
          ok: true,
          result: readEmailOtpWarmSessionStatus(msg.payload.sessionId),
        });
        return;
      }
      case 'claimEmailOtpWarmSessionMaterial': {
        postToMainThread({
          id: msg.id,
          ok: true,
          result: claimEmailOtpWarmSessionMaterial({
            sessionId: readString(msg.payload.sessionId, 'sessionId'),
            uses: msg.payload.uses,
            consume: msg.payload.consume,
          }),
        });
        return;
      }
      case 'consumeEmailOtpWarmSessionUses': {
        postToMainThread({
          id: msg.id,
          ok: true,
          result: consumeEmailOtpWarmSessionUses({
            sessionId: readString(msg.payload.sessionId, 'sessionId'),
            uses: msg.payload.uses,
          }),
        });
        return;
      }
      case 'sealEmailOtpWarmSessionMaterial': {
        const transport = parseSigningSessionSealTransport(msg.payload.transport);
        const result = transport
          ? await sealEmailOtpWarmSessionMaterial({
              sessionId: readString(msg.payload.sessionId, 'sessionId'),
              transport,
            })
          : {
              ok: false,
              code: 'invalid_args',
              message: 'Invalid signing-session seal transport',
            };
        postToMainThread({
          id: msg.id,
          ok: true,
          result,
        });
        return;
      }
      case 'rehydrateEmailOtpEcdsaWarmSessionMaterial': {
        const transport = parseSigningSessionSealTransport(msg.payload.transport);
        const result = transport
          ? await rehydrateEmailOtpEcdsaWarmSessionMaterial({
              sealedSecretB64u: readString(msg.payload.sealedSecretB64u, 'sealedSecretB64u'),
              remainingUses: Math.floor(Number(msg.payload.remainingUses) || 0),
              expiresAtMs: Math.floor(Number(msg.payload.expiresAtMs) || 0),
              transport,
              restore: msg.payload.restore,
            })
          : {
              ok: false,
              code: 'invalid_args',
              message: 'Invalid signing-session seal transport',
            };
        postToMainThread({
          id: msg.id,
          ok: true,
          result,
        });
        return;
      }
      case 'claimEmailOtpEcdsaSigningShare': {
        const result = claimEmailOtpEcdsaSigningShare(
          readString(msg.payload.sessionId, 'sessionId'),
        );
        postToMainThread(
          {
            id: msg.id,
            ok: true,
            result,
          },
          result.ok ? [result.clientSigningShare32] : undefined,
        );
        return;
      }
      case 'clearEmailOtpWarmSessionMaterial': {
        deleteEmailOtpWarmSession(readString(msg.payload.sessionId, 'sessionId'));
        postToMainThread({
          id: msg.id,
          ok: true,
          result: {
            ok: true,
            cleared: true,
          },
        });
        return;
      }
      case 'exportThresholdEcdsaHssKeyWithEmailOtpAuthorization': {
        const routePlan = readRoutePlan(
          msg.payload.routePlan,
          'exportThresholdEcdsaHssKeyWithEmailOtpAuthorization',
        );
        if (routePlan.operation !== WALLET_EMAIL_OTP_EXPORT_OPERATION) {
          throw new Error('Email OTP ECDSA export requires export_key routePlan');
        }
        const routeAuth = routePlanSessionAuth(routePlan);
        const runtimePolicyScope =
          normalizeThresholdRuntimePolicyScope(msg.payload.runtimePolicyScope) ||
          parseThresholdRuntimePolicyScopeFromJwt(routeAuth?.jwt);
        const recovered = await loginWithEmailOtpAndRecoverClientRootShare({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          walletId: readString(msg.payload.walletId, 'walletId'),
          ...(runtimePolicyScope?.orgId ? { orgId: runtimePolicyScope.orgId } : {}),
          userId: msg.payload.userId,
          challengeId: readString(msg.payload.challengeId, 'challengeId'),
          otpCode: readString(msg.payload.otpCode, 'otpCode'),
          shamirPrimeB64u: readString(msg.payload.shamirPrimeB64u, 'shamirPrimeB64u'),
          routePlan,
        });
        try {
          const walletId = readString(msg.payload.walletId, 'walletId');
          const artifact = await runThresholdEcdsaRoleLocalExportFromClientRootShare({
            relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
            userId: walletId,
            subjectId: toWalletSubjectId(msg.payload.subjectId),
            rpId: readString(msg.payload.rpId, 'rpId'),
            clientRootShare32: recovered.clientRootShare32,
            keyHandle: readString(msg.payload.keyHandle, 'keyHandle'),
            relayerKeyId: readString(msg.payload.relayerKeyId, 'relayerKeyId'),
            ecdsaThresholdKeyId: readString(
              msg.payload.ecdsaThresholdKeyId,
              'ecdsaThresholdKeyId',
            ),
            signingRootId: readString(msg.payload.signingRootId, 'signingRootId'),
            signingRootVersion: msg.payload.signingRootVersion,
            roleLocalState: msg.payload.roleLocalState,
            thresholdSessionId: readString(msg.payload.thresholdSessionId, 'thresholdSessionId'),
            walletSigningSessionId: readString(
              msg.payload.walletSigningSessionId,
              'walletSigningSessionId',
            ),
            thresholdExpiresAtMs: Number(msg.payload.thresholdExpiresAtMs),
            participantIds: msg.payload.participantIds,
            thresholdSessionAuthToken:
              msg.payload.thresholdSessionAuthToken ||
              (routeAuth?.kind === 'threshold_session' ? routeAuth.jwt : undefined),
            sessionKind: msg.payload.sessionKind,
          });
          postToMainThread({
            id: msg.id,
            ok: true,
            result: artifact,
          });
        } finally {
          zeroizeBytes(recovered.clientRootShare32);
        }
        return;
      }
      default:
        throw new Error('Unsupported emailOtp worker operation type');
    }
  } catch (error) {
    const err = asWorkerErrorPayload(error);
    postToMainThread({
      id: msg.id,
      ok: false,
      error: err.message,
      ...(err.code ? { code: err.code } : {}),
      ...(err.coreCode ? { coreCode: err.coreCode } : {}),
    });
  }
});
