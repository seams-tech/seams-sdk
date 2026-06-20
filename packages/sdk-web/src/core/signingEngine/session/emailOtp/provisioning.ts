import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import {
  buildEd25519SessionPolicy,
  normalizeThresholdRuntimePolicyScope,
} from '@/core/signingEngine/threshold/sessionPolicy';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { runThresholdEd25519HssCeremonyWithMaterialHandle } from '@/core/signingEngine/threshold/ed25519/hssLifecycle';
import {
  THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
  THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
} from '@/core/signingEngine/threshold/ed25519/hssClientBase';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import type { RouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import { ROUTER_AB_ED25519_WALLET_SESSION_PATH_V2 } from '@shared/utils/signingSessionSeal';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { ThresholdEd25519WorkerMaterialBindingInputWithoutVerifier } from '@/core/types/signer-worker';
import type {
  BuildCurrentSealedSessionRecordInput,
  BuildCurrentSealedSessionRecordBaseInput,
  SigningSessionRestoreLeaseHandle,
  SigningSessionSealedRecordFilter,
  SigningSessionSealedStoreRecord,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import { getStoredThresholdEd25519SessionRecordByThresholdSessionId } from '@/core/signingEngine/session/persistence/records';
import type { PersistWarmSessionEd25519CapabilityArgs } from '../warmCapabilities/persistence';
import { markRouterAbEd25519WorkerMaterialRuntimeValidated } from '../routerAbSigningWalletSession';
import { attachEd25519SessionToEmailOtpSigningSessionSealBestEffort } from './companionSessions';
import {
  deriveThresholdEd25519HssClientInputsFromEmailOtpRecoveryCode,
  prepareRecoveryCodeSealAuthorizationForEmailOtp,
  recoveryCodeBindingDigestForEmailOtpMaterial,
} from './clientSecretSource';
import type {
  EmailOtpEd25519RecoveryCodeSigningSessionHydration,
} from './recoveryCodeWarmSessionHydration';

export const EMAIL_OTP_THRESHOLD_ED25519_HSS_KEY_VERSION = 'threshold-ed25519-hss-v1' as const;

export type EmailOtpThresholdEd25519ProvisioningResult = {
  publicKey?: string;
  relayerKeyId: string;
  keyVersion: string;
  sessionId: string;
  expiresAtMs: number;
  remainingUses: number;
  participantIds: number[];
  jwt: string;
  clientVerifyingShareB64u?: string;
};

export type EmailOtpEd25519SessionReconstructionKey = {
  relayerKeyId: string;
  keyVersion: string;
  participantIds: number[];
};

export type EmailOtpEd25519SessionReconstructionPlan =
  | {
      kind: 'reconstruct';
      ed25519Key: EmailOtpEd25519SessionReconstructionKey;
      runtimePolicyScope: ThresholdRuntimePolicyScope;
    }
  | {
      kind: 'defer';
      reason: 'missing_runtime_policy_scope';
      ed25519Key: EmailOtpEd25519SessionReconstructionKey;
      runtimePolicyScope?: never;
    }
  | {
      kind: 'defer';
      reason: 'missing_ed25519_key_identity' | 'not_needed_for_ecdsa';
      ed25519Key?: never;
      runtimePolicyScope?: never;
    };

type EmailOtpEd25519CommonArgs = {
  nearAccountId: AccountId | string;
  relayUrl: string;
  rpId: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  participantIds?: number[];
  ttlMs?: number;
  remainingUses?: number;
};

export type ReconstructEmailOtpEd25519SessionArgs = Omit<
  EmailOtpEd25519CommonArgs,
  'participantIds'
> & {
  kind: 'session_ed25519_reconstruction';
  recoveryCodeSecret32B64u: string;
  routeAuth: AppOrWalletSessionAuth;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  signingGrantId: string;
  ecdsaThresholdSessionId?: string;
  ed25519Key: EmailOtpEd25519SessionReconstructionKey;
  registrationAttemptId?: never;
  appSessionJwt?: never;
};

function normalizeOptionalString(value: unknown): string | undefined {
  const normalized = String(value ?? '').trim();
  return normalized || undefined;
}

export async function reconstructEmailOtpEd25519Session(args: {
  input: ReconstructEmailOtpEd25519SessionArgs;
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  persistWarmSessionEd25519Capability: (
    args: PersistWarmSessionEd25519CapabilityArgs,
  ) => unknown | Promise<unknown>;
  recoveryCodeSigningSessionHydration: EmailOtpEd25519RecoveryCodeSigningSessionHydration;
  sessionPersistenceMode?: string | null;
  readExactSealedSession: (
    thresholdSessionId: string,
    filter: SigningSessionSealedRecordFilter,
  ) => Promise<SigningSessionSealedStoreRecord | null>;
  getThresholdEcdsaSessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
  getThresholdEd25519SessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEd25519SessionRecord | null;
  registerSigningSession: (record: BuildCurrentSealedSessionRecordInput) => Promise<void>;
}): Promise<EmailOtpThresholdEd25519ProvisioningResult> {
  const input = args.input;
  const nearAccountId = toAccountId(input.nearAccountId);
  const relayerUrl = String(input.relayUrl || '').trim();
  const rpId = String(input.rpId || '').trim();
  const recoveryCodeSecret32B64u = String(input.recoveryCodeSecret32B64u || '').trim();
  const routeAuthJwt = String(input.routeAuth.jwt || '').trim();
  const signingGrantId = normalizeOptionalString(input.signingGrantId);
  const ecdsaThresholdSessionId = normalizeOptionalString(input.ecdsaThresholdSessionId);
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(input.runtimePolicyScope);
  const participantIds = normalizeThresholdEd25519ParticipantIds(input.ed25519Key.participantIds);
  const relayerKeyId = normalizeOptionalString(input.ed25519Key.relayerKeyId);
  const keyVersion = normalizeOptionalString(input.ed25519Key.keyVersion);
  if (!relayerUrl) {
    throw new Error('Email OTP threshold-ed25519 session reconstruction requires relayerUrl');
  }
  if (!rpId) throw new Error('Email OTP threshold-ed25519 session reconstruction requires rpId');
  if (!recoveryCodeSecret32B64u) {
    throw new Error(
      'Email OTP threshold-ed25519 session reconstruction requires recovery-code material',
    );
  }
  if (!routeAuthJwt) {
    throw new Error('Email OTP threshold-ed25519 session reconstruction requires route auth');
  }
  if (!runtimePolicyScope) {
    throw new Error(
      'Email OTP threshold-ed25519 session reconstruction requires canonical runtime scope',
    );
  }
  if (!signingGrantId) {
    throw new Error(
      'Email OTP threshold-ed25519 session reconstruction requires wallet session identity',
    );
  }
  if (!relayerKeyId || !keyVersion || !participantIds) {
    throw new Error(
      'Email OTP threshold-ed25519 session reconstruction requires concrete Ed25519 key identity',
    );
  }
  const workerCtx = args.getSignerWorkerContext();
  if (!workerCtx) {
    throw new Error(
      'Email OTP threshold-ed25519 session reconstruction requires the dedicated emailOtp worker',
    );
  }
  const context = {
    signingRootId: signingRootScopeFromRuntimePolicyScope(runtimePolicyScope).signingRootId,
    nearAccountId: String(nearAccountId),
    keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
    keyVersion,
    participantIds,
    derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
  };
  const clientInputs = await deriveThresholdEd25519HssClientInputsFromEmailOtpRecoveryCode({
    sessionId: `email-otp-ed25519-reconstruction:${String(nearAccountId)}`,
    ...context,
    recoveryCodeSecret32B64u,
    workerCtx,
  });
  const { policy } = await buildEd25519SessionPolicy({
    nearAccountId,
    rpId,
    relayerKeyId,
    runtimePolicyScope,
    routerAbNormalSigning: input.routerAbNormalSigning,
    participantIds,
    signingGrantId,
    ttlMs: input.ttlMs,
    remainingUses: input.remainingUses,
  });
  const minted = await postJsonExpectOk({
    url: joinUrlPath(relayerUrl, ROUTER_AB_ED25519_WALLET_SESSION_PATH_V2),
    headers: { Authorization: `Bearer ${routeAuthJwt}` },
    credentials: 'include',
    operation: 'Email OTP threshold-ed25519 session reconstruction mint',
    body: {
      sessionKind: 'jwt',
      relayerKeyId,
      sessionPolicy: policy,
    },
  });
  const sessionId = String(minted.sessionId || policy.thresholdSessionId || '').trim();
  const jwt = String(minted.jwt || '').trim();
  const expiresAtMs = Number.isFinite(Number(minted.expiresAtMs))
    ? Math.floor(Number(minted.expiresAtMs))
    : minted.expiresAt
      ? Date.parse(String(minted.expiresAt))
      : Date.now() + policy.ttlMs;
  const remainingUses = Number.isFinite(Number(minted.remainingUses))
    ? Math.floor(Number(minted.remainingUses))
    : policy.remainingUses;
  const sessionScope =
    normalizeThresholdRuntimePolicyScope(minted.runtimePolicyScope) || runtimePolicyScope;
  const signingRootScope = signingRootScopeFromRuntimePolicyScope(sessionScope);
  const signingRootVersion = String(signingRootScope.signingRootVersion || '').trim();
  if (!signingRootVersion) {
    throw new Error('Email OTP threshold-ed25519 session mint missing signing-root version');
  }
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(
    minted.routerAbNormalSigning,
  );
  if (!sessionId || !jwt || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    throw new Error(
      'Email OTP threshold-ed25519 session reconstruction mint returned incomplete data',
    );
  }
  if (!routerAbNormalSigning) {
    throw new Error('Email OTP threshold-ed25519 session mint missing Router A/B state');
  }
  const signingWorkerId = String(routerAbNormalSigning.signingWorkerId || '').trim();
  if (!signingWorkerId) {
    throw new Error('Email OTP threshold-ed25519 session mint missing SigningWorker id');
  }
  const materialCreatedAtMs = Date.now();
  const authSubjectId =
    normalizeOptionalString(input.emailOtpAuthContext.authSubjectId) || String(nearAccountId);
  const materialBinding = {
    thresholdSessionId: sessionId,
    signingGrantId,
    signingRootId: signingRootScope.signingRootId,
    signingRootVersion,
    expiresAtMs,
    nearAccountId: String(nearAccountId),
    signerSlot: 1,
    relayerKeyId,
    keyVersion,
    participantIds,
    createdAtMs: materialCreatedAtMs,
    signingWorkerId,
  };
  const bindingInput: ThresholdEd25519WorkerMaterialBindingInputWithoutVerifier = {
    nearAccountId: materialBinding.nearAccountId,
    signerSlot: materialBinding.signerSlot,
    signingRootId: materialBinding.signingRootId,
    signingRootVersion: materialBinding.signingRootVersion,
    relayerKeyId: materialBinding.relayerKeyId,
    keyVersion: materialBinding.keyVersion,
    participantIds: materialBinding.participantIds,
    createdAtMs: materialBinding.createdAtMs,
  };
  const recoveryCodeBindingDigest = await recoveryCodeBindingDigestForEmailOtpMaterial({
    authSubjectId,
    rpId,
    nearAccountId: String(nearAccountId),
  });
  const preparedSealAuthorization = await prepareRecoveryCodeSealAuthorizationForEmailOtp({
    bindingInput,
    authSubjectId,
    recoveryCodeBindingDigest,
    recoveryCodeSecret32B64u,
    expiresAtMs,
    workerCtx,
  });
  const completed = await runThresholdEd25519HssCeremonyWithMaterialHandle({
    relayerUrl,
    walletSessionJwt: jwt,
    relayerKeyId,
    operation: 'warm_session_reconstruction',
    context: {
      ...context,
      signingRootId: signingRootScopeFromRuntimePolicyScope(sessionScope).signingRootId,
    },
    clientInputs,
    outputProjection: {
      kind: 'client-masked-projection',
      clientRecoverableSecretB64u: recoveryCodeSecret32B64u,
    },
    materialBinding,
    preparedSealAuthorization,
    workerCtx,
  });
  if (!completed.ok) {
    throw new Error(
      completed.message || 'Email OTP threshold-ed25519 session reconstruction failed',
    );
  }
  const signingMaterial = completed.signingMaterial;
  const clientVerifyingShareB64u = String(signingMaterial.clientVerifyingShareB64u || '').trim();
  if (!clientVerifyingShareB64u) {
    throw new Error('Email OTP threshold-ed25519 material handle is missing verifying share');
  }
  await args.persistWarmSessionEd25519Capability({
    kind: 'jwt_email_otp',
    nearAccountId,
    rpId,
    relayerUrl,
    relayerKeyId,
    runtimePolicyScope: sessionScope,
    participantIds,
    sessionKind: 'jwt',
    sessionId,
    signingGrantId,
    expiresAtMs,
    remainingUses,
    jwt,
    clientVerifyingShareB64u,
    ed25519WorkerMaterialHandle: signingMaterial.materialHandle,
    ed25519WorkerMaterialBindingDigest: signingMaterial.materialBindingDigest,
    sealedWorkerMaterialRef: signingMaterial.sealedWorkerMaterialRef,
    sealedWorkerMaterialB64u: signingMaterial.sealedWorkerMaterialB64u,
    materialFormatVersion: signingMaterial.materialFormatVersion,
    materialKeyId: signingMaterial.materialKeyId,
    materialCreatedAtMs,
    signerSlot: signingMaterial.signerSlot,
    keyVersion: signingMaterial.keyVersion,
    routerAbNormalSigning,
    emailOtpAuthContext: input.emailOtpAuthContext,
    source: 'email_otp',
  });
  markRouterAbEd25519WorkerMaterialRuntimeValidated(
    getStoredThresholdEd25519SessionRecordByThresholdSessionId(sessionId),
  );
  await args.recoveryCodeSigningSessionHydration.hydrateRecoveryCodeSigningSession({
    sessionId,
    recoveryCodeSecret32B64u,
    expiresAtMs,
    remainingUses,
    transport: {
      curve: 'ed25519',
      authMethod: 'email_otp',
      walletId: String(nearAccountId),
      relayerUrl,
      signingGrantId,
      walletSessionJwt: jwt,
    },
  });
  if (ecdsaThresholdSessionId) {
    await attachEd25519SessionToEmailOtpSigningSessionSealBestEffort({
      sessionPersistenceMode: args.sessionPersistenceMode,
      ecdsaThresholdSessionId,
      ed25519ThresholdSessionId: sessionId,
      readExactSealedSession: args.readExactSealedSession,
      getThresholdEcdsaSessionRecordByThresholdSessionId:
        args.getThresholdEcdsaSessionRecordByThresholdSessionId,
      getThresholdEd25519SessionRecordByThresholdSessionId:
        args.getThresholdEd25519SessionRecordByThresholdSessionId,
      registerSigningSession: args.registerSigningSession,
    });
  }
  return {
    relayerKeyId,
    keyVersion,
    sessionId,
    expiresAtMs,
    remainingUses,
    participantIds,
    jwt,
    clientVerifyingShareB64u,
  };
}

function joinUrlPath(baseUrl: string, path: string): string {
  const base = String(baseUrl || '')
    .trim()
    .replace(/\/+$/, '');
  const suffix = String(path || '').trim();
  if (!base) return '';
  return `${base}${suffix.startsWith('/') ? suffix : `/${suffix}`}`;
}

function replaceUrlPathSuffix(url: string, fromPath: string, toPath: string): string {
  const raw = String(url || '').trim();
  if (!raw) return '';
  try {
    const parsed = new URL(raw);
    if (parsed.pathname === fromPath || parsed.pathname === `${fromPath}/`) {
      parsed.pathname = toPath;
      return parsed.toString();
    }
  } catch {}
  if (raw.endsWith(fromPath)) return `${raw.slice(0, raw.length - fromPath.length)}${toPath}`;
  if (raw.endsWith(`${fromPath}/`)) {
    return `${raw.slice(0, raw.length - fromPath.length - 1)}${toPath}`;
  }
  return '';
}

async function readJsonObjectResponse(response: Response): Promise<Record<string, unknown>> {
  const parsed = await response.json().catch(() => ({}));
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
    ? (parsed as Record<string, unknown>)
    : {};
}

async function postJsonExpectOk(args: {
  url: string;
  headers?: Record<string, string>;
  body: unknown;
  credentials?: RequestCredentials;
  operation: string;
}): Promise<Record<string, unknown>> {
  const response = await fetch(args.url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(args.headers || {}) },
    credentials: args.credentials || 'omit',
    body: JSON.stringify(args.body),
  });
  const data = await readJsonObjectResponse(response);
  if (!response.ok || data.ok === false) {
    throw new Error(
      String(data.message || data.code || `${args.operation} failed with HTTP ${response.status}`),
    );
  }
  return data;
}
