import { toAccountId } from '@/core/types/accountIds';
import {
  emailOtpAuthContextProviderUserId,
  type ThresholdEcdsaEmailOtpAuthContext,
} from '@/core/signingEngine/session/identity/laneIdentity';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import {
  buildEd25519SessionPolicy,
  normalizeThresholdRuntimePolicyScope,
} from '@/core/signingEngine/threshold/sessionPolicy';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { runThresholdEd25519HssCeremonyWithMaterialHandle } from '@/core/signingEngine/threshold/ed25519/hssLifecycle';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import type { RouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import { ROUTER_AB_ED25519_WALLET_SESSION_PATH } from '@shared/utils/signingSessionSeal';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { ThresholdEd25519WorkerMaterialBindingInputWithoutVerifier } from '@/core/types/signer-worker';
import type {
  BuildCurrentSealedSessionRecordInput,
  SigningSessionRestoreLeaseHandle,
  SigningSessionSealedRecordFilter,
  SigningSessionSealedStoreRecord,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type {
  ThresholdEcdsaSessionRecord,
  OperationUsableThresholdEd25519SessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import {
  buildOperationUsableThresholdEd25519SessionRecord,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
} from '@/core/signingEngine/session/persistence/records';
import type { NearEd25519SignerBinding } from '@shared/utils/walletCapabilityBindings';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { PersistWarmSessionEd25519CapabilityArgs } from '../warmCapabilities/persistence';
import { markRouterAbEd25519WorkerMaterialRuntimeValidated } from '../routerAbSigningWalletSession';
import {
  attachEd25519SessionToEmailOtpSigningSessionSeal,
  type EmailOtpCompanionSessionAttachResult,
} from './companionSessions';
import {
  deriveThresholdEd25519HssClientInputsFromEmailOtpRecoveryCode,
  prepareRecoveryCodeSealAuthorizationForEmailOtp,
  recoveryCodeBindingDigestForEmailOtpMaterial,
} from './clientSecretSource';
import type {
  EmailOtpEd25519RecoveryCodeSigningSessionHydration,
} from './recoveryCodeWarmSessionHydration';
import {
  parseEd25519ClientVerifyingShareB64u,
  parseEd25519SealedWorkerMaterialRef,
  parseEd25519WorkerMaterialBindingDigest,
  parseEd25519WorkerMaterialHandle,
  parseEd25519WorkerMaterialKeyId,
} from '../keyMaterialBrands';
import {
  parseSdkEcdsaHssSigningRootId,
  parseSdkEcdsaHssSigningRootVersion,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';

export const EMAIL_OTP_THRESHOLD_ED25519_HSS_KEY_VERSION = 'threshold-ed25519-hss-v1' as const;

export type EmailOtpThresholdEd25519ProvisioningResult = {
  publicKey?: string;
  relayerKeyId: string;
  keyVersion: string;
  sessionId: string;
  record: OperationUsableThresholdEd25519SessionRecord;
  expiresAtMs: number;
  remainingUses: number;
  participantIds: number[];
  jwt: string;
  clientVerifyingShareB64u?: string;
  reconstructionTimings: EmailOtpThresholdEd25519ProvisioningTimings;
};

export type EmailOtpThresholdEd25519ProvisioningTimingBucket = 'warmCapabilityPersistenceMs';

export type EmailOtpThresholdEd25519ProvisioningTimings = Record<
  EmailOtpThresholdEd25519ProvisioningTimingBucket,
  number
>;

export type EmailOtpEd25519SessionReconstructionKey = {
  signer: NearEd25519SignerBinding;
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

function nowMs(): number {
  return typeof performance !== 'undefined' && typeof performance.now === 'function'
    ? performance.now()
    : Date.now();
}

function createEmailOtpThresholdEd25519ProvisioningTimings():
  EmailOtpThresholdEd25519ProvisioningTimings {
  return {
    warmCapabilityPersistenceMs: 0,
  };
}

function addEmailOtpThresholdEd25519ProvisioningTiming(
  timings: EmailOtpThresholdEd25519ProvisioningTimings,
  bucket: EmailOtpThresholdEd25519ProvisioningTimingBucket,
  startedAtMs: number,
): void {
  timings[bucket] += Math.max(0, Math.round(nowMs() - startedAtMs));
}

function assertNeverEmailOtpCompanionSessionAttachResult(
  result: never,
): never {
  throw new Error(
    `Unsupported Email OTP companion attachment result: ${String(
      (result as { kind?: unknown })?.kind || '',
    )}`,
  );
}

function observeOptionalEmailOtpCompanionAttachmentResult(
  result: EmailOtpCompanionSessionAttachResult,
): void {
  switch (result.kind) {
    case 'attached':
    case 'already_attached':
    case 'not_required':
      return;
    case 'missing_required_material':
      console.warn('[EmailOtpSession] optional companion attachment skipped', {
        reason: result.reason,
      });
      return;
    case 'failed':
      console.warn('[EmailOtpSession] optional companion attachment failed', {
        message: result.message,
      });
      return;
    default:
      return assertNeverEmailOtpCompanionSessionAttachResult(result);
  }
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
  const reconstructionTimings = createEmailOtpThresholdEd25519ProvisioningTimings();
  const signer = input.ed25519Key.signer;
  const walletId = toWalletId(signer.account.wallet.walletId);
  const nearAccountId = toAccountId(signer.account.nearAccountId);
  const nearEd25519SigningKeyId = signer.nearEd25519SigningKeyId;
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
  if (!nearEd25519SigningKeyId) {
    throw new Error(
      'Email OTP threshold-ed25519 session reconstruction requires NEAR Ed25519 signing key',
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
  const initialSigningRootScope = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope);
  const clientInputs = await deriveThresholdEd25519HssClientInputsFromEmailOtpRecoveryCode({
    sessionId: [
      'email-otp-ed25519-reconstruction',
      String(walletId),
      String(nearAccountId),
      nearEd25519SigningKeyId,
    ].join(':'),
    hssBindingFacts: {
      nearEd25519SigningKeyId,
      signingRootId: parseSdkEcdsaHssSigningRootId(initialSigningRootScope.signingRootId),
      signingRootVersion: parseSdkEcdsaHssSigningRootVersion(
        initialSigningRootScope.signingRootVersion,
      ),
    },
    participantIds,
    recoveryCodeSecret32B64u,
    workerCtx,
  });
  const { policy } = await buildEd25519SessionPolicy({
    nearAccountId,
    nearEd25519SigningKeyId,
    authority: { kind: 'wallet_auth_authority', authority: input.emailOtpAuthContext.authority },
    relayerKeyId,
    runtimePolicyScope,
    routerAbNormalSigning: input.routerAbNormalSigning,
    participantIds,
    signingGrantId,
    ttlMs: input.ttlMs,
    remainingUses: input.remainingUses,
  });
  const minted = await postJsonExpectOk({
    url: joinUrlPath(relayerUrl, ROUTER_AB_ED25519_WALLET_SESSION_PATH),
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
  const providerUserId = normalizeOptionalString(
    emailOtpAuthContextProviderUserId(input.emailOtpAuthContext),
  );
  if (!providerUserId) {
    throw new Error(
      'Email OTP threshold-ed25519 session reconstruction requires provider user id',
    );
  }
  const materialBinding = {
    thresholdSessionId: sessionId,
    signingGrantId,
    signingRootId: signingRootScope.signingRootId,
    signingRootVersion,
    expiresAtMs,
    nearAccountId: String(nearAccountId),
    signerSlot: signer.signerSlot,
    relayerKeyId,
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
    participantIds: materialBinding.participantIds,
    createdAtMs: materialBinding.createdAtMs,
  };
  const recoveryCodeBindingDigest = await recoveryCodeBindingDigestForEmailOtpMaterial({
    providerUserId,
    rpId,
    nearAccountId: String(nearAccountId),
  });
  const preparedSealAuthorization = await prepareRecoveryCodeSealAuthorizationForEmailOtp({
    bindingInput,
    providerUserId,
    recoveryCodeBindingDigest,
    recoveryCodeSecret32B64u,
    workerCtx,
  });
  const completed = await runThresholdEd25519HssCeremonyWithMaterialHandle({
    relayerUrl,
    walletSessionJwt: jwt,
    relayerKeyId,
    operation: 'warm_session_reconstruction',
    clientOutputMaskOperation: 'warm_session_reconstruction',
    context: {
      applicationBindingDigestB64u: clientInputs.applicationBindingDigestB64u,
      participantIds: clientInputs.participantIds,
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
  const clientVerifyingShareB64uRaw = String(
    signingMaterial.clientVerifyingShareB64u || '',
  ).trim();
  if (!clientVerifyingShareB64uRaw) {
    throw new Error('Email OTP threshold-ed25519 material handle is missing verifying share');
  }
  const clientVerifyingShareB64u =
    parseEd25519ClientVerifyingShareB64u(clientVerifyingShareB64uRaw);
  const warmCapabilityPersistenceStartedAtMs = nowMs();
  await args.persistWarmSessionEd25519Capability({
    kind: 'jwt_email_otp',
    walletId: String(walletId),
    nearAccountId,
    nearEd25519SigningKeyId,
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
    ed25519WorkerMaterialHandle: parseEd25519WorkerMaterialHandle(signingMaterial.materialHandle),
    ed25519WorkerMaterialBindingDigest: parseEd25519WorkerMaterialBindingDigest(
      signingMaterial.materialBindingDigest,
    ),
    sealedWorkerMaterialRef: parseEd25519SealedWorkerMaterialRef(
      signingMaterial.sealedWorkerMaterialRef,
    ),
    sealedWorkerMaterialB64u: signingMaterial.sealedWorkerMaterialB64u,
    materialFormatVersion: signingMaterial.materialFormatVersion,
    materialKeyId: parseEd25519WorkerMaterialKeyId(signingMaterial.materialKeyId),
    materialCreatedAtMs,
    signerSlot: signingMaterial.signerSlot,
    routerAbNormalSigning,
    emailOtpAuthContext: input.emailOtpAuthContext,
    source: 'email_otp',
  });
  addEmailOtpThresholdEd25519ProvisioningTiming(
    reconstructionTimings,
    'warmCapabilityPersistenceMs',
    warmCapabilityPersistenceStartedAtMs,
  );
  const storedCurrentRecord = getStoredThresholdEd25519SessionRecordByThresholdSessionId(sessionId);
  if (!storedCurrentRecord) {
    throw new Error(
      'Email OTP threshold-ed25519 session reconstruction did not store a current record',
    );
  }
  markRouterAbEd25519WorkerMaterialRuntimeValidated(storedCurrentRecord);
  const currentRecord = buildOperationUsableThresholdEd25519SessionRecord(storedCurrentRecord);
  if (!currentRecord) {
    throw new Error(
      'Email OTP threshold-ed25519 session reconstruction did not commit an operation-usable current record',
    );
  }
  await args.recoveryCodeSigningSessionHydration.hydrateRecoveryCodeSigningSession({
    sessionId,
    recoveryCodeSecret32B64u,
    expiresAtMs,
    remainingUses,
    transport: {
      curve: 'ed25519',
      authMethod: 'email_otp',
      walletId: String(walletId),
      relayerUrl,
      signingGrantId,
      walletSessionJwt: jwt,
    },
  });
  if (ecdsaThresholdSessionId) {
    const attachResult = await attachEd25519SessionToEmailOtpSigningSessionSeal({
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
    observeOptionalEmailOtpCompanionAttachmentResult(attachResult);
  }
  return {
    relayerKeyId,
    keyVersion,
    sessionId,
    record: currentRecord,
    expiresAtMs,
    remainingUses,
    participantIds,
    jwt,
    clientVerifyingShareB64u,
    reconstructionTimings,
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
