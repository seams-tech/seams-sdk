import type { NearEd25519YaoSigningCapability } from '@/core/signingEngine/interfaces/near';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  EmailOtpEd25519YaoActiveCapabilityDescriptorV1,
  EmailOtpEd25519YaoRecoveryBootstrapV1,
} from '@/core/signingEngine/workerManager/workerTypes';
import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import {
  ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1,
  ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1,
  parseRouterAbEd25519YaoWarmRecoveryBootstrapRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  buildEmailOtpWalletAuthAuthority,
  parseEmailOtpWalletAuthAuthority,
  walletAuthAuthoritiesMatch,
} from '@shared/utils/walletAuthAuthority';
import {
  normalizeRuntimePolicyScope,
  signingRootScopeFromRuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import { isPlainObject } from '@shared/utils/validation';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import type { NearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import { parseEd25519YaoRecoveryCapabilityV1 } from '../../flows/recovery/passkeyEd25519YaoRecovery';
import type { Ed25519YaoActiveClientIdentityV1 } from '../../threshold/ed25519/yaoActiveClientRegistry';
import {
  readExactSealedSession,
  type CurrentEd25519SealedSessionRecord,
} from '../persistence/sealedSessionStore';
import { parseSigningSessionSealKeyVersion } from '../keyMaterialBrands';
import {
  activateColdEmailOtpEd25519YaoUnlockedRecoveryV1,
  prepareColdEmailOtpEd25519YaoRecoveryV1,
  type EmailOtpEd25519YaoBudgetRecoveryResult,
} from './ed25519YaoBudgetRecovery';
import { requestRehydrateEmailOtpEd25519YaoFactor } from './workerRequests';
import type {
  SigningGrantId,
  ThresholdEd25519SessionId,
} from '../operationState/types';
import {
  resolveEmailOtpAuthLane,
  type EmailOtpSigningSessionAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';

export type EmailOtpEd25519YaoSilentRecoveryUnavailableReason =
  | 'sealed_session_missing'
  | 'sealed_session_expired'
  | 'sealed_session_exhausted'
  | 'wallet_session_expired';

export type EmailOtpEd25519YaoSilentRecoveryResultV1 =
  | {
      kind: 'recovered';
      recovery: EmailOtpEd25519YaoBudgetRecoveryResult;
    }
  | {
      kind: 'reauth_required';
      reason: EmailOtpEd25519YaoSilentRecoveryUnavailableReason;
    };

export type EmailOtpEd25519YaoSilentRecoverySubject = {
  walletId: WalletId;
  nearAccountId: AccountId;
  signerSlot: number;
  thresholdSessionId: string;
};

export type EmailOtpEd25519YaoExportSubjectV1 = {
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: number;
  thresholdSessionId: ThresholdEd25519SessionId;
  signingGrantId: SigningGrantId;
  providerSubjectId: string;
};

export type EmailOtpEd25519YaoExportContextV1 = {
  kind: 'email_otp_ed25519_yao_export_context_v1';
  authLane: Extract<EmailOtpSigningSessionAuthLane, { curve: 'ed25519' }>;
  walletSessionJwt: string;
  runtimePolicyScope: EmailOtpEd25519YaoRecoveryBootstrapV1['session']['runtimePolicyScope'];
  capability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1;
};

export type EmailOtpEd25519YaoExportContextPorts = {
  readExactSealedSession: typeof readExactSealedSession;
  fetch: typeof fetch;
};

export type EmailOtpEd25519YaoSilentRecoveryPorts = {
  readExactSealedSession: typeof readExactSealedSession;
  fetch: typeof fetch;
  workerContext: WorkerOperationContext;
  resolveActiveCapability: (
    identity: Ed25519YaoActiveClientIdentityV1,
  ) => NearEd25519YaoSigningCapability | null;
  activateCapability: (
    capability: NearEd25519YaoSigningCapability,
  ) => Promise<Ed25519YaoActiveClientIdentityV1>;
  nowMs: () => number;
};

type ReadySealedRecord = {
  kind: 'ready';
  record: CurrentEd25519SealedSessionRecord;
};

type UnavailableSealedRecord = {
  kind: 'reauth_required';
  reason: Exclude<EmailOtpEd25519YaoSilentRecoveryUnavailableReason, 'wallet_session_expired'>;
};

type SealedRecordResolution = ReadySealedRecord | UnavailableSealedRecord;

type WarmBootstrapFetchResult =
  | { kind: 'ready'; response: Record<string, unknown> }
  | { kind: 'reauth_required'; reason: 'wallet_session_expired' };

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  return value;
}

function requireString(value: unknown, label: string): string {
  const parsed = typeof value === 'string' ? value.trim() : '';
  if (!parsed) throw new Error(`${label} is required`);
  return parsed;
}

function requirePositiveInteger(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${label} must be a positive integer`);
  }
  return value;
}

function requireParticipantIds(value: unknown): readonly [number, number] {
  if (
    !Array.isArray(value) ||
    value.length !== 2 ||
    !Number.isSafeInteger(value[0]) ||
    !Number.isSafeInteger(value[1]) ||
    value[0] < 1 ||
    value[1] < 1 ||
    value[0] === value[1]
  ) {
    throw new Error('participantIds must contain two distinct positive integers');
  }
  return [Number(value[0]), Number(value[1])];
}

function exactBootstrapResponseKeys(record: Record<string, unknown>): void {
  const expected = [
    'authority',
    'authorityScope',
    'capability',
    'kind',
    'nearAccountId',
    'nearEd25519SigningKeyId',
    'participantIds',
    'routerAbNormalSigning',
    'runtimePolicyScope',
    'signerSlot',
    'signingGrantId',
    'signingWorkerId',
    'thresholdExpiresAtMs',
    'thresholdSessionId',
    'walletId',
  ].sort();
  const actual = Object.keys(record).sort();
  if (actual.length !== expected.length) {
    throw new Error('Email OTP Ed25519 warm recovery response fields are invalid');
  }
  for (let index = 0; index < expected.length; index += 1) {
    if (actual[index] !== expected[index]) {
      throw new Error('Email OTP Ed25519 warm recovery response fields are invalid');
    }
  }
}

function sameRuntimePolicyScope(
  left: ReturnType<typeof normalizeRuntimePolicyScope>,
  right: ReturnType<typeof normalizeRuntimePolicyScope>,
): boolean {
  return (
    left.orgId === right.orgId &&
    left.projectId === right.projectId &&
    left.envId === right.envId &&
    left.signingRootVersion === right.signingRootVersion
  );
}

function emailOtpRestoreMetadata(record: CurrentEd25519SealedSessionRecord): {
  provider: 'google' | 'email';
  providerSubjectId: string;
  emailHashHex: string;
  walletSessionJwt: string;
} {
  const restore = record.ed25519Restore;
  if (
    record.authMethod !== 'email_otp' ||
    !('provider' in restore) ||
    !restore.provider ||
    !restore.providerSubjectId ||
    !restore.emailHashHex ||
    restore.sessionKind !== 'jwt'
  ) {
    throw new Error('Email OTP Ed25519 sealed recovery requires exact Email OTP restore metadata');
  }
  return {
    provider: restore.provider,
    providerSubjectId: requireString(restore.providerSubjectId, 'providerSubjectId'),
    emailHashHex: requireString(restore.emailHashHex, 'emailHashHex'),
    walletSessionJwt: requireString(restore.walletSessionJwt, 'walletSessionJwt'),
  };
}

function sealedRecordMatchesSubject(
  record: CurrentEd25519SealedSessionRecord,
  subject: EmailOtpEd25519YaoSilentRecoverySubject,
): boolean {
  const restore = record.ed25519Restore;
  return (
    record.authMethod === 'email_otp' &&
    record.walletId === String(subject.walletId) &&
    restore.nearAccountId === String(subject.nearAccountId) &&
    restore.signerSlot === subject.signerSlot &&
    record.thresholdSessionIds.ed25519 === subject.thresholdSessionId
  );
}

function sealedRecordMatchesExportSubject(
  record: CurrentEd25519SealedSessionRecord,
  subject: EmailOtpEd25519YaoExportSubjectV1,
): boolean {
  const restore = record.ed25519Restore;
  return (
    sealedRecordMatchesSubject(record, {
      walletId: subject.walletId,
      nearAccountId: subject.nearAccountId,
      signerSlot: subject.signerSlot,
      thresholdSessionId: String(subject.thresholdSessionId),
    }) &&
    restore.nearEd25519SigningKeyId === String(subject.nearEd25519SigningKeyId) &&
    record.signingGrantId === String(subject.signingGrantId) &&
    'providerSubjectId' in restore &&
    restore.providerSubjectId === subject.providerSubjectId
  );
}

async function resolveSealedRecord(args: {
  subject: EmailOtpEd25519YaoSilentRecoverySubject;
  ports: EmailOtpEd25519YaoSilentRecoveryPorts;
}): Promise<SealedRecordResolution> {
  const record = await args.ports.readExactSealedSession(args.subject.thresholdSessionId, {
    authMethod: 'email_otp',
    curve: 'ed25519',
  });
  if (!record || record.curve !== 'ed25519' || !sealedRecordMatchesSubject(record, args.subject)) {
    return { kind: 'reauth_required', reason: 'sealed_session_missing' };
  }
  if (record.expiresAtMs <= args.ports.nowMs()) {
    return { kind: 'reauth_required', reason: 'sealed_session_expired' };
  }
  if (record.remainingUses < 1) {
    return { kind: 'reauth_required', reason: 'sealed_session_exhausted' };
  }
  return { kind: 'ready', record };
}

function warmBootstrapRequest(record: CurrentEd25519SealedSessionRecord) {
  const restore = record.ed25519Restore;
  const parsed = parseRouterAbEd25519YaoWarmRecoveryBootstrapRequestV1({
    kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_request_v1',
    walletId: record.walletId,
    nearAccountId: restore.nearAccountId,
    nearEd25519SigningKeyId: restore.nearEd25519SigningKeyId,
    signerSlot: restore.signerSlot,
    thresholdSessionId: record.thresholdSessionIds.ed25519,
    signingGrantId: record.signingGrantId,
    signingWorkerId: restore.routerAbNormalSigning.signingWorkerId,
    participantIds: restore.participantIds,
  });
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

async function parseJsonResponseOrNull(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

async function fetchWarmBootstrap(args: {
  record: CurrentEd25519SealedSessionRecord;
  relayerUrl: string;
  fetch: typeof fetch;
}): Promise<WarmBootstrapFetchResult> {
  const restore = emailOtpRestoreMetadata(args.record);
  const response = await args.fetch(
    `${new URL(args.relayerUrl).origin}${ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1}`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${restore.walletSessionJwt}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(warmBootstrapRequest(args.record)),
    },
  );
  const body = await parseJsonResponseOrNull(response);
  const parsedBody = isPlainObject(body) ? body : null;
  if (!response.ok) {
    const code = parsedBody ? String(parsedBody.code || '').trim() : '';
    if (response.status === 401 && code === 'wallet_session_expired') {
      return { kind: 'reauth_required', reason: 'wallet_session_expired' };
    }
    const message = parsedBody ? String(parsedBody.message || '').trim() : '';
    throw new Error(
      `[SigningEngine][near] Email OTP Ed25519 warm recovery bootstrap failed (HTTP ${response.status}${code ? `, ${code}` : ''}): ${message || 'invalid response'}`,
    );
  }
  if (!parsedBody) {
    throw new Error('Email OTP Ed25519 warm recovery bootstrap returned invalid JSON');
  }
  return { kind: 'ready', response: parsedBody };
}

function activeCapabilityDescriptor(raw: unknown): EmailOtpEd25519YaoActiveCapabilityDescriptorV1 {
  const parsed = parseEd25519YaoRecoveryCapabilityV1(raw);
  return {
    kind: 'router_ab_ed25519_yao_active_capability_v1',
    activeCapabilityBinding: parsed.activeCapabilityBinding,
    registeredPublicKey: parsed.registeredPublicKey,
    nearAccountId: String(parsed.nearAccountId),
    applicationBinding: parsed.applicationBinding,
    runtimePolicyScope: parsed.runtimePolicyScope,
    participantIds: parsed.participantIds,
    lifecycle: parsed.lifecycle,
    stateEpoch: parsed.stateEpoch,
  };
}

type VerifiedEmailOtpEd25519YaoWarmBootstrapV1 = {
  kind: 'verified_email_otp_ed25519_yao_warm_bootstrap_v1';
  session: Omit<EmailOtpEd25519YaoRecoveryBootstrapV1['session'], 'remainingUses'>;
  capability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1;
};

function parseWarmBootstrap(args: {
  record: CurrentEd25519SealedSessionRecord;
  response: Record<string, unknown>;
  expiresAtMs: number;
}): VerifiedEmailOtpEd25519YaoWarmBootstrapV1 {
  const record = args.record;
  const restore = record.ed25519Restore;
  const emailOtp = emailOtpRestoreMetadata(record);
  const response = args.response;
  exactBootstrapResponseKeys(response);
  if (response.kind !== 'router_ab_ed25519_yao_warm_recovery_bootstrap_v1') {
    throw new Error('Email OTP Ed25519 warm recovery bootstrap kind is invalid');
  }
  const walletId = requireString(response.walletId, 'response.walletId');
  const nearAccountId = requireString(response.nearAccountId, 'response.nearAccountId');
  const nearEd25519SigningKeyId = requireString(
    response.nearEd25519SigningKeyId,
    'response.nearEd25519SigningKeyId',
  );
  const signerSlot = requirePositiveInteger(response.signerSlot, 'response.signerSlot');
  const thresholdSessionId = requireString(
    response.thresholdSessionId,
    'response.thresholdSessionId',
  );
  const signingGrantId = requireString(response.signingGrantId, 'response.signingGrantId');
  const signingWorkerId = requireString(response.signingWorkerId, 'response.signingWorkerId');
  const thresholdExpiresAtMs = requirePositiveInteger(
    response.thresholdExpiresAtMs,
    'response.thresholdExpiresAtMs',
  );
  const participantIds = requireParticipantIds(response.participantIds);
  const authority = parseEmailOtpWalletAuthAuthority(response.authority);
  const expectedAuthority = buildEmailOtpWalletAuthAuthority({
    walletId: record.walletId,
    provider: emailOtp.provider,
    providerUserId: emailOtp.providerSubjectId,
    emailHashHex: emailOtp.emailHashHex,
  });
  const authorityScope = requireRecord(response.authorityScope, 'response.authorityScope');
  const provider = authorityScope.provider;
  if (provider !== 'google' && provider !== 'email') {
    throw new Error('Email OTP Ed25519 warm recovery provider is invalid');
  }
  const providerUserId = requireString(
    authorityScope.providerUserId,
    'response.authorityScope.providerUserId',
  );
  const runtimePolicyScope = normalizeRuntimePolicyScope(
    requireRecord(response.runtimePolicyScope, 'response.runtimePolicyScope'),
  );
  const sealedRuntimePolicyScope = normalizeRuntimePolicyScope(
    requireRecord(restore.runtimePolicyScope, 'ed25519Restore.runtimePolicyScope'),
  );
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(
    response.routerAbNormalSigning,
  );
  const signingRoot = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope);
  if (
    !authority ||
    !walletAuthAuthoritiesMatch(authority, expectedAuthority) ||
    authorityScope.kind !== 'email_otp' ||
    provider !== emailOtp.provider ||
    providerUserId !== emailOtp.providerSubjectId ||
    !routerAbNormalSigning ||
    !signingRoot ||
    walletId !== record.walletId ||
    nearAccountId !== restore.nearAccountId ||
    nearEd25519SigningKeyId !== restore.nearEd25519SigningKeyId ||
    signerSlot !== restore.signerSlot ||
    thresholdSessionId !== record.thresholdSessionIds.ed25519 ||
    signingGrantId !== record.signingGrantId ||
    signingWorkerId !== restore.relayerKeyId ||
    signingWorkerId !== restore.routerAbNormalSigning.signingWorkerId ||
    routerAbNormalSigning.signingWorkerId !== signingWorkerId ||
    thresholdExpiresAtMs !== record.expiresAtMs ||
    args.expiresAtMs !== record.expiresAtMs ||
    participantIds[0] !== restore.participantIds[0] ||
    participantIds[1] !== restore.participantIds[1] ||
    !sameRuntimePolicyScope(runtimePolicyScope, sealedRuntimePolicyScope)
  ) {
    throw new Error('Email OTP Ed25519 warm recovery changed the exact sealed lane');
  }
  return {
    kind: 'verified_email_otp_ed25519_yao_warm_bootstrap_v1',
    session: {
      sessionKind: 'jwt',
      walletSessionJwt: emailOtp.walletSessionJwt,
      walletId: walletIdFromString(walletId),
      nearAccountId,
      nearEd25519SigningKeyId,
      authorityScope: {
        kind: 'email_otp',
        provider,
        providerUserId,
      },
      thresholdSessionId,
      signingGrantId,
      expiresAtMs: thresholdExpiresAtMs,
      participantIds,
      signingRootId: signingRoot.signingRootId,
      signingRootVersion: requireString(
        signingRoot.signingRootVersion,
        'runtimePolicyScope.signingRootVersion',
      ),
      runtimePolicyScope,
      routerAbNormalSigning,
    },
    capability: activeCapabilityDescriptor(response.capability),
  };
}

function recoveryBootstrapFromVerifiedWarmBootstrap(args: {
  verified: VerifiedEmailOtpEd25519YaoWarmBootstrapV1;
  remainingUses: number;
}): EmailOtpEd25519YaoRecoveryBootstrapV1 {
  const session = args.verified.session;
  return {
    kind: ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1,
    session: {
      sessionKind: session.sessionKind,
      walletSessionJwt: session.walletSessionJwt,
      walletId: session.walletId,
      nearAccountId: session.nearAccountId,
      nearEd25519SigningKeyId: session.nearEd25519SigningKeyId,
      authorityScope: session.authorityScope,
      thresholdSessionId: session.thresholdSessionId,
      signingGrantId: session.signingGrantId,
      expiresAtMs: session.expiresAtMs,
      participantIds: session.participantIds,
      remainingUses: requirePositiveInteger(args.remainingUses, 'remainingUses'),
      signingRootId: session.signingRootId,
      signingRootVersion: session.signingRootVersion,
      runtimePolicyScope: session.runtimePolicyScope,
      routerAbNormalSigning: session.routerAbNormalSigning,
    },
    capability: args.verified.capability,
  };
}

function unavailableReasonForWorkerCode(
  code: string,
): EmailOtpEd25519YaoSilentRecoveryUnavailableReason | null {
  switch (code) {
    case 'not_found':
    case 'missing':
      return 'sealed_session_missing';
    case 'expired':
      return 'sealed_session_expired';
    case 'exhausted':
      return 'sealed_session_exhausted';
    case 'wallet_session_expired':
      return 'wallet_session_expired';
    default:
      return null;
  }
}

export async function recoverEmailOtpEd25519YaoFromSealedSessionV1(input: {
  subject: EmailOtpEd25519YaoSilentRecoverySubject;
  expectedOperationalPublicKey: string;
  rpId: string;
  relayerUrl: string;
  authPolicy: EmailOtpAuthPolicy;
  ports: EmailOtpEd25519YaoSilentRecoveryPorts;
}): Promise<EmailOtpEd25519YaoSilentRecoveryResultV1> {
  const sealedRecord = await resolveSealedRecord({ subject: input.subject, ports: input.ports });
  if (sealedRecord.kind === 'reauth_required') return sealedRecord;
  const record = sealedRecord.record;
  const emailOtp = emailOtpRestoreMetadata(record);
  const bootstrapResponse = await fetchWarmBootstrap({
    record,
    relayerUrl: input.relayerUrl,
    fetch: input.ports.fetch,
  });
  if (bootstrapResponse.kind === 'reauth_required') return bootstrapResponse;
  const prepared = prepareColdEmailOtpEd25519YaoRecoveryV1({
    identity: {
      walletId: input.subject.walletId,
      nearAccountId: input.subject.nearAccountId,
      thresholdSessionId: input.subject.thresholdSessionId,
    },
    signerSlot: input.subject.signerSlot,
    expectedOperationalPublicKey: input.expectedOperationalPublicKey,
    providerSubject: emailOtp.providerSubjectId,
    emailHashHex: emailOtp.emailHashHex,
    rpId: input.rpId,
    relayerUrl: input.relayerUrl,
    authPolicy: input.authPolicy,
    remainingUses: record.remainingUses,
    resolveActiveCapability: input.ports.resolveActiveCapability,
  });
  const rehydrated = await requestRehydrateEmailOtpEd25519YaoFactor({
    workerCtx: input.ports.workerContext,
    sealedSecretB64u: record.sealedSecretB64u,
    remainingUses: record.remainingUses,
    expiresAtMs: record.expiresAtMs,
    transport: {
      relayerUrl: record.relayerUrl,
      walletSessionJwt: emailOtp.walletSessionJwt,
      signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(record.keyVersion),
      shamirPrimeB64u: requireString(record.shamirPrimeB64u, 'shamirPrimeB64u'),
    },
    restore: {
      sessionId: record.thresholdSessionIds.ed25519,
      walletId: record.walletId,
      providerSubject: emailOtp.providerSubjectId,
    },
  });
  if (!rehydrated.ok) {
    const reason = unavailableReasonForWorkerCode(rehydrated.code);
    if (reason) return { kind: 'reauth_required', reason };
    throw new Error(
      `[SigningEngine][near] Email OTP Ed25519 sealed factor restore failed (${rehydrated.code}): ${rehydrated.message}`,
    );
  }
  const verifiedBootstrap = parseWarmBootstrap({
    record,
    response: bootstrapResponse.response,
    expiresAtMs: rehydrated.expiresAtMs,
  });
  const bootstrap = recoveryBootstrapFromVerifiedWarmBootstrap({
    verified: verifiedBootstrap,
    remainingUses: rehydrated.remainingUses,
  });
  const recovery = await activateColdEmailOtpEd25519YaoUnlockedRecoveryV1({
    prepared,
    bootstrap,
    pendingFactorHandle: rehydrated.pendingFactorHandle,
    workerContext: input.ports.workerContext,
    activateCapability: input.ports.activateCapability,
  });
  return { kind: 'recovered', recovery };
}

export async function resolveEmailOtpEd25519YaoExportContextV1(input: {
  subject: EmailOtpEd25519YaoExportSubjectV1;
  relayerUrl: string;
  ports: EmailOtpEd25519YaoExportContextPorts;
}): Promise<EmailOtpEd25519YaoExportContextV1> {
  const record = await input.ports.readExactSealedSession(
    String(input.subject.thresholdSessionId),
    {
      authMethod: 'email_otp',
      curve: 'ed25519',
    },
  );
  if (
    !record ||
    record.curve !== 'ed25519' ||
    !sealedRecordMatchesExportSubject(record, input.subject)
  ) {
    throw new Error(
      '[SigningEngine][ed25519-export] exact durable Email OTP Yao context is unavailable',
    );
  }
  const bootstrapResponse = await fetchWarmBootstrap({
    record,
    relayerUrl: input.relayerUrl,
    fetch: input.ports.fetch,
  });
  if (bootstrapResponse.kind === 'reauth_required') {
    throw new Error(
      '[SigningEngine][ed25519-export] Email OTP Yao Wallet Session expired before export',
    );
  }
  const bootstrap = parseWarmBootstrap({
    record,
    response: bootstrapResponse.response,
    expiresAtMs: record.expiresAtMs,
  });
  if (bootstrap.session.authorityScope.providerUserId !== input.subject.providerSubjectId) {
    throw new Error(
      '[SigningEngine][ed25519-export] durable Email OTP authority changed before export',
    );
  }
  const authLane = resolveEmailOtpAuthLane({
    routeAuth: {
      kind: 'wallet_session',
      jwt: bootstrap.session.walletSessionJwt,
    },
    thresholdSessionId: String(input.subject.thresholdSessionId),
    authorizingSigningGrantId: String(input.subject.signingGrantId),
    curve: 'ed25519',
  });
  if (authLane?.kind !== 'signing_session' || authLane.curve !== 'ed25519') {
    throw new Error(
      '[SigningEngine][ed25519-export] durable Email OTP signing-session authority is invalid',
    );
  }
  return {
    kind: 'email_otp_ed25519_yao_export_context_v1',
    authLane,
    walletSessionJwt: bootstrap.session.walletSessionJwt,
    runtimePolicyScope: bootstrap.session.runtimePolicyScope,
    capability: bootstrap.capability,
  };
}
