import {
  computeRegistrationNearEd25519SigningKeyId,
  nearEd25519SigningKeyIdFromString,
  registrationEd25519AuthorityScope,
  walletIdFromString,
  type NearEd25519SigningKeyId,
  type RegistrationEd25519AuthorityScope,
  type RegistrationIntentV1,
  type RegistrationNearAccountProvisioning,
  type RegistrationNearEd25519SignerPlan,
  type ThresholdEd25519RegistrationSpec,
  type WalletId,
} from '@shared/utils/registrationIntent';
import { deriveSigningRootId, normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  parseSdkEcdsaHssSigningRootId,
  parseSdkEcdsaHssSigningRootVersion,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { computeSdkEd25519HssApplicationBindingDigestB64u } from '@shared/threshold/ed25519HssBinding';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  type Ed25519SessionPolicy,
  type ThresholdEd25519AuthorityScope,
  type ThresholdEd25519BootstrapSession,
  type ThresholdEd25519RegistrationAccountScope,
  type ThresholdRuntimePolicyScope,
  type WalletRegistrationHssRespondRequest,
} from '../../core/types';
import type {
  ThresholdSigningService,
} from '../../core/ThresholdService/ThresholdSigningService';
import type { ThresholdEd25519RegistrationKeygenResult } from '../../core/ThresholdService';
import {
  parseThresholdEd25519AuthorityScope,
  thresholdEd25519AuthorityScopesMatch,
} from '../../core/ThresholdService/validation';
import { buildWalletEd25519SignerId } from '../../core/WalletStore';
import type { WalletSignerRecord } from '../../core/d1WalletStore';
import type {
  StoredEd25519RegistrationPrepared,
  StoredEd25519RegistrationPrepareScope,
  StoredWalletRegistrationCeremony,
} from '../../core/RegistrationCeremonyStore';

export function d1RegistrationIntentSigningRootId(input: {
  readonly signingRootId?: string;
  readonly intent: RegistrationIntentV1;
}): string {
  return (
    toOptionalTrimmedString(input.signingRootId) ||
    (input.intent.runtimePolicyScope ? deriveSigningRootId(input.intent.runtimePolicyScope) : '')
  );
}

export function d1RegistrationIntentSigningRootVersion(input: {
  readonly signingRootVersion?: string;
  readonly intent: RegistrationIntentV1;
}): string {
  return (
    toOptionalTrimmedString(input.signingRootVersion) ||
    toOptionalTrimmedString(input.intent.runtimePolicyScope?.signingRootVersion) ||
    'default'
  );
}

function d1RegistrationEd25519SpecFromPlanBranch(
  branch: RegistrationNearEd25519SignerPlan,
): ThresholdEd25519RegistrationSpec {
  return {
    accountProvisioning: branch.accountProvisioning,
    signerSlot: branch.signerSlot,
    participantIds: [...branch.participantIds],
    keyPurpose: branch.keyPurpose,
    keyVersion: branch.keyVersion,
    derivationVersion: branch.derivationVersion,
  };
}

export async function d1RegistrationIntentNearEd25519SigningKeyId(input: {
  readonly signingRootId?: string;
  readonly signingRootVersion?: string;
  readonly intent: RegistrationIntentV1;
  readonly nearEd25519: RegistrationNearEd25519SignerPlan;
}): Promise<NearEd25519SigningKeyId> {
  return await computeRegistrationNearEd25519SigningKeyId({
    walletId: input.intent.walletId,
    authorityScope: registrationEd25519AuthorityScope(input.intent.authMethod),
    signingRootId: d1RegistrationIntentSigningRootId({
      signingRootId: input.signingRootId,
      intent: input.intent,
    }),
    signingRootVersion: d1RegistrationIntentSigningRootVersion({
      signingRootVersion: input.signingRootVersion,
      intent: input.intent,
    }),
    ed25519: d1RegistrationEd25519SpecFromPlanBranch(input.nearEd25519),
  });
}

export function d1ThresholdEd25519AuthorityScopeFromRegistrationScope(
  authorityScope: RegistrationEd25519AuthorityScope,
): ThresholdEd25519AuthorityScope {
  switch (authorityScope.kind) {
    case 'passkey':
      return { kind: 'passkey_rp', rpId: authorityScope.rpId };
    case 'email_otp':
      switch (authorityScope.proofKind) {
        case 'otp_challenge':
          return {
            kind: 'email_otp',
            proofKind: 'otp_challenge',
            email: authorityScope.email,
            ...(authorityScope.challengeId ? { challengeId: authorityScope.challengeId } : {}),
          };
        case 'google_sso_registration':
          return {
            kind: 'email_otp',
            proofKind: 'google_sso_registration',
            email: authorityScope.email,
            googleEmailOtpRegistrationAttemptId:
              authorityScope.googleEmailOtpRegistrationAttemptId,
            googleEmailOtpRegistrationOfferId: authorityScope.googleEmailOtpRegistrationOfferId,
            googleEmailOtpRegistrationCandidateId:
              authorityScope.googleEmailOtpRegistrationCandidateId,
          };
      }
  }
}

export function d1RegistrationIntentThresholdEd25519AuthorityScope(
  intent: RegistrationIntentV1,
): ThresholdEd25519AuthorityScope {
  return d1ThresholdEd25519AuthorityScopeFromRegistrationScope(
    registrationEd25519AuthorityScope(intent.authMethod),
  );
}

export function d1ThresholdEd25519RegistrationAccountScope(input: {
  readonly walletId: WalletId;
  readonly intentDigestB64u: string;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  readonly signerSlot: number;
  readonly keyPurpose: string;
  readonly keyVersion: string;
  readonly derivationVersion: number;
  readonly participantIds: number[];
  readonly accountProvisioning: RegistrationNearAccountProvisioning;
}): ThresholdEd25519RegistrationAccountScope {
  const common = {
    walletId: String(input.walletId),
    intentDigestB64u: input.intentDigestB64u,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
    signerSlot: input.signerSlot,
    keyPurpose: input.keyPurpose,
    keyVersion: input.keyVersion,
    derivationVersion: input.derivationVersion,
    participantIds: [...input.participantIds],
  };
  switch (input.accountProvisioning.kind) {
    case 'implicit_account':
      return {
        kind: 'generated_implicit_registration_scope',
        ...common,
      };
    case 'sponsored_named_account':
      return {
        kind: 'sponsored_named_registration_scope',
        ...common,
        requestedAccountId: String(input.accountProvisioning.requestedAccountId),
      };
  }
}

async function d1ThresholdEd25519HssContextFromRegistrationAccountScope(
  scope: ThresholdEd25519RegistrationAccountScope,
) {
  return {
    applicationBindingDigestB64u: await computeSdkEd25519HssApplicationBindingDigestB64u({
      nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(scope.nearEd25519SigningKeyId),
      signingRootId: parseSdkEcdsaHssSigningRootId(scope.signingRootId),
      signingRootVersion: parseSdkEcdsaHssSigningRootVersion(scope.signingRootVersion),
    }),
    participantIds: [...scope.participantIds],
  };
}

export async function resolveD1NearEd25519RegistrationPrepareScope(input: {
  readonly intent: RegistrationIntentV1;
  readonly nearEd25519: RegistrationNearEd25519SignerPlan;
  readonly registrationIntentDigestB64u: string;
  readonly orgId: string;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly expectedOrigin: string;
}): Promise<StoredEd25519RegistrationPrepareScope> {
  const nearEd25519SigningKeyId = await d1RegistrationIntentNearEd25519SigningKeyId({
    intent: input.intent,
    nearEd25519: input.nearEd25519,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
  });
  return {
    walletId: input.intent.walletId,
    authorityScope: registrationEd25519AuthorityScope(input.intent.authMethod),
    registrationIntentDigestB64u: input.registrationIntentDigestB64u,
    expectedOrigin: input.expectedOrigin,
    orgId: input.orgId,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    nearEd25519SigningKeyId,
    signerSlot: input.nearEd25519.signerSlot,
    keyPurpose: input.nearEd25519.keyPurpose,
    keyVersion: input.nearEd25519.keyVersion,
    derivationVersion: input.nearEd25519.derivationVersion,
    participantIds: [...input.nearEd25519.participantIds],
  };
}

export async function prepareD1NearEd25519RegistrationHss(input: {
  readonly threshold: ThresholdSigningService | null;
  readonly scope: StoredEd25519RegistrationPrepareScope;
  readonly accountProvisioning: RegistrationNearAccountProvisioning;
}) {
  if (!input.threshold) {
    return {
      ok: false as const,
      code: 'not_configured',
      message: 'threshold signing is not configured on this server',
    };
  }
  const registrationAccountScope = d1ThresholdEd25519RegistrationAccountScope({
    walletId: walletIdFromString(input.scope.walletId),
    intentDigestB64u: input.scope.registrationIntentDigestB64u,
    signingRootId: input.scope.signingRootId,
    signingRootVersion: input.scope.signingRootVersion,
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
      input.scope.nearEd25519SigningKeyId,
    ),
    signerSlot: input.scope.signerSlot,
    keyPurpose: input.scope.keyPurpose,
    keyVersion: input.scope.keyVersion,
    derivationVersion: input.scope.derivationVersion,
    participantIds: input.scope.participantIds,
    accountProvisioning: input.accountProvisioning,
  });
  return await input.threshold.ed25519Hss.prepareForRegistration({
    orgId: input.scope.orgId,
    signingRootId: input.scope.signingRootId,
    signingRootVersion: input.scope.signingRootVersion,
    request: {
      registrationAccountScope,
      wallet_key_id: registrationAccountScope.nearEd25519SigningKeyId,
      context: await d1ThresholdEd25519HssContextFromRegistrationAccountScope(
        registrationAccountScope,
      ),
    },
  });
}

export async function respondD1NearEd25519RegistrationHss(input: {
  readonly threshold: ThresholdSigningService | null;
  readonly ceremony: StoredWalletRegistrationCeremony;
  readonly nearEd25519: RegistrationNearEd25519SignerPlan;
  readonly preparedEd25519: StoredEd25519RegistrationPrepared;
  readonly requestEd25519: NonNullable<WalletRegistrationHssRespondRequest['ed25519']>;
}): Promise<
  | {
      ok: true;
      responded: {
        readonly contextBindingB64u: string;
        readonly serverInputDeliveryB64u: string;
      };
    }
  | { ok: false; code: string; message: string }
> {
  if (!input.threshold) {
    return {
      ok: false,
      code: 'not_configured',
      message: 'threshold signing is not configured on this server',
    };
  }
  const nearEd25519SigningKeyId = await d1RegistrationIntentNearEd25519SigningKeyId({
    intent: input.ceremony.intent,
    nearEd25519: input.nearEd25519,
    signingRootId: input.ceremony.signingRootId,
    signingRootVersion: input.ceremony.signingRootVersion,
  });
  const responded = await input.threshold.ed25519Hss.respondForRegistration({
    orgId: input.ceremony.orgId,
    request: {
      registrationAccountScope: d1ThresholdEd25519RegistrationAccountScope({
        walletId: input.ceremony.intent.walletId,
        intentDigestB64u: input.ceremony.digestB64u,
        signingRootId: d1RegistrationIntentSigningRootId({
          signingRootId: input.ceremony.signingRootId,
          intent: input.ceremony.intent,
        }),
        signingRootVersion: d1RegistrationIntentSigningRootVersion({
          signingRootVersion: input.ceremony.signingRootVersion,
          intent: input.ceremony.intent,
        }),
        nearEd25519SigningKeyId,
        signerSlot: input.nearEd25519.signerSlot,
        keyPurpose: input.nearEd25519.keyPurpose,
        keyVersion: input.nearEd25519.keyVersion,
        derivationVersion: input.nearEd25519.derivationVersion,
        participantIds: [...input.nearEd25519.participantIds],
        accountProvisioning: input.nearEd25519.accountProvisioning,
      }),
      wallet_key_id: nearEd25519SigningKeyId,
      ceremonyHandle: input.preparedEd25519.ceremonyHandle,
      preparedSession: input.preparedEd25519.preparedSession,
      serverState: input.preparedEd25519.serverState,
      clientRequest: input.requestEd25519.clientRequest,
    },
  });
  if (!responded.ok) {
    return {
      ok: false,
      code: responded.code || 'hss_respond_failed',
      message: responded.message || 'Ed25519 HSS respond failed',
    };
  }
  return {
    ok: true,
    responded: {
      contextBindingB64u: responded.contextBindingB64u,
      serverInputDeliveryB64u: responded.serverInputDeliveryB64u,
    },
  };
}

export function buildD1WalletEd25519SignerRecord(input: {
  readonly walletId: WalletId;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  readonly signerSlot: number;
  readonly keygen: Extract<ThresholdEd25519RegistrationKeygenResult, { ok: true }>;
  readonly now: number;
}): WalletSignerRecord {
  return {
    version: 'wallet_signer_ed25519_v1',
    walletId: input.walletId,
    signerId: buildWalletEd25519SignerId({
      nearAccountId: input.nearAccountId,
      signerSlot: input.signerSlot,
    }),
    nearAccountId: input.nearAccountId,
    nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
    signerSlot: input.signerSlot,
    publicKey: input.keygen.publicKey,
    relayerKeyId: input.keygen.relayerKeyId,
    keyVersion: input.keygen.keyVersion,
    recoveryExportCapable: input.keygen.recoveryExportCapable,
    clientParticipantId: input.keygen.clientParticipantId,
    relayerParticipantId: input.keygen.relayerParticipantId,
    participantIds: input.keygen.participantIds,
    createdAtMs: input.now,
    updatedAtMs: input.now,
  };
}

type D1InvalidBodyResult = { ok: false; code: 'invalid_body'; message: string };

type D1Ed25519SessionPolicyBuildResult =
  | { ok: true; value: Ed25519SessionPolicy }
  | D1InvalidBodyResult;

function parseD1ThresholdEd25519SessionPolicyRouterAbNormalSigning(
  requestedSessionPolicy: Record<string, unknown>,
): { ok: true; value: Ed25519SessionPolicy['routerAbNormalSigning'] } | D1InvalidBodyResult {
  if (!Object.prototype.hasOwnProperty.call(requestedSessionPolicy, 'routerAbNormalSigning')) {
    return { ok: true, value: undefined };
  }
  try {
    const parsed = parseRouterAbEd25519NormalSigningState(
      requestedSessionPolicy.routerAbNormalSigning,
    );
    if (parsed) return { ok: true, value: parsed };
    return {
      ok: false,
      code: 'invalid_body',
      message:
        'threshold_ed25519.session_policy.routerAbNormalSigning must be a Router A/B normal-signing state',
    };
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

function parseD1ThresholdEd25519SessionPolicyParticipantIds(
  requestedSessionPolicy: Record<string, unknown>,
): { ok: true; value: number[] | undefined } | D1InvalidBodyResult {
  if (!Object.prototype.hasOwnProperty.call(requestedSessionPolicy, 'participantIds')) {
    return { ok: true, value: undefined };
  }
  const participantIds = normalizeThresholdEd25519ParticipantIds(
    requestedSessionPolicy.participantIds,
  );
  if (participantIds) return { ok: true, value: participantIds };
  return {
    ok: false,
    code: 'invalid_body',
    message: 'threshold_ed25519.session_policy.participantIds must contain participant ids',
  };
}

function validateD1ThresholdEd25519SessionPolicyBindings(input: {
  readonly requestedSessionPolicy: Record<string, unknown>;
  readonly expectedWalletId: string;
  readonly expectedRelayerKeyId: string;
  readonly expectedNearAccountId: string;
  readonly expectedNearEd25519SigningKeyId: string;
  readonly expectedAuthorityScope: ThresholdEd25519AuthorityScope;
}): string | null {
  const walletId = toOptionalTrimmedString(input.requestedSessionPolicy.walletId);
  if (walletId && walletId !== input.expectedWalletId) {
    return 'threshold_ed25519.session_policy.walletId mismatch';
  }
  const relayerKeyId = toOptionalTrimmedString(input.requestedSessionPolicy.relayerKeyId);
  if (relayerKeyId && relayerKeyId !== input.expectedRelayerKeyId) {
    return 'threshold_ed25519.session_policy.relayerKeyId mismatch';
  }
  const nearAccountId = toOptionalTrimmedString(input.requestedSessionPolicy.nearAccountId);
  if (nearAccountId && nearAccountId !== input.expectedNearAccountId) {
    return 'threshold_ed25519.session_policy.nearAccountId mismatch';
  }
  const nearEd25519SigningKeyId = toOptionalTrimmedString(
    input.requestedSessionPolicy.nearEd25519SigningKeyId,
  );
  if (
    nearEd25519SigningKeyId &&
    nearEd25519SigningKeyId !== input.expectedNearEd25519SigningKeyId
  ) {
    return 'threshold_ed25519.session_policy.nearEd25519SigningKeyId mismatch';
  }
  const rootRpId = toOptionalTrimmedString(input.requestedSessionPolicy.rpId);
  if (rootRpId) {
    return 'threshold_ed25519.session_policy.rpId belongs in authorityScope';
  }
  const authorityScope = parseThresholdEd25519AuthorityScope(
    input.requestedSessionPolicy.authorityScope,
  );
  if (!authorityScope) {
    return 'threshold_ed25519.session_policy.authorityScope is required';
  }
  if (!thresholdEd25519AuthorityScopesMatch(authorityScope, input.expectedAuthorityScope)) {
    return 'threshold_ed25519.session_policy.authorityScope mismatch';
  }
  return null;
}

export function buildD1ThresholdEd25519RegistrationSessionPolicy(input: {
  readonly requestedSessionPolicy: Record<string, unknown>;
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly relayerKeyId: string;
  readonly expectedAuthorityScope: ThresholdEd25519AuthorityScope;
  readonly runtimePolicyScope?: ThresholdRuntimePolicyScope;
}): D1Ed25519SessionPolicyBuildResult {
  const requestedSessionPolicy = input.requestedSessionPolicy;
  const bindingError = validateD1ThresholdEd25519SessionPolicyBindings({
    requestedSessionPolicy,
    expectedWalletId: input.walletId,
    expectedRelayerKeyId: input.relayerKeyId,
    expectedNearAccountId: input.nearAccountId,
    expectedNearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
    expectedAuthorityScope: input.expectedAuthorityScope,
  });
  if (bindingError) return { ok: false, code: 'invalid_body', message: bindingError };

  const version = toOptionalTrimmedString(requestedSessionPolicy.version);
  if (version !== 'threshold_session_v1') {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'threshold_ed25519.session_policy.version must be threshold_session_v1',
    };
  }
  const authorityScope = parseThresholdEd25519AuthorityScope(
    requestedSessionPolicy.authorityScope,
  );
  if (!authorityScope) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'threshold_ed25519.session_policy.authorityScope is required',
    };
  }
  const thresholdSessionId = toOptionalTrimmedString(
    requestedSessionPolicy.thresholdSessionId,
  );
  if (!thresholdSessionId) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'threshold_ed25519.session_policy.thresholdSessionId is required',
    };
  }
  const ttlMs = Number(requestedSessionPolicy.ttlMs);
  const remainingUses = Number(requestedSessionPolicy.remainingUses);
  if (
    !Number.isFinite(ttlMs) ||
    ttlMs <= 0 ||
    !Number.isFinite(remainingUses) ||
    remainingUses <= 0
  ) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'threshold_ed25519.session_policy ttlMs/remainingUses must be positive',
    };
  }
  const routerAbNormalSigning =
    parseD1ThresholdEd25519SessionPolicyRouterAbNormalSigning(requestedSessionPolicy);
  if (!routerAbNormalSigning.ok) return routerAbNormalSigning;
  const participantIds =
    parseD1ThresholdEd25519SessionPolicyParticipantIds(requestedSessionPolicy);
  if (!participantIds.ok) return participantIds;

  const policy: Ed25519SessionPolicy = {
    version: 'threshold_session_v1',
    walletId: input.walletId,
    nearAccountId: input.nearAccountId,
    nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
    authorityScope,
    relayerKeyId: input.relayerKeyId,
    thresholdSessionId,
    ttlMs,
    remainingUses,
  };
  const signingGrantId = toOptionalTrimmedString(requestedSessionPolicy.signingGrantId);
  if (signingGrantId) policy.signingGrantId = signingGrantId;
  if (input.runtimePolicyScope) policy.runtimePolicyScope = input.runtimePolicyScope;
  if (routerAbNormalSigning.value) policy.routerAbNormalSigning = routerAbNormalSigning.value;
  if (participantIds.value) policy.participantIds = participantIds.value;
  return { ok: true, value: policy };
}

export function toD1ThresholdEd25519BootstrapSession(session: {
  readonly walletId?: unknown;
  readonly nearAccountId?: unknown;
  readonly nearEd25519SigningKeyId?: unknown;
  readonly thresholdSessionId?: unknown;
  readonly signingGrantId?: unknown;
  readonly expiresAtMs?: unknown;
  readonly expiresAt?: unknown;
  readonly participantIds?: unknown;
  readonly remainingUses?: unknown;
  readonly runtimePolicyScope?: unknown;
  readonly routerAbNormalSigning?: unknown;
  readonly jwt?: unknown;
}): ThresholdEd25519BootstrapSession | null {
  const walletId = toOptionalTrimmedString(session.walletId);
  const nearAccountId = toOptionalTrimmedString(session.nearAccountId);
  const nearEd25519SigningKeyId = toOptionalTrimmedString(session.nearEd25519SigningKeyId);
  const thresholdSessionId = toOptionalTrimmedString(session.thresholdSessionId);
  const signingGrantId = toOptionalTrimmedString(session.signingGrantId);
  const expiresAtMs = Number(session.expiresAtMs);
  let runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope> | undefined;
  try {
    runtimePolicyScope = normalizeRuntimePolicyScope(session.runtimePolicyScope);
  } catch {
    runtimePolicyScope = undefined;
  }
  if (
    !walletId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !thresholdSessionId ||
    !signingGrantId ||
    !Number.isFinite(expiresAtMs) ||
    expiresAtMs <= 0
  ) {
    return null;
  }
  return {
    sessionKind: 'jwt',
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    thresholdSessionId,
    signingGrantId,
    expiresAtMs,
    ...(typeof session.expiresAt === 'string' && session.expiresAt.trim()
      ? { expiresAt: session.expiresAt.trim() }
      : {}),
    ...(Array.isArray(session.participantIds) ? { participantIds: session.participantIds } : {}),
    ...(Number.isFinite(Number(session.remainingUses))
      ? { remainingUses: Number(session.remainingUses) }
      : {}),
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(session.routerAbNormalSigning
      ? { routerAbNormalSigning: session.routerAbNormalSigning as any }
      : {}),
    ...(typeof session.jwt === 'string' && session.jwt.trim() ? { jwt: session.jwt.trim() } : {}),
  };
}
