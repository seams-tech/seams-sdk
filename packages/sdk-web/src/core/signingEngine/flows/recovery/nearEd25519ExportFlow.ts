import { getNearThresholdKeyMaterial } from '@/core/accountData/near/keyMaterial';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { KeyExportEventPhase } from '@/core/types/sdkSentEvents';
import type { ThemeName } from '@/core/types/seams';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { buildPasskeyEd25519SessionPolicy, type ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { ThresholdEd25519SessionRecord } from '../../session/persistence/records';
import { getStoredThresholdEd25519SessionRecordForLane } from '../../session/persistence/records';
import type { RouterAbEd25519NormalSigningState } from '../../threshold/ed25519/routerAbNormalSigningState';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import { toAuthorizingSigningGrantId } from '../../stepUpConfirmation/otpPrompt/authLane';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import { buildThresholdEd25519WebAuthnPrfSecretSource } from '../../threshold/ed25519/walletSession';
import type {
  ProvisionWarmEd25519CapabilityArgs,
  ProvisionWarmEd25519CapabilityResult,
} from '../../session/warmCapabilities/types';
import {
  parseRouterAbEd25519WalletSessionAuthorityFromRecord,
  type RouterAbEd25519WalletSessionAuthorityFailureReason,
} from '../../session/routerAbSigningWalletSession';
import type {
  Ed25519ExportLane,
  ExportEd25519SeedWithAuthorizationArgs,
  EmailOtpEd25519ExportSessionRecord,
  RequestEmailOtpChallengeArgs,
} from '../../session/emailOtp/exportRecoveryRuntime';
import { walletSessionRefFromSession } from '../../interfaces/ecdsaChainTarget';
import type { ExactNearEd25519ExportLane } from './exportLaneSelection';
import {
  type EmailOtpNearAccountExportAuthorizationDeps,
  isExportViewerSessionOpen,
  removeExportViewerHostIfPresent,
  requestEmailOtpKeyExportAuthorization,
  requestNearEd25519ExportAuthorization,
  showNearEd25519ExportViewer,
} from './keyExportConfirmation';
import {
  createExportUiRequestId,
  emitKeyExportEvent,
  requirePrfFirstForPrivateKeyExport,
  type KeyExportEventCallback,
} from './keyExportFlow';
import { runNearEd25519SingleKeyHssExport } from './nearEd25519HssExport';
import { buildThresholdEd25519SeedExportArtifactFromHssReport } from '../../threshold/ed25519/hssLifecycle';
import type { RecoveryNearKeyMaterialStorePort } from './recoveryStorePorts';

export type NearEd25519SingleKeyExportDeps = {
  keyMaterialStore: RecoveryNearKeyMaterialStorePort;
  touchConfirm: Parameters<typeof showNearEd25519ExportViewer>[0]['touchConfirm'];
  theme?: ThemeName;
  emailOtpSessions: {
    requestExportChallenge: EmailOtpNearAccountExportAuthorizationDeps['requestExportChallenge'];
    exportEd25519SeedWithAuthorization: (
      args: ExportEd25519SeedWithAuthorizationArgs,
    ) => Promise<{ publicKey: string; privateKey: string }>;
  };
  getSignerWorkerContext: () => WorkerOperationContext;
  provisionThresholdEd25519Session: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
};

type NearEd25519SingleKeyExportArgs = {
  nearAccountId: AccountId;
  exportLane: ExactNearEd25519ExportLane;
  options: {
    variant?: 'drawer' | 'modal';
    theme?: 'dark' | 'light';
  };
  flowId: string;
  onEvent?: KeyExportEventCallback;
};

type ExportedKeySchemes = Array<'ed25519' | 'secp256k1'>;

export type RouterAbEd25519ExportWalletSessionAuth = {
  kind: 'router_ab_ed25519_export_wallet_session_auth_v1';
  walletSessionJwt: string;
  thresholdSessionId: string;
  signingGrantId: string;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds: number[];
  expiresAtMs: number;
  remainingUses: number;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  signingWorkerId: string;
};

export type RouterAbEd25519ExportWalletSessionAuthFailureReason =
  | RouterAbEd25519WalletSessionAuthorityFailureReason
  | 'missing_relayer_url'
  | 'missing_relayer_key_id'
  | 'missing_participant_ids'
  | 'missing_runtime_policy_scope'
  | 'missing_router_ab_state'
  | 'invalid_budget';

export type RouterAbEd25519ExportWalletSessionAuthResult =
  | { ok: true; value: RouterAbEd25519ExportWalletSessionAuth }
  | { ok: false; reason: RouterAbEd25519ExportWalletSessionAuthFailureReason };

function nonEmptyString(value: unknown): string {
  return String(value || '').trim();
}

function positiveInteger(value: unknown): number {
  const parsed = Math.floor(Number(value));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

function requireEmailOtpEd25519ExportRecord(
  record: ThresholdEd25519SessionRecord,
): EmailOtpEd25519ExportSessionRecord {
  if (record.source !== SIGNER_AUTH_METHODS.emailOtp) {
    throw new Error('[SigningEngine][ed25519-export] Email OTP export requires Email OTP record');
  }
  const signingGrantId = nonEmptyString(record.signingGrantId);
  if (!signingGrantId) {
    throw new Error('[SigningEngine][ed25519-export] Email OTP export requires signing grant identity');
  }
  if (!record.runtimePolicyScope) {
    throw new Error('[SigningEngine][ed25519-export] Email OTP export requires runtime policy scope');
  }
  if (!record.emailOtpAuthContext) {
    throw new Error('[SigningEngine][ed25519-export] Email OTP export requires auth context');
  }
  return {
    ...record,
    source: 'email_otp',
    signingGrantId,
    runtimePolicyScope: record.runtimePolicyScope,
    emailOtpAuthContext: record.emailOtpAuthContext,
  };
}

function buildEd25519ExportLane(args: {
  record: ThresholdEd25519SessionRecord;
  walletSessionAuth: RouterAbEd25519ExportWalletSessionAuth;
  expectedPublicKey: string;
}): Ed25519ExportLane {
  const record = requireEmailOtpEd25519ExportRecord(args.record);
  const thresholdSessionId = nonEmptyString(record.thresholdSessionId);
  const expectedPublicKey = nonEmptyString(args.expectedPublicKey);
  const relayerKeyId = nonEmptyString(record.relayerKeyId);
  if (!thresholdSessionId) {
    throw new Error('[SigningEngine][ed25519-export] Email OTP export requires threshold session identity');
  }
  if (!expectedPublicKey) {
    throw new Error('[SigningEngine][ed25519-export] Email OTP export requires expected public key');
  }
  if (!relayerKeyId) {
    throw new Error('[SigningEngine][ed25519-export] Email OTP export requires relayer key identity');
  }
  if (
    args.walletSessionAuth.thresholdSessionId !== thresholdSessionId ||
    args.walletSessionAuth.signingGrantId !== record.signingGrantId
  ) {
    throw new Error('[SigningEngine][ed25519-export] Email OTP committed lane authority drifted');
  }
  if (args.walletSessionAuth.participantIds.length === 0) {
    throw new Error('[SigningEngine][ed25519-export] Email OTP export requires participant identity');
  }
  const authLane = {
    kind: 'signing_session' as const,
    jwt: args.walletSessionAuth.walletSessionJwt,
    thresholdSessionId,
    authorizingSigningGrantId: toAuthorizingSigningGrantId(record.signingGrantId),
    curve: 'ed25519' as const,
  };
  return {
    source: 'record_backed',
    record,
    authority: record.emailOtpAuthContext.authority,
    authLane,
    walletSessionAuthority: {
      kind: 'wallet_session_authority',
      walletSessionJwt: args.walletSessionAuth.walletSessionJwt,
      thresholdSessionId,
      signingGrantId: record.signingGrantId,
    },
    participantIds: [...args.walletSessionAuth.participantIds],
    relayerKeyId,
    expectedPublicKey,
  };
}

export function resolveRouterAbEd25519ExportWalletSessionAuthFromRecord(
  record: ThresholdEd25519SessionRecord | null | undefined,
): RouterAbEd25519ExportWalletSessionAuthResult {
  if (!record) return { ok: false, reason: 'missing_record' };
  const walletSessionAuthority = parseRouterAbEd25519WalletSessionAuthorityFromRecord(record);
  if (!walletSessionAuthority.ok) return walletSessionAuthority;
  const walletSessionJwt = walletSessionAuthority.value.auth.walletSessionJwt;
  const { thresholdSessionId, signingGrantId } = walletSessionAuthority.value;
  const relayerUrl = nonEmptyString(record.relayerUrl);
  if (!relayerUrl) return { ok: false, reason: 'missing_relayer_url' };
  const relayerKeyId = nonEmptyString(record.relayerKeyId);
  if (!relayerKeyId) return { ok: false, reason: 'missing_relayer_key_id' };
  const participantIds = Array.isArray(record.participantIds)
    ? record.participantIds.map((value) => Number(value)).filter(Number.isFinite)
    : [];
  if (participantIds.length === 0) return { ok: false, reason: 'missing_participant_ids' };
  if (!record.runtimePolicyScope) return { ok: false, reason: 'missing_runtime_policy_scope' };
  const routerAbNormalSigning = record.routerAbNormalSigning;
  const signingWorkerId = nonEmptyString(routerAbNormalSigning.signingWorkerId);
  if (!signingWorkerId) {
    return { ok: false, reason: 'missing_router_ab_state' };
  }
  const expiresAtMs = positiveInteger(record.expiresAtMs);
  const remainingUses = positiveInteger(record.remainingUses);
  if (!expiresAtMs || expiresAtMs <= Date.now() || !remainingUses) {
    return { ok: false, reason: 'invalid_budget' };
  }
  return {
    ok: true,
    value: {
      kind: 'router_ab_ed25519_export_wallet_session_auth_v1',
      walletSessionJwt,
      thresholdSessionId,
      signingGrantId,
      relayerUrl,
      relayerKeyId,
      participantIds,
      expiresAtMs,
      remainingUses,
      runtimePolicyScope: record.runtimePolicyScope,
      routerAbNormalSigning,
      signingWorkerId,
    },
  };
}

function assertNearEd25519ExportRecordMatchesLane(args: {
  record: ThresholdEd25519SessionRecord | null | undefined;
  exportLane: ExactNearEd25519ExportLane;
}): ThresholdEd25519SessionRecord {
  const record = args.record;
  if (!record) {
    throw new Error('[SigningEngine][ed25519-export] exact export session record is not ready');
  }
  const signer = args.exportLane.signer;
  if (String(record.walletId) !== String(signer.account.wallet.walletId)) {
    throw new Error('[SigningEngine][ed25519-export] exact export wallet identity drifted');
  }
  if (String(record.nearAccountId) !== String(signer.account.nearAccountId)) {
    throw new Error('[SigningEngine][ed25519-export] exact export NEAR account drifted');
  }
  if (String(record.nearEd25519SigningKeyId) !== String(signer.nearEd25519SigningKeyId)) {
    throw new Error('[SigningEngine][ed25519-export] exact export signing key drifted');
  }
  if (Number(record.signerSlot) !== signer.signerSlot) {
    throw new Error('[SigningEngine][ed25519-export] exact export signer slot drifted');
  }
  const recordAuthMethod =
    record.source === SIGNER_AUTH_METHODS.emailOtp ? 'email_otp' : 'passkey';
  if (recordAuthMethod !== args.exportLane.authMethod) {
    throw new Error('[SigningEngine][ed25519-export] exact export auth method drifted');
  }
  if (String(record.signingGrantId || '').trim() !== args.exportLane.signingGrantId) {
    throw new Error('[SigningEngine][ed25519-export] exact export wallet session drifted');
  }
  if (String(record.thresholdSessionId || '').trim() !== args.exportLane.thresholdSessionId) {
    throw new Error('[SigningEngine][ed25519-export] exact export threshold session drifted');
  }
  return record;
}

function emitNearEd25519MaterialStarted(args: {
  flowId: string;
  nearAccountId: AccountId;
  onEvent?: KeyExportEventCallback;
}): void {
  emitKeyExportEvent(args.onEvent, {
    phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_STARTED,
    status: 'running',
    flowId: args.flowId,
    accountId: String(args.nearAccountId),
    interaction: { kind: 'none', overlay: 'none' },
    data: { chain: 'near', curve: 'ed25519' },
  });
}

function emitNearEd25519MaterialSucceeded(args: {
  flowId: string;
  nearAccountId: AccountId;
  onEvent?: KeyExportEventCallback;
}): void {
  emitKeyExportEvent(args.onEvent, {
    phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_SUCCEEDED,
    status: 'succeeded',
    flowId: args.flowId,
    accountId: String(args.nearAccountId),
    interaction: { kind: 'none', overlay: 'none' },
    data: { chain: 'near', curve: 'ed25519' },
  });
}

async function prepareFreshPasskeyEd25519ExportAuthority(
  deps: NearEd25519SingleKeyExportDeps,
  args: {
    record: ThresholdEd25519SessionRecord;
    nearAccountId: AccountId;
    expectedPublicKey: string;
    runtimePolicyScope: ThresholdRuntimePolicyScope;
    flowId: string;
    onEvent?: KeyExportEventCallback;
  },
): Promise<{
  walletSessionJwt: string;
  thresholdSessionId: string;
  signingGrantId: string;
  prfFirstB64u: string;
}> {
  const signerSlot = Math.floor(Number(args.record.signerSlot) || 0);
  if (signerSlot <= 0) {
    throw new Error('[SigningEngine][ed25519-export] passkey export requires signer slot');
  }
  if (args.record.source === SIGNER_AUTH_METHODS.emailOtp) {
    throw new Error('[SigningEngine][ed25519-export] passkey export received Email OTP record');
  }
  const source = args.record.source;
  const authority = buildPasskeyWalletAuthAuthority({
    walletId: args.record.walletId,
    rpId: args.record.rpId,
    credentialIdB64u: args.record.passkeyCredentialIdB64u,
  });
  const planned = await buildPasskeyEd25519SessionPolicy({
    nearAccountId: args.nearAccountId,
    nearEd25519SigningKeyId: String(args.record.nearEd25519SigningKeyId),
    authority,
    relayerKeyId: args.record.relayerKeyId,
    runtimePolicyScope: args.runtimePolicyScope,
    routerAbNormalSigning: args.record.routerAbNormalSigning,
    participantIds: args.record.participantIds,
    remainingUses: 1,
  });
  const exportCredential = await requestNearEd25519ExportAuthorization(
    { touchConfirm: deps.touchConfirm, theme: deps.theme },
    {
      nearAccountId: args.nearAccountId,
      expectedPublicKey: args.expectedPublicKey,
      challengeB64u: planned.sessionPolicyDigest32,
      flowId: args.flowId,
      onEvent: args.onEvent,
    },
  );
  const prfFirstB64u = requirePrfFirstForPrivateKeyExport({
    credential: exportCredential.credential,
    errorContext: 'single-key HSS Ed25519 export',
  });
  const provisioned = await deps.provisionThresholdEd25519Session({
    kind: 'exact_ed25519_provisioning',
    walletId: String(args.record.walletId),
    nearAccountId: args.nearAccountId,
    nearEd25519SigningKeyId: String(args.record.nearEd25519SigningKeyId),
    relayerUrl: args.record.relayerUrl,
    relayerKeyId: args.record.relayerKeyId,
    source,
    authority: {
      kind: 'wallet_auth_authority',
      authority,
    },
    auth: {
      kind: 'threshold_session_policy_webauthn',
      policySecretSource: buildThresholdEd25519WebAuthnPrfSecretSource({
        credential: exportCredential.credential,
        rpId: args.record.rpId,
      }),
    },
    runtimePolicyScope: args.runtimePolicyScope,
    routerAbNormalSigning: args.record.routerAbNormalSigning,
    participantIds: args.record.participantIds,
    sessionKind: 'jwt',
    signerSlot,
    sessionId: planned.policy.thresholdSessionId,
    signingGrantId: planned.policy.signingGrantId,
    remainingUses: planned.policy.remainingUses,
  });
  if (!provisioned.ok) {
    throw new Error(
      provisioned.message || provisioned.code || 'Passkey Ed25519 export session mint failed',
    );
  }
  const walletSessionJwt = String(provisioned.jwt || '').trim();
  const thresholdSessionId = String(provisioned.sessionId || '').trim();
  const signingGrantId = String(provisioned.signingGrantId || '').trim();
  if (!walletSessionJwt || !thresholdSessionId || !signingGrantId) {
    throw new Error('[SigningEngine][ed25519-export] passkey export session mint was incomplete');
  }
  return {
    walletSessionJwt,
    thresholdSessionId,
    signingGrantId,
    prfFirstB64u,
  };
}

async function runNearEd25519HssExportAndViewer(
  deps: NearEd25519SingleKeyExportDeps,
  args: {
    nearAccountId: AccountId;
    nearEd25519SigningKeyId: ExactNearEd25519ExportLane['signer']['nearEd25519SigningKeyId'];
    expectedPublicKey: string;
    participantIds: number[];
    thresholdSessionId: string;
    walletSessionJwt: string;
    relayerUrl: string;
    relayerKeyId: string;
    runtimePolicyScope: ThresholdRuntimePolicyScope;
    prfFirstB64u: string;
    viewerSessionId: string;
    options: NearEd25519SingleKeyExportArgs['options'];
    flowId: string;
    onEvent?: KeyExportEventCallback;
    errorContext: string;
  },
): Promise<{ accountId: string; exportedSchemes: ExportedKeySchemes }> {
  emitNearEd25519MaterialStarted({
    flowId: args.flowId,
    nearAccountId: args.nearAccountId,
    onEvent: args.onEvent,
  });
  const signingRootScope = signingRootScopeFromRuntimePolicyScope(args.runtimePolicyScope);
  const signingRootId = String(signingRootScope.signingRootId || '').trim();
  const signingRootVersion = String(signingRootScope.signingRootVersion || '').trim();
  if (!signingRootId || !signingRootVersion) {
    throw new Error(`Missing signing root scope for ${args.errorContext} Ed25519 seed export`);
  }
  const hssTask = runNearEd25519SingleKeyHssExport(
    { getSignerWorkerContext: deps.getSignerWorkerContext },
    {
      signingRootId,
      signingRootVersion,
      nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
      nearAccountId: args.nearAccountId,
      participantIds: args.participantIds,
      thresholdSessionId: args.thresholdSessionId,
      walletSessionJwt: args.walletSessionJwt,
      relayerUrl: args.relayerUrl,
      relayerKeyId: args.relayerKeyId,
      prfFirstB64u: args.prfFirstB64u,
    },
  );
  await showNearEd25519ExportViewer(
    { touchConfirm: deps.touchConfirm, theme: deps.theme },
    {
      nearAccountId: args.nearAccountId,
      expectedPublicKey: args.expectedPublicKey,
      variant: args.options.variant,
      theme: args.options.theme,
      loading: true,
      viewerSessionId: args.viewerSessionId,
      flowId: args.flowId,
      onEvent: args.onEvent,
    },
  );

  const { preparedSession, finalizedReport } = await hssTask;
  const artifactResult = await buildThresholdEd25519SeedExportArtifactFromHssReport({
    preparedSession,
    finalizedReport,
    expectedPublicKey: args.expectedPublicKey,
    workerCtx: deps.getSignerWorkerContext(),
  });
  if (!artifactResult.ok) {
    throw new Error(
      artifactResult.message ||
        `Failed to build ${args.errorContext} Ed25519 seed export artifact`,
    );
  }
  emitNearEd25519MaterialSucceeded({
    flowId: args.flowId,
    nearAccountId: args.nearAccountId,
    onEvent: args.onEvent,
  });

  if (!isExportViewerSessionOpen(args.viewerSessionId)) {
    return {
      accountId: args.nearAccountId,
      exportedSchemes: ['ed25519'],
    };
  }
  await showNearEd25519ExportViewer(
    { touchConfirm: deps.touchConfirm, theme: deps.theme },
    {
      nearAccountId: args.nearAccountId,
      expectedPublicKey: artifactResult.artifact.publicKey,
      privateKey: artifactResult.artifact.privateKey,
      variant: args.options.variant,
      theme: args.options.theme,
      viewerSessionId: args.viewerSessionId,
      flowId: args.flowId,
      onEvent: args.onEvent,
    },
  );
  return {
    accountId: args.nearAccountId,
    exportedSchemes: ['ed25519'],
  };
}

export async function tryExportNearEd25519SingleKeyHssWithAuthorization(
  deps: NearEd25519SingleKeyExportDeps,
  args: NearEd25519SingleKeyExportArgs,
): Promise<{ accountId: string; exportedSchemes: ExportedKeySchemes } | null> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const signer = args.exportLane.signer;
  const sessionRecord = assertNearEd25519ExportRecordMatchesLane({
    record: getStoredThresholdEd25519SessionRecordForLane({
      walletId: signer.account.wallet.walletId,
      nearAccountId,
      nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
      authMethod: args.exportLane.authMethod,
      signingGrantId: args.exportLane.signingGrantId,
      thresholdSessionId: args.exportLane.thresholdSessionId,
      signerSlot: signer.signerSlot,
    }),
    exportLane: args.exportLane,
  });
  const orgId = String(sessionRecord.runtimePolicyScope?.orgId || '').trim();
  const projectId = String(sessionRecord.runtimePolicyScope?.projectId || '').trim();
  const envId = String(sessionRecord.runtimePolicyScope?.envId || '').trim();
  const signingRootVersion = String(
    sessionRecord.runtimePolicyScope?.signingRootVersion || '',
  ).trim();
  const thresholdSessionId = String(sessionRecord.thresholdSessionId || '').trim();
  const relayerUrl = String(sessionRecord.relayerUrl || '').trim();
  const relayerKeyId = String(sessionRecord.relayerKeyId || '').trim();
  const participantIds = Array.isArray(sessionRecord.participantIds)
    ? sessionRecord.participantIds.map((value) => Number(value))
    : [];
  const hasCanonicalRuntimeScope = Boolean(orgId && projectId && envId && signingRootVersion);

  const requireSingleKeyHssExportPrerequisite = (condition: boolean, message: string): void => {
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

  const signerSlot = signer.signerSlot;

  const thresholdKeyMaterial = await getNearThresholdKeyMaterial(
    {
      clientDB: deps.keyMaterialStore,
      keyMaterialStore: deps.keyMaterialStore,
    },
    nearAccountId,
    signerSlot,
  ).catch(() => null);
  const keyVersion = String(thresholdKeyMaterial?.keyVersion || '').trim();
  const expectedPublicKey = String(thresholdKeyMaterial?.publicKey || '').trim();
  if (!thresholdKeyMaterial || !keyVersion || !expectedPublicKey) {
    requireSingleKeyHssExportPrerequisite(
      false,
      'Missing canonical public key material for single-key HSS Ed25519 export',
    );
    return null;
  }
  const viewerSessionId = createExportUiRequestId('export-near-ed25519-viewer-session');

  try {
    if (sessionRecord.source === SIGNER_AUTH_METHODS.emailOtp) {
      const exportWalletSessionAuth =
        resolveRouterAbEd25519ExportWalletSessionAuthFromRecord(sessionRecord);
      if (!exportWalletSessionAuth.ok) {
        requireSingleKeyHssExportPrerequisite(
          false,
          'Missing Router A/B Wallet Session JWT for single-key HSS Ed25519 export',
        );
        return null;
      }
      const committedLane = buildEd25519ExportLane({
        record: sessionRecord,
        walletSessionAuth: exportWalletSessionAuth.value,
        expectedPublicKey,
      });
      const authorization = await requestEmailOtpKeyExportAuthorization(
        {
          touchConfirm: deps.touchConfirm,
          requestExportChallenge: (request) =>
            deps.emailOtpSessions.requestExportChallenge({
              ...request,
            }),
        },
        {
          kind: 'near_account_export_auth',
          walletSession: walletSessionRefFromSession({
            walletId: sessionRecord.walletId,
            walletSessionUserId: sessionRecord.walletId,
          }),
          nearAccountId,
          chain: 'near',
          publicKey: expectedPublicKey,
          curve: 'ed25519',
          challengeAuthority: { kind: 'signing_session', authLane: committedLane.authLane },
        },
      );
      emitNearEd25519MaterialStarted({
        flowId: args.flowId,
        nearAccountId,
        onEvent: args.onEvent,
      });
      await showNearEd25519ExportViewer(
        { touchConfirm: deps.touchConfirm, theme: deps.theme },
        {
          nearAccountId,
          expectedPublicKey,
          variant: args.options.variant,
          theme: args.options.theme,
          loading: true,
          viewerSessionId,
          flowId: args.flowId,
          onEvent: args.onEvent,
        },
      );
      const artifact = await deps.emailOtpSessions.exportEd25519SeedWithAuthorization({
        nearAccountId,
        challengeId: authorization.challengeId,
        otpCode: authorization.otpCode,
        committedLane,
      });
      emitNearEd25519MaterialSucceeded({
        flowId: args.flowId,
        nearAccountId,
        onEvent: args.onEvent,
      });
      if (!isExportViewerSessionOpen(viewerSessionId)) {
        return {
          accountId: nearAccountId,
          exportedSchemes: ['ed25519'],
        };
      }
      await showNearEd25519ExportViewer(
        { touchConfirm: deps.touchConfirm, theme: deps.theme },
        {
          nearAccountId,
          expectedPublicKey: artifact.publicKey,
          privateKey: artifact.privateKey,
          variant: args.options.variant,
          theme: args.options.theme,
          viewerSessionId,
          flowId: args.flowId,
          onEvent: args.onEvent,
        },
      );
      return {
        accountId: nearAccountId,
        exportedSchemes: ['ed25519'],
      };
    }

    const exportAuthority = await prepareFreshPasskeyEd25519ExportAuthority(
      deps,
      {
        record: sessionRecord,
        nearAccountId,
        expectedPublicKey,
        runtimePolicyScope: defaultRuntimePolicyScope,
        flowId: args.flowId,
        onEvent: args.onEvent,
      },
    );
    return await runNearEd25519HssExportAndViewer(deps, {
      runtimePolicyScope: defaultRuntimePolicyScope,
      nearAccountId,
      nearEd25519SigningKeyId: args.exportLane.signer.nearEd25519SigningKeyId,
      participantIds,
      thresholdSessionId: exportAuthority.thresholdSessionId,
      walletSessionJwt: exportAuthority.walletSessionJwt,
      relayerUrl,
      relayerKeyId,
      prfFirstB64u: exportAuthority.prfFirstB64u,
      expectedPublicKey,
      viewerSessionId,
      options: args.options,
      flowId: args.flowId,
      onEvent: args.onEvent,
      errorContext: 'single-key HSS',
    });
  } catch (error: unknown) {
    removeExportViewerHostIfPresent();
    throw error;
  }
}
