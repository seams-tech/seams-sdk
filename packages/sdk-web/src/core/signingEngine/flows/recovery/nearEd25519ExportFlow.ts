import { getNearThresholdKeyMaterial } from '@/core/accountData/near/keyMaterial';
import { getLastLoggedInSignerSlot } from '../../webauthnAuth/device/signerSlot';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { KeyExportEventPhase } from '@/core/types/sdkSentEvents';
import type { ThemeName } from '@/core/types/seams';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { ThresholdEd25519SessionRecord } from '../../session/persistence/records';
import { getStoredThresholdEd25519SessionRecordForLane } from '../../session/persistence/records';
import type { RouterAbEd25519NormalSigningState } from '../../threshold/ed25519/routerAbNormalSigningState';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  toAuthorizingSigningGrantId,
  type EmailOtpAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import { walletSessionJwtFromPersistedEd25519Record } from '../../session/walletSessionAuthBoundary';
import type {
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
    exportEd25519SeedWithAuthorization: (args: {
      nearAccountId: AccountId;
      challengeId: string;
      otpCode: string;
      record: ThresholdEd25519SessionRecord;
      participantIds: number[];
      thresholdSessionId: string;
      walletSessionJwt: string;
      relayerKeyId: string;
      expectedPublicKey: string;
      routeAuth?: AppOrWalletSessionAuth;
      authLane?: EmailOtpAuthLane;
    }) => Promise<{ publicKey: string; privateKey: string }>;
  };
  getSignerWorkerContext: () => WorkerOperationContext;
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
  | 'missing_record'
  | 'cookie_session'
  | 'missing_wallet_session_jwt'
  | 'missing_threshold_session_id'
  | 'missing_signing_grant_id'
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

export function resolveRouterAbEd25519ExportWalletSessionAuthFromRecord(
  record: ThresholdEd25519SessionRecord | null | undefined,
): RouterAbEd25519ExportWalletSessionAuthResult {
  if (!record) return { ok: false, reason: 'missing_record' };
  if (record.thresholdSessionKind !== 'jwt') return { ok: false, reason: 'cookie_session' };
  const walletSessionJwt = walletSessionJwtFromPersistedEd25519Record(record);
  if (!walletSessionJwt) return { ok: false, reason: 'missing_wallet_session_jwt' };
  const thresholdSessionId = nonEmptyString(record.thresholdSessionId);
  if (!thresholdSessionId) return { ok: false, reason: 'missing_threshold_session_id' };
  const signingGrantId = nonEmptyString(record.signingGrantId);
  if (!signingGrantId) return { ok: false, reason: 'missing_signing_grant_id' };
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
  const signingWorkerId = nonEmptyString(routerAbNormalSigning?.signingWorkerId);
  if (!routerAbNormalSigning || !signingWorkerId) {
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

async function runNearEd25519HssExportAndViewer(
  deps: NearEd25519SingleKeyExportDeps,
  args: {
    nearAccountId: AccountId;
    ed25519KeyScopeId: ExactNearEd25519ExportLane['signer']['ed25519KeyScopeId'];
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
      ed25519KeyScopeId: args.ed25519KeyScopeId,
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
  const sessionRecord = assertNearEd25519ExportRecordMatchesLane({
    record: getStoredThresholdEd25519SessionRecordForLane({
      nearAccountId,
      authMethod: args.exportLane.authMethod,
      signingGrantId: args.exportLane.signingGrantId,
      thresholdSessionId: args.exportLane.thresholdSessionId,
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

  const signerSlot = await getLastLoggedInSignerSlot(nearAccountId, deps.keyMaterialStore).catch(
    () => null as number | null,
  );
  if (signerSlot == null) {
    requireSingleKeyHssExportPrerequisite(
      false,
      'Missing signer slot for single-key HSS Ed25519 export',
    );
    return null;
  }

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
  const exportWalletSessionAuth =
    resolveRouterAbEd25519ExportWalletSessionAuthFromRecord(sessionRecord);
  if (!exportWalletSessionAuth.ok) {
    requireSingleKeyHssExportPrerequisite(
      false,
      'Missing Router A/B Wallet Session JWT for single-key HSS Ed25519 export',
    );
    return null;
  }
  const walletSessionJwt = exportWalletSessionAuth.value.walletSessionJwt;

  const viewerSessionId = createExportUiRequestId('export-near-ed25519-viewer-session');

  try {
    if (sessionRecord.source === SIGNER_AUTH_METHODS.emailOtp) {
      const signingGrantId = String(sessionRecord.signingGrantId || '').trim();
      if (!signingGrantId) {
        throw new Error('Email OTP Ed25519 export requires signing grant identity');
      }
      const exportSigningSessionAuthLane = {
        kind: 'signing_session' as const,
        jwt: walletSessionJwt,
        thresholdSessionId,
        authorizingSigningGrantId: toAuthorizingSigningGrantId(
          signingGrantId,
        ),
        curve: 'ed25519' as const,
      };
      const authorization = await requestEmailOtpKeyExportAuthorization(
        {
          touchConfirm: deps.touchConfirm,
          requestExportChallenge: (request) =>
            deps.emailOtpSessions.requestExportChallenge({
              kind: 'near_account_challenge',
              walletSession: walletSessionRefFromSession({
                walletId: sessionRecord.walletId,
                walletSessionUserId: sessionRecord.walletId,
              }),
	              nearAccountId,
	              chain: 'near',
              ...(request.routeAuth ? { routeAuth: request.routeAuth } : {}),
              ...(request.authLane ? { authLane: request.authLane } : {}),
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
          authLane: exportSigningSessionAuthLane,
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
        record: sessionRecord,
        participantIds,
        thresholdSessionId,
        walletSessionJwt,
        relayerKeyId,
        expectedPublicKey,
        authLane: exportSigningSessionAuthLane,
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

    const exportCredential = await requestNearEd25519ExportAuthorization(
      { touchConfirm: deps.touchConfirm, theme: deps.theme },
      {
        nearAccountId,
        expectedPublicKey,
        flowId: args.flowId,
        onEvent: args.onEvent,
      },
    );
    const prfFirstB64u = requirePrfFirstForPrivateKeyExport({
      credential: exportCredential.credential,
      errorContext: 'single-key HSS Ed25519 export',
    });
    return await runNearEd25519HssExportAndViewer(deps, {
      runtimePolicyScope: defaultRuntimePolicyScope,
      nearAccountId,
      ed25519KeyScopeId: args.exportLane.signer.ed25519KeyScopeId,
      participantIds,
      thresholdSessionId,
      walletSessionJwt,
      relayerUrl,
      relayerKeyId,
      prfFirstB64u,
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
