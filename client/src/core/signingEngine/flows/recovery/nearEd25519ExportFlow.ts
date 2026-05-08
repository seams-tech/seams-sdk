import { getNearThresholdKeyMaterial } from '@/core/accountData/near/keyMaterial';
import { getLastLoggedInSignerSlot } from '../../walletAuth/webauthn/device/signerSlot';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { KeyExportEventPhase } from '@/core/types/sdkSentEvents';
import type { ThemeName } from '@/core/types/seams';
import { requireThresholdSessionAuthToken } from '@shared/utils/sessionTokens';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { ThresholdEd25519SessionRecord } from '../../session/persistence/records';
import { getStoredThresholdEd25519SessionRecordForLane } from '../../session/persistence/records';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type { EmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { ExactNearEd25519ExportLane } from './exportLaneSelection';
import {
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

export type NearEd25519SingleKeyExportDeps = {
  indexedDB: Parameters<typeof getNearThresholdKeyMaterial>[0] & {
    clientDB: Parameters<typeof getLastLoggedInSignerSlot>[1];
  };
  touchConfirm: Parameters<typeof showNearEd25519ExportViewer>[0]['touchConfirm'];
  theme?: ThemeName;
  emailOtpSessions: {
    requestExportChallenge: (args: {
      nearAccountId: AccountId | string;
      chain: 'near';
      routeAuth?: AppOrThresholdSessionAuth;
      authLane?: EmailOtpAuthLane;
    }) => Promise<{ challengeId: string; emailHint?: string }>;
    recoverEd25519ExportPrfFirst: (args: {
      nearAccountId: AccountId | string;
      challengeId: string;
      otpCode: string;
      record: ThresholdEd25519SessionRecord;
      routeAuth?: AppOrThresholdSessionAuth;
      authLane?: EmailOtpAuthLane;
    }) => Promise<{ prfFirstB64u: string }>;
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
  if (String(record.walletSigningSessionId || '').trim() !== args.exportLane.walletSigningSessionId) {
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
    expectedPublicKey: string;
    keyVersion: string;
    participantIds: number[];
    thresholdSessionId: string;
    thresholdSessionAuthToken: string;
    relayerUrl: string;
    relayerKeyId: string;
    signingRootId: string;
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
  const hssTask = runNearEd25519SingleKeyHssExport(
    { getSignerWorkerContext: deps.getSignerWorkerContext },
    {
      signingRootId: args.signingRootId,
      nearAccountId: args.nearAccountId,
      keyVersion: args.keyVersion,
      participantIds: args.participantIds,
      thresholdSessionId: args.thresholdSessionId,
      thresholdSessionAuthToken: args.thresholdSessionAuthToken,
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
  if (!artifactResult.success || !artifactResult.artifact) {
    throw new Error(
      artifactResult.error || `Failed to build ${args.errorContext} Ed25519 seed export artifact`,
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
      walletSigningSessionId: args.exportLane.walletSigningSessionId,
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
  const thresholdSessionAuthToken = String(sessionRecord.thresholdSessionAuthToken || '').trim();
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
    !thresholdSessionAuthToken ||
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
  const defaultSigningRootId =
    signingRootScopeFromRuntimePolicyScope(defaultRuntimePolicyScope).signingRootId;

  const signerSlot = await getLastLoggedInSignerSlot(nearAccountId, deps.indexedDB.clientDB).catch(
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
    deps.indexedDB,
    nearAccountId,
    signerSlot,
  ).catch(() => null);
  const keyVersion = String(thresholdKeyMaterial?.keyVersion || '').trim();
  const expectedPublicKey = String(thresholdKeyMaterial?.publicKey || '').trim();
  if (!keyVersion || !expectedPublicKey) {
    requireSingleKeyHssExportPrerequisite(
      false,
      'Missing canonical public key material for single-key HSS Ed25519 export',
    );
    return null;
  }

  const viewerSessionId = createExportUiRequestId('export-near-ed25519-viewer-session');

  try {
    if (sessionRecord.source === SIGNER_AUTH_METHODS.emailOtp) {
      const walletSigningSessionId = String(sessionRecord.walletSigningSessionId || '').trim();
      if (!walletSigningSessionId) {
        throw new Error('Email OTP Ed25519 export requires wallet signing-session identity');
      }
      const exportSigningSessionAuthLane = {
        kind: 'signing_session' as const,
        jwt: requireThresholdSessionAuthToken(
          String(sessionRecord.thresholdSessionAuthToken || '').trim(),
          'exportThresholdSessionAuthToken',
        ),
        thresholdSessionId,
        walletSigningSessionId,
        curve: 'ed25519' as const,
      };
      const authorization = await requestEmailOtpKeyExportAuthorization(
        {
          touchConfirm: deps.touchConfirm,
          requestExportChallenge: (request) =>
            deps.emailOtpSessions.requestExportChallenge({
              ...request,
              nearAccountId,
              chain: 'near',
            }),
        },
        {
          nearAccountId,
          chain: 'near',
          publicKey: expectedPublicKey,
          curve: 'ed25519',
          authLane: exportSigningSessionAuthLane,
        },
      );
      const exportMaterial = await deps.emailOtpSessions.recoverEd25519ExportPrfFirst({
        nearAccountId,
        challengeId: authorization.challengeId,
        otpCode: authorization.otpCode,
        record: sessionRecord,
        authLane: exportSigningSessionAuthLane,
      });
      return await runNearEd25519HssExportAndViewer(deps, {
        signingRootId: defaultSigningRootId,
        nearAccountId,
        keyVersion,
        participantIds,
        thresholdSessionId,
        thresholdSessionAuthToken,
        relayerUrl,
        relayerKeyId,
        prfFirstB64u: exportMaterial.prfFirstB64u,
        expectedPublicKey,
        viewerSessionId,
        options: args.options,
        flowId: args.flowId,
        onEvent: args.onEvent,
        errorContext: 'Email OTP single-key HSS',
      });
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
      credential: exportCredential,
      errorContext: 'single-key HSS Ed25519 export',
    });
    return await runNearEd25519HssExportAndViewer(deps, {
      signingRootId: defaultSigningRootId,
      nearAccountId,
      keyVersion,
      participantIds,
      thresholdSessionId,
      thresholdSessionAuthToken,
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
