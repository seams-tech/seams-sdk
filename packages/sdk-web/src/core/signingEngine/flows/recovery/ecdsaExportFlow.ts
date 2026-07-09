import { KeyExportEventPhase } from '@/core/types/sdkSentEvents';
import type { ThemeMode, WalletAuthCurve } from '@/core/types/seams';
import {
  toWalletId,
  walletSessionRefFromSession,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { SENSITIVE_OPERATION_POLICIES } from '@shared/utils/signerDomain';
import type { EmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { WarmSessionPostSignPolicyAdapterDeps } from '../../session/operationState/warmSessionPolicyAdapter';
import { assertWarmSessionEcdsaOperationAllowed } from '../../session/operationState/warmSessionPolicyAdapter';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  ecdsaExportBoundaryChain,
  type EcdsaExportLane,
  type EcdsaExportSessionStoreDeps,
  type ExactEcdsaExportLane,
  type FreshEmailOtpEcdsaExportMaterial,
  type FreshEmailOtpEcdsaExportMaterialNeedsChallenge,
  type FreshEmailOtpEcdsaExportMaterialRouteAuthReady,
  type FreshPasskeyEcdsaExportMaterial,
  type ReadyEcdsaExportMaterial,
  type ReadyPasskeyThresholdEcdsaExportMaterial,
  resolveEcdsaExportMaterialForLane,
} from './ecdsaExportMaterial';
import { exportEcdsaHssKeyWithWalletSession } from './ecdsaHssExport';
import { buildEcdsaSessionPolicy } from '../../threshold/sessionPolicy';
import { computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u } from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { getPrfFirstB64uFromCredential } from '../../webauthnAuth/credentials/credentialExtensions';
import {
  buildEcdsaExportActivation,
  type ThresholdEcdsaActivationRequest,
} from '../../session/passkey/ecdsaSessionProvision';
import { buildEcdsaSessionIdentity } from '../../session/warmCapabilities/ecdsaProvisionPlan';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import { getThresholdEcdsaSessionRecordByKey } from '../../session/persistence/records';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
} from '../../session/identity/exactSigningLaneIdentity';
import {
  type EmailOtpWalletSessionExportAuthorizationDeps,
  createEmailOtpKeyExportRequiresPasskeyError,
  isEmailOtpPasskeyStepUpError,
  requestEmailOtpKeyExportAuthorization,
  requestThresholdEcdsaExportAuthorization,
  showThresholdEcdsaExportViewer,
  isExportViewerSessionOpen,
  removeExportViewerHostIfPresent,
} from './keyExportConfirmation';
import {
  createExportUiRequestId,
  emitKeyExportEvent,
  type KeyExportEventCallback,
} from './keyExportFlow';

type ExportedKeySchemes = Array<'ed25519' | 'secp256k1'>;
type EcdsaExportArtifact = {
  publicKeyHex: string;
  privateKeyHex: string;
  ethereumAddress: string;
};

export type EcdsaExportFlowDeps = {
  sessionStore: EcdsaExportSessionStoreDeps;
  touchConfirm: Parameters<typeof showThresholdEcdsaExportViewer>[0]['touchConfirm'];
  theme?: ThemeMode;
  emailOtp: {
    requestExportChallenge: EmailOtpWalletSessionExportAuthorizationDeps['requestExportChallenge'];
    exportEcdsaKeyWithFreshEmailOtpLane: (args: {
      walletSession: ReturnType<typeof walletSessionRefFromSession>;
      chainTarget: ThresholdEcdsaChainTarget;
      challengeId: string;
      otpCode: string;
      publicFacts: FreshEmailOtpEcdsaExportMaterial['publicFacts'];
      providerUserId?: string;
      emailHashHex: string;
      runtimePolicyScope: FreshEmailOtpEcdsaExportMaterial['runtimePolicyScope'];
    }) => Promise<EcdsaExportArtifact>;
    exportEcdsaKeyWithAuthorization: (args: {
      walletSession: ReturnType<typeof walletSessionRefFromSession>;
      challengeId: string;
      otpCode: string;
      committedLane: EcdsaExportLane<EmailOtpWalletAuthAuthority>;
    }) => Promise<EcdsaExportArtifact>;
  };
  warmSessionPolicy: Pick<
    WarmSessionPostSignPolicyAdapterDeps,
    'getWarmSession' | 'resolveExactEcdsaRecord'
  >;
  provisionThresholdEcdsaSession: (
    args: ThresholdEcdsaActivationRequest,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  getSignerWorkerContext: () => WorkerOperationContext;
};

type EcdsaExportOptions = {
  variant?: 'drawer' | 'modal';
  theme?: 'dark' | 'light';
};

function emitEcdsaMaterialStarted(args: {
  flowId: string;
  walletId: string;
  chain: 'evm' | 'tempo';
  onEvent?: KeyExportEventCallback;
}): void {
  emitKeyExportEvent(args.onEvent, {
    phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_STARTED,
    status: 'running',
    flowId: args.flowId,
    accountId: String(args.walletId),
    interaction: { kind: 'none', overlay: 'none' },
    data: { chain: args.chain, curve: 'ecdsa' },
  });
}

function emitEcdsaMaterialSucceeded(args: {
  flowId: string;
  walletId: string;
  chain: 'evm' | 'tempo';
  source?: 'cached';
  onEvent?: KeyExportEventCallback;
}): void {
  emitKeyExportEvent(args.onEvent, {
    phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_SUCCEEDED,
    status: 'succeeded',
    flowId: args.flowId,
    accountId: String(args.walletId),
    interaction: { kind: 'none', overlay: 'none' },
    data: { chain: args.chain, curve: 'ecdsa', ...(args.source ? { source: args.source } : {}) },
  });
}

async function showEcdsaExportArtifact(
  deps: Pick<EcdsaExportFlowDeps, 'touchConfirm' | 'theme'>,
  args: {
    walletId: string;
    exportLane: ExactEcdsaExportLane;
    artifact: EcdsaExportArtifact;
    options: EcdsaExportOptions;
    viewerSessionId?: string;
    flowId: string;
    onEvent?: KeyExportEventCallback;
  },
): Promise<void> {
  await showThresholdEcdsaExportViewer(
    { touchConfirm: deps.touchConfirm, theme: deps.theme },
    {
      state: 'ready',
      walletId: args.walletId,
      chainTarget: args.exportLane.session.chainTarget,
      publicKeyHex: String(args.artifact.publicKeyHex || '').trim(),
      privateKeyHex: String(args.artifact.privateKeyHex || '').trim(),
      ethereumAddress: String(args.artifact.ethereumAddress || '').trim(),
      variant: args.options.variant,
      theme: args.options.theme,
      viewerSessionId: args.viewerSessionId,
      flowId: args.flowId,
      onEvent: args.onEvent,
    },
  );
}

async function showEcdsaExportLoadingViewer(
  deps: Pick<EcdsaExportFlowDeps, 'touchConfirm' | 'theme'>,
  args: {
    walletId: string;
    exportLane: ExactEcdsaExportLane;
    publicKey: string;
    ethereumAddress: string;
    options: EcdsaExportOptions;
    viewerSessionId: string;
    flowId: string;
    onEvent?: KeyExportEventCallback;
  },
): Promise<void> {
  await showThresholdEcdsaExportViewer(
    { touchConfirm: deps.touchConfirm, theme: deps.theme },
    {
      state: 'loading',
      walletId: args.walletId,
      chainTarget: args.exportLane.session.chainTarget,
      publicKeyHex: String(args.publicKey || '').trim(),
      ethereumAddress: String(args.ethereumAddress || '').trim(),
      variant: args.options.variant,
      theme: args.options.theme,
      viewerSessionId: args.viewerSessionId,
      flowId: args.flowId,
      onEvent: args.onEvent,
    },
  );
}

async function prepareAndShowEcdsaExportArtifact(
  deps: EcdsaExportFlowDeps,
  args: {
    walletId: string;
    exportLane: ExactEcdsaExportLane;
    exportPublicKey: string;
    options: EcdsaExportOptions;
    flowId: string;
    onEvent?: KeyExportEventCallback;
    prepareArtifact: () => Promise<EcdsaExportArtifact>;
  },
): Promise<{ accountId: string; exportedSchemes: ExportedKeySchemes }> {
  const exportChain = ecdsaExportBoundaryChain(args.exportLane);
  const viewerSessionId = createExportUiRequestId('export-threshold-ecdsa-viewer-session');
  emitEcdsaMaterialStarted({
    flowId: args.flowId,
    walletId: args.walletId,
    chain: exportChain,
    onEvent: args.onEvent,
  });
  try {
    await showEcdsaExportLoadingViewer(deps, {
      walletId: args.walletId,
      exportLane: args.exportLane,
      publicKey: args.exportPublicKey,
      ethereumAddress: args.exportLane.publicFacts.thresholdOwnerAddress,
      options: args.options,
      viewerSessionId,
      flowId: args.flowId,
      onEvent: args.onEvent,
    });
    const artifact = await args.prepareArtifact();
    emitEcdsaMaterialSucceeded({
      flowId: args.flowId,
      walletId: args.walletId,
      chain: exportChain,
      onEvent: args.onEvent,
    });
    if (!isExportViewerSessionOpen(viewerSessionId)) {
      return {
        accountId: String(args.walletId),
        exportedSchemes: ['secp256k1'],
      };
    }
    await showEcdsaExportArtifact(deps, {
      walletId: args.walletId,
      exportLane: args.exportLane,
      artifact,
      options: args.options,
      viewerSessionId,
      flowId: args.flowId,
      onEvent: args.onEvent,
    });
    return {
      accountId: String(args.walletId),
      exportedSchemes: ['secp256k1'],
    };
  } catch (error: unknown) {
    removeExportViewerHostIfPresent();
    throw error;
  }
}

function requirePasskeyEcdsaExportAuth(
  exportLane: ExactEcdsaExportLane,
): Extract<ExactEcdsaExportLane['laneIdentity']['auth'], { kind: 'passkey' }> {
  const auth = exportLane.laneIdentity.auth;
  if (auth.kind !== 'passkey') {
    throw new Error('[SigningEngine][ecdsa-export] fresh passkey export requires passkey lane');
  }
  return auth;
}

function walletKeyForFreshPasskeyEcdsaExport(args: {
  exportLane: ExactEcdsaExportLane;
  material: FreshPasskeyEcdsaExportMaterial;
}) {
  return {
    kind: 'evm_family_ecdsa_wallet_key' as const,
    walletId: args.exportLane.key.walletId,
    evmFamilySigningKeySlotId: args.exportLane.key.evmFamilySigningKeySlotId,
    keyHandle: args.material.publicFacts.keyHandle,
    chainTarget: args.exportLane.session.chainTarget,
    keyFacts: {
      kind: 'evm_family_ecdsa_key_facts' as const,
      keyScope: args.exportLane.key.keyScope,
      ecdsaThresholdKeyId: args.exportLane.key.ecdsaThresholdKeyId,
      signingRootId: args.exportLane.key.signingRootId,
      signingRootVersion: args.exportLane.key.signingRootVersion,
      participantIds: args.exportLane.key.participantIds,
      thresholdOwnerAddress: args.material.publicFacts.thresholdOwnerAddress,
      thresholdEcdsaPublicKeyB64u: args.material.publicFacts.publicKeyB64u,
    },
  };
}

function refreshedPasskeyEcdsaExportLane(args: {
  baseLane: ExactEcdsaExportLane;
  thresholdSessionId: string;
  signingGrantId: string;
}): ExactEcdsaExportLane {
  const laneIdentity = exactEcdsaSigningLaneIdentity({
    signer: buildEvmFamilyEcdsaSignerBinding({
      walletId: args.baseLane.key.walletId,
      chainTarget: args.baseLane.session.chainTarget,
      keyHandle: args.baseLane.publicFacts.keyHandle,
      key: args.baseLane.key,
    }),
    auth: requirePasskeyEcdsaExportAuth(args.baseLane),
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
  });
  return {
    ...args.baseLane,
    laneIdentity,
    session: {
      ...args.baseLane.session,
      signingGrantId: laneIdentity.signingGrantId,
      thresholdSessionId: laneIdentity.thresholdSessionId,
      state: 'ready',
      material: { kind: 'loaded_worker_material' },
    },
  };
}

async function prepareFreshPasskeyEcdsaExportMaterial(
  deps: EcdsaExportFlowDeps,
  args: {
    walletId: string;
    exportLane: ExactEcdsaExportLane;
    material: FreshPasskeyEcdsaExportMaterial;
    exportPublicKey: string;
    flowId: string;
    onEvent?: KeyExportEventCallback;
  },
): Promise<{
  exportLane: ExactEcdsaExportLane;
  material: ReadyPasskeyThresholdEcdsaExportMaterial;
  credential: Awaited<ReturnType<typeof requestThresholdEcdsaExportAuthorization>>['credential'];
}> {
  if (args.material.record.source === 'email_otp') {
    throw new Error('[SigningEngine][ecdsa-export] fresh passkey export received Email OTP record');
  }
  const auth = requirePasskeyEcdsaExportAuth(args.exportLane);
  const record = args.material.record;
  const relayerKeyId = String(record.relayerKeyId || '').trim();
  const ecdsaThresholdKeyId = String(record.ecdsaThresholdKeyId || '').trim();
  const evmFamilySigningKeySlotId = String(record.evmFamilySigningKeySlotId || '').trim();
  if (!relayerKeyId || !ecdsaThresholdKeyId || !evmFamilySigningKeySlotId) {
    throw new Error('[SigningEngine][ecdsa-export] fresh passkey export missing key identity');
  }
  const planned = await buildEcdsaSessionPolicy({
    walletId: args.walletId,
    evmFamilySigningKeySlotId,
    relayerKeyId,
    chainTarget: args.exportLane.session.chainTarget,
    ecdsaThresholdKeyId,
    runtimePolicyScope: args.material.runtimePolicyScope,
    participantIds: record.participantIds.map((participantId) => Number(participantId)),
    remainingUses: 1,
  });
  const requestId = createExportUiRequestId('tecdsa-export-bootstrap');
  const challengeB64u = await computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u({
    walletId: planned.policy.walletId,
    evmFamilySigningKeySlotId: planned.policy.evmFamilySigningKeySlotId,
    rpId: auth.rpId,
    ecdsaThresholdKeyId: planned.policy.ecdsaThresholdKeyId,
    signingRootId: String(record.signingRootId || args.exportLane.key.signingRootId),
    signingRootVersion: String(
      record.signingRootVersion || args.exportLane.key.signingRootVersion || 'default',
    ),
    keyScope: args.exportLane.key.keyScope,
    relayerKeyId,
    requestId,
    sessionId: planned.policy.sessionId,
    signingGrantId: planned.policy.signingGrantId,
    ttlMs: planned.policy.ttlMs,
    remainingUses: planned.policy.remainingUses,
    participantIds: planned.policy.participantIds || record.participantIds,
  });
  const exportCredential = await requestThresholdEcdsaExportAuthorization(
    { touchConfirm: deps.touchConfirm, theme: deps.theme },
    {
      walletSessionUserId: args.walletId,
      publicKey: args.exportPublicKey,
      chainTarget: args.exportLane.session.chainTarget,
      challengeB64u,
      flowId: args.flowId,
      onEvent: args.onEvent,
    },
  );
  const passkeyPrfFirstB64u = String(
    getPrfFirstB64uFromCredential(exportCredential.credential) || '',
  ).trim();
  if (!passkeyPrfFirstB64u) {
    throw new Error('[SigningEngine][ecdsa-export] passkey export requires PRF.first');
  }
  const provisioned = await deps.provisionThresholdEcdsaSession(
    buildEcdsaExportActivation({
      walletKey: walletKeyForFreshPasskeyEcdsaExport({
        exportLane: args.exportLane,
        material: args.material,
      }),
      lanePolicy: {
        chainTarget: args.exportLane.session.chainTarget,
        thresholdSessionId: planned.policy.sessionId,
        signingGrantId: planned.policy.signingGrantId,
        thresholdSessionKind: 'jwt',
        ttlMs: planned.policy.ttlMs,
        remainingUses: planned.policy.remainingUses,
        runtimePolicyScope: args.material.runtimePolicyScope,
      },
      source: record.source,
      relayerUrl: record.relayerUrl,
      sessionIdentity: buildEcdsaSessionIdentity({
        thresholdSessionId: planned.policy.sessionId,
        signingGrantId: planned.policy.signingGrantId,
      }),
      sessionKind: 'jwt',
      sessionBudgetUses: planned.policy.remainingUses,
      requestId,
      runtimePolicy: { kind: 'scoped_policy', scope: args.material.runtimePolicyScope },
      passkeyPrfFirstB64u,
      webauthnAuthentication: exportCredential.credential,
    }),
  );
  const thresholdSessionId = String(provisioned.session.thresholdSessionId || '').trim();
  const signingGrantId = String(provisioned.session.signingGrantId || '').trim();
  if (!thresholdSessionId || !signingGrantId) {
    throw new Error('[SigningEngine][ecdsa-export] passkey export provision returned no session');
  }
  const refreshedRecord = getThresholdEcdsaSessionRecordByKey(deps.sessionStore, {
    walletId: toWalletId(args.walletId),
    keyHandle: args.material.publicFacts.keyHandle,
    authMethod: 'passkey',
    curve: 'ecdsa',
    chainTarget: args.exportLane.session.chainTarget,
    signingGrantId,
    thresholdSessionId,
  });
  if (!refreshedRecord) {
    throw new Error('[SigningEngine][ecdsa-export] passkey export provision did not publish record');
  }
  const refreshedLane = refreshedPasskeyEcdsaExportLane({
    baseLane: args.exportLane,
    thresholdSessionId,
    signingGrantId,
  });
  const refreshedMaterial = await resolveEcdsaExportMaterialForLane(
    deps.sessionStore,
    refreshedLane,
  );
  if (
    refreshedMaterial.kind !== 'ready_threshold_ecdsa_export_material' ||
    refreshedMaterial.authMethod !== 'passkey'
  ) {
    throw new Error('[SigningEngine][ecdsa-export] passkey export provision is not ready');
  }
  return {
    exportLane: refreshedLane,
    material: refreshedMaterial,
    credential: exportCredential.credential,
  };
}

export async function exportThresholdEcdsaKeyWithFreshEmailOtpAuthorization(
  deps: EcdsaExportFlowDeps,
  args: {
    walletId: string;
    exportLane: ExactEcdsaExportLane;
    material: FreshEmailOtpEcdsaExportMaterialNeedsChallenge;
    options: EcdsaExportOptions;
    flowId: string;
    onEvent?: KeyExportEventCallback;
  },
): Promise<{ accountId: string; exportedSchemes: ExportedKeySchemes }> {
  if (
    args.exportLane.session.authMethod !== 'email_otp' ||
    args.material.kind !== 'fresh_email_otp_needs_challenge'
  ) {
    throw new Error('[SigningEngine][ecdsa-export] fresh export requires Email OTP lane');
  }
  const exportChain = ecdsaExportBoundaryChain(args.exportLane);
  const authorization = await requestEmailOtpKeyExportAuthorization(
    {
      touchConfirm: deps.touchConfirm,
      requestExportChallenge: deps.emailOtp.requestExportChallenge,
    },
    {
      kind: 'wallet_session_export_auth',
      walletSession: walletSessionRefFromSession({
        walletId: args.walletId,
        walletSessionUserId: args.walletId,
      }),
      chain: exportChain,
      publicKey: String(args.material.publicFacts.publicKeyB64u),
      curve: 'ecdsa' satisfies WalletAuthCurve,
      challengeAuthority: { kind: 'fresh_login' },
    },
  );
  return await prepareAndShowEcdsaExportArtifact(deps, {
    walletId: args.walletId,
    exportLane: args.exportLane,
    exportPublicKey: String(args.material.publicFacts.publicKeyB64u),
    options: args.options,
    flowId: args.flowId,
    onEvent: args.onEvent,
    prepareArtifact: async () => {
      const walletSession = walletSessionRefFromSession({
        walletId: args.walletId,
        walletSessionUserId: args.walletId,
      });
      if (args.material.providerIdentityMode === 'explicit_provider_user') {
        return await deps.emailOtp.exportEcdsaKeyWithFreshEmailOtpLane({
          walletSession,
          chainTarget: args.material.chainTarget,
          challengeId: authorization.challengeId,
          otpCode: authorization.otpCode,
          publicFacts: args.material.publicFacts,
          providerUserId: args.material.providerUserId,
          emailHashHex: args.material.emailHashHex,
          runtimePolicyScope: args.material.runtimePolicyScope,
        });
      }
      return await deps.emailOtp.exportEcdsaKeyWithFreshEmailOtpLane({
        walletSession,
        chainTarget: args.material.chainTarget,
        challengeId: authorization.challengeId,
        otpCode: authorization.otpCode,
        publicFacts: args.material.publicFacts,
        emailHashHex: args.material.emailHashHex,
        runtimePolicyScope: args.material.runtimePolicyScope,
      });
    },
  });
}

export async function exportThresholdEcdsaKeyWithFreshEmailOtpRouteAuth(
  deps: EcdsaExportFlowDeps,
  args: {
    walletId: string;
    exportLane: ExactEcdsaExportLane;
    material: FreshEmailOtpEcdsaExportMaterialRouteAuthReady;
    options: EcdsaExportOptions;
    flowId: string;
    onEvent?: KeyExportEventCallback;
  },
): Promise<{ accountId: string; exportedSchemes: ExportedKeySchemes }> {
  const exportChain = ecdsaExportBoundaryChain(args.exportLane);
  const committedLane = args.material.committedLane;
  const authorization = await requestEmailOtpKeyExportAuthorization(
    {
      touchConfirm: deps.touchConfirm,
      requestExportChallenge: deps.emailOtp.requestExportChallenge,
    },
    {
      kind: 'wallet_session_export_auth',
      walletSession: walletSessionRefFromSession({
        walletId: args.walletId,
        walletSessionUserId: args.walletId,
      }),
      chain: exportChain,
      publicKey: String(args.material.publicFacts.publicKeyB64u),
      curve: 'ecdsa' satisfies WalletAuthCurve,
      challengeAuthority: { kind: 'signing_session', authLane: committedLane.authLane },
    },
  );
  return await prepareAndShowEcdsaExportArtifact(deps, {
    walletId: args.walletId,
    exportLane: args.exportLane,
    exportPublicKey: String(args.material.publicFacts.publicKeyB64u),
    options: args.options,
    flowId: args.flowId,
    onEvent: args.onEvent,
    prepareArtifact: async () =>
      await deps.emailOtp.exportEcdsaKeyWithAuthorization({
        walletSession: walletSessionRefFromSession({
          walletId: args.walletId,
          walletSessionUserId: args.walletId,
        }),
        challengeId: authorization.challengeId,
        otpCode: authorization.otpCode,
        committedLane,
      }),
  });
}

export async function exportThresholdEcdsaKeyWithFreshPasskeyAuthorization(
  deps: EcdsaExportFlowDeps,
  args: {
    walletId: string;
    exportLane: ExactEcdsaExportLane;
    material: FreshPasskeyEcdsaExportMaterial;
    options: EcdsaExportOptions;
    flowId: string;
    onEvent?: KeyExportEventCallback;
  },
): Promise<{ accountId: string; exportedSchemes: ExportedKeySchemes }> {
  if (args.exportLane.session.authMethod !== 'passkey') {
    throw new Error('[SigningEngine][ecdsa-export] fresh passkey export requires passkey lane');
  }
  const exportPublicKey = String(args.material.publicFacts.publicKeyB64u);
  const prepared = await prepareFreshPasskeyEcdsaExportMaterial(deps, {
    walletId: args.walletId,
    exportLane: args.exportLane,
    material: args.material,
    exportPublicKey,
    flowId: args.flowId,
    onEvent: args.onEvent,
  });
  return await prepareAndShowEcdsaExportArtifact(deps, {
    walletId: args.walletId,
    exportLane: prepared.exportLane,
    exportPublicKey,
    options: args.options,
    flowId: args.flowId,
    onEvent: args.onEvent,
    prepareArtifact: async () =>
      await exportEcdsaHssKeyWithWalletSession(
        { getSignerWorkerContext: deps.getSignerWorkerContext },
        {
          walletSessionUserId: args.walletId,
          signerSession: prepared.material.signerSession,
          committedLane: prepared.material.committedLane,
          credential: prepared.credential,
        },
      ),
  });
}

export async function exportThresholdEcdsaKeyWithAuthorization(
  deps: EcdsaExportFlowDeps,
  args: {
    walletId: string;
    material: ReadyEcdsaExportMaterial;
    exportLane: ExactEcdsaExportLane;
    options: EcdsaExportOptions;
    flowId: string;
    onEvent?: KeyExportEventCallback;
  },
): Promise<{ accountId: string; exportedSchemes: ExportedKeySchemes }> {
  const exportChain = ecdsaExportBoundaryChain(args.exportLane);
  const exportPublicKey =
    String(args.material.cachedExportArtifact?.publicKeyHex || '').trim() ||
    String(args.material.publicFacts.publicKeyB64u);
  const cachedArtifact = args.material.cachedExportArtifact;

  if (args.material.authMethod === 'email_otp') {
    const committedLane = args.material.committedLane;
    const authorization = await requestEmailOtpKeyExportAuthorization(
      {
        touchConfirm: deps.touchConfirm,
        requestExportChallenge: deps.emailOtp.requestExportChallenge,
      },
      {
        kind: 'wallet_session_export_auth',
        walletSession: walletSessionRefFromSession({
          walletId: args.walletId,
          walletSessionUserId: args.walletId,
        }),
        chain: exportChain,
        publicKey: exportPublicKey,
        curve: 'ecdsa',
        challengeAuthority: { kind: 'signing_session', authLane: committedLane.authLane },
      },
    );
    return await prepareAndShowEcdsaExportArtifact(deps, {
      walletId: args.walletId,
      exportLane: args.exportLane,
      exportPublicKey,
      options: args.options,
      flowId: args.flowId,
      onEvent: args.onEvent,
      prepareArtifact: async () =>
        await deps.emailOtp.exportEcdsaKeyWithAuthorization({
          walletSession: walletSessionRefFromSession({
            walletId: args.walletId,
            walletSessionUserId: args.walletId,
          }),
          challengeId: authorization.challengeId,
          otpCode: authorization.otpCode,
          committedLane,
        }),
    });
  }

  const passkeyCommittedLane = args.material.committedLane;
  const currentRecord = passkeyCommittedLane.record;
  try {
    await assertWarmSessionEcdsaOperationAllowed(deps.warmSessionPolicy, {
      lane: args.exportLane.laneIdentity,
      operationLabel: 'threshold-ecdsa key export',
      source: currentRecord.source,
      sensitivePolicy: SENSITIVE_OPERATION_POLICIES.requirePasskey,
    });
  } catch (error: unknown) {
    if (isEmailOtpPasskeyStepUpError(error)) {
      throw createEmailOtpKeyExportRequiresPasskeyError();
    }
    throw error;
  }
  if (cachedArtifact) {
    emitEcdsaMaterialStarted({
      flowId: args.flowId,
      walletId: args.walletId,
      chain: exportChain,
      onEvent: args.onEvent,
    });
    emitEcdsaMaterialSucceeded({
      flowId: args.flowId,
      walletId: args.walletId,
      chain: exportChain,
      source: 'cached',
      onEvent: args.onEvent,
    });
    await showEcdsaExportArtifact(deps, {
      walletId: args.walletId,
      exportLane: args.exportLane,
      artifact: cachedArtifact,
      options: args.options,
      flowId: args.flowId,
      onEvent: args.onEvent,
    });
    return {
      accountId: String(args.walletId),
      exportedSchemes: ['secp256k1'],
    };
  }
  const exportCredential = await requestThresholdEcdsaExportAuthorization(
    { touchConfirm: deps.touchConfirm, theme: deps.theme },
    {
      walletSessionUserId: args.walletId,
      publicKey: exportPublicKey,
      chainTarget: args.exportLane.session.chainTarget,
      flowId: args.flowId,
      onEvent: args.onEvent,
    },
  );
  return await prepareAndShowEcdsaExportArtifact(deps, {
    walletId: args.walletId,
    exportLane: args.exportLane,
    exportPublicKey,
    options: args.options,
    flowId: args.flowId,
    onEvent: args.onEvent,
    prepareArtifact: async () =>
      await exportEcdsaHssKeyWithWalletSession(
        { getSignerWorkerContext: deps.getSignerWorkerContext },
        {
          walletSessionUserId: args.walletId,
          signerSession: args.material.signerSession,
          committedLane: passkeyCommittedLane,
          credential: exportCredential.credential,
        },
      ),
  });
}
