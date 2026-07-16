import { KeyExportEventPhase } from '@/core/types/sdkSentEvents';
import type { ThemeMode, WalletAuthCurve } from '@/core/types/seams';
import {
  walletSessionRefFromSession,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { SENSITIVE_OPERATION_POLICIES } from '@shared/utils/signerDomain';
import type { EmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { WarmSessionPostSignPolicyAdapterDeps } from '../../session/operationState/warmSessionPolicyAdapter';
import { assertWarmSessionEcdsaOperationAllowed } from '../../session/operationState/warmSessionPolicyAdapter';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type { UiConfirmRuntimeBridgePort } from '../../uiConfirm/uiConfirm.types';
import {
  ecdsaExportBoundaryChain,
  type EcdsaExportLane,
  type EcdsaExportSessionStoreDeps,
  type ExactEcdsaExportLane,
  type FreshEmailOtpEcdsaExportMaterial,
  type FreshPasskeyEcdsaExportMaterial,
  type ReadyEcdsaExportMaterial,
  resolveEcdsaExportMaterialForLane,
} from './ecdsaExportMaterial';
import {
  exportEcdsaDerivationKeyWithExplicitExportSession,
  exportEcdsaDerivationKeyWithWalletSession,
} from './ecdsaDerivationExport';
import { buildEcdsaSessionPolicy } from '../../threshold/sessionPolicy';
import { computeEcdsaDerivationRoleLocalPasskeyBootstrapAuthDigest32B64u } from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { getPrfFirstB64uFromCredential } from '../../webauthnAuth/credentials/credentialExtensions';
import {
  buildEcdsaExportActivation,
  type ThresholdEcdsaPasskeyExportActivationRequest,
  type ThresholdEcdsaExplicitKeyExportBootstrapResult,
} from '../../session/passkey/ecdsaSessionProvision';
import { buildEcdsaSessionIdentity } from '../../session/warmCapabilities/ecdsaProvisionPlan';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import {
  type EmailOtpEcdsaExportAuthorizationDeps,
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

type ExportedKeySchemes = Array<'secp256k1'>;
type EcdsaExportArtifact = {
  publicKeyHex: string;
  privateKeyHex: string;
  ethereumAddress: string;
};

export type EcdsaExportFlowDeps = {
  sessionStore: EcdsaExportSessionStoreDeps;
  touchConfirm: Pick<UiConfirmRuntimeBridgePort, 'initialize' | 'requestUserConfirmation'>;
  theme?: ThemeMode;
  emailOtp: {
    requestExportChallenge: EmailOtpWalletSessionExportAuthorizationDeps['requestExportChallenge'];
    requestPublicReauthExportChallenge: EmailOtpEcdsaExportAuthorizationDeps['requestPublicReauthExportChallenge'];
    exportEcdsaKeyWithDurableAuthorization: (args: {
      walletSession: ReturnType<typeof walletSessionRefFromSession>;
      chainTarget: ThresholdEcdsaChainTarget;
      challengeId: string;
      otpCode: string;
      publicFacts: FreshEmailOtpEcdsaExportMaterial['publicFacts'];
      runtimePolicyScope: FreshEmailOtpEcdsaExportMaterial['runtimePolicyScope'];
      signingSessionAuthority: Extract<
        FreshEmailOtpEcdsaExportMaterial['authorization'],
        { kind: 'durable_authority_backed' }
      >['signingSessionAuthority'];
    }) => Promise<EcdsaExportArtifact>;
    exportEcdsaKeyWithAuthorization: (args: {
      walletSession: ReturnType<typeof walletSessionRefFromSession>;
      challengeId: string;
      otpCode: string;
      committedLane: EcdsaExportLane<EmailOtpWalletAuthAuthority>;
    }) => Promise<EcdsaExportArtifact>;
    exportEcdsaKeyWithPublicReauthAuthorization: (args: {
      walletSession: ReturnType<typeof walletSessionRefFromSession>;
      chainTarget: ThresholdEcdsaChainTarget;
      challengeId: string;
      otpCode: string;
      publicReauthAuthority: Extract<
        FreshEmailOtpEcdsaExportMaterial['authorization'],
        { kind: 'public_reauth_authority_backed' }
      >['publicReauthAuthority'];
    }) => Promise<EcdsaExportArtifact>;
  };
  warmSessionPolicy: Pick<
    WarmSessionPostSignPolicyAdapterDeps,
    'getWarmSession' | 'resolveExactEcdsaRecord'
  >;
  provisionPasskeyEcdsaExplicitExportSession: (
    args: ThresholdEcdsaPasskeyExportActivationRequest,
  ) => Promise<ThresholdEcdsaExplicitKeyExportBootstrapResult>;
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
  exportProvision: ThresholdEcdsaExplicitKeyExportBootstrapResult;
  credential: Awaited<ReturnType<typeof requestThresholdEcdsaExportAuthorization>>['credential'];
}> {
  const auth = requirePasskeyEcdsaExportAuth(args.exportLane);
  const bootstrap = args.material.bootstrap;
  const planned = await buildEcdsaSessionPolicy({
    walletId: args.walletId,
    evmFamilySigningKeySlotId: bootstrap.evmFamilySigningKeySlotId,
    relayerKeyId: bootstrap.relayerKeyId,
    chainTarget: args.exportLane.session.chainTarget,
    ecdsaThresholdKeyId: bootstrap.ecdsaThresholdKeyId,
    runtimePolicyScope: args.material.runtimePolicyScope,
    participantIds: bootstrap.participantIds.map((participantId) => Number(participantId)),
    remainingUses: 1,
  });
  const requestId = createExportUiRequestId('tecdsa-export-bootstrap');
  const challengeB64u = await computeEcdsaDerivationRoleLocalPasskeyBootstrapAuthDigest32B64u({
    walletId: planned.policy.walletId,
    evmFamilySigningKeySlotId: planned.policy.evmFamilySigningKeySlotId,
    rpId: auth.rpId,
    ecdsaThresholdKeyId: planned.policy.ecdsaThresholdKeyId,
    signingRootId: bootstrap.signingRootId,
    signingRootVersion: bootstrap.signingRootVersion,
    keyScope: args.exportLane.key.keyScope,
    relayerKeyId: bootstrap.relayerKeyId,
    requestId,
    sessionId: planned.policy.sessionId,
    signingGrantId: planned.policy.signingGrantId,
    ttlMs: planned.policy.ttlMs,
    remainingUses: planned.policy.remainingUses,
    participantIds: planned.policy.participantIds || [...bootstrap.participantIds],
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
  const provisionedResult = await deps.provisionPasskeyEcdsaExplicitExportSession(
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
      source: bootstrap.source,
      relayerUrl: bootstrap.relayerUrl,
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
  return {
    exportProvision: provisionedResult,
    credential: exportCredential.credential,
  };
}

function emailOtpEcdsaExportChallengeAuthority(material: FreshEmailOtpEcdsaExportMaterial) {
  switch (material.authorization.kind) {
    case 'record_backed':
      return {
        kind: 'signing_session' as const,
        authLane: material.authorization.committedLane.authLane,
      };
    case 'durable_authority_backed':
      return {
        kind: 'signing_session' as const,
        authLane: material.authorization.signingSessionAuthority.authLane,
      };
    case 'public_reauth_authority_backed':
      return { kind: 'public_reauth' as const };
  }
}

async function prepareFreshEmailOtpEcdsaExportArtifact(args: {
  deps: EcdsaExportFlowDeps;
  walletId: string;
  material: FreshEmailOtpEcdsaExportMaterial;
  authorization: Awaited<ReturnType<typeof requestEmailOtpKeyExportAuthorization>>;
}): Promise<EcdsaExportArtifact> {
  const walletSession = walletSessionRefFromSession({
    walletId: args.walletId,
    walletSessionUserId: args.walletId,
  });
  switch (args.material.authorization.kind) {
    case 'record_backed':
      return await args.deps.emailOtp.exportEcdsaKeyWithAuthorization({
        walletSession,
        challengeId: args.authorization.challengeId,
        otpCode: args.authorization.otpCode,
        committedLane: args.material.authorization.committedLane,
      });
    case 'durable_authority_backed':
      return await args.deps.emailOtp.exportEcdsaKeyWithDurableAuthorization({
        walletSession,
        chainTarget: args.material.chainTarget,
        challengeId: args.authorization.challengeId,
        otpCode: args.authorization.otpCode,
        publicFacts: args.material.publicFacts,
        runtimePolicyScope: args.material.runtimePolicyScope,
        signingSessionAuthority: args.material.authorization.signingSessionAuthority,
      });
    case 'public_reauth_authority_backed':
      return await args.deps.emailOtp.exportEcdsaKeyWithPublicReauthAuthorization({
        walletSession,
        chainTarget: args.material.chainTarget,
        challengeId: args.authorization.challengeId,
        otpCode: args.authorization.otpCode,
        publicReauthAuthority: args.material.authorization.publicReauthAuthority,
      });
  }
}

export async function exportThresholdEcdsaKeyWithFreshEmailOtpRouteAuth(
  deps: EcdsaExportFlowDeps,
  args: {
    walletId: string;
    exportLane: ExactEcdsaExportLane;
    material: FreshEmailOtpEcdsaExportMaterial;
    options: EcdsaExportOptions;
    flowId: string;
    onEvent?: KeyExportEventCallback;
  },
): Promise<{ accountId: string; exportedSchemes: ExportedKeySchemes }> {
  const exportChain = ecdsaExportBoundaryChain(args.exportLane);
  const challengeAuthority = emailOtpEcdsaExportChallengeAuthority(args.material);
  const authorization = await requestEmailOtpKeyExportAuthorization(
    {
      touchConfirm: deps.touchConfirm,
      requestExportChallenge: deps.emailOtp.requestExportChallenge,
      requestPublicReauthExportChallenge: deps.emailOtp.requestPublicReauthExportChallenge,
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
      challengeAuthority,
    },
  );
  return await prepareAndShowEcdsaExportArtifact(deps, {
    walletId: args.walletId,
    exportLane: args.exportLane,
    exportPublicKey: String(args.material.publicFacts.publicKeyB64u),
    options: args.options,
    flowId: args.flowId,
    onEvent: args.onEvent,
    prepareArtifact: prepareFreshEmailOtpEcdsaExportArtifact.bind(undefined, {
      deps,
      walletId: args.walletId,
      material: args.material,
      authorization,
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
    exportLane: args.exportLane,
    exportPublicKey,
    options: args.options,
    flowId: args.flowId,
    onEvent: args.onEvent,
    prepareArtifact: async () =>
      await exportEcdsaDerivationKeyWithExplicitExportSession(
        { getSignerWorkerContext: deps.getSignerWorkerContext },
        {
          walletSessionUserId: args.walletId,
          exportProvision: prepared.exportProvision,
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
        requestPublicReauthExportChallenge: deps.emailOtp.requestPublicReauthExportChallenge,
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
      await exportEcdsaDerivationKeyWithWalletSession(
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
