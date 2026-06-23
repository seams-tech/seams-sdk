import { KeyExportEventPhase } from '@/core/types/sdkSentEvents';
import type { ThemeName, WalletAuthCurve } from '@/core/types/seams';
import {
  toWalletId,
  walletSessionRefFromSession,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { SENSITIVE_OPERATION_POLICIES, SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import {
  toAuthorizingSigningGrantId,
  type EmailOtpAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import type { WarmSessionPostSignPolicyAdapterDeps } from '../../session/operationState/warmSessionPolicyAdapter';
import { assertWarmSessionEcdsaOperationAllowed } from '../../session/operationState/warmSessionPolicyAdapter';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  ecdsaExportBoundaryChain,
  type EcdsaExportSessionStoreDeps,
  type ExactEcdsaExportLane,
  type FreshEmailOtpEcdsaExportMaterial,
  type FreshEmailOtpEcdsaExportMaterialNeedsChallenge,
  type FreshEmailOtpEcdsaExportMaterialRouteAuthReady,
  type ReadyEcdsaExportMaterial,
} from './ecdsaExportMaterial';
import { exportEcdsaHssKeyWithWalletSession } from './ecdsaHssExport';
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
  theme?: ThemeName;
  getRpId: () => string | null;
  emailOtp: {
    requestExportChallenge: EmailOtpWalletSessionExportAuthorizationDeps['requestExportChallenge'];
    exportEcdsaKeyWithFreshEmailOtpLane: (args: {
      walletSession: ReturnType<typeof walletSessionRefFromSession>;
      chainTarget: ThresholdEcdsaChainTarget;
      challengeId: string;
      otpCode: string;
      publicFacts: FreshEmailOtpEcdsaExportMaterial['publicFacts'];
      authSubjectId?: string;
      runtimePolicyScope: FreshEmailOtpEcdsaExportMaterial['runtimePolicyScope'];
    }) => Promise<EcdsaExportArtifact>;
    exportEcdsaKeyWithAuthorization: (args: {
      walletSession: ReturnType<typeof walletSessionRefFromSession>;
      challengeId: string;
      otpCode: string;
      record: ThresholdEcdsaSessionRecord;
      rpId: string;
      authLane: EmailOtpAuthLane;
    }) => Promise<EcdsaExportArtifact>;
  };
  warmSessionPolicy: Pick<
    WarmSessionPostSignPolicyAdapterDeps,
    'getWarmSession' | 'resolveExactEcdsaRecord'
  >;
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
      if (args.material.authSubjectMode === 'explicit_auth_subject') {
        return await deps.emailOtp.exportEcdsaKeyWithFreshEmailOtpLane({
          walletSession,
          chainTarget: args.material.chainTarget,
          challengeId: authorization.challengeId,
          otpCode: authorization.otpCode,
          publicFacts: args.material.publicFacts,
          authSubjectId: args.material.authSubjectId,
          runtimePolicyScope: args.material.runtimePolicyScope,
        });
      }
      return await deps.emailOtp.exportEcdsaKeyWithFreshEmailOtpLane({
        walletSession,
        chainTarget: args.material.chainTarget,
        challengeId: authorization.challengeId,
        otpCode: authorization.otpCode,
        publicFacts: args.material.publicFacts,
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
      authLane: args.material.authLane,
    },
  );
  const rpId = String(deps.getRpId() || '').trim();
  if (!rpId) {
    throw new Error('Missing rpId for threshold-ecdsa Email OTP export');
  }
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
        record: args.material.record,
        rpId,
        authLane: args.material.authLane,
      }),
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
  const currentRecord = args.material.record;
  const exportPublicKey =
    String(args.material.cachedExportArtifact?.publicKeyHex || '').trim() ||
    String(args.material.publicFacts.publicKeyB64u);
  const cachedArtifact = args.material.cachedExportArtifact;

  if (currentRecord.source === SIGNER_AUTH_METHODS.emailOtp) {
    const rpId = String(deps.getRpId() || '').trim();
    if (!rpId) {
      throw new Error('Missing rpId for threshold-ecdsa Email OTP export');
    }
    const signingGrantId = String(currentRecord.signingGrantId || '').trim();
    if (!signingGrantId) {
      throw new Error('Email OTP ECDSA export requires signing grant identity');
    }
    const exportSigningSessionAuthLane = {
      kind: 'signing_session' as const,
      jwt: args.material.signerSession.routerAbEcdsaHssNormalSigning.credential.walletSessionJwt,
      thresholdSessionId: currentRecord.thresholdSessionId,
      authorizingSigningGrantId:
        toAuthorizingSigningGrantId(signingGrantId),
      curve: 'ecdsa' as const,
      chainTarget: args.exportLane.session.chainTarget,
    };
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
        authLane: exportSigningSessionAuthLane,
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
          record: currentRecord,
          rpId,
          authLane: exportSigningSessionAuthLane,
        }),
    });
  }

  try {
    await assertWarmSessionEcdsaOperationAllowed(deps.warmSessionPolicy, {
      walletId: toWalletId(args.walletId),
      chainTarget: args.exportLane.session.chainTarget,
      thresholdSessionId: args.material.signerSession.session.thresholdSessionId,
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
  const rpId = String(deps.getRpId() || '').trim();
  if (!rpId) {
    throw new Error('Missing rpId for threshold-ecdsa explicit export');
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
          rpId,
          signerSession: args.material.signerSession,
          record: args.material.record,
          credential: exportCredential.credential,
        },
      ),
  });
}
