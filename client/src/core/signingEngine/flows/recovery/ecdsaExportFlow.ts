import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { KeyExportEventPhase } from '@/core/types/sdkSentEvents';
import type { ThemeName, WalletAuthCurve } from '@/core/types/seams';
import {
  toWalletId,
  walletSessionRefFromSession,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  SENSITIVE_OPERATION_POLICIES,
  SIGNER_AUTH_METHODS,
} from '@shared/utils/signerDomain';
import { requireThresholdSessionAuthToken } from '@shared/utils/sessionTokens';
import {
  toAuthorizingWalletSigningSessionId,
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
  type ReadyEcdsaExportMaterial,
} from './ecdsaExportMaterial';
import { exportEcdsaHssKeyWithThresholdSession } from './ecdsaHssExport';
import {
  type EmailOtpWalletSessionExportAuthorizationDeps,
  createEmailOtpKeyExportRequiresPasskeyError,
  isEmailOtpPasskeyStepUpError,
  requestEmailOtpKeyExportAuthorization,
  requestThresholdEcdsaExportAuthorization,
  showThresholdEcdsaExportViewer,
} from './keyExportConfirmation';
import {
  emitKeyExportEvent,
  requirePrfFirstForPrivateKeyExport,
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
      runtimePolicyScope?: FreshEmailOtpEcdsaExportMaterial['runtimePolicyScope'];
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
  nearAccountId: AccountId;
  chain: 'evm' | 'tempo';
  onEvent?: KeyExportEventCallback;
}): void {
  emitKeyExportEvent(args.onEvent, {
    phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_STARTED,
    status: 'running',
    flowId: args.flowId,
    accountId: String(args.nearAccountId),
    interaction: { kind: 'none', overlay: 'none' },
    data: { chain: args.chain, curve: 'ecdsa' },
  });
}

function emitEcdsaMaterialSucceeded(args: {
  flowId: string;
  nearAccountId: AccountId;
  chain: 'evm' | 'tempo';
  source?: 'cached';
  onEvent?: KeyExportEventCallback;
}): void {
  emitKeyExportEvent(args.onEvent, {
    phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_SUCCEEDED,
    status: 'succeeded',
    flowId: args.flowId,
    accountId: String(args.nearAccountId),
    interaction: { kind: 'none', overlay: 'none' },
    data: { chain: args.chain, curve: 'ecdsa', ...(args.source ? { source: args.source } : {}) },
  });
}

async function showEcdsaExportArtifact(
  deps: Pick<EcdsaExportFlowDeps, 'touchConfirm' | 'theme'>,
  args: {
    walletSessionUserId: string;
    exportLane: ExactEcdsaExportLane;
    artifact: EcdsaExportArtifact;
    options: EcdsaExportOptions;
    flowId: string;
    onEvent?: KeyExportEventCallback;
  },
): Promise<void> {
  await showThresholdEcdsaExportViewer(
    { touchConfirm: deps.touchConfirm, theme: deps.theme },
    {
      nearAccountId: toAccountId(args.walletSessionUserId),
      chainTarget: args.exportLane.session.chainTarget,
      publicKeyHex: String(args.artifact.publicKeyHex || '').trim(),
      privateKeyHex: String(args.artifact.privateKeyHex || '').trim(),
      ethereumAddress: String(args.artifact.ethereumAddress || '').trim(),
      variant: args.options.variant,
      theme: args.options.theme,
      flowId: args.flowId,
      onEvent: args.onEvent,
    },
  );
}

export async function exportThresholdEcdsaKeyWithFreshEmailOtpAuthorization(
  deps: EcdsaExportFlowDeps,
  args: {
    walletSessionUserId: string;
    exportLane: ExactEcdsaExportLane;
    material: FreshEmailOtpEcdsaExportMaterial;
    options: EcdsaExportOptions;
    flowId: string;
    onEvent?: KeyExportEventCallback;
  },
): Promise<{ accountId: string; exportedSchemes: ExportedKeySchemes }> {
  if (args.exportLane.session.authMethod !== 'email_otp' || args.material.kind !== 'fresh_email_otp') {
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
        walletId: args.walletSessionUserId,
        walletSessionUserId: args.walletSessionUserId,
      }),
      chain: exportChain,
      publicKey: String(args.material.publicFacts.publicKeyB64u),
      curve: 'ecdsa' satisfies WalletAuthCurve,
    },
  );
  emitEcdsaMaterialStarted({
    flowId: args.flowId,
    nearAccountId: args.walletSessionUserId,
    chain: exportChain,
    onEvent: args.onEvent,
  });
  const artifact = await deps.emailOtp.exportEcdsaKeyWithFreshEmailOtpLane({
    walletSession: walletSessionRefFromSession({
      walletId: args.walletSessionUserId,
      walletSessionUserId: args.walletSessionUserId,
    }),
    chainTarget: args.material.chainTarget,
    challengeId: authorization.challengeId,
    otpCode: authorization.otpCode,
    publicFacts: args.material.publicFacts,
    ...(args.material.authSubjectId ? { authSubjectId: args.material.authSubjectId } : {}),
    ...(args.material.runtimePolicyScope ? { runtimePolicyScope: args.material.runtimePolicyScope } : {}),
  });
  emitEcdsaMaterialSucceeded({
    flowId: args.flowId,
    nearAccountId: args.walletSessionUserId,
    chain: exportChain,
    onEvent: args.onEvent,
  });
  await showEcdsaExportArtifact(deps, {
    walletSessionUserId: args.walletSessionUserId,
    exportLane: args.exportLane,
    artifact,
    options: args.options,
    flowId: args.flowId,
    onEvent: args.onEvent,
  });
  return {
    accountId: String(args.walletSessionUserId),
    exportedSchemes: ['secp256k1'],
  };
}

export async function exportThresholdEcdsaKeyWithAuthorization(
  deps: EcdsaExportFlowDeps,
  args: {
    walletSessionUserId: string;
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

  if (currentRecord.source === SIGNER_AUTH_METHODS.emailOtp) {
    const rpId = String(deps.getRpId() || '').trim();
    if (!rpId) {
      throw new Error('Missing rpId for threshold-ecdsa Email OTP export');
    }
    const walletSigningSessionId = String(currentRecord.walletSigningSessionId || '').trim();
    if (!walletSigningSessionId) {
      throw new Error('Email OTP ECDSA export requires wallet signing-session identity');
    }
    const exportSigningSessionAuthLane = {
      kind: 'signing_session' as const,
      jwt: requireThresholdSessionAuthToken(
        String(currentRecord.thresholdSessionAuthToken || '').trim(),
        'exportThresholdSessionAuthToken',
      ),
      thresholdSessionId: currentRecord.thresholdSessionId,
      authorizingWalletSigningSessionId: toAuthorizingWalletSigningSessionId(
        walletSigningSessionId,
      ),
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
          walletId: args.walletSessionUserId,
          walletSessionUserId: args.walletSessionUserId,
        }),
        chain: exportChain,
        publicKey: exportPublicKey,
        curve: 'ecdsa',
        authLane: exportSigningSessionAuthLane,
      },
    );
    emitEcdsaMaterialStarted({
      flowId: args.flowId,
      nearAccountId: args.walletSessionUserId,
      chain: exportChain,
      onEvent: args.onEvent,
    });
    const artifact = await deps.emailOtp.exportEcdsaKeyWithAuthorization({
      walletSession: walletSessionRefFromSession({
        walletId: args.walletSessionUserId,
        walletSessionUserId: args.walletSessionUserId,
      }),
      challengeId: authorization.challengeId,
      otpCode: authorization.otpCode,
      record: currentRecord,
      rpId,
      authLane: exportSigningSessionAuthLane,
    });
    emitEcdsaMaterialSucceeded({
      flowId: args.flowId,
      nearAccountId: args.walletSessionUserId,
      chain: exportChain,
      onEvent: args.onEvent,
    });
    await showEcdsaExportArtifact(deps, {
      walletSessionUserId: args.walletSessionUserId,
      exportLane: args.exportLane,
      artifact,
      options: args.options,
      flowId: args.flowId,
      onEvent: args.onEvent,
    });
    return {
      accountId: String(args.walletSessionUserId),
      exportedSchemes: ['secp256k1'],
    };
  }

  try {
    await assertWarmSessionEcdsaOperationAllowed(deps.warmSessionPolicy, {
      walletId: toWalletId(args.walletSessionUserId),
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
  const rpId = String(deps.getRpId() || '').trim();
  if (!rpId) {
    throw new Error('Missing rpId for threshold-ecdsa explicit export');
  }
  const exportCredential = await requestThresholdEcdsaExportAuthorization(
    { touchConfirm: deps.touchConfirm, theme: deps.theme },
    {
      walletSessionUserId: args.walletSessionUserId,
      publicKey: exportPublicKey,
      chainTarget: args.exportLane.session.chainTarget,
      flowId: args.flowId,
      onEvent: args.onEvent,
    },
  );
  const yClient32LeB64u = requirePrfFirstForPrivateKeyExport({
    credential: exportCredential.credential,
    errorContext: 'threshold-ecdsa explicit export',
  });

  emitEcdsaMaterialStarted({
    flowId: args.flowId,
    nearAccountId: args.walletSessionUserId,
    chain: exportChain,
    onEvent: args.onEvent,
  });

  const cachedArtifact = args.material.cachedExportArtifact;
  if (cachedArtifact) {
    emitEcdsaMaterialSucceeded({
      flowId: args.flowId,
      nearAccountId: args.walletSessionUserId,
      chain: exportChain,
      source: 'cached',
      onEvent: args.onEvent,
    });
    await showEcdsaExportArtifact(deps, {
      walletSessionUserId: args.walletSessionUserId,
      exportLane: args.exportLane,
      artifact: cachedArtifact,
      options: args.options,
      flowId: args.flowId,
      onEvent: args.onEvent,
    });
    return {
      accountId: String(args.walletSessionUserId),
      exportedSchemes: ['secp256k1'],
    };
  }

  const artifact = await exportEcdsaHssKeyWithThresholdSession(
    { getSignerWorkerContext: deps.getSignerWorkerContext },
    {
      walletSessionUserId: args.walletSessionUserId,
      chainTarget: args.exportLane.session.chainTarget,
      rpId,
      signerSession: args.material.signerSession,
      clientRootShare32B64u: yClient32LeB64u,
    },
  );
  emitEcdsaMaterialSucceeded({
    flowId: args.flowId,
    nearAccountId: args.walletSessionUserId,
    chain: exportChain,
    onEvent: args.onEvent,
  });

  await showEcdsaExportArtifact(deps, {
    walletSessionUserId: args.walletSessionUserId,
    exportLane: args.exportLane,
    artifact,
    options: args.options,
    flowId: args.flowId,
    onEvent: args.onEvent,
  });
  return {
    accountId: String(args.walletSessionUserId),
    exportedSchemes: ['secp256k1'],
  };
}
