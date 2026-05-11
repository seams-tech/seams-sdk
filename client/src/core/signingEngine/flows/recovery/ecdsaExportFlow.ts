import type { AccountId } from '@/core/types/accountIds';
import { KeyExportEventPhase } from '@/core/types/sdkSentEvents';
import type { ThemeName, WalletAuthCurve } from '@/core/types/seams';
import {
  SENSITIVE_OPERATION_POLICIES,
  SIGNER_AUTH_METHODS,
} from '@shared/utils/signerDomain';
import { requireThresholdSessionAuthToken } from '@shared/utils/sessionTokens';
import type { EmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import type { WarmSessionPostSignPolicyAdapterDeps } from '../../session/operationState/warmSessionPolicyAdapter';
import { assertWarmSessionEcdsaOperationAllowed } from '../../session/operationState/warmSessionPolicyAdapter';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  assertEcdsaExportKeyRefMatchesLane,
  ecdsaExportBoundaryChain,
  resolveEcdsaExportRecordForLane,
  type EcdsaExportSessionStoreDeps,
  type ExactEcdsaExportLane,
  type FreshEmailOtpEcdsaExportMaterial,
} from './ecdsaExportMaterial';
import { exportEcdsaHssKeyWithThresholdSession } from './ecdsaHssExport';
import {
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
    requestExportChallenge: Parameters<typeof requestEmailOtpKeyExportAuthorization>[0]['requestExportChallenge'];
    exportEcdsaKeyWithFreshEmailOtpLane: (args: {
      nearAccountId: AccountId;
      subjectId: ExactEcdsaExportLane['subjectId'];
      chainTarget: ExactEcdsaExportLane['chainTarget'];
      challengeId: string;
      otpCode: string;
      ecdsaThresholdKeyId: string;
      participantIds: number[];
      authSubjectId?: string;
      runtimePolicyScope?: FreshEmailOtpEcdsaExportMaterial['runtimePolicyScope'];
    }) => Promise<EcdsaExportArtifact>;
    exportEcdsaKeyWithAuthorization: (args: {
      nearAccountId: AccountId;
      challengeId: string;
      otpCode: string;
      record: ThresholdEcdsaSessionRecord;
      rpId: string;
      authLane: EmailOtpAuthLane;
    }) => Promise<EcdsaExportArtifact>;
  };
  warmSessionPolicy: Pick<
    WarmSessionPostSignPolicyAdapterDeps,
    'getWarmSession' | 'resolveCurrentEcdsaRecord'
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
    nearAccountId: AccountId;
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
      nearAccountId: args.nearAccountId,
      chainTarget: args.exportLane.chainTarget,
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
    nearAccountId: AccountId;
    exportLane: ExactEcdsaExportLane;
    material: FreshEmailOtpEcdsaExportMaterial;
    options: EcdsaExportOptions;
    flowId: string;
    onEvent?: KeyExportEventCallback;
  },
): Promise<{ accountId: string; exportedSchemes: ExportedKeySchemes }> {
  if (args.exportLane.authMethod !== 'email_otp' || args.material.kind !== 'fresh_email_otp') {
    throw new Error('[SigningEngine][ecdsa-export] fresh export requires Email OTP lane');
  }
  const exportChain = ecdsaExportBoundaryChain(args.exportLane);
  const authorization = await requestEmailOtpKeyExportAuthorization(
    {
      touchConfirm: deps.touchConfirm,
      requestExportChallenge: deps.emailOtp.requestExportChallenge,
    },
    {
      nearAccountId: args.nearAccountId,
      chain: exportChain,
      publicKey: args.material.publicKey,
      curve: 'ecdsa' satisfies WalletAuthCurve,
    },
  );
  emitEcdsaMaterialStarted({
    flowId: args.flowId,
    nearAccountId: args.nearAccountId,
    chain: exportChain,
    onEvent: args.onEvent,
  });
  const artifact = await deps.emailOtp.exportEcdsaKeyWithFreshEmailOtpLane({
    nearAccountId: args.nearAccountId,
    subjectId: args.exportLane.subjectId,
    chainTarget: args.material.chainTarget,
    challengeId: authorization.challengeId,
    otpCode: authorization.otpCode,
    ecdsaThresholdKeyId: args.material.ecdsaThresholdKeyId,
    participantIds: args.material.participantIds,
    ...(args.material.authSubjectId ? { authSubjectId: args.material.authSubjectId } : {}),
    ...(args.material.runtimePolicyScope ? { runtimePolicyScope: args.material.runtimePolicyScope } : {}),
  });
  emitEcdsaMaterialSucceeded({
    flowId: args.flowId,
    nearAccountId: args.nearAccountId,
    chain: exportChain,
    onEvent: args.onEvent,
  });
  await showEcdsaExportArtifact(deps, {
    nearAccountId: args.nearAccountId,
    exportLane: args.exportLane,
    artifact,
    options: args.options,
    flowId: args.flowId,
    onEvent: args.onEvent,
  });
  return {
    accountId: String(args.nearAccountId),
    exportedSchemes: ['secp256k1'],
  };
}

export async function exportThresholdEcdsaKeyWithAuthorization(
  deps: EcdsaExportFlowDeps,
  args: {
    nearAccountId: AccountId;
    keyRef: ThresholdEcdsaSecp256k1KeyRef;
    exportLane: ExactEcdsaExportLane;
    options: EcdsaExportOptions;
    flowId: string;
    onEvent?: KeyExportEventCallback;
  },
): Promise<{ accountId: string; exportedSchemes: ExportedKeySchemes }> {
  assertEcdsaExportKeyRefMatchesLane({
    keyRef: args.keyRef,
    exportLane: args.exportLane,
  });
  const exportChain = ecdsaExportBoundaryChain(args.exportLane);
  const currentRecord = resolveEcdsaExportRecordForLane(deps.sessionStore, args.exportLane);
  const exportPublicKey =
    String(args.keyRef.ecdsaHssExportArtifact?.publicKeyHex || '').trim() ||
    String(args.keyRef.ecdsaThresholdKeyId || '').trim() ||
    String(args.keyRef.ethereumAddress || '').trim() ||
    '(threshold export key)';

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
      walletSigningSessionId,
      curve: 'ecdsa' as const,
      chainTarget: args.exportLane.chainTarget,
    };
    const authorization = await requestEmailOtpKeyExportAuthorization(
      {
        touchConfirm: deps.touchConfirm,
        requestExportChallenge: deps.emailOtp.requestExportChallenge,
      },
      {
        nearAccountId: args.nearAccountId,
        chain: exportChain,
        publicKey: exportPublicKey,
        curve: 'ecdsa',
        authLane: exportSigningSessionAuthLane,
      },
    );
    emitEcdsaMaterialStarted({
      flowId: args.flowId,
      nearAccountId: args.nearAccountId,
      chain: exportChain,
      onEvent: args.onEvent,
    });
    const artifact = await deps.emailOtp.exportEcdsaKeyWithAuthorization({
      nearAccountId: args.nearAccountId,
      challengeId: authorization.challengeId,
      otpCode: authorization.otpCode,
      record: currentRecord,
      rpId,
      authLane: exportSigningSessionAuthLane,
    });
    emitEcdsaMaterialSucceeded({
      flowId: args.flowId,
      nearAccountId: args.nearAccountId,
      chain: exportChain,
      onEvent: args.onEvent,
    });
    await showEcdsaExportArtifact(deps, {
      nearAccountId: args.nearAccountId,
      exportLane: args.exportLane,
      artifact,
      options: args.options,
      flowId: args.flowId,
      onEvent: args.onEvent,
    });
    return {
      accountId: String(args.nearAccountId),
      exportedSchemes: ['secp256k1'],
    };
  }

  try {
    await assertWarmSessionEcdsaOperationAllowed(deps.warmSessionPolicy, {
      nearAccountId: args.nearAccountId,
      chainTarget: args.exportLane.chainTarget,
      thresholdSessionId: args.keyRef.thresholdSessionId,
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
      nearAccountId: args.nearAccountId,
      publicKey: exportPublicKey,
      chainTarget: args.exportLane.chainTarget,
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
    nearAccountId: args.nearAccountId,
    chain: exportChain,
    onEvent: args.onEvent,
  });

  const cachedArtifact = args.keyRef.ecdsaHssExportArtifact;
  if (cachedArtifact) {
    emitEcdsaMaterialSucceeded({
      flowId: args.flowId,
      nearAccountId: args.nearAccountId,
      chain: exportChain,
      source: 'cached',
      onEvent: args.onEvent,
    });
    await showEcdsaExportArtifact(deps, {
      nearAccountId: args.nearAccountId,
      exportLane: args.exportLane,
      artifact: cachedArtifact,
      options: args.options,
      flowId: args.flowId,
      onEvent: args.onEvent,
    });
    return {
      accountId: String(args.nearAccountId),
      exportedSchemes: ['secp256k1'],
    };
  }

  const artifact = await exportEcdsaHssKeyWithThresholdSession(
    { getSignerWorkerContext: deps.getSignerWorkerContext },
    {
      nearAccountId: args.nearAccountId,
      subjectId: args.exportLane.subjectId,
      chainTarget: args.exportLane.chainTarget,
      rpId,
      keyRef: args.keyRef,
      clientRootShare32B64u: yClient32LeB64u,
    },
  );
  emitEcdsaMaterialSucceeded({
    flowId: args.flowId,
    nearAccountId: args.nearAccountId,
    chain: exportChain,
    onEvent: args.onEvent,
  });

  await showEcdsaExportArtifact(deps, {
    nearAccountId: args.nearAccountId,
    exportLane: args.exportLane,
    artifact,
    options: args.options,
    flowId: args.flowId,
    onEvent: args.onEvent,
  });
  return {
    accountId: String(args.nearAccountId),
    exportedSchemes: ['secp256k1'],
  };
}
