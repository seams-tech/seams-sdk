import { KeyExportEventPhase } from '@/core/types/sdkSentEvents';
import type { ThemeMode, WalletAuthCurve } from '@/core/types/seams';
import type { VerifiedEcdsaPublicFacts } from '../../session/identity/evmFamilyEcdsaIdentity';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
  walletSessionRefFromSession,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EcdsaExplicitExportSessionAuth } from '../../threshold/ecdsa/activation';
import type { EcdsaExplicitExportOperationAuthorization } from '../../threshold/ecdsa/activation';
import type { EmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type { UiConfirmRuntimeBridgePort } from '../../uiConfirm/uiConfirm.types';
import {
  ecdsaExportBoundaryChain,
  type EcdsaExportSessionStoreDeps,
  type EmailOtpEcdsaExportAuthLane,
  type ExactEcdsaExportLane,
  type FreshEmailOtpEcdsaExportMaterial,
  type FreshPasskeyEcdsaExportMaterial,
  resolveEcdsaExportMaterialForLane,
} from './ecdsaExportMaterial';
import { exportEcdsaDerivationKeyWithExplicitExportSession } from './ecdsaDerivationExport';
import {
  buildEcdsaExportActivation,
  type ThresholdEcdsaPasskeyExportActivationRequest,
  type ThresholdEcdsaExplicitKeyExportBootstrapResult,
} from '../../session/passkey/ecdsaSessionProvision';
import { deriveEvmFamilySigningKeySlotId } from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  type EmailOtpEcdsaExportAuthorizationDeps,
  type EmailOtpWalletSessionExportAuthorizationDeps,
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
import { resolveActiveEcdsaCapabilityRuntime } from '../../session/material/activeEcdsaCapabilityRuntime';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import { resolveThresholdEcdsaSigningQueueKey } from '../../threshold/ecdsa/signingQueue';
import {
  issueEcdsaOperationStepUpGrant,
  prepareEcdsaOperationStepUp,
  type EcdsaOperationStepUpSessionAuth,
  type PreparedEcdsaOperationStepUp,
} from '../../threshold/ecdsa/operationStepUp';
import { parseAppSessionJwt } from '@shared/utils/domainIds';
import {
  buildPasskeyWalletAuthAuthority,
  isEmailOtpWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
  type EmailOtpWalletAuthAuthority as CanonicalEmailOtpWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { parseCapabilityGrantId } from '@shared/authorization/capabilityKinds';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  buildPersistedEcdsaRoleLocalMaterial,
  type PersistedEcdsaRoleLocalMaterial,
} from '../../session/material/ecdsaRoleLocalMaterialResolver';

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
      publicFacts: VerifiedEcdsaPublicFacts;
      runtimePolicyScope: ThresholdRuntimePolicyScope;
      signingSessionAuthority: Extract<
        FreshEmailOtpEcdsaExportMaterial['authorization'],
        { kind: 'wallet_session_authorized' }
      >['signingSessionAuthority'];
      persistedMaterial: PersistedEcdsaRoleLocalMaterial;
      explicitExportAuthorization: EcdsaExplicitExportOperationAuthorization;
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
      persistedMaterial: PersistedEcdsaRoleLocalMaterial;
      explicitExportAuthorization: EcdsaExplicitExportOperationAuthorization;
    }) => Promise<EcdsaExportArtifact>;
  };
  provisionPasskeyEcdsaExplicitExportSession: (
    args: ThresholdEcdsaPasskeyExportActivationRequest,
  ) => Promise<ThresholdEcdsaExplicitKeyExportBootstrapResult>;
  resolvePasskeyEcdsaExportRouteAuth: (
    walletId: string,
    chainTarget: ThresholdEcdsaChainTarget,
    authMethod: 'passkey' | 'email_otp',
  ) => Promise<EcdsaExplicitExportSessionAuth>;
  getSignerWorkerContext: () => WorkerOperationContext;
  withThresholdEcdsaSigningQueue: <T>(args: {
    queueKey: string;
    walletId: WalletId;
    enabled: boolean;
    task: () => Promise<T>;
  }) => Promise<T>;
};

type EcdsaExportOptions = {
  variant?: 'drawer' | 'modal';
  theme?: 'dark' | 'light';
};

async function resolvePasskeyEcdsaExportRouteAuth(args: {
  deps: Pick<EcdsaExportFlowDeps, 'resolvePasskeyEcdsaExportRouteAuth'>;
  walletId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  authMethod: 'passkey' | 'email_otp';
}): Promise<EcdsaExplicitExportSessionAuth> {
  return await args.deps.resolvePasskeyEcdsaExportRouteAuth(
    args.walletId,
    args.chainTarget,
    args.authMethod,
  );
}

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
    const materialActivation = args.exportLane.laneIdentity.signer.materialActivation;
    const artifact = await deps.withThresholdEcdsaSigningQueue({
      queueKey: resolveThresholdEcdsaSigningQueueKey({ materialActivation }),
      walletId: args.exportLane.key.walletId,
      enabled: true,
      task: async () => {
        const current = await resolveActiveEcdsaCapabilityRuntime({
          walletId: args.exportLane.key.walletId,
          chainTarget: args.exportLane.session.chainTarget,
        });
        if (current.kind !== 'resolved') {
          throw new Error(
            `[SigningEngine][ecdsa-export] prepared material was superseded: ${current.reason}`,
          );
        }
        if (
          !mpcMaterialActivationRefsEqual(current.runtime.materialActivation, materialActivation)
        ) {
          throw new Error(
            '[SigningEngine][ecdsa-export] prepared material activation was superseded',
          );
        }
        return await args.prepareArtifact();
      },
    });
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

async function exportOperationDigest(value: unknown) {
  return parseDigestB64u(base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(value))));
}

async function prepareExplicitEcdsaExportOperation(args: {
  readonly walletId: string;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly requestId: string;
  readonly persistedMaterial: PersistedEcdsaRoleLocalMaterial;
}): Promise<PreparedEcdsaOperationStepUp> {
  const resolved = await resolveActiveEcdsaCapabilityRuntime({
    walletId: toWalletId(args.walletId),
    chainTarget: args.chainTarget,
  });
  if (resolved.kind !== 'resolved') {
    throw new Error(
      `[SigningEngine][ecdsa-export] canonical runtime unavailable: ${resolved.reason}`,
    );
  }
  if (
    !mpcMaterialActivationRefsEqual(
      resolved.runtime.materialActivation,
      args.persistedMaterial.materialActivation,
    )
  ) {
    throw new Error('[SigningEngine][ecdsa-export] export material activation mismatch');
  }
  const participantIds = resolved.runtime.participantIds;
  const chainTargetKey = thresholdEcdsaChainTargetKey(args.chainTarget);
  return await prepareEcdsaOperationStepUp({
    walletId: args.walletId,
    operationKind: 'evm.export_key',
    operationId: args.requestId,
    operationDigests: {
      laneDigest: await exportOperationDigest({
        walletId: args.walletId,
        chainTarget: chainTargetKey,
        materialActivation: args.persistedMaterial.materialActivation,
        keyHandle: args.persistedMaterial.publicFacts.keyHandle,
      }),
      intentDigest: await exportOperationDigest({
        operation: 'explicit_key_export',
        requestId: args.requestId,
        walletId: args.walletId,
        chainTarget: chainTargetKey,
      }),
      displayDigest: await exportOperationDigest({
        operation: 'Export Private Key',
        publicKey: args.persistedMaterial.publicFacts.groupPublicKey33B64u,
        address: args.persistedMaterial.publicFacts.ethereumAddress,
      }),
    },
    materialActivation: args.persistedMaterial.materialActivation,
    normalSigningScope: resolved.runtime.normalSigning.scope,
    keyHandle: args.persistedMaterial.publicFacts.keyHandle,
    relayerKeyId: resolved.runtime.relayerKeyId,
    participantIds: [Number(participantIds[0]), Number(participantIds[1])],
    expiresAtMs: Date.now() + 5 * 60_000,
  });
}

function operationStepUpSessionAuth(
  sessionAuth: EcdsaExplicitExportSessionAuth,
): EcdsaOperationStepUpSessionAuth {
  switch (sessionAuth.kind) {
    case 'app_session': {
      const parsed = parseAppSessionJwt(sessionAuth.jwt);
      if (!parsed.ok) throw new Error(parsed.error.message);
      return { kind: 'app_session_jwt', appSessionJwt: parsed.value };
    }
    case 'cookie':
      return { kind: 'app_session_cookie' };
  }
}

function passkeyExportProof(args: {
  readonly persistedMaterial: PersistedEcdsaRoleLocalMaterial;
  readonly authBinding: Extract<ExactEcdsaExportLane['laneIdentity']['auth'], { kind: 'passkey' }>;
  readonly credential: Awaited<
    ReturnType<typeof requestThresholdEcdsaExportAuthorization>
  >['credential'];
}) {
  const authority = buildPasskeyWalletAuthAuthority({
    walletId: args.persistedMaterial.publicFacts.walletId,
    rpId: args.authBinding.rpId,
    credentialIdB64u: args.authBinding.credentialIdB64u,
  });
  const credential = args.credential;
  return {
    kind: 'passkey' as const,
    authority,
    webauthn_authentication: {
      id: credential.id,
      rawId: credential.rawId,
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment ?? null,
      response: {
        clientDataJSON: credential.response.clientDataJSON,
        authenticatorData: credential.response.authenticatorData,
        signature: credential.response.signature,
        userHandle: credential.response.userHandle ?? null,
      },
      clientExtensionResults: credential.clientExtensionResults ?? null,
    },
  };
}

function emailOtpExportProof(args: {
  readonly authority: CanonicalEmailOtpWalletAuthAuthority;
  readonly challengeId: string;
  readonly otpCode: string;
}) {
  if (!isEmailOtpWalletAuthAuthority(args.authority)) {
    throw new Error('[SigningEngine][ecdsa-export] Email OTP material authority mismatch');
  }
  return {
    kind: 'email_otp' as const,
    authority: args.authority,
    challenge_id: args.challengeId,
    otp_code: args.otpCode,
  };
}

async function issueExplicitEcdsaExportAuthorization(args: {
  readonly relayerUrl: string;
  readonly sessionAuth: EcdsaExplicitExportSessionAuth;
  readonly prepared: PreparedEcdsaOperationStepUp;
  readonly proof: ReturnType<typeof passkeyExportProof> | ReturnType<typeof emailOtpExportProof>;
}) {
  const grant = await issueEcdsaOperationStepUpGrant({
    relayerUrl: args.relayerUrl,
    sessionAuth: operationStepUpSessionAuth(args.sessionAuth),
    request: {
      kind: 'router_ab_ecdsa_operation_step_up_grant_v1',
      operation: args.prepared.operation,
      proof: args.proof,
    },
  });
  const grantId = parseCapabilityGrantId(grant.authorization.grant_id);
  if (!grantId.ok) throw new Error(grantId.error.message);
  return {
    kind: 'operation_step_up' as const,
    grantId: grantId.value,
    operation: args.prepared.operation,
    sessionAuth: args.sessionAuth,
    expiresAtMs: grant.expires_at_ms,
    quotaUse: 'none' as const,
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
  exportActivation: ThresholdEcdsaPasskeyExportActivationRequest;
  credential: Awaited<ReturnType<typeof requestThresholdEcdsaExportAuthorization>>['credential'];
}> {
  requirePasskeyEcdsaExportAuth(args.exportLane);
  const requestId = createExportUiRequestId('tecdsa-export');
  const prepared = await prepareExplicitEcdsaExportOperation({
    walletId: args.walletId,
    chainTarget: args.exportLane.session.chainTarget,
    requestId,
    persistedMaterial: args.material.existingRoleLocalMaterial,
  });
  const exportCredential = await requestThresholdEcdsaExportAuthorization(
    { touchConfirm: deps.touchConfirm, theme: deps.theme },
    {
      walletSessionUserId: args.walletId,
      publicKey: args.exportPublicKey,
      chainTarget: args.exportLane.session.chainTarget,
      challengeB64u: prepared.challengeB64u,
      flowId: args.flowId,
      onEvent: args.onEvent,
    },
  );
  const sessionAuth = await resolvePasskeyEcdsaExportRouteAuth({
    deps,
    walletId: args.walletId,
    chainTarget: args.exportLane.session.chainTarget,
    authMethod: 'passkey',
  });
  const authorization = await issueExplicitEcdsaExportAuthorization({
    relayerUrl: args.material.relayerUrl,
    sessionAuth,
    prepared,
    proof: passkeyExportProof({
      persistedMaterial: args.material.existingRoleLocalMaterial,
      authBinding: requirePasskeyEcdsaExportAuth(args.exportLane),
      credential: exportCredential.credential,
    }),
  });
  const exportActivation = buildEcdsaExportActivation({
    relayerUrl: args.material.relayerUrl,
    existingRoleLocalMaterial: args.material.existingRoleLocalMaterial,
    authorization,
  });
  return {
    exportActivation,
    credential: exportCredential.credential,
  };
}

function emailOtpEcdsaExportChallengeAuthority(material: FreshEmailOtpEcdsaExportMaterial) {
  switch (material.authorization.kind) {
    case 'wallet_session_authorized':
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
  persistedMaterial: PersistedEcdsaRoleLocalMaterial;
  explicitExportAuthorization: EcdsaExplicitExportOperationAuthorization;
}): Promise<EcdsaExportArtifact> {
  const walletSession = walletSessionRefFromSession({
    walletId: args.walletId,
    walletSessionUserId: args.walletId,
  });
  switch (args.material.authorization.kind) {
    case 'wallet_session_authorized':
      return await args.deps.emailOtp.exportEcdsaKeyWithDurableAuthorization({
        walletSession,
        chainTarget: args.material.chainTarget,
        challengeId: args.authorization.challengeId,
        otpCode: args.authorization.otpCode,
        publicFacts: args.material.publicFacts,
        runtimePolicyScope: args.material.runtimePolicyScope,
        signingSessionAuthority: args.material.authorization.signingSessionAuthority,
        persistedMaterial: args.persistedMaterial,
        explicitExportAuthorization: args.explicitExportAuthorization,
      });
    case 'public_reauth_authority_backed':
      return await args.deps.emailOtp.exportEcdsaKeyWithPublicReauthAuthorization({
        walletSession,
        chainTarget: args.material.chainTarget,
        challengeId: args.authorization.challengeId,
        otpCode: args.authorization.otpCode,
        publicReauthAuthority: args.material.authorization.publicReauthAuthority,
        persistedMaterial: args.persistedMaterial,
        explicitExportAuthorization: args.explicitExportAuthorization,
      });
  }
}

async function resolveEmailOtpExplicitExportMaterial(args: {
  readonly walletId: string;
  readonly chainTarget: ThresholdEcdsaChainTarget;
}): Promise<{
  readonly persistedMaterial: PersistedEcdsaRoleLocalMaterial;
  readonly relayerUrl: string;
  readonly authority: CanonicalEmailOtpWalletAuthAuthority;
}> {
  const resolved = await resolveActiveEcdsaCapabilityRuntime({
    walletId: toWalletId(args.walletId),
    chainTarget: args.chainTarget,
  });
  if (resolved.kind !== 'resolved') {
    throw new Error(
      `[SigningEngine][ecdsa-export] Email OTP canonical runtime unavailable: ${resolved.reason}`,
    );
  }
  if (resolved.runtime.authBinding.kind !== 'email_otp') {
    throw new Error('[SigningEngine][ecdsa-export] Email OTP runtime authority mismatch');
  }
  return {
    persistedMaterial: buildPersistedEcdsaRoleLocalMaterial({
      authority: await walletAuthAuthorityRef({
        authority: resolved.runtime.authBinding.emailOtpAuthority,
      }),
      materialActivation: resolved.runtime.materialActivation,
      publicFacts: resolved.manifest.durableMaterial.roleLocalPublicFacts,
    }),
    relayerUrl: resolved.runtime.relayerUrl,
    authority: resolved.runtime.authBinding.emailOtpAuthority,
  };
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
  const exactMaterial = await resolveEmailOtpExplicitExportMaterial({
    walletId: args.walletId,
    chainTarget: args.exportLane.session.chainTarget,
  });
  const prepared = await prepareExplicitEcdsaExportOperation({
    walletId: args.walletId,
    chainTarget: args.exportLane.session.chainTarget,
    requestId: createExportUiRequestId('tecdsa-email-otp-export'),
    persistedMaterial: exactMaterial.persistedMaterial,
  });
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
      flowId: args.flowId,
      onEvent: args.onEvent,
    },
  );
  const sessionAuth = await resolvePasskeyEcdsaExportRouteAuth({
    deps,
    walletId: args.walletId,
    chainTarget: args.exportLane.session.chainTarget,
    authMethod: 'email_otp',
  });
  const explicitExportAuthorization = await issueExplicitEcdsaExportAuthorization({
    relayerUrl: exactMaterial.relayerUrl,
    sessionAuth,
    prepared,
    proof: emailOtpExportProof({
      authority: exactMaterial.authority,
      challengeId: authorization.challengeId,
      otpCode: authorization.otpCode,
    }),
  });
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
      persistedMaterial: exactMaterial.persistedMaterial,
      explicitExportAuthorization,
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
    prepareArtifact: async () => {
      const exportProvision = await deps.provisionPasskeyEcdsaExplicitExportSession(
        prepared.exportActivation,
      );
      return await exportEcdsaDerivationKeyWithExplicitExportSession(
        { getSignerWorkerContext: deps.getSignerWorkerContext },
        {
          walletSessionUserId: args.walletId,
          exportProvision,
          credential: prepared.credential,
        },
      );
    },
  });
}
