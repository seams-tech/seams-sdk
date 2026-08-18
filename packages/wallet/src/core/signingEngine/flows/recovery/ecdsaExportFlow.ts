import { KeyExportEventPhase } from '@/core/types/sdkSentEvents';
import type { ThemeMode, WalletAuthCurve } from '@/core/types/seams';
import type { VerifiedEcdsaPublicFacts } from '../../session/identity/evmFamilyEcdsaIdentity';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import {
  thresholdEcdsaChainTargetKey,
  walletSessionRefFromSession,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
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
  resolveFreshEmailOtpEcdsaExportMaterialForLane,
} from './ecdsaExportMaterial';
import { exportEcdsaDerivationKey } from './ecdsaDerivationExport';
import {
  buildEcdsaExportActivation,
  type ThresholdEcdsaPasskeyExportActivationRequest,
  type ThresholdEcdsaExplicitKeyExportBootstrapResult,
} from '../../session/passkey/ecdsaSessionProvision';
import { deriveEvmFamilySigningKeySlotId } from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  type EmailOtpExportAuthorizationDeps,
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
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import { resolveThresholdEcdsaSigningQueueKey } from '../../threshold/ecdsa/signingQueue';
import {
  issueEcdsaOperationStepUpAuthorization,
  prepareEcdsaOperationStepUp,
  type PreparedEcdsaOperationStepUp,
} from '../../threshold/ecdsa/operationStepUp';
import {
  buildPasskeyWalletAuthAuthority,
  isEmailOtpWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
  type EmailOtpWalletAuthAuthority as CanonicalEmailOtpWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { PersistedEcdsaRoleLocalMaterial } from '../../session/material/ecdsaRoleLocalMaterialResolver';
import type { RouterAbEcdsaOperationStepUpAuthorizationV1Wire } from '@shared/utils/routerAbEcdsaDerivation';

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
    requestExportChallenge: EmailOtpExportAuthorizationDeps['requestExportChallenge'];
    exportEcdsaKeyWithDurableAuthorization: (args: {
      walletSession: ReturnType<typeof walletSessionRefFromSession>;
      chainTarget: ThresholdEcdsaChainTarget;
      challengeId: string;
      otpCode: string;
      publicFacts: VerifiedEcdsaPublicFacts;
      runtimePolicyScope: ThresholdRuntimePolicyScope;
      authority: Extract<
        FreshEmailOtpEcdsaExportMaterial['authorization'],
        { kind: 'fresh_operation_authorization_required' }
      >['authority'];
      persistedMaterial: PersistedEcdsaRoleLocalMaterial;
      explicitExportAuthorization: EcdsaExplicitExportOperationAuthorization;
    }) => Promise<EcdsaExportArtifact>;
  };
  provisionPasskeyEcdsaExplicitExportSession: (
    args: ThresholdEcdsaPasskeyExportActivationRequest,
  ) => Promise<ThresholdEcdsaExplicitKeyExportBootstrapResult>;
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
      chainTarget: args.exportLane.chainTarget,
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
      chainTarget: args.exportLane.chainTarget,
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
        if (args.exportLane.authMethod === 'email_otp') {
          const current = await resolveFreshEmailOtpEcdsaExportMaterialForLane(
            deps.sessionStore,
            args.exportLane,
          );
          if (
            !mpcMaterialActivationRefsEqual(
              current.persistedMaterial.materialActivation,
              materialActivation,
            )
          ) {
            throw new Error(
              '[SigningEngine][ecdsa-export] prepared material activation was superseded',
            );
          }
        } else {
          const current = await resolveEcdsaExportMaterialForLane(
            deps.sessionStore,
            args.exportLane,
          );
          if (current.kind !== 'fresh_passkey_needs_authorization') {
            throw new Error('[SigningEngine][ecdsa-export] prepared export authority changed');
          }
          if (
            !mpcMaterialActivationRefsEqual(
              current.existingRoleLocalMaterial.materialActivation,
              materialActivation,
            )
          ) {
            throw new Error(
              '[SigningEngine][ecdsa-export] prepared material activation was superseded',
            );
          }
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

type EcdsaExportOperationRuntime = Pick<
  FreshEmailOtpEcdsaExportMaterial,
  'normalSigning' | 'relayerKeyId' | 'participantIds'
>;

async function prepareExplicitEcdsaExportOperationWithRuntime(args: {
  readonly walletId: string;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly requestId: string;
  readonly persistedMaterial: PersistedEcdsaRoleLocalMaterial;
  readonly operationRuntime: EcdsaExportOperationRuntime;
}): Promise<PreparedEcdsaOperationStepUp> {
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
    normalSigningScope: args.operationRuntime.normalSigning.scope,
    keyHandle: args.persistedMaterial.publicFacts.keyHandle,
    relayerKeyId: args.operationRuntime.relayerKeyId,
    participantIds: [
      Number(args.operationRuntime.participantIds[0]),
      Number(args.operationRuntime.participantIds[1]),
    ],
    expiresAtMs: Date.now() + 5 * 60_000,
  });
}

async function prepareExplicitEcdsaExportOperation(args: {
  readonly walletId: string;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly requestId: string;
  readonly persistedMaterial: PersistedEcdsaRoleLocalMaterial;
  readonly operationRuntime: EcdsaExportOperationRuntime;
}): Promise<PreparedEcdsaOperationStepUp> {
  return await prepareExplicitEcdsaExportOperationWithRuntime({
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    requestId: args.requestId,
    persistedMaterial: args.persistedMaterial,
    operationRuntime: args.operationRuntime,
  });
}

async function assertEcdsaExportMaterialStillActive(args: {
  readonly deps: EcdsaExportFlowDeps;
  readonly exportLane: ExactEcdsaExportLane;
  readonly expectedMaterialActivation: PersistedEcdsaRoleLocalMaterial['materialActivation'];
}): Promise<void> {
  const current = await resolveEcdsaExportMaterialForLane(args.deps.sessionStore, args.exportLane);
  if (current.kind !== 'fresh_passkey_needs_authorization') {
    throw new Error('[SigningEngine][ecdsa-export] passkey export authority changed');
  }
  if (
    !mpcMaterialActivationRefsEqual(
      current.existingRoleLocalMaterial.materialActivation,
      args.expectedMaterialActivation,
    )
  ) {
    throw new Error(
      '[SigningEngine][ecdsa-export] active material changed after authorization confirmation',
    );
  }
}

async function assertEmailOtpEcdsaExportMaterialStillActive(args: {
  readonly deps: EcdsaExportFlowDeps;
  readonly exportLane: ExactEcdsaExportLane;
  readonly expectedMaterialActivation: PersistedEcdsaRoleLocalMaterial['materialActivation'];
}): Promise<void> {
  const resolved = await resolveFreshEmailOtpEcdsaExportMaterialForLane(
    args.deps.sessionStore,
    args.exportLane,
  );
  if (
    !mpcMaterialActivationRefsEqual(
      resolved.persistedMaterial.materialActivation,
      args.expectedMaterialActivation,
    )
  ) {
    throw new Error(
      '[SigningEngine][ecdsa-export] active material changed after authorization confirmation',
    );
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
  readonly prepared: PreparedEcdsaOperationStepUp;
  readonly proof: ReturnType<typeof passkeyExportProof> | ReturnType<typeof emailOtpExportProof>;
}) {
  const authorization = await issueEcdsaOperationStepUpAuthorization({
    relayerUrl: args.relayerUrl,
    request: {
      kind: 'router_ab_ecdsa_operation_step_up_v1',
      operation: args.prepared.operation,
      proof: args.proof,
    },
  });
  const evidenceSetDigest = authorization.authorization.evidence_set_digest;
  const unseal = normalizeIssuedEcdsaExportUnseal({
    proofKind: args.proof.kind,
    unseal: authorization.authorization.unseal,
  });
  return {
    kind: 'verified_step_up' as const,
    evidenceSetDigest,
    operation: args.prepared.operation,
    expiresAtMs: authorization.expires_at_ms,
    quotaUse: 'none' as const,
    unseal,
  };
}

function normalizeIssuedEcdsaExportUnseal(args: {
  proofKind: 'passkey' | 'email_otp';
  unseal: RouterAbEcdsaOperationStepUpAuthorizationV1Wire['unseal'];
}): RouterAbEcdsaOperationStepUpAuthorizationV1Wire['unseal'] {
  switch (args.proofKind) {
    case 'passkey':
      if (args.unseal.kind !== 'not_requested') {
        throw new Error(
          '[SigningEngine][ecdsa-export] passkey step-up returned Email OTP unseal material',
        );
      }
      return { kind: 'not_requested' };
    case 'email_otp':
      if (args.unseal.kind !== 'email_otp_grant') {
        throw new Error(
          '[SigningEngine][ecdsa-export] Email OTP step-up did not return an unseal grant',
        );
      }
      return {
        kind: 'email_otp_grant',
        grant: args.unseal.grant,
        challenge_id: args.unseal.challenge_id,
      };
    default: {
      const exhaustive: never = args.proofKind;
      throw new Error(`Unsupported ECDSA export step-up proof: ${String(exhaustive)}`);
    }
  }
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
    chainTarget: args.exportLane.chainTarget,
    requestId,
    persistedMaterial: args.material.existingRoleLocalMaterial,
    operationRuntime: args.material,
  });
  const exportCredential = await requestThresholdEcdsaExportAuthorization(
    { touchConfirm: deps.touchConfirm, theme: deps.theme },
    {
      walletSessionUserId: args.walletId,
      credentialIdB64u: requirePasskeyEcdsaExportAuth(args.exportLane).credentialIdB64u,
      publicKey: args.exportPublicKey,
      chainTarget: args.exportLane.chainTarget,
      challengeB64u: prepared.challengeB64u,
      flowId: args.flowId,
      onEvent: args.onEvent,
    },
  );
  await assertEcdsaExportMaterialStillActive({
    deps,
    exportLane: args.exportLane,
    expectedMaterialActivation: args.material.existingRoleLocalMaterial.materialActivation,
  });
  const authorization = await issueExplicitEcdsaExportAuthorization({
    relayerUrl: args.material.relayerUrl,
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
  return await args.deps.emailOtp.exportEcdsaKeyWithDurableAuthorization({
    walletSession,
    chainTarget: args.material.chainTarget,
    challengeId: args.authorization.challengeId,
    otpCode: args.authorization.otpCode,
    publicFacts: args.material.publicFacts,
    runtimePolicyScope: args.material.runtimePolicyScope,
    authority: args.material.authorization.authority,
    persistedMaterial: args.persistedMaterial,
    explicitExportAuthorization: args.explicitExportAuthorization,
  });
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
  const prepared = await prepareExplicitEcdsaExportOperationWithRuntime({
    walletId: args.walletId,
    chainTarget: args.exportLane.chainTarget,
    requestId: createExportUiRequestId('tecdsa-email-otp-export'),
    persistedMaterial: args.material.persistedMaterial,
    operationRuntime: args.material,
  });
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
      flowId: args.flowId,
      onEvent: args.onEvent,
    },
  );
  await assertEmailOtpEcdsaExportMaterialStillActive({
    deps,
    exportLane: args.exportLane,
    expectedMaterialActivation: args.material.persistedMaterial.materialActivation,
  });
  const explicitExportAuthorization = await issueExplicitEcdsaExportAuthorization({
    relayerUrl: args.material.relayerUrl,
    prepared,
    proof: emailOtpExportProof({
      authority: args.material.authorization.authority,
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
      persistedMaterial: args.material.persistedMaterial,
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
  if (args.exportLane.authMethod !== 'passkey') {
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
      return await exportEcdsaDerivationKey(
        { getSignerWorkerContext: deps.getSignerWorkerContext },
        {
          walletSessionUserId: args.walletId,
          exportProvision,
          factorAuthorization: {
            kind: 'passkey',
            passkeyCredentialIdB64u: String(prepared.credential.rawId || prepared.credential.id),
            credential: prepared.credential,
          },
        },
      );
    },
  });
}
