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
  type ActiveWalletAuthorityEcdsaExportMaterial,
  resolveEcdsaExportMaterialForLane,
  resolveFreshEmailOtpEcdsaExportMaterialForLane,
} from './ecdsaExportMaterial';
import {
  type ActiveWalletAuthorityEcdsaExportAuthorization,
  exportActiveWalletAuthorityEcdsaHolderKey,
  exportEcdsaDerivationKey,
} from './ecdsaDerivationExport';
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
  type EcdsaOperationStepUpTransport,
  type PreparedEcdsaOperationStepUp,
} from '../../threshold/ecdsa/operationStepUp';
import {
  isEmailOtpWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
  type EmailOtpWalletAuthAuthority as CanonicalEmailOtpWalletAuthAuthority,
  type PasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { PersistedEcdsaRoleLocalMaterial } from '../../session/material/ecdsaRoleLocalMaterialResolver';
import type {
  RouterAbEcdsaDerivationNormalSigningStateV1,
  RouterAbEcdsaOperationStepUpAuthorizationV1Wire,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  resolveActiveWalletAuthorityEcdsaRuntimeV1,
  type ActiveWalletAuthorityEcdsaRuntimeV1,
} from '../../session/material/activeWalletAuthorityEcdsaRuntime';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';

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

type DisplayableEcdsaExportLane = ExactEcdsaExportLane;
type CanonicalEcdsaExportLane = Extract<ExactEcdsaExportLane, { source: 'canonical_capability' }>;
type ActiveWalletAuthorityEcdsaExportLane = Extract<
  ExactEcdsaExportLane,
  { source: 'active_wallet_authority' }
>;

type PrepareAndShowEcdsaExportArtifactArgs = {
  readonly walletId: string;
  readonly exportPublicKey: string;
  readonly options: EcdsaExportOptions;
  readonly flowId: string;
  readonly onEvent?: KeyExportEventCallback;
  readonly prepareArtifact: () => Promise<EcdsaExportArtifact>;
};

type PrepareAndShowEcdsaExportArtifactInput =
  | (PrepareAndShowEcdsaExportArtifactArgs & {
      readonly exportLane: CanonicalEcdsaExportLane;
      readonly activeRuntime?: never;
    })
  | (PrepareAndShowEcdsaExportArtifactArgs & {
      readonly exportLane: ActiveWalletAuthorityEcdsaExportLane;
      readonly activeRuntime: ActiveWalletAuthorityEcdsaRuntimeV1;
    });

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
    exportLane: DisplayableEcdsaExportLane;
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
    exportLane: DisplayableEcdsaExportLane;
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
  args: PrepareAndShowEcdsaExportArtifactInput,
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
        if (args.exportLane.source === 'active_wallet_authority') {
          const activeRuntime = args.activeRuntime;
          if (!activeRuntime) {
            throw new Error('[SigningEngine][ecdsa-export] active runtime is missing');
          }
          await assertActiveWalletAuthorityEcdsaRuntimeStillActive({
            expectedRuntime: activeRuntime,
          });
        } else if (args.exportLane.authMethod === 'email_otp') {
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

type EcdsaExportOperationRuntime = {
  readonly normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
  readonly relayerKeyId: string;
  readonly participantIds: readonly [number, number];
};

async function prepareExplicitEcdsaExportOperationWithRuntime(args: {
  readonly walletId: string;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly requestId: string;
  readonly keyHandle: string;
  readonly displayPublicKey: string;
  readonly displayAddress: string;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly operationRuntime: EcdsaExportOperationRuntime;
  readonly operationExpiresAtMs: number;
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
        materialActivation: args.materialActivation,
        keyHandle: args.keyHandle,
      }),
      intentDigest: await exportOperationDigest({
        operation: 'explicit_key_export',
        requestId: args.requestId,
        walletId: args.walletId,
        chainTarget: chainTargetKey,
      }),
      displayDigest: await exportOperationDigest({
        operation: 'Export Private Key',
        publicKey: args.displayPublicKey,
        address: args.displayAddress,
      }),
    },
    materialActivation: args.materialActivation,
    normalSigningScope: args.operationRuntime.normalSigning.scope,
    keyHandle: args.keyHandle,
    relayerKeyId: args.operationRuntime.relayerKeyId,
    participantIds: [
      Number(args.operationRuntime.participantIds[0]),
      Number(args.operationRuntime.participantIds[1]),
    ],
    expiresAtMs: args.operationExpiresAtMs,
  });
}

async function prepareExplicitEcdsaExportOperation(args: {
  readonly walletId: string;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly requestId: string;
  readonly keyHandle: string;
  readonly displayPublicKey: string;
  readonly displayAddress: string;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly operationRuntime: EcdsaExportOperationRuntime;
  readonly operationExpiresAtMs: number;
}): Promise<PreparedEcdsaOperationStepUp> {
  return await prepareExplicitEcdsaExportOperationWithRuntime({
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    requestId: args.requestId,
    keyHandle: args.keyHandle,
    displayPublicKey: args.displayPublicKey,
    displayAddress: args.displayAddress,
    materialActivation: args.materialActivation,
    operationRuntime: args.operationRuntime,
    operationExpiresAtMs: args.operationExpiresAtMs,
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

function assertActiveWalletAuthorityEcdsaRuntimeIdentity(args: {
  readonly expected: ActiveWalletAuthorityEcdsaRuntimeV1;
  readonly actual: ActiveWalletAuthorityEcdsaRuntimeV1;
}): void {
  const expected = args.expected;
  const actual = args.actual;
  if (
    expected.walletId !== actual.walletId ||
    expected.authorityId !== actual.authorityId ||
    expected.walletAuthMethodId !== actual.walletAuthMethodId ||
    expected.authorityDigestB64u !== actual.authorityDigestB64u ||
    expected.authorityRevocationEpoch !== actual.authorityRevocationEpoch ||
    expected.walletSessionId !== actual.walletSessionId ||
    expected.requiredCapability !== actual.requiredCapability ||
    !mpcMaterialActivationRefsEqual(expected.materialActivation, actual.materialActivation) ||
    alphabetizeStringify(expected.operationCredential) !==
      alphabetizeStringify(actual.operationCredential) ||
    alphabetizeStringify(expected.session) !== alphabetizeStringify(actual.session) ||
    alphabetizeStringify(expected.authority) !== alphabetizeStringify(actual.authority) ||
    alphabetizeStringify(expected.authMethod) !== alphabetizeStringify(actual.authMethod) ||
    alphabetizeStringify(expected.auth) !== alphabetizeStringify(actual.auth) ||
    alphabetizeStringify(expected.factorAuthority) !==
      alphabetizeStringify(actual.factorAuthority) ||
    alphabetizeStringify(expected.holderRuntime) !== alphabetizeStringify(actual.holderRuntime) ||
    alphabetizeStringify(expected.normalSigning) !== alphabetizeStringify(actual.normalSigning) ||
    alphabetizeStringify(expected.key) !== alphabetizeStringify(actual.key) ||
    alphabetizeStringify(expected.publicFacts) !== alphabetizeStringify(actual.publicFacts)
  ) {
    throw new Error(
      '[SigningEngine][ecdsa-export] active Wallet Authority runtime was replaced after authorization',
    );
  }
}

async function resolveFreshActiveWalletAuthorityEcdsaRuntime(args: {
  readonly expectedRuntime: ActiveWalletAuthorityEcdsaRuntimeV1;
}): Promise<ActiveWalletAuthorityEcdsaRuntimeV1> {
  const resolution = await resolveActiveWalletAuthorityEcdsaRuntimeV1({
    walletId: args.expectedRuntime.walletId,
    requiredCapability: 'export_keys',
    materialActivation: args.expectedRuntime.materialActivation,
  });
  if (resolution.kind !== 'resolved') {
    throw new Error(
      `[SigningEngine][ecdsa-export] active Wallet Authority runtime is ${resolution.reason}`,
    );
  }
  assertActiveWalletAuthorityEcdsaRuntimeIdentity({
    expected: args.expectedRuntime,
    actual: resolution.runtime,
  });
  return resolution.runtime;
}

async function assertActiveWalletAuthorityEcdsaRuntimeStillActive(args: {
  readonly expectedRuntime: ActiveWalletAuthorityEcdsaRuntimeV1;
}): Promise<void> {
  await resolveFreshActiveWalletAuthorityEcdsaRuntime(args);
}

function passkeyExportProof(args: {
  readonly authority: PasskeyWalletAuthAuthority;
  readonly credential: Awaited<
    ReturnType<typeof requestThresholdEcdsaExportAuthorization>
  >['credential'];
}) {
  const credential = args.credential;
  const credentialId = String(credential.rawId || credential.id || '').trim();
  if (!credentialId || credentialId !== args.authority.factor.credentialIdB64u) {
    throw new Error('[SigningEngine][ecdsa-export] passkey credential does not match authority');
  }
  return {
    kind: 'passkey' as const,
    authority: args.authority,
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
  readonly transport?: EcdsaOperationStepUpTransport;
}): Promise<ActiveWalletAuthorityEcdsaExportAuthorization> {
  const authorization = await issueEcdsaOperationStepUpAuthorization({
    relayerUrl: args.relayerUrl,
    ...(args.transport ? { transport: args.transport } : {}),
    request: {
      kind: 'router_ab_ecdsa_operation_step_up_v1',
      operation: args.prepared.operation,
      proof: args.proof,
    },
  });
  if (authorization.operation_kind !== 'evm.export_key') {
    throw new Error('[SigningEngine][ecdsa-export] operation step-up kind mismatch');
  }
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
    exportTopology: authorization.export_topology,
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
    exportLane: CanonicalEcdsaExportLane;
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
    keyHandle: args.material.existingRoleLocalMaterial.publicFacts.keyHandle,
    displayPublicKey: args.material.existingRoleLocalMaterial.publicFacts.groupPublicKey33B64u,
    displayAddress: args.material.existingRoleLocalMaterial.publicFacts.ethereumAddress,
    materialActivation: args.material.existingRoleLocalMaterial.materialActivation,
    operationRuntime: args.material,
    operationExpiresAtMs: Date.now() + 5 * 60_000,
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
  const authority = args.exportLane.capability.authority;
  if (!isPasskeyWalletAuthAuthority(authority)) {
    throw new Error('[SigningEngine][ecdsa-export] exact Passkey capability authority changed');
  }
  const authorization = await issueExplicitEcdsaExportAuthorization({
    relayerUrl: args.material.relayerUrl,
    prepared,
    transport: { kind: 'legacy_cookie' },
    proof: passkeyExportProof({
      authority,
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

function activeEcdsaExportOperationRuntime(
  material: ActiveWalletAuthorityEcdsaExportMaterial,
): EcdsaExportOperationRuntime {
  return {
    normalSigning: material.runtime.normalSigning,
    relayerKeyId: material.relayerKeyId,
    participantIds: material.participantIds,
  };
}

function activeEcdsaExportOperationExpiry(runtime: ActiveWalletAuthorityEcdsaRuntimeV1): number {
  return Math.min(Date.now() + 5 * 60_000, runtime.session.expiresAtMs);
}

async function prepareActiveWalletAuthorityPasskeyEcdsaExport(args: {
  readonly deps: EcdsaExportFlowDeps;
  readonly walletId: string;
  readonly exportLane: ActiveWalletAuthorityEcdsaExportLane;
  readonly material: Extract<
    ActiveWalletAuthorityEcdsaExportMaterial,
    { kind: 'active_wallet_authority_passkey_needs_authorization' }
  >;
  readonly exportPublicKey: string;
  readonly flowId: string;
  readonly onEvent?: KeyExportEventCallback;
}): Promise<{
  readonly runtime: ActiveWalletAuthorityEcdsaRuntimeV1;
  readonly authorization: ActiveWalletAuthorityEcdsaExportAuthorization;
}> {
  if (args.material.runtime.auth.kind !== 'passkey') {
    throw new Error('[SigningEngine][ecdsa-export] active passkey runtime auth mismatch');
  }
  if (!isPasskeyWalletAuthAuthority(args.material.factorAuthority)) {
    throw new Error('[SigningEngine][ecdsa-export] active passkey factor authority mismatch');
  }
  const prepared = await prepareExplicitEcdsaExportOperation({
    walletId: args.walletId,
    chainTarget: args.exportLane.chainTarget,
    requestId: createExportUiRequestId('tecdsa-active-passkey-export'),
    keyHandle: args.material.runtime.publicFacts.keyHandle,
    displayPublicKey: args.material.runtime.publicFacts.publicKeyB64u,
    displayAddress: args.material.runtime.publicFacts.thresholdOwnerAddress,
    materialActivation: args.material.runtime.materialActivation,
    operationRuntime: activeEcdsaExportOperationRuntime(args.material),
    operationExpiresAtMs: activeEcdsaExportOperationExpiry(args.material.runtime),
  });
  const exportCredential = await requestThresholdEcdsaExportAuthorization(
    { touchConfirm: args.deps.touchConfirm, theme: args.deps.theme },
    {
      walletSessionUserId: args.walletId,
      credentialIdB64u: args.material.factorAuthority.factor.credentialIdB64u,
      publicKey: args.exportPublicKey,
      chainTarget: args.exportLane.chainTarget,
      challengeB64u: prepared.challengeB64u,
      flowId: args.flowId,
      onEvent: args.onEvent,
    },
  );
  const runtime = await resolveFreshActiveWalletAuthorityEcdsaRuntime({
    expectedRuntime: args.material.runtime,
  });
  if (!isPasskeyWalletAuthAuthority(runtime.factorAuthority)) {
    throw new Error('[SigningEngine][ecdsa-export] active passkey factor authority changed');
  }
  const authorization = await issueExplicitEcdsaExportAuthorization({
    relayerUrl: args.material.relayerUrl,
    prepared,
    transport: {
      kind: 'wallet_session_bearer',
      token: runtime.operationCredential.token,
    },
    proof: passkeyExportProof({
      authority: runtime.factorAuthority,
      credential: exportCredential.credential,
    }),
  });
  return { runtime, authorization };
}

async function prepareActiveWalletAuthorityEmailOtpEcdsaExport(args: {
  readonly deps: EcdsaExportFlowDeps;
  readonly walletId: string;
  readonly exportLane: ActiveWalletAuthorityEcdsaExportLane;
  readonly material: Extract<
    ActiveWalletAuthorityEcdsaExportMaterial,
    { kind: 'active_wallet_authority_email_otp_needs_authorization' }
  >;
  readonly exportPublicKey: string;
  readonly flowId: string;
  readonly onEvent?: KeyExportEventCallback;
}): Promise<{
  readonly runtime: ActiveWalletAuthorityEcdsaRuntimeV1;
  readonly authorization: ActiveWalletAuthorityEcdsaExportAuthorization;
}> {
  if (args.material.runtime.auth.kind !== 'email_otp') {
    throw new Error('[SigningEngine][ecdsa-export] active Email OTP runtime auth mismatch');
  }
  if (!isEmailOtpWalletAuthAuthority(args.material.factorAuthority)) {
    throw new Error('[SigningEngine][ecdsa-export] active Email OTP factor authority mismatch');
  }
  const prepared = await prepareExplicitEcdsaExportOperation({
    walletId: args.walletId,
    chainTarget: args.exportLane.chainTarget,
    requestId: createExportUiRequestId('tecdsa-active-email-otp-export'),
    keyHandle: args.material.runtime.publicFacts.keyHandle,
    displayPublicKey: args.material.runtime.publicFacts.publicKeyB64u,
    displayAddress: args.material.runtime.publicFacts.thresholdOwnerAddress,
    materialActivation: args.material.runtime.materialActivation,
    operationRuntime: activeEcdsaExportOperationRuntime(args.material),
    operationExpiresAtMs: activeEcdsaExportOperationExpiry(args.material.runtime),
  });
  const authorization = await requestEmailOtpKeyExportAuthorization(
    {
      touchConfirm: args.deps.touchConfirm,
      requestExportChallenge: args.deps.emailOtp.requestExportChallenge,
    },
    {
      kind: 'wallet_session_export_auth',
      walletSession: walletSessionRefFromSession({
        walletId: args.walletId,
        walletSessionUserId: args.walletId,
      }),
      chain: ecdsaExportBoundaryChain(args.exportLane),
      publicKey: args.exportPublicKey,
      curve: 'ecdsa' satisfies WalletAuthCurve,
      flowId: args.flowId,
      onEvent: args.onEvent,
    },
  );
  const runtime = await resolveFreshActiveWalletAuthorityEcdsaRuntime({
    expectedRuntime: args.material.runtime,
  });
  if (!isEmailOtpWalletAuthAuthority(runtime.factorAuthority)) {
    throw new Error('[SigningEngine][ecdsa-export] active Email OTP factor authority changed');
  }
  const explicitExportAuthorization = await issueExplicitEcdsaExportAuthorization({
    relayerUrl: args.material.relayerUrl,
    prepared,
    transport: {
      kind: 'wallet_session_bearer',
      token: runtime.operationCredential.token,
    },
    proof: emailOtpExportProof({
      authority: runtime.factorAuthority,
      challengeId: authorization.challengeId,
      otpCode: authorization.otpCode,
    }),
  });
  return { runtime, authorization: explicitExportAuthorization };
}

export async function exportThresholdEcdsaKeyWithActiveWalletAuthority(
  deps: EcdsaExportFlowDeps,
  args: {
    readonly walletId: string;
    readonly exportLane: ActiveWalletAuthorityEcdsaExportLane;
    readonly material: ActiveWalletAuthorityEcdsaExportMaterial;
    readonly options: EcdsaExportOptions;
    readonly flowId: string;
    readonly onEvent?: KeyExportEventCallback;
  },
): Promise<{ accountId: string; exportedSchemes: ExportedKeySchemes }> {
  const exportPublicKey = String(args.material.publicFacts.publicKeyB64u);
  const prepared =
    args.material.kind === 'active_wallet_authority_passkey_needs_authorization'
      ? await prepareActiveWalletAuthorityPasskeyEcdsaExport({
          deps,
          walletId: args.walletId,
          exportLane: args.exportLane,
          material: args.material,
          exportPublicKey,
          flowId: args.flowId,
          onEvent: args.onEvent,
        })
      : await prepareActiveWalletAuthorityEmailOtpEcdsaExport({
          deps,
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
    activeRuntime: prepared.runtime,
    exportPublicKey,
    options: args.options,
    flowId: args.flowId,
    onEvent: args.onEvent,
    prepareArtifact: async () => {
      const runtime = await resolveFreshActiveWalletAuthorityEcdsaRuntime({
        expectedRuntime: prepared.runtime,
      });
      return await exportActiveWalletAuthorityEcdsaHolderKey(
        { getSignerWorkerContext: deps.getSignerWorkerContext },
        {
          runtime,
          operationAuthorization: prepared.authorization,
          relayerUrl: args.material.relayerUrl,
        },
      );
    },
  });
}

export async function exportThresholdEcdsaKeyWithFreshEmailOtpRouteAuth(
  deps: EcdsaExportFlowDeps,
  args: {
    walletId: string;
    exportLane: CanonicalEcdsaExportLane;
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
    keyHandle: args.material.persistedMaterial.publicFacts.keyHandle,
    displayPublicKey: args.material.persistedMaterial.publicFacts.groupPublicKey33B64u,
    displayAddress: args.material.persistedMaterial.publicFacts.ethereumAddress,
    materialActivation: args.material.persistedMaterial.materialActivation,
    operationRuntime: args.material,
    operationExpiresAtMs: Date.now() + 5 * 60_000,
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
    transport: { kind: 'legacy_cookie' },
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
    exportLane: CanonicalEcdsaExportLane;
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
