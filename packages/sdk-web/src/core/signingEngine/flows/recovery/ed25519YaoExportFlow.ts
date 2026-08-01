import type { AccountId } from '@/core/types/accountIds';
import { KeyExportEventPhase } from '@/core/types/sdkSentEvents';
import {
  ROUTER_AB_ED25519_YAO_EXPORT_ARTIFACT_KIND_V1,
  type RouterAbEd25519YaoExportWorkerPayloadV1,
} from '@/core/types/secure-confirm-worker';
import type { NearEd25519YaoSigningCapability } from '../../interfaces/near';
import type {
  PasskeyMpcExportPort,
  UiConfirmRuntimeBridgePort,
} from '../../uiConfirm/uiConfirm.types';
import type { ExactEd25519SigningLaneIdentity } from '../../session/identity/exactSigningLaneIdentity';
import {
  exactEd25519SigningLaneIdentity,
  nearEd25519SignerBindingFromBoundaryFields,
} from '../../session/identity/exactSigningLaneIdentity';
import { toRpId } from '../../session/identity/evmFamilyEcdsaIdentity';
import type {
  Ed25519YaoActiveClientIdentityV1,
} from '../../threshold/ed25519/yaoActiveClientRegistry';
import {
  createExportUiRequestId,
  emitKeyExportEvent,
  type KeyExportEventCallback,
} from './keyExportFlow';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { walletSessionRefFromSession } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { base58Encode } from '@shared/utils/base58';
import type { EmailOtpWalletSessionExportAuthorizationDeps } from './keyExportConfirmation';
import {
  requestEmailOtpEd25519KeyExportAuthorization,
  showEd25519ExportViewer,
} from './keyExportConfirmation';
import type {
  ResolvedEmailOtpEd25519YaoExportV1,
} from '../../session/emailOtp/ed25519YaoSealedRecovery';
import {
  resolveEmailOtpAuthLane,
  type EmailOtpSigningSessionAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import type {
  PasskeyEd25519YaoExportContextResolutionV1,
  PasskeyEd25519YaoExportContextV1,
} from '../../session/passkey/ed25519YaoWarmRecovery';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import { resolveThresholdEd25519CommitQueueKey } from '../../threshold/ed25519/commitQueue';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import { nearEd25519YaoMaterialActivationFromMetadata } from '../../session/material/nearEd25519YaoMaterialActivation';

export type Ed25519YaoExportFlowDeps = {
  touchConfirm: Pick<UiConfirmRuntimeBridgePort, 'initialize' | 'requestUserConfirmation'>;
  passkeyMpcExport: PasskeyMpcExportPort;
  resolveActiveCapability: (
    identity: Ed25519YaoActiveClientIdentityV1,
  ) => NearEd25519YaoSigningCapability | null;
  recoverPasskeyCapability: (
    args: {
      laneIdentity: ExactEd25519SigningLaneIdentity<PasskeyEd25519LaneAuth>;
      materialActivation: MpcMaterialActivationRef;
    },
  ) => Promise<NearEd25519YaoSigningCapability>;
  resolvePasskeyExportContext: (
    args: {
      laneIdentity: ExactEd25519SigningLaneIdentity<PasskeyEd25519LaneAuth>;
      materialActivation: MpcMaterialActivationRef;
    },
  ) => Promise<PasskeyEd25519YaoExportContextResolutionV1>;
  withThresholdEd25519CommitQueue: <T>(args: {
    queueKey: string;
    nearAccountId: AccountId;
    enabled: boolean;
    task: () => Promise<T>;
  }) => Promise<T>;
  emailOtp: {
    requestExportChallenge: EmailOtpWalletSessionExportAuthorizationDeps['requestExportChallenge'];
    resolveExportContext: (
      args: {
        laneIdentity: ExactEd25519SigningLaneIdentity<EmailOtpEd25519LaneAuth>;
        materialActivation: MpcMaterialActivationRef;
      },
    ) => Promise<ResolvedEmailOtpEd25519YaoExportV1>;
    exportSeedWithFreshAuthorization: (args: {
      challengeId: string;
      otpCode: string;
      exportContext: ResolvedEmailOtpEd25519YaoExportV1;
    }) => Promise<{
      artifactKind: 'near-ed25519-seed-v1';
      publicKey: string;
      privateKey: string;
    }>;
  };
  theme?: 'dark' | 'light';
};

export type ExportEd25519YaoKeyArgs = {
  walletId: WalletId;
  nearAccountId: AccountId;
  laneIdentity: ExactEd25519SigningLaneIdentity;
  materialActivation: MpcMaterialActivationRef;
  options: {
    variant?: 'drawer' | 'modal';
    theme?: 'dark' | 'light';
  };
  flowId: string;
  onEvent?: KeyExportEventCallback;
};

function safeStateEpoch(value: bigint): number {
  const epoch = Number(value);
  if (!Number.isSafeInteger(epoch) || epoch < 0 || BigInt(epoch) !== value) {
    throw new Error('[SigningEngine][ed25519-export] active capability state epoch is invalid');
  }
  return epoch;
}

function emailOtpExportAuthLane(
  context: ResolvedEmailOtpEd25519YaoExportV1,
): Extract<EmailOtpSigningSessionAuthLane, { curve: 'ed25519' }> {
  const authLane = resolveEmailOtpAuthLane({
    routeAuth: {
      kind: 'wallet_session',
      jwt: context.authorization.walletSessionJwt,
    },
    curve: 'ed25519',
  });
  if (authLane?.kind !== 'signing_session' || authLane.curve !== 'ed25519') {
    throw new Error('[SigningEngine][ed25519-export] canonical Email OTP auth lane is invalid');
  }
  return authLane;
}

type ResolvedPasskeyEd25519YaoExportContext = {
  laneIdentity: ExactEd25519SigningLaneIdentity<PasskeyEd25519LaneAuth>;
  relayerUrl: string;
  walletSessionJwt: string;
  capability: RouterAbEd25519YaoExportWorkerPayloadV1['capability'];
};

function passkeyEd25519ExportMaterialActivation(
  resolved: ResolvedPasskeyEd25519YaoExportContext,
) {
  return resolved.capability.materialActivation;
}

function emailOtpEd25519ExportMaterialActivation(
  context: ResolvedEmailOtpEd25519YaoExportV1,
) {
  return context.material.materialActivation;
}

type PasskeyEd25519LaneAuth = Extract<
  ExactEd25519SigningLaneIdentity['auth'],
  { kind: 'passkey' }
>;

type EmailOtpEd25519LaneAuth = Extract<
  ExactEd25519SigningLaneIdentity['auth'],
  { kind: 'email_otp' }
>;

function isExactPasskeyEd25519SigningLaneIdentity(
  laneIdentity: ExactEd25519SigningLaneIdentity,
): laneIdentity is ExactEd25519SigningLaneIdentity<PasskeyEd25519LaneAuth> {
  return laneIdentity.auth.kind === 'passkey';
}

function requirePasskeyExportLaneIdentity(
  args: ExportEd25519YaoKeyArgs,
): ExactEd25519SigningLaneIdentity<PasskeyEd25519LaneAuth> {
  if (!isExactPasskeyEd25519SigningLaneIdentity(args.laneIdentity)) {
    throw new Error('[SigningEngine][ed25519-export] export requires a passkey Yao lane');
  }
  if (
    args.laneIdentity.signer.account.wallet.walletId !== args.walletId ||
    String(args.laneIdentity.signer.account.nearAccountId) !== String(args.nearAccountId)
  ) {
    throw new Error('[SigningEngine][ed25519-export] exact lane subject mismatch');
  }
  return args.laneIdentity;
}

function isExactEmailOtpEd25519SigningLaneIdentity(
  laneIdentity: ExactEd25519SigningLaneIdentity,
): laneIdentity is ExactEd25519SigningLaneIdentity<EmailOtpEd25519LaneAuth> {
  return laneIdentity.auth.kind === 'email_otp';
}

function requireEmailOtpExportLaneIdentity(
  args: ExportEd25519YaoKeyArgs,
): ExactEd25519SigningLaneIdentity<EmailOtpEd25519LaneAuth> {
  if (!isExactEmailOtpEd25519SigningLaneIdentity(args.laneIdentity)) {
    throw new Error('[SigningEngine][ed25519-export] export requires an Email OTP Yao lane');
  }
  if (
    args.laneIdentity.signer.account.wallet.walletId !== args.walletId ||
    String(args.laneIdentity.signer.account.nearAccountId) !== String(args.nearAccountId)
  ) {
    throw new Error('[SigningEngine][ed25519-export] exact lane subject mismatch');
  }
  return args.laneIdentity;
}

function activeCapabilityLookupScope(
  laneIdentity: ExactEd25519SigningLaneIdentity,
  materialActivation: MpcMaterialActivationRef,
): Ed25519YaoActiveClientIdentityV1 {
  return {
    walletId: laneIdentity.signer.account.wallet.walletId,
    nearAccountId: laneIdentity.signer.account.nearAccountId,
    materialActivation,
  };
}

function passkeyExportStableIdentityMatches(args: {
  selected: ExactEd25519SigningLaneIdentity<PasskeyEd25519LaneAuth>;
  current: ExactEd25519SigningLaneIdentity<PasskeyEd25519LaneAuth>;
}): boolean {
  const selectedSigner = args.selected.signer;
  const currentSigner = args.current.signer;
  return (
    String(selectedSigner.account.wallet.walletId) ===
      String(currentSigner.account.wallet.walletId) &&
    String(selectedSigner.account.nearAccountId) === String(currentSigner.account.nearAccountId) &&
    String(selectedSigner.nearEd25519SigningKeyId) ===
      String(currentSigner.nearEd25519SigningKeyId) &&
    selectedSigner.signerSlot === currentSigner.signerSlot &&
    selectedSigner.account.kind === currentSigner.account.kind &&
    String(args.selected.thresholdSessionId) === String(args.current.thresholdSessionId) &&
    String(args.selected.auth.rpId) === String(args.current.auth.rpId) &&
    args.selected.auth.credentialIdB64u === args.current.auth.credentialIdB64u
  );
}

function resolvePasskeyExportContextFromActiveCapability(args: {
  capability: NearEd25519YaoSigningCapability;
  selectedLaneIdentity: ExactEd25519SigningLaneIdentity<PasskeyEd25519LaneAuth>;
  selectedMaterialActivation: MpcMaterialActivationRef;
}): ResolvedPasskeyEd25519YaoExportContext {
  const { capability } = args;
  if (capability.activeClient.status().kind !== 'active') {
    throw new Error('[SigningEngine][ed25519-export] recovered Yao capability is inactive');
  }
  const currentLaneIdentity = capability.walletSessionState.signingLane.identity;
  if (!isExactPasskeyEd25519SigningLaneIdentity(currentLaneIdentity)) {
    throw new Error(
      '[SigningEngine][ed25519-export] recovered capability requires passkey authority',
    );
  }
  if (
    !passkeyExportStableIdentityMatches({
      selected: args.selectedLaneIdentity,
      current: currentLaneIdentity,
    })
  ) {
    throw new Error('[SigningEngine][ed25519-export] Yao capability stable identity mismatch');
  }
  const metadata = capability.activeClient.metadata();
  const materialActivation = nearEd25519YaoMaterialActivationFromMetadata(metadata);
  if (!mpcMaterialActivationRefsEqual(args.selectedMaterialActivation, materialActivation)) {
    throw new Error('[SigningEngine][ed25519-export] Yao capability activation mismatch');
  }
  return {
    laneIdentity: currentLaneIdentity,
    relayerUrl: capability.walletSessionState.relayerUrl,
    walletSessionJwt: capability.walletSessionState.walletSessionAuth.walletSessionJwt,
    capability: {
      materialActivation,
      scope: metadata.scope,
      applicationBinding: metadata.applicationBinding,
      participantIds: metadata.participantIds,
      registeredPublicKey: [...metadata.registeredPublicKey],
      stateEpoch: safeStateEpoch(metadata.stateEpoch),
      activeCapabilityBinding: [...metadata.activeCapabilityBinding],
      runtimePolicyScope: capability.walletSessionState.runtimePolicyScope,
    },
  };
}

function passkeyLaneIdentityFromExportContext(
  context: PasskeyEd25519YaoExportContextV1,
): ExactEd25519SigningLaneIdentity<PasskeyEd25519LaneAuth> {
  const descriptor = context.descriptor;
  const laneIdentity = exactEd25519SigningLaneIdentity({
    signer: nearEd25519SignerBindingFromBoundaryFields({
      walletId: descriptor.walletId,
      nearAccountId: descriptor.nearAccountId,
      nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
        descriptor.nearEd25519SigningKeyId,
      ),
      signerSlot: descriptor.signerSlot,
    }),
    auth: {
      kind: 'passkey',
      rpId: toRpId(context.rpId),
      credentialIdB64u: descriptor.credentialIdB64u,
    },
    signingGrantId: descriptor.session.signingGrantId,
    thresholdSessionId: descriptor.session.thresholdSessionId,
  });
  if (!isExactPasskeyEd25519SigningLaneIdentity(laneIdentity)) {
    throw new Error(
      '[SigningEngine][ed25519-export] durable Yao context requires passkey authority',
    );
  }
  return laneIdentity;
}

function requireDurablePasskeyExportContext(args: {
  context: PasskeyEd25519YaoExportContextV1;
  selectedLaneIdentity: ExactEd25519SigningLaneIdentity<PasskeyEd25519LaneAuth>;
  selectedMaterialActivation: MpcMaterialActivationRef;
}): ResolvedPasskeyEd25519YaoExportContext {
  const currentLaneIdentity = passkeyLaneIdentityFromExportContext(args.context);
  if (
    !passkeyExportStableIdentityMatches({
      selected: args.selectedLaneIdentity,
      current: currentLaneIdentity,
    })
  ) {
    throw new Error('[SigningEngine][ed25519-export] durable Yao context identity mismatch');
  }
  const descriptor = args.context.descriptor;
  if (
    !mpcMaterialActivationRefsEqual(
      args.selectedMaterialActivation,
      descriptor.capability.materialActivation,
    )
  ) {
    throw new Error('[SigningEngine][ed25519-export] durable Yao context activation mismatch');
  }
  const lifecycle = descriptor.capability.lifecycle;
  return {
    laneIdentity: currentLaneIdentity,
    relayerUrl: args.context.relayerUrl,
    walletSessionJwt: descriptor.session.walletSessionJwt,
    capability: {
      materialActivation: descriptor.capability.materialActivation,
      scope: {
        lifecycle_id: lifecycle.lifecycleId,
        root_share_epoch: lifecycle.rootShareEpoch,
        account_id: lifecycle.accountId,
        threshold_session_id: lifecycle.thresholdSessionId,
        signer_set_id: lifecycle.signerSetId,
        signing_worker_id: lifecycle.signingWorkerId,
        material_activation: routerAbMpcMaterialActivationRefToWire(
          descriptor.capability.materialActivation,
        ),
      },
      applicationBinding: descriptor.capability.applicationBinding,
      participantIds: descriptor.capability.participantIds,
      registeredPublicKey: descriptor.capability.registeredPublicKey,
      stateEpoch: descriptor.capability.stateEpoch,
      activeCapabilityBinding: descriptor.capability.activeCapabilityBinding,
      runtimePolicyScope: descriptor.session.runtimePolicyScope,
    },
  };
}

async function resolveExactPasskeyExportContext(
  deps: Ed25519YaoExportFlowDeps,
  args: ExportEd25519YaoKeyArgs,
): Promise<ResolvedPasskeyEd25519YaoExportContext> {
  const laneIdentity = requirePasskeyExportLaneIdentity(args);
  const activeCapability = deps.resolveActiveCapability(
    activeCapabilityLookupScope(laneIdentity, args.materialActivation),
  );
  if (activeCapability) {
    return resolvePasskeyExportContextFromActiveCapability({
      capability: activeCapability,
      selectedLaneIdentity: laneIdentity,
      selectedMaterialActivation: args.materialActivation,
    });
  }
  const durableContext = await deps.resolvePasskeyExportContext({
    laneIdentity,
    materialActivation: args.materialActivation,
  });
  switch (durableContext.kind) {
    case 'ready':
      return requireDurablePasskeyExportContext({
        context: durableContext.context,
        selectedLaneIdentity: laneIdentity,
        selectedMaterialActivation: args.materialActivation,
      });
    case 'capability_recovery_required': {
      const capability = await deps.recoverPasskeyCapability({
        laneIdentity,
        materialActivation: args.materialActivation,
      });
      return resolvePasskeyExportContextFromActiveCapability({
        capability,
        selectedLaneIdentity: laneIdentity,
        selectedMaterialActivation: args.materialActivation,
      });
    }
  }
  durableContext satisfies never;
  throw new Error('[SigningEngine][ed25519-export] unsupported passkey export context state');
}

async function resolveExactEmailOtpExportContext(
  deps: Ed25519YaoExportFlowDeps,
  args: ExportEd25519YaoKeyArgs,
): Promise<{
  context: ResolvedEmailOtpEd25519YaoExportV1;
  laneIdentity: ExactEd25519SigningLaneIdentity<EmailOtpEd25519LaneAuth>;
}> {
  const laneIdentity = requireEmailOtpExportLaneIdentity(args);
  const context = await deps.emailOtp.resolveExportContext({
    laneIdentity,
    materialActivation: args.materialActivation,
  });
  if (
    !mpcMaterialActivationRefsEqual(
      args.materialActivation,
      context.material.materialActivation,
    )
  ) {
    throw new Error('[SigningEngine][ed25519-export] Email OTP Yao context activation mismatch');
  }
  return { context, laneIdentity };
}

function buildWorkerPayload(args: {
  resolved: ResolvedPasskeyEd25519YaoExportContext;
  viewerSessionId: string;
  input: ExportEd25519YaoKeyArgs;
  theme?: 'dark' | 'light';
}): RouterAbEd25519YaoExportWorkerPayloadV1 {
  const signer = args.resolved.laneIdentity.signer;
  return {
    artifactKind: ROUTER_AB_ED25519_YAO_EXPORT_ARTIFACT_KIND_V1,
    walletId: String(args.input.walletId),
    nearAccountId: String(args.input.nearAccountId),
    relayerUrl: args.resolved.relayerUrl,
    authorization: {
      kind: 'wallet_session',
      walletSessionJwt: args.resolved.walletSessionJwt,
    },
    flowId: args.input.flowId,
    viewerSessionId: args.viewerSessionId,
    exactLane: {
      nearEd25519SigningKeyId: String(signer.nearEd25519SigningKeyId),
      signerSlot: signer.signerSlot,
      credentialIdB64u: args.resolved.laneIdentity.auth.credentialIdB64u,
      materialActivation: passkeyEd25519ExportMaterialActivation(args.resolved),
    },
    capability: args.resolved.capability,
    variant: args.input.options.variant,
    theme: args.input.options.theme ?? args.theme,
  };
}

type Ed25519ExportViewerLifecycleContext = {
  flowId: string;
  walletId: WalletId;
  onEvent?: KeyExportEventCallback;
};

function emitEd25519ExportViewerLifecycle(
  context: Ed25519ExportViewerLifecycleContext,
  event: 'opened' | 'closed',
): void {
  const accountId = String(context.walletId);
  emitKeyExportEvent(context.onEvent, {
    phase:
      event === 'opened'
        ? KeyExportEventPhase.STEP_04_VIEWER_OPENED
        : KeyExportEventPhase.STEP_05_VIEWER_CLOSED,
    status: event === 'opened' ? 'waiting_for_user' : 'succeeded',
    flowId: context.flowId,
    accountId,
    interaction: {
      kind: 'key_export_viewer',
      overlay: event === 'opened' ? 'show' : 'hide',
    },
    data: { chain: 'near', curve: 'ed25519' },
  });
  if (event !== 'closed') return;
  emitKeyExportEvent(context.onEvent, {
    phase: KeyExportEventPhase.STEP_06_COMPLETED,
    status: 'succeeded',
    flowId: context.flowId,
    accountId,
    interaction: { kind: 'none', overlay: 'hide' },
    data: { chain: 'near', curve: 'ed25519' },
  });
}

export async function exportEd25519YaoKeyWithFreshAuthorization(
  deps: Ed25519YaoExportFlowDeps,
  args: ExportEd25519YaoKeyArgs,
): Promise<{ accountId: string; exportedSchemes: Array<'ed25519'> }> {
  switch (args.laneIdentity.auth.kind) {
    case 'passkey':
      break;
    case 'email_otp':
      return await exportEd25519YaoKeyWithFreshEmailOtp(deps, args);
    default:
      args.laneIdentity.auth satisfies never;
      throw new Error('[SigningEngine][ed25519-export] unsupported lane authorization method');
  }
  const contextResolution = resolveExactPasskeyExportContext(deps, args);
  const uiInitialization = deps.touchConfirm.initialize();
  const [resolved] = await Promise.all([contextResolution, uiInitialization]);
  const eventAccountId = String(args.walletId);
  const viewerSessionId = createExportUiRequestId('export-ed25519-yao-viewer-session');
  const onViewerLifecycle = emitEd25519ExportViewerLifecycle.bind(undefined, {
    flowId: args.flowId,
    walletId: args.walletId,
    onEvent: args.onEvent,
  });
  emitKeyExportEvent(args.onEvent, {
    phase: KeyExportEventPhase.STEP_02_AUTH_PASSKEY_PROMPT_STARTED,
    status: 'waiting_for_user',
    flowId: args.flowId,
    accountId: eventAccountId,
    authMethod: 'passkey',
    interaction: { kind: 'passkey_assert', overlay: 'show' },
    data: { intent: 'ed25519_export', chain: 'near', curve: 'ed25519' },
  });
  emitKeyExportEvent(args.onEvent, {
    phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_STARTED,
    status: 'running',
    flowId: args.flowId,
    accountId: eventAccountId,
    interaction: { kind: 'none', overlay: 'none' },
    data: { chain: 'near', curve: 'ed25519' },
  });
  const result = await deps.withThresholdEd25519CommitQueue({
    queueKey: resolveThresholdEd25519CommitQueueKey({
      materialActivation: passkeyEd25519ExportMaterialActivation(resolved),
    }),
    nearAccountId: args.nearAccountId,
    enabled: true,
    task: () =>
      deps.passkeyMpcExport.exportPrivateKeysWithUi(
        buildWorkerPayload({
          resolved,
          viewerSessionId,
          input: args,
          theme: deps.theme,
        }),
        { onViewerLifecycle },
      ),
  });
  if (
    !result.ok ||
    result.exportedSchemes.length !== 1 ||
    result.exportedSchemes[0] !== 'ed25519'
  ) {
    throw new Error(result.error || '[SigningEngine][ed25519-export] secure export failed');
  }
  emitKeyExportEvent(args.onEvent, {
    phase: KeyExportEventPhase.STEP_02_AUTH_PASSKEY_PROMPT_SUCCEEDED,
    status: 'succeeded',
    flowId: args.flowId,
    accountId: eventAccountId,
    authMethod: 'passkey',
    interaction: { kind: 'passkey_assert', overlay: 'none' },
    data: { intent: 'ed25519_export', chain: 'near', curve: 'ed25519' },
  });
  emitKeyExportEvent(args.onEvent, {
    phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_SUCCEEDED,
    status: 'succeeded',
    flowId: args.flowId,
    accountId: eventAccountId,
    interaction: { kind: 'none', overlay: 'none' },
    data: { chain: 'near', curve: 'ed25519' },
  });
  return { accountId: String(args.nearAccountId), exportedSchemes: ['ed25519'] };
}

async function exportEd25519YaoKeyWithFreshEmailOtp(
  deps: Ed25519YaoExportFlowDeps,
  args: ExportEd25519YaoKeyArgs,
): Promise<{ accountId: string; exportedSchemes: Array<'ed25519'> }> {
  const resolved = await resolveExactEmailOtpExportContext(deps, args);
  const publicKey = `ed25519:${base58Encode(
    Uint8Array.from(resolved.context.material.capability.registeredPublicKey),
  )}`;
  const authorization = await requestEmailOtpEd25519KeyExportAuthorization(
    {
      touchConfirm: deps.touchConfirm,
      requestExportChallenge: deps.emailOtp.requestExportChallenge,
    },
    {
      kind: 'wallet_session_ed25519_export_auth',
      walletSession: walletSessionRefFromSession({
        walletId: args.walletId,
        walletSessionUserId: args.walletId,
      }),
      nearAccountId: String(args.nearAccountId),
      nearEd25519SigningKeyId: String(resolved.laneIdentity.signer.nearEd25519SigningKeyId),
      signerSlot: resolved.laneIdentity.signer.signerSlot,
      authLane: emailOtpExportAuthLane(resolved.context),
      publicKey,
      curve: 'ed25519',
      chain: 'near',
      flowId: args.flowId,
      onEvent: args.onEvent,
    },
  );
  emitKeyExportEvent(args.onEvent, {
    phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_STARTED,
    status: 'running',
    flowId: args.flowId,
    accountId: String(args.nearAccountId),
    interaction: { kind: 'none', overlay: 'none' },
    data: { chain: 'near', curve: 'ed25519' },
  });
  const artifact = await deps.withThresholdEd25519CommitQueue({
    queueKey: resolveThresholdEd25519CommitQueueKey({
      materialActivation: emailOtpEd25519ExportMaterialActivation(resolved.context),
    }),
    nearAccountId: args.nearAccountId,
    enabled: true,
      task: () =>
        deps.emailOtp.exportSeedWithFreshAuthorization({
        challengeId: authorization.challengeId,
        otpCode: authorization.otpCode,
        exportContext: resolved.context,
      }),
  });
  emitKeyExportEvent(args.onEvent, {
    phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_SUCCEEDED,
    status: 'succeeded',
    flowId: args.flowId,
    accountId: String(args.nearAccountId),
    interaction: { kind: 'none', overlay: 'none' },
    data: { chain: 'near', curve: 'ed25519' },
  });
  await showEd25519ExportViewer(
    { touchConfirm: deps.touchConfirm, theme: deps.theme },
    {
      walletId: String(args.walletId),
      nearAccountId: String(args.nearAccountId),
      publicKey: artifact.publicKey,
      privateKey: artifact.privateKey,
      variant: args.options.variant,
      theme: args.options.theme,
      flowId: args.flowId,
      onEvent: args.onEvent,
    },
  );
  return { accountId: String(args.nearAccountId), exportedSchemes: ['ed25519'] };
}
