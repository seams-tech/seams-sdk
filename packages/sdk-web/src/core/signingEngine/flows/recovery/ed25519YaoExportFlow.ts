import type { AccountId } from '@/core/types/accountIds';
import { KeyExportEventPhase } from '@/core/types/sdkSentEvents';
import {
  ROUTER_AB_ED25519_YAO_EXPORT_ARTIFACT_KIND_V1,
  type RouterAbEd25519YaoExportWorkerPayloadV1,
} from '@/core/types/secure-confirm-worker';
import type { NearEd25519YaoSigningCapability } from '../../interfaces/near';
import type { UiConfirmRuntimeBridgePort } from '../../uiConfirm/uiConfirm.types';
import type { ExactEd25519SigningLaneIdentity } from '../../session/identity/exactSigningLaneIdentity';
import {
  exactEd25519SigningLaneIdentity,
  nearEd25519SignerBindingFromBoundaryFields,
} from '../../session/identity/exactSigningLaneIdentity';
import { toRpId } from '../../session/identity/evmFamilyEcdsaIdentity';
import type { Ed25519YaoActiveClientIdentityV1 } from '../../threshold/ed25519/yaoActiveClientRegistry';
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
  EmailOtpEd25519YaoExportContextV1,
  EmailOtpEd25519YaoExportSubjectV1,
} from '../../session/emailOtp/ed25519YaoSealedRecovery';
import type { EmailOtpEd25519YaoActiveCapabilityDescriptorV1 } from '../../workerManager/workerTypes';
import type {
  PasskeyEd25519YaoExportContextResolutionV1,
  PasskeyEd25519YaoExportContextV1,
} from '../../session/passkey/ed25519YaoWarmRecovery';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';

export type Ed25519YaoExportFlowDeps = {
  touchConfirm: Pick<
    UiConfirmRuntimeBridgePort,
    'exportPrivateKeysWithUi' | 'initialize' | 'requestUserConfirmation'
  >;
  resolveActiveCapability: (
    identity: Ed25519YaoActiveClientIdentityV1,
  ) => NearEd25519YaoSigningCapability | null;
  recoverPasskeyCapability: (
    laneIdentity: ExactPasskeyEd25519SigningLaneIdentity,
  ) => Promise<NearEd25519YaoSigningCapability>;
  resolvePasskeyExportContext: (
    laneIdentity: ExactPasskeyEd25519SigningLaneIdentity,
  ) => Promise<PasskeyEd25519YaoExportContextResolutionV1>;
  emailOtp: {
    requestExportChallenge: EmailOtpWalletSessionExportAuthorizationDeps['requestExportChallenge'];
    resolveExportContext: (
      subject: EmailOtpEd25519YaoExportSubjectV1,
    ) => Promise<EmailOtpEd25519YaoExportContextV1>;
    exportSeedWithFreshAuthorization: (args: {
      walletSession: ReturnType<typeof walletSessionRefFromSession>;
      challengeId: string;
      otpCode: string;
      providerSubjectId: string;
      walletSessionJwt: string;
      nearAccountId: string;
      nearEd25519SigningKeyId: string;
      signerSlot: number;
      thresholdSessionId: string;
      signingGrantId: string;
      authLane: Extract<EmailOtpEd25519YaoExportContextV1['authLane'], { curve: 'ed25519' }>;
      runtimePolicyScope: NearEd25519YaoSigningCapability['walletSessionState']['runtimePolicyScope'];
      capability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1;
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

type ResolvedPasskeyEd25519YaoExportContext = {
  laneIdentity: ExactPasskeyEd25519SigningLaneIdentity;
  relayerUrl: string;
  walletSessionJwt: string;
  capability: RouterAbEd25519YaoExportWorkerPayloadV1['capability'];
};

type ExactPasskeyEd25519SigningLaneIdentity = ExactEd25519SigningLaneIdentity & {
  auth: Extract<ExactEd25519SigningLaneIdentity['auth'], { kind: 'passkey' }>;
};

function isExactPasskeyEd25519SigningLaneIdentity(
  laneIdentity: ExactEd25519SigningLaneIdentity,
): laneIdentity is ExactPasskeyEd25519SigningLaneIdentity {
  return laneIdentity.auth.kind === 'passkey';
}

function requirePasskeyExportLaneIdentity(
  args: ExportEd25519YaoKeyArgs,
): ExactPasskeyEd25519SigningLaneIdentity {
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

type ExactEmailOtpEd25519SigningLaneIdentity = ExactEd25519SigningLaneIdentity & {
  auth: Extract<ExactEd25519SigningLaneIdentity['auth'], { kind: 'email_otp' }>;
};

function isExactEmailOtpEd25519SigningLaneIdentity(
  laneIdentity: ExactEd25519SigningLaneIdentity,
): laneIdentity is ExactEmailOtpEd25519SigningLaneIdentity {
  return laneIdentity.auth.kind === 'email_otp';
}

function requireEmailOtpExportLaneIdentity(
  args: ExportEd25519YaoKeyArgs,
): ExactEmailOtpEd25519SigningLaneIdentity {
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

function activeCapabilityIdentity(
  laneIdentity: ExactEd25519SigningLaneIdentity,
): Ed25519YaoActiveClientIdentityV1 {
  return {
    walletId: laneIdentity.signer.account.wallet.walletId,
    nearAccountId: laneIdentity.signer.account.nearAccountId,
    thresholdSessionId: String(laneIdentity.thresholdSessionId),
  };
}

function passkeyExportStableIdentityMatches(args: {
  selected: ExactPasskeyEd25519SigningLaneIdentity;
  current: ExactPasskeyEd25519SigningLaneIdentity;
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
  selectedLaneIdentity: ExactPasskeyEd25519SigningLaneIdentity;
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
  return {
    laneIdentity: currentLaneIdentity,
    relayerUrl: capability.walletSessionState.relayerUrl,
    walletSessionJwt: capability.walletSessionState.walletSessionAuth.walletSessionJwt,
    capability: {
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
): ExactPasskeyEd25519SigningLaneIdentity {
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
  selectedLaneIdentity: ExactPasskeyEd25519SigningLaneIdentity;
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
  const lifecycle = descriptor.capability.lifecycle;
  return {
    laneIdentity: currentLaneIdentity,
    relayerUrl: args.context.relayerUrl,
    walletSessionJwt: descriptor.session.walletSessionJwt,
    capability: {
      scope: {
        lifecycle_id: lifecycle.lifecycleId,
        root_share_epoch: lifecycle.rootShareEpoch,
        account_id: lifecycle.accountId,
        wallet_session_id: lifecycle.walletSessionId,
        signer_set_id: lifecycle.signerSetId,
        signing_worker_id: lifecycle.signingWorkerId,
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
  const activeCapability = deps.resolveActiveCapability(activeCapabilityIdentity(laneIdentity));
  if (activeCapability) {
    return resolvePasskeyExportContextFromActiveCapability({
      capability: activeCapability,
      selectedLaneIdentity: laneIdentity,
    });
  }
  const durableContext = await deps.resolvePasskeyExportContext(laneIdentity);
  switch (durableContext.kind) {
    case 'ready':
      return requireDurablePasskeyExportContext({
        context: durableContext.context,
        selectedLaneIdentity: laneIdentity,
      });
    case 'capability_recovery_required': {
      const capability = await deps.recoverPasskeyCapability(laneIdentity);
      return resolvePasskeyExportContextFromActiveCapability({
        capability,
        selectedLaneIdentity: laneIdentity,
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
  context: EmailOtpEd25519YaoExportContextV1;
  laneIdentity: ExactEmailOtpEd25519SigningLaneIdentity;
}> {
  const laneIdentity = requireEmailOtpExportLaneIdentity(args);
  const context = await deps.emailOtp.resolveExportContext({
    walletId: laneIdentity.signer.account.wallet.walletId,
    nearAccountId: laneIdentity.signer.account.nearAccountId,
    nearEd25519SigningKeyId: laneIdentity.signer.nearEd25519SigningKeyId,
    signerSlot: laneIdentity.signer.signerSlot,
    thresholdSessionId: laneIdentity.thresholdSessionId,
    signingGrantId: laneIdentity.signingGrantId,
    providerSubjectId: laneIdentity.auth.providerSubjectId,
  });
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
    walletSessionJwt: args.resolved.walletSessionJwt,
    flowId: args.input.flowId,
    viewerSessionId: args.viewerSessionId,
    exactLane: {
      nearEd25519SigningKeyId: String(signer.nearEd25519SigningKeyId),
      signerSlot: signer.signerSlot,
      credentialIdB64u: args.resolved.laneIdentity.auth.credentialIdB64u,
      signingGrantId: String(args.resolved.laneIdentity.signingGrantId),
      thresholdSessionId: String(args.resolved.laneIdentity.thresholdSessionId),
      activeStateSessionId: args.resolved.capability.scope.wallet_session_id,
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

export async function exportEd25519YaoKeyWithFreshPasskey(
  deps: Ed25519YaoExportFlowDeps,
  args: ExportEd25519YaoKeyArgs,
): Promise<{ accountId: string; exportedSchemes: Array<'ed25519'> }> {
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
  const result = await deps.touchConfirm.exportPrivateKeysWithUi(
    buildWorkerPayload({
      resolved,
      viewerSessionId,
      input: args,
      theme: deps.theme,
    }),
    { onViewerLifecycle },
  );
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

export async function exportEd25519YaoKeyWithFreshEmailOtp(
  deps: Ed25519YaoExportFlowDeps,
  args: ExportEd25519YaoKeyArgs,
): Promise<{ accountId: string; exportedSchemes: Array<'ed25519'> }> {
  const resolved = await resolveExactEmailOtpExportContext(deps, args);
  const publicKey = `ed25519:${base58Encode(
    Uint8Array.from(resolved.context.capability.registeredPublicKey),
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
      thresholdSessionId: String(resolved.laneIdentity.thresholdSessionId),
      signingGrantId: String(resolved.laneIdentity.signingGrantId),
      authLane: resolved.context.authLane,
      publicKey,
      curve: 'ed25519',
      chain: 'near',
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
  const artifact = await deps.emailOtp.exportSeedWithFreshAuthorization({
    walletSession: walletSessionRefFromSession({
      walletId: args.walletId,
      walletSessionUserId: args.walletId,
    }),
    challengeId: authorization.challengeId,
    otpCode: authorization.otpCode,
    providerSubjectId: resolved.laneIdentity.auth.providerSubjectId,
    walletSessionJwt: resolved.context.walletSessionJwt,
    nearAccountId: String(args.nearAccountId),
    nearEd25519SigningKeyId: String(resolved.laneIdentity.signer.nearEd25519SigningKeyId),
    signerSlot: resolved.laneIdentity.signer.signerSlot,
    thresholdSessionId: String(resolved.laneIdentity.thresholdSessionId),
    signingGrantId: String(resolved.laneIdentity.signingGrantId),
    authLane: resolved.context.authLane,
    runtimePolicyScope: resolved.context.runtimePolicyScope,
    capability: resolved.context.capability,
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
