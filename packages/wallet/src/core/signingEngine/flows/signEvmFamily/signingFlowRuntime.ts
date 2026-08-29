import type {
  SigningSessionPlan,
  SigningOperationContext,
} from '../../session/operationState/types';
import type { SigningOperationTransitionObserver } from '../shared/signingStateMachine';
import type { EvmFamilySigningDeps } from '../../interfaces/operationDeps';
import type { EvmFamilyLifecycleEventCallback, EvmFamilySenderSignatureAlgorithm } from './types';
import { loadSecp256k1EngineCtor, loadWebAuthnP256EngineCtor } from './signerLoader';
import type { EcdsaSigningMaterialPlan, SupersededEcdsaSigningMaterial } from './signingFlow';
import type { EvmFamilyThresholdEcdsaStepUpRuntime } from './requireEvmFamilyStepUpAuth';
import type { EvmFamilySigningAuthSideEffect } from './freshAuthRetryPolicy';
import {
  attachReusableEcdsaWalletSessionAuthorization,
  buildActiveWalletAuthorityReadySecp256k1Material,
  resolveHydratedSecp256k1SigningMaterial,
} from './readySecp256k1Material';
import { resolveExactEcdsaCapabilityRuntime } from '../../session/material/activeEcdsaCapabilityRuntime';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import {
  walletAuthAuthoritiesMatch,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import type { SignerAuthMethod } from '@shared/utils/signerDomain';
import {
  walletSessionAuthorizations,
  walletSessionAuthorizationIdForCurve,
  WalletSessionAuthorizationUpgradeRequiredError,
  type WalletSessionOperationCredentialV1,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { IndexedDBManager } from '@/core/indexedDB';
import {
  resolveExactWalletAuthAuthority,
  type OwnerLaneScopeStores,
} from '../../session/identity/ownerLaneScope';
import { readEmailOtpProviderSubjectForWalletV1 } from '../../threshold/ed25519/yaoPublicCapabilityReferences';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EvmSigningRequest } from '../../chains/evm/evmSigning.types';
import type { TempoSigningRequest } from '../../chains/tempo/tempoSigning.types';
import { requireEvmFamilyEcdsaSigner } from '../../session/identity/exactSigningLaneIdentity';
import type { ExactEcdsaSigningLaneIdentity } from '../../session/identity/exactSigningLaneIdentity';

/** The exact material activation the signer binding names. Signing serializes
 * per activation, so this is the only identity the runtime needs — no selected
 * lane, and therefore no authorization. */
type EvmFamilyEcdsaMaterialActivation = ReturnType<
  typeof requireEvmFamilyEcdsaSigner
>['materialActivation'];
import {
  authorizeEvmFamilyEcdsaOperationStepUp,
  prepareEvmFamilyEcdsaOperationStepUp,
} from './thresholdAdmission';
import { emitEvmFamilySigningOperationTrace } from './events';
import { resolveThresholdEcdsaSigningQueueKey } from '../../threshold/ecdsa/signingQueue';
import type {
  ActiveEvmFamilyWalletSessionAuthorization,
  CanonicalEvmFamilyEcdsaSigningCapability,
} from '../../session/material/ecdsaSigningCapability';
import type { ActiveEcdsaCapabilityManifest } from '../../session/material/ecdsaCapabilityManifest';
import type { OperationDigestSet } from '@shared/authorization/operationFingerprint';
import {
  resolveActiveWalletAuthorityEcdsaRuntimeV1,
  type ActiveWalletAuthorityEcdsaSigningAuthPlan,
  type ActiveWalletAuthorityEcdsaRuntimeV1,
} from '../../session/material/activeWalletAuthorityEcdsaRuntime';
import type { TransactionSigningIntent } from '../../session/operationState/transactionState';

export type ActiveWalletAuthorityEvmFamilyFlowRuntime = {
  readonly runtime: ActiveWalletAuthorityEcdsaRuntimeV1;
  readonly intent: TransactionSigningIntent;
  readonly confirmationAuthPlan: ActiveWalletAuthorityEcdsaSigningAuthPlan;
};

export function buildActiveWalletAuthorityConfirmationAuthPlan(
  runtime: ActiveWalletAuthorityEcdsaRuntimeV1,
): ActiveWalletAuthorityEcdsaSigningAuthPlan {
  return {
    kind: 'active_wallet_authority',
    method: runtime.auth.kind,
    accountId: String(runtime.walletId),
    intent: 'transaction_sign',
    curve: 'ecdsa',
    walletSessionId: runtime.operationCredential.walletSessionId,
    authorityId: runtime.authorityId,
    authMethodId: runtime.walletAuthMethodId,
    expiresAtMs: runtime.session.expiresAtMs,
  };
}

function signerAuthMethodForWalletAuthority(authority: WalletAuthAuthority): SignerAuthMethod {
  switch (authority.factor.kind) {
    case 'passkey':
      return 'passkey';
    case 'email_otp':
      return 'email_otp';
    default:
      authority.factor satisfies never;
      throw new Error('[SigningEngine] unsupported wallet authorization factor');
  }
}

async function runSerializedEcdsaMaterialUse<T>(
  args: {
    deps: EvmFamilySigningDeps;
    walletId: WalletId;
    materialActivation: EvmFamilyEcdsaMaterialActivation;
    shouldAbort?: () => boolean;
  },
  task: () => Promise<T>,
): Promise<T> {
  return await args.deps.withThresholdEcdsaSigningQueue({
    queueKey: resolveThresholdEcdsaSigningQueueKey({
      materialActivation: args.materialActivation,
    }),
    walletId: args.walletId,
    enabled: true,
    ...(args.shouldAbort ? { shouldAbort: args.shouldAbort } : {}),
    task,
  });
}

function requireEvmFamilyRelayerUrl(deps: EvmFamilySigningDeps): string {
  const relayerUrl = String(deps.seamsWebConfigs.network.relayer?.url || '').trim();
  if (!relayerUrl) {
    throw new Error('[SigningEngine] EVM-family signing requires relayerUrl');
  }
  return relayerUrl;
}

async function resolveCurrentActiveWalletAuthorityRuntime(args: {
  readonly prepared: ActiveWalletAuthorityEcdsaRuntimeV1;
  readonly signer: ReturnType<typeof requireEvmFamilyEcdsaSigner>;
}): Promise<ActiveWalletAuthorityEcdsaRuntimeV1> {
  const current = await resolveActiveWalletAuthorityEcdsaRuntimeV1({
    walletId: args.signer.walletId,
    chainTarget: args.signer.chainTarget,
    requiredCapability: 'sign',
    materialActivation: args.signer.materialActivation,
  });
  if (current.kind !== 'resolved') {
    throw new Error(`[SigningEngine] active Wallet Authority ECDSA runtime is ${current.reason}`);
  }
  const runtime = current.runtime;
  if (
    runtime.authorityId !== args.prepared.authorityId ||
    runtime.walletAuthMethodId !== args.prepared.walletAuthMethodId ||
    runtime.authorityDigestB64u !== args.prepared.authorityDigestB64u ||
    runtime.authorityRevocationEpoch !== args.prepared.authorityRevocationEpoch ||
    runtime.walletSessionId !== args.prepared.walletSessionId ||
    runtime.publicFacts.keyHandle !== args.signer.keyHandle
  ) {
    throw new Error('[SigningEngine] active Wallet Authority ECDSA runtime was replaced');
  }
  return runtime;
}

async function getEcdsaOperationWalletAuthMethod(walletAuthMethodId: string) {
  return await IndexedDBManager.getWalletAuthMethodV2(walletAuthMethodId);
}

async function listEcdsaOperationWalletAuthMethods(walletId: string) {
  return await IndexedDBManager.listWalletAuthMethodsForWallet(walletId);
}

async function getEcdsaOperationPasskeyAuthenticator(args: {
  readonly walletId: string;
  readonly credentialId: string;
}) {
  return await IndexedDBManager.getWalletPasskeyAuthenticator(args);
}

async function readEcdsaOperationProviderSubject(walletId: string) {
  return await readEmailOtpProviderSubjectForWalletV1(IndexedDBManager, walletId);
}

const ecdsaOperationFactorStores: OwnerLaneScopeStores = {
  getWalletAuthMethodV2: getEcdsaOperationWalletAuthMethod,
  listWalletAuthMethodsForWallet: listEcdsaOperationWalletAuthMethods,
  getWalletPasskeyAuthenticator: getEcdsaOperationPasskeyAuthenticator,
  readEmailOtpProviderSubjectForWallet: readEcdsaOperationProviderSubject,
};

export type ExactEcdsaOperationCredentialResolution =
  | {
      readonly kind: 'resolved';
      readonly operationCredential: WalletSessionOperationCredentialV1;
      readonly reason?: never;
    }
  | {
      readonly kind: 'upgrade_required';
      readonly operationCredential?: never;
      readonly reason?: never;
    }
  | {
      readonly kind: 'unavailable';
      readonly reason:
        | 'selected_authority_unavailable'
        | 'selected_authority_mismatch'
        | 'missing_wallet_session'
        | 'wallet_session_expired'
        | 'wallet_session_identity_mismatch'
        | 'wallet_session_capability_mismatch'
        | 'persistence_unavailable';
      readonly operationCredential?: never;
    };

export async function resolveExactEcdsaOperationCredential(args: {
  readonly walletId: WalletId;
  readonly authority: WalletAuthAuthority;
  readonly materialActivation: EvmFamilyEcdsaMaterialActivation;
  readonly nowMs: number;
}): Promise<ExactEcdsaOperationCredentialResolution> {
  let selected: Awaited<ReturnType<typeof IndexedDBManager.resolveSelectedWalletAuthority>>;
  try {
    selected = await IndexedDBManager.resolveSelectedWalletAuthority(String(args.walletId));
  } catch {
    return { kind: 'unavailable', reason: 'persistence_unavailable' };
  }
  if (selected.kind !== 'resolved') {
    return { kind: 'unavailable', reason: 'selected_authority_unavailable' };
  }
  const { selection, authMethod, authority } = selected;
  if (
    selection.lockState !== 'unlocked' ||
    authMethod.status !== 'active' ||
    authority.state !== 'active' ||
    selection.walletId !== args.walletId ||
    authMethod.walletId !== args.walletId ||
    authority.walletId !== args.walletId ||
    selection.walletAuthMethodId !== authMethod.walletAuthMethodId ||
    authMethod.walletAuthorityId !== authority.authorityId ||
    args.authority.walletId !== args.walletId ||
    args.authority.bindingId !== authMethod.walletAuthMethodId
  ) {
    return { kind: 'unavailable', reason: 'selected_authority_mismatch' };
  }
  let selectedFactorAuthority: WalletAuthAuthority;
  try {
    selectedFactorAuthority = await resolveExactWalletAuthAuthority({
      authMethod,
      stores: ecdsaOperationFactorStores,
    });
  } catch {
    return { kind: 'unavailable', reason: 'selected_authority_mismatch' };
  }
  if (!walletAuthAuthoritiesMatch(selectedFactorAuthority, args.authority)) {
    return { kind: 'unavailable', reason: 'selected_authority_mismatch' };
  }
  const ecdsaActivation = authority.signerActivations.ecdsa;
  if (
    !ecdsaActivation ||
    ecdsaActivation.signer.walletId !== args.walletId ||
    !mpcMaterialActivationRefsEqual(ecdsaActivation.materialActivation, args.materialActivation)
  ) {
    return { kind: 'unavailable', reason: 'selected_authority_mismatch' };
  }

  let read: Awaited<
    ReturnType<typeof walletSessionAuthorizations.readExactWithOperationCredential>
  >;
  try {
    read = await walletSessionAuthorizations.readExactWithOperationCredential({
      walletId: args.walletId,
      authorityId: authority.authorityId,
      authMethodId: authMethod.walletAuthMethodId,
    });
  } catch {
    return { kind: 'unavailable', reason: 'persistence_unavailable' };
  }
  switch (read.kind) {
    case 'missing':
      return { kind: 'unavailable', reason: 'missing_wallet_session' };
    case 'upgrade_required':
      return { kind: 'upgrade_required' };
    case 'found':
      break;
  }

  const session = read.record;
  const operationCredential = read.operationCredential;
  if (session.expiresAtMs <= args.nowMs) {
    return { kind: 'unavailable', reason: 'wallet_session_expired' };
  }
  if (
    session.walletId !== args.walletId ||
    session.authorityId !== authority.authorityId ||
    session.authMethodId !== authMethod.walletAuthMethodId ||
    session.authorityDigestB64u !== authority.authorityDigestB64u ||
    session.authorityRevocationEpoch !== authority.revocationEpoch ||
    operationCredential.walletSessionId.trim().length === 0 ||
    operationCredential.token.trim().length === 0
  ) {
    return { kind: 'unavailable', reason: 'wallet_session_identity_mismatch' };
  }
  let matchingCapabilityCount = 0;
  for (const subject of session.capabilitySubjects) {
    if (
      subject.kind === 'sign' &&
      subject.keyFamily === 'ecdsa_secp256k1' &&
      mpcMaterialActivationRefsEqual(subject.materialActivation, args.materialActivation)
    ) {
      matchingCapabilityCount += 1;
    }
  }
  if (matchingCapabilityCount !== 1) {
    return { kind: 'unavailable', reason: 'wallet_session_capability_mismatch' };
  }
  return { kind: 'resolved', operationCredential };
}

function requireExactEcdsaOperationCredentialToken(
  resolution: ExactEcdsaOperationCredentialResolution,
): string {
  switch (resolution.kind) {
    case 'resolved':
      return resolution.operationCredential.token;
    case 'upgrade_required':
      throw new WalletSessionAuthorizationUpgradeRequiredError(
        '[SigningEngine] exact ECDSA Wallet Session requires a newer client',
      );
    case 'unavailable':
      throw new Error(
        `[SigningEngine] exact ECDSA Wallet Session is unavailable: ${resolution.reason}`,
      );
  }
}

/** R90-INV-010. The wallet's active manifest names the material that may be
 * used right now. When it has moved on from the one this operation was prepared
 * against, the preparation is superseded -- material activation is advance-only,
 * so the prepared side is always the stale one. That is a re-resolution, not a
 * failure and not a request for the wrong material. */
export function ecdsaSigningMaterialSupersession(args: {
  preparedMaterialActivation: EvmFamilyEcdsaMaterialActivation;
  currentMaterialActivation: EvmFamilyEcdsaMaterialActivation;
}): SupersededEcdsaSigningMaterial | null {
  if (
    mpcMaterialActivationRefsEqual(args.currentMaterialActivation, args.preparedMaterialActivation)
  ) {
    return null;
  }
  return {
    kind: 'superseded',
    supersessionKind: 'material_activation_replaced',
    preparedMaterialActivation: args.preparedMaterialActivation,
    currentMaterialActivation: args.currentMaterialActivation,
  };
}

export function ecdsaSigningCapabilitySupersession(args: {
  preparedCapability: CanonicalEvmFamilyEcdsaSigningCapability;
  currentManifest: ActiveEcdsaCapabilityManifest;
}): SupersededEcdsaSigningMaterial | null {
  const preparedManifest = args.preparedCapability.manifest;
  const preparedActivation = preparedManifest.activation.materialActivation;
  const currentActivation = args.currentManifest.activation.materialActivation;
  const activationSupersession = ecdsaSigningMaterialSupersession({
    preparedMaterialActivation: preparedActivation,
    currentMaterialActivation: currentActivation,
  });
  if (activationSupersession) return activationSupersession;
  const preparedSigner = preparedManifest.signer;
  const currentSigner = args.currentManifest.signer;
  if (
    String(preparedManifest.identity.manifestId) ===
      String(args.currentManifest.identity.manifestId) &&
    Number(preparedManifest.identity.manifestRevision) ===
      Number(args.currentManifest.identity.manifestRevision) &&
    String(preparedSigner.capability) === String(currentSigner.capability) &&
    String(preparedSigner.authority.walletId) === String(currentSigner.authority.walletId) &&
    String(preparedSigner.authority.authorityDigest) ===
      String(currentSigner.authority.authorityDigest)
  ) {
    return null;
  }
  return {
    kind: 'superseded',
    supersessionKind: 'capability_authority_replaced',
    preparedMaterialActivation: preparedActivation,
    currentMaterialActivation: currentActivation,
  };
}

export function ecdsaSigningAuthorizationSupersession(args: {
  preparedAuthorization: ActiveEvmFamilyWalletSessionAuthorization;
  currentAuthorization: ActiveEvmFamilyWalletSessionAuthorization | null;
  materialActivation: EvmFamilyEcdsaMaterialActivation;
}): SupersededEcdsaSigningMaterial | null {
  const prepared = args.preparedAuthorization.projection;
  const currentAuthorization = args.currentAuthorization;
  const current = currentAuthorization?.projection;
  const preparedAuthorizationId = walletSessionAuthorizationIdForCurve(prepared, 'ecdsa');
  const currentAuthorizationId = current
    ? walletSessionAuthorizationIdForCurve(current, 'ecdsa')
    : null;
  if (
    currentAuthorization &&
    current &&
    String(current.walletId) === String(prepared.walletId) &&
    String(current.walletSessionId) === String(prepared.walletSessionId) &&
    currentAuthorizationId !== null &&
    currentAuthorizationId === preparedAuthorizationId &&
    String(current.quotaId) === String(prepared.quotaId) &&
    String(currentAuthorization.status.walletSessionId) ===
      String(args.preparedAuthorization.status.walletSessionId) &&
    String(currentAuthorization.status.quotaId) ===
      String(args.preparedAuthorization.status.quotaId) &&
    String(current.authority.authorityDigest) === String(prepared.authority.authorityDigest)
  ) {
    return null;
  }
  return {
    kind: 'superseded',
    supersessionKind: 'reusable_authorization_replaced',
    preparedMaterialActivation: args.materialActivation,
    currentMaterialActivation: args.materialActivation,
  };
}

async function resolveEcdsaSigningMaterialHydrationPlan(args: {
  capability: CanonicalEvmFamilyEcdsaSigningCapability;
  preparedAuthorization: ActiveEvmFamilyWalletSessionAuthorization | null;
  currentAuthorization: ActiveEvmFamilyWalletSessionAuthorization | null;
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  materialActivation: EvmFamilyEcdsaMaterialActivation;
  relayerUrl: string;
  workerCtx: ReturnType<EvmFamilySigningDeps['getSignerWorkerContext']>;
}): Promise<EcdsaSigningMaterialPlan> {
  // Resolve the active capability material first. Reusable authorization is
  // checked separately; without it, the hydrated material requires operation
  // step-up authorization.
  const activeRuntimeResolution = await resolveExactEcdsaCapabilityRuntime({
    manifest: args.capability.manifest,
    chainTarget: args.chainTarget,
    relayerUrl: args.relayerUrl,
  });
  if (activeRuntimeResolution.kind !== 'resolved') {
    return {
      kind: 'failed',
      failure: { kind: 'unavailable', reason: 'runtime_correlation_mismatch' },
    };
  }
  const superseded = ecdsaSigningCapabilitySupersession({
    preparedCapability: args.capability,
    currentManifest: activeRuntimeResolution.manifest,
  });
  if (superseded) return { kind: 'superseded', replacement: superseded };
  if (args.preparedAuthorization) {
    const authorizationSupersession = ecdsaSigningAuthorizationSupersession({
      preparedAuthorization: args.preparedAuthorization,
      currentAuthorization: args.currentAuthorization,
      materialActivation: args.materialActivation,
    });
    if (authorizationSupersession) {
      return { kind: 'superseded', replacement: authorizationSupersession };
    }
  }
  const resolution = await resolveHydratedSecp256k1SigningMaterial({
    capability: args.capability,
    runtime: activeRuntimeResolution.runtime,
    chainTarget: args.chainTarget,
    materialActivation: args.materialActivation,
    workerCtx: args.workerCtx,
  });
  if (resolution.kind === 'unavailable') {
    return { kind: 'failed', failure: resolution };
  }
  if (!args.preparedAuthorization) {
    return {
      kind: 'authorization_required',
      requirement: {
        kind: 'material_for_step_up',
        material: resolution.material,
      },
    };
  }
  if (!args.currentAuthorization) {
    return {
      kind: 'superseded',
      replacement: {
        kind: 'superseded',
        supersessionKind: 'reusable_authorization_replaced',
        preparedMaterialActivation: args.materialActivation,
        currentMaterialActivation: args.materialActivation,
      },
    };
  }
  return {
    kind: 'ready',
    value: {
      kind: 'material_from_canonical_capability',
      material: attachReusableEcdsaWalletSessionAuthorization({
        material: resolution.material,
        capability: args.capability,
        authorization: args.currentAuthorization,
      }),
    },
  };
}

export async function createEvmFamilySigningFlowRuntime(args: {
  deps: EvmFamilySigningDeps;
  walletSession: WalletSessionRef;
  request: TempoSigningRequest | EvmSigningRequest;
  chainTarget: ThresholdEcdsaChainTarget;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  signingSessionPlan?: SigningSessionPlan;
  emailOtpSigningForFlow?: EvmFamilyThresholdEcdsaStepUpRuntime['emailOtpSigning'];
  confirmationConfigOverride?: unknown;
  shouldAbort?: () => boolean;
  onEvent?: EvmFamilyLifecycleEventCallback;
  onAuthSideEffectStarted?: (sideEffect: EvmFamilySigningAuthSideEffect) => void;
  signingOperation?: SigningOperationContext;
  onSigningOperationTransition?: SigningOperationTransitionObserver;
  // The exact material identity, whether or not a reusable Wallet Session
  // authorizes it. Everything below is resolved from wallet, chain target and
  // material activation.
  getEcdsaSigningLaneIdentity: () => ExactEcdsaSigningLaneIdentity;
  activeWalletAuthority?: ActiveWalletAuthorityEvmFamilyFlowRuntime;
}) {
  const [Secp256k1Engine, WebAuthnP256Engine] = await Promise.all([
    loadSecp256k1EngineCtor(),
    loadWebAuthnP256EngineCtor(),
  ]);
  const workerCtx = args.deps.getSignerWorkerContext();
  const ctx = args.deps.touchConfirm.getContext();
  const walletId = toWalletId(args.walletSession.walletId);
  const relayerUrl = requireEvmFamilyRelayerUrl(args.deps);

  const resolvedSigner =
    args.senderSignatureAlgorithm === 'secp256k1'
      ? requireEvmFamilyEcdsaSigner(
          args.getEcdsaSigningLaneIdentity(),
          'ECDSA signing material hydration',
        )
      : undefined;
  if (args.activeWalletAuthority && !resolvedSigner) {
    throw new Error(
      '[SigningEngine] active Wallet Authority runtime requires a threshold ECDSA signer',
    );
  }
  const capability =
    resolvedSigner && !args.activeWalletAuthority
      ? await args.deps.resolveCanonicalEcdsaSigningCapability({
          walletId: resolvedSigner.walletId,
          chainTarget: resolvedSigner.chainTarget,
          materialActivation: resolvedSigner.materialActivation,
        })
      : undefined;
  const activeAuthorization =
    resolvedSigner && !args.activeWalletAuthority
      ? await args.deps.resolveActiveEcdsaWalletSessionAuthorization(resolvedSigner.walletId)
      : null;
  const exactOperationCredentialScope =
    resolvedSigner && capability && !args.activeWalletAuthority
      ? {
          walletId: resolvedSigner.walletId,
          authority: capability.authority,
          materialActivation: resolvedSigner.materialActivation,
        }
      : undefined;
  const thresholdEcdsaStepUpRuntime: EvmFamilyThresholdEcdsaStepUpRuntime | undefined =
    capability && exactOperationCredentialScope
      ? {
          ...(args.emailOtpSigningForFlow ? { emailOtpSigning: args.emailOtpSigningForFlow } : {}),
          // Without an active reusable Wallet Session the candidate is
          // auth-neutral, so the operation must be authorized by a step-up on
          // the capability's own factor rather than a warm session.
          reusableAuthorization: activeAuthorization
            ? { kind: 'active' }
            : {
                kind: 'absent',
                requiredFactor: signerAuthMethodForWalletAuthority(capability.authority),
              },
          operationStepUp: {
            prepare: async ({ operation, operationDigests, material }) =>
              await prepareEvmFamilyEcdsaOperationStepUp({
                operation,
                operationDigests,
                material,
              }),
            authorize: async ({ authorization, prepared, material }) => {
              args.onAuthSideEffectStarted?.(
                authorization.kind === 'passkey' ? 'passkey_reauth' : 'email_otp_challenge',
              );
              const walletSessionToken = requireExactEcdsaOperationCredentialToken(
                await resolveExactEcdsaOperationCredential({
                  walletId: exactOperationCredentialScope.walletId,
                  authority: exactOperationCredentialScope.authority,
                  materialActivation: exactOperationCredentialScope.materialActivation,
                  nowMs: Date.now(),
                }),
              );
              return await authorizeEvmFamilyEcdsaOperationStepUp({
                relayerUrl,
                authority: capability.authority,
                authorization,
                prepared,
                material,
                walletSessionToken,
              });
            },
          },
          ...(args.onAuthSideEffectStarted
            ? { onAuthSideEffectStarted: args.onAuthSideEffectStarted }
            : {}),
        }
      : undefined;

  const secp256k1Engine = new Secp256k1Engine({
    getRpId: () => ctx.touchIdPrompt.getRpId(),
    workerCtx,
    shouldAbort: args.shouldAbort,
  });
  const activeWalletAuthority = args.activeWalletAuthority;
  const activeWalletAuthorityAuthorization =
    activeWalletAuthority && resolvedSigner
      ? {
          kind: 'active_wallet_authority' as const,
          confirmationAuthPlan: activeWalletAuthority.confirmationAuthPlan,
          sign: async (input: {
            readonly requestId: string;
            readonly operationId: string;
            readonly operationDigests: OperationDigestSet;
            readonly signingDigest32: Uint8Array;
          }) => {
            if (String(activeWalletAuthority.intent.operationId) !== input.operationId) {
              throw new Error(
                '[SigningEngine] active Wallet Authority signing operation identity changed',
              );
            }
            return await runSerializedEcdsaMaterialUse(
              {
                deps: args.deps,
                walletId: resolvedSigner.walletId,
                materialActivation: resolvedSigner.materialActivation,
                ...(args.shouldAbort ? { shouldAbort: args.shouldAbort } : {}),
              },
              async () => {
                const runtime = await resolveCurrentActiveWalletAuthorityRuntime({
                  prepared: activeWalletAuthority.runtime,
                  signer: resolvedSigner,
                });
                const readyMaterial = buildActiveWalletAuthorityReadySecp256k1Material({
                  authorityRuntime: runtime,
                  chainTarget: resolvedSigner.chainTarget,
                  relayerUrl,
                });
                return await secp256k1Engine.signReady(
                  {
                    kind: 'digest',
                    algorithm: 'secp256k1',
                    digest32: input.signingDigest32,
                  },
                  readyMaterial,
                  {
                    intent: activeWalletAuthority.intent,
                    authPlan: activeWalletAuthority.confirmationAuthPlan,
                  },
                  input.operationDigests,
                );
              },
            );
          },
        }
      : undefined;

  const flowArgs = {
    ctx,
    touchConfirm: args.deps.touchConfirm,
    workerCtx,
    walletId,
    onEvent: args.onEvent,
    engines: {
      secp256k1: secp256k1Engine,
      webauthnP256: new WebAuthnP256Engine(workerCtx),
    },
    ...(resolvedSigner && capability
      ? {
          runEcdsaMaterialUse: runSerializedEcdsaMaterialUse.bind(null, {
            deps: args.deps,
            walletId: resolvedSigner.walletId,
            materialActivation: resolvedSigner.materialActivation,
            ...(args.shouldAbort ? { shouldAbort: args.shouldAbort } : {}),
          }),
          resolveEcdsaSigningMaterialPlan: async () =>
            await resolveEcdsaSigningMaterialHydrationPlan({
              capability,
              preparedAuthorization: activeAuthorization,
              currentAuthorization: activeAuthorization
                ? await args.deps.resolveActiveEcdsaWalletSessionAuthorization(
                    resolvedSigner.walletId,
                  )
                : null,
              walletId: resolvedSigner.walletId,
              chainTarget: resolvedSigner.chainTarget,
              materialActivation: resolvedSigner.materialActivation,
              relayerUrl,
              workerCtx,
            }),
        }
      : {}),
    ...(activeWalletAuthorityAuthorization
      ? { authorization: activeWalletAuthorityAuthorization }
      : {}),
    ...(args.signingSessionPlan ? { signingSessionPlan: args.signingSessionPlan } : {}),
    ...(args.signingOperation ? { signingOperation: args.signingOperation } : {}),
    onSigningOperationTransition:
      args.onSigningOperationTransition || emitEvmFamilySigningOperationTrace,
    ...(thresholdEcdsaStepUpRuntime ? { thresholdEcdsaStepUpRuntime } : {}),
    confirmationConfigOverride: args.confirmationConfigOverride,
  };

  return { flowArgs };
}
