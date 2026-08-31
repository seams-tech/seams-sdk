import type { RuntimePorts } from '@/core/platform';
import { IndexedDBManager, walletSessionAuthorizations } from '@/core/indexedDB';
import type { OwnerLaneScope } from '@/core/signingEngine/session/identity/signingLaneAuthBinding';
import {
  resolveExactWalletAuthAuthority as resolveExactWalletAuthAuthorityFromMethod,
  type OwnerLaneScopeStores,
} from '@/core/signingEngine/session/identity/ownerLaneScope';
import { IndexedDbEcdsaCapabilityManifestStore } from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import { SIGNING_SESSION_SEAL_GROUP_ID } from '@shared/utils/signingSessionSeal';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import {
  createRelayerExactWalletSessionStatusPort,
  type ExactWalletSessionStatus,
} from '@/core/rpcClients/relayer/walletSessionAuthorizationStatus';
import { readPersistedAvailableSigningLanesForSigning as readPersistedAvailableSigningLanesForSigningOperation } from '@/core/signingEngine/session/availability/persistedAvailableSigningLanes';
import { createCanonicalWalletSessionStatusReader } from '@/core/signingEngine/session/lifecycle/canonicalWalletSessionStatus';
import type { EmailOtpWalletSessionCoordinator } from '@/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator';
import type { BrowserSealedSigningSessionStorePorts } from './createBrowserSigningStores';
import type { UserPreferencesManager } from '@/core/signingEngine/session/userPreferences';
import type { TouchIdPrompt } from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import { provisionThresholdEcdsaSession as provisionThresholdEcdsaSessionOperation } from '@/core/signingEngine/session/passkey/ecdsaSessionProvision';
import { provisionThresholdEd25519Session as provisionThresholdEd25519SessionOperation } from '@/core/signingEngine/session/passkey/ed25519SessionProvision';
import {
  persistThresholdEcdsaBootstrapForWalletTarget as persistThresholdEcdsaBootstrapForWalletTargetOperation,
  type ThresholdEcdsaBootstrapStorePort,
} from '@/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence';
import { createSigningEnginePorts } from '@/core/signingEngine/assembly/createPorts';
import type { SigningEngineStorePorts } from '@/core/signingEngine/assembly/ports/shared';
import {
  configuredThresholdEcdsaChainTargets,
  thresholdEcdsaChainTargetKey,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  authorizeEvmFamilyEcdsaSigningCapability,
  buildCanonicalEvmFamilyEcdsaSigningCapability,
  buildExactEcdsaDirectCapabilityRuntime,
  buildExactEvmFamilyWalletSessionAuthorization,
  type AuthorizedEvmFamilyEcdsaSigningCapability,
  type BuildExactEvmFamilyWalletSessionAuthorizationInput,
  type CanonicalEvmFamilyEcdsaSigningCapability,
  type ExactEvmFamilyWalletSessionAuthorization,
  type EvmFamilyEcdsaSigningCapabilityAvailability,
} from '@/core/signingEngine/session/material/ecdsaSigningCapability';
import {
  buildActiveNearEd25519WalletSessionAuthorization,
  type ExactNearEd25519WalletSessionAuthorization,
  type NearEd25519WalletSessionAuthorizationReadResult,
} from '@/core/signingEngine/session/material/nearEd25519YaoSigningPreparation';
import {
  isEmailOtpWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { buildPersistedEcdsaRoleLocalMaterial } from '@/core/signingEngine/session/material/ecdsaRoleLocalMaterialResolver';
import type { ActiveEcdsaCapabilityManifest } from '@/core/signingEngine/session/material/ecdsaCapabilityManifest';
import { signEvmFamily as signEvmFamilyOperation } from '@/core/signingEngine/flows/signEvmFamily/signEvmFamily';
import { EvmFamilyEcdsaMaterialSupersededError } from '@/core/signingEngine/flows/signEvmFamily/signingFlow';
import type { NonceCoordinator } from '@/core/signingEngine/nonce/NonceCoordinator';
import {
  withThresholdEcdsaSigningQueue,
  type ThresholdEcdsaSigningQueueByKey,
} from '@/core/signingEngine/threshold/ecdsa/signingQueue';
import {
  withThresholdEd25519CommitQueue,
  type ThresholdEd25519CommitQueueByKey,
} from '@/core/signingEngine/threshold/ed25519/commitQueue';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager/SignerWorkerManager';
import type {
  PasskeyMpcExportPort,
  PasskeyMpcSessionPort,
  UiConfirmRuntimeBridgePort,
} from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type { WarmSigningPorts } from '@/core/signingEngine/assembly/ports/warmSigning';
import type { WorkerResourceWarmupPolicy } from '@/core/signingEngine/assembly/warmup';
import type { SeamsConfigsReadonly, ThemeMode } from '@/core/types/seams';
import * as registrationPublic from '@/core/signingEngine/flows/registration/public';
import type { Ed25519YaoPublicCapabilityReferenceStorePort } from '@/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';
import type { EmailOtpEcdsaChallengeAuthority } from '@/core/signingEngine/flows/signEvmFamily/emailOtpSigningSession';
import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  SIGNER_AUTH_METHODS,
  WALLET_AUTH_METHODS,
  type SignerAuthMethod,
} from '@shared/utils/signerDomain';
import {
  walletAuthAuthorityRef,
  type WalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import type { EmailOtpTransactionSigningChallenge } from '@/core/signingEngine/session/emailOtp/publicTypes';
import type { RestorePersistedSessionForSigningInput } from '@/core/signingEngine/session/sealedRecovery/sealedRecovery.types';
import { __isWalletIframeHostMode } from '@/core/browser/walletIframe/host-mode';
import { readOwnerWalletExecutionLaneProjectionV1 } from '@/core/rpcClients/relayer/ownerWalletExecutionLanePreflight';
import { hydrateWalletExecutionLane } from '@/core/signingEngine/session/lanes/walletExecutionLaneHydration';
import type { EcdsaCapabilityManifestLookup } from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import { readEmailOtpProviderSubjectForWalletV1 } from '@/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';
import { readExactWalletSessionAuthorization } from './createBrowserRecoveryPublicDeps';
import { resolveExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import { resolveExactEcdsaCapabilityRuntime } from '@/core/signingEngine/session/material/activeEcdsaCapabilityRuntime';
import {
  ed25519SealedRuntimeAuthorityRef,
  type ExactEd25519SealedSessionRuntime,
} from '@/core/signingEngine/session/warmCapabilities/ed25519SealedSessionRuntime';
import type {
  CurrentEcdsaSealedSessionRecord,
  CurrentSealedSessionRecord,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type { ActiveWalletSessionV1 } from '@shared/device-linking/contracts';

type SigningEnginePorts = ReturnType<typeof createSigningEnginePorts>;

const ecdsaCapabilityManifestStore = new IndexedDbEcdsaCapabilityManifestStore();

type BrowserEcdsaCapabilityReaderContext = Pick<
  BrowserSigningSurfaceEnginePortsArgs,
  'seamsWebConfigs' | 'emailOtpSessions' | 'sealedSigningSessionStore' | 'touchIdPrompt' | 'stores'
>;

type BrowserSelectedWalletAuthority =
  BuildExactEvmFamilyWalletSessionAuthorizationInput['selected'];
type BrowserWalletSession = BuildExactEvmFamilyWalletSessionAuthorizationInput['session'];
type BrowserWalletSessionOperationCredential =
  BuildExactEvmFamilyWalletSessionAuthorizationInput['operationCredential'];
type BrowserSelectedWalletAuthorityResolution = Awaited<
  ReturnType<typeof IndexedDBManager.resolveSelectedWalletAuthority>
>;
type BrowserEcdsaWalletSessionAuthorizationInput = Pick<
  Parameters<
    Parameters<typeof createSigningEnginePorts>[0]['resolveAuthorizedEcdsaSigningCapability']
>[0],
  'walletId' | 'chainTarget' | 'materialActivation'
>;

function walletSessionImmutableIdentityMatches(
  left: ActiveWalletSessionV1,
  right: ActiveWalletSessionV1,
): boolean {
  return (
    left.kind === right.kind &&
    left.walletId === right.walletId &&
    left.authorityId === right.authorityId &&
    left.authMethodId === right.authMethodId &&
    left.authorizationId === right.authorizationId &&
    left.quotaId === right.quotaId &&
    left.issuedAtMs === right.issuedAtMs &&
    left.expiresAtMs === right.expiresAtMs
  );
}

function walletSessionMatchesSelectedAuthority(
  session: ActiveWalletSessionV1,
  selected: BrowserSelectedWalletAuthority,
): boolean {
  return (
    session.walletId === selected.authority.walletId &&
    session.authorityId === selected.authority.authorityId &&
    session.authMethodId === selected.authMethod.walletAuthMethodId &&
    session.authorityDigestB64u === selected.authority.authorityDigestB64u &&
    session.authorityRevocationEpoch === selected.authority.revocationEpoch
  );
}

function omitPasskeyRestoreAuthMethod(
  input: RestorePersistedSessionForSigningInput,
): Omit<RestorePersistedSessionForSigningInput, 'authMethod'> {
  if (input.authMethod !== 'passkey') {
    throw new Error('Passkey restore adapter received a non-Passkey request');
  }
  const { authMethod: _authMethod, ...passkeyRestore } = input;
  return passkeyRestore;
}

type ExactWalletAuthMethodStore = Pick<
  OwnerLaneScopeStores,
  | 'getWalletAuthMethodV2'
  | 'listWalletAuthMethodsForWallet'
  | 'readEmailOtpProviderSubjectForWallet'
>;

const browserExactWalletAuthMethodStore: ExactWalletAuthMethodStore = {
  getWalletAuthMethodV2: IndexedDBManager.getWalletAuthMethodV2.bind(IndexedDBManager),
  listWalletAuthMethodsForWallet:
    IndexedDBManager.listWalletAuthMethodsForWallet.bind(IndexedDBManager),
  readEmailOtpProviderSubjectForWallet: readEmailOtpProviderSubjectForWalletV1.bind(
    null,
    IndexedDBManager,
  ),
};

async function noWalletPasskeyAuthenticator(): Promise<null> {
  return null;
}

/**
 * R103C: the active wallet auth-method store is the one source that resolves
 * an authority reference to its full authority. Sealed-session restores and
 * loose authenticator lists are history and hints; matching against them let
 * a stale or sibling credential answer for the active authority.
 */
export async function resolveExactWalletAuthAuthority(
  authorityRef: WalletAuthAuthorityRef,
  walletAuthMethodStore: ExactWalletAuthMethodStore,
): ReturnType<typeof resolveExactWalletAuthAuthorityFromMethod> {
  const authMethod = await walletAuthMethodStore.getWalletAuthMethodV2(
    String(authorityRef.walletAuthMethodId),
  );
  if (
    !authMethod ||
    authMethod.status !== 'active' ||
    authMethod.walletId !== authorityRef.walletId
  ) {
    throw new Error('Exact wallet authentication authority is unavailable');
  }
  let authority: Awaited<ReturnType<typeof resolveExactWalletAuthAuthorityFromMethod>>;
  try {
    authority = await resolveExactWalletAuthAuthorityFromMethod({
      authMethod,
      stores: {
        ...walletAuthMethodStore,
        getWalletPasskeyAuthenticator: noWalletPasskeyAuthenticator,
      },
    });
  } catch {
    throw new Error('Exact wallet authentication authority is unavailable');
  }
  const candidateRef = await walletAuthAuthorityRef({ authority });
  if (
    candidateRef.walletId === authorityRef.walletId &&
    candidateRef.walletAuthMethodId === authorityRef.walletAuthMethodId &&
    candidateRef.authorityDigest === authorityRef.authorityDigest
  ) {
    return authority;
  }
  throw new Error('Exact wallet authentication authority is unavailable');
}

export function createBrowserCanonicalWalletSessionStatusReader(
  args: BrowserEcdsaCapabilityReaderContext,
) {
  return createCanonicalWalletSessionStatusReader({
    relayerUrl: String(args.seamsWebConfigs.network.relayer?.url || '').trim(),
    readAuthorization: readExactWalletSessionAuthorization,
  });
}

function exactSelectedWalletAuthority(
  result: BrowserSelectedWalletAuthorityResolution,
  walletId: ReturnType<typeof toWalletId>,
): BrowserSelectedWalletAuthority | null {
  if (result.kind !== 'resolved') return null;
  if (
    result.selection.lockState !== 'unlocked' ||
    result.selection.walletId !== walletId ||
    result.selection.walletAuthMethodId !== result.authMethod.walletAuthMethodId ||
    result.authMethod.status !== 'active' ||
    result.authMethod.walletId !== walletId ||
    result.authMethod.walletAuthorityId !== result.authority.authorityId ||
    result.authority.state !== 'active' ||
    result.authority.walletId !== walletId
  ) {
    return null;
  }
  return {
    kind: result.kind,
    selection: result.selection,
    authMethod: result.authMethod,
    authority: result.authority,
    signerMaterials: result.signerMaterials,
    exportRoot: result.exportRoot,
  };
}

async function resolveBrowserSelectedFactorAuthority(
  selected: BrowserSelectedWalletAuthority,
): Promise<WalletAuthAuthority> {
  return await resolveExactWalletAuthAuthorityFromMethod({
    authMethod: selected.authMethod,
    stores: {
      ...browserExactWalletAuthMethodStore,
      getWalletPasskeyAuthenticator: noWalletPasskeyAuthenticator,
    },
  });
}

async function resolveBrowserSelectedPasskeyFactorAuthorityForSealedRuntime(args: {
  readonly walletId: ReturnType<typeof toWalletId>;
  readonly runtime: ExactEd25519SealedSessionRuntime;
}): Promise<WalletAuthAuthorityRef> {
  let selectedResult: BrowserSelectedWalletAuthorityResolution;
  try {
    selectedResult = await IndexedDBManager.resolveSelectedWalletAuthority(String(args.walletId));
  } catch {
    throw new Error('[SigningEngine][near] exact Passkey authority is unavailable');
  }
  const selected = exactSelectedWalletAuthority(selectedResult, args.walletId);
  if (!selected || selected.authMethod.kind !== WALLET_AUTH_METHODS.passkey) {
    throw new Error('[SigningEngine][near] exact Passkey authority is unavailable');
  }
  if (
    args.runtime.walletId !== args.walletId ||
    args.runtime.factor.kind !== WALLET_AUTH_METHODS.passkey ||
    String(args.runtime.factor.rpId) !== String(selected.authMethod.rpId) ||
    args.runtime.factor.credentialIdB64u !== selected.authMethod.credentialIdB64u
  ) {
    throw new Error('[SigningEngine][near] exact Passkey authority changed');
  }

  let sealedAuthority: WalletAuthAuthorityRef;
  try {
    sealedAuthority = await ed25519SealedRuntimeAuthorityRef({
      runtime: args.runtime,
      walletAuthMethodId: selected.authMethod.walletAuthMethodId,
    });
  } catch {
    throw new Error('[SigningEngine][near] exact Passkey authority changed');
  }
  let factorAuthority: WalletAuthAuthority;
  try {
    factorAuthority = await resolveBrowserSelectedFactorAuthority(selected);
  } catch {
    throw new Error('[SigningEngine][near] exact Passkey authority changed');
  }
  const factorAuthorityRef = await walletAuthAuthorityRef({ authority: factorAuthority });
  if (
    factorAuthorityRef.walletId !== sealedAuthority.walletId ||
    factorAuthorityRef.walletAuthMethodId !== sealedAuthority.walletAuthMethodId ||
    factorAuthorityRef.authorityDigest !== sealedAuthority.authorityDigest
  ) {
    throw new Error('[SigningEngine][near] exact Passkey authority changed');
  }
  return factorAuthorityRef;
}

type BrowserNearEd25519PasskeyMaterialAuthorizationRead = Extract<
  NearEd25519WalletSessionAuthorizationReadResult,
  { readonly kind: 'found' }
> | { readonly kind: 'exhausted'; readonly authorization?: never };

export async function resolveBrowserNearEd25519PasskeyAuthorityForMaterial(args: {
  readonly walletId: ReturnType<typeof toWalletId>;
  readonly runtime: ExactEd25519SealedSessionRuntime;
  readonly authorizationRead: BrowserNearEd25519PasskeyMaterialAuthorizationRead;
}): Promise<WalletAuthAuthorityRef> {
  switch (args.authorizationRead.kind) {
    case 'exhausted':
      return await resolveBrowserSelectedPasskeyFactorAuthorityForSealedRuntime(args);
    case 'found': {
      const authorization = args.authorizationRead.authorization;
      if (
        authorization.selectedAuthMethod.kind !== WALLET_AUTH_METHODS.passkey ||
        args.runtime.factor.kind !== WALLET_AUTH_METHODS.passkey ||
        String(args.runtime.factor.rpId) !== String(authorization.selectedAuthMethod.rpId) ||
        args.runtime.factor.credentialIdB64u !==
          authorization.selectedAuthMethod.credentialIdB64u
      ) {
        throw new Error('[SigningEngine][near] exact Passkey authority changed');
      }
      const authority = await ed25519SealedRuntimeAuthorityRef({
        runtime: args.runtime,
        walletAuthMethodId: authorization.selectedAuthMethod.walletAuthMethodId,
      });
      const selectedFactorAuthority = await walletAuthAuthorityRef({
        authority: authorization.selectedFactorAuthority,
      });
      if (
        authority.walletId !== selectedFactorAuthority.walletId ||
        authority.walletAuthMethodId !== selectedFactorAuthority.walletAuthMethodId ||
        authority.authorityDigest !== selectedFactorAuthority.authorityDigest
      ) {
        throw new Error('[SigningEngine][near] exact Passkey authority changed');
      }
      return authority;
    }
    default:
      args.authorizationRead satisfies never;
      throw new Error('[SigningEngine][near] unsupported exact Passkey authorization read');
  }
}

type NearEd25519NonAuthorizedReadResult = Exclude<
  NearEd25519WalletSessionAuthorizationReadResult,
  { readonly kind: 'found' }
>;

function nearEd25519ReadResultFromRemoteStatus(
  status: ExactWalletSessionStatus,
): NearEd25519NonAuthorizedReadResult {
  switch (status.status) {
    case 'missing':
      return { kind: 'missing' };
    case 'exhausted':
      return { kind: 'exhausted' };
    case 'expired':
      return { kind: 'expired' };
    case 'superseded':
      return { kind: 'superseded' };
    case 'authority_unavailable':
      return { kind: 'authority_unavailable' };
    case 'method_unavailable':
      return { kind: 'method_unavailable' };
    case 'capability_unavailable':
      return { kind: 'capability_unavailable' };
    case 'invalid':
      return { kind: 'unavailable' };
    case 'active':
      throw new Error('[SigningEngine][near] active status must be resolved as authorization');
    default:
      status satisfies never;
      throw new Error('[SigningEngine][near] unsupported Wallet Session status');
  }
}

/**
 * Reads the selected authority, exact V6 session row, and authenticated
 * relayer status as one Ed25519 authorization value. The local row never
 * authorizes an operation without the status read.
 */
export async function readBrowserExactNearEd25519WalletSessionAuthorization(
  walletIdInput: ReturnType<typeof toWalletId>,
  relayerUrlInput: string,
): Promise<NearEd25519WalletSessionAuthorizationReadResult> {
  const walletId = toWalletId(walletIdInput);
  let selectedResult: BrowserSelectedWalletAuthorityResolution;
  try {
    selectedResult = await IndexedDBManager.resolveSelectedWalletAuthority(String(walletId));
  } catch {
    return { kind: 'persistence_unavailable' };
  }
  const selected = exactSelectedWalletAuthority(selectedResult, walletId);
  if (!selected) return { kind: 'missing' };

  let exactRead: Awaited<ReturnType<typeof walletSessionAuthorizations.readExactActiveForWallet>>;
  try {
    exactRead = await walletSessionAuthorizations.readExactActiveForWallet({
      walletId,
      authorityId: selected.authority.authorityId,
      authMethodId: selected.authMethod.walletAuthMethodId,
    });
  } catch {
    return { kind: 'persistence_unavailable' };
  }
  switch (exactRead.kind) {
    case 'missing':
    case 'corrupt':
    case 'persistence_unavailable':
    case 'upgrade_required':
      return exactRead;
    case 'found':
      break;
    default:
      exactRead satisfies never;
      throw new Error('[SigningEngine][near] unsupported exact Wallet Session read result');
  }

  const relayerUrl = String(relayerUrlInput || '').trim();
  if (!relayerUrl) return { kind: 'unavailable' };
  const nowMs = Date.now();
  if (exactRead.record.expiresAtMs <= nowMs) return { kind: 'expired' };

  let status: ExactWalletSessionStatus;
  try {
    status = await createRelayerExactWalletSessionStatusPort({
      relayerUrl,
      operationCredential: exactRead.operationCredential,
    }).read({
      walletSessionId: exactRead.operationCredential.walletSessionId,
      quotaId: exactRead.record.quotaId,
    });
  } catch {
    return { kind: 'unavailable' };
  }
  if (status.status !== 'active') return nearEd25519ReadResultFromRemoteStatus(status);

  let currentSelectedResult: BrowserSelectedWalletAuthorityResolution;
  try {
    currentSelectedResult = await IndexedDBManager.resolveSelectedWalletAuthority(String(walletId));
  } catch {
    return { kind: 'persistence_unavailable' };
  }
  const currentSelected = exactSelectedWalletAuthority(currentSelectedResult, walletId);
  if (!currentSelected) return { kind: 'missing' };
  const authorizationNowMs = Date.now();
  if (status.authorization.expiresAtMs <= authorizationNowMs) return { kind: 'expired' };
  if (
    status.walletSessionId !== exactRead.operationCredential.walletSessionId ||
    status.quotaId !== exactRead.record.quotaId ||
    status.expiresAtMs !== status.authorization.expiresAtMs ||
    !walletSessionImmutableIdentityMatches(status.authorization, exactRead.record) ||
    !walletSessionMatchesSelectedAuthority(status.authorization, currentSelected)
  ) {
    return { kind: 'corrupt' };
  }
  try {
    await walletSessionAuthorizations.replaceExactActive({
      active: status.authorization,
      operationCredential: exactRead.operationCredential,
    });
  } catch {
    return { kind: 'persistence_unavailable' };
  }
  let selectedFactorAuthority: WalletAuthAuthority;
  try {
    selectedFactorAuthority = await resolveBrowserSelectedFactorAuthority(currentSelected);
  } catch {
    return { kind: 'unavailable' };
  }

  try {
    const authorization = buildActiveNearEd25519WalletSessionAuthorization({
      selectedAuthority: currentSelected.authority,
      selectedAuthMethod: currentSelected.authMethod,
      selectedFactorAuthority,
      session: status.authorization,
      operationCredential: exactRead.operationCredential,
      status,
      nowMs: authorizationNowMs,
    });
    return { kind: 'found', authorization };
  } catch {
    return { kind: 'corrupt' };
  }
}

export async function resolveBrowserActiveNearEd25519WalletSessionAuthorization(
  walletId: ReturnType<typeof toWalletId>,
  relayerUrl: string,
): Promise<ExactNearEd25519WalletSessionAuthorization | null> {
  const read = await readBrowserExactNearEd25519WalletSessionAuthorization(walletId, relayerUrl);
  return read.kind === 'found' ? read.authorization : null;
}

function isCurrentEcdsaSealedSessionRecord(
  record: CurrentSealedSessionRecord,
): record is CurrentEcdsaSealedSessionRecord {
  return record.curve === 'ecdsa';
}

function manifestMatchesExactEcdsaAuthorization(args: {
  readonly manifest: ActiveEcdsaCapabilityManifest;
  readonly selected: BrowserSelectedWalletAuthority;
  readonly walletId: ReturnType<typeof toWalletId>;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly materialActivation: MpcMaterialActivationRef;
}): boolean {
  const { manifest, selected, walletId, chainTarget, materialActivation } = args;
  return (
    manifest.signer.walletId === walletId &&
    manifest.signer.authority.walletId === walletId &&
    manifest.signer.authority.walletAuthMethodId === selected.authMethod.walletAuthMethodId &&
    mpcMaterialActivationRefsEqual(manifest.activation.materialActivation, materialActivation) &&
    manifest.signer.scope.targetMemberships.some(
      (membership) =>
        thresholdEcdsaChainTargetKey(membership) === thresholdEcdsaChainTargetKey(chainTarget),
    )
  );
}

async function buildBrowserExactEcdsaWalletSessionAuthorization(args: {
  readonly context: BrowserEcdsaCapabilityReaderContext;
  readonly walletId: ReturnType<typeof toWalletId>;
  readonly selected: BrowserSelectedWalletAuthority;
  readonly session: BrowserWalletSession;
  readonly operationCredential: BrowserWalletSessionOperationCredential;
  readonly status: Extract<ExactWalletSessionStatus, { readonly status: 'active' }>;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly nowMs: number;
}): Promise<
  | { readonly kind: 'resolved'; readonly authorization: ExactEvmFamilyWalletSessionAuthorization }
  | { readonly kind: 'inactive'; readonly reason: string }
> {
  const manifests = await listBrowserActiveEcdsaCapabilityManifestsForWallet(String(args.walletId));
  const matchingManifests = manifests.filter((candidate) =>
    manifestMatchesExactEcdsaAuthorization({
      manifest: candidate,
      selected: args.selected,
      walletId: args.walletId,
      chainTarget: args.chainTarget,
      materialActivation: args.materialActivation,
    }),
  );
  if (matchingManifests.length !== 1) {
    return {
      kind: 'inactive',
      reason: `Expected one exact ECDSA capability manifest; found ${matchingManifests.length}`,
    };
  }
  const [manifest] = matchingManifests;
  if (!manifest) return { kind: 'inactive', reason: 'Exact ECDSA capability manifest is missing' };
  const capability = await browserCanonicalEcdsaCapabilityFromManifest(manifest);
  const sealedRecords =
    await args.context.sealedSigningSessionStore.listExactSealedSessionsForWallet({
      walletId: String(args.walletId),
      filter: {
        authMethod: args.selected.authMethod.kind,
        curve: 'ecdsa',
        chainTarget: args.chainTarget,
      },
    });
  const runtimeResolution = resolveExactEcdsaSealedRuntime({
    manifest,
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    sealedRecords: sealedRecords.filter(isCurrentEcdsaSealedSessionRecord),
  });
  let runtime: BuildExactEvmFamilyWalletSessionAuthorizationInput['runtime'];
  if (runtimeResolution.kind === 'resolved') {
    runtime = runtimeResolution.runtime;
  } else {
    if (runtimeResolution.reason !== 'missing_material') {
      return {
        kind: 'inactive',
        reason: `Exact sealed ECDSA runtime is ${runtimeResolution.reason}`,
      };
    }
    const capabilityRuntime = await resolveExactEcdsaCapabilityRuntime({
      manifest,
      chainTarget: args.chainTarget,
      relayerUrl: args.context.seamsWebConfigs.network.relayer?.url ?? '',
    });
    if (capabilityRuntime.kind !== 'resolved') {
      return {
        kind: 'inactive',
        reason: `Exact durable ECDSA capability runtime is ${capabilityRuntime.reason}`,
      };
    }
    try {
      runtime = buildExactEcdsaDirectCapabilityRuntime({
        runtime: capabilityRuntime.runtime,
        authority: capability.authority,
        status: args.status,
      });
    } catch {
      return { kind: 'inactive', reason: 'Exact durable ECDSA quota facts are invalid' };
    }
  }
  try {
    return {
      kind: 'resolved',
      authorization: buildExactEvmFamilyWalletSessionAuthorization({
        capability,
        selected: args.selected,
        session: args.session,
        operationCredential: args.operationCredential,
        runtime,
        nowMs: args.nowMs,
      }),
    };
  } catch (error) {
    return {
      kind: 'inactive',
      reason:
        error instanceof Error
          ? error.message
          : 'Exact ECDSA Wallet Session authorization is invalid',
    };
  }
}

export type BrowserWalletSessionAuthorizationResolution =
  | { kind: 'active'; authorization: ExactEvmFamilyWalletSessionAuthorization }
  | { kind: 'inactive'; reason: string };

// Resolves the selected wallet authority's exact Wallet Session and sealed
// ECDSA runtime, then pairs it with the live relayer status. Configuration
// failures throw; inactive session states return `inactive` so warm-capability
// readers can degrade to `authorization_required` without treating them as
// errors.
export async function resolveBrowserActiveEcdsaWalletSessionAuthorization(
  args: BrowserEcdsaCapabilityReaderContext,
  input: BrowserEcdsaWalletSessionAuthorizationInput,
): Promise<BrowserWalletSessionAuthorizationResolution> {
  const walletId = toWalletId(input.walletId);
  const nowMs = Date.now();
  const selectedResult = await IndexedDBManager.resolveSelectedWalletAuthority(String(walletId));
  const selected = exactSelectedWalletAuthority(selectedResult, walletId);
  if (!selected) {
    return {
      kind: 'inactive',
      reason: 'Selected wallet authentication authority is unavailable',
    };
  }
  const relayerUrl = String(args.seamsWebConfigs.network.relayer?.url || '').trim();
  if (!relayerUrl) throw new Error('Exact Wallet Session status requires a relayer URL');
  const exactAuthorization = await readExactWalletSessionAuthorization(walletId);
  if (exactAuthorization.kind !== 'found') {
    return {
      kind: 'inactive',
      reason: `Exact Wallet Session authorization is ${exactAuthorization.kind}`,
    };
  }
  if (exactAuthorization.record.expiresAtMs <= nowMs) {
    return { kind: 'inactive', reason: 'Exact Wallet Session authorization is expired' };
  }
  const status = await createRelayerExactWalletSessionStatusPort({
    relayerUrl,
    operationCredential: exactAuthorization.operationCredential,
  }).read({
    walletSessionId: exactAuthorization.operationCredential.walletSessionId,
    quotaId: exactAuthorization.record.quotaId,
  });
  if (status.status !== 'active') {
    return { kind: 'inactive', reason: `Exact Wallet Session is ${status.status}` };
  }
  const currentSelectedResult = await IndexedDBManager.resolveSelectedWalletAuthority(
    String(walletId),
  );
  const currentSelected = exactSelectedWalletAuthority(currentSelectedResult, walletId);
  if (
    !currentSelected ||
    status.walletSessionId !== exactAuthorization.operationCredential.walletSessionId ||
    status.quotaId !== exactAuthorization.record.quotaId ||
    status.expiresAtMs !== status.authorization.expiresAtMs ||
    !walletSessionImmutableIdentityMatches(status.authorization, exactAuthorization.record) ||
    !walletSessionMatchesSelectedAuthority(status.authorization, currentSelected)
  ) {
    return { kind: 'inactive', reason: 'Exact Wallet Session status identity is inconsistent' };
  }
  const authorizationNowMs = Date.now();
  if (status.authorization.expiresAtMs <= authorizationNowMs) {
    return { kind: 'inactive', reason: 'Exact Wallet Session authorization is expired' };
  }
  try {
    await walletSessionAuthorizations.replaceExactActive({
      active: status.authorization,
      operationCredential: exactAuthorization.operationCredential,
    });
  } catch {
    return {
      kind: 'inactive',
      reason: 'Exact Wallet Session promotion reconciliation could not be persisted',
    };
  }
  const authorizationResolution = await buildBrowserExactEcdsaWalletSessionAuthorization({
    context: args,
    walletId,
    selected: currentSelected,
    session: status.authorization,
    operationCredential: exactAuthorization.operationCredential,
    status,
    chainTarget: input.chainTarget,
    materialActivation: input.materialActivation,
    nowMs: authorizationNowMs,
  });
  if (authorizationResolution.kind !== 'resolved') {
    return authorizationResolution;
  }
  return {
    kind: 'active',
    authorization: authorizationResolution.authorization,
  };
}

export function createBrowserActiveEcdsaWalletSessionAuthorizationResolver(
  args: BrowserEcdsaCapabilityReaderContext,
): (
  input: BrowserEcdsaWalletSessionAuthorizationInput,
) => Promise<ExactEvmFamilyWalletSessionAuthorization | null> {
  return async (input) => {
    const resolution = await resolveBrowserActiveEcdsaWalletSessionAuthorization(args, input);
    return resolution.kind === 'active' ? resolution.authorization : null;
  };
}

/** The wallet's current active manifest covering the requested target, if one
 * exists. This is what a replacement race resolves against: the prepared
 * capability's manifest is gone or retired, but the wallet still signs for the
 * target -- through the replacement. */
async function activeEcdsaReplacementManifestForTarget(args: {
  walletId: ReturnType<typeof toWalletId>;
  subjects: readonly Parameters<typeof ecdsaCapabilityManifestStore.lookup>[0][];
  chainTarget: ThresholdEcdsaChainTarget;
}): Promise<ActiveEcdsaCapabilityManifest | null> {
  for (const subject of args.subjects) {
    const lookup = await ecdsaCapabilityManifestStore.lookup(subject);
    if (lookup.kind === 'persistence_unavailable') {
      throw new Error('ECDSA capability persistence is unavailable');
    }
    if (lookup.kind !== 'active') continue;
    const manifest = lookup.manifest;
    if (manifest.signer.walletId !== args.walletId) continue;
    if (
      manifest.signer.scope.targetMemberships.some(
        (target) =>
          thresholdEcdsaChainTargetKey(target) === thresholdEcdsaChainTargetKey(args.chainTarget),
      )
    ) {
      return manifest;
    }
  }
  return null;
}

type BrowserCanonicalEcdsaCapabilityResolution = {
  readonly capability: CanonicalEvmFamilyEcdsaSigningCapability;
  readonly lookup: Extract<EcdsaCapabilityManifestLookup, { readonly kind: 'active' }>;
};

export async function resolveAmbiguousEcdsaActivationForSelectedAuthMethod(input: {
  readonly walletId: ReturnType<typeof toWalletId>;
  readonly materialActivation: Parameters<
    typeof ecdsaCapabilityManifestStore.lookupByMaterialActivation
  >[0]['materialActivation'];
  readonly authorities: readonly WalletAuthAuthorityRef[];
}) {
  const selected = await IndexedDBManager.resolveSelectedWalletAuthority(String(input.walletId));
  if (selected.kind !== 'resolved') {
    throw new Error(
      `ECDSA material activation is ambiguous and the wallet selection is ${selected.kind}`,
    );
  }
  const chosen = input.authorities.find(
    (authority) => authority.walletAuthMethodId === selected.selection.walletAuthMethodId,
  );
  if (!chosen) {
    throw new Error(
      'ECDSA material activation has no access projection for the selected wallet auth method',
    );
  }
  return await ecdsaCapabilityManifestStore.lookupByMaterialActivation({
    walletId: input.walletId,
    materialActivation: input.materialActivation,
    authority: chosen,
  });
}

async function resolveBrowserCanonicalEcdsaSigningCapability(
  args: BrowserEcdsaCapabilityReaderContext,
  input: Parameters<
    Parameters<typeof createSigningEnginePorts>[0]['resolveCanonicalEcdsaSigningCapability']
  >[0],
): Promise<BrowserCanonicalEcdsaCapabilityResolution> {
  const walletId = toWalletId(input.walletId);
  const subjects = await ecdsaCapabilityManifestStore.listActiveWalletCapabilitySubjects(walletId);
  if (subjects.kind !== 'resolved') {
    throw new Error(`ECDSA capability subjects are ${subjects.kind}`);
  }
  // Replacement race: preparation named a capability whose manifest has since
  // been replaced. That surfaces here as either no active subject for the
  // prepared capability ref, or a lookup that returns `retired`. Both are
  // R90-INV-010 supersession, not a missing wallet: when a replacement
  // covering the same target exists, throw the typed superseded error so
  // `signEvmFamily` performs its one bounded re-resolution instead of
  // reporting a terminal signing failure.
  const throwSupersededByReplacement = async (fallback: () => never): Promise<never> => {
    const replacement = await activeEcdsaReplacementManifestForTarget({
      walletId,
      subjects: subjects.subjects,
      chainTarget: input.chainTarget,
    });
    if (replacement) {
      throw new EvmFamilyEcdsaMaterialSupersededError({
        kind: 'superseded',
        supersessionKind: 'material_activation_replaced',
        preparedMaterialActivation: input.materialActivation,
        currentMaterialActivation: replacement.activation.materialActivation,
      });
    }
    return fallback();
  };
  let manifestLookup = await ecdsaCapabilityManifestStore.lookupByMaterialActivation({
    walletId,
    materialActivation: input.materialActivation,
  });
  if (manifestLookup.kind === 'ambiguous_authority') {
    // R109C: several auth methods on one wallet authority each hold their own
    // access projection over this activation. Signing happens as the selected
    // method, so name it rather than taking whichever sibling scans first.
    manifestLookup = await resolveAmbiguousEcdsaActivationForSelectedAuthMethod({
      walletId,
      materialActivation: input.materialActivation,
      authorities: manifestLookup.authorities,
    });
  }
  if (
    manifestLookup.kind === 'persistence_unavailable' ||
    manifestLookup.kind === 'exact_record_conflict' ||
    manifestLookup.kind === 'corrupt'
  ) {
    throw new Error(`ECDSA material activation is ${manifestLookup.kind}`);
  }
  if (manifestLookup.kind !== 'active') {
    return await throwSupersededByReplacement(() => {
      throw new Error('ECDSA capability manifest is missing');
    });
  }
  const manifest = manifestLookup.manifest;
  if (
    manifest.signer.walletId !== walletId ||
    !manifest.signer.scope.targetMemberships.some(
      (target) =>
        thresholdEcdsaChainTargetKey(target) === thresholdEcdsaChainTargetKey(input.chainTarget),
    )
  ) {
    throw new Error('ECDSA capability manifest does not match the requested signer');
  }
  // Return the current manifest for this capability even when preparation named
  // an older activation. The signing runtime compares the two exact activation
  // references and returns the typed `superseded` outcome, which owns the single
  // canonical re-resolution. Throwing here would turn routine replacement into
  // a terminal signing failure before that boundary can classify it.
  const capability = await browserCanonicalEcdsaCapabilityFromManifest(manifest);
  return { capability, lookup: manifestLookup };
}

/**
 * A manifest already names its own exact authority, so build the capability
 * from it directly. Re-resolving by material activation would ask "which
 * projection covers this activation" - a question with more than one answer
 * once an added method holds its own.
 */
async function browserCanonicalEcdsaCapabilityFromManifest(
  manifest: ActiveEcdsaCapabilityManifest,
): Promise<CanonicalEvmFamilyEcdsaSigningCapability> {
  return await buildCanonicalEvmFamilyEcdsaSigningCapability({
    authority: await resolveExactWalletAuthAuthority(manifest.signer.authority, {
      getWalletAuthMethodV2: (id) => IndexedDBManager.getWalletAuthMethodV2(id),
      listWalletAuthMethodsForWallet: (walletId) =>
        IndexedDBManager.listWalletAuthMethodsForWallet(walletId),
      readEmailOtpProviderSubjectForWallet: (walletId) =>
        readEmailOtpProviderSubjectForWalletV1(IndexedDBManager, walletId),
    }),
    manifest,
    material: buildPersistedEcdsaRoleLocalMaterial({
      authority: manifest.signer.authority,
      materialActivation: manifest.activation.materialActivation,
      publicFacts: manifest.durableMaterial.roleLocalPublicFacts,
    }),
  });
}

async function getBrowserCanonicalEcdsaSigningCapability(
  args: BrowserEcdsaCapabilityReaderContext,
  input: Parameters<
    Parameters<typeof createSigningEnginePorts>[0]['resolveCanonicalEcdsaSigningCapability']
  >[0],
): Promise<CanonicalEvmFamilyEcdsaSigningCapability> {
  return (await resolveBrowserCanonicalEcdsaSigningCapability(args, input)).capability;
}

async function getBrowserEcdsaSigningCapability(
  args: BrowserEcdsaCapabilityReaderContext,
  input: Parameters<
    Parameters<typeof createSigningEnginePorts>[0]['resolveAuthorizedEcdsaSigningCapability']
  >[0],
): Promise<AuthorizedEvmFamilyEcdsaSigningCapability> {
  const resolution = await resolveBrowserActiveEcdsaWalletSessionAuthorization(args, input);
  if (resolution.kind !== 'active') {
    throw new Error(resolution.reason);
  }
  const browserAuthorization = resolution.authorization;
  const canonical = await resolveBrowserCanonicalEcdsaSigningCapability(args, input);
  const projection = await readOwnerWalletExecutionLaneProjectionV1({
    relayerUrl: String(args.seamsWebConfigs.network.relayer?.url || '').trim(),
    walletSessionToken: browserAuthorization.operationCredential.token,
    curve: 'ecdsa_secp256k1',
    expectedMaterialActivation: canonical.capability.manifest.activation.materialActivation,
  });
  const hydrated = hydrateWalletExecutionLane({
    walletKey: projection.walletKey,
    lane: projection.lane,
    material: {
      keyFamily: 'ecdsa_secp256k1',
      laneShareEpoch: projection.lane.laneShareEpoch,
      lookup: canonical.lookup,
      runtime: { kind: 'absent' },
    },
  });
  if (hydrated.kind !== 'active_wallet_execution_lane_v1') {
    throw new Error(`Owner ECDSA execution lane is ${hydrated.reason}`);
  }
  return authorizeEvmFamilyEcdsaSigningCapability({
    capability: canonical.capability,
    authorization: browserAuthorization,
    nowMs: Date.now(),
  });
}

export async function listBrowserEcdsaSigningCapabilitiesForWallet(
  args: BrowserEcdsaCapabilityReaderContext,
  input: {
    walletId: string;
    chainTargets: readonly ThresholdEcdsaChainTarget[];
    authMethod?: SignerAuthMethod;
  },
): Promise<readonly EvmFamilyEcdsaSigningCapabilityAvailability[]> {
  const walletId = toWalletId(input.walletId);
  const subjects = await ecdsaCapabilityManifestStore.listActiveWalletCapabilitySubjects(walletId);
  if (subjects.kind !== 'resolved') return [];
  const capabilities: EvmFamilyEcdsaSigningCapabilityAvailability[] = [];
  for (const subject of subjects.subjects) {
    const lookup = await ecdsaCapabilityManifestStore.lookup(subject);
    if (lookup.kind !== 'active') continue;
    const manifest = lookup.manifest;
    if (
      !manifest.signer.scope.targetMemberships.some((membership) =>
        input.chainTargets.some(
          (target) =>
            thresholdEcdsaChainTargetKey(target) === thresholdEcdsaChainTargetKey(membership),
        ),
      )
    ) {
      continue;
    }
    const matchingTarget = input.chainTargets.find((target) =>
      manifest.signer.scope.targetMemberships.some(
        (membership) =>
          thresholdEcdsaChainTargetKey(target) === thresholdEcdsaChainTargetKey(membership),
      ),
    );
    if (!matchingTarget) continue;
    // This loop is already walking one subject at a time, so use that subject's
    // own manifest. Going back through the activation would collapse every
    // sibling projection onto whichever method is currently selected, and an
    // added method would never appear as a candidate for its own family.
    let capability: CanonicalEvmFamilyEcdsaSigningCapability;
    try {
      capability = await browserCanonicalEcdsaCapabilityFromManifest(manifest);
    } catch {
      /* A revoked method keeps its projection until something prunes it, and
         resolving that projection's authority fails because the method is no
         longer active. Enumeration is asking which capabilities are usable, so
         one that is not is a skip - throwing here would let a retired sibling
         take the surviving method's lanes down with it. */
      continue;
    }
    const capabilityAuthMethod = isPasskeyWalletAuthAuthority(capability.authority)
      ? 'passkey'
      : isEmailOtpWalletAuthAuthority(capability.authority)
        ? 'email_otp'
        : null;
    if (!capabilityAuthMethod || (input.authMethod && capabilityAuthMethod !== input.authMethod)) {
      continue;
    }
    const authorizationResolution = await resolveBrowserActiveEcdsaWalletSessionAuthorization(
      args,
      {
        walletId,
        chainTarget: matchingTarget,
        materialActivation: manifest.activation.materialActivation,
      },
    );
    if (authorizationResolution.kind === 'active') {
      try {
        capabilities.push(
          authorizeEvmFamilyEcdsaSigningCapability({
            capability,
            authorization: authorizationResolution.authorization,
            nowMs: Date.now(),
          }),
        );
        continue;
      } catch {
        // The exact session may authorize a sibling capability for the same
        // authority while this manifest names different material.
      }
    }
    capabilities.push({ kind: 'authorization_required', capability });
  }
  return capabilities;
}

export async function listBrowserActiveEcdsaCapabilityManifestsForWallet(
  walletIdInput: string,
): Promise<readonly ActiveEcdsaCapabilityManifest[]> {
  const walletId = toWalletId(walletIdInput);
  const subjects = await ecdsaCapabilityManifestStore.listActiveWalletCapabilitySubjects(walletId);
  if (subjects.kind !== 'resolved') return [];
  const manifests: ActiveEcdsaCapabilityManifest[] = [];
  for (const subject of subjects.subjects) {
    const lookup = await ecdsaCapabilityManifestStore.lookup(subject);
    if (lookup.kind === 'active') manifests.push(lookup.manifest);
  }
  return manifests;
}

async function requestEmailOtpEcdsaStepUpChallenge(args: {
  coordinator: EmailOtpWalletSessionCoordinator;
  walletSession: WalletSessionRef;
  chain: ThresholdEcdsaChainTarget['kind'];
  authority: EmailOtpEcdsaChallengeAuthority;
  operationFingerprintDigest: DigestB64u;
}): Promise<EmailOtpTransactionSigningChallenge> {
  switch (args.authority.kind) {
    case 'live_session':
      return await args.coordinator.requestTransactionSigningChallenge({
        kind: 'wallet_session_challenge',
        walletSession: args.walletSession,
        chain: args.chain,
        authLane: args.authority.authLane,
        operationFingerprintDigest: args.operationFingerprintDigest,
      });
    case 'capability_step_up':
      return await args.coordinator.requestTransactionSigningChallenge({
        kind: 'wallet_login_challenge',
        walletSession: args.walletSession,
        chain: args.chain,
        operationFingerprintDigest: args.operationFingerprintDigest,
      });
  }
}

export type BrowserSigningSurfaceEnginePortsArgs = {
  runtimePorts: RuntimePorts;
  stores: SigningEngineStorePorts;
  ed25519YaoPublicCapabilityReferences: Ed25519YaoPublicCapabilityReferenceStorePort;
  seamsWebConfigs: SeamsConfigsReadonly;
  nearClient: NearClient;
  touchIdPrompt: TouchIdPrompt;
  userPreferencesManager: UserPreferencesManager;
  nonceCoordinator: NonceCoordinator;
  touchConfirm: UiConfirmRuntimeBridgePort;
  passkeyMpcSession: PasskeyMpcSessionPort;
  passkeyMpcExport: PasskeyMpcExportPort;
  signerWorkerManager: SignerWorkerManager;
  emailOtpSessions: EmailOtpWalletSessionCoordinator;
  warmSigning: WarmSigningPorts;
  sealedSigningSessionStore: BrowserSealedSigningSessionStorePorts;
  ecdsaBootstrapStore: ThresholdEcdsaBootstrapStorePort;
  thresholdEcdsaBootstrapQueueByWallet: Map<string, Promise<void>>;
  thresholdEcdsaSigningQueueByKey: ThresholdEcdsaSigningQueueByKey;
  thresholdEd25519CommitQueueByKey: ThresholdEd25519CommitQueueByKey;
  getWorkerBaseOrigin: () => string;
  workerWarmupPolicy: WorkerResourceWarmupPolicy;
  getTheme: () => ThemeMode;
  ensureSealedRefreshStartupParity: () => Promise<void>;
  resolveOwnerLaneScope: (walletId: string) => Promise<OwnerLaneScope>;
  getEnginePorts: () => SigningEnginePorts;
  getRegistrationPublicDeps: () => registrationPublic.RegistrationPublicDeps;
  prepareNearEd25519YaoMaterialBoundary: Parameters<
    typeof createSigningEnginePorts
  >[0]['prepareNearEd25519YaoMaterialBoundary'];
};

export function createBrowserSigningSurfaceEnginePorts(
  args: BrowserSigningSurfaceEnginePortsArgs,
): SigningEnginePorts {
  const readCanonicalWalletSessionStatus = createBrowserCanonicalWalletSessionStatusReader(args);
  return createSigningEnginePorts({
    runtimePorts: args.runtimePorts,
    stores: args.stores,
    ed25519YaoPublicCapabilityReferences: args.ed25519YaoPublicCapabilityReferences,
    seamsWebConfigs: args.seamsWebConfigs,
    nearClient: args.nearClient,
    touchIdPrompt: args.touchIdPrompt,
    userPreferencesManager: args.userPreferencesManager,
    nonceCoordinator: args.nonceCoordinator,
    ensureSealedRefreshStartupParity: args.ensureSealedRefreshStartupParity,
    touchConfirm: args.touchConfirm,
    passkeyMpcSession: args.passkeyMpcSession,
    passkeyMpcExport: args.passkeyMpcExport,
    getEmailOtpWarmSessionStatus: (target) =>
      args.emailOtpSessions.readWarmSessionStatusOnly(target),
    consumeEmailOtpWarmSessionUses: (consumeArgs) =>
      args.emailOtpSessions.consumeWarmSessionUses(consumeArgs),
    clearEmailOtpWarmSessionMaterial: (thresholdSessionId) =>
      args.emailOtpSessions.clearVolatileWarmSessionMaterial({
        kind: 'ecdsa',
        thresholdSessionId,
      }),
    getWalletSessionStatus: (statusArgs) => readCanonicalWalletSessionStatus(statusArgs),
    resolveCanonicalEcdsaSigningCapability: (input) =>
      getBrowserCanonicalEcdsaSigningCapability(args, input),
    resolveAuthorizedEcdsaSigningCapability: (input) =>
      getBrowserEcdsaSigningCapability(args, input),
    resolveActiveEcdsaWalletSessionAuthorization:
      createBrowserActiveEcdsaWalletSessionAuthorizationResolver(args),
    resolveOwnerLaneScope: args.resolveOwnerLaneScope,
    signerWorkerManager: args.signerWorkerManager,
    getWorkerBaseOrigin: args.getWorkerBaseOrigin,
    workerWarmupPolicy: args.workerWarmupPolicy,
    getTheme: args.getTheme,
    signTempo: (signArgs) =>
      signEvmFamilyOperation(args.getEnginePorts().tempoSigningDeps, signArgs),
    activateAuthenticatedWalletState: (activationArgs) =>
      registrationPublic.activateAuthenticatedWalletState(args.getRegistrationPublicDeps(), {
        walletId: activationArgs.walletId,
        nearAccountId: activationArgs.nearAccountId,
        signerSlot: activationArgs.signerSlot,
        nearClient: activationArgs.nearClient,
      }),
    persistThresholdEcdsaBootstrapForWalletTarget: (persistArgs) =>
      persistThresholdEcdsaBootstrapForWalletTargetOperation({
        bootstrapStore: args.ecdsaBootstrapStore,
        walletId: persistArgs.walletId,
        chainTarget: persistArgs.chainTarget,
        bootstrap: persistArgs.bootstrap,
        signerAuth: persistArgs.signerAuth,
      }),
    requestEmailOtpTransactionSigningChallenge: (challengeArgs) =>
      requestEmailOtpEcdsaStepUpChallenge({
        coordinator: args.emailOtpSessions,
        walletSession: challengeArgs.walletSession,
        chain: challengeArgs.chain,
        authority: challengeArgs.authority,
        operationFingerprintDigest: challengeArgs.operationFingerprintDigest,
      }),
    requestEmailOtpEd25519SigningChallenge: ({ walletSession, operationFingerprintDigest }) =>
      args.emailOtpSessions.requestTransactionSigningChallenge({
        kind: 'wallet_login_challenge',
        walletSession,
        chain: 'near',
        operationFingerprintDigest,
      }),
    prepareNearEd25519YaoMaterialBoundary: args.prepareNearEd25519YaoMaterialBoundary,
    provisionThresholdEd25519Session: (provisionArgs) =>
      provisionThresholdEd25519SessionOperation(
        {
          credentialStore: args.stores.recoveryAndDeviceLinking.credentialStore,
          touchIdPrompt: args.touchIdPrompt,
          touchConfirm: args.passkeyMpcSession,
          defaultRelayerUrl: args.seamsWebConfigs.network.relayer?.url || '',
          getSignerWorkerContext: () =>
            args.getEnginePorts().walletSessionActivationDeps.getSignerWorkerContext(),
        },
        provisionArgs,
      ),
    restorePersistedSessionForSigning: (restoreArgs) =>
      restoreArgs.authMethod === 'passkey'
        ? args.passkeyMpcSession.restorePersistedSessionForSigning(
            omitPasskeyRestoreAuthMethod(restoreArgs),
          )
        : args.emailOtpSessions.restorePersistedSessionForSigning(restoreArgs),
    readAvailableSigningLanesForSigning: async (readArgs) =>
      readPersistedAvailableSigningLanesForSigningOperation(
        {
          activeWalletAuthorityEcdsaRuntimeReadPorts: {
            resolveSelectedWalletAuthority:
              IndexedDBManager.resolveSelectedWalletAuthority.bind(IndexedDBManager),
            readExactWithOperationCredential:
              walletSessionAuthorizations.readExactWithOperationCredential.bind(
                walletSessionAuthorizations,
              ),
          },
          ed25519YaoPublicCapabilityLanes: args.ed25519YaoPublicCapabilityReferences,
          isEd25519YaoPublicCapabilityActive: (reference) => {
            switch (reference.auth.kind) {
              case 'email_otp':
                return true;
              case 'passkey':
                return (
                  args.getEnginePorts().ed25519YaoActiveClients.resolve({
                    walletId: reference.walletId,
                    nearAccountId: reference.nearAccountId,
                    materialActivation: reference.materialActivation,
                  }) !== null
                );
            }
          },
          readActiveWalletSessionAuthorization: (walletId) =>
            readBrowserExactNearEd25519WalletSessionAuthorization(
              toWalletId(walletId),
              String(args.seamsWebConfigs.network.relayer?.url || '').trim(),
            ),
          listEcdsaSigningCapabilitiesForWallet: (input) =>
            listBrowserEcdsaSigningCapabilitiesForWallet(args, input),
        },
        readArgs,
        configuredThresholdEcdsaChainTargets(args.seamsWebConfigs.network.chains),
      ),
    provisionThresholdEcdsaSession: (provisionArgs) =>
      provisionThresholdEcdsaSessionOperation(
        {
          queueByWallet: args.thresholdEcdsaBootstrapQueueByWallet,
          activationDeps: args.getEnginePorts().walletSessionActivationDeps,
          persistEcdsaRoleLocalReadyRecord:
            args.runtimePorts.storage.persistEcdsaRoleLocalReadyRecord,
        },
        provisionArgs,
      ),
    withThresholdEcdsaSigningQueue: (queueArgs) =>
      withThresholdEcdsaSigningQueue({
        queueByKey: args.thresholdEcdsaSigningQueueByKey,
        ...queueArgs,
        walletId: toWalletId(queueArgs.walletId),
      }),
    withThresholdEd25519CommitQueue: (queueArgs) =>
      withThresholdEd25519CommitQueue({
        queueByKey: args.thresholdEd25519CommitQueueByKey,
        ...queueArgs,
      }),
  });
}

export type BrowserSigningSurfaceEnginePorts = SigningEnginePorts;
