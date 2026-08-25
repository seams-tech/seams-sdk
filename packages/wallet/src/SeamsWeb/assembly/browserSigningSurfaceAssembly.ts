import type { RuntimePorts } from '@/core/platform';
import { IndexedDBManager, walletSessionAuthorizations } from '@/core/indexedDB';
import type { OwnerLaneScope } from '@/core/signingEngine/session/identity/signingLaneAuthBinding';
import { IndexedDbEcdsaCapabilityManifestStore } from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import { SIGNING_SESSION_SEAL_GROUP_ID } from '@shared/utils/signingSessionSeal';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import { createRelayerReusableWalletSessionStatusPort } from '@/core/rpcClients/relayer/walletSessionAuthorizationStatus';
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
  type ActiveEvmFamilyWalletSessionAuthorization,
  type AuthorizedEvmFamilyEcdsaSigningCapability,
  type CanonicalEvmFamilyEcdsaSigningCapability,
  type EvmFamilyEcdsaSigningCapabilityAvailability,
} from '@/core/signingEngine/session/material/ecdsaSigningCapability';
import {
  isEmailOtpWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
  parseEmailOtpWalletAuthAuthority,
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
import type { EmailOtpTransactionSigningChallenge } from '@/core/signingEngine/session/emailOtp/publicTypes';
import type { RestorePersistedSessionForSigningInput } from '@/core/signingEngine/session/sealedRecovery/sealedRecovery.types';
import { __isWalletIframeHostMode } from '@/core/browser/walletIframe/host-mode';
import { walletSessionTokenForCurve } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { readOwnerWalletExecutionLaneProjectionV1 } from '@/core/rpcClients/relayer/ownerWalletExecutionLanePreflight';
import { hydrateWalletExecutionLane } from '@/core/signingEngine/session/lanes/walletExecutionLaneHydration';
import type { EcdsaCapabilityManifestLookup } from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import type { WalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import type { LocalWalletAuthMethodRecord } from '@/core/indexedDB/passkeyClientDB.types';

type SigningEnginePorts = ReturnType<typeof createSigningEnginePorts>;

const ecdsaCapabilityManifestStore = new IndexedDbEcdsaCapabilityManifestStore();

type BrowserEcdsaCapabilityReaderContext = Pick<
  BrowserSigningSurfaceEnginePortsArgs,
  'seamsWebConfigs' | 'emailOtpSessions' | 'sealedSigningSessionStore' | 'touchIdPrompt' | 'stores'
>;

function omitPasskeyRestoreAuthMethod(
  input: RestorePersistedSessionForSigningInput,
): Omit<RestorePersistedSessionForSigningInput, 'authMethod'> {
  if (input.authMethod !== 'passkey') {
    throw new Error('Passkey restore adapter received a non-Passkey request');
  }
  const { authMethod: _authMethod, ...passkeyRestore } = input;
  return passkeyRestore;
}

type ExactWalletAuthMethodStore = {
  getWalletAuthMethodV2(walletAuthMethodId: string): Promise<WalletAuthMethodRecordV2 | null>;
  listWalletAuthMethodsForWallet(walletId: string): Promise<readonly LocalWalletAuthMethodRecord[]>;
};

/**
 * R103C: the active wallet auth-method store is the one source that resolves
 * an authority reference to its full authority. Sealed-session restores and
 * loose authenticator lists are history and hints; matching against them let
 * a stale or sibling credential answer for the active authority.
 */
export async function resolveExactWalletAuthAuthority(
  authorityRef: WalletAuthAuthorityRef,
  walletAuthMethodStore: ExactWalletAuthMethodStore,
): Promise<WalletAuthAuthority> {
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
  let authority: WalletAuthAuthority;
  switch (authMethod.kind) {
    case 'passkey':
      authority = {
        walletId: authMethod.walletId,
        factor: {
          kind: 'passkey',
          credentialIdB64u: authMethod.credentialIdB64u,
        },
        verifier: {
          kind: 'webauthn',
          rpId: authMethod.rpId,
        },
        bindingId: authMethod.walletAuthMethodId,
      };
      break;
    case 'email_otp': {
      const localMethods = await walletAuthMethodStore.listWalletAuthMethodsForWallet(
        authMethod.walletId,
      );
      const matches = localMethods.filter(
        (method): method is Extract<LocalWalletAuthMethodRecord, { kind: 'email_otp' }> => {
          if (method.kind !== 'email_otp' || method.status !== 'active') return false;
          const candidate = parseEmailOtpWalletAuthAuthority(method.authority);
          return (
            candidate?.walletId === authMethod.walletId &&
            candidate.bindingId === authMethod.walletAuthMethodId &&
            candidate.verifier.emailHashHex === authMethod.emailHashHex
          );
        },
      );
      const exactAuthority =
        matches.length === 1 ? parseEmailOtpWalletAuthAuthority(matches[0].authority) : null;
      if (!exactAuthority) {
        throw new Error('Exact wallet authentication authority is unavailable');
      }
      authority = exactAuthority;
      break;
    }
    default:
      authMethod satisfies never;
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
    readAuthorization: async (walletId) => {
      const read = await walletSessionAuthorizations.readActiveForWallet(walletId);
      return read.kind === 'found' ? read.projection : null;
    },
  });
}

export type BrowserWalletSessionAuthorizationResolution =
  | { kind: 'active'; authorization: ActiveEvmFamilyWalletSessionAuthorization }
  | { kind: 'inactive'; reason: string };

// Resolves the wallet's reusable Wallet Session authorization pair (persisted
// projection + live relayer status). Configuration failures throw; inactive
// session states return `inactive` so warm-capability readers can degrade to
// `authorization_required` without treating them as errors.
export async function resolveBrowserActiveEcdsaWalletSessionAuthorization(
  args: BrowserEcdsaCapabilityReaderContext,
  walletId: Parameters<
    Parameters<typeof createSigningEnginePorts>[0]['resolveAuthorizedEcdsaSigningCapability']
  >[0]['walletId'],
): Promise<BrowserWalletSessionAuthorizationResolution> {
  const authorizationRead = await walletSessionAuthorizations.readActiveForWallet(walletId);
  if (authorizationRead.kind !== 'found') {
    return {
      kind: 'inactive',
      reason: `Reusable Wallet Session authorization is ${authorizationRead.kind}`,
    };
  }
  const projection = authorizationRead.projection;
  if (projection.expiresAtMs <= Date.now()) {
    return { kind: 'inactive', reason: 'Reusable Wallet Session authorization is expired' };
  }
  const relayerUrl = String(args.seamsWebConfigs.network.relayer?.url || '').trim();
  if (!relayerUrl) throw new Error('Reusable Wallet Session status requires a relayer URL');
  const walletSessionToken = walletSessionTokenForCurve(projection, 'ecdsa');
  if (!walletSessionToken) {
    return {
      kind: 'inactive',
      reason: 'Reusable Wallet Session authorization has no ECDSA token',
    };
  }
  const status = await createRelayerReusableWalletSessionStatusPort({
    relayerUrl,
    auth: { kind: 'opaque_wallet_session', walletSessionToken },
  }).read({
    walletSessionId: projection.walletSessionId,
    quotaId: projection.quotaId,
  });
  if (status.status !== 'active') {
    return { kind: 'inactive', reason: `Reusable Wallet Session is ${status.status}` };
  }
  return {
    kind: 'active',
    authorization: {
      kind: 'active_reusable_wallet_session_authorization',
      projection,
      status,
    },
  };
}

export function createBrowserActiveEcdsaWalletSessionAuthorizationResolver(
  args: BrowserEcdsaCapabilityReaderContext,
): (
  walletId: Parameters<typeof resolveBrowserActiveEcdsaWalletSessionAuthorization>[1],
) => Promise<ActiveEvmFamilyWalletSessionAuthorization | null> {
  return async (walletId) => {
    const resolution = await resolveBrowserActiveEcdsaWalletSessionAuthorization(args, walletId);
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
  const resolution = await resolveBrowserActiveEcdsaWalletSessionAuthorization(
    args,
    input.walletId,
  );
  if (resolution.kind !== 'active') {
    throw new Error(resolution.reason);
  }
  const browserAuthorization = resolution.authorization;
  const canonical = await resolveBrowserCanonicalEcdsaSigningCapability(args, input);
  const walletSessionToken = walletSessionTokenForCurve(browserAuthorization.projection, 'ecdsa');
  if (!walletSessionToken) {
    throw new Error('Owner ECDSA execution-lane preflight requires an opaque Wallet Session token');
  }
  const projection = await readOwnerWalletExecutionLaneProjectionV1({
    relayerUrl: String(args.seamsWebConfigs.network.relayer?.url || '').trim(),
    walletSessionToken,
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
  const authorizationResolution = await resolveBrowserActiveEcdsaWalletSessionAuthorization(
    args,
    walletId,
  );
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
    const capability = await browserCanonicalEcdsaCapabilityFromManifest(manifest);
    const capabilityAuthMethod = isPasskeyWalletAuthAuthority(capability.authority)
      ? 'passkey'
      : isEmailOtpWalletAuthAuthority(capability.authority)
        ? 'email_otp'
        : null;
    if (!capabilityAuthMethod || (input.authMethod && capabilityAuthMethod !== input.authMethod)) {
      continue;
    }
    if (
      authorizationResolution.kind === 'active' &&
      authorizationResolution.authorization.projection.authority.authorityDigest ===
        capability.manifest.signer.authority.authorityDigest
    ) {
      capabilities.push(
        authorizeEvmFamilyEcdsaSigningCapability({
          capability,
          authorization: authorizationResolution.authorization,
        }),
      );
      continue;
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
}): Promise<EmailOtpTransactionSigningChallenge> {
  switch (args.authority.kind) {
    case 'live_session':
      return await args.coordinator.requestTransactionSigningChallenge({
        kind: 'wallet_session_challenge',
        walletSession: args.walletSession,
        chain: args.chain,
        authLane: args.authority.authLane,
      });
    case 'capability_step_up':
      return await args.coordinator.requestTransactionSigningChallenge({
        kind: 'wallet_login_challenge',
        walletSession: args.walletSession,
        chain: args.chain,
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
      }),
    requestEmailOtpEd25519SigningChallenge: ({ walletSession }) =>
      args.emailOtpSessions.requestTransactionSigningChallenge({
        kind: 'wallet_login_challenge',
        walletSession,
        chain: 'near',
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
          readActiveWalletSessionAuthorization: async (walletId) => {
            const read = await walletSessionAuthorizations.readActiveForWallet(
              toWalletId(walletId),
            );
            return read.kind === 'found' ? read.projection : null;
          },
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
