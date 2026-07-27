import type { RuntimePorts } from '@/core/platform';
import { IndexedDBManager, walletSessionAuthorizations } from '@/core/indexedDB';
import { IndexedDbEcdsaCapabilityManifestStore } from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import {
  createRelayerReusableWalletSessionStatusPort,
  type ReusableWalletSessionStatusAuth,
} from '@/core/rpcClients/relayer/walletSessionAuthorizationStatus';
import { readPersistedAvailableSigningLanesForSigning as readPersistedAvailableSigningLanesForSigningOperation } from '@/core/signingEngine/session/availability/persistedAvailableSigningLanes';
import { readTrustedWalletSigningBudgetStatus as readTrustedWalletSigningBudgetStatusOperation } from '@/core/signingEngine/session/budget/budgetStatusReader';
import type { EmailOtpWalletSessionCoordinator } from '@/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator';
import {
  getThresholdEcdsaSessionRecordByKey as getThresholdEcdsaSessionRecordByIdentityOperation,
  getThresholdEcdsaSessionRecordForWalletTarget as getThresholdEcdsaSessionRecordForWalletTargetOperation,
  listThresholdEcdsaKeyRefsForWalletTarget as listThresholdEcdsaKeyRefsForWalletTargetOperation,
  listThresholdEcdsaSessionRecordsForWalletTarget as listThresholdEcdsaSessionRecordsForWalletTargetOperation,
  markThresholdEd25519EmailOtpSessionConsumedForWallet as markThresholdEd25519EmailOtpSessionConsumedForWalletOperation,
  type ThresholdEcdsaSessionRecord,
} from '@/core/signingEngine/session/persistence/records';
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
} from '@/core/signingEngine/flows/signEvmFamily/ecdsaSigningCapability';
import { buildPersistedEcdsaRoleLocalMaterial } from '@/core/signingEngine/session/material/ecdsaRoleLocalMaterialResolver';
import { listEcdsaSealedSessionsForWallet } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import { signEvmFamily as signEvmFamilyOperation } from '@/core/signingEngine/flows/signEvmFamily/signEvmFamily';
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
import type { UiConfirmRuntimeBridgePort } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type { WarmSigningPorts } from '@/core/signingEngine/assembly/ports/warmSigning';
import type { WorkerResourceWarmupPolicy } from '@/core/signingEngine/assembly/warmup';
import type { SeamsConfigsReadonly, ThemeMode } from '@/core/types/seams';
import type { AccountId } from '@/core/types/accountIds';
import * as registrationPublic from '@/core/signingEngine/flows/registration/public';
import type { Ed25519YaoPublicCapabilityReferenceStorePort } from '@/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';
import { rehydrateEmailOtpEd25519CapabilityForSigningV1 } from '@/core/signingEngine/session/emailOtp/ed25519YaoBudgetRecovery';
import type {
  EmailOtpEcdsaChallengeAuthority,
} from '@/core/signingEngine/flows/signEvmFamily/emailOtpSigningSession';
import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { parseAppSessionJwt, mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import { SIGNER_AUTH_METHODS, WALLET_AUTH_METHODS } from '@shared/utils/signerDomain';
import {
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
  type WalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type { EmailOtpTransactionSigningChallenge } from '@/core/signingEngine/session/emailOtp/publicTypes';

type SigningEnginePorts = ReturnType<typeof createSigningEnginePorts>;
type EmailOtpEd25519RecoveryRequest = Omit<
  Parameters<typeof rehydrateEmailOtpEd25519CapabilityForSigningV1>[0],
  | 'workerContext'
  | 'shamirPrimeB64u'
  | 'resolveActiveCapability'
  | 'activateCapability'
  | 'expectedOperationalPublicKey'
  | 'materialActivation'
>;

const ecdsaCapabilityManifestStore = new IndexedDbEcdsaCapabilityManifestStore();

type BrowserEcdsaCapabilityReaderContext = Pick<
  BrowserSigningSurfaceEnginePortsArgs,
  'seamsWebConfigs' | 'emailOtpSessions'
>;

async function resolveExactWalletAuthAuthority(
  authorityRef: WalletAuthAuthorityRef,
): Promise<WalletAuthAuthority> {
  const authMethods = await IndexedDBManager.listWalletAuthMethodsForWallet(
    authorityRef.walletId,
  );
  for (const authMethod of authMethods) {
    if (
      authMethod.kind !== 'passkey' ||
      authMethod.status !== 'active' ||
      authMethod.localStatus !== 'synced'
    ) {
      continue;
    }
    const authority = buildPasskeyWalletAuthAuthority({
      walletId: authMethod.walletId,
      rpId: authMethod.rpId,
      credentialIdB64u: authMethod.credentialIdB64u,
    });
    const candidateRef = await walletAuthAuthorityRef({ authority });
    if (candidateRef.authorityDigest === authorityRef.authorityDigest) return authority;
  }
  const sealedRecords = await listEcdsaSealedSessionsForWallet({
    walletId: authorityRef.walletId,
    filter: { curve: 'ecdsa', authMethod: WALLET_AUTH_METHODS.emailOtp },
  });
  for (const sealedRecord of sealedRecords) {
    if (
      !('recordKind' in sealedRecord) ||
      sealedRecord.ecdsaRestore.source !== 'email_otp' ||
      sealedRecord.ecdsaRestore.authority.authorityDigest !== authorityRef.authorityDigest
    ) {
      continue;
    }
    return sealedRecord.ecdsaRestore.emailOtpAuthority;
  }
  throw new Error('Exact wallet authentication authority is unavailable');
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
  let auth: ReusableWalletSessionStatusAuth;
  if (projection.authMethod === WALLET_AUTH_METHODS.emailOtp) {
    const jwt = await args.emailOtpSessions.resolveAppSessionJwt({
      walletSession: {
        walletId,
        walletSessionUserId: String(projection.authority.authorityDigest),
      },
      relayUrl: relayerUrl,
    });
    const parsedJwt = parseAppSessionJwt(jwt);
    if (!parsedJwt.ok) throw new Error(parsedJwt.error.message);
    auth = { kind: 'app_session_jwt', appSessionJwt: parsedJwt.value };
  } else {
    auth = { kind: 'app_session_cookie' };
  }
  const status = await createRelayerReusableWalletSessionStatusPort({ relayerUrl, auth }).read({
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
  const projection = browserAuthorization.projection;
  const manifestLookup = await ecdsaCapabilityManifestStore.lookup({
    capability: input.materialActivation.capability,
    authority: projection.authority,
  });
  if (manifestLookup.kind !== 'active') {
    throw new Error(`ECDSA capability manifest is ${manifestLookup.kind}`);
  }
  const manifest = manifestLookup.manifest;
  if (
    !mpcMaterialActivationRefsEqual(
      manifest.activation.materialActivation,
      input.materialActivation,
    ) ||
    !manifest.signer.scope.targetMemberships.some(
      (target) =>
        thresholdEcdsaChainTargetKey(target) === thresholdEcdsaChainTargetKey(input.chainTarget),
    )
  ) {
    throw new Error('ECDSA capability manifest does not match the requested signer');
  }
  return authorizeEvmFamilyEcdsaSigningCapability({
    capability: await buildCanonicalEvmFamilyEcdsaSigningCapability({
      authority: await resolveExactWalletAuthAuthority(projection.authority),
      manifest,
      material: buildPersistedEcdsaRoleLocalMaterial({
        authority: manifest.signer.authority,
        materialActivation: manifest.activation.materialActivation,
        publicFacts: manifest.durableMaterial.roleLocalPublicFacts,
      }),
    }),
    authorization: browserAuthorization,
  });
}

export async function listBrowserEcdsaSigningCapabilitiesForWallet(
  args: BrowserEcdsaCapabilityReaderContext,
  input: {
    walletId: string;
    chainTargets: readonly ThresholdEcdsaChainTarget[];
    authMethod?: 'email_otp' | 'passkey';
  },
): Promise<readonly AuthorizedEvmFamilyEcdsaSigningCapability[]> {
  const walletId = toWalletId(input.walletId);
  const subjects = await ecdsaCapabilityManifestStore.listActiveWalletCapabilitySubjects(walletId);
  if (subjects.kind !== 'resolved') return [];
  const capabilities: AuthorizedEvmFamilyEcdsaSigningCapability[] = [];
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
    const capability = await getBrowserEcdsaSigningCapability(args, {
      walletId,
      chainTarget: manifest.signer.scope.targetMemberships[0],
      materialActivation: manifest.activation.materialActivation,
    });
    if (input.authMethod && capability.authorization.projection.authMethod !== input.authMethod) {
      continue;
    }
    capabilities.push(capability);
  }
  return capabilities;
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
    case 'public_reauth_anchor':
      return await args.coordinator.requestPublicReauthTransactionSigningChallenge({
        walletSession: args.walletSession,
        chain: args.chain,
      });
  }
}

async function resolveBrowserEcdsaOperationStepUpSessionAuth(args: {
  context: BrowserEcdsaCapabilityReaderContext;
  walletSession: WalletSessionRef;
  authMethod: 'passkey' | 'email_otp';
}) {
  switch (args.authMethod) {
    case 'passkey':
      return { kind: 'app_session_cookie' } as const;
    case 'email_otp': {
      const relayerUrl = String(args.context.seamsWebConfigs.network.relayer?.url || '').trim();
      if (!relayerUrl) throw new Error('ECDSA operation step-up requires a relayer URL');
      const jwt = await args.context.emailOtpSessions.resolveAppSessionJwt({
        walletSession: args.walletSession,
        relayUrl: relayerUrl,
      });
      const parsedJwt = parseAppSessionJwt(jwt);
      if (!parsedJwt.ok) throw new Error(parsedJwt.error.message);
      return { kind: 'app_session_jwt', appSessionJwt: parsedJwt.value } as const;
    }
  }
}

async function rehydrateEmailOtpEd25519CapabilityForSigning(args: {
  assembly: BrowserSigningSurfaceEnginePortsArgs;
  request: EmailOtpEd25519RecoveryRequest;
}) {
  const user = await registrationPublic.getUserBySignerSlot(
    args.assembly.getRegistrationPublicDeps(),
    args.request.nearAccountId,
    args.request.record.signerSlot,
  );
  if (
    !user ||
    String(user.walletId) !== String(args.request.record.walletId) ||
    user.authMethod !== SIGNER_AUTH_METHODS.emailOtp
  ) {
    throw new Error('Email OTP Ed25519 recovery requires one exact persisted signer projection');
  }
  const references = [];
  for (const reference of await args.assembly.ed25519YaoPublicCapabilityReferences.list()) {
    if (
      String(reference.walletId) === String(args.request.record.walletId) &&
      String(reference.nearAccountId) === String(args.request.nearAccountId)
    ) {
      references.push(reference);
    }
  }
  if (references.length !== 1 || !references[0]) {
    throw new Error('Email OTP Ed25519 recovery requires one exact public material activation');
  }
  const recovered = await rehydrateEmailOtpEd25519CapabilityForSigningV1({
    nearAccountId: args.request.nearAccountId,
    record: args.request.record,
    committedLane: args.request.committedLane,
    challengeId: args.request.challengeId,
    otpCode: args.request.otpCode,
    remainingUses: args.request.remainingUses,
    expectedOperationalPublicKey: user.operationalPublicKey,
    workerContext: args.assembly.signerWorkerManager.getContext(),
    shamirPrimeB64u: args.assembly.seamsWebConfigs.signing.sessionSeal.shamirPrimeB64u,
    materialActivation: references[0].materialActivation,
    resolveActiveCapability: (scope) =>
      args.assembly.getEnginePorts().ed25519YaoActiveClients.resolveForWalletAccount(scope),
    activateCapability: (capability) =>
      args.assembly.getEnginePorts().ed25519YaoActiveClients.activate(capability),
  });
  await args.assembly.emailOtpSessions.persistEd25519YaoSessionForRefresh({
    record: recovered.record,
    rpId: args.assembly.touchIdPrompt.getRpId(),
  });
  return recovered;
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
  signerWorkerManager: SignerWorkerManager;
  emailOtpSessions: EmailOtpWalletSessionCoordinator;
  warmSigning: WarmSigningPorts;
  ecdsaBootstrapStore: ThresholdEcdsaBootstrapStorePort;
  thresholdEcdsaBootstrapQueueByWallet: Map<string, Promise<void>>;
  thresholdEcdsaSigningQueueByKey: ThresholdEcdsaSigningQueueByKey;
  thresholdEd25519CommitQueueByKey: ThresholdEd25519CommitQueueByKey;
  getWorkerBaseOrigin: () => string;
  workerWarmupPolicy: WorkerResourceWarmupPolicy;
  getTheme: () => ThemeMode;
  ensureSealedRefreshStartupParity: () => Promise<void>;
  getEnginePorts: () => SigningEnginePorts;
  getRegistrationPublicDeps: () => registrationPublic.RegistrationPublicDeps;
  rehydratePasskeyEd25519YaoCapabilityForSigning: Parameters<
    typeof createSigningEnginePorts
  >[0]['rehydratePasskeyEd25519YaoCapabilityForSigning'];
  preparePasskeyEd25519YaoOperationStepUpForSigning: Parameters<
    typeof createSigningEnginePorts
  >[0]['preparePasskeyEd25519YaoOperationStepUpForSigning'];
  recoverEmailOtpEd25519YaoCapabilitySilentlyForSigning: Parameters<
    typeof createSigningEnginePorts
  >[0]['recoverEmailOtpEd25519YaoCapabilitySilentlyForSigning'];
};

export function createBrowserSigningSurfaceEnginePorts(
  args: BrowserSigningSurfaceEnginePortsArgs,
): SigningEnginePorts {
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
    getEmailOtpWarmSessionStatus: (sessionId) =>
      args.emailOtpSessions.readWarmSessionStatusOnly(sessionId),
    consumeEmailOtpWarmSessionUses: (consumeArgs) =>
      args.emailOtpSessions.consumeWarmSessionUses(consumeArgs),
    clearEmailOtpWarmSessionMaterial: args.emailOtpSessions.clearVolatileWarmSessionMaterial.bind(
      args.emailOtpSessions,
    ),
    getWalletSigningBudgetStatus: (statusArgs) =>
      readTrustedWalletSigningBudgetStatusOperation(
        {
          ecdsaSessions: args.warmSigning.ecdsaSessions,
        },
        statusArgs,
      ),
    resolveAuthorizedEcdsaSigningCapability: (input) => getBrowserEcdsaSigningCapability(args, input),
    resolveActiveEcdsaWalletSessionAuthorization:
      createBrowserActiveEcdsaWalletSessionAuthorizationResolver(args),
    resolveEcdsaOperationStepUpSessionAuth: (input) =>
      resolveBrowserEcdsaOperationStepUpSessionAuth({
        context: args,
        walletSession: input.walletSession,
        authMethod: input.authMethod,
      }),
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
    listThresholdEcdsaKeyRefsForWalletTarget: (listArgs) =>
      listThresholdEcdsaKeyRefsForWalletTargetOperation(args.warmSigning.ecdsaSessions, listArgs),
    listThresholdEcdsaSessionRecordsForWalletTarget: (listArgs) =>
      listThresholdEcdsaSessionRecordsForWalletTargetOperation(
        args.warmSigning.ecdsaSessions,
        listArgs,
      ),
    getThresholdEcdsaSessionRecordByKey: (identity) =>
      getThresholdEcdsaSessionRecordByIdentityOperation(args.warmSigning.ecdsaSessions, identity),
    getPasskeyThresholdEcdsaSessionRecordForSigning: (recordArgs) =>
      getThresholdEcdsaSessionRecordForWalletTargetOperation(args.warmSigning.ecdsaSessions, {
        walletId: recordArgs.walletId,
        chainTarget: recordArgs.chainTarget,
        source: recordArgs.source,
      }),
    requestEmailOtpTransactionSigningChallenge: (challengeArgs) =>
      requestEmailOtpEcdsaStepUpChallenge({
        coordinator: args.emailOtpSessions,
        walletSession: challengeArgs.walletSession,
        chain: challengeArgs.chain,
        authority: challengeArgs.authority,
      }),
    requestEmailOtpEd25519SigningChallenge: (challengeArgs) =>
      args.emailOtpSessions.requestTransactionSigningChallenge({
        kind: 'near_account_challenge',
        walletSession: challengeArgs.walletSession,
        nearAccountId: challengeArgs.nearAccountId,
        chain: 'near',
        authLane: challengeArgs.authLane,
      }),
    rehydrateEmailOtpEd25519CapabilityForSigning: (recoveryArgs) =>
      rehydrateEmailOtpEd25519CapabilityForSigning({ assembly: args, request: recoveryArgs }),
    rehydratePasskeyEd25519YaoCapabilityForSigning:
      args.rehydratePasskeyEd25519YaoCapabilityForSigning,
    preparePasskeyEd25519YaoOperationStepUpForSigning:
      args.preparePasskeyEd25519YaoOperationStepUpForSigning,
    recoverEmailOtpEd25519YaoCapabilitySilentlyForSigning:
      args.recoverEmailOtpEd25519YaoCapabilitySilentlyForSigning,
    provisionThresholdEd25519Session: (provisionArgs) =>
      provisionThresholdEd25519SessionOperation(
        {
          credentialStore: args.stores.recoveryAndDeviceLinking.credentialStore,
          touchIdPrompt: args.touchIdPrompt,
          touchConfirm: args.touchConfirm,
          defaultRelayerUrl: args.seamsWebConfigs.network.relayer?.url || '',
          getSignerWorkerContext: () =>
            args.getEnginePorts().walletSessionActivationDeps.getSignerWorkerContext(),
        },
        provisionArgs,
      ),
    restorePersistedSessionForSigning: (restoreArgs) =>
      restoreArgs.authMethod === 'passkey'
        ? args.touchConfirm.restorePersistedSessionForSigning({
            ...restoreArgs,
            authMethod: 'passkey',
          })
        : args.emailOtpSessions.restorePersistedSessionForSigning(restoreArgs),
    readAvailableSigningLanesForSigning: (readArgs) =>
      readPersistedAvailableSigningLanesForSigningOperation(
        {
          listEcdsaSigningCapabilitiesForWallet: (input) =>
            listBrowserEcdsaSigningCapabilitiesForWallet(args, input),
          statusReader: args.warmSigning.statusUiConfirm,
          getEmailOtpWarmSessionStatus: (sessionId) =>
            args.warmSigning.statusUiConfirm.getWarmSessionStatus({ sessionId }),
          getWalletSigningBudgetStatus: (statusArgs) =>
            args.getEnginePorts().signingSessionCoordinator.getAvailableStatus(statusArgs),
        },
        readArgs,
        configuredThresholdEcdsaChainTargets(args.seamsWebConfigs.network.chains),
      ),
    markThresholdEd25519EmailOtpSessionConsumedForWallet: (markArgs) =>
      markThresholdEd25519EmailOtpSessionConsumedForWalletOperation(markArgs),
    provisionThresholdEcdsaSession: (provisionArgs) =>
      provisionThresholdEcdsaSessionOperation(
        {
          queueByWallet: args.thresholdEcdsaBootstrapQueueByWallet,
          activationDeps: args.getEnginePorts().walletSessionActivationDeps,
          touchConfirm: args.touchConfirm,
          persistEcdsaRoleLocalReadyRecord:
            args.runtimePorts.storage.persistEcdsaRoleLocalReadyRecord,
          resolveSealTransport: ({ lane }) =>
            args.warmSigning.capabilityReader.resolveEcdsaSealTransportByThresholdSessionId({
              lane,
            }),
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
