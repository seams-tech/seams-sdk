import type {
  AfterCall,
  CreateUnlockFlowEventInput,
  LoginHooksOptions,
} from '@/core/types/sdkSentEvents';
import { createUnlockFlowEvent, UnlockEventPhase } from '@/core/types/sdkSentEvents';
import type {
  GetRecentUnlocksResult,
  LoginAndCreateSessionResult,
  LoginResult,
  WalletSession,
  LoginState,
  SigningSessionStatus,
  ThresholdWarmLoginAndCreateSessionResult,
  WalletAuthMethod,
} from '@/core/types/seams';
import type {
  EcdsaLoginSessionSurface,
  LockWebContext,
  LoginWebContext,
  LoginWarmSigningSurface,
  RecentUnlocksWebContext,
  UserAccountLookupSurface,
  WalletSessionWebContext,
} from '@/web/SeamsWeb/signingSurface/types';
import type { AccountId } from '@/core/types/accountIds';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import {
  getUserFriendlyErrorMessage,
  isUserCancellationError,
  toError,
} from '@shared/utils/errors';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { isObject } from '@shared/utils/validation';
import { IndexedDBManager } from '@/core/indexedDB';
import {
  getLastSelectedNearAccount,
  getNearAccountProjection,
  resolveNearAccountProfileContinuity,
} from '@/core/accountData/near/accountProjection';
import { getNearThresholdKeyMaterial } from '@/core/accountData/near/keyMaterial';
import type { ClientAuthenticatorData, ClientUserData } from '@/core/accountData/near/types';
import { exchangeSession, type SessionExchangeInput } from '@/core/rpcClients/near/rpcCalls';
import {
  repairWalletEcdsaKeyFactsInventoryWithAppSession,
  repairWalletEcdsaKeyFactsInventoryWithWebAuthn,
  type WalletEcdsaKeyFactsInventoryTarget,
} from '@/core/rpcClients/relayer/walletRegistration';
import type { ThresholdEcdsaHssRouteAuth } from '@/core/rpcClients/relayer/thresholdEcdsa';
import { parseSignerSlot } from '@/core/signingEngine/webauthnAuth/device/signerSlot';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  getStoredThresholdEd25519SessionRecordForAccount,
  thresholdEcdsaSessionRecordReadModel,
  type ThresholdEcdsaSessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import { parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord } from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import type { ThresholdEcdsaSessionStoreSource } from '@/core/signingEngine/session/identity/laneIdentity';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import {
  parseThresholdRuntimePolicyScopeFromJwt,
  type ThresholdRuntimePolicyScope,
} from '@/core/signingEngine/threshold/sessionPolicy';
import {
  buildThresholdEd25519ProvidedPrfSecretSource,
  buildThresholdEd25519WebAuthnPrfSecretSource,
  type ThresholdEd25519SessionMintAuthorization,
} from '@/core/signingEngine/threshold/ed25519/authSession';
import { shouldRequireThresholdWarmSession } from '@/web/SeamsWeb/operations/session/thresholdWarmSessionDefaults';
import { prewarmThresholdEd25519ClientBaseFromCredential } from '@/web/SeamsWeb/operations/session/thresholdWarmSessionBootstrap';
import { listConfiguredThresholdEcdsaPublicationTargets } from '@/web/SeamsWeb/operations/session/thresholdEcdsaProvisioning';
import type {
  AvailableSigningLanes,
  ConcreteAvailableEcdsaSigningLane,
  AvailableEcdsaSigningLane,
  AvailableEd25519SigningLane,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import {
  ecdsaAvailableLaneForTarget,
  ecdsaAvailableLaneTargets,
  isConcreteAvailableSigningLane,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import { assertWalletRuntimePostconditions } from '@/core/signingEngine/session/postconditions/runtimePostconditions';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
  type WalletId,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { buildEcdsaSessionIdentity } from '@/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaSessionLanePolicy,
  evmFamilyEcdsaWalletKeyToIdentity,
  resolveThresholdEcdsaKeyIdFromRecord,
  resolveThresholdSigningRootBindingFromRecord,
  toEvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyIdentity,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildSharedKeyTargetCompletion,
  collectConfiguredTargetThresholdEcdsaWarmKeys,
  configuredTargetThresholdEcdsaWarmKey,
  mergeCanonicalThresholdEcdsaWarmSessionContexts,
  parseActiveEcdsaSignerRecordForUnlock,
  planUnlockEcdsaWarmup,
  requireCompleteSharedKeyTargetContext,
  type ActiveEcdsaSignerRecord,
  type BlockedEcdsaSignerRecord,
  type CanonicalThresholdEcdsaWarmSessionContext,
  type ConfiguredTargetThresholdEcdsaWarmKey,
  type RepairRequiredEcdsaSignerRecord,
  type SharedKeyTargetCompletion,
  type WalletUnlockSelection,
} from '@/core/signingEngine/session/passkey/unlockEcdsaWarmupPlanner';
import {
  DEV_DEFAULT_UNLOCK_REMAINING_USES,
  resolveSigningBudgetPolicyRemainingUses,
  resolveWalletUnlockBudgetPolicyFromRequestedUses,
  type WalletUnlockBudgetPolicy,
} from '@/core/signingEngine/session/budget/policy';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import { computeWalletEcdsaKeyFactsInventoryChallengeDigestB64u } from '@shared/utils/ecdsaKeyFactsInventory';
import { collectPasskeyLoginAssertion } from '@/web/SeamsWeb/operations/authMethods/passkey/loginAssertion';
import {
  collectFreshLocalPasskeyUnlockCredential,
  createLocalUnlockChallengeB64u,
} from '@/web/SeamsWeb/operations/authMethods/passkey/localUnlock';
import {
  passkeyCredentialIdB64uFromAuthentication,
  passkeyPrfFirstB64uFromCredential,
} from '@/web/SeamsWeb/operations/authMethods/passkey/ecdsaBootstrap';

type EmitUnlockEventInput = Omit<CreateUnlockFlowEventInput, 'accountId' | 'flowId'>;

function emitUnlockEvent(
  onEvent: LoginHooksOptions['onEvent'] | undefined,
  nearAccountId: AccountId,
  event: EmitUnlockEventInput,
): void {
  onEvent?.(
    createUnlockFlowEvent({
      flowId: `unlock:${nearAccountId}`,
      accountId: String(nearAccountId),
      ...event,
    }),
  );
}

function resolveLoginWalletUnlockSelection(
  selection: LoginHooksOptions['unlockSelection'] | undefined,
): WalletUnlockSelection {
  switch (selection?.mode) {
    case 'ed25519_only':
      return { mode: 'ed25519_only', ed25519: true };
    case 'ecdsa_only':
      return { mode: 'ecdsa_only', ecdsa: true };
    case 'ed25519_and_ecdsa':
    case undefined:
      return { mode: 'ed25519_and_ecdsa', ed25519: true, ecdsa: true };
  }
  selection satisfies never;
  return { mode: 'ed25519_and_ecdsa', ed25519: true, ecdsa: true };
}

type LoginUnlockAccountSubject =
  | {
      kind: 'near_operational_signer';
      userData: ClientUserData;
      operationalPublicKey: string;
    }
  | {
      kind: 'ecdsa_wallet_only';
      userData: ClientUserData;
      operationalPublicKey: null;
    };

type LoginUnlockAccountPhase = {
  kind: 'login_unlock_account_phase_ready';
  accountSubject: LoginUnlockAccountSubject;
  authenticators: ClientAuthenticatorData[];
  baseSignerSlot: number;
  localUnlockAuthMethod: WalletAuthMethod;
  requiresLocalPasskeyUnlock: boolean;
};

type LoginEcdsaKeyFactsRepairAuthority =
  | {
      kind: 'app_session';
      appSessionJwt: string;
      policyExpiresAtMs: number;
    }
  | {
      kind: 'webauthn';
    };

function walletUnlockSelectionRequiresEd25519(selection: WalletUnlockSelection): boolean {
  return selection.mode === 'ed25519_only' || selection.mode === 'ed25519_and_ecdsa';
}

function isActiveThresholdLoginSigningSession(
  sessionStatus: SigningSessionStatus | null | undefined,
): sessionStatus is ThresholdWarmLoginAndCreateSessionResult['signingSession'] {
  return sessionStatus?.status === 'active';
}

function resolveLoginEcdsaKeyFactsRepairAuthority(args: {
  repair: LoginHooksOptions['ecdsaKeyFactsRepair'] | undefined;
  appSessionJwt?: string;
}): LoginEcdsaKeyFactsRepairAuthority | null {
  if (!args.repair) return null;
  switch (args.repair.mode) {
    case 'app_session': {
      const appSessionJwt = String(args.repair.appSessionJwt || args.appSessionJwt || '').trim();
      if (!appSessionJwt) return null;
      const requestedTtlMs = Math.floor(Number(args.repair.policyTtlMs) || 0);
      const policyTtlMs = requestedTtlMs > 0 ? requestedTtlMs : 60_000;
      return {
        kind: 'app_session',
        appSessionJwt,
        policyExpiresAtMs: Date.now() + policyTtlMs,
      };
    }
    case 'webauthn':
      return { kind: 'webauthn' };
  }
  return null;
}

type ResolveThresholdLoginWarmupPhaseInputArgs = {
  context: LoginWebContext;
  signerSlot: number;
  selection: WalletUnlockSelection;
  repair: LoginHooksOptions['ecdsaKeyFactsRepair'] | undefined;
  appSessionJwt?: string;
  useAppSessionCookie?: boolean;
};

type ThresholdLoginWarmupPhaseInput = {
  kind: 'threshold_login_warmup_phase_input';
  signerSlot: number;
  selection: WalletUnlockSelection;
  relayerUrl: string;
  rpId: string;
  configuredEcdsaTargets: ConfiguredThresholdEcdsaPublicationTarget[];
  selectedEcdsaTargets: ConfiguredThresholdEcdsaPublicationTarget[];
  wantsEd25519Warmup: boolean;
  wantsEcdsaWarmup: boolean;
  repairAuthority: LoginEcdsaKeyFactsRepairAuthority | null;
  appSessionJwt?: string;
  useAppSessionCookie?: boolean;
};

function resolveThresholdLoginWarmupPhaseInput(
  args: ResolveThresholdLoginWarmupPhaseInputArgs,
): ThresholdLoginWarmupPhaseInput {
  const relayerUrl = String(args.context.configs?.network.relayer?.url || '').trim();
  if (!relayerUrl) {
    throw new Error('[login] threshold warm session requires relayer.url to be configured');
  }
  const configuredEcdsaTargets = listConfiguredThresholdEcdsaPublicationTargets(
    args.context.configs.network.chains,
  );
  const wantsEd25519Warmup =
    args.selection.mode === 'ed25519_only' || args.selection.mode === 'ed25519_and_ecdsa';
  const wantsEcdsaWarmup =
    configuredEcdsaTargets.length > 0 &&
    (args.selection.mode === 'ecdsa_only' || args.selection.mode === 'ed25519_and_ecdsa');
  return {
    kind: 'threshold_login_warmup_phase_input',
    signerSlot: args.signerSlot,
    selection: args.selection,
    relayerUrl,
    rpId: String(args.context.signingEngine.getRpId() || '').trim(),
    configuredEcdsaTargets,
    selectedEcdsaTargets: wantsEcdsaWarmup ? configuredEcdsaTargets : [],
    wantsEd25519Warmup,
    wantsEcdsaWarmup,
    repairAuthority: resolveLoginEcdsaKeyFactsRepairAuthority({
      repair: args.repair,
      appSessionJwt: args.appSessionJwt,
    }),
    ...(args.appSessionJwt ? { appSessionJwt: args.appSessionJwt } : {}),
    ...(args.useAppSessionCookie === undefined
      ? {}
      : { useAppSessionCookie: args.useAppSessionCookie }),
  };
}

async function assertPasskeyUnlockRuntimePostconditions(args: {
  context: LoginWebContext;
  nearAccountId: AccountId;
  signersWarmed: readonly ('ed25519' | 'ecdsa')[];
}): Promise<void> {
  const requiredTargets = [
    ...(args.signersWarmed.includes('ed25519') ? [{ curve: 'ed25519' as const }] : []),
    ...(args.signersWarmed.includes('ecdsa')
      ? listConfiguredThresholdEcdsaPublicationTargets(args.context.configs.network.chains).map(
          (target) => ({ curve: 'ecdsa' as const, chainTarget: target.chainTarget }),
        )
      : []),
  ];
  if (requiredTargets.length === 0) return;
  await assertWalletRuntimePostconditions({
    source: 'wallet_unlock',
    walletId: String(args.nearAccountId),
    authMethod: 'passkey',
    requiredTargets,
    readPersistedAvailableSigningLanes: async (input) =>
      await args.context.signingEngine.readPersistedAvailableSigningLanes(input),
  });
}

function normalizeLoginUnlockAccountSubject(args: {
  userData: ClientUserData;
  selection: WalletUnlockSelection;
  nearAccountId: AccountId;
}): LoginUnlockAccountSubject {
  const operationalPublicKey =
    typeof args.userData.operationalPublicKey === 'string'
      ? args.userData.operationalPublicKey.trim()
      : '';
  if (operationalPublicKey) {
    return {
      kind: 'near_operational_signer',
      userData: args.userData,
      operationalPublicKey,
    };
  }
  if (walletUnlockSelectionRequiresEd25519(args.selection)) {
    throw new Error(
      `No NEAR operational key found for ${args.nearAccountId}. Please register an account.`,
    );
  }
  return {
    kind: 'ecdsa_wallet_only',
    userData: args.userData,
    operationalPublicKey: null,
  };
}

async function readLoginUnlockAccountPhase(args: {
  signingEngine: UserAccountLookupSurface;
  nearAccountId: AccountId;
  signerSlotHint: number | null;
  selection: WalletUnlockSelection;
  onEvent?: LoginHooksOptions['onEvent'];
}): Promise<LoginUnlockAccountPhase> {
  emitUnlockEvent(args.onEvent, args.nearAccountId, {
    phase: UnlockEventPhase.STEP_02_ACCOUNT_LOOKUP_STARTED,
    status: 'running',
    authMethod: 'passkey',
  });

  const hintUserPromise: Promise<ClientUserData | null> =
    args.signerSlotHint !== null
      ? args.signingEngine
          .getUserBySignerSlot(args.nearAccountId, args.signerSlotHint)
          .catch(() => null)
      : Promise.resolve(null);

  const [hintUser, lastUser, latestByAccount, authenticators] = await Promise.all([
    hintUserPromise,
    args.signingEngine.getLastUser().catch(() => null),
    getNearAccountProjection(IndexedDBManager, args.nearAccountId).catch(() => null),
    args.signingEngine.nearAuthenticatorsByAccount(args.nearAccountId).catch(() => []),
  ]);

  if (authenticators.length === 0) {
    throw new Error(
      `No authenticators found for account ${args.nearAccountId}. Please register an account.`,
    );
  }

  let userData: ClientUserData | null = null;
  if (hintUser && hintUser.nearAccountId === args.nearAccountId) {
    userData = hintUser;
  } else if (latestByAccount && latestByAccount.nearAccountId === args.nearAccountId) {
    userData = latestByAccount;
  } else if (lastUser && lastUser.nearAccountId === args.nearAccountId) {
    userData = lastUser;
  } else {
    userData = await args.signingEngine
      .getUserBySignerSlot(args.nearAccountId, 1)
      .catch(() => null);
  }

  if (!userData) {
    throw new Error(
      `User data not found for ${args.nearAccountId} in IndexedDB. Please register an account.`,
    );
  }
  const accountSubject = normalizeLoginUnlockAccountSubject({
    userData,
    selection: args.selection,
    nearAccountId: args.nearAccountId,
  });

  emitUnlockEvent(args.onEvent, args.nearAccountId, {
    phase: UnlockEventPhase.STEP_02_ACCOUNT_LOOKUP_SUCCEEDED,
    status: 'succeeded',
    authMethod: 'passkey',
    data: {
      signerSlot: userData.signerSlot,
      ...(accountSubject.operationalPublicKey
        ? { operationalPublicKey: accountSubject.operationalPublicKey }
        : { walletKind: accountSubject.kind }),
    },
  });

  const baseSignerSlot =
    args.signerSlotHint ??
    (Number.isFinite(userData.signerSlot) && userData.signerSlot >= 1 ? userData.signerSlot : 1);
  const localUnlockAuthMethod = userData.authMethod || SIGNER_AUTH_METHODS.passkey;
  return {
    kind: 'login_unlock_account_phase_ready',
    accountSubject,
    authenticators,
    baseSignerSlot,
    localUnlockAuthMethod,
    requiresLocalPasskeyUnlock: localUnlockAuthMethod === SIGNER_AUTH_METHODS.passkey,
  };
}

/**
 * Core login function (passkey identity + relay-issued sessions).
 *
 * Responsibilities:
 * - Select the active account + signer slot (last-user pointer).
 * - Optionally mint a relayer app session (JWT/cookie) via session exchange.
 *
 * Note: signing flows still perform their own UserConfirm/WebAuthn prompting as needed.
 */
export async function unlock(
  context: LoginWebContext,
  nearAccountId: AccountId,
  options?: LoginHooksOptions,
): Promise<LoginAndCreateSessionResult> {
  const { onEvent, onError, afterCall } = options || {};
  const { signingEngine } = context;
  let loginCredential: WebAuthnAuthenticationCredential | undefined;

  emitUnlockEvent(onEvent, nearAccountId, {
    phase: UnlockEventPhase.STEP_01_STARTED,
    status: 'started',
    authMethod: 'passkey',
  });

  try {
    await signingEngine.assertSealedRefreshStartupParity();

    if (typeof window !== 'undefined' && !window.isSecureContext) {
      const errorMessage = 'Passkey operations require a secure context (HTTPS or localhost).';
      return await finalizeLoginError({
        nearAccountId,
        message: errorMessage,
        error: new Error(errorMessage),
        onEvent,
        onError,
        afterCall,
        callAfterCall: false,
      });
    }

    const signerSlotHint = parseSignerSlot(options?.signerSlot, { min: 1 });
    const walletUnlockSelection = resolveLoginWalletUnlockSelection(options?.unlockSelection);
    const accountPhase = await readLoginUnlockAccountPhase({
      signingEngine,
      nearAccountId,
      signerSlotHint,
      selection: walletUnlockSelection,
      onEvent,
    });
    const { accountSubject, authenticators, baseSignerSlot, requiresLocalPasskeyUnlock } =
      accountPhase;

    const collectLocalPasskeyCredentialForChallenge = async (args: {
      challengeB64u: string;
      saveAsLoginCredential: boolean;
    }): Promise<WebAuthnAuthenticationCredential> => {
      const credential = await collectPasskeyLoginAssertion({
        signingEngine,
        subjectId: String(nearAccountId),
        challengeB64u: args.challengeB64u,
        authenticators,
        onPromptStarted: () => {
          emitUnlockEvent(onEvent, nearAccountId, {
            phase: UnlockEventPhase.STEP_03_PASSKEY_PROMPT_STARTED,
            status: 'waiting_for_user',
            authMethod: 'passkey',
            interaction: {
              kind: 'passkey_assert',
              overlay: 'show',
            },
          });
        },
        onPromptSucceeded: () => {
          emitUnlockEvent(onEvent, nearAccountId, {
            phase: UnlockEventPhase.STEP_03_PASSKEY_PROMPT_SUCCEEDED,
            status: 'succeeded',
            authMethod: 'passkey',
            interaction: {
              kind: 'passkey_assert',
              overlay: 'hide',
            },
          });
        },
      });
      if (args.saveAsLoginCredential) {
        loginCredential = credential;
      }
      return credential;
    };

    const collectFreshLocalPasskeyUnlockCredentialForLogin = async (): Promise<void> => {
      const credential = await collectFreshLocalPasskeyUnlockCredential({
        currentCredential: loginCredential,
        collectCredentialForChallenge: async (challengeB64u) =>
          await collectLocalPasskeyCredentialForChallenge({
            challengeB64u,
            saveAsLoginCredential: true,
          }),
      });
      if (credential) loginCredential = credential;
    };

    const signingSessionPolicy = (() => {
      const ttlMsRaw =
        options?.signingSession?.ttlMs ?? context.configs?.signing.sessionDefaults?.ttlMs;
      const configuredRemainingUses = options?.signingSession?.remainingUses;
      const defaultRemainingUses = context.configs?.signing.sessionDefaults?.remainingUses;
      const requestedRemainingUses =
        configuredRemainingUses ?? defaultRemainingUses ?? DEV_DEFAULT_UNLOCK_REMAINING_USES;
      const ttlMs =
        typeof ttlMsRaw === 'number' ? Math.floor(ttlMsRaw) : Math.floor(Number(ttlMsRaw) || 0);
      const unlockBudgetPolicy = resolveWalletUnlockBudgetPolicyFromRequestedUses({
        requestedRemainingUses,
        ...(configuredRemainingUses == null && defaultRemainingUses == null
          ? {}
          : { policyVersion: 'sdk_unlock_config_v1' }),
      });
      return {
        ttlMs: Math.max(0, ttlMs),
        unlockBudgetPolicy,
      };
    })();

    let signingSession: LoginAndCreateSessionResult['signingSession'] | undefined;
    // Warm sessions are enabled when policy budgets are non-zero.
    const shouldWarmThresholdSigningSession =
      signingSessionPolicy.ttlMs > 0 && signingSessionPolicy.unlockBudgetPolicy != null;
    const requireThresholdWarmup = shouldWarmThresholdSigningSession;
    const shouldPrewarmThresholdEd25519ClientBase = walletUnlockSelection.mode !== 'ecdsa_only';

    const requireActiveWarmSession = (
      source: string,
      sessionStatus: SigningSessionStatus | null | undefined = signingSession,
    ): ThresholdWarmLoginAndCreateSessionResult['signingSession'] => {
      if (isActiveThresholdLoginSigningSession(sessionStatus)) {
        return sessionStatus;
      }
      const status = String(sessionStatus?.status || 'not_found');
      throw new Error(
        `[login] ${source} did not produce an active warm signing session (status=${status})`,
      );
    };

    const warmThresholdSigningSessions = async (
      warmupInput: ThresholdLoginWarmupPhaseInput,
    ): Promise<ThresholdLoginWarmupPhaseResult> => {
      emitUnlockEvent(onEvent, nearAccountId, {
        phase: UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED,
        status: 'running',
        authMethod: loginCredential ? 'passkey' : 'warm_session',
      });

      const thresholdKeyMaterial = warmupInput.wantsEd25519Warmup
        ? await getNearThresholdKeyMaterial(
            {
              clientDB: IndexedDBManager,
              keyMaterialStore: IndexedDBManager,
            },
            nearAccountId,
            warmupInput.signerSlot,
          ).catch(() => null)
        : null;
      if (warmupInput.wantsEd25519Warmup && !thresholdKeyMaterial) {
        throw new Error(
          `[login] threshold warm-up requires threshold key material for ${nearAccountId} signer slot ${warmupInput.signerSlot}`,
        );
      }

      const participantIds =
        thresholdKeyMaterial?.participants.map((participant) => participant.id) || [];
      const managedRuntimeScopeBootstrap = resolveManagedThresholdRuntimeScopeBootstrap(context);
      let volatileWarmMaterialCleared = false;
      const clearVolatileWarmMaterialForUnlock = async (): Promise<void> => {
        if (volatileWarmMaterialCleared) return;
        volatileWarmMaterialCleared = true;
        await signingEngine.clearVolatileWarmSigningMaterial(toWalletId(nearAccountId));
      };
      const storedCanonicalEcdsaContext = await resolveCanonicalThresholdEcdsaWarmSessionContext(
        context,
        signingEngine,
        nearAccountId,
        {
          repairAuthority: warmupInput.repairAuthority,
          repairRequested: Boolean(options?.ecdsaKeyFactsRepair),
          relayerUrl: warmupInput.relayerUrl,
          rpId: warmupInput.rpId,
          collectWebAuthnRepairCredential: async (challengeB64u) =>
            await collectLocalPasskeyCredentialForChallenge({
              challengeB64u,
              saveAsLoginCredential: true,
            }),
        },
      );
      const ecdsaTargetCompletion = buildSharedKeyTargetCompletion({
        context: storedCanonicalEcdsaContext,
        configuredTargets: warmupInput.selectedEcdsaTargets,
      });
      const canFirstBootstrapThresholdEcdsa = Boolean(managedRuntimeScopeBootstrap);
      const warmupPlan = resolveThresholdLoginWarmupPlan({
        selection: warmupInput.selection,
        selectedEcdsaTargets: warmupInput.selectedEcdsaTargets,
        storedCanonicalEcdsaContext,
        canFirstBootstrapThresholdEcdsa,
        wantsEd25519Warmup: warmupInput.wantsEd25519Warmup,
      });
      await clearVolatileWarmMaterialForUnlock();
      const preferredEd25519SessionId = createThresholdLoginWarmSessionId('threshold-login');
      const localPasskeyCredentialIdB64u = String(
        loginCredential?.rawId ||
          loginCredential?.id ||
          authenticators.find((authenticator) => authenticator.signerSlot === baseSignerSlot)
            ?.credentialId ||
          authenticators[0]?.credentialId ||
          '',
      ).trim();
      const warmupResult = await primeThresholdLoginWarmSigners({
        context,
        signingEngine,
        nearAccountId,
        relayerUrl: warmupInput.relayerUrl,
        relayerKeyId: thresholdKeyMaterial?.relayerKeyId || '',
        participantIds,
        ttlMs: signingSessionPolicy.ttlMs,
        unlockBudgetPolicy:
          signingSessionPolicy.unlockBudgetPolicy ||
          (() => {
            throw new Error('[login] unlock warm-up requires a wallet unlock budget policy');
          })(),
        ecdsaContextResolution: warmupPlan.ecdsaContextResolution,
        ...(loginCredential ? { credential: loginCredential } : {}),
        ...(localPasskeyCredentialIdB64u ? { localPasskeyCredentialIdB64u } : {}),
        ...(managedRuntimeScopeBootstrap ? { managedRuntimeScopeBootstrap } : {}),
        signersToWarm: warmupPlan.signersToWarm,
        ed25519DependsOnEcdsa: warmupPlan.ed25519DependsOnEcdsa,
        ecdsaDependsOnEd25519: warmupPlan.ecdsaDependsOnEd25519,
        preferredEd25519SessionId,
        appSessionJwt: warmupInput.appSessionJwt,
        useAppSessionCookie: warmupInput.useAppSessionCookie,
      });

      if (warmupPlan.signersToWarm.includes('ed25519')) {
        const warmStatus = await signingEngine
          .getWarmThresholdEd25519SessionStatus(nearAccountId)
          .catch(() => null);
        signingSession = warmStatus || signingSession;
      } else {
        signingSession =
          ecdsaOnlySigningSessionStatus(warmupResult.ecdsaBootstraps) || signingSession;
      }
      const activeSigningSession = requireActiveWarmSession('threshold warm-up');

      if (warmupPlan.signersToWarm.includes('ed25519')) {
        emitUnlockEvent(onEvent, nearAccountId, {
          phase: UnlockEventPhase.STEP_05_ED25519_SIGNING_SESSION_READY,
          status: 'succeeded',
          authMethod: 'warm_session',
        });
      }
      if (warmupPlan.signersToWarm.includes('ecdsa')) {
        emitUnlockEvent(onEvent, nearAccountId, {
          phase: UnlockEventPhase.STEP_05_ECDSA_SIGNING_SESSION_READY,
          status: 'succeeded',
          authMethod: 'warm_session',
        });
      }

      return {
        kind: 'threshold_login_warmup_ready',
        signingSession: activeSigningSession,
        signersWarmed: warmupPlan.signersToWarm,
      };
    };

    const requireThresholdWarmLoginBundle = (
      source: string,
    ): Pick<ThresholdWarmLoginAndCreateSessionResult, 'signingSession'> => {
      const activeSigningSession = requireActiveWarmSession(source);
      return {
        signingSession: activeSigningSession,
      };
    };

    const persistSuccessfulLoginState = async (signerSlot: number): Promise<void> => {
      await signingEngine.setLastUser(nearAccountId, signerSlot).catch(() => undefined);
      await signingEngine.updateLastLogin(nearAccountId).catch(() => undefined);
    };
    const recoverNonceLanesAfterUnlock = async (): Promise<void> => {
      await signingEngine
        .getNonceCoordinator()
        .recoverDurableLeases({ accountId: nearAccountId })
        .catch((error: unknown) => {
          console.warn('[login] nonce lane durable recovery after unlock failed', error);
        });
    };

    const session = options?.session;
    const wantsServerSession = session !== undefined;

    if (wantsServerSession) {
      const relayUrl = (session?.relayUrl || context.configs.network.relayer.url).trim();
      if (!relayUrl) {
        throw new Error('Missing relayUrl for session-style login');
      }

      const exchange = session?.exchange;
      if (exchange?.type === 'oidc_jwt' || exchange?.type === 'passkey_assertion') {
        const exchangeRoute = (session?.route || '/session/exchange').trim();
        const exchangePath = exchangeRoute.startsWith('/') ? exchangeRoute : `/${exchangeRoute}`;
        let exchangeInput: SessionExchangeInput;

        if (exchange.type === 'oidc_jwt') {
          exchangeInput = {
            type: 'oidc_jwt',
            token: exchange.token,
          };
          emitUnlockEvent(onEvent, nearAccountId, {
            phase: UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_STARTED,
            status: 'running',
          });
        } else {
          const rpId = String(signingEngine.getRpId() || '').trim();
          if (!rpId) {
            throw new Error('Missing rpId for passkey_assertion session exchange');
          }

          emitUnlockEvent(onEvent, nearAccountId, {
            phase: UnlockEventPhase.STEP_03_PASSKEY_CHALLENGE_STARTED,
            status: 'running',
            authMethod: 'passkey',
          });

          const unlockChallengeResp = await fetch(
            joinNormalizedUrl(relayUrl, '/wallet/unlock/challenge'),
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                unlockBackend: 'passkey',
                userId: String(nearAccountId),
                rpId,
              }),
            },
          );
          const unlockChallengeJsonUnknown: unknown = await unlockChallengeResp
            .json()
            .catch(() => ({}));
          const unlockChallengeJson = isObject(unlockChallengeJsonUnknown)
            ? unlockChallengeJsonUnknown
            : {};
          const unlockChallengeOk = unlockChallengeJson.ok === true;
          const unlockChallengeMessage =
            typeof unlockChallengeJson.message === 'string' ? unlockChallengeJson.message : '';
          if (!unlockChallengeResp.ok || !unlockChallengeOk) {
            throw new Error(
              unlockChallengeMessage ||
                `wallet/unlock/challenge failed (HTTP ${unlockChallengeResp.status})`,
            );
          }

          const challengeId = String(unlockChallengeJson.challengeId || '').trim();
          const challengeB64u = String(unlockChallengeJson.challengeB64u || '').trim();
          if (!challengeId || !challengeB64u) {
            throw new Error('wallet/unlock/challenge returned invalid challenge');
          }

          const credentialIds = Array.isArray(
            (unlockChallengeJson as { credentialIds?: unknown }).credentialIds,
          )
            ? (unlockChallengeJson as { credentialIds: unknown[] }).credentialIds
                .map((id) => String(id || '').trim())
                .filter((id) => id.length > 0)
            : [];
          const allowCredentials = credentialIds.map((id) => ({
            id,
            type: 'public-key' as const,
            transports: [],
          }));

          emitUnlockEvent(onEvent, nearAccountId, {
            phase: UnlockEventPhase.STEP_03_PASSKEY_PROMPT_STARTED,
            status: 'waiting_for_user',
            authMethod: 'passkey',
            interaction: {
              kind: 'passkey_assert',
              overlay: 'show',
            },
          });
          const webauthnAuthentication = await signingEngine.getAuthenticationCredentialsSerialized(
            {
              subjectId: String(nearAccountId),
              challengeB64u,
              allowCredentials,
              includeSecondPrfOutput: false,
            },
          );
          emitUnlockEvent(onEvent, nearAccountId, {
            phase: UnlockEventPhase.STEP_03_PASSKEY_PROMPT_SUCCEEDED,
            status: 'succeeded',
            authMethod: 'passkey',
            interaction: {
              kind: 'passkey_assert',
              overlay: 'hide',
            },
          });
          loginCredential = webauthnAuthentication;
          const expectedOrigin = String(
            exchange.expectedOrigin ??
              exchange.expected_origin ??
              (typeof window !== 'undefined' ? window.location.origin : ''),
          ).trim();

          exchangeInput = {
            type: 'passkey_assertion',
            challengeId,
            webauthn_authentication: webauthnAuthentication,
            ...(expectedOrigin ? { expected_origin: expectedOrigin } : {}),
          };
          emitUnlockEvent(onEvent, nearAccountId, {
            phase: UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_STARTED,
            status: 'running',
            authMethod: 'passkey',
          });
        }

        const exchanged = await exchangeSession(
          relayUrl,
          exchangePath,
          session.kind,
          exchangeInput,
        );
        if (!exchanged.success) {
          throw new Error(exchanged.error || 'Session exchange failed');
        }

        emitUnlockEvent(onEvent, nearAccountId, {
          phase: UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_SUCCEEDED,
          status: 'succeeded',
          authMethod: loginCredential ? 'passkey' : undefined,
        });

        if (requireThresholdWarmup) {
          const warmupPhase = await warmThresholdSigningSessions(
            resolveThresholdLoginWarmupPhaseInput({
              context,
              signerSlot: baseSignerSlot,
              selection: walletUnlockSelection,
              repair: options?.ecdsaKeyFactsRepair,
              appSessionJwt: exchanged.jwt,
              useAppSessionCookie: session.kind === 'cookie' && !!loginCredential,
            }),
          );
          signingSession = warmupPhase.signingSession;
          await assertPasskeyUnlockRuntimePostconditions({
            context,
            nearAccountId,
            signersWarmed: warmupPhase.signersWarmed,
          });
        }
        await persistSuccessfulLoginState(baseSignerSlot);
        await recoverNonceLanesAfterUnlock();
        if (loginCredential && shouldPrewarmThresholdEd25519ClientBase) {
          void prewarmThresholdEd25519ClientBaseFromCredential({
            context,
            credential: loginCredential,
            nearAccountId,
            signerSlot: baseSignerSlot,
          }).catch(() => undefined);
        }

        emitUnlockEvent(onEvent, nearAccountId, {
          phase: UnlockEventPhase.STEP_06_SESSION_READY,
          status: 'succeeded',
          authMethod: loginCredential ? 'passkey' : undefined,
        });

        const loginResult: LoginResult = {
          success: true,
          loggedInNearAccountId: String(nearAccountId),
          operationalPublicKey: accountSubject.operationalPublicKey,
          nearAccountId,
          ...(exchanged.jwt ? { jwt: exchanged.jwt } : {}),
        };

        const enrichedLoginResult: LoginAndCreateSessionResult = requireThresholdWarmup
          ? {
              ...loginResult,
              ...requireThresholdWarmLoginBundle('login'),
            }
          : {
              ...loginResult,
              ...(signingSession ? { signingSession } : {}),
            };
        return await finalizeLoginSuccess({
          nearAccountId,
          loginResult: enrichedLoginResult,
          onEvent,
          afterCall,
        });
      }

      const requestedRouteRaw = (session?.route || '').trim();
      const requestedRoute = requestedRouteRaw
        ? requestedRouteRaw.startsWith('/')
          ? requestedRouteRaw
          : `/${requestedRouteRaw}`
        : '';
      if (!exchange && (!requestedRoute || requestedRoute === '/session/exchange')) {
        throw new Error(
          'session.exchange is required when session.route targets /session/exchange',
        );
      }
      if (!exchange) {
        throw new Error('session.exchange is required for server session issuance');
      }
      throw new Error('session.exchange.type must be one of: oidc_jwt, passkey_assertion');
    }

    emitUnlockEvent(onEvent, nearAccountId, {
      phase: UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_SKIPPED,
      status: 'skipped',
    });

    if (requiresLocalPasskeyUnlock && !loginCredential && !requireThresholdWarmup) {
      await collectFreshLocalPasskeyUnlockCredentialForLogin();
    }

    if (requireThresholdWarmup) {
      const warmupPhase = await warmThresholdSigningSessions(
        resolveThresholdLoginWarmupPhaseInput({
          context,
          signerSlot: baseSignerSlot,
          selection: walletUnlockSelection,
          repair: options?.ecdsaKeyFactsRepair,
        }),
      );
      signingSession = warmupPhase.signingSession;
      await assertPasskeyUnlockRuntimePostconditions({
        context,
        nearAccountId,
        signersWarmed: warmupPhase.signersWarmed,
      });
    }

    await persistSuccessfulLoginState(baseSignerSlot);
    await recoverNonceLanesAfterUnlock();
    if (loginCredential && shouldPrewarmThresholdEd25519ClientBase) {
      void prewarmThresholdEd25519ClientBaseFromCredential({
        context,
        credential: loginCredential,
        nearAccountId,
        signerSlot: baseSignerSlot,
      }).catch(() => undefined);
    }

    const loginResult: LoginAndCreateSessionResult = requireThresholdWarmup
      ? {
          success: true,
          loggedInNearAccountId: String(nearAccountId),
          operationalPublicKey: accountSubject.operationalPublicKey,
          nearAccountId,
          ...requireThresholdWarmLoginBundle('login'),
        }
      : {
          success: true,
          loggedInNearAccountId: String(nearAccountId),
          operationalPublicKey: accountSubject.operationalPublicKey,
          nearAccountId,
          ...(signingSession ? { signingSession } : {}),
        };

    emitUnlockEvent(onEvent, nearAccountId, {
      phase: UnlockEventPhase.STEP_06_SESSION_READY,
      status: 'succeeded',
      authMethod: loginCredential ? 'passkey' : undefined,
    });

    return await finalizeLoginSuccess({
      nearAccountId,
      loginResult,
      onEvent,
      afterCall,
    });
  } catch (err: unknown) {
    const errorMessage = getUserFriendlyErrorMessage(err, 'login') || 'Login failed';
    return await finalizeLoginError({
      nearAccountId,
      message: errorMessage,
      error: err,
      cancelled: isUserCancellationError(err),
      onEvent,
      onError,
      afterCall,
    });
  }
}

async function finalizeLoginSuccess(args: {
  nearAccountId: AccountId;
  loginResult: LoginResult;
  onEvent?: LoginHooksOptions['onEvent'];
  afterCall?: AfterCall<LoginAndCreateSessionResult>;
}): Promise<LoginAndCreateSessionResult> {
  const { nearAccountId, loginResult, onEvent, afterCall } = args;
  emitUnlockEvent(onEvent, nearAccountId, {
    phase: UnlockEventPhase.STEP_07_COMPLETED,
    status: 'succeeded',
    data: {
      operationalPublicKey: loginResult.operationalPublicKey ?? '',
    },
  });
  await afterCall?.(true, loginResult);
  return loginResult;
}

async function finalizeLoginError(args: {
  nearAccountId: AccountId;
  message: string;
  error?: unknown;
  onEvent?: LoginHooksOptions['onEvent'];
  onError?: (error: Error) => void;
  afterCall?: AfterCall<LoginAndCreateSessionResult>;
  callOnError?: boolean;
  callAfterCall?: boolean;
  cancelled?: boolean;
}): Promise<LoginAndCreateSessionResult> {
  const {
    message,
    nearAccountId,
    error,
    onEvent,
    onError,
    afterCall,
    callOnError = true,
    callAfterCall = true,
    cancelled = false,
  } = args;

  if (callOnError) {
    onError?.(toError(error));
  }

  emitUnlockEvent(onEvent, nearAccountId, {
    phase: cancelled ? UnlockEventPhase.CANCELLED : UnlockEventPhase.FAILED,
    status: cancelled ? 'cancelled' : 'failed',
    ...(cancelled ? {} : { message }),
    interaction: {
      kind: 'passkey_assert',
      overlay: 'hide',
    },
    error: {
      message,
    },
  });

  if (callAfterCall) {
    await afterCall?.(false);
  }
  return { success: false, error: message };
}

type ConfiguredThresholdEcdsaPublicationTarget = ReturnType<
  typeof listConfiguredThresholdEcdsaPublicationTargets
>[number];

type ThresholdLoginWarmEcdsaContextResolution =
  | {
      kind: 'pre_resolved';
      context: CanonicalThresholdEcdsaWarmSessionContext;
      initialContext?: never;
      resolveAfterEd25519?: never;
    }
  | {
      kind: 'first_bootstrap_missing_shared_key';
      initialContext: CanonicalThresholdEcdsaWarmSessionContext;
      context?: never;
      resolveAfterEd25519?: never;
    }
  | {
      kind: 'resolve_after_ed25519';
      initialContext: CanonicalThresholdEcdsaWarmSessionContext;
      resolveAfterEd25519: (
        ed25519State: ThresholdLoginWarmEd25519State,
      ) => Promise<CanonicalThresholdEcdsaWarmSessionContext>;
      context?: never;
    };

type ThresholdLoginWarmupPlan = {
  kind: 'threshold_login_warmup_plan_ready';
  storedCanonicalEcdsaContext: CanonicalThresholdEcdsaWarmSessionContext;
  sharedKeyTargetCompletion: SharedKeyTargetCompletion;
  ecdsaContextResolution: ThresholdLoginWarmEcdsaContextResolution;
  signersToWarm: ThresholdLoginWarmSigner[];
  ed25519DependsOnEcdsa: boolean;
  ecdsaDependsOnEd25519: boolean;
};

type ThresholdLoginWarmupPhaseResult = {
  kind: 'threshold_login_warmup_ready';
  signingSession: ThresholdWarmLoginAndCreateSessionResult['signingSession'];
  signersWarmed: ThresholdLoginWarmSigner[];
};

function resolveLoginThresholdEcdsaBootstrapIdentity(
  bootstrap: ThresholdEcdsaSessionBootstrapResult,
): {
  keyHandle: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
} {
  const keyRef = bootstrap.thresholdEcdsaKeyRef;
  const keyHandle = String(keyRef.keyHandle || '').trim();
  if (!keyHandle) {
    throw new Error('[login] threshold ECDSA bootstrap missing keyHandle');
  }
  const canonicalKeyHandle = toEvmFamilyEcdsaKeyHandle(keyHandle);
  const runtimePolicyScope = parseThresholdRuntimePolicyScopeFromJwt(
    String(bootstrap.session.jwt || keyRef.thresholdSessionAuthToken || '').trim(),
  );
  const signingRootBinding = resolveThresholdSigningRootBindingFromRecord({
    record: {
      keyHandle: canonicalKeyHandle,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      signingRootId: keyRef.signingRootId,
      signingRootVersion: keyRef.signingRootVersion,
    },
  });
  return {
    keyHandle,
    ecdsaThresholdKeyId: resolveThresholdEcdsaKeyIdFromRecord({
      record: { ecdsaThresholdKeyId: keyRef.ecdsaThresholdKeyId },
    }),
    signingRootId: String(signingRootBinding.signingRootId),
    signingRootVersion: String(signingRootBinding.signingRootVersion),
  };
}

type ManagedThresholdRuntimeScopeBootstrap = {
  environmentId: string;
  publishableKey: string;
};

type ThresholdLoginWarmSigner = 'ed25519' | 'ecdsa';

type ThresholdLoginWarmupTask = {
  signer: ThresholdLoginWarmSigner;
  dependencies: ThresholdLoginWarmSigner[];
  run: () => Promise<void>;
};

type ThresholdLoginWarmEd25519State = {
  sessionId: string;
  walletSigningSessionId: string;
  jwt: string;
  ecdsaHssPasskeyPrfFirstB64u: string;
};

type ThresholdLoginWarmEcdsaBootstrapIdentity = {
  routeAuth?: ThresholdEcdsaHssRouteAuth;
};

type ThresholdLoginWarmupResult = {
  ecdsaBootstraps: ThresholdEcdsaSessionBootstrapResult[];
};

type ThresholdEcdsaAuthorizedEd25519Mint = {
  thresholdEcdsaSessionJwt: string;
  passkeyPrfFirstB64u: string;
  passkeyCredentialIdB64u: string;
  walletSigningSessionId: string;
};

function passkeyCredentialIdB64uFromEcdsaRecord(record: ThresholdEcdsaSessionRecord): string {
  try {
    const readyRecord = parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(record);
    return readyRecord.authMethod.kind === 'passkey'
      ? String(readyRecord.authMethod.credentialIdB64u || '').trim()
      : '';
  } catch {
    return '';
  }
}

function buildThresholdLoginWarmSignerSelection(
  signersToWarm: ThresholdLoginWarmSigner[] | undefined,
): ThresholdLoginWarmSigner[] {
  const requested =
    Array.isArray(signersToWarm) && signersToWarm.length > 0
      ? signersToWarm
      : (['ed25519', 'ecdsa'] as ThresholdLoginWarmSigner[]);
  const normalized: ThresholdLoginWarmSigner[] = [];
  for (const signer of requested) {
    if (signer !== 'ed25519' && signer !== 'ecdsa') continue;
    if (normalized.includes(signer)) continue;
    normalized.push(signer);
  }
  return normalized;
}

async function runThresholdLoginWarmupTasks(tasks: ThresholdLoginWarmupTask[]): Promise<void> {
  const pendingBySigner = new Map<ThresholdLoginWarmSigner, ThresholdLoginWarmupTask>();
  for (const task of tasks) {
    pendingBySigner.set(task.signer, task);
  }
  const completed = new Set<ThresholdLoginWarmSigner>();

  while (pendingBySigner.size > 0) {
    const ready: ThresholdLoginWarmupTask[] = [];
    for (const task of pendingBySigner.values()) {
      if (task.dependencies.every((dep) => completed.has(dep))) {
        ready.push(task);
      }
    }
    if (ready.length === 0) {
      throw new Error('[login] threshold warm-up task dependency graph is unsatisfied');
    }
    await Promise.all(
      ready.map(async (task) => {
        await task.run();
        completed.add(task.signer);
        pendingBySigner.delete(task.signer);
      }),
    );
  }
}

function resolveThresholdLoginWarmEcdsaBootstrapIdentity(args: {
  ed25519State: ThresholdLoginWarmEd25519State;
  credential?: WebAuthnAuthenticationCredential;
  appSessionJwt?: string;
  useAppSessionCookie?: boolean;
}): ThresholdLoginWarmEcdsaBootstrapIdentity {
  const appSessionJwt = String(args.appSessionJwt || '').trim();
  const thresholdSessionAuthToken = String(args.ed25519State.jwt || '').trim();
  if (appSessionJwt) {
    return {
      routeAuth: { kind: 'app_session', jwt: appSessionJwt },
    };
  }
  if (thresholdSessionAuthToken) {
    return {
      routeAuth: { kind: 'threshold_session', jwt: thresholdSessionAuthToken },
    };
  }
  if (args.useAppSessionCookie) {
    return {
      routeAuth: { kind: 'cookie' },
    };
  }
  if (args.credential) {
    return {};
  }
  throw new Error('[login] threshold ECDSA warm-up requires route authorization');
}

function thresholdLoginWarmupErrorMessage(error: unknown): string {
  return String(
    (error && typeof error === 'object' && 'message' in error
      ? (error as { message?: unknown }).message
      : error) || '',
  );
}

function resolveThresholdLoginWarmEcdsaPrfFirstB64u(args: {
  ed25519State: ThresholdLoginWarmEd25519State;
  credential?: WebAuthnAuthenticationCredential;
}): string {
  if (args.credential) {
    const prfFirstB64u = passkeyPrfFirstB64uFromCredential(args.credential);
    if (prfFirstB64u) return prfFirstB64u;
  }
  const fromEd25519Session = String(args.ed25519State.ecdsaHssPasskeyPrfFirstB64u || '').trim();
  if (fromEd25519Session) {
    return fromEd25519Session;
  }
  throw new Error(
    '[login] threshold ECDSA warm-up requires passkey PRF.first or primed Ed25519 session material',
  );
}

function ecdsaOnlySigningSessionStatus(
  bootstraps: readonly ThresholdEcdsaSessionBootstrapResult[],
): SigningSessionStatus | null {
  const session = bootstraps[0]?.session;
  const sessionId = String(session?.sessionId || '').trim();
  if (!session || !sessionId) return null;
  return {
    sessionId,
    status: 'active',
    authMethod: 'passkey',
    remainingUses: session.remainingUses,
    expiresAtMs: session.expiresAtMs,
    ...(session.projectionVersion ? { projectionVersion: session.projectionVersion } : {}),
    createdAtMs: Date.now(),
  };
}

function buildLoginThresholdEd25519SessionMintAuthorization(args: {
  appSessionJwt?: string;
  useAppSessionCookie?: boolean;
  credential?: WebAuthnAuthenticationCredential;
  rpId: string;
  thresholdEcdsaSessionJwt?: string;
  localPrfFirstB64u?: string;
}): ThresholdEd25519SessionMintAuthorization | undefined {
  const thresholdEcdsaSessionJwt = String(args.thresholdEcdsaSessionJwt || '').trim();
  const localPrfFirstB64u = String(args.localPrfFirstB64u || '').trim();
  if (thresholdEcdsaSessionJwt && localPrfFirstB64u) {
    return {
      kind: 'threshold_ecdsa_session_jwt',
      thresholdEcdsaSessionJwt,
      localSecretSource: buildThresholdEd25519ProvidedPrfSecretSource({
        prfFirstB64u: localPrfFirstB64u,
      }),
    };
  }
  const appSessionJwt = String(args.appSessionJwt || '').trim();
  if (appSessionJwt) {
    if (!args.credential) return undefined;
    return {
      kind: 'app_session_jwt',
      appSessionJwt,
      localSecretSource: buildThresholdEd25519WebAuthnPrfSecretSource({
        credential: args.credential,
        rpId: args.rpId,
      }),
    };
  }
  if (args.useAppSessionCookie) {
    if (!args.credential) return undefined;
    return {
      kind: 'app_session_cookie',
      localSecretSource: buildThresholdEd25519WebAuthnPrfSecretSource({
        credential: args.credential,
        rpId: args.rpId,
      }),
    };
  }
  return undefined;
}

async function primeThresholdLoginWarmSigners(args: {
  context: LoginWebContext;
  signingEngine: LoginWarmSigningSurface;
  nearAccountId: AccountId;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds: number[];
  ttlMs: number;
  unlockBudgetPolicy: WalletUnlockBudgetPolicy;
  ecdsaContextResolution: ThresholdLoginWarmEcdsaContextResolution;
  credential?: WebAuthnAuthenticationCredential;
  localPasskeyCredentialIdB64u?: string;
  managedRuntimeScopeBootstrap?: ManagedThresholdRuntimeScopeBootstrap;
  signersToWarm?: ThresholdLoginWarmSigner[];
  ed25519DependsOnEcdsa?: boolean;
  ecdsaDependsOnEd25519?: boolean;
  preferredEd25519SessionId?: string;
  appSessionJwt?: string;
  useAppSessionCookie?: boolean;
}): Promise<ThresholdLoginWarmupResult> {
  const signersToWarm = buildThresholdLoginWarmSignerSelection(args.signersToWarm);
  const initialCanonicalEcdsaContext =
    args.ecdsaContextResolution.kind === 'pre_resolved'
      ? args.ecdsaContextResolution.context
      : args.ecdsaContextResolution.initialContext;
  let activeCanonicalEcdsaContext = initialCanonicalEcdsaContext;
  const warmState: ThresholdLoginWarmEd25519State = {
    sessionId: '',
    walletSigningSessionId: '',
    jwt: '',
    ecdsaHssPasskeyPrfFirstB64u: '',
  };
  const unlockRemainingUses = resolveSigningBudgetPolicyRemainingUses(args.unlockBudgetPolicy);
  const ecdsaBootstraps: ThresholdEcdsaSessionBootstrapResult[] = [];
  let ecdsaAuthorizedEd25519Mint: ThresholdEcdsaAuthorizedEd25519Mint | null = null;

  const tasks: ThresholdLoginWarmupTask[] = [];
  if (signersToWarm.includes('ed25519')) {
    tasks.push({
      signer: 'ed25519',
      dependencies: args.ed25519DependsOnEcdsa ? ['ecdsa'] : [],
      run: async () => {
        const ecdsaMint = ecdsaAuthorizedEd25519Mint;
        const auth = buildLoginThresholdEd25519SessionMintAuthorization({
          appSessionJwt: args.appSessionJwt,
          useAppSessionCookie: args.useAppSessionCookie,
          credential: args.credential,
          rpId: args.signingEngine.getRpId(),
          thresholdEcdsaSessionJwt: ecdsaMint?.thresholdEcdsaSessionJwt,
          localPrfFirstB64u: ecdsaMint?.passkeyPrfFirstB64u,
        });
        const ed25519ProvisioningIdentity = (() => {
          if (!args.ed25519DependsOnEcdsa) {
            return { kind: 'fresh_ed25519_provisioning' as const };
          }
          if (!ecdsaMint) {
            throw new Error(
              '[login] threshold Ed25519 warm-up requires the ECDSA bootstrap session minted during unlock',
            );
          }
          return {
            kind: 'exact_ed25519_provisioning' as const,
            sessionId:
              String(args.preferredEd25519SessionId || '').trim() ||
              createThresholdLoginWarmSessionId('threshold-login'),
            walletSigningSessionId: ecdsaMint.walletSigningSessionId,
          };
        })();
        const connected = await args.signingEngine.connectEd25519Session({
          ...ed25519ProvisioningIdentity,
          nearAccountId: args.nearAccountId,
          relayerUrl: args.relayerUrl,
          relayerKeyId: args.relayerKeyId,
          source: 'login',
          ...(auth ? { auth } : {}),
          ...(initialCanonicalEcdsaContext.runtimePolicyScope
            ? { runtimePolicyScope: initialCanonicalEcdsaContext.runtimePolicyScope }
            : {}),
          ...(args.managedRuntimeScopeBootstrap
            ? { runtimeScopeBootstrap: args.managedRuntimeScopeBootstrap }
            : {}),
          participantIds: args.participantIds,
          sessionKind: args.useAppSessionCookie ? 'cookie' : 'jwt',
          ttlMs: args.ttlMs,
          remainingUses: unlockRemainingUses,
        });
        if (!connected.ok) {
          const details = String(
            connected.message || connected.code || 'Failed to connect threshold Ed25519 session',
          );
          throw new Error(`[login] threshold Ed25519 warm-up failed: ${details}`);
        }

        const connectedSessionId = String(connected.sessionId || '').trim();
        if (!connectedSessionId) {
          throw new Error('[login] threshold Ed25519 warm-up did not return a sessionId');
        }

        const connectedJwt = String(connected.jwt || '').trim();
        if (!connectedJwt && !args.useAppSessionCookie) {
          throw new Error('[login] threshold Ed25519 warm-up did not return a JWT session token');
        }

        const connectedWalletSigningSessionId = String(
          connected.walletSigningSessionId || '',
        ).trim();
        if (!connectedWalletSigningSessionId) {
          throw new Error(
            '[login] threshold Ed25519 warm-up did not return a walletSigningSessionId',
          );
        }

        const connectedEcdsaHssPasskeyPrfFirstB64u = String(
          connected.ecdsaHssPasskeyPrfFirstB64u || '',
        ).trim();
        if (signersToWarm.includes('ecdsa') && !connectedEcdsaHssPasskeyPrfFirstB64u) {
          throw new Error(
            '[login] threshold ECDSA warm-up missing passkey PRF.first from the primed Ed25519 session',
          );
        }

        warmState.sessionId = connectedSessionId;
        warmState.walletSigningSessionId = connectedWalletSigningSessionId;
        warmState.jwt = connectedJwt;
        warmState.ecdsaHssPasskeyPrfFirstB64u = connectedEcdsaHssPasskeyPrfFirstB64u;
        if (args.ecdsaContextResolution.kind === 'resolve_after_ed25519') {
          activeCanonicalEcdsaContext =
            await args.ecdsaContextResolution.resolveAfterEd25519(warmState);
        }
      },
    });
  }
  if (signersToWarm.includes('ecdsa')) {
    tasks.push({
      signer: 'ecdsa',
      dependencies: args.ecdsaDependsOnEd25519 ? ['ed25519'] : [],
      run: async () => {
        let bootstrapIdentity: ThresholdLoginWarmEcdsaBootstrapIdentity | null = null;
        const configuredEcdsaTargets = listConfiguredThresholdEcdsaPublicationTargets(
          args.context.configs.network.chains,
        );
        const completeActiveContextFromSharedKey = (source: string): void => {
          const completion = buildSharedKeyTargetCompletion({
            context: activeCanonicalEcdsaContext,
            configuredTargets: configuredEcdsaTargets,
          });
          if (completion.kind === 'complete_shared_key_targets') {
            activeCanonicalEcdsaContext = completion.context;
            return;
          }
          if (completion.kind === 'ambiguous_shared_key_targets') {
            requireCompleteSharedKeyTargetContext({ completion, source });
          }
        };
        const rememberBootstrappedKey = (input: {
          target: (typeof configuredEcdsaTargets)[number];
          bootstrap: ThresholdEcdsaSessionBootstrapResult;
        }): ConfiguredTargetThresholdEcdsaWarmKey => {
          const keyRef = input.bootstrap.thresholdEcdsaKeyRef;
          const identity = resolveLoginThresholdEcdsaBootstrapIdentity(input.bootstrap);
          const thresholdOwnerAddress = String(
            input.bootstrap.keygen.ethereumAddress || keyRef.ethereumAddress || '',
          ).trim();
          const key = buildBaseEvmFamilyEcdsaKeyIdentity({
            walletId: args.nearAccountId,
            rpId: String(args.signingEngine.getRpId() || '').trim(),
            ecdsaThresholdKeyId: identity.ecdsaThresholdKeyId,
            signingRootId: identity.signingRootId,
            signingRootVersion: identity.signingRootVersion,
            participantIds: keyRef.participantIds || input.bootstrap.keygen.participantIds,
            thresholdOwnerAddress,
          });
          const warmKey = configuredTargetThresholdEcdsaWarmKey({
            chainTarget: input.target.chainTarget,
            keyHandle: identity.keyHandle,
            key,
          });
          const runtimePolicyScope = parseThresholdRuntimePolicyScopeFromJwt(
            String(input.bootstrap.session.jwt || keyRef.thresholdSessionAuthToken || '').trim(),
          );
          activeCanonicalEcdsaContext = mergeCanonicalThresholdEcdsaWarmSessionContexts(
            activeCanonicalEcdsaContext,
            {
              ecdsaKeys: [warmKey],
              ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
            },
          );
          completeActiveContextFromSharedKey('login first-bootstrapped ECDSA key');
          return warmKey;
        };
        const rememberEcdsaAuthorizedEd25519Mint = (
          bootstrap: ThresholdEcdsaSessionBootstrapResult,
        ): void => {
          if (ecdsaAuthorizedEd25519Mint) return;
          const thresholdEcdsaSessionJwt = String(bootstrap.session.jwt || '').trim();
          const passkeyPrfFirstB64u =
            String(bootstrap.passkeyPrfFirstB64u || '').trim() ||
            (args.credential ? passkeyPrfFirstB64uFromCredential(args.credential) : '');
          const passkeyCredentialIdB64u =
            String(bootstrap.passkeyCredentialIdB64u || '').trim() ||
            passkeyCredentialIdB64uFromAuthentication(args.credential) ||
            String(args.localPasskeyCredentialIdB64u || '').trim();
          const walletSigningSessionId = String(
            bootstrap.thresholdEcdsaKeyRef?.walletSigningSessionId ||
              bootstrap.session?.walletSigningSessionId ||
              '',
          ).trim();
          if (
            !thresholdEcdsaSessionJwt ||
            !passkeyPrfFirstB64u ||
            !passkeyCredentialIdB64u ||
            !walletSigningSessionId
          ) {
            return;
          }
          ecdsaAuthorizedEd25519Mint = {
            thresholdEcdsaSessionJwt,
            passkeyPrfFirstB64u,
            passkeyCredentialIdB64u,
            walletSigningSessionId,
          };
        };
        const ecdsaOnlyWalletSigningSessionId =
          String(warmState.walletSigningSessionId || '').trim() ||
          createThresholdLoginWarmSessionId('wallet-ecdsa-login');
        const resolveCurrentBootstrapIdentity = (): ThresholdLoginWarmEcdsaBootstrapIdentity => {
          if (bootstrapIdentity) return bootstrapIdentity;
          const thresholdEcdsaSessionJwt = String(
            ecdsaAuthorizedEd25519Mint?.thresholdEcdsaSessionJwt || '',
          ).trim();
          if (thresholdEcdsaSessionJwt) {
            return {
              routeAuth: { kind: 'threshold_session', jwt: thresholdEcdsaSessionJwt },
            };
          }
          bootstrapIdentity = resolveThresholdLoginWarmEcdsaBootstrapIdentity({
            ed25519State: warmState,
            ...(args.credential ? { credential: args.credential } : {}),
            appSessionJwt: args.appSessionJwt,
            useAppSessionCookie: args.useAppSessionCookie,
          });
          return bootstrapIdentity;
        };
        const bootstrapTarget = async (
          target: (typeof configuredEcdsaTargets)[number],
          targetEcdsaKey: ConfiguredTargetThresholdEcdsaWarmKey,
        ) => {
          if (!targetEcdsaKey.key) {
            throw new Error('[login] threshold ECDSA warm-up requires shared key identity');
          }
          const thresholdSessionId = createThresholdLoginWarmSessionId('threshold-ecdsa-login');
          const lanePolicy = buildEvmFamilyEcdsaSessionLanePolicy({
            chainTarget: target.chainTarget,
            thresholdSessionId,
            walletSigningSessionId: ecdsaOnlyWalletSigningSessionId,
            thresholdSessionKind: args.useAppSessionCookie ? 'cookie' : 'jwt',
            ttlMs: args.ttlMs,
            remainingUses: unlockRemainingUses,
            ...(activeCanonicalEcdsaContext.runtimePolicyScope
              ? { runtimePolicyScope: activeCanonicalEcdsaContext.runtimePolicyScope }
              : {}),
          });
          const bootstrappedPasskeyPrfFirstB64u = String(
            ecdsaAuthorizedEd25519Mint?.passkeyPrfFirstB64u || '',
          ).trim();
          const hasPasskeyPrfSource = Boolean(
            String(warmState.ecdsaHssPasskeyPrfFirstB64u || '').trim() || args.credential,
          );
          const passkeyPrfFirstB64u = bootstrappedPasskeyPrfFirstB64u
            ? bootstrappedPasskeyPrfFirstB64u
            : hasPasskeyPrfSource
              ? resolveThresholdLoginWarmEcdsaPrfFirstB64u({
                  ed25519State: warmState,
                  credential: args.credential,
                })
              : '';
          const currentBootstrapIdentity = passkeyPrfFirstB64u
            ? resolveCurrentBootstrapIdentity()
            : null;
          const passkeyBootstrapProof =
            passkeyPrfFirstB64u && args.credential
              ? {
                  passkeyPrfFirstB64u: passkeyPrfFirstB64u,
                  webauthnAuthentication: args.credential,
                }
              : null;
          if (passkeyBootstrapProof) {
            const routeAuth = currentBootstrapIdentity?.routeAuth;
            if (
              routeAuth &&
              (routeAuth.kind === 'app_session' ||
                routeAuth.kind === 'bootstrap_grant' ||
                routeAuth.kind === 'publishable_key')
            ) {
              return await args.signingEngine.bootstrapEcdsaSession({
                kind: 'passkey_fresh_ecdsa_bootstrap',
                source: 'login',
                relayerUrl: args.relayerUrl,
                keyHandle: toEvmFamilyEcdsaKeyHandle(targetEcdsaKey.keyHandle),
                key: targetEcdsaKey.key,
                lanePolicy,
                routeAuth,
                ...passkeyBootstrapProof,
                ...(args.managedRuntimeScopeBootstrap
                  ? { runtimeScopeBootstrap: args.managedRuntimeScopeBootstrap }
                  : {}),
              });
            }
            return await args.signingEngine.bootstrapEcdsaSession({
              kind: 'passkey_fresh_ecdsa_bootstrap',
              source: 'login',
              relayerUrl: args.relayerUrl,
              keyHandle: toEvmFamilyEcdsaKeyHandle(targetEcdsaKey.keyHandle),
              key: targetEcdsaKey.key,
              lanePolicy,
              ...passkeyBootstrapProof,
              ...(args.managedRuntimeScopeBootstrap
                ? { runtimeScopeBootstrap: args.managedRuntimeScopeBootstrap }
                : {}),
            });
          }
          const passkeyCredentialIdB64u = String(
            passkeyCredentialIdB64uFromAuthentication(args.credential) ||
              ecdsaAuthorizedEd25519Mint?.passkeyCredentialIdB64u ||
              targetEcdsaKey.passkeyCredentialIdB64u ||
              args.localPasskeyCredentialIdB64u ||
              '',
          ).trim();
          if (
            currentBootstrapIdentity?.routeAuth &&
            passkeyPrfFirstB64u &&
            passkeyCredentialIdB64u
          ) {
            return await args.signingEngine.bootstrapEcdsaSession({
              kind: 'threshold_session_auth_reconnect_ecdsa_bootstrap',
              source: 'login',
              relayerUrl: args.relayerUrl,
              keyHandle: toEvmFamilyEcdsaKeyHandle(targetEcdsaKey.keyHandle),
              key: targetEcdsaKey.key,
              lanePolicy,
              passkeyPrfFirstB64u: passkeyPrfFirstB64u,
              passkeyCredentialIdB64u,
              routeAuth: currentBootstrapIdentity.routeAuth,
              ...(args.managedRuntimeScopeBootstrap
                ? { runtimeScopeBootstrap: args.managedRuntimeScopeBootstrap }
                : {}),
            });
          }
          return await args.signingEngine.bootstrapEcdsaSession({
            kind: 'passkey_fresh_ecdsa_bootstrap',
            source: 'login',
            relayerUrl: args.relayerUrl,
            keyHandle: toEvmFamilyEcdsaKeyHandle(targetEcdsaKey.keyHandle),
            key: targetEcdsaKey.key,
            lanePolicy,
            ...(args.managedRuntimeScopeBootstrap
              ? { runtimeScopeBootstrap: args.managedRuntimeScopeBootstrap }
              : {}),
          });
        };
        const firstBootstrapTarget = async (target: (typeof configuredEcdsaTargets)[number]) => {
          if (!args.managedRuntimeScopeBootstrap) {
            throw new Error(
              '[login] threshold ECDSA first bootstrap requires managed runtime scope bootstrap',
            );
          }
          const thresholdSessionId = createThresholdLoginWarmSessionId('threshold-ecdsa-login');
          const passkeyPrfFirstB64u = args.credential
            ? resolveThresholdLoginWarmEcdsaPrfFirstB64u({
                ed25519State: warmState,
                credential: args.credential,
              })
            : undefined;
          const passkeyBootstrapProof =
            passkeyPrfFirstB64u && args.credential
              ? {
                  passkeyPrfFirstB64u: passkeyPrfFirstB64u,
                  webauthnAuthentication: args.credential,
                }
              : null;
          const sessionIdentity = buildEcdsaSessionIdentity({
            thresholdSessionId,
            walletSigningSessionId: ecdsaOnlyWalletSigningSessionId,
          });
          const appSessionJwt = String(args.appSessionJwt || '').trim();
          if (args.useAppSessionCookie) {
            if (passkeyBootstrapProof) {
              return await args.signingEngine.bootstrapEcdsaSession({
                kind: 'passkey_fresh_ecdsa_bootstrap',
                walletId: args.nearAccountId,
                chainTarget: target.chainTarget,
                source: 'login',
                relayerUrl: args.relayerUrl,
                sessionKind: 'cookie',
                sessionIdentity,
                ...passkeyBootstrapProof,
                runtimeScopeBootstrap: args.managedRuntimeScopeBootstrap,
                ttlMs: args.ttlMs,
                remainingUses: unlockRemainingUses,
              });
            }
            return await args.signingEngine.bootstrapEcdsaSession({
              kind: 'passkey_fresh_ecdsa_bootstrap',
              walletId: args.nearAccountId,
              chainTarget: target.chainTarget,
              source: 'login',
              relayerUrl: args.relayerUrl,
              sessionKind: 'cookie',
              sessionIdentity,
              runtimeScopeBootstrap: args.managedRuntimeScopeBootstrap,
              ttlMs: args.ttlMs,
              remainingUses: unlockRemainingUses,
            });
          }
          if (appSessionJwt) {
            if (passkeyBootstrapProof) {
              return await args.signingEngine.bootstrapEcdsaSession({
                kind: 'passkey_fresh_ecdsa_bootstrap',
                walletId: args.nearAccountId,
                chainTarget: target.chainTarget,
                source: 'login',
                relayerUrl: args.relayerUrl,
                sessionKind: 'jwt',
                sessionIdentity,
                routeAuth: { kind: 'app_session', jwt: appSessionJwt },
                ...passkeyBootstrapProof,
                runtimeScopeBootstrap: args.managedRuntimeScopeBootstrap,
                ttlMs: args.ttlMs,
                remainingUses: unlockRemainingUses,
              });
            }
            return await args.signingEngine.bootstrapEcdsaSession({
              kind: 'passkey_fresh_ecdsa_bootstrap',
              walletId: args.nearAccountId,
              chainTarget: target.chainTarget,
              source: 'login',
              relayerUrl: args.relayerUrl,
              sessionKind: 'jwt',
              sessionIdentity,
              routeAuth: { kind: 'app_session', jwt: appSessionJwt },
              runtimeScopeBootstrap: args.managedRuntimeScopeBootstrap,
              ttlMs: args.ttlMs,
              remainingUses: unlockRemainingUses,
            });
          }
          if (passkeyBootstrapProof) {
            return await args.signingEngine.bootstrapEcdsaSession({
              kind: 'passkey_fresh_ecdsa_bootstrap',
              walletId: args.nearAccountId,
              chainTarget: target.chainTarget,
              source: 'login',
              relayerUrl: args.relayerUrl,
              sessionKind: 'jwt',
              sessionIdentity,
              routeAuth: {
                kind: 'publishable_key',
                token: args.managedRuntimeScopeBootstrap.publishableKey,
              },
              ...passkeyBootstrapProof,
              runtimeScopeBootstrap: args.managedRuntimeScopeBootstrap,
              ttlMs: args.ttlMs,
              remainingUses: unlockRemainingUses,
            });
          }
          return await args.signingEngine.bootstrapEcdsaSession({
            kind: 'passkey_fresh_ecdsa_bootstrap',
            walletId: args.nearAccountId,
            chainTarget: target.chainTarget,
            source: 'login',
            relayerUrl: args.relayerUrl,
            sessionKind: 'jwt',
            sessionIdentity,
            routeAuth: {
              kind: 'publishable_key',
              token: args.managedRuntimeScopeBootstrap.publishableKey,
            },
            runtimeScopeBootstrap: args.managedRuntimeScopeBootstrap,
            ttlMs: args.ttlMs,
            remainingUses: unlockRemainingUses,
          });
        };
        const bootstrapConfiguredTargets = async () => {
          completeActiveContextFromSharedKey('login ECDSA warm-up preflight');
          for (const target of configuredEcdsaTargets) {
            const targetKey = thresholdEcdsaChainTargetKey(target.chainTarget);
            let targetEcdsaKey = activeCanonicalEcdsaContext.ecdsaKeys.find(
              (key) => key.targetKey === targetKey,
            );
            const keyHandle = String(targetEcdsaKey?.keyHandle || '').trim();
            if (!targetEcdsaKey?.key || !keyHandle) {
              const bootstrap = await firstBootstrapTarget(target);
              ecdsaBootstraps.push(bootstrap);
              rememberEcdsaAuthorizedEd25519Mint(bootstrap);
              targetEcdsaKey = rememberBootstrappedKey({ target, bootstrap });
              continue;
            }
            const bootstrap = await bootstrapTarget(target, targetEcdsaKey);
            ecdsaBootstraps.push(bootstrap);
            rememberEcdsaAuthorizedEd25519Mint(bootstrap);
            const returnedKeyHandle = String(
              bootstrap.thresholdEcdsaKeyRef?.keyHandle || '',
            ).trim();
            if (returnedKeyHandle !== targetEcdsaKey.keyHandle) {
              throw new Error(
                `[login] threshold ECDSA warm-up returned a different keyHandle for ${targetKey}`,
              );
            }
          }
        };
        try {
          await bootstrapConfiguredTargets();
        } catch (error: unknown) {
          const details =
            thresholdLoginWarmupErrorMessage(error) ||
            'Failed to bootstrap threshold ECDSA session';
          throw new Error(`[login] threshold ECDSA warm-up failed: ${details}`);
        }
      },
    });
  }

  await runThresholdLoginWarmupTasks(tasks);
  return { ecdsaBootstraps };
}

/**
 * High-level login snapshot used by React contexts/UI.
 *
 * Login state is derived from:
 * - IndexedDB last-user pointer, and
 * - when threshold-signer warm sessions are enabled, an active PRF-first cache entry
 *   in the UserConfirm worker for the account's active signing session id.
 */
export async function getWalletSession(
  context: WalletSessionWebContext,
  nearAccountId?: AccountId,
): Promise<WalletSession> {
  await context.signingEngine.assertSealedRefreshStartupParity().catch((error: unknown) => {
    console.warn(
      '[WalletSession] sealed refresh startup parity check failed during session read; continuing with cached login state',
      error instanceof Error ? error.message : String(error || 'unknown error'),
    );
  });
  const login = await getLoginStateInternal(context, nearAccountId);
  const signingSession = login?.nearAccountId
    ? await resolveSigningSessionStatusForUi(context, login.nearAccountId).catch(() => null)
    : null;
  const authMethod: WalletAuthMethod | null =
    signingSession?.authMethod ||
    login.authMethod ||
    (login.isLoggedIn && login.publicKey ? 'passkey' : null);
  const retention = signingSession?.retention || null;
  const nonceDiagnostics = readWalletSessionNonceDiagnostics(context, login.nearAccountId);
  return {
    login: { ...login, authMethod },
    signingSession,
    authMethod,
    retention,
    nonceDiagnostics,
  };
}

function readWalletSessionNonceDiagnostics(
  context: WalletSessionWebContext,
  nearAccountId?: AccountId | string | null,
): WalletSession['nonceDiagnostics'] {
  const accountId = String(nearAccountId || '').trim();
  if (!accountId) return null;
  try {
    return context.signingEngine.getNonceCoordinator().getDiagnostics({
      accountId,
      emitMetrics: true,
    });
  } catch {
    return null;
  }
}

const THRESHOLD_ECDSA_LOGIN_METADATA_SOURCES: readonly ThresholdEcdsaSessionStoreSource[] = [
  'email_otp',
  'login',
  'registration',
  'manual-bootstrap',
];

function readThresholdEcdsaLoginMetadataRecords(
  context: WalletSessionWebContext,
  nearAccountId: AccountId,
): ThresholdEcdsaSessionRecord[] {
  const allowedSources = new Set<ThresholdEcdsaSessionStoreSource>(
    THRESHOLD_ECDSA_LOGIN_METADATA_SOURCES,
  );
  return listConfiguredThresholdEcdsaPublicationTargets(context.configs.network.chains).flatMap(
    (target) =>
      context.signingEngine
        .listThresholdEcdsaSessionRecordsForWalletTarget({
          walletId: toWalletId(nearAccountId),
          chainTarget: target.chainTarget,
        })
        .filter((record) => allowedSources.has(record.source)),
  );
}

function normalizeEvmOwnerAddress(value: unknown): string {
  const candidate = String(value || '')
    .trim()
    .toLowerCase();
  return /^0x[0-9a-f]{40}$/.test(candidate) ? candidate : '';
}

function resolveUniqueThresholdEcdsaRecordAddress(args: {
  nearAccountId: AccountId;
  records: readonly ThresholdEcdsaSessionRecord[];
}): string | null {
  const addresses = [
    ...new Set(
      args.records
        .map((record) => normalizeEvmOwnerAddress(record.ethereumAddress))
        .filter(Boolean),
    ),
  ];
  if (addresses.length === 1) return addresses[0]!;
  if (addresses.length > 1) {
    console.warn('[WalletSession] conflicting threshold ECDSA record addresses', {
      nearAccountId: String(args.nearAccountId),
      addresses,
    });
  }
  return null;
}

async function readProfileContinuityThresholdEcdsaWalletKeys(
  context: WalletSessionWebContext,
  nearAccountId: AccountId,
): Promise<ActiveEcdsaSignerRecord['walletKey'][]> {
  const configuredTargets = listConfiguredThresholdEcdsaPublicationTargets(
    context.configs.network.chains,
  ).map((target) => target.chainTarget);
  if (!configuredTargets.length) return [];
  const walletSigners = await IndexedDBManager.listAccountSignersByProfile({
    profileId: String(toWalletId(nearAccountId)),
    status: 'active',
  }).catch(() => []);
  const walletKeys: ActiveEcdsaSignerRecord['walletKey'][] = [];
  for (const signer of walletSigners) {
    const parsed = parseActiveEcdsaSignerRecordForUnlock({
      walletId: toWalletId(nearAccountId),
      configuredTargets,
      signer,
    });
    if (parsed.kind === 'active_ecdsa_signer_record') {
      walletKeys.push(parsed.walletKey);
    }
  }
  return walletKeys;
}

async function resolveProfileContinuityThresholdEcdsaEthereumAddress(
  context: WalletSessionWebContext,
  nearAccountId: AccountId,
): Promise<string | null> {
  const addresses = [
    ...new Set(
      (await readProfileContinuityThresholdEcdsaWalletKeys(context, nearAccountId))
        .map((walletKey) => normalizeEvmOwnerAddress(walletKey.keyFacts.thresholdOwnerAddress))
        .filter(Boolean),
    ),
  ];
  if (addresses.length === 1) return addresses[0]!;
  if (addresses.length > 1) {
    console.warn('[WalletSession] conflicting profile threshold ECDSA addresses', {
      nearAccountId: String(nearAccountId),
      addresses,
    });
  }
  return null;
}

async function resolveThresholdEcdsaEthereumAddress(
  context: WalletSessionWebContext,
  nearAccountId: AccountId,
): Promise<string | null> {
  const runtimeAddress = resolveUniqueThresholdEcdsaRecordAddress({
    nearAccountId,
    records: readThresholdEcdsaLoginMetadataRecords(context, nearAccountId),
  });
  if (runtimeAddress) return runtimeAddress;
  const profileAddress = await resolveProfileContinuityThresholdEcdsaEthereumAddress(
    context,
    nearAccountId,
  );
  if (profileAddress) return profileAddress;
  const snapshot = await readAvailableSigningLanesForUi(context, nearAccountId).catch(() => null);
  if (!snapshot) return null;
  const addresses = [
    ...new Set(
      ecdsaAvailableLaneTargets(snapshot)
        .map((target) => ecdsaAvailableLaneForTarget(snapshot, target))
        .filter(
          (lane): lane is ConcreteAvailableEcdsaSigningLane =>
            lane.curve === 'ecdsa' && isConcreteAvailableSigningLane(lane),
        )
        .map((lane) => normalizeEvmOwnerAddress(lane.key.thresholdOwnerAddress))
        .filter(Boolean),
    ),
  ];
  if (addresses.length === 1) return addresses[0]!;
  if (addresses.length > 1) {
    console.warn('[WalletSession] conflicting threshold ECDSA sealed lane addresses', {
      nearAccountId: String(nearAccountId),
      addresses,
    });
  }
  return null;
}

function resolveThresholdLoginWarmSigners(args: {
  selection: WalletUnlockSelection;
  configuredEcdsaTargets: readonly ConfiguredThresholdEcdsaPublicationTarget[];
  canonicalEcdsaContext?: CanonicalThresholdEcdsaWarmSessionContext | null;
}): ThresholdLoginWarmSigner[] {
  if (args.selection.mode === 'ed25519_only') return ['ed25519'];
  if (!args.configuredEcdsaTargets.length) {
    return args.selection.mode === 'ecdsa_only' ? [] : ['ed25519'];
  }
  const keyIdsByTarget = new Set(
    (args.canonicalEcdsaContext?.ecdsaKeys || []).map((key) => key.targetKey),
  );
  if (keyIdsByTarget.size === 0) {
    throw new Error('[login] threshold ECDSA warm-up missing canonical key identity');
  }
  const missingTargets = args.configuredEcdsaTargets
    .map((target) => thresholdEcdsaChainTargetKey(target.chainTarget))
    .filter((targetKey) => !keyIdsByTarget.has(targetKey));
  if (missingTargets.length) {
    throw new Error(
      `[login] threshold ECDSA warm-up missing configured-target key ids for ${missingTargets.join(
        ', ',
      )}`,
    );
  }
  return args.selection.mode === 'ecdsa_only' ? ['ecdsa'] : ['ed25519', 'ecdsa'];
}

function resolveThresholdLoginWarmupPlan(args: {
  selection: WalletUnlockSelection;
  selectedEcdsaTargets: readonly ConfiguredThresholdEcdsaPublicationTarget[];
  storedCanonicalEcdsaContext: CanonicalThresholdEcdsaWarmSessionContext;
  canFirstBootstrapThresholdEcdsa: boolean;
  wantsEd25519Warmup: boolean;
}): ThresholdLoginWarmupPlan {
  const sharedKeyTargetCompletion = buildSharedKeyTargetCompletion({
    context: args.storedCanonicalEcdsaContext,
    configuredTargets: args.selectedEcdsaTargets,
  });
  let ecdsaContextResolution: ThresholdLoginWarmEcdsaContextResolution;
  let signersToWarm: ThresholdLoginWarmSigner[];
  let ed25519DependsOnEcdsa = false;
  let ecdsaDependsOnEd25519 = false;
  if (sharedKeyTargetCompletion.kind === 'missing_shared_key' && args.selectedEcdsaTargets.length) {
    const initialContext: CanonicalThresholdEcdsaWarmSessionContext = {
      ecdsaKeys: [],
      ...(args.storedCanonicalEcdsaContext.runtimePolicyScope
        ? { runtimePolicyScope: args.storedCanonicalEcdsaContext.runtimePolicyScope }
        : {}),
    };
    if (!args.canFirstBootstrapThresholdEcdsa) {
      throw new Error(
        `[login] threshold ECDSA warm-up requires complete local key facts for ${sharedKeyTargetCompletion.missingTargets.join(
          ', ',
        )}; run explicit ECDSA key-facts repair before unlock`,
      );
    }
    signersToWarm = args.wantsEd25519Warmup ? ['ecdsa', 'ed25519'] : ['ecdsa'];
    ed25519DependsOnEcdsa = args.wantsEd25519Warmup;
    ecdsaContextResolution = {
      kind: 'first_bootstrap_missing_shared_key',
      initialContext,
    };
  } else {
    const resolvedCanonicalEcdsaContext = requireCompleteSharedKeyTargetContext({
      completion: sharedKeyTargetCompletion,
      source: 'stored ECDSA key facts',
    });
    ecdsaContextResolution = {
      kind: 'pre_resolved',
      context: resolvedCanonicalEcdsaContext,
    };
    signersToWarm = resolveThresholdLoginWarmSigners({
      selection: args.selection,
      configuredEcdsaTargets: args.selectedEcdsaTargets,
      canonicalEcdsaContext: resolvedCanonicalEcdsaContext,
    });
    ecdsaDependsOnEd25519 = signersToWarm.includes('ed25519') && signersToWarm.includes('ecdsa');
  }
  if (!signersToWarm.length) {
    throw new Error('[login] ECDSA unlock requested with no configured ECDSA targets');
  }
  return {
    kind: 'threshold_login_warmup_plan_ready',
    storedCanonicalEcdsaContext: args.storedCanonicalEcdsaContext,
    sharedKeyTargetCompletion,
    ecdsaContextResolution,
    signersToWarm,
    ed25519DependsOnEcdsa,
    ecdsaDependsOnEd25519,
  };
}

function createThresholdLoginWarmSessionId(prefix: string): string {
  return secureRandomId(prefix, 32, 'threshold login warm session IDs');
}

async function resolveWalletEcdsaKeyFactsInventoryWithWebAuthn(args: {
  nearAccountId: AccountId;
  relayerUrl: string;
  rpId: string;
  keyTargets: readonly WalletEcdsaKeyFactsInventoryTarget[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  collectCredential?: (challengeB64u: string) => Promise<WebAuthnAuthenticationCredential>;
}) {
  if (!args.collectCredential) {
    throw new Error('[login] WebAuthn ECDSA key-facts repair requires a credential collector');
  }
  const serverNonceB64u = createLocalUnlockChallengeB64u();
  const expectedChallengeDigestB64u = await computeWalletEcdsaKeyFactsInventoryChallengeDigestB64u({
    walletId: args.nearAccountId,
    rpId: args.rpId,
    keyTargets: args.keyTargets,
    serverNonceB64u,
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
  });
  const credential = await args.collectCredential(expectedChallengeDigestB64u);
  return await repairWalletEcdsaKeyFactsInventoryWithWebAuthn({
    relayerUrl: args.relayerUrl,
    walletId: args.nearAccountId,
    rpId: args.rpId,
    credential,
    keyTargets: args.keyTargets,
    serverNonceB64u,
    expectedChallengeDigestB64u,
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
  });
}

async function resolveProfileContinuityEcdsaWarmKeys(
  nearAccountId: AccountId,
  configuredTargets: readonly ConfiguredThresholdEcdsaPublicationTarget[],
  repairInput?: {
    repairAuthority: LoginEcdsaKeyFactsRepairAuthority | null;
    repairRequested: boolean;
    relayerUrl: string;
    rpId: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    collectWebAuthnRepairCredential?: (
      challengeB64u: string,
    ) => Promise<WebAuthnAuthenticationCredential>;
  },
): Promise<ConfiguredTargetThresholdEcdsaWarmKey[]> {
  const configuredChainTargets = configuredTargets.map((target) => target.chainTarget);
  const walletSigners = await IndexedDBManager.listAccountSignersByProfile({
    profileId: String(toWalletId(nearAccountId)),
    status: 'active',
  }).catch(() => []);
  const activeSignerRecords: ActiveEcdsaSignerRecord[] = [];
  const repairRecords: RepairRequiredEcdsaSignerRecord[] = [];
  const blockedRecords: BlockedEcdsaSignerRecord[] = [];
  for (const signer of walletSigners) {
    const parsed = parseActiveEcdsaSignerRecordForUnlock({
      walletId: toWalletId(nearAccountId),
      configuredTargets: configuredChainTargets,
      signer,
    });
    switch (parsed.kind) {
      case 'active_ecdsa_signer_record':
        activeSignerRecords.push(parsed);
        break;
      case 'repair_required':
        repairRecords.push(parsed);
        break;
      case 'blocked':
        blockedRecords.push(parsed);
        break;
      case 'skipped':
        break;
      default:
        parsed satisfies never;
    }
  }
  if (!activeSignerRecords.length && !repairRecords.length && !blockedRecords.length) {
    return [];
  }
  const plan = planUnlockEcdsaWarmup({
    selection: { mode: 'ecdsa_only', ecdsa: true },
    configuredTargets: configuredChainTargets,
    activeSignerRecords,
    repairRecords,
    blockedRecords,
    localSessionRecords: [],
    runtimeConfig: {
      explicitRepairMode: repairInput?.repairRequested === true,
      allowAuthenticatedKeyFactsInventory: Boolean(repairInput?.repairAuthority),
    },
  });
  switch (plan.kind) {
    case 'ready': {
      const keys = plan.readyTargets.map((target) =>
        configuredTargetThresholdEcdsaWarmKey({
          chainTarget: target.chainTarget,
          keyHandle: target.walletKey.keyHandle,
          key: evmFamilyEcdsaWalletKeyToIdentity(target.walletKey),
        }),
      );
      return collectConfiguredTargetThresholdEcdsaWarmKeys({
        source: 'profile continuity',
        keys,
      });
    }
    case 'no_configured_ecdsa_targets':
      return [];
    case 'awaiting_authenticated_key_facts_inventory': {
      const repairAuthority = repairInput?.repairAuthority;
      if (!repairAuthority) {
        throw new Error(
          '[login] threshold ECDSA key-facts repair requires authenticated repair authority',
        );
      }
      const relayerUrl = String(repairInput.relayerUrl || '').trim();
      const rpId = String(repairInput.rpId || '').trim();
      if (!relayerUrl || !rpId) {
        throw new Error('[login] threshold ECDSA key-facts repair requires relayerUrl and rpId');
      }
      const inventory =
        repairAuthority.kind === 'app_session'
          ? await repairWalletEcdsaKeyFactsInventoryWithAppSession({
              relayerUrl,
              walletId: nearAccountId,
              rpId,
              appSessionJwt: repairAuthority.appSessionJwt,
              keyTargets: plan.keyTargets,
              policy: {
                permission: 'ecdsa_key_facts_inventory',
                walletId: nearAccountId,
                chainTargets: plan.keyTargets.map((target) => target.chainTarget),
                expiresAtMs: repairAuthority.policyExpiresAtMs,
              },
              ...(repairInput.runtimePolicyScope
                ? { runtimePolicyScope: repairInput.runtimePolicyScope }
                : {}),
            })
          : await resolveWalletEcdsaKeyFactsInventoryWithWebAuthn({
              nearAccountId,
              relayerUrl,
              rpId,
              keyTargets: plan.keyTargets,
              ...(repairInput.runtimePolicyScope
                ? { runtimePolicyScope: repairInput.runtimePolicyScope }
                : {}),
              collectCredential: repairInput.collectWebAuthnRepairCredential,
            });
      const repairedKeys = collectConfiguredTargetThresholdEcdsaWarmKeys({
        source: 'profile continuity repair',
        keys: inventory.records.map((record) =>
          configuredTargetThresholdEcdsaWarmKey({
            chainTarget: record.walletKey.chainTarget,
            keyHandle: record.walletKey.keyHandle,
            key: evmFamilyEcdsaWalletKeyToIdentity(record.walletKey),
          }),
        ),
      });
      const repairedCompletion = buildSharedKeyTargetCompletion({
        context: { ecdsaKeys: repairedKeys },
        configuredTargets,
      });
      if (repairedCompletion.kind !== 'complete_shared_key_targets') {
        throw new Error('[login] threshold ECDSA key-facts repair returned incomplete key facts');
      }
      return repairedCompletion.context.ecdsaKeys;
    }
    case 'repair_required': {
      const targets = plan.repairRecords.map((record) => record.targetKey).join(', ');
      if (repairInput?.repairRequested) {
        throw new Error(
          `[login] threshold ECDSA key-facts repair requires authenticated repair authority for ${targets}`,
        );
      }
      throw new Error(
        `[login] threshold ECDSA warm-up requires complete local key facts for ${targets}; run explicit ECDSA key-facts repair before unlock`,
      );
    }
    case 'blocked': {
      const reasons = plan.blockedRecords
        .map((record) => `${record.targetKey || 'unknown'}:${record.reason}`)
        .join(', ');
      throw new Error(
        `[login] threshold ECDSA warm-up requires complete local key facts before unlock; run explicit ECDSA key-facts repair before unlock; blocked profile signer records: ${reasons}`,
      );
    }
  }
  plan satisfies never;
  return [];
}

async function resolveCanonicalThresholdEcdsaWarmSessionContext(
  context: LoginWebContext,
  signingEngine: Pick<EcdsaLoginSessionSurface, 'listThresholdEcdsaSessionRecordsForWalletTarget'>,
  nearAccountId: AccountId,
  repairInput?: {
    repairAuthority: LoginEcdsaKeyFactsRepairAuthority | null;
    repairRequested: boolean;
    relayerUrl: string;
    rpId: string;
    collectWebAuthnRepairCredential?: (
      challengeB64u: string,
    ) => Promise<WebAuthnAuthenticationCredential>;
  },
): Promise<CanonicalThresholdEcdsaWarmSessionContext> {
  const allowedSources = new Set<ThresholdEcdsaSessionStoreSource>(
    THRESHOLD_ECDSA_LOGIN_METADATA_SOURCES,
  );
  const configuredTargets = listConfiguredThresholdEcdsaPublicationTargets(
    context.configs.network.chains,
  );
  const storedKeys: ConfiguredTargetThresholdEcdsaWarmKey[] = [];
  let runtimePolicyScope: ThresholdRuntimePolicyScope | undefined;
  for (const target of configuredTargets) {
    for (const record of signingEngine.listThresholdEcdsaSessionRecordsForWalletTarget({
      walletId: toWalletId(nearAccountId),
      chainTarget: target.chainTarget,
    })) {
      if (!allowedSources.has(record.source)) continue;
      const keyHandle = String(record.keyHandle || '').trim();
      if (keyHandle) {
        let key: EvmFamilyEcdsaKeyIdentity;
        try {
          key = thresholdEcdsaSessionRecordReadModel(record).key;
        } catch {
          continue;
        }
        storedKeys.push(
          configuredTargetThresholdEcdsaWarmKey({
            chainTarget: target.chainTarget,
            keyHandle,
            key,
            passkeyCredentialIdB64u: passkeyCredentialIdB64uFromEcdsaRecord(record),
          }),
        );
      }
      if (!runtimePolicyScope && record.runtimePolicyScope) {
        runtimePolicyScope = record.runtimePolicyScope;
      }
    }
  }
  const exactStoredKeys = collectConfiguredTargetThresholdEcdsaWarmKeys({
    source: 'stored',
    keys: storedKeys,
  });
  if (exactStoredKeys.length) {
    return {
      ecdsaKeys: exactStoredKeys,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    };
  }
  const snapshot = await readAvailableSigningLanesForUi(context, nearAccountId).catch(() => null);
  const availableLaneKeys: ConfiguredTargetThresholdEcdsaWarmKey[] = [];
  if (snapshot) {
    for (const target of ecdsaAvailableLaneTargets(snapshot)) {
      const lane = ecdsaAvailableLaneForTarget(snapshot, target);
      if (!isConcreteAvailableSigningLane(lane)) continue;
      const keyHandle = String(lane.publicFacts.keyHandle || '').trim();
      if (!keyHandle) continue;
      availableLaneKeys.push(
        configuredTargetThresholdEcdsaWarmKey({
          chainTarget: target,
          keyHandle,
          key: lane.key,
        }),
      );
    }
  }
  const exactAvailableLaneKeys = collectConfiguredTargetThresholdEcdsaWarmKeys({
    source: 'available lane',
    keys: availableLaneKeys,
  });
  if (exactAvailableLaneKeys.length) {
    return {
      ecdsaKeys: exactAvailableLaneKeys,
    };
  }
  const profileEcdsaThresholdKeys = await resolveProfileContinuityEcdsaWarmKeys(
    nearAccountId,
    configuredTargets,
    {
      ...(repairInput || {
        repairAuthority: null,
        repairRequested: false,
        relayerUrl: '',
        rpId: '',
      }),
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    },
  );
  if (profileEcdsaThresholdKeys.length) {
    return {
      ecdsaKeys: profileEcdsaThresholdKeys,
    };
  }
  return {
    ecdsaKeys: [],
  };
}

function resolveManagedThresholdRuntimeScopeBootstrap(
  context: Pick<LoginWebContext, 'configs'>,
): ManagedThresholdRuntimeScopeBootstrap | undefined {
  const registration = context.configs?.registration;
  if (!registration || registration.mode !== 'managed') return undefined;
  const environmentId = String(registration.environmentId || '').trim();
  const publishableKey = String(registration.publishableKey || '').trim();
  if (!environmentId || !publishableKey) return undefined;
  return { environmentId, publishableKey };
}

function resolveThresholdEcdsaPublicKeyB64u(
  context: WalletSessionWebContext,
  nearAccountId: AccountId,
): string | null {
  for (const record of readThresholdEcdsaLoginMetadataRecords(context, nearAccountId)) {
    const thresholdEcdsaPublicKeyB64u = String(record.thresholdEcdsaPublicKeyB64u || '').trim();
    if (thresholdEcdsaPublicKeyB64u) return thresholdEcdsaPublicKeyB64u;
  }
  return null;
}

async function resolveProfileContinuityThresholdEcdsaPublicKeyB64u(
  context: WalletSessionWebContext,
  nearAccountId: AccountId,
): Promise<string | null> {
  const publicKeys = [
    ...new Set(
      (await readProfileContinuityThresholdEcdsaWalletKeys(context, nearAccountId))
        .map((walletKey) => String(walletKey.keyFacts.thresholdEcdsaPublicKeyB64u || '').trim())
        .filter(Boolean),
    ),
  ];
  if (publicKeys.length === 1) return publicKeys[0]!;
  if (publicKeys.length > 1) {
    console.warn('[WalletSession] conflicting profile threshold ECDSA public keys', {
      nearAccountId: String(nearAccountId),
      publicKeyCount: publicKeys.length,
    });
  }
  return null;
}

async function resolveThresholdEcdsaLoginMetadata(
  context: WalletSessionWebContext,
  nearAccountId: AccountId,
): Promise<{
  ethereumAddress: string | null;
  thresholdEcdsaPublicKeyB64u: string | null;
}> {
  const [ethereumAddress, thresholdEcdsaPublicKeyB64u] = await Promise.all([
    resolveThresholdEcdsaEthereumAddress(context, nearAccountId),
    (async () =>
      resolveThresholdEcdsaPublicKeyB64u(context, nearAccountId) ||
      (await resolveProfileContinuityThresholdEcdsaPublicKeyB64u(context, nearAccountId)))(),
  ]);
  return {
    ethereumAddress,
    thresholdEcdsaPublicKeyB64u,
  };
}

function isThresholdSignerMode(context: WalletSessionWebContext): boolean {
  const signingConfig = context.configs?.signing as { mode?: { mode?: unknown } } | undefined;
  return String(signingConfig?.mode?.mode || '').trim() === 'threshold-signer';
}

async function resolveWarmSigningSessionStatusForUi(
  context: WalletSessionWebContext,
  nearAccountId: AccountId,
  hints?: {
    ed25519?: SigningSessionStatus | null;
  },
): Promise<SigningSessionStatus | null> {
  const ed25519 =
    hints && 'ed25519' in hints
      ? hints.ed25519 || null
      : await context.signingEngine
          .getWarmThresholdEd25519SessionStatus(nearAccountId)
          .catch(() => null);
  const ecdsaStatuses = (
    await Promise.all(
      listConfiguredThresholdEcdsaPublicationTargets(context.configs.network.chains).map((target) =>
        context.signingEngine
          .listWarmThresholdEcdsaSessionStatuses(toWalletId(nearAccountId), target.chainTarget)
          .catch(() => []),
      ),
    )
  ).flat();

  const statuses = [ed25519, ...ecdsaStatuses].filter((status): status is SigningSessionStatus =>
    Boolean(status),
  );
  return selectSigningSessionStatusForUi(statuses);
}

type AvailableSigningLanesLane = AvailableEd25519SigningLane | AvailableEcdsaSigningLane;

function selectSigningSessionStatusForUi(
  statuses: readonly (SigningSessionStatus | null | undefined)[],
): SigningSessionStatus | null {
  const candidates = statuses.filter((status): status is SigningSessionStatus => Boolean(status));
  const active = candidates
    .filter((status) => status.status === 'active')
    .sort((left, right) => {
      const leftUses = Math.floor(Number(left.remainingUses) || 0);
      const rightUses = Math.floor(Number(right.remainingUses) || 0);
      if (leftUses !== rightUses) return leftUses - rightUses;
      return Math.floor(Number(left.expiresAtMs) || 0) - Math.floor(Number(right.expiresAtMs) || 0);
    })[0];
  if (active) return active;
  return candidates.find((status) => status.status !== 'not_found') || candidates[0] || null;
}

function snapshotLaneToSigningSessionStatus(
  lane: AvailableSigningLanesLane,
): SigningSessionStatus | null {
  if (!isConcreteAvailableSigningLane(lane)) return null;
  const sessionId = String(lane.thresholdSessionId || '').trim();
  if (!sessionId) return null;
  if (
    lane.state !== 'ready' &&
    lane.state !== 'restorable' &&
    lane.state !== 'expired' &&
    lane.state !== 'exhausted'
  ) {
    return null;
  }
  const remainingUses = Math.floor(Number(lane.remainingUses ?? lane.policyHint?.remainingUses));
  const expiresAtMs = Math.floor(Number(lane.expiresAtMs ?? lane.policyHint?.expiresAtMs));
  if (lane.state === 'restorable') {
    if (Number.isFinite(remainingUses) && remainingUses <= 0) return null;
    if (Number.isFinite(expiresAtMs) && expiresAtMs > 0 && Date.now() >= expiresAtMs) return null;
  }
  const status: SigningSessionStatus = {
    sessionId,
    status:
      lane.state === 'ready' || lane.state === 'restorable'
        ? 'active'
        : lane.state === 'expired'
          ? 'expired'
          : 'exhausted',
    ...(lane.authMethod ? { authMethod: lane.authMethod } : {}),
  };
  if (Number.isFinite(remainingUses) && remainingUses >= 0) {
    status.remainingUses = remainingUses;
  }
  if (Number.isFinite(expiresAtMs) && expiresAtMs > 0) {
    status.expiresAtMs = expiresAtMs;
  }
  return status;
}

function snapshotToSigningSessionStatusForUi(
  snapshot: AvailableSigningLanes | null,
): SigningSessionStatus | null {
  if (!snapshot) return null;
  return selectSigningSessionStatusForUi([
    snapshotLaneToSigningSessionStatus(snapshot.lanes.ed25519.near),
    ...ecdsaAvailableLaneTargets(snapshot).map((target) =>
      snapshotLaneToSigningSessionStatus(ecdsaAvailableLaneForTarget(snapshot, target)),
    ),
  ]);
}

async function readAvailableSigningLanesForUi(
  context: WalletSessionWebContext,
  nearAccountId: AccountId,
): Promise<AvailableSigningLanes | null> {
  return await context.signingEngine.readPersistedAvailableSigningLanes({
    walletId: nearAccountId,
  });
}

async function resolveSnapshotSigningSessionStatusForUi(
  context: WalletSessionWebContext,
  nearAccountId: AccountId,
): Promise<SigningSessionStatus | null> {
  return snapshotToSigningSessionStatusForUi(
    await readAvailableSigningLanesForUi(context, nearAccountId),
  );
}

async function resolveSigningSessionStatusForUi(
  context: WalletSessionWebContext,
  nearAccountId: AccountId,
  hints?: {
    ed25519?: SigningSessionStatus | null;
    snapshot?: SigningSessionStatus | null;
  },
): Promise<SigningSessionStatus | null> {
  const [warmStatus, snapshotStatus] = await Promise.all([
    resolveWarmSigningSessionStatusForUi(context, nearAccountId, hints).catch(() => null),
    hints && 'snapshot' in hints
      ? Promise.resolve(hints.snapshot || null)
      : resolveSnapshotSigningSessionStatusForUi(context, nearAccountId).catch(() => null),
  ]);
  // Status reads are side-effect-free. The next signing command owns exact
  // restore; warm status remains useful as a runtime fallback while the
  // refactor finishes.
  return selectSigningSessionStatusForUi([snapshotStatus, warmStatus]);
}

async function getLoginStateInternal(
  context: WalletSessionWebContext,
  nearAccountId?: AccountId,
): Promise<LoginState> {
  const { signingEngine } = context;
  try {
    const lastUser = await signingEngine.getLastUser().catch(() => null);
    const lastSelectedAccount =
      nearAccountId || lastUser?.nearAccountId
        ? null
        : await getLastSelectedNearAccount(IndexedDBManager).catch(() => null);
    const targetAccountId =
      nearAccountId ?? lastUser?.nearAccountId ?? lastSelectedAccount?.nearAccountId ?? null;
    if (!targetAccountId) {
      return {
        isLoggedIn: false,
        nearAccountId: null,
        publicKey: null,
        userData: null,
        authMethod: null,
        thresholdEcdsaEthereumAddress: null,
        thresholdEcdsaPublicKeyB64u: null,
      };
    }

    const latestByAccount =
      lastUser && lastUser.nearAccountId === targetAccountId
        ? null
        : await getNearAccountProjection(IndexedDBManager, targetAccountId).catch(() => null);
    const userData =
      (lastUser && lastUser.nearAccountId === targetAccountId ? lastUser : latestByAccount) ||
      (await signingEngine.getUserBySignerSlot(targetAccountId, 1).catch(() => null));
    const resolvedNearAccountId = targetAccountId;
    const thresholdMetadata = await resolveThresholdEcdsaLoginMetadata(
      context,
      resolvedNearAccountId,
    );
    const requiresWarmSession = shouldRequireThresholdWarmSession(context);
    const thresholdSignerMode = isThresholdSignerMode(context);
    const hasThresholdEcdsaLogin = !!(
      thresholdMetadata.thresholdEcdsaPublicKeyB64u || thresholdMetadata.ethereumAddress
    );
    const ed25519WarmStatus = await signingEngine
      .getWarmThresholdEd25519SessionStatus(resolvedNearAccountId)
      .catch(() => null);
    const snapshotStatusForLogin = await resolveSnapshotSigningSessionStatusForUi(
      context,
      resolvedNearAccountId,
    ).catch(() => null);
    const hasThresholdEd25519SessionRecord =
      !!getStoredThresholdEd25519SessionRecordForAccount(resolvedNearAccountId);
    const shouldGateNearPublicKey =
      requiresWarmSession || thresholdSignerMode || hasThresholdEcdsaLogin;
    const hasThresholdEd25519SigningCapability =
      ed25519WarmStatus?.status === 'active' ||
      snapshotStatusForLogin?.status === 'active' ||
      hasThresholdEd25519SessionRecord;
    const publicKey =
      userData?.operationalPublicKey &&
      (!shouldGateNearPublicKey || hasThresholdEd25519SigningCapability)
        ? userData.operationalPublicKey
        : null;
    const hasNearOperationalLogin = !!(userData && publicKey);
    const shouldResolveWarmStatusForLogin =
      requiresWarmSession || thresholdSignerMode || hasThresholdEcdsaLogin || !publicKey;
    const warmStatusForLogin = shouldResolveWarmStatusForLogin
      ? await resolveSigningSessionStatusForUi(context, resolvedNearAccountId, {
          ed25519: ed25519WarmStatus,
          snapshot: snapshotStatusForLogin,
        }).catch(() => null)
      : null;
    const hasActiveWarmSigningSession = warmStatusForLogin?.status === 'active';
    const isLoggedIn =
      hasNearOperationalLogin || hasThresholdEcdsaLogin || hasActiveWarmSigningSession;

    if (isLoggedIn && (requiresWarmSession || !hasNearOperationalLogin)) {
      const warmStatus =
        warmStatusForLogin ||
        (await resolveSigningSessionStatusForUi(context, resolvedNearAccountId, {
          ed25519: ed25519WarmStatus,
          snapshot: snapshotStatusForLogin,
        }));
      if (!warmStatus || warmStatus.status !== 'active') {
        return {
          isLoggedIn: false,
          nearAccountId: resolvedNearAccountId,
          publicKey: null,
          userData: null,
          authMethod: null,
          thresholdEcdsaEthereumAddress: thresholdMetadata.ethereumAddress,
          thresholdEcdsaPublicKeyB64u: thresholdMetadata.thresholdEcdsaPublicKeyB64u,
        };
      }
    }

    return {
      isLoggedIn,
      nearAccountId: resolvedNearAccountId,
      publicKey,
      userData,
      authMethod:
        isLoggedIn && publicKey
          ? 'passkey'
          : isLoggedIn
            ? warmStatusForLogin?.authMethod || null
            : null,
      thresholdEcdsaEthereumAddress: thresholdMetadata.ethereumAddress,
      thresholdEcdsaPublicKeyB64u: thresholdMetadata.thresholdEcdsaPublicKeyB64u,
    };
  } catch (error: unknown) {
    console.warn('Error getting login state:', error);
    return {
      isLoggedIn: false,
      nearAccountId: nearAccountId || null,
      publicKey: null,
      userData: null,
      authMethod: null,
      thresholdEcdsaEthereumAddress: null,
      thresholdEcdsaPublicKeyB64u: null,
    };
  }
}

/**
 * List recently used accounts from IndexedDB.
 *
 * Used for account picker UIs and initial app bootstrap state.
 */
export async function getRecentUnlocks(
  context: RecentUnlocksWebContext,
): Promise<GetRecentUnlocksResult> {
  const allUsersData = await context.signingEngine.getAllUsers();
  const accountIds = [...new Set(allUsersData.map((user) => user.nearAccountId))];
  const lastUsedAccount = await context.signingEngine.getLastUser();
  return {
    accountIds,
    accounts: allUsersData.map((user) => ({
      nearAccountId: user.nearAccountId,
      signerSlot: user.signerSlot,
      authMethod: user.authMethod || null,
    })),
    lastUsedAccount,
  };
}

/**
 * Lock: clears last-user pointer and client-side caches.
 */
export async function lock(context: LockWebContext): Promise<void> {
  const { signingEngine } = context;
  await IndexedDBManager.clearLastProfileSelection().catch(() => undefined);
  try {
    signingEngine.getNonceCoordinator().clearAll();
  } catch {}
  try {
    signingEngine.clearThresholdEcdsaCommitQueue();
  } catch {}
  try {
    signingEngine.clearAllThresholdEcdsaSessionRecords();
  } catch {}
  try {
    await signingEngine.clearVolatileWarmSigningMaterial();
  } catch {}
  try {
    clearAllStoredThresholdEd25519SessionRecords();
  } catch {}
}
