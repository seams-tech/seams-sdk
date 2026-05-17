import type {
  AfterCall,
  CreateUnlockFlowEventInput,
  LoginHooksOptions,
} from '../types/sdkSentEvents';
import { createUnlockFlowEvent, UnlockEventPhase } from '../types/sdkSentEvents';
import type {
  GetRecentUnlocksResult,
  LoginAndCreateSessionResult,
  LoginResult,
  WalletSession,
  LoginState,
  SigningSessionStatus,
  ThresholdWarmLoginAndCreateSessionResult,
  WalletAuthMethod,
} from '../types/seams';
import type { PasskeyManagerContext } from './index';
import type { AccountId } from '../types/accountIds';
import type { WebAuthnAuthenticationCredential } from '../types';
import {
  getUserFriendlyErrorMessage,
  isUserCancellationError,
  toError,
} from '@shared/utils/errors';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import { isObject } from '@shared/utils/validation';
import { IndexedDBManager } from '../indexedDB';
import {
  getLastSelectedNearAccount,
  getNearAccountProjection,
  resolveNearAccountProfileContinuity,
} from '../accountData/near/accountProjection';
import { getNearThresholdKeyMaterial } from '../accountData/near/keyMaterial';
import type { ClientUserData } from '../accountData/near/types';
import { exchangeSession, type SessionExchangeInput } from '../rpcClients/near/rpcCalls';
import type { ThresholdEcdsaHssRouteAuth } from '../rpcClients/relayer/thresholdEcdsa';
import { parseSignerSlot } from '../signingEngine/webauthnAuth/device/signerSlot';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  getStoredThresholdEd25519SessionRecordForAccount,
  type ThresholdEcdsaSessionRecord,
} from '../signingEngine/session/persistence/records';
import type { ThresholdEcdsaSessionStoreSource } from '../signingEngine/session/identity/laneIdentity';
import {
  generateWalletSigningSessionId,
  type ThresholdRuntimePolicyScope,
} from '../signingEngine/threshold/sessionPolicy';
import { shouldRequireThresholdWarmSession } from './thresholdWarmSessionDefaults';
import { prewarmThresholdEd25519ClientBaseFromCredential } from './thresholdWarmSessionBootstrap';
import { listConfiguredThresholdEcdsaPublicationTargets } from './thresholdEcdsaProvisioning';
import type {
  AvailableSigningLanes,
  ConcreteAvailableEcdsaSigningLane,
  AvailableEcdsaSigningLane,
  AvailableEd25519SigningLane,
} from '../signingEngine/session/availability/availableSigningLanes';
import {
  ecdsaAvailableLaneForTarget,
  ecdsaAvailableLaneTargets,
  isConcreteAvailableSigningLane,
} from '../signingEngine/session/availability/availableSigningLanes';
import {
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
  walletSubjectIdFromWalletProfile,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { buildEcdsaSessionIdentity } from '../signingEngine/session/warmCapabilities/ecdsaProvisionPlan';
import {
  buildEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaKeyIdentityFromRecord,
  buildEvmFamilyEcdsaSessionLanePolicy,
  deriveEvmFamilyKeyFingerprint,
  type EvmFamilyEcdsaKeyIdentity,
} from '../signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { SIGNER_AUTH_METHODS, SIGNER_KINDS } from '@shared/utils/signerDomain';

type EmitUnlockEventInput = Omit<CreateUnlockFlowEventInput, 'accountId' | 'flowId'>;

const PASSKEY_UNLOCK_SIGNING_SESSION_REMAINING_USES = 3;

function emitUnlockEvent(
  onEvent: LoginHooksOptions['onEvent'] | undefined,
  nearAccountId: AccountId | string,
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
  context: PasskeyManagerContext,
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

    emitUnlockEvent(onEvent, nearAccountId, {
      phase: UnlockEventPhase.STEP_02_ACCOUNT_LOOKUP_STARTED,
      status: 'running',
      authMethod: 'passkey',
    });

    const hintUserPromise: Promise<ClientUserData | null> =
      signerSlotHint !== null
        ? signingEngine.getUserBySignerSlot(nearAccountId, signerSlotHint).catch(() => null)
        : Promise.resolve(null);

    const [hintUser, lastUser, latestByAccount, authenticators] = await Promise.all([
      hintUserPromise,
      signingEngine.getLastUser().catch(() => null),
      getNearAccountProjection(IndexedDBManager.clientDB, nearAccountId).catch(() => null),
      signingEngine.getAuthenticatorsByUser(nearAccountId).catch(() => []),
    ]);

    if (authenticators.length === 0) {
      throw new Error(
        `No authenticators found for account ${nearAccountId}. Please register an account.`,
      );
    }

    let userData: ClientUserData | null = null;
    if (hintUser && hintUser.nearAccountId === nearAccountId) {
      userData = hintUser;
    } else if (latestByAccount && latestByAccount.nearAccountId === nearAccountId) {
      userData = latestByAccount;
    } else if (lastUser && lastUser.nearAccountId === nearAccountId) {
      userData = lastUser;
    } else {
      userData = await signingEngine.getUserBySignerSlot(nearAccountId, 1).catch(() => null);
    }

    if (!userData) {
      throw new Error(
        `User data not found for ${nearAccountId} in IndexedDB. Please register an account.`,
      );
    }
    if (!userData.operationalPublicKey) {
      throw new Error(
        `No NEAR operational key found for ${nearAccountId}. Please register an account.`,
      );
    }

    emitUnlockEvent(onEvent, nearAccountId, {
      phase: UnlockEventPhase.STEP_02_ACCOUNT_LOOKUP_SUCCEEDED,
      status: 'succeeded',
      authMethod: 'passkey',
      data: {
        signerSlot: userData.signerSlot,
        operationalPublicKey: userData.operationalPublicKey,
      },
    });

    const baseSignerSlot =
      signerSlotHint ??
      (Number.isFinite(userData.signerSlot) && userData.signerSlot >= 1 ? userData.signerSlot : 1);

    const signingSessionPolicy = (() => {
      const ttlMsRaw =
        options?.signingSession?.ttlMs ?? context.configs?.signing.sessionDefaults?.ttlMs;
      const remainingUsesRaw =
        options?.signingSession?.remainingUses ?? PASSKEY_UNLOCK_SIGNING_SESSION_REMAINING_USES;
      const ttlMs =
        typeof ttlMsRaw === 'number' ? Math.floor(ttlMsRaw) : Math.floor(Number(ttlMsRaw) || 0);
      const remainingUses =
        typeof remainingUsesRaw === 'number'
          ? Math.floor(remainingUsesRaw)
          : Math.floor(Number(remainingUsesRaw) || 0);
      return {
        ttlMs: Math.max(0, ttlMs),
        remainingUses: Math.min(
          Math.max(0, remainingUses),
          PASSKEY_UNLOCK_SIGNING_SESSION_REMAINING_USES,
        ),
      };
    })();

    let signingSession: LoginAndCreateSessionResult['signingSession'] | undefined;
    // Warm sessions are enabled when policy budgets are non-zero.
    const shouldWarmThresholdSigningSession =
      signingSessionPolicy.ttlMs > 0 && signingSessionPolicy.remainingUses > 0;
    const requireThresholdWarmup = shouldWarmThresholdSigningSession;

    const requireActiveWarmSession = (source: string): void => {
      if (signingSession?.status === 'active') return;
      const status = String(signingSession?.status || 'not_found');
      throw new Error(
        `[login] ${source} did not produce an active warm signing session (status=${status})`,
      );
    };

    const maybeWarmThresholdSigningSessions = async (args: {
      signerSlot: number;
      appSessionJwt?: string;
      useAppSessionCookie?: boolean;
    }): Promise<void> => {
      if (!requireThresholdWarmup) return;

      const relayerUrl = String(context.configs?.network.relayer?.url || '').trim();
      if (!relayerUrl) {
        throw new Error('[login] threshold warm session requires relayer.url to be configured');
      }

      emitUnlockEvent(onEvent, nearAccountId, {
        phase: UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED,
        status: 'running',
        authMethod: loginCredential ? 'passkey' : 'warm_session',
      });

      const thresholdKeyMaterial = await getNearThresholdKeyMaterial(
        {
          clientDB: IndexedDBManager.clientDB,
          accountKeyMaterialDB: IndexedDBManager.accountKeyMaterialDB,
        },
        nearAccountId,
        args.signerSlot,
      ).catch(() => null);
      if (!thresholdKeyMaterial) {
        throw new Error(
          `[login] threshold warm-up requires threshold key material for ${nearAccountId} signer slot ${args.signerSlot}`,
        );
      }

      const participantIds = thresholdKeyMaterial.participants.map((participant) => participant.id);
      const configuredEcdsaTargets = listConfiguredThresholdEcdsaPublicationTargets(
        context.configs.network.chains,
      );
      const ecdsaChainTargets = configuredEcdsaTargets.map((target) => target.chainTarget);
      let restoredPasskeySigningSessionsAttempted = false;
      const canAttemptRestoredPasskeySessions = (): boolean => {
        if (loginCredential || args.appSessionJwt || args.useAppSessionCookie) return false;
        return typeof signingEngine.restorePersistedSessionsForWallet === 'function';
      };
      const restorePasskeySigningSessionsForUnlock = async (): Promise<void> => {
        if (!canAttemptRestoredPasskeySessions()) return;
        if (restoredPasskeySigningSessionsAttempted) return;
        restoredPasskeySigningSessionsAttempted = true;
        await signingEngine
          .restorePersistedSessionsForWallet({
            walletId: nearAccountId,
            authMethod: 'passkey',
            ecdsaChainTargets,
            maxRecords: Math.max(1, ecdsaChainTargets.length + 1),
          })
          .catch((error: unknown) => {
            console.warn('[login] passkey signing-session sealed restore during unlock failed', {
              nearAccountId,
              error: error instanceof Error ? error.message : String(error || 'unknown error'),
            });
          });
      };
      await restorePasskeySigningSessionsForUnlock();
      const storedCanonicalEcdsaContext = await resolveCanonicalThresholdEcdsaWarmSessionContext(
        context,
        signingEngine as unknown,
        nearAccountId,
      );
      let keyIdentityInventory: ThresholdEcdsaKeyIdentityInventoryEntry[] = [];
      const storedSharedKeyTargetCompletion = buildSharedKeyTargetCompletion({
        context: storedCanonicalEcdsaContext,
        configuredTargets: configuredEcdsaTargets,
      });
      const storedEcdsaKeyIdentityTargets = thresholdEcdsaKeyIdentityTargetRequestsFromContext({
        context: storedCanonicalEcdsaContext,
        configuredTargets: configuredEcdsaTargets,
      });
      if (
        configuredEcdsaTargets.length &&
        !keyIdentityInventory.length &&
        storedSharedKeyTargetCompletion.kind !== 'complete_shared_key_targets'
      ) {
        keyIdentityInventory = await resolveThresholdEcdsaKeyIdentityInventoryFromRestoredEd25519({
          relayerUrl,
          nearAccountId,
          rpId: String(signingEngine.getRpId() || '').trim(),
          keyTargets: storedEcdsaKeyIdentityTargets,
        });
      }
      const inventoryCanonicalEcdsaContext = resolveThresholdEcdsaKeyInventoryWarmSessionContext({
        keyIdentityInventory,
        configuredTargets: configuredEcdsaTargets,
      });
      const mergedCanonicalEcdsaContext = mergeCanonicalThresholdEcdsaWarmSessionContexts(
        storedCanonicalEcdsaContext,
        inventoryCanonicalEcdsaContext,
      );
      const sharedKeyTargetCompletion = buildSharedKeyTargetCompletion({
        context: mergedCanonicalEcdsaContext,
        configuredTargets: configuredEcdsaTargets,
      });
      let ecdsaContextResolution: ThresholdLoginWarmEcdsaContextResolution;
      let resolvedCanonicalEcdsaContext: CanonicalThresholdEcdsaWarmSessionContext;
      let signersToWarm: ThresholdLoginWarmSigner[];
      if (
        sharedKeyTargetCompletion.kind === 'missing_shared_key' &&
        configuredEcdsaTargets.length
      ) {
        const initialContext: CanonicalThresholdEcdsaWarmSessionContext = {
          ecdsaKeyIds: [],
          ...(mergedCanonicalEcdsaContext.runtimePolicyScope
            ? { runtimePolicyScope: mergedCanonicalEcdsaContext.runtimePolicyScope }
            : {}),
        };
        resolvedCanonicalEcdsaContext = initialContext;
        signersToWarm = ['ed25519', 'ecdsa'];
        ecdsaContextResolution = {
          kind: 'resolve_after_ed25519',
          initialContext,
          resolveAfterEd25519: async (ed25519State) => {
            const thresholdSessionAuthToken = String(ed25519State.jwt || '').trim();
            if (!thresholdSessionAuthToken) {
              throw new Error(
                '[login] threshold ECDSA warm-up requires Ed25519 threshold session auth before signer inventory fetch',
              );
            }
            const freshEcdsaKeyIdentityTargets = thresholdEcdsaKeyIdentityTargetRequestsFromContext(
              {
                context: mergedCanonicalEcdsaContext,
                configuredTargets: configuredEcdsaTargets,
              },
            );
            const freshKeyIdentityInventory =
              await resolveThresholdEcdsaKeyIdentityInventoryFromThresholdEd25519Auth({
                relayerUrl,
                nearAccountId,
                rpId: String(signingEngine.getRpId() || '').trim(),
                thresholdSessionAuthToken,
                keyTargets: freshEcdsaKeyIdentityTargets,
                source: 'fresh_ed25519',
              });
            const postEd25519InventoryContext = resolveThresholdEcdsaKeyInventoryWarmSessionContext(
              {
                keyIdentityInventory: [...keyIdentityInventory, ...freshKeyIdentityInventory],
                configuredTargets: configuredEcdsaTargets,
              },
            );
            const postEd25519MergedContext = mergeCanonicalThresholdEcdsaWarmSessionContexts(
              mergedCanonicalEcdsaContext,
              postEd25519InventoryContext,
            );
            return requireCompleteSharedKeyTargetContext({
              completion: buildSharedKeyTargetCompletion({
                context: postEd25519MergedContext,
                configuredTargets: configuredEcdsaTargets,
              }),
              source: 'fresh Ed25519 signer inventory',
            });
          },
        };
      } else {
        resolvedCanonicalEcdsaContext = requireCompleteSharedKeyTargetContext({
          completion: sharedKeyTargetCompletion,
          source: 'stored/normal ECDSA key inventory',
        });
        ecdsaContextResolution = {
          kind: 'pre_resolved',
          context: resolvedCanonicalEcdsaContext,
        };
        signersToWarm = await resolveThresholdLoginWarmSigners({
          configuredEcdsaTargets,
          canonicalEcdsaContext: resolvedCanonicalEcdsaContext,
        });
      }
      console.info('[login][ecdsa-warmup-diagnostic] signer selection', {
        nearAccountId,
        configuredTargets: configuredEcdsaTargets.map((target) =>
          thresholdEcdsaChainTargetKey(target.chainTarget),
        ),
        storedKeyTargets: storedCanonicalEcdsaContext.ecdsaKeyIds.map((key) => ({
          targetKey: key.targetKey,
          ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
          hasCanonicalKey: Boolean(key.key),
        })),
        keyIdentityInventoryTargets: keyIdentityInventory.map((entry) => ({
          targetKey: thresholdEcdsaChainTargetKey(entry.chainTarget),
          ecdsaThresholdKeyId: entry.ecdsaThresholdKeyId,
          hasCanonicalKey: Boolean(entry.key),
        })),
        sharedKeyTargetCompletion:
          sharedKeyTargetCompletion.kind === 'complete_shared_key_targets'
            ? {
                kind: sharedKeyTargetCompletion.kind,
                targetKeys: sharedKeyTargetCompletion.context.ecdsaKeyIds.map(
                  (key) => key.targetKey,
                ),
              }
            : sharedKeyTargetCompletion,
        ecdsaContextResolution: ecdsaContextResolution.kind,
        signersToWarm,
      });
      const preferredEd25519SessionId = createThresholdLoginWarmSessionId('threshold-login');
      const managedRuntimeScopeBootstrap = resolveManagedThresholdRuntimeScopeBootstrap(context);
      const hasPositiveRemainingUses = (value: unknown): boolean => {
        const remainingUses = Math.floor(Number(value));
        return Number.isFinite(remainingUses) && remainingUses > 0;
      };
      let restoredWarmSigners: ThresholdLoginWarmSigner[] = [];
      const canUseRestoredSigningSessions = async (): Promise<boolean> => {
        if (!canAttemptRestoredPasskeySessions()) return false;
        await restorePasskeySigningSessionsForUnlock();
        const restoredEd25519Status = await signingEngine
          .getWarmThresholdEd25519SessionStatus(nearAccountId)
          .catch(() => null);
        const restoredEd25519Active =
          restoredEd25519Status?.status === 'active' &&
          restoredEd25519Status.authMethod === 'passkey' &&
          hasPositiveRemainingUses(restoredEd25519Status.remainingUses);
        if (!restoredEd25519Active) return false;
        const missingEcdsaTargets: string[] = [];
        if (signersToWarm.includes('ecdsa')) {
          if (ecdsaContextResolution.kind !== 'pre_resolved') return false;
          const canonicalEcdsaContext = ecdsaContextResolution.context;
          let snapshot = await readAvailableSigningLanesForUi(context, nearAccountId).catch(
            () => null,
          );
          let restoredTargets = resolveRestoredPasskeyEcdsaWarmTargets({
            snapshot,
            configuredEcdsaTargets,
            canonicalEcdsaContext,
          });
          if (restoredTargets.length) {
            console.info('[login] completing restored passkey ECDSA warm lanes', {
              nearAccountId,
              ecdsaTargets: restoredTargets.map((target) => target.targetKey),
            });
            await bootstrapRestoredPasskeyEcdsaWarmTargets({
              signingEngine,
              nearAccountId,
              relayerUrl,
              ttlMs: signingSessionPolicy.ttlMs,
              remainingUses: signingSessionPolicy.remainingUses,
              canonicalEcdsaContext,
              ...(managedRuntimeScopeBootstrap ? { managedRuntimeScopeBootstrap } : {}),
              targets: restoredTargets,
            });
            snapshot = await readAvailableSigningLanesForUi(context, nearAccountId).catch(
              () => null,
            );
            restoredTargets = resolveRestoredPasskeyEcdsaWarmTargets({
              snapshot,
              configuredEcdsaTargets,
              canonicalEcdsaContext,
            });
          }
          missingEcdsaTargets.push(...restoredTargets.map((target) => target.targetKey));
          if (missingEcdsaTargets.length) {
            throw new Error(
              `[login] restored ECDSA warm-up did not produce ready lanes for ${missingEcdsaTargets.join(
                ', ',
              )}`,
            );
          }
        }
        restoredWarmSigners = [...signersToWarm];
        console.info('[login] reusing restored passkey signing sessions during unlock', {
          nearAccountId,
          restoredWarmSigners,
          missingEcdsaTargets,
          ecdsaTargets: configuredEcdsaTargets.map((target) =>
            thresholdEcdsaChainTargetKey(target.chainTarget),
          ),
        });
        signingSession = restoredEd25519Status;
        return true;
      };
      if (await canUseRestoredSigningSessions()) {
        emitUnlockEvent(onEvent, nearAccountId, {
          phase: UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED,
          status: 'succeeded',
          authMethod: 'warm_session',
        });
        if (restoredWarmSigners.includes('ed25519')) {
          emitUnlockEvent(onEvent, nearAccountId, {
            phase: UnlockEventPhase.STEP_05_ED25519_SIGNING_SESSION_READY,
            status: 'succeeded',
            authMethod: 'warm_session',
          });
        }
        if (restoredWarmSigners.includes('ecdsa')) {
          emitUnlockEvent(onEvent, nearAccountId, {
            phase: UnlockEventPhase.STEP_05_ECDSA_SIGNING_SESSION_READY,
            status: 'succeeded',
            authMethod: 'warm_session',
          });
        }
        return;
      }
      await primeThresholdLoginWarmSigners({
        context,
        signingEngine,
        nearAccountId,
        relayerUrl,
        relayerKeyId: thresholdKeyMaterial.relayerKeyId,
        participantIds,
        ttlMs: signingSessionPolicy.ttlMs,
        remainingUses: signingSessionPolicy.remainingUses,
        ecdsaContextResolution,
        ...(loginCredential ? { credential: loginCredential } : {}),
        ...(managedRuntimeScopeBootstrap ? { managedRuntimeScopeBootstrap } : {}),
        signersToWarm,
        preferredEd25519SessionId,
        appSessionJwt: args.appSessionJwt,
        useAppSessionCookie: args.useAppSessionCookie,
      });

      const warmStatus = await signingEngine
        .getWarmThresholdEd25519SessionStatus(nearAccountId)
        .catch(() => null);
      signingSession = warmStatus || signingSession;
      requireActiveWarmSession('threshold warm-up');

      if (signersToWarm.includes('ed25519')) {
        emitUnlockEvent(onEvent, nearAccountId, {
          phase: UnlockEventPhase.STEP_05_ED25519_SIGNING_SESSION_READY,
          status: 'succeeded',
          authMethod: 'warm_session',
        });
      }
      if (signersToWarm.includes('ecdsa')) {
        emitUnlockEvent(onEvent, nearAccountId, {
          phase: UnlockEventPhase.STEP_05_ECDSA_SIGNING_SESSION_READY,
          status: 'succeeded',
          authMethod: 'warm_session',
        });
      }
    };

    const requireThresholdWarmLoginBundle = (
      source: string,
    ): Pick<ThresholdWarmLoginAndCreateSessionResult, 'signingSession'> => {
      requireActiveWarmSession(source);
      const activeSigningSession =
        signingSession as ThresholdWarmLoginAndCreateSessionResult['signingSession'];
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
              nearAccountId,
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
          await maybeWarmThresholdSigningSessions({
            signerSlot: baseSignerSlot,
            appSessionJwt: exchanged.jwt,
            useAppSessionCookie: session.kind === 'cookie' && !!loginCredential,
          });
        }
        await persistSuccessfulLoginState(baseSignerSlot);
        await recoverNonceLanesAfterUnlock();
        if (loginCredential) {
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
          operationalPublicKey: userData.operationalPublicKey,
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

    if (requireThresholdWarmup) {
      await maybeWarmThresholdSigningSessions({
        signerSlot: baseSignerSlot,
      });
    }

    await persistSuccessfulLoginState(baseSignerSlot);
    await recoverNonceLanesAfterUnlock();
    if (loginCredential) {
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
          operationalPublicKey: userData.operationalPublicKey,
          nearAccountId,
          ...requireThresholdWarmLoginBundle('login'),
        }
      : {
          success: true,
          loggedInNearAccountId: String(nearAccountId),
          operationalPublicKey: userData.operationalPublicKey,
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

type ConfiguredTargetThresholdEcdsaWarmKey = {
  chainTarget: ThresholdEcdsaChainTarget;
  targetKey: string;
  ecdsaThresholdKeyId: string;
  key?: EvmFamilyEcdsaKeyIdentity;
};

type ThresholdEcdsaKeyIdentityInventoryEntry = {
  ecdsaThresholdKeyId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  accountAddress: string;
  ownerAddress: string;
  key: EvmFamilyEcdsaKeyIdentity;
};

type CanonicalThresholdEcdsaWarmSessionContext = {
  ecdsaKeyIds: ConfiguredTargetThresholdEcdsaWarmKey[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
};

type SharedKeyTargetCompletion =
  | {
      kind: 'complete_shared_key_targets';
      context: CanonicalThresholdEcdsaWarmSessionContext;
      missingTargets?: never;
      ecdsaThresholdKeyIds?: never;
    }
  | {
      kind: 'ambiguous_shared_key_targets';
      ecdsaThresholdKeyIds: string[];
      missingTargets?: never;
      context?: never;
    }
  | {
      kind: 'missing_shared_key';
      missingTargets: string[];
      context?: never;
      ecdsaThresholdKeyIds?: never;
    };

type ThresholdLoginWarmEcdsaContextResolution =
  | {
      kind: 'pre_resolved';
      context: CanonicalThresholdEcdsaWarmSessionContext;
      initialContext?: never;
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

function configuredTargetThresholdEcdsaWarmKey(args: {
  chainTarget: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId: string;
  key?: EvmFamilyEcdsaKeyIdentity;
}): ConfiguredTargetThresholdEcdsaWarmKey {
  const ecdsaThresholdKeyId = String(args.ecdsaThresholdKeyId || '').trim();
  if (!ecdsaThresholdKeyId) {
    throw new Error('[login] configured-target ECDSA warm key requires ecdsaThresholdKeyId');
  }
  if (args.key && String(args.key.ecdsaThresholdKeyId) !== ecdsaThresholdKeyId) {
    throw new Error('[login] configured-target ECDSA warm key does not match shared key identity');
  }
  return {
    chainTarget: args.chainTarget,
    targetKey: thresholdEcdsaChainTargetKey(args.chainTarget),
    ecdsaThresholdKeyId,
    ...(args.key ? { key: args.key } : {}),
  };
}

function collectConfiguredTargetThresholdEcdsaWarmKeys(args: {
  keys: readonly ConfiguredTargetThresholdEcdsaWarmKey[];
  source: string;
}): ConfiguredTargetThresholdEcdsaWarmKey[] {
  const byTarget = new Map<string, ConfiguredTargetThresholdEcdsaWarmKey>();
  for (const key of args.keys) {
    const targetKey = thresholdEcdsaChainTargetKey(key.chainTarget);
    const ecdsaThresholdKeyId = String(key.ecdsaThresholdKeyId || '').trim();
    if (!ecdsaThresholdKeyId) continue;
    const existing = byTarget.get(targetKey);
    if (existing && existing.ecdsaThresholdKeyId !== ecdsaThresholdKeyId) {
      throw new Error(
        `[login] threshold ECDSA warm-up received ambiguous ${args.source} key identities for ${targetKey}`,
      );
    }
    if (
      existing?.key &&
      key.key &&
      deriveEvmFamilyKeyFingerprint(existing.key) !== deriveEvmFamilyKeyFingerprint(key.key)
    ) {
      throw new Error(
        `[login] threshold ECDSA warm-up received ambiguous ${args.source} key fingerprints for ${targetKey}`,
      );
    }
    byTarget.set(targetKey, {
      chainTarget: key.chainTarget,
      targetKey,
      ecdsaThresholdKeyId,
      ...(key.key || existing?.key ? { key: key.key || existing?.key } : {}),
    });
  }
  return [...byTarget.values()];
}

function mergeCanonicalThresholdEcdsaWarmSessionContexts(
  stored: CanonicalThresholdEcdsaWarmSessionContext,
  relay: CanonicalThresholdEcdsaWarmSessionContext | null,
): CanonicalThresholdEcdsaWarmSessionContext {
  const ecdsaKeyIds = collectConfiguredTargetThresholdEcdsaWarmKeys({
    source: 'stored/relay',
    keys: [...stored.ecdsaKeyIds, ...(relay?.ecdsaKeyIds || [])],
  });
  return {
    ecdsaKeyIds,
    ...(relay?.runtimePolicyScope
      ? { runtimePolicyScope: relay.runtimePolicyScope }
      : stored.runtimePolicyScope
        ? { runtimePolicyScope: stored.runtimePolicyScope }
        : {}),
  };
}

type ThresholdEcdsaKeyIdentityTargetRequest = {
  ecdsaThresholdKeyId: string;
  chainTarget: ThresholdEcdsaChainTarget;
};

function thresholdEcdsaKeyIdentityTargetRequestsFromContext(args: {
  context: CanonicalThresholdEcdsaWarmSessionContext;
  configuredTargets: readonly ConfiguredThresholdEcdsaPublicationTarget[];
}): ThresholdEcdsaKeyIdentityTargetRequest[] {
  const configuredByTarget = new Map(
    args.configuredTargets.map((target) => [
      thresholdEcdsaChainTargetKey(target.chainTarget),
      target.chainTarget,
    ]),
  );
  const seen = new Set<string>();
  const keyTargets: ThresholdEcdsaKeyIdentityTargetRequest[] = [];
  for (const key of args.context.ecdsaKeyIds) {
    const chainTarget = configuredByTarget.get(key.targetKey);
    if (!chainTarget) continue;
    const ecdsaThresholdKeyId = key.ecdsaThresholdKeyId.trim();
    if (!ecdsaThresholdKeyId) continue;
    const requestKey = `${key.targetKey}::${ecdsaThresholdKeyId}`;
    if (seen.has(requestKey)) continue;
    seen.add(requestKey);
    keyTargets.push({ ecdsaThresholdKeyId, chainTarget });
  }
  return keyTargets;
}

async function fetchThresholdEd25519EcdsaKeyIdentityTargets(args: {
  relayerUrl: string;
  thresholdSessionAuthToken: string;
  keyTargets: readonly ThresholdEcdsaKeyIdentityTargetRequest[];
}): Promise<{ records: unknown[]; diagnostics: unknown; httpStatus: number }> {
  const relayerUrl = String(args.relayerUrl || '').trim();
  const thresholdSessionAuthToken = String(args.thresholdSessionAuthToken || '').trim();
  if (!relayerUrl || !thresholdSessionAuthToken) {
    return { records: [], diagnostics: null, httpStatus: 0 };
  }
  const response = await fetch(joinNormalizedUrl(relayerUrl, '/threshold-ecdsa/key-identities'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${thresholdSessionAuthToken}`,
    },
    body: JSON.stringify({ keyTargets: args.keyTargets }),
  });
  const dataUnknown: unknown = await response.json().catch(() => ({}));
  const data = isObject(dataUnknown) ? dataUnknown : {};
  if (!response.ok || data.ok === false) {
    throw new Error(
      String(
        data.message ||
          data.code ||
          `threshold ECDSA key identity inventory failed (HTTP ${response.status})`,
      ),
    );
  }
  return {
    records: Array.isArray(data.ecdsaKeyIdentityTargets) ? data.ecdsaKeyIdentityTargets : [],
    diagnostics: Object.prototype.hasOwnProperty.call(data, 'diagnostics')
      ? data.diagnostics
      : null,
    httpStatus: response.status,
  };
}

function parseThresholdEcdsaKeyIdentityTargets(args: {
  nearAccountId: AccountId;
  rpId: string;
  records: readonly unknown[];
}): ThresholdEcdsaKeyIdentityInventoryEntry[] {
  const entries: ThresholdEcdsaKeyIdentityInventoryEntry[] = [];
  for (const raw of args.records) {
    if (!isObject(raw) || !isObject(raw.key)) continue;
    let chainTarget: ThresholdEcdsaChainTarget;
    try {
      if (!isObject(raw.chainTarget)) continue;
      chainTarget = thresholdEcdsaChainTargetFromRequest(raw.chainTarget);
    } catch {
      continue;
    }
    const ecdsaThresholdKeyId = String(raw.ecdsaThresholdKeyId || '').trim();
    const keyWalletId = String(raw.key.walletId || '').trim();
    const keySubjectId = String(raw.key.subjectId || '').trim();
    const keyRpId = String(raw.key.rpId || '').trim();
    const ownerAddress = normalizeEvmOwnerAddress(raw.ownerAddress);
    const accountAddress = normalizeEvmOwnerAddress(raw.accountAddress);
    const thresholdOwnerAddress = normalizeEvmOwnerAddress(raw.key.thresholdOwnerAddress);
    if (
      !ecdsaThresholdKeyId ||
      !ownerAddress ||
      !accountAddress ||
      !thresholdOwnerAddress ||
      keyWalletId !== String(args.nearAccountId) ||
      keySubjectId !== String(walletSubjectIdFromWalletProfile({ walletId: args.nearAccountId })) ||
      keyRpId !== args.rpId ||
      thresholdOwnerAddress !== ownerAddress
    ) {
      continue;
    }
    let key: EvmFamilyEcdsaKeyIdentity;
    try {
      key = buildEvmFamilyEcdsaKeyIdentity({
        walletId: args.nearAccountId,
        subjectId: walletSubjectIdFromWalletProfile({ walletId: args.nearAccountId }),
        rpId: args.rpId,
        ecdsaThresholdKeyId,
        signingRootId: String(raw.key.signingRootId || '').trim(),
        signingRootVersion: String(raw.key.signingRootVersion || 'default').trim(),
        participantIds: raw.key.participantIds,
        thresholdOwnerAddress,
      });
    } catch {
      continue;
    }
    entries.push({
      ecdsaThresholdKeyId,
      chainTarget,
      accountAddress,
      ownerAddress,
      key,
    });
  }
  return entries;
}

async function resolveThresholdEcdsaKeyIdentityInventoryFromRestoredEd25519(args: {
  relayerUrl: string;
  nearAccountId: AccountId;
  rpId: string;
  keyTargets: readonly ThresholdEcdsaKeyIdentityTargetRequest[];
}): Promise<ThresholdEcdsaKeyIdentityInventoryEntry[]> {
  const record = getStoredThresholdEd25519SessionRecordForAccount(args.nearAccountId);
  const thresholdSessionAuthToken = String(record?.thresholdSessionAuthToken || '').trim();
  if (!thresholdSessionAuthToken || !args.keyTargets.length) return [];
  return await resolveThresholdEcdsaKeyIdentityInventoryFromThresholdEd25519Auth({
    relayerUrl: args.relayerUrl,
    nearAccountId: args.nearAccountId,
    rpId: args.rpId,
    thresholdSessionAuthToken,
    keyTargets: args.keyTargets,
    source: 'restored_ed25519',
  });
}

async function resolveThresholdEcdsaKeyIdentityInventoryFromThresholdEd25519Auth(args: {
  relayerUrl: string;
  nearAccountId: AccountId;
  rpId: string;
  thresholdSessionAuthToken: string;
  keyTargets: readonly ThresholdEcdsaKeyIdentityTargetRequest[];
  source: 'restored_ed25519' | 'fresh_ed25519';
}): Promise<ThresholdEcdsaKeyIdentityInventoryEntry[]> {
  try {
    if (!args.keyTargets.length) return [];
    const inventory = await fetchThresholdEd25519EcdsaKeyIdentityTargets({
      relayerUrl: args.relayerUrl,
      thresholdSessionAuthToken: args.thresholdSessionAuthToken,
      keyTargets: args.keyTargets,
    });
    console.info('[login][ecdsa-warmup-diagnostic] Ed25519 ECDSA key inventory response', {
      nearAccountId: args.nearAccountId,
      source: args.source,
      requestedTargets: args.keyTargets.map((target) =>
        thresholdEcdsaChainTargetKey(target.chainTarget),
      ),
      httpStatus: inventory.httpStatus,
      rawRecordCount: inventory.records.length,
      serverDiagnostics: inventory.diagnostics,
    });
    const records = inventory.records;
    if (!records.length) {
      console.info('[login][ecdsa-warmup-diagnostic] Ed25519 ECDSA key inventory empty', {
        nearAccountId: args.nearAccountId,
        source: args.source,
        requestedTargets: args.keyTargets.map((target) =>
          thresholdEcdsaChainTargetKey(target.chainTarget),
        ),
        serverDiagnostics: inventory.diagnostics,
      });
      return [];
    }
    const keyIdentityInventory = parseThresholdEcdsaKeyIdentityTargets({
      nearAccountId: args.nearAccountId,
      rpId: args.rpId,
      records,
    });
    console.info('[login][ecdsa-warmup-diagnostic] Ed25519 ECDSA key inventory loaded', {
      nearAccountId: args.nearAccountId,
      source: args.source,
      rawRecordCount: records.length,
      acceptedEntryCount: keyIdentityInventory.length,
      requestedTargets: args.keyTargets.map((target) =>
        thresholdEcdsaChainTargetKey(target.chainTarget),
      ),
      acceptedTargetKeys: keyIdentityInventory.map((entry) =>
        thresholdEcdsaChainTargetKey(entry.chainTarget),
      ),
      canonicalKeyCount: keyIdentityInventory.length,
      serverDiagnostics: inventory.diagnostics,
    });
    return keyIdentityInventory;
  } catch (error: unknown) {
    console.warn('[login][ecdsa-warmup-diagnostic] Ed25519 ECDSA key inventory failed', {
      nearAccountId: args.nearAccountId,
      source: args.source,
      error: error instanceof Error ? error.message : String(error || 'unknown error'),
    });
    return [];
  }
}

function buildSharedKeyTargetCompletion(args: {
  context: CanonicalThresholdEcdsaWarmSessionContext;
  configuredTargets: readonly ConfiguredThresholdEcdsaPublicationTarget[];
}): SharedKeyTargetCompletion {
  if (!args.configuredTargets.length) {
    return { kind: 'complete_shared_key_targets', context: args.context };
  }

  const byTarget = new Map<string, ConfiguredTargetThresholdEcdsaWarmKey>();
  for (const key of args.context.ecdsaKeyIds) {
    byTarget.set(key.targetKey, key);
  }
  const missingTargetKeys = args.configuredTargets
    .map((target) => thresholdEcdsaChainTargetKey(target.chainTarget))
    .filter((targetKey) => !byTarget.has(targetKey));
  const keyIds = [
    ...new Set(
      [...byTarget.values()]
        .map((key) => String(key.ecdsaThresholdKeyId || '').trim())
        .filter(Boolean),
    ),
  ];
  if (keyIds.length > 1) {
    return {
      kind: 'ambiguous_shared_key_targets',
      ecdsaThresholdKeyIds: keyIds,
    };
  }
  const keyFingerprints = [
    ...new Set(
      [...byTarget.values()]
        .map((key) => (key.key ? deriveEvmFamilyKeyFingerprint(key.key) : ''))
        .filter(Boolean),
    ),
  ];
  if (keyFingerprints.length > 1) {
    return {
      kind: 'ambiguous_shared_key_targets',
      ecdsaThresholdKeyIds: keyIds,
    };
  }

  const sharedKey = [...byTarget.values()].find((key) => key.key)?.key;
  if (!sharedKey) {
    return {
      kind: 'missing_shared_key',
      missingTargets: missingTargetKeys.length
        ? missingTargetKeys
        : args.configuredTargets.map((target) => thresholdEcdsaChainTargetKey(target.chainTarget)),
    };
  }
  const ecdsaThresholdKeyId = String(sharedKey.ecdsaThresholdKeyId);
  const expectedKeyId = keyIds[0];
  if (expectedKeyId && expectedKeyId !== ecdsaThresholdKeyId) {
    return {
      kind: 'ambiguous_shared_key_targets',
      ecdsaThresholdKeyIds: [expectedKeyId, ecdsaThresholdKeyId],
    };
  }

  for (const target of args.configuredTargets) {
    const targetKey = thresholdEcdsaChainTargetKey(target.chainTarget);
    const existing = byTarget.get(targetKey);
    byTarget.set(
      targetKey,
      configuredTargetThresholdEcdsaWarmKey({
        chainTarget: target.chainTarget,
        ecdsaThresholdKeyId,
        key: existing?.key || sharedKey,
      }),
    );
  }

  const context: CanonicalThresholdEcdsaWarmSessionContext = {
    ecdsaKeyIds: collectConfiguredTargetThresholdEcdsaWarmKeys({
      source: 'configured EVM-family shared-key target completion',
      keys: [...byTarget.values()],
    }),
    ...(args.context.runtimePolicyScope
      ? { runtimePolicyScope: args.context.runtimePolicyScope }
      : {}),
  };
  const remainingMissingTargets = args.configuredTargets.filter(
    (target) =>
      !context.ecdsaKeyIds.some(
        (key) => key.targetKey === thresholdEcdsaChainTargetKey(target.chainTarget),
      ),
  );
  if (remainingMissingTargets.length) {
    return {
      kind: 'missing_shared_key',
      missingTargets: remainingMissingTargets.map((target) =>
        thresholdEcdsaChainTargetKey(target.chainTarget),
      ),
    };
  }
  return { kind: 'complete_shared_key_targets', context };
}

function requireCompleteSharedKeyTargetContext(args: {
  completion: SharedKeyTargetCompletion;
  source: string;
}): CanonicalThresholdEcdsaWarmSessionContext {
  switch (args.completion.kind) {
    case 'complete_shared_key_targets':
      return args.completion.context;
    case 'ambiguous_shared_key_targets':
      throw new Error(
        `[login] threshold ECDSA warm-up received ambiguous shared key identities from ${args.source}: ${args.completion.ecdsaThresholdKeyIds.join(
          ', ',
        )}`,
      );
    case 'missing_shared_key':
      throw new Error(
        `[login] threshold ECDSA warm-up could not resolve canonical shared key identity from ${args.source} for ${args.completion.missingTargets.join(
          ', ',
        )}`,
      );
  }
  args.completion satisfies never;
  throw new Error('[login] unsupported ECDSA warm-up key completion state');
}

function resolveThresholdEcdsaKeyInventoryWarmSessionContext(args: {
  keyIdentityInventory: readonly ThresholdEcdsaKeyIdentityInventoryEntry[];
  configuredTargets: readonly ConfiguredThresholdEcdsaPublicationTarget[];
}): CanonicalThresholdEcdsaWarmSessionContext | null {
  const configuredTargets = args.configuredTargets.map((target) => target.chainTarget);
  if (!configuredTargets.length || !args.keyIdentityInventory.length) return null;

  const matchingEntries = args.keyIdentityInventory.filter((entry) =>
    configuredTargets.some((target) => thresholdEcdsaChainTargetsEqual(entry.chainTarget, target)),
  );
  if (!matchingEntries.length) return null;

  const keys: ConfiguredTargetThresholdEcdsaWarmKey[] = [];
  for (const entry of matchingEntries) {
    const ecdsaThresholdKeyId = entry.ecdsaThresholdKeyId.trim();
    if (!ecdsaThresholdKeyId) continue;
    keys.push(
      configuredTargetThresholdEcdsaWarmKey({
        chainTarget: entry.chainTarget,
        ecdsaThresholdKeyId,
        key: entry.key,
      }),
    );
  }
  const ecdsaKeyIds = collectConfiguredTargetThresholdEcdsaWarmKeys({
    source: 'normal ECDSA key identity inventory',
    keys,
  });
  if (!ecdsaKeyIds.length) return null;

  return {
    ecdsaKeyIds,
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
  jwt: string;
  ecdsaHssClientRootShare32B64u: string;
};

type ThresholdLoginWarmEcdsaBootstrapIdentity = {
  routeAuth: ThresholdEcdsaHssRouteAuth;
};

type RestoredPasskeyEcdsaWarmTarget = {
  target: ConfiguredThresholdEcdsaPublicationTarget;
  targetKey: string;
  ecdsaKey: ConfiguredTargetThresholdEcdsaWarmKey & { key: EvmFamilyEcdsaKeyIdentity };
};

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
  if (normalized.includes('ecdsa') && !normalized.includes('ed25519')) {
    throw new Error('[login] threshold ECDSA warm-up requires Ed25519 session priming');
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

function isReadyRestoredPasskeyEcdsaLane(args: {
  snapshot: AvailableSigningLanes | null;
  chainTarget: ThresholdEcdsaChainTarget;
}): boolean {
  if (!args.snapshot) return false;
  const lane = ecdsaAvailableLaneForTarget(args.snapshot, args.chainTarget);
  return (
    isConcreteAvailableSigningLane(lane) &&
    lane.authMethod === 'passkey' &&
    lane.state === 'ready' &&
    Number(lane.remainingUses) > 0
  );
}

function resolveRestoredPasskeyEcdsaWarmTargets(args: {
  snapshot: AvailableSigningLanes | null;
  configuredEcdsaTargets: readonly ConfiguredThresholdEcdsaPublicationTarget[];
  canonicalEcdsaContext: CanonicalThresholdEcdsaWarmSessionContext;
}): RestoredPasskeyEcdsaWarmTarget[] {
  const targets: RestoredPasskeyEcdsaWarmTarget[] = [];
  for (const target of args.configuredEcdsaTargets) {
    if (
      isReadyRestoredPasskeyEcdsaLane({
        snapshot: args.snapshot,
        chainTarget: target.chainTarget,
      })
    ) {
      continue;
    }
    const targetKey = thresholdEcdsaChainTargetKey(target.chainTarget);
    const ecdsaKey = args.canonicalEcdsaContext.ecdsaKeyIds.find(
      (key) => key.targetKey === targetKey,
    );
    if (!ecdsaKey?.key) {
      throw new Error(
        `[login] restored ECDSA warm-up requires shared key identity for ${targetKey}`,
      );
    }
    targets.push({
      target,
      targetKey,
      ecdsaKey: {
        chainTarget: ecdsaKey.chainTarget,
        targetKey: ecdsaKey.targetKey,
        ecdsaThresholdKeyId: ecdsaKey.ecdsaThresholdKeyId,
        key: ecdsaKey.key,
      },
    });
  }
  return targets;
}

function resolveRestoredPasskeyEd25519SessionKind(nearAccountId: AccountId): 'jwt' | 'cookie' {
  const record = getStoredThresholdEd25519SessionRecordForAccount(nearAccountId);
  if (!record) {
    throw new Error('[login] restored Ed25519 session record is required for ECDSA warm-up');
  }
  if (record.source === 'email_otp' || record.emailOtpAuthContext) {
    throw new Error('[login] restored passkey Ed25519 session is required for ECDSA warm-up');
  }
  return record.thresholdSessionKind;
}

async function bootstrapRestoredPasskeyEcdsaWarmTargets(args: {
  signingEngine: PasskeyManagerContext['signingEngine'];
  nearAccountId: AccountId;
  relayerUrl: string;
  ttlMs: number;
  remainingUses: number;
  canonicalEcdsaContext: CanonicalThresholdEcdsaWarmSessionContext;
  managedRuntimeScopeBootstrap?: ManagedThresholdRuntimeScopeBootstrap;
  targets: readonly RestoredPasskeyEcdsaWarmTarget[];
}): Promise<void> {
  if (!args.targets.length) return;
  const subjectId = walletSubjectIdFromWalletProfile({ walletId: args.nearAccountId });
  const thresholdSessionKind = resolveRestoredPasskeyEd25519SessionKind(args.nearAccountId);
  for (const target of args.targets) {
    const thresholdSessionId = createThresholdLoginWarmSessionId('threshold-ecdsa-login');
    const walletSigningSessionId = generateWalletSigningSessionId();
    const lanePolicy = buildEvmFamilyEcdsaSessionLanePolicy({
      chainTarget: target.target.chainTarget,
      thresholdSessionId,
      walletSigningSessionId,
      thresholdSessionKind,
      ttlMs: args.ttlMs,
      remainingUses: args.remainingUses,
      ...(args.canonicalEcdsaContext.runtimePolicyScope
        ? { runtimePolicyScope: args.canonicalEcdsaContext.runtimePolicyScope }
        : {}),
    });
    await args.signingEngine.bootstrapLoginEcdsaSessionFromRestoredEd25519({
      walletId: args.nearAccountId,
      subjectId,
      chainTarget: target.target.chainTarget,
      relayerUrl: args.relayerUrl,
      key: target.ecdsaKey.key,
      lanePolicy,
      ttlMs: args.ttlMs,
      remainingUses: args.remainingUses,
      ...(args.canonicalEcdsaContext.runtimePolicyScope
        ? { runtimePolicyScope: args.canonicalEcdsaContext.runtimePolicyScope }
        : {}),
      ...(args.managedRuntimeScopeBootstrap
        ? { runtimeScopeBootstrap: args.managedRuntimeScopeBootstrap }
        : {}),
    });
  }
}

function resolveThresholdLoginWarmEcdsaBootstrapIdentity(args: {
  ed25519State: ThresholdLoginWarmEd25519State;
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
  throw new Error('[login] threshold ECDSA warm-up requires route authorization');
}

function thresholdLoginWarmupErrorMessage(error: unknown): string {
  return String(
    (error && typeof error === 'object' && 'message' in error
      ? (error as { message?: unknown }).message
      : error) || '',
  );
}

async function primeThresholdLoginWarmSigners(args: {
  context: PasskeyManagerContext;
  signingEngine: PasskeyManagerContext['signingEngine'];
  nearAccountId: AccountId;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds: number[];
  ttlMs: number;
  remainingUses: number;
  ecdsaContextResolution: ThresholdLoginWarmEcdsaContextResolution;
  credential?: WebAuthnAuthenticationCredential;
  managedRuntimeScopeBootstrap?: ManagedThresholdRuntimeScopeBootstrap;
  signersToWarm?: ThresholdLoginWarmSigner[];
  preferredEd25519SessionId?: string;
  appSessionJwt?: string;
  useAppSessionCookie?: boolean;
}): Promise<void> {
  const signersToWarm = buildThresholdLoginWarmSignerSelection(args.signersToWarm);
  const initialCanonicalEcdsaContext =
    args.ecdsaContextResolution.kind === 'pre_resolved'
      ? args.ecdsaContextResolution.context
      : args.ecdsaContextResolution.initialContext;
  let activeCanonicalEcdsaContext = initialCanonicalEcdsaContext;
  const warmState: ThresholdLoginWarmEd25519State = {
    sessionId: '',
    jwt: '',
    ecdsaHssClientRootShare32B64u: '',
  };

  const tasks: ThresholdLoginWarmupTask[] = [];
  if (signersToWarm.includes('ed25519')) {
    tasks.push({
      signer: 'ed25519',
      dependencies: [],
      run: async () => {
        const connected = await args.signingEngine.connectEd25519Session({
          kind: 'fresh_ed25519_provisioning',
          nearAccountId: args.nearAccountId,
          relayerUrl: args.relayerUrl,
          relayerKeyId: args.relayerKeyId,
          source: 'login',
          ...(args.appSessionJwt ? { appSessionJwt: args.appSessionJwt } : {}),
          ...(args.useAppSessionCookie ? { useAppSessionCookie: args.useAppSessionCookie } : {}),
          ...(args.credential ? { localPrfCredential: args.credential } : {}),
          ...(initialCanonicalEcdsaContext.runtimePolicyScope
            ? { runtimePolicyScope: initialCanonicalEcdsaContext.runtimePolicyScope }
            : {}),
          ...(args.managedRuntimeScopeBootstrap
            ? { runtimeScopeBootstrap: args.managedRuntimeScopeBootstrap }
            : {}),
          participantIds: args.participantIds,
          sessionKind: args.useAppSessionCookie ? 'cookie' : 'jwt',
          ttlMs: args.ttlMs,
          remainingUses: args.remainingUses,
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

        const connectedEcdsaHssClientRootShare32B64u = String(
          connected.ecdsaHssClientRootShare32B64u || '',
        ).trim();
        if (!connectedEcdsaHssClientRootShare32B64u) {
          throw new Error(
            '[login] threshold ECDSA warm-up missing clientRootShare32B64u from the primed Ed25519 session',
          );
        }

        warmState.sessionId = connectedSessionId;
        warmState.jwt = connectedJwt;
        warmState.ecdsaHssClientRootShare32B64u = connectedEcdsaHssClientRootShare32B64u;
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
      dependencies: ['ed25519'],
      run: async () => {
        let bootstrapIdentity: ThresholdLoginWarmEcdsaBootstrapIdentity | null = null;
        const subjectId = walletSubjectIdFromWalletProfile({ walletId: args.nearAccountId });
        const configuredEcdsaTargets = listConfiguredThresholdEcdsaPublicationTargets(
          args.context.configs.network.chains,
        );
        const bootstrapTarget = async (
          target: (typeof configuredEcdsaTargets)[number],
          targetEcdsaKey: ConfiguredTargetThresholdEcdsaWarmKey,
        ) => {
          if (!bootstrapIdentity) {
            throw new Error('[login] threshold ECDSA warm-up requires bootstrap identity');
          }
          if (!targetEcdsaKey.key) {
            throw new Error('[login] threshold ECDSA warm-up requires shared key identity');
          }
          const thresholdSessionId = createThresholdLoginWarmSessionId('threshold-ecdsa-login');
          const walletSigningSessionId = generateWalletSigningSessionId();
          const lanePolicy = buildEvmFamilyEcdsaSessionLanePolicy({
            chainTarget: target.chainTarget,
            thresholdSessionId,
            walletSigningSessionId,
            thresholdSessionKind: args.useAppSessionCookie ? 'cookie' : 'jwt',
            ttlMs: args.ttlMs,
            remainingUses: args.remainingUses,
            ...(activeCanonicalEcdsaContext.runtimePolicyScope
              ? { runtimePolicyScope: activeCanonicalEcdsaContext.runtimePolicyScope }
              : {}),
          });
          return await args.signingEngine.bootstrapEcdsaSession({
            kind: 'threshold_session_auth_reconnect_ecdsa_bootstrap',
            source: 'login',
            relayerUrl: args.relayerUrl,
            key: targetEcdsaKey.key,
            lanePolicy,
            clientRootShare32B64u: warmState.ecdsaHssClientRootShare32B64u,
            routeAuth: bootstrapIdentity.routeAuth,
            ...(args.managedRuntimeScopeBootstrap
              ? { runtimeScopeBootstrap: args.managedRuntimeScopeBootstrap }
              : {}),
          });
        };
        const bootstrapConfiguredTargets = async () => {
          for (const target of configuredEcdsaTargets) {
            const targetKey = thresholdEcdsaChainTargetKey(target.chainTarget);
            const targetEcdsaKey = activeCanonicalEcdsaContext.ecdsaKeyIds.find(
              (key) => key.targetKey === targetKey,
            );
            const ecdsaThresholdKeyId = String(targetEcdsaKey?.ecdsaThresholdKeyId || '').trim();
            if (!targetEcdsaKey || !ecdsaThresholdKeyId) {
              throw new Error(
                `[login] threshold ECDSA warm-up requires ecdsaThresholdKeyId for ${targetKey}`,
              );
            }
            console.info('[login] threshold ECDSA warm-up target selected', {
              nearAccountId: args.nearAccountId,
              targetKey,
              chainTarget: target.chainTarget,
              ecdsaThresholdKeyId,
            });
            const bootstrap = await bootstrapTarget(target, targetEcdsaKey);
            const returnedEcdsaThresholdKeyId = String(
              bootstrap.thresholdEcdsaKeyRef?.ecdsaThresholdKeyId || '',
            ).trim();
            if (returnedEcdsaThresholdKeyId !== ecdsaThresholdKeyId) {
              throw new Error(
                `[login] threshold ECDSA warm-up returned a different ecdsaThresholdKeyId for ${targetKey}`,
              );
            }
            console.info('[login] threshold ECDSA warm-up target provisioned', {
              nearAccountId: args.nearAccountId,
              targetKey,
              chainTarget: target.chainTarget,
              ecdsaThresholdKeyId,
              thresholdSessionId:
                bootstrap.thresholdEcdsaKeyRef?.thresholdSessionId ||
                bootstrap.session?.sessionId ||
                null,
              walletSigningSessionId:
                bootstrap.thresholdEcdsaKeyRef?.walletSigningSessionId ||
                bootstrap.session?.walletSigningSessionId ||
                null,
              remainingUses: bootstrap.session?.remainingUses,
              expiresAtMs: bootstrap.session?.expiresAtMs,
            });
          }
        };
        try {
          bootstrapIdentity = resolveThresholdLoginWarmEcdsaBootstrapIdentity({
            ed25519State: warmState,
            appSessionJwt: args.appSessionJwt,
            useAppSessionCookie: args.useAppSessionCookie,
          });
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
  context: PasskeyManagerContext,
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
  context: PasskeyManagerContext,
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
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
): ThresholdEcdsaSessionRecord[] {
  const signingEngine = context.signingEngine as {
    listThresholdEcdsaSessionRecordsForTarget?: (args: {
      subjectId: WalletSubjectId;
      chainTarget: ReturnType<
        typeof listConfiguredThresholdEcdsaPublicationTargets
      >[number]['chainTarget'];
      source?: ThresholdEcdsaSessionStoreSource;
    }) => ThresholdEcdsaSessionRecord[];
  };
  if (typeof signingEngine.listThresholdEcdsaSessionRecordsForTarget !== 'function') {
    return [];
  }

  const allowedSources = new Set<ThresholdEcdsaSessionStoreSource>(
    THRESHOLD_ECDSA_LOGIN_METADATA_SOURCES,
  );
  const subjectId = walletSubjectIdFromWalletProfile({ walletId: nearAccountId });
  return listConfiguredThresholdEcdsaPublicationTargets(context.configs.network.chains).flatMap(
    (target) =>
      signingEngine
        .listThresholdEcdsaSessionRecordsForTarget?.({
          subjectId,
          chainTarget: target.chainTarget,
        })
        ?.filter((record) => allowedSources.has(record.source)) || [],
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

async function resolveThresholdEcdsaEthereumAddress(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
): Promise<string | null> {
  const runtimeAddress = resolveUniqueThresholdEcdsaRecordAddress({
    nearAccountId,
    records: readThresholdEcdsaLoginMetadataRecords(context, nearAccountId),
  });
  if (runtimeAddress) return runtimeAddress;
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

async function resolveThresholdLoginWarmSigners(args: {
  configuredEcdsaTargets: readonly ConfiguredThresholdEcdsaPublicationTarget[];
  canonicalEcdsaContext?: CanonicalThresholdEcdsaWarmSessionContext | null;
}): Promise<ThresholdLoginWarmSigner[]> {
  if (!args.configuredEcdsaTargets.length) return ['ed25519'];
  const keyIdsByTarget = new Set(
    (args.canonicalEcdsaContext?.ecdsaKeyIds || []).map((key) => key.targetKey),
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
  return ['ed25519', 'ecdsa'];
}

function createThresholdLoginWarmSessionId(prefix: string): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return `${prefix}-${crypto.randomUUID()}`;
  }
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

async function resolveProfileContinuityEcdsaWarmKeys(
  nearAccountId: AccountId,
  configuredTargets: readonly ConfiguredThresholdEcdsaPublicationTarget[],
): Promise<ConfiguredTargetThresholdEcdsaWarmKey[]> {
  const continuity = await resolveNearAccountProfileContinuity(
    IndexedDBManager.clientDB,
    nearAccountId,
  ).catch(() => null);
  const keys: ConfiguredTargetThresholdEcdsaWarmKey[] = [];
  for (const signer of continuity?.accountSigners || []) {
    if (signer.status && signer.status !== 'active') continue;
    if (signer.signerKind && signer.signerKind !== SIGNER_KINDS.thresholdEcdsa) continue;
    if (signer.signerAuthMethod && signer.signerAuthMethod !== SIGNER_AUTH_METHODS.passkey) {
      continue;
    }
    const metadata = signer.metadata || {};
    const keyId = String(metadata.ecdsaThresholdKeyId || '').trim();
    if (!keyId || !isObject(metadata.chainTarget)) continue;
    let chainTarget: ThresholdEcdsaChainTarget;
    try {
      chainTarget = thresholdEcdsaChainTargetFromRequest(metadata.chainTarget);
    } catch {
      continue;
    }
    if (
      !configuredTargets.some((target) =>
        thresholdEcdsaChainTargetsEqual(target.chainTarget, chainTarget),
      )
    ) {
      continue;
    }
    keys.push(
      configuredTargetThresholdEcdsaWarmKey({
        chainTarget,
        ecdsaThresholdKeyId: keyId,
      }),
    );
  }
  return collectConfiguredTargetThresholdEcdsaWarmKeys({
    source: 'profile continuity',
    keys,
  });
}

async function resolveCanonicalThresholdEcdsaWarmSessionContext(
  context: PasskeyManagerContext,
  signingEngine: unknown,
  nearAccountId: AccountId,
): Promise<CanonicalThresholdEcdsaWarmSessionContext> {
  const typedSigningEngine = signingEngine as {
    listThresholdEcdsaSessionRecordsForTarget?: (args: {
      subjectId: WalletSubjectId;
      chainTarget: ReturnType<
        typeof listConfiguredThresholdEcdsaPublicationTargets
      >[number]['chainTarget'];
      source?: ThresholdEcdsaSessionStoreSource;
    }) => ThresholdEcdsaSessionRecord[];
  };
  const allowedSources = new Set<ThresholdEcdsaSessionStoreSource>(
    THRESHOLD_ECDSA_LOGIN_METADATA_SOURCES,
  );
  const configuredTargets = listConfiguredThresholdEcdsaPublicationTargets(
    context.configs.network.chains,
  );
  const rpId = String(context.signingEngine.getRpId() || '').trim();
  if (!rpId) {
    throw new Error('[login] threshold ECDSA warm-up requires rpId');
  }
  const storedKeys: ConfiguredTargetThresholdEcdsaWarmKey[] = [];
  let runtimePolicyScope: ThresholdRuntimePolicyScope | undefined;
  if (typeof typedSigningEngine.listThresholdEcdsaSessionRecordsForTarget === 'function') {
    const subjectId = walletSubjectIdFromWalletProfile({ walletId: nearAccountId });
    for (const target of configuredTargets) {
      for (const record of typedSigningEngine.listThresholdEcdsaSessionRecordsForTarget({
        subjectId,
        chainTarget: target.chainTarget,
      })) {
        if (!allowedSources.has(record.source)) continue;
        const ecdsaThresholdKeyId = String(record.ecdsaThresholdKeyId || '').trim();
        if (ecdsaThresholdKeyId) {
          let key: EvmFamilyEcdsaKeyIdentity;
          try {
            key = buildEvmFamilyEcdsaKeyIdentityFromRecord({ record, rpId });
          } catch {
            continue;
          }
          storedKeys.push(
            configuredTargetThresholdEcdsaWarmKey({
              chainTarget: target.chainTarget,
              ecdsaThresholdKeyId,
              key,
            }),
          );
        }
        if (!runtimePolicyScope && record.runtimePolicyScope) {
          runtimePolicyScope = record.runtimePolicyScope;
        }
      }
    }
  }
  const exactStoredKeys = collectConfiguredTargetThresholdEcdsaWarmKeys({
    source: 'stored',
    keys: storedKeys,
  });
  if (exactStoredKeys.length) {
    return {
      ecdsaKeyIds: exactStoredKeys,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    };
  }
  const snapshot = await readAvailableSigningLanesForUi(context, nearAccountId).catch(() => null);
  const availableLaneKeys: ConfiguredTargetThresholdEcdsaWarmKey[] = [];
  if (snapshot) {
    for (const target of ecdsaAvailableLaneTargets(snapshot)) {
      const lane = ecdsaAvailableLaneForTarget(snapshot, target);
      if (!isConcreteAvailableSigningLane(lane)) continue;
      const ecdsaThresholdKeyId = String(lane.key.ecdsaThresholdKeyId || '').trim();
      if (!ecdsaThresholdKeyId) continue;
      availableLaneKeys.push(
        configuredTargetThresholdEcdsaWarmKey({
          chainTarget: target,
          ecdsaThresholdKeyId,
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
      ecdsaKeyIds: exactAvailableLaneKeys,
    };
  }
  const profileEcdsaThresholdKeys = await resolveProfileContinuityEcdsaWarmKeys(
    nearAccountId,
    configuredTargets,
  );
  if (profileEcdsaThresholdKeys.length) {
    return {
      ecdsaKeyIds: profileEcdsaThresholdKeys,
    };
  }
  return {
    ecdsaKeyIds: [],
  };
}

function resolveManagedThresholdRuntimeScopeBootstrap(
  context: PasskeyManagerContext,
): ManagedThresholdRuntimeScopeBootstrap | undefined {
  const registration = context.configs?.registration;
  if (!registration || registration.mode !== 'managed') return undefined;
  const environmentId = String(registration.environmentId || '').trim();
  const publishableKey = String(registration.publishableKey || '').trim();
  if (!environmentId || !publishableKey) return undefined;
  return { environmentId, publishableKey };
}

function resolveThresholdEcdsaPublicKeyB64u(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
): string | null {
  for (const record of readThresholdEcdsaLoginMetadataRecords(context, nearAccountId)) {
    const thresholdEcdsaPublicKeyB64u = String(record.thresholdEcdsaPublicKeyB64u || '').trim();
    if (thresholdEcdsaPublicKeyB64u) return thresholdEcdsaPublicKeyB64u;
  }
  return null;
}

async function resolveThresholdEcdsaLoginMetadata(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
): Promise<{
  ethereumAddress: string | null;
  thresholdEcdsaPublicKeyB64u: string | null;
}> {
  const [ethereumAddress, thresholdEcdsaPublicKeyB64u] = await Promise.all([
    resolveThresholdEcdsaEthereumAddress(context, nearAccountId),
    Promise.resolve(resolveThresholdEcdsaPublicKeyB64u(context, nearAccountId)),
  ]);
  return {
    ethereumAddress,
    thresholdEcdsaPublicKeyB64u,
  };
}

function isThresholdSignerMode(context: PasskeyManagerContext): boolean {
  const signingConfig = context.configs?.signing as { mode?: { mode?: unknown } } | undefined;
  return String(signingConfig?.mode?.mode || '').trim() === 'threshold-signer';
}

async function resolveWarmSigningSessionStatusForUi(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
  hints?: {
    ed25519?: SigningSessionStatus | null;
  },
): Promise<SigningSessionStatus | null> {
  const signingEngine = context.signingEngine as typeof context.signingEngine & {
    listWarmThresholdEcdsaSessionStatuses?: (
      nearAccountId: AccountId | string,
      chainTarget: ReturnType<
        typeof listConfiguredThresholdEcdsaPublicationTargets
      >[number]['chainTarget'],
    ) => Promise<SigningSessionStatus[]>;
  };

  const ed25519 =
    hints && 'ed25519' in hints
      ? hints.ed25519 || null
      : await signingEngine.getWarmThresholdEd25519SessionStatus(nearAccountId).catch(() => null);
  const ecdsaStatuses =
    typeof signingEngine.listWarmThresholdEcdsaSessionStatuses === 'function'
      ? (
          await Promise.all(
            listConfiguredThresholdEcdsaPublicationTargets(context.configs.network.chains).map(
              (target) =>
                signingEngine
                  .listWarmThresholdEcdsaSessionStatuses(nearAccountId, target.chainTarget)
                  .catch(() => []),
            ),
          )
        ).flat()
      : [];

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
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
): Promise<AvailableSigningLanes | null> {
  const signingEngine = context.signingEngine as typeof context.signingEngine & {
    readPersistedAvailableSigningLanes?: typeof context.signingEngine.readPersistedAvailableSigningLanes;
  };
  if (typeof signingEngine.readPersistedAvailableSigningLanes !== 'function') {
    return null;
  }
  return await signingEngine.readPersistedAvailableSigningLanes({
    walletId: nearAccountId,
    subjectId: walletSubjectIdFromWalletProfile({ walletId: nearAccountId }),
  });
}

async function resolveSnapshotSigningSessionStatusForUi(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
): Promise<SigningSessionStatus | null> {
  return snapshotToSigningSessionStatusForUi(
    await readAvailableSigningLanesForUi(context, nearAccountId),
  );
}

async function resolveSigningSessionStatusForUi(
  context: PasskeyManagerContext,
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
  context: PasskeyManagerContext,
  nearAccountId?: AccountId,
): Promise<LoginState> {
  const { signingEngine } = context;
  try {
    const lastUser = await signingEngine.getLastUser().catch(() => null);
    const lastSelectedAccount =
      nearAccountId || lastUser?.nearAccountId
        ? null
        : await getLastSelectedNearAccount(IndexedDBManager.clientDB).catch(() => null);
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
        : await getNearAccountProjection(IndexedDBManager.clientDB, targetAccountId).catch(
            () => null,
          );
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
  context: PasskeyManagerContext,
): Promise<GetRecentUnlocksResult> {
  const { signingEngine } = context;
  const allUsersData = await signingEngine.getAllUsers();
  const accountIds = [...new Set(allUsersData.map((user) => user.nearAccountId))];
  const lastUsedAccount = await signingEngine.getLastUser();
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
export async function lock(context: PasskeyManagerContext): Promise<void> {
  const { signingEngine } = context;
  await IndexedDBManager.clientDB.clearLastProfileSelection().catch(() => undefined);
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
    await signingEngine.clearWarmSigningSessions();
  } catch {}
  try {
    clearAllStoredThresholdEd25519SessionRecords();
  } catch {}
}
