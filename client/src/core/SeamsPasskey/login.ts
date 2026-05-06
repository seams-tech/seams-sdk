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
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import { IndexedDBManager } from '../indexedDB';
import {
  getLastSelectedNearAccount,
  getNearAccountProjection,
  resolveNearAccountProfileContinuity,
} from '../accountData/near/accountProjection';
import { getNearThresholdKeyMaterial } from '../accountData/near/keyMaterial';
import type { ClientUserData } from '../accountData/near/types';
import { exchangeSession, type SessionExchangeInput } from '../rpcClients/near/rpcCalls';
import { parseSignerSlot } from '../signingEngine/signers/webauthn/device/signerSlot';
import {
  createEmailOtpWalletAuthAdapter,
  createPasskeyWalletAuthAdapter,
  createWalletAuthModeResolver,
  resolveAccountAuthMetadataForSignerSource,
} from '../signingEngine/auth';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  getStoredThresholdEd25519SessionRecordForAccount,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreSource,
} from '../signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import type { ThresholdRuntimePolicyScope } from '../signingEngine/threshold/session/sessionPolicy';
import { shouldRequireThresholdWarmSession } from './thresholdWarmSessionDefaults';
import { prewarmThresholdEd25519ClientBaseFromCredential } from './thresholdWarmSessionBootstrap';
import {
  listConfiguredThresholdEcdsaPublicationTargets,
} from './thresholdEcdsaProvisioning';
import type {
  SigningSessionSnapshot,
  SigningSessionSnapshotEcdsaLane,
  SigningSessionSnapshotEd25519Lane,
} from '../signingEngine/session/snapshotReader';
import {
  ecdsaSnapshotLaneForTarget,
  ecdsaSnapshotTargets,
  isConcreteSigningSessionSnapshotLane,
} from '../signingEngine/session/snapshotReader';
import {
  toWalletSubjectId,
  type WalletSubjectId,
} from '../signingEngine/session/signingSession/ecdsaChainTarget';

type EmitUnlockEventInput = Omit<CreateUnlockFlowEventInput, 'accountId' | 'flowId'>;

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
        options?.signingSession?.remainingUses ??
        context.configs?.signing.sessionDefaults?.remainingUses;
      const ttlMs =
        typeof ttlMsRaw === 'number' ? Math.floor(ttlMsRaw) : Math.floor(Number(ttlMsRaw) || 0);
      const remainingUses =
        typeof remainingUsesRaw === 'number'
          ? Math.floor(remainingUsesRaw)
          : Math.floor(Number(remainingUsesRaw) || 0);
      return {
        ttlMs: Math.max(0, ttlMs),
        remainingUses: Math.max(0, remainingUses),
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
      const canonicalEcdsaContext = await resolveCanonicalThresholdEcdsaWarmSessionContext(
        context,
        signingEngine as unknown,
        nearAccountId,
      );
      const signersToWarm = await resolveThresholdLoginWarmSigners({
        nearAccountId,
        canonicalEcdsaContext,
      });
      // Always mint a fresh shared threshold session id for login warm-up.
      // Reusing a stored ECDSA thresholdSessionId can point at an expired server auth session,
      // which breaks sealed PRF persistence before reload continuity is established.
      const preferredEd25519SessionId = createThresholdLoginWarmSessionId('threshold-login');
      const managedRuntimeScopeBootstrap = resolveManagedThresholdRuntimeScopeBootstrap(context);
      await signingEngine.clearWarmSigningSessions(nearAccountId).catch(() => undefined);
      await primeThresholdLoginWarmSigners({
        context,
        signingEngine,
        nearAccountId,
        relayerUrl,
        relayerKeyId: thresholdKeyMaterial.relayerKeyId,
        participantIds,
        ttlMs: signingSessionPolicy.ttlMs,
        remainingUses: signingSessionPolicy.remainingUses,
        canonicalEcdsaContext,
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

          const walletAuthResolver = createWalletAuthModeResolver({
            passkey: createPasskeyWalletAuthAdapter({
              challenge: async () =>
                await signingEngine.getAuthenticationCredentialsSerialized({
                  nearAccountId,
                  challengeB64u,
                  allowCredentials,
                  includeSecondPrfOutput: false,
                }),
              complete: async ({ response }) => ({
                method: 'passkey',
                webauthnAuthentication: response,
              }),
            }),
            emailOtp: createEmailOtpWalletAuthAdapter({
              challenge: async () => {
                throw new Error('Email OTP wallet unlock uses the Email OTP login flow');
              },
              complete: async () => {
                throw new Error('Email OTP wallet unlock uses the Email OTP login flow');
              },
            }),
          });
          const walletAuthPlan = await walletAuthResolver.resolveWalletAuthPlan({
            accountId: nearAccountId,
            accountAuth: resolveAccountAuthMetadataForSignerSource(),
            intent: 'wallet_unlock',
          });
          if (walletAuthPlan.kind !== 'passkeyReauth') {
            throw new Error('Passkey session exchange requires passkey authorization');
          }
          emitUnlockEvent(onEvent, nearAccountId, {
            phase: UnlockEventPhase.STEP_03_PASSKEY_PROMPT_STARTED,
            status: 'waiting_for_user',
            authMethod: 'passkey',
            interaction: {
              kind: 'passkey_assert',
              overlay: 'show',
            },
          });
          const walletAuthChallenge = await walletAuthPlan.challenge();
          const walletAuthProof = await walletAuthPlan.complete(walletAuthChallenge);
          emitUnlockEvent(onEvent, nearAccountId, {
            phase: UnlockEventPhase.STEP_03_PASSKEY_PROMPT_SUCCEEDED,
            status: 'succeeded',
            authMethod: 'passkey',
            interaction: {
              kind: 'passkey_assert',
              overlay: 'hide',
            },
          });
          const webauthnAuthentication =
            walletAuthProof.webauthnAuthentication as WebAuthnAuthenticationCredential;
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

type CanonicalThresholdEcdsaWarmSessionContext = {
  thresholdSessionId: string | null;
  ecdsaThresholdKeyId?: string | null;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
};

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
  ecdsaHssClientRootShare32B64u: string;
};

type ThresholdLoginWarmEcdsaBootstrapIdentity = {
  ecdsaThresholdKeyId: string;
  walletSigningSessionId: string;
  routeAuth: AppOrThresholdSessionAuth;
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

function requireThresholdLoginWarmEcdsaBootstrapIdentity(args: {
  canonicalEcdsaContext: CanonicalThresholdEcdsaWarmSessionContext;
  ed25519State: ThresholdLoginWarmEd25519State;
  appSessionJwt?: string;
}): ThresholdLoginWarmEcdsaBootstrapIdentity {
  const ecdsaThresholdKeyId = String(args.canonicalEcdsaContext.ecdsaThresholdKeyId || '').trim();
  if (!ecdsaThresholdKeyId) {
    throw new Error('[login] threshold ECDSA warm-up requires a canonical ecdsaThresholdKeyId');
  }

  const walletSigningSessionId = String(args.ed25519State.walletSigningSessionId || '').trim();
  if (!walletSigningSessionId) {
    throw new Error(
      '[login] threshold ECDSA warm-up requires the wallet signing-session identity',
    );
  }

  const appSessionJwt = String(args.appSessionJwt || '').trim();
  const thresholdSessionAuthToken = String(args.ed25519State.jwt || '').trim();
  const routeAuth: AppOrThresholdSessionAuth = appSessionJwt
    ? { kind: 'app_session', jwt: appSessionJwt }
    : { kind: 'threshold_session', jwt: thresholdSessionAuthToken };
  if (!('jwt' in routeAuth) || !String(routeAuth.jwt || '').trim()) {
    throw new Error('[login] threshold ECDSA warm-up requires route authorization');
  }

  return {
    ecdsaThresholdKeyId,
    walletSigningSessionId,
    routeAuth,
  };
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
  canonicalEcdsaContext: CanonicalThresholdEcdsaWarmSessionContext;
  credential?: WebAuthnAuthenticationCredential;
  managedRuntimeScopeBootstrap?: ManagedThresholdRuntimeScopeBootstrap;
  signersToWarm?: ThresholdLoginWarmSigner[];
  preferredEd25519SessionId?: string;
  appSessionJwt?: string;
  useAppSessionCookie?: boolean;
}): Promise<void> {
  const signersToWarm = buildThresholdLoginWarmSignerSelection(args.signersToWarm);
  const warmState: ThresholdLoginWarmEd25519State = {
    sessionId: '',
    walletSigningSessionId: '',
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
          nearAccountId: args.nearAccountId,
          relayerUrl: args.relayerUrl,
          relayerKeyId: args.relayerKeyId,
          ...(args.appSessionJwt ? { appSessionJwt: args.appSessionJwt } : {}),
          ...(args.useAppSessionCookie ? { useAppSessionCookie: args.useAppSessionCookie } : {}),
          ...(args.credential ? { localPrfCredential: args.credential } : {}),
          ...(args.canonicalEcdsaContext.runtimePolicyScope
            ? { runtimePolicyScope: args.canonicalEcdsaContext.runtimePolicyScope }
            : {}),
          ...(args.managedRuntimeScopeBootstrap
            ? { runtimeScopeBootstrap: args.managedRuntimeScopeBootstrap }
            : {}),
          participantIds: args.participantIds,
          sessionKind: args.useAppSessionCookie ? 'cookie' : 'jwt',
          ttlMs: args.ttlMs,
          remainingUses: args.remainingUses,
          sessionId: args.preferredEd25519SessionId || undefined,
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
        if (!connectedJwt) {
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
        warmState.walletSigningSessionId = connectedWalletSigningSessionId;
        warmState.jwt = connectedJwt;
        warmState.ecdsaHssClientRootShare32B64u = connectedEcdsaHssClientRootShare32B64u;
      },
    });
  }
  if (signersToWarm.includes('ecdsa')) {
    tasks.push({
      signer: 'ecdsa',
      dependencies: ['ed25519'],
      run: async () => {
        try {
          const bootstrapIdentity = requireThresholdLoginWarmEcdsaBootstrapIdentity({
            canonicalEcdsaContext: args.canonicalEcdsaContext,
            ed25519State: warmState,
            appSessionJwt: args.appSessionJwt,
          });
          for (const target of listConfiguredThresholdEcdsaPublicationTargets(
            args.context.configs.network.chains,
          )) {
            const sessionId = createThresholdLoginWarmSessionId('threshold-ecdsa-login');
            await args.signingEngine.bootstrapEcdsaSession({
              nearAccountId: args.nearAccountId,
              subjectId: toWalletSubjectId(args.nearAccountId),
              chainTarget: target.chainTarget,
              source: 'login',
              relayerUrl: args.relayerUrl,
              ecdsaThresholdKeyId: bootstrapIdentity.ecdsaThresholdKeyId,
              participantIds: args.participantIds,
              sessionKind: 'jwt',
              sessionId,
              walletSigningSessionId: bootstrapIdentity.walletSigningSessionId,
              ttlMs: args.ttlMs,
              remainingUses: args.remainingUses,
              clientRootShare32B64u: warmState.ecdsaHssClientRootShare32B64u,
              thresholdSessionAuth: bootstrapIdentity.routeAuth,
              ...(args.canonicalEcdsaContext.runtimePolicyScope
                ? { runtimePolicyScope: args.canonicalEcdsaContext.runtimePolicyScope }
                : {}),
              ...(args.managedRuntimeScopeBootstrap
                ? { runtimeScopeBootstrap: args.managedRuntimeScopeBootstrap }
                : {}),
            });
          }
        } catch (error: unknown) {
          const details = String(
            (error && typeof error === 'object' && 'message' in error
              ? (error as { message?: unknown }).message
              : error) || 'Failed to bootstrap threshold ECDSA session',
          );
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
    listConcreteThresholdEcdsaSessionRecordsForSubject?: (args: {
      subjectId: WalletSubjectId;
    }) => ThresholdEcdsaSessionRecord[];
  };
  if (typeof signingEngine.listConcreteThresholdEcdsaSessionRecordsForSubject !== 'function') {
    return [];
  }

  const allowedSources = new Set<ThresholdEcdsaSessionStoreSource>(
    THRESHOLD_ECDSA_LOGIN_METADATA_SOURCES,
  );
  return signingEngine
    .listConcreteThresholdEcdsaSessionRecordsForSubject({
      subjectId: toWalletSubjectId(nearAccountId),
    })
    .filter((record) => allowedSources.has(record.source));
}

async function resolveThresholdEcdsaEthereumAddress(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
): Promise<string | null> {
  for (const record of readThresholdEcdsaLoginMetadataRecords(context, nearAccountId)) {
    const candidate = String(record.ethereumAddress || '').trim();
    if (candidate) return candidate;
  }

  try {
    const continuity = await resolveNearAccountProfileContinuity(
      IndexedDBManager.clientDB,
      nearAccountId,
    );
    const chainAccounts = continuity?.chainAccounts || [];
    if (!Array.isArray(chainAccounts) || chainAccounts.length === 0) return null;

    const thresholdRows = chainAccounts.filter((row) => {
      const accountModel = String(row.accountModel || '')
        .trim()
        .toLowerCase();
      return accountModel === 'erc4337' || accountModel === 'tempo-native';
    });
    if (!thresholdRows.length) return null;

    const preferred = [
      ...thresholdRows.filter(
        (row) => row.isPrimary && String(row.chainIdKey || '').startsWith('evm:'),
      ),
      ...thresholdRows.filter(
        (row) => row.isPrimary && String(row.chainIdKey || '').startsWith('tempo:'),
      ),
      ...thresholdRows.filter((row) => String(row.chainIdKey || '').startsWith('evm:')),
      ...thresholdRows.filter((row) => String(row.chainIdKey || '').startsWith('tempo:')),
      ...thresholdRows,
    ];

    const selected = preferred[0];
    if (!selected) return null;
    const candidate = String(
      selected.counterfactualAddress || selected.accountAddress || '',
    ).trim();
    return candidate || null;
  } catch {
    return null;
  }
}

async function resolveThresholdLoginWarmSigners(args: {
  nearAccountId: AccountId;
  canonicalEcdsaContext?: CanonicalThresholdEcdsaWarmSessionContext | null;
}): Promise<ThresholdLoginWarmSigner[]> {
  const hasExactThresholdEcdsaKeyIdentity =
    !!String(args.canonicalEcdsaContext?.ecdsaThresholdKeyId || '').trim();
  try {
    const continuity = await resolveNearAccountProfileContinuity(
      IndexedDBManager.clientDB,
      args.nearAccountId,
    );
    const chainAccounts = Array.isArray(continuity?.chainAccounts) ? continuity.chainAccounts : [];
    const hasThresholdEcdsaAccount = chainAccounts.some((row) => {
      const accountModel = String(row?.accountModel || '')
        .trim()
        .toLowerCase();
      return accountModel === 'erc4337' || accountModel === 'tempo-native';
    }) || Boolean(await resolveProfileContinuityEcdsaThresholdKeyId(args.nearAccountId));
    return hasThresholdEcdsaAccount && hasExactThresholdEcdsaKeyIdentity
      ? ['ed25519', 'ecdsa']
      : ['ed25519'];
  } catch {
    return hasExactThresholdEcdsaKeyIdentity ? ['ed25519', 'ecdsa'] : ['ed25519'];
  }
}

function createThresholdLoginWarmSessionId(prefix: string): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return `${prefix}-${crypto.randomUUID()}`;
  }
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

async function resolveProfileContinuityEcdsaThresholdKeyId(
  nearAccountId: AccountId,
): Promise<string | null> {
  const continuity = await resolveNearAccountProfileContinuity(
    IndexedDBManager.clientDB,
    nearAccountId,
  ).catch(() => null);
  const keyIds = new Set<string>();
  for (const signer of continuity?.accountSigners || []) {
    if (signer.status && signer.status !== 'active') continue;
    const metadata = signer.metadata || {};
    const keyId = String(metadata.ecdsaThresholdKeyId || '').trim();
    if (keyId) keyIds.add(keyId);
  }
  if (keyIds.size === 1) return [...keyIds][0]!;
  return null;
}

async function resolveCanonicalThresholdEcdsaWarmSessionContext(
  context: PasskeyManagerContext,
  signingEngine: unknown,
  nearAccountId: AccountId,
): Promise<CanonicalThresholdEcdsaWarmSessionContext> {
  const typedSigningEngine = signingEngine as {
    listConcreteThresholdEcdsaSessionRecordsForSubject?: (args: {
      subjectId: WalletSubjectId;
    }) => ThresholdEcdsaSessionRecord[];
  };
  const allowedSources = new Set<ThresholdEcdsaSessionStoreSource>(
    THRESHOLD_ECDSA_LOGIN_METADATA_SOURCES,
  );
  if (typeof typedSigningEngine.listConcreteThresholdEcdsaSessionRecordsForSubject === 'function') {
    for (const record of typedSigningEngine.listConcreteThresholdEcdsaSessionRecordsForSubject({
      subjectId: toWalletSubjectId(nearAccountId),
    })) {
      if (!allowedSources.has(record.source)) continue;
      const thresholdSessionId = String(record.thresholdSessionId || '').trim();
      const ecdsaThresholdKeyId = String(record.ecdsaThresholdKeyId || '').trim();
      if (thresholdSessionId || ecdsaThresholdKeyId || record.runtimePolicyScope) {
        return {
          thresholdSessionId: thresholdSessionId || null,
          ...(ecdsaThresholdKeyId ? { ecdsaThresholdKeyId } : {}),
          ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
        };
      }
    }
  }
  const snapshot = await readSigningSessionSnapshotForUi(context, nearAccountId).catch(() => null);
  const ecdsaThresholdKeyIds = new Set<string>();
  if (snapshot) {
    for (const target of ecdsaSnapshotTargets(snapshot)) {
      const lane = ecdsaSnapshotLaneForTarget(snapshot, target);
      if (!isConcreteSigningSessionSnapshotLane(lane)) continue;
      const ecdsaThresholdKeyId = String(lane.ecdsaThresholdKeyId || '').trim();
      if (ecdsaThresholdKeyId) ecdsaThresholdKeyIds.add(ecdsaThresholdKeyId);
    }
  }
  if (ecdsaThresholdKeyIds.size === 1) {
    return {
      thresholdSessionId: null,
      ecdsaThresholdKeyId: [...ecdsaThresholdKeyIds][0],
    };
  }
  const profileEcdsaThresholdKeyId = await resolveProfileContinuityEcdsaThresholdKeyId(
    nearAccountId,
  );
  if (profileEcdsaThresholdKeyId) {
    return {
      thresholdSessionId: null,
      ecdsaThresholdKeyId: profileEcdsaThresholdKeyId,
    };
  }
  return {
    thresholdSessionId: null,
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
      chainTarget: ReturnType<typeof listConfiguredThresholdEcdsaPublicationTargets>[number]['chainTarget'],
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

type SigningSessionSnapshotLane =
  | SigningSessionSnapshotEd25519Lane
  | SigningSessionSnapshotEcdsaLane;

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
  lane: SigningSessionSnapshotLane,
): SigningSessionStatus | null {
  if (!isConcreteSigningSessionSnapshotLane(lane)) return null;
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
  snapshot: SigningSessionSnapshot | null,
): SigningSessionStatus | null {
  if (!snapshot) return null;
  return selectSigningSessionStatusForUi([
    snapshotLaneToSigningSessionStatus(snapshot.lanes.ed25519.near),
    ...ecdsaSnapshotTargets(snapshot).map((target) =>
      snapshotLaneToSigningSessionStatus(ecdsaSnapshotLaneForTarget(snapshot, target)),
    ),
  ]);
}

async function readSigningSessionSnapshotForUi(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
): Promise<SigningSessionSnapshot | null> {
  const signingEngine = context.signingEngine as typeof context.signingEngine & {
    readPersistedSigningSessionSnapshot?: typeof context.signingEngine.readPersistedSigningSessionSnapshot;
  };
  if (typeof signingEngine.readPersistedSigningSessionSnapshot !== 'function') {
    return null;
  }
  return await signingEngine.readPersistedSigningSessionSnapshot({
    walletId: nearAccountId,
    subjectId: toWalletSubjectId(nearAccountId),
  });
}

async function resolveSnapshotSigningSessionStatusForUi(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
): Promise<SigningSessionStatus | null> {
  return snapshotToSigningSessionStatusForUi(
    await readSigningSessionSnapshotForUi(context, nearAccountId),
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
  const accountIds = allUsersData.map((user) => user.nearAccountId);
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
