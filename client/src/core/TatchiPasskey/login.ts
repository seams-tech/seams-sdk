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
} from '../types/tatchi';
import type { PasskeyManagerContext } from './index';
import type { AccountId } from '../types/accountIds';
import type { WebAuthnAuthenticationCredential } from '../types';
import { getUserFriendlyErrorMessage, isUserCancellationError, toError } from '@shared/utils/errors';
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
      (Number.isFinite(userData.signerSlot) && userData.signerSlot >= 1
        ? userData.signerSlot
        : 1);

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
      const canonicalEcdsaContext = resolveCanonicalThresholdEcdsaWarmSessionContext(
        signingEngine as unknown,
        nearAccountId,
      );
      const existingThresholdEcdsaPublicKeyB64u = resolveThresholdEcdsaPublicKeyB64u(
        context,
        nearAccountId,
      );
      const signersToWarm = await resolveThresholdLoginWarmSigners({
        nearAccountId,
        canonicalEcdsaContext,
        existingThresholdEcdsaPublicKeyB64u,
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
  const warmState: {
    sessionId: string;
    walletSigningSessionId: string;
    jwt: string;
    ecdsaHssClientRootShare32B64u: string;
  } = {
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

        const connectedEcdsaHssClientRootShare32B64u = String(
          connected.ecdsaHssClientRootShare32B64u || '',
        ).trim();
        if (!connectedEcdsaHssClientRootShare32B64u) {
          throw new Error(
            '[login] threshold ECDSA warm-up missing clientRootShare32B64u from the primed Ed25519 session',
          );
        }

        warmState.sessionId = connectedSessionId;
        warmState.walletSigningSessionId = String(connected.walletSigningSessionId || '').trim();
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
          const appSessionJwt = String(args.appSessionJwt || '').trim();
          const useAppSessionBootstrapJwt =
            !!appSessionJwt &&
            !!String(args.canonicalEcdsaContext.ecdsaThresholdKeyId || '').trim();
          const routeAuth: AppOrThresholdSessionAuth | undefined =
            useAppSessionBootstrapJwt && appSessionJwt
              ? { kind: 'app_session', jwt: appSessionJwt }
              : warmState.jwt
                ? { kind: 'threshold_session', jwt: warmState.jwt }
                : undefined;
          for (const chain of ['tempo', 'evm'] as const) {
            await args.signingEngine.bootstrapEcdsaSession({
              nearAccountId: args.nearAccountId,
              chain,
              source: 'login',
              relayerUrl: args.relayerUrl,
              ...(args.canonicalEcdsaContext.ecdsaThresholdKeyId
                ? { ecdsaThresholdKeyId: args.canonicalEcdsaContext.ecdsaThresholdKeyId }
                : {}),
              participantIds: args.participantIds,
              sessionKind: 'jwt',
              ...(warmState.walletSigningSessionId
                ? { walletSigningSessionId: warmState.walletSigningSessionId }
                : {}),
              ttlMs: args.ttlMs,
              remainingUses: args.remainingUses,
              clientRootShare32B64u: warmState.ecdsaHssClientRootShare32B64u,
              ...(routeAuth ? { thresholdRouteAuth: routeAuth } : {}),
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
    ? await resolveWarmSigningSessionStatusForUi(context, login.nearAccountId).catch(() => null)
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

const THRESHOLD_ECDSA_LOGIN_METADATA_CHAINS: ReadonlyArray<'tempo' | 'evm'> = [
  'tempo',
  'evm',
];
const walletSessionInitRestoreByAccount = new Map<string, Promise<void>>();

async function restorePersistedSessionsForWalletSessionInit(
  context: PasskeyManagerContext,
  nearAccountId: AccountId | string,
): Promise<void> {
  const accountId = String(nearAccountId || '').trim();
  if (!accountId) return;
  const existing = walletSessionInitRestoreByAccount.get(accountId);
  if (existing) {
    await existing;
    return;
  }
  const restorePromise = (async () => {
    const signingEngine = context.signingEngine as typeof context.signingEngine & {
      restorePersistedSessionsForAccount?: typeof context.signingEngine.restorePersistedSessionsForAccount;
      readPersistedSigningSessionSnapshot?: typeof context.signingEngine.readPersistedSigningSessionSnapshot;
    };
    if (
      typeof signingEngine.restorePersistedSessionsForAccount !== 'function' ||
      typeof signingEngine.readPersistedSigningSessionSnapshot !== 'function'
    ) {
      return;
    }
    // Startup/session polling is a command boundary: restore durable material once,
    // then consume the side-effect-free snapshot path before status readers run.
    await signingEngine.restorePersistedSessionsForAccount({
      walletId: accountId,
      maxRecords: 12,
    });
    await signingEngine.readPersistedSigningSessionSnapshot({
      walletId: accountId,
    });
  })().catch((error: unknown) => {
    console.warn('[WalletSession] persisted signing-session init restore failed', {
      accountId,
      error: error instanceof Error ? error.message : String(error || 'unknown error'),
    });
  });
  walletSessionInitRestoreByAccount.set(accountId, restorePromise);
  await restorePromise;
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
  const getRecord = (
    context.signingEngine as {
      getThresholdEcdsaSessionRecordForLookup?: (args: {
        nearAccountId: AccountId | string;
        chain: 'evm' | 'tempo';
        source?: ThresholdEcdsaSessionStoreSource;
      }) => ThresholdEcdsaSessionRecord;
    }
  )?.getThresholdEcdsaSessionRecordForLookup;
  if (typeof getRecord !== 'function') return [];

  const out: ThresholdEcdsaSessionRecord[] = [];
  const seen = new Set<string>();
  for (const chain of THRESHOLD_ECDSA_LOGIN_METADATA_CHAINS) {
    for (const source of THRESHOLD_ECDSA_LOGIN_METADATA_SOURCES) {
      try {
        const record = getRecord({
          nearAccountId,
          chain,
          source,
        });
        const key = [
          record.chain,
          record.source,
          record.thresholdSessionId,
          record.ecdsaThresholdKeyId,
          record.signingRootId,
          record.signingRootVersion || '',
        ].join('|');
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(record);
      } catch {}
    }
  }
  return out;
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
  existingThresholdEcdsaPublicKeyB64u?: string | null;
}): Promise<ThresholdLoginWarmSigner[]> {
  const hasExistingThresholdEcdsaSession =
    !!String(args.canonicalEcdsaContext?.thresholdSessionId || '').trim() ||
    !!args.canonicalEcdsaContext?.runtimePolicyScope ||
    !!String(args.existingThresholdEcdsaPublicKeyB64u || '').trim();
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
    });
    return hasThresholdEcdsaAccount || hasExistingThresholdEcdsaSession
      ? ['ed25519', 'ecdsa']
      : ['ed25519'];
  } catch {
    return hasExistingThresholdEcdsaSession ? ['ed25519', 'ecdsa'] : ['ed25519'];
  }
}

function createThresholdLoginWarmSessionId(prefix: string): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function resolveCanonicalThresholdEcdsaWarmSessionContext(
  signingEngine: unknown,
  nearAccountId: AccountId,
): CanonicalThresholdEcdsaWarmSessionContext {
  const getRecord = (
    signingEngine as {
      getThresholdEcdsaSessionRecordForLookup?: (args: {
        nearAccountId: AccountId | string;
        chain: 'evm' | 'tempo';
        source: ThresholdEcdsaSessionStoreSource;
      }) => {
        thresholdSessionId?: string;
        ecdsaThresholdKeyId?: string;
        runtimePolicyScope?: ThresholdRuntimePolicyScope;
      };
    }
  )?.getThresholdEcdsaSessionRecordForLookup;
  if (typeof getRecord !== 'function') {
    return {
      thresholdSessionId: null,
    };
  }
  const chains: Array<'tempo' | 'evm'> = ['tempo', 'evm'];
  for (const chain of chains) {
    for (const source of THRESHOLD_ECDSA_LOGIN_METADATA_SOURCES) {
      try {
        const record = getRecord({ nearAccountId, chain, source });
        const thresholdSessionId = String(record?.thresholdSessionId || '').trim();
        const ecdsaThresholdKeyId = String(record?.ecdsaThresholdKeyId || '').trim();
        if (thresholdSessionId || ecdsaThresholdKeyId || record?.runtimePolicyScope) {
          return {
            thresholdSessionId: thresholdSessionId || null,
            ...(ecdsaThresholdKeyId ? { ecdsaThresholdKeyId } : {}),
            ...(record?.runtimePolicyScope
              ? { runtimePolicyScope: record.runtimePolicyScope }
              : {}),
          };
        }
      } catch {}
    }
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
      chain: 'tempo' | 'evm',
    ) => Promise<SigningSessionStatus[]>;
  };

  const ed25519 =
    hints && 'ed25519' in hints
      ? hints.ed25519 || null
      : await signingEngine.getWarmThresholdEd25519SessionStatus(nearAccountId).catch(() => null);
  const ecdsaStatuses =
    typeof signingEngine.listWarmThresholdEcdsaSessionStatuses === 'function'
      ? (
          await Promise.all([
            signingEngine
              .listWarmThresholdEcdsaSessionStatuses(nearAccountId, 'tempo')
              .catch(() => []),
            signingEngine
              .listWarmThresholdEcdsaSessionStatuses(nearAccountId, 'evm')
              .catch(() => []),
          ])
        ).flat()
      : [];

  const statuses = [ed25519, ...ecdsaStatuses].filter(
    (status): status is SigningSessionStatus => Boolean(status),
  );
  const active = statuses
    .filter((status) => status.status === 'active')
    .sort((left, right) => {
      const leftUses = Math.floor(Number(left.remainingUses) || 0);
      const rightUses = Math.floor(Number(right.remainingUses) || 0);
      if (leftUses !== rightUses) return leftUses - rightUses;
      return Math.floor(Number(left.expiresAtMs) || 0) - Math.floor(Number(right.expiresAtMs) || 0);
    })[0];
  if (active) return active;
  return statuses.find((status) => status.status !== 'not_found') || statuses[0] || null;
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

    await restorePersistedSessionsForWalletSessionInit(context, targetAccountId);

    const latestByAccount =
      lastUser && lastUser.nearAccountId === targetAccountId
        ? null
        : await getNearAccountProjection(IndexedDBManager.clientDB, targetAccountId).catch(
            () => null,
          );
    const userData =
      (lastUser && lastUser.nearAccountId === targetAccountId
        ? lastUser
        : latestByAccount) ||
      (await signingEngine.getUserBySignerSlot(targetAccountId, 1).catch(() => null));
    const resolvedNearAccountId = targetAccountId;
    const thresholdMetadata = await resolveThresholdEcdsaLoginMetadata(context, resolvedNearAccountId);
    const requiresWarmSession = shouldRequireThresholdWarmSession(context);
    const thresholdSignerMode = isThresholdSignerMode(context);
    const hasThresholdEcdsaLogin = !!(
      thresholdMetadata.thresholdEcdsaPublicKeyB64u || thresholdMetadata.ethereumAddress
    );
    const ed25519WarmStatus = await signingEngine
      .getWarmThresholdEd25519SessionStatus(resolvedNearAccountId)
      .catch(() => null);
    const hasThresholdEd25519SessionRecord = !!getStoredThresholdEd25519SessionRecordForAccount(
      resolvedNearAccountId,
    );
    const shouldGateNearPublicKey =
      requiresWarmSession || thresholdSignerMode || hasThresholdEcdsaLogin;
    const hasThresholdEd25519SigningCapability =
      ed25519WarmStatus?.status === 'active' || hasThresholdEd25519SessionRecord;
    const publicKey =
      userData?.operationalPublicKey &&
      (!shouldGateNearPublicKey || hasThresholdEd25519SigningCapability)
        ? userData.operationalPublicKey
        : null;
    const hasNearOperationalLogin = !!(userData && publicKey);
    const shouldResolveWarmStatusForLogin =
      requiresWarmSession || thresholdSignerMode || hasThresholdEcdsaLogin || !publicKey;
    const warmStatusForLogin = shouldResolveWarmStatusForLogin
      ? await resolveWarmSigningSessionStatusForUi(context, resolvedNearAccountId, {
          ed25519: ed25519WarmStatus,
        }).catch(() => null)
      : null;
    const hasActiveWarmSigningSession = warmStatusForLogin?.status === 'active';
    const isLoggedIn =
      hasNearOperationalLogin || hasThresholdEcdsaLogin || hasActiveWarmSigningSession;

    if (isLoggedIn && (requiresWarmSession || !hasNearOperationalLogin)) {
      const warmStatus =
        warmStatusForLogin ||
        (await resolveWarmSigningSessionStatusForUi(context, resolvedNearAccountId, {
          ed25519: ed25519WarmStatus,
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
