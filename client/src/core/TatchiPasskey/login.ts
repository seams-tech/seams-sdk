import type { AfterCall, LoginHooksOptions, LoginSSEvent } from '../types/sdkSentEvents';
import { LoginPhase, LoginStatus } from '../types/sdkSentEvents';
import type {
  GetRecentUnlocksResult,
  LoginAndCreateSessionResult,
  LoginResult,
  WalletSession,
  LoginState,
  ThresholdWarmLoginAndCreateSessionResult,
} from '../types/tatchi';
import type { PasskeyManagerContext } from './index';
import type { AccountId } from '../types/accountIds';
import { getUserFriendlyErrorMessage, toError } from '@shared/utils/errors';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import { isObject } from '@shared/utils/validation';
import { IndexedDBManager } from '../indexedDB';
import { getNearAccountProjection, resolveNearAccountProfileContinuity } from '../accountData/near/accountProjection';
import { getNearThresholdKeyMaterial } from '../accountData/near/keyMaterial';
import type { ClientUserData } from '../accountData/near/types';
import { exchangeSession, type SessionExchangeInput } from '../rpcClients/near/rpcCalls';
import { parseDeviceNumber } from '../signingEngine/signers/webauthn/device/getDeviceNumber';
import { clearAllCachedEd25519AuthSessions } from '../signingEngine/threshold/session/ed25519AuthSession';
import { clearAllStoredThresholdEd25519SessionRecords } from '../signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import type { ThresholdRuntimeSnapshotScope } from '../signingEngine/threshold/session/sessionPolicy';
import { shouldRequireThresholdWarmSession } from './thresholdWarmSessionDefaults';
import { prewarmThresholdEd25519ClientBaseFromCredential } from './thresholdWarmSessionBootstrap';

/**
 * Core login function (passkey identity + relay-issued sessions).
 *
 * Responsibilities:
 * - Select the active account + passkey deviceNumber (last-user pointer).
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
  let loginCredential: import('../types').WebAuthnAuthenticationCredential | undefined;

  onEvent?.({
    step: 1,
    phase: LoginPhase.STEP_1_PREPARATION,
    status: LoginStatus.PROGRESS,
    message: `Starting login for ${nearAccountId}`,
  });

  try {
    await signingEngine.assertSealedRefreshStartupParity();

    if (typeof window !== 'undefined' && !window.isSecureContext) {
      const errorMessage = 'Passkey operations require a secure context (HTTPS or localhost).';
      return await finalizeLoginError({
        message: errorMessage,
        error: new Error(errorMessage),
        onEvent,
        onError,
        afterCall,
        callAfterCall: false,
      });
    }

    const deviceNumberHint = parseDeviceNumber(options?.deviceNumber, { min: 1 });

    const hintUserPromise: Promise<ClientUserData | null> =
      deviceNumberHint !== null
        ? signingEngine.getUserByDevice(nearAccountId, deviceNumberHint).catch(() => null)
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
      userData = await signingEngine.getUserByDevice(nearAccountId, 1).catch(() => null);
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

    const baseDeviceNumber =
      deviceNumberHint ??
      (Number.isFinite(userData.deviceNumber) && userData.deviceNumber >= 1
        ? userData.deviceNumber
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

    const maybeWarmThresholdSigningSessions = async (deviceNumber: number): Promise<void> => {
      if (!requireThresholdWarmup) return;

      const relayerUrl = String(context.configs?.network.relayer?.url || '').trim();
      if (!relayerUrl) {
        throw new Error('[login] threshold warm session requires relayer.url to be configured');
      }

      onEvent?.({
        step: 2,
        phase: LoginPhase.STEP_2_WEBAUTHN_ASSERTION,
        status: LoginStatus.PROGRESS,
        message: 'Preparing a threshold signing session...',
      });

      const thresholdKeyMaterial = await getNearThresholdKeyMaterial(
        {
          clientDB: IndexedDBManager.clientDB,
          accountKeyMaterialDB: IndexedDBManager.accountKeyMaterialDB,
        },
        nearAccountId,
        deviceNumber,
      ).catch(() => null);
      if (!thresholdKeyMaterial) {
        throw new Error(
          `[login] threshold warm-up requires threshold key material for ${nearAccountId} device ${deviceNumber}`,
        );
      }

      const participantIds = thresholdKeyMaterial.participants.map((participant) => participant.id);
      const signersToWarm = await resolveThresholdLoginWarmSigners(nearAccountId);
      const canonicalEcdsaContext = signersToWarm.includes('ecdsa')
        ? resolveCanonicalThresholdEcdsaWarmSessionContext(signingEngine as unknown, nearAccountId)
        : {
            thresholdSessionId: null,
            clientVerifyingShareB64u: null,
          };
      // Always mint a fresh shared threshold session id for login warm-up.
      // Reusing a stored ECDSA thresholdSessionId can point at an expired server auth session,
      // which breaks sealed PRF persistence before reload continuity is established.
      const preferredEd25519SessionId = createThresholdLoginWarmSessionId('threshold-login');
      const managedRuntimeScopeBootstrap = resolveManagedThresholdRuntimeScopeBootstrap(context);
      await signingEngine.clearWarmSigningSessions(nearAccountId).catch(() => undefined);
      await primeThresholdLoginWarmSigners({
        signingEngine,
        nearAccountId,
        relayerUrl,
        relayerKeyId: thresholdKeyMaterial.relayerKeyId,
        participantIds,
        ttlMs: signingSessionPolicy.ttlMs,
        remainingUses: signingSessionPolicy.remainingUses,
        canonicalEcdsaContext,
        ...(managedRuntimeScopeBootstrap ? { managedRuntimeScopeBootstrap } : {}),
        signersToWarm,
        preferredEd25519SessionId,
      });

      const warmStatus = await signingEngine
        .getWarmThresholdEd25519SessionStatus(nearAccountId)
        .catch(() => null);
      signingSession = warmStatus || signingSession;
      requireActiveWarmSession('threshold warm-up');

      onEvent?.({
        step: 3,
        phase: LoginPhase.STEP_3_SESSION_READY,
        status: LoginStatus.PROGRESS,
        message: 'Warm signing session ready',
      });
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

    const persistSuccessfulLoginState = async (deviceNumber: number): Promise<void> => {
      await signingEngine.setLastUser(nearAccountId, deviceNumber).catch(() => undefined);
      await signingEngine.updateLastLogin(nearAccountId).catch(() => undefined);
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
          onEvent?.({
            step: 2,
            phase: LoginPhase.STEP_2_WEBAUTHN_ASSERTION,
            status: LoginStatus.PROGRESS,
            message: 'Exchanging app session token...',
          });
        } else {
          const rpId = String(signingEngine.getRpId() || '').trim();
          if (!rpId) {
            throw new Error('Missing rpId for passkey_assertion session exchange');
          }

          onEvent?.({
            step: 2,
            phase: LoginPhase.STEP_2_WEBAUTHN_ASSERTION,
            status: LoginStatus.PROGRESS,
            message: 'Unlocking app session with passkey...',
          });

          const unlockChallengeResp = await fetch(
            joinNormalizedUrl(relayUrl, '/wallet/unlock/challenge'),
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                user_id: String(nearAccountId),
                rp_id: rpId,
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

          const webauthnAuthentication = await signingEngine.getAuthenticationCredentialsSerialized(
            {
              nearAccountId,
              challengeB64u,
              allowCredentials,
              includeSecondPrfOutput: false,
            },
          );
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

        if (requireThresholdWarmup) {
          await maybeWarmThresholdSigningSessions(baseDeviceNumber);
        }
        await persistSuccessfulLoginState(baseDeviceNumber);
        if (loginCredential) {
          void prewarmThresholdEd25519ClientBaseFromCredential({
            context,
            credential: loginCredential,
            nearAccountId,
            deviceNumber: baseDeviceNumber,
          }).catch(() => undefined);
        }

        onEvent?.({
          step: 3,
          phase: LoginPhase.STEP_3_SESSION_READY,
          status: LoginStatus.PROGRESS,
          message: 'Session ready',
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

    if (requireThresholdWarmup) {
      await maybeWarmThresholdSigningSessions(baseDeviceNumber);
    }

    await persistSuccessfulLoginState(baseDeviceNumber);
    if (loginCredential) {
      void prewarmThresholdEd25519ClientBaseFromCredential({
        context,
        credential: loginCredential,
        nearAccountId,
        deviceNumber: baseDeviceNumber,
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

    return await finalizeLoginSuccess({
      nearAccountId,
      loginResult,
      onEvent,
      afterCall,
    });
  } catch (err: unknown) {
    const errorMessage = getUserFriendlyErrorMessage(err, 'login') || 'Login failed';
    return await finalizeLoginError({
      message: errorMessage,
      error: err,
      onEvent,
      onError,
      afterCall,
    });
  }
}

async function finalizeLoginSuccess(args: {
  nearAccountId: AccountId;
  loginResult: LoginResult;
  onEvent?: (event: LoginSSEvent) => void;
  afterCall?: AfterCall<LoginAndCreateSessionResult>;
}): Promise<LoginAndCreateSessionResult> {
  const { nearAccountId, loginResult, onEvent, afterCall } = args;
  onEvent?.({
    step: 4,
    phase: LoginPhase.STEP_4_LOGIN_COMPLETE,
    status: LoginStatus.SUCCESS,
    message: 'Login completed successfully',
    nearAccountId,
    operationalPublicKey: loginResult.operationalPublicKey ?? '',
  });
  await afterCall?.(true, loginResult);
  return loginResult;
}

async function finalizeLoginError(args: {
  message: string;
  error?: unknown;
  onEvent?: (event: LoginSSEvent) => void;
  onError?: (error: Error) => void;
  afterCall?: AfterCall<LoginAndCreateSessionResult>;
  callOnError?: boolean;
  callAfterCall?: boolean;
}): Promise<LoginAndCreateSessionResult> {
  const {
    message,
    error,
    onEvent,
    onError,
    afterCall,
    callOnError = true,
    callAfterCall = true,
  } = args;

  if (callOnError) {
    onError?.(toError(error));
  }

  onEvent?.({
    step: 0,
    phase: LoginPhase.LOGIN_ERROR,
    status: LoginStatus.ERROR,
    message,
    error: message,
  });

  if (callAfterCall) {
    await afterCall?.(false);
  }
  return { success: false, error: message };
}

type CanonicalThresholdEcdsaWarmSessionContext = {
  thresholdSessionId: string | null;
  clientVerifyingShareB64u: string | null;
  runtimeSnapshotScope?: ThresholdRuntimeSnapshotScope;
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
  signingEngine: PasskeyManagerContext['signingEngine'];
  nearAccountId: AccountId;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds: number[];
  ttlMs: number;
  remainingUses: number;
  canonicalEcdsaContext: CanonicalThresholdEcdsaWarmSessionContext;
  managedRuntimeScopeBootstrap?: ManagedThresholdRuntimeScopeBootstrap;
  signersToWarm?: ThresholdLoginWarmSigner[];
  preferredEd25519SessionId?: string;
}): Promise<void> {
  const signersToWarm = buildThresholdLoginWarmSignerSelection(args.signersToWarm);
  const warmState: {
    sessionId: string;
    jwt: string;
    ecdsaClientVerifyingShareB64u: string;
  } = {
    sessionId: '',
    jwt: '',
    ecdsaClientVerifyingShareB64u: '',
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
          ...(args.canonicalEcdsaContext.runtimeSnapshotScope
            ? { runtimeSnapshotScope: args.canonicalEcdsaContext.runtimeSnapshotScope }
            : {}),
          ...(args.managedRuntimeScopeBootstrap
            ? { runtimeScopeBootstrap: args.managedRuntimeScopeBootstrap }
            : {}),
          participantIds: args.participantIds,
          sessionKind: 'jwt',
          ttlMs: args.ttlMs,
          remainingUses: args.remainingUses,
          sessionId:
            args.preferredEd25519SessionId ||
            args.canonicalEcdsaContext.thresholdSessionId ||
            undefined,
        });
        if (!connected.ok) {
          const details = String(
            connected.message || connected.code || 'Failed to connect threshold Ed25519 session',
          );
          throw new Error(`[login] threshold Ed25519 warm-up failed: ${details}`);
        }

        const connectedSessionId = String(
          connected.sessionId || args.canonicalEcdsaContext.thresholdSessionId || '',
        ).trim();
        if (!connectedSessionId) {
          throw new Error('[login] threshold Ed25519 warm-up did not return a sessionId');
        }

        const connectedJwt = String(connected.jwt || '').trim();
        if (!connectedJwt) {
          throw new Error('[login] threshold Ed25519 warm-up did not return a JWT session token');
        }

        const connectedEcdsaClientVerifyingShareB64u = String(
          connected.ecdsaClientVerifyingShareB64u || '',
        ).trim();
        const canonicalEcdsaClientVerifyingShareB64u = String(
          args.canonicalEcdsaContext.clientVerifyingShareB64u || '',
        ).trim();
        const ecdsaClientVerifyingShareB64u =
          connectedEcdsaClientVerifyingShareB64u || canonicalEcdsaClientVerifyingShareB64u;
        if (!ecdsaClientVerifyingShareB64u) {
          throw new Error(
            '[login] threshold ECDSA warm-up missing clientVerifyingShareB64u from canonical cache or primary prompt derivation',
          );
        }

        warmState.sessionId = connectedSessionId;
        warmState.jwt = connectedJwt;
        warmState.ecdsaClientVerifyingShareB64u = ecdsaClientVerifyingShareB64u;
      },
    });
  }
  if (signersToWarm.includes('ecdsa')) {
    tasks.push({
      signer: 'ecdsa',
      dependencies: ['ed25519'],
      run: async () => {
        try {
          for (const chain of ['tempo', 'evm'] as const) {
            await args.signingEngine.bootstrapEcdsaSession({
              nearAccountId: args.nearAccountId,
              chain,
              source: 'login',
              relayerUrl: args.relayerUrl,
              participantIds: args.participantIds,
              sessionKind: 'jwt',
              ttlMs: args.ttlMs,
              remainingUses: args.remainingUses,
              sessionId: warmState.sessionId,
              clientVerifyingShareB64u: warmState.ecdsaClientVerifyingShareB64u,
              authorizationJwt: warmState.jwt,
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
    ? await context.signingEngine
        .getWarmThresholdEd25519SessionStatus(login.nearAccountId)
        .catch(() => null)
    : null;
  return { login, signingSession };
}

async function resolveThresholdEcdsaEthereumAddress(
  nearAccountId: AccountId,
): Promise<string | null> {
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

async function resolveThresholdLoginWarmSigners(
  nearAccountId: AccountId,
): Promise<ThresholdLoginWarmSigner[]> {
  try {
    const continuity = await resolveNearAccountProfileContinuity(
      IndexedDBManager.clientDB,
      nearAccountId,
    );
    const chainAccounts = Array.isArray(continuity?.chainAccounts) ? continuity.chainAccounts : [];
    const hasThresholdEcdsaAccount = chainAccounts.some((row) => {
      const accountModel = String(row?.accountModel || '')
        .trim()
        .toLowerCase();
      return accountModel === 'erc4337' || accountModel === 'tempo-native';
    });
    return hasThresholdEcdsaAccount ? ['ed25519', 'ecdsa'] : ['ed25519'];
  } catch {
    return ['ed25519'];
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
      getThresholdEcdsaSessionRecordForSigning?: (args: {
        nearAccountId: AccountId | string;
        chain: 'evm' | 'tempo';
      }) => {
        thresholdSessionId?: string;
        clientVerifyingShareB64u?: string;
        runtimeSnapshotScope?: ThresholdRuntimeSnapshotScope;
      };
    }
  )?.getThresholdEcdsaSessionRecordForSigning;
  if (typeof getRecord !== 'function') {
    return {
      thresholdSessionId: null,
      clientVerifyingShareB64u: null,
    };
  }
  const chains: Array<'tempo' | 'evm'> = ['tempo', 'evm'];
  for (const chain of chains) {
    try {
      const record = getRecord({ nearAccountId, chain });
      const thresholdSessionId = String(record?.thresholdSessionId || '').trim();
      const clientVerifyingShareB64u = String(record?.clientVerifyingShareB64u || '').trim();
      if (thresholdSessionId || clientVerifyingShareB64u || record?.runtimeSnapshotScope) {
        return {
          thresholdSessionId: thresholdSessionId || null,
          clientVerifyingShareB64u: clientVerifyingShareB64u || null,
          ...(record?.runtimeSnapshotScope
            ? { runtimeSnapshotScope: record.runtimeSnapshotScope }
            : {}),
        };
      }
    } catch {}
  }
  return {
    thresholdSessionId: null,
    clientVerifyingShareB64u: null,
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

function resolveThresholdEcdsaGroupPublicKeyB64u(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
): string | null {
  const chains: Array<'tempo' | 'evm'> = ['tempo', 'evm'];
  for (const chain of chains) {
    try {
      const record = context.signingEngine.getThresholdEcdsaSessionRecordForSigning({
        nearAccountId,
        chain,
      });
      const groupPublicKeyB64u = String(record.groupPublicKeyB64u || '').trim();
      if (groupPublicKeyB64u) return groupPublicKeyB64u;
    } catch {}
  }
  return null;
}

async function resolveThresholdEcdsaLoginMetadata(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
): Promise<{
  ethereumAddress: string | null;
  groupPublicKeyB64u: string | null;
}> {
  const [ethereumAddress, groupPublicKeyB64u] = await Promise.all([
    resolveThresholdEcdsaEthereumAddress(nearAccountId),
    Promise.resolve(resolveThresholdEcdsaGroupPublicKeyB64u(context, nearAccountId)),
  ]);
  return {
    ethereumAddress,
    groupPublicKeyB64u,
  };
}

async function getLoginStateInternal(
  context: PasskeyManagerContext,
  nearAccountId?: AccountId,
): Promise<LoginState> {
  const { signingEngine } = context;
  try {
    const lastUser = await signingEngine.getLastUser().catch(() => null);
    const targetAccountId = nearAccountId ?? lastUser?.nearAccountId ?? null;
    if (!targetAccountId) {
      return {
        isLoggedIn: false,
        nearAccountId: null,
        publicKey: null,
        userData: null,
        thresholdEcdsaEthereumAddress: null,
        thresholdEcdsaGroupPublicKeyB64u: null,
      };
    }

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
      (await signingEngine.getUserByDevice(targetAccountId, 1).catch(() => null));
    const publicKey = userData?.operationalPublicKey || null;
    const isLoggedIn = !!(userData && userData.operationalPublicKey);
    const resolvedNearAccountId = targetAccountId;

    if (isLoggedIn && shouldRequireThresholdWarmSession(context)) {
      const warmStatus = resolvedNearAccountId
        ? await signingEngine
            .getWarmThresholdEd25519SessionStatus(resolvedNearAccountId)
            .catch(() => null)
        : null;
      if (!warmStatus || warmStatus.status !== 'active') {
        return {
          isLoggedIn: false,
          nearAccountId: resolvedNearAccountId,
          publicKey: null,
          userData: null,
          thresholdEcdsaEthereumAddress: null,
          thresholdEcdsaGroupPublicKeyB64u: null,
        };
      }
    }

    const thresholdMetadata = resolvedNearAccountId
      ? await resolveThresholdEcdsaLoginMetadata(context, resolvedNearAccountId)
      : { ethereumAddress: null, groupPublicKeyB64u: null };

    return {
      isLoggedIn,
      nearAccountId: resolvedNearAccountId,
      publicKey,
      userData,
      thresholdEcdsaEthereumAddress: thresholdMetadata.ethereumAddress,
      thresholdEcdsaGroupPublicKeyB64u: thresholdMetadata.groupPublicKeyB64u,
    };
  } catch (error: unknown) {
    console.warn('Error getting login state:', error);
    return {
      isLoggedIn: false,
      nearAccountId: nearAccountId || null,
      publicKey: null,
      userData: null,
      thresholdEcdsaEthereumAddress: null,
      thresholdEcdsaGroupPublicKeyB64u: null,
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
    signingEngine.getNonceManager().clear();
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
    clearAllCachedEd25519AuthSessions();
  } catch {}
  try {
    clearAllStoredThresholdEd25519SessionRecords();
  } catch {}
}
