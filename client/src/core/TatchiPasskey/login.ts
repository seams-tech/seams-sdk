import type {
  AfterCall,
  LoginHooksOptions,
  LoginSSEvent,
} from '../types/sdkSentEvents';
import { LoginPhase, LoginStatus } from '../types/sdkSentEvents';
import type {
  GetRecentLoginsResult,
  LoginAndCreateSessionResult,
  LoginResult,
  LoginSession,
  LoginState,
} from '../types/tatchi';
import type { PasskeyManagerContext } from './index';
import type { AccountId } from '../types/accountIds';
import { getUserFriendlyErrorMessage, toError } from '@shared/utils/errors';
import { authenticatorsToAllowCredentials } from '../signingEngine/signers/webauthn/credentials';
import { IndexedDBManager } from '../indexedDB';
import type { ClientAuthenticatorData, ClientUserData } from '../indexedDB';
import { createWebAuthnLoginOptions, verifyWebAuthnLogin } from '../rpcClients/near/rpcCalls';
import { parseDeviceNumber } from '../signingEngine/signers/webauthn/device/getDeviceNumber';
import { clearAllCachedEd25519AuthSessions } from '../signingEngine/threshold/session/ed25519AuthSession';
import { clearAllCachedEcdsaAuthSessions } from '../signingEngine/threshold/session/ecdsaAuthSession';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';

/**
 * Core login function (standard WebAuthn; relay-issued sessions).
 *
 * Responsibilities:
 * - Select the active account + passkey deviceNumber (last-user pointer).
 * - Optionally mint a relayer session (JWT/cookie) via standard WebAuthn challenge/verify.
 *
 * Note: signing flows still perform their own UserConfirm/WebAuthn prompting as needed.
 */
export async function loginAndCreateSession(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
  options?: LoginHooksOptions
): Promise<LoginAndCreateSessionResult> {
  const { onEvent, onError, afterCall } = options || {};
  const { signingEngine } = context;

  onEvent?.({
    step: 1,
    phase: LoginPhase.STEP_1_PREPARATION,
    status: LoginStatus.PROGRESS,
    message: `Starting login for ${nearAccountId}`,
  });

  try {
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
      IndexedDBManager.clientDB.getMostRecentNearAccountProjection(nearAccountId).catch(() => null),
      signingEngine.getAuthenticatorsByUser(nearAccountId).catch(() => []),
    ]);

    if (authenticators.length === 0) {
      throw new Error(`No authenticators found for account ${nearAccountId}. Please register an account.`);
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
      throw new Error(`User data not found for ${nearAccountId} in IndexedDB. Please register an account.`);
    }
    if (!userData.clientNearPublicKey) {
      throw new Error(`No NEAR public key found for ${nearAccountId}. Please register an account.`);
    }

    const baseDeviceNumber =
      deviceNumberHint ??
      (Number.isFinite(userData.deviceNumber) && userData.deviceNumber >= 1 ? userData.deviceNumber : 1);

    const signingSessionPolicy = (() => {
      const ttlMsRaw = options?.signingSession?.ttlMs ?? context.configs?.signingSessionDefaults?.ttlMs;
      const remainingUsesRaw = options?.signingSession?.remainingUses ?? context.configs?.signingSessionDefaults?.remainingUses;
      const ttlMs = typeof ttlMsRaw === 'number' ? Math.floor(ttlMsRaw) : Math.floor(Number(ttlMsRaw) || 0);
      const remainingUses = typeof remainingUsesRaw === 'number'
        ? Math.floor(remainingUsesRaw)
        : Math.floor(Number(remainingUsesRaw) || 0);
      return {
        ttlMs: Math.max(0, ttlMs),
        remainingUses: Math.max(0, remainingUses),
      };
    })();

    let signingSession: LoginAndCreateSessionResult['signingSession'] | undefined;
    let thresholdEcdsaKeyRef: LoginAndCreateSessionResult['thresholdEcdsaKeyRef'] | undefined;
    const isThresholdSignerMode = context.configs?.signerMode?.mode === 'threshold-signer';
    // Warm sessions are enabled when policy budgets are non-zero.
    const shouldWarmThresholdSigningSession =
      signingSessionPolicy.ttlMs > 0 && signingSessionPolicy.remainingUses > 0;
    // In threshold-signer mode, warm session bootstrap must succeed during login.
    const requireThresholdWarmup = isThresholdSignerMode && shouldWarmThresholdSigningSession;
    const shouldWarmThresholdEcdsaDuringLogin = requireThresholdWarmup && (
      context.configs?.registrationSignerDefaults?.tempo?.enabled === true
      || context.configs?.registrationSignerDefaults?.evm?.enabled === true
    );

    const requireActiveWarmSession = (source: string): void => {
      if (signingSession?.status === 'active') return;
      const status = String(signingSession?.status || 'not_found');
      throw new Error(`[login] ${source} did not produce an active warm signing session (status=${status})`);
    };

    const maybeWarmThresholdSigningSession = async (deviceNumber: number): Promise<void> => {
      if (!requireThresholdWarmup) return;

      const thresholdKeyMaterial = await IndexedDBManager
        .getNearThresholdKeyMaterial(nearAccountId, deviceNumber)
        .catch(() => null);
      if (!thresholdKeyMaterial?.relayerKeyId) {
        throw new Error(
          `[login] threshold-signer mode requires enrolled threshold ed25519 key material for ${nearAccountId}`,
        );
      }

      const relayerUrl = String(context.configs?.relayer?.url || '').trim();
      if (!relayerUrl) {
        throw new Error('[login] threshold warm session requires relayer.url to be configured');
      }

      const participantIds = normalizeThresholdEd25519ParticipantIds(
        thresholdKeyMaterial.participants?.map((p) => p.id),
      );

      onEvent?.({
        step: 2,
        phase: LoginPhase.STEP_2_WEBAUTHN_ASSERTION,
        status: LoginStatus.PROGRESS,
        message: 'Preparing a warm NEAR signing session...',
      });

      const connect = await signingEngine.connectEd25519Session({
        nearAccountId,
        relayerKeyId: thresholdKeyMaterial.relayerKeyId,
        ...(participantIds ? { participantIds } : {}),
        relayerUrl,
        sessionKind: 'jwt',
        ttlMs: signingSessionPolicy.ttlMs,
        remainingUses: signingSessionPolicy.remainingUses,
      });
      if (!connect.ok) {
        throw new Error(connect.message || connect.code || 'Failed to connect threshold ed25519 signing session');
      }

      signingSession = await signingEngine.getWarmSigningSessionStatus(nearAccountId).catch(() => null) || undefined;
      requireActiveWarmSession('threshold ed25519 warm-up');

      onEvent?.({
        step: 3,
        phase: LoginPhase.STEP_3_SESSION_READY,
        status: LoginStatus.PROGRESS,
        message: 'Warm signing session ready',
      });
    };

    const maybeWarmThresholdEcdsaSigningSession = async (): Promise<void> => {
      if (!requireThresholdWarmup) return;

      const relayerUrl = String(context.configs?.relayer?.url || '').trim();
      if (!relayerUrl) {
        throw new Error('[login] threshold ECDSA warm session requires relayer.url to be configured');
      }

      onEvent?.({
        step: 2,
        phase: LoginPhase.STEP_2_WEBAUTHN_ASSERTION,
        status: LoginStatus.PROGRESS,
        message: 'Preparing a warm Tempo/EVM signing session...',
      });

      const bootstrap = await signingEngine.bootstrapEcdsaSession({
        nearAccountId,
        chain: 'tempo',
        relayerUrl,
        sessionKind: 'jwt',
        ttlMs: signingSessionPolicy.ttlMs,
        remainingUses: signingSessionPolicy.remainingUses,
      });
      const keyRef = bootstrap.thresholdEcdsaKeyRef;
      const thresholdSessionId = String(keyRef?.thresholdSessionId || '').trim();
      const thresholdSessionJwt = String(keyRef?.thresholdSessionJwt || '').trim();
      if (!keyRef || !thresholdSessionId || !thresholdSessionJwt) {
        throw new Error('[login] threshold ECDSA warm-up completed without a valid threshold session keyRef');
      }
      thresholdEcdsaKeyRef = keyRef;

      const warmStatus = await signingEngine.getWarmSigningSessionStatus(nearAccountId).catch(() => null);
      signingSession = warmStatus || signingSession;
      requireActiveWarmSession('threshold ECDSA warm-up');

      onEvent?.({
        step: 3,
        phase: LoginPhase.STEP_3_SESSION_READY,
        status: LoginStatus.PROGRESS,
        message: 'Warm Tempo/EVM signing session ready',
      });
    };

    const persistSuccessfulLoginState = async (deviceNumber: number): Promise<void> => {
      await signingEngine.setLastUser(nearAccountId, deviceNumber).catch(() => undefined);
      await signingEngine.updateLastLogin(nearAccountId).catch(() => undefined);
    };

    const session = options?.session;
    const wantsServerSession = session !== undefined;

    if (wantsServerSession) {
      const relayUrl = (session?.relayUrl || context.configs.relayer.url).trim();
      if (!relayUrl) {
        throw new Error('Missing relayUrl for session-style login');
      }

      const verifyRoute = (session?.route || '/auth/passkey/verify').trim();
      const verifyPath = verifyRoute.startsWith('/') ? verifyRoute : `/${verifyRoute}`;
      const optionsRoute = verifyPath.endsWith('/verify')
        ? `${verifyPath.slice(0, -'/verify'.length)}/options`
        : '/auth/passkey/options';

      const rpId = signingEngine.getRpId();
      if (!rpId) {
        throw new Error('Missing rpId for login session mint');
      }

      const loginOptions = await createWebAuthnLoginOptions(relayUrl, optionsRoute, {
        userId: nearAccountId,
        rpId,
      });
      if (!loginOptions.success || !loginOptions.challengeId || !loginOptions.challengeB64u) {
        throw new Error(loginOptions.error || 'Failed to create WebAuthn login options');
      }

      onEvent?.({
        step: 2,
        phase: LoginPhase.STEP_2_WEBAUTHN_ASSERTION,
        status: LoginStatus.PROGRESS,
        message: 'Authenticating with passkey...',
      });

      const authenticatorsForPrompt = prioritizeAuthenticatorsByDeviceNumber(authenticators, baseDeviceNumber);
      const credential = await signingEngine.getAuthenticationCredentialsSerialized({
        nearAccountId,
        challengeB64u: loginOptions.challengeB64u,
        allowCredentials: authenticatorsToAllowCredentials(authenticatorsForPrompt),
      });

      const selectedDeviceNumber = resolveDeviceNumberFromCredentialId(
        authenticators,
        credential.rawId,
        baseDeviceNumber,
      );

      const selectedUserData = await signingEngine
        .getUserByDevice(nearAccountId, selectedDeviceNumber)
        .catch(() => userData);

      const v = await verifyWebAuthnLogin(relayUrl, verifyPath, session.kind, {
        challengeId: loginOptions.challengeId,
        webauthnAuthentication: credential,
      });
      if (!v.success || !v.verified) {
        throw new Error(v.error || 'Session verification failed');
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
        clientNearPublicKey: selectedUserData?.clientNearPublicKey ?? userData.clientNearPublicKey,
        nearAccountId,
        ...(v.jwt ? { jwt: v.jwt } : {}),
      };

      if (requireThresholdWarmup) {
        if (shouldWarmThresholdEcdsaDuringLogin) {
          await maybeWarmThresholdEcdsaSigningSession();
        } else {
          await maybeWarmThresholdSigningSession(selectedDeviceNumber);
        }
      }

      await persistSuccessfulLoginState(selectedDeviceNumber);

      const enrichedLoginResult: LoginAndCreateSessionResult = {
        ...loginResult,
        ...(signingSession ? { signingSession } : {}),
        ...(thresholdEcdsaKeyRef ? { thresholdEcdsaKeyRef } : {}),
      };
      return await finalizeLoginSuccess({
        nearAccountId,
        loginResult: enrichedLoginResult,
        onEvent,
        afterCall,
      });
    }

    if (requireThresholdWarmup) {
      if (shouldWarmThresholdEcdsaDuringLogin) {
        await maybeWarmThresholdEcdsaSigningSession();
      } else {
        await maybeWarmThresholdSigningSession(baseDeviceNumber);
      }
    }

    await persistSuccessfulLoginState(baseDeviceNumber);

    const loginResult: LoginAndCreateSessionResult = {
      success: true,
      loggedInNearAccountId: String(nearAccountId),
      clientNearPublicKey: userData.clientNearPublicKey,
      nearAccountId,
      ...(signingSession ? { signingSession } : {}),
      ...(thresholdEcdsaKeyRef ? { thresholdEcdsaKeyRef } : {}),
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
    clientNearPublicKey: loginResult.clientNearPublicKey ?? '',
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

function resolveDeviceNumberFromCredentialId(
  authenticators: ClientAuthenticatorData[],
  credentialRawId: string,
  fallback: number,
): number {
  const rawId = String(credentialRawId || '').trim();
  if (!rawId) return fallback;
  const matched = authenticators.find((a) => a.credentialId === rawId);
  const deviceNumber = matched?.deviceNumber;
  return Number.isSafeInteger(deviceNumber) && (deviceNumber as number) >= 1 ? (deviceNumber as number) : fallback;
}

function prioritizeAuthenticatorsByDeviceNumber(
  authenticators: ClientAuthenticatorData[],
  deviceNumber: number | null
): ClientAuthenticatorData[] {
  if (authenticators.length <= 1) return authenticators;
  if (deviceNumber === null) return authenticators;
  const preferred = authenticators.filter((a) => a.deviceNumber === deviceNumber);
  if (preferred.length === 0) return authenticators;
  const rest = authenticators.filter((a) => a.deviceNumber !== deviceNumber);
  return [...preferred, ...rest];
}

/**
 * High-level login snapshot used by React contexts/UI.
 *
 * Login state is derived from:
 * - IndexedDB last-user pointer, and
 * - when threshold-signer warm sessions are enabled, an active PRF-first cache entry
 *   in the UserConfirm worker for the account's active signing session id.
 */
export async function getLoginSession(
  context: PasskeyManagerContext,
  nearAccountId?: AccountId
): Promise<LoginSession> {
  const login = await getLoginStateInternal(context, nearAccountId);
  const signingSession = login?.nearAccountId
    ? await context.signingEngine.getWarmSigningSessionStatus(login.nearAccountId).catch(() => null)
    : null;
  return { login, signingSession };
}

async function getLoginStateInternal(
  context: PasskeyManagerContext,
  nearAccountId?: AccountId
): Promise<LoginState> {
  const { signingEngine } = context;
  try {
    const lastUser = await signingEngine.getLastUser().catch(() => null);
    const targetAccountId = nearAccountId ?? lastUser?.nearAccountId ?? null;

    if (!lastUser || (targetAccountId && lastUser.nearAccountId !== targetAccountId)) {
      return {
        isLoggedIn: false,
        nearAccountId: targetAccountId || null,
        publicKey: null,
        userData: null,
      };
    }

    const userData = lastUser;
    const publicKey = userData?.clientNearPublicKey || null;
    const isLoggedIn = !!(userData && userData.clientNearPublicKey);
    const resolvedNearAccountId = targetAccountId ?? null;

    if (isLoggedIn && shouldRequireActiveWarmSessionForLoginState(context)) {
      const warmStatus = resolvedNearAccountId
        ? await signingEngine.getWarmSigningSessionStatus(resolvedNearAccountId).catch(() => null)
        : null;
      if (!warmStatus || warmStatus.status !== 'active') {
        return {
          isLoggedIn: false,
          nearAccountId: resolvedNearAccountId,
          publicKey: null,
          userData: null,
        };
      }
    }

    return {
      isLoggedIn,
      nearAccountId: resolvedNearAccountId,
      publicKey,
      userData,
    };
  } catch (error: unknown) {
    console.warn('Error getting login state:', error);
    return {
      isLoggedIn: false,
      nearAccountId: nearAccountId || null,
      publicKey: null,
      userData: null,
    };
  }
}

function shouldRequireActiveWarmSessionForLoginState(
  context: PasskeyManagerContext,
): boolean {
  if (context.configs?.signerMode?.mode !== 'threshold-signer') return false;
  const ttlMsRaw = context.configs?.signingSessionDefaults?.ttlMs;
  const remainingUsesRaw = context.configs?.signingSessionDefaults?.remainingUses;
  const ttlMs = typeof ttlMsRaw === 'number' ? Math.floor(ttlMsRaw) : Math.floor(Number(ttlMsRaw) || 0);
  const remainingUses = typeof remainingUsesRaw === 'number'
    ? Math.floor(remainingUsesRaw)
    : Math.floor(Number(remainingUsesRaw) || 0);
  return ttlMs > 0 && remainingUses > 0;
}

/**
 * List recently used accounts from IndexedDB.
 *
 * Used for account picker UIs and initial app bootstrap state.
 */
export async function getRecentLogins(
  context: PasskeyManagerContext
): Promise<GetRecentLoginsResult> {
  const { signingEngine } = context;
  const allUsersData = await signingEngine.getAllUsers();
  const accountIds = allUsersData.map(user => user.nearAccountId);
  const lastUsedAccount = await signingEngine.getLastUser();
  return {
    accountIds,
    lastUsedAccount,
  };
}

/**
 * Logout: clears last-user pointer and client-side caches.
 */
export async function logoutAndClearSession(context: PasskeyManagerContext): Promise<void> {
  const { signingEngine } = context;
  await IndexedDBManager.clientDB.clearLastProfileSelection().catch(() => undefined);
  try { signingEngine.getNonceManager().clear(); } catch {}
  try { await signingEngine.clearWarmSigningSessions(); } catch {}
  try { clearAllCachedEd25519AuthSessions(); } catch {}
  try { clearAllCachedEcdsaAuthSessions(); } catch {}
}
