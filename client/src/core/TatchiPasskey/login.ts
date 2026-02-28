import type { AfterCall, LoginHooksOptions, LoginSSEvent } from '../types/sdkSentEvents';
import { LoginPhase, LoginStatus } from '../types/sdkSentEvents';
import type {
  GetRecentLoginsResult,
  LoginAndCreateSessionResult,
  LoginResult,
  LoginSession,
  LoginState,
  ThresholdWarmLoginAndCreateSessionResult,
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
import { clearAllStoredThresholdEd25519SessionRecords } from '../signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import { shouldRequireThresholdWarmSession } from './thresholdWarmSessionDefaults';

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
  options?: LoginHooksOptions,
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
    if (!userData.clientNearPublicKey) {
      throw new Error(`No NEAR public key found for ${nearAccountId}. Please register an account.`);
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
    const isThresholdSignerMode = context.configs?.signing.mode?.mode === 'threshold-signer';
    // Warm sessions are enabled when policy budgets are non-zero.
    const shouldWarmThresholdSigningSession =
      signingSessionPolicy.ttlMs > 0 && signingSessionPolicy.remainingUses > 0;
    // In threshold-signer mode, warm session creation must succeed during login.
    const requireThresholdWarmup = isThresholdSignerMode && shouldWarmThresholdSigningSession;

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

      const thresholdKeyMaterial = await IndexedDBManager.getNearThresholdKeyMaterial(
        nearAccountId,
        deviceNumber,
      ).catch(() => null);
      if (!thresholdKeyMaterial) {
        throw new Error(
          `[login] threshold warm-up requires threshold key material for ${nearAccountId} device ${deviceNumber}`,
        );
      }

      const participantIds = thresholdKeyMaterial.participants.map((participant) => participant.id);
      const canonicalEcdsaContext = resolveCanonicalThresholdEcdsaWarmSessionContext(
        signingEngine as unknown,
        nearAccountId,
      );
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
      });

      const warmStatus = await signingEngine
        .getWarmSigningSessionStatus(nearAccountId)
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

      const authenticatorsForPrompt = prioritizeAuthenticatorsByDeviceNumber(
        authenticators,
        baseDeviceNumber,
      );
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
        await maybeWarmThresholdSigningSessions(selectedDeviceNumber);
      }

      await persistSuccessfulLoginState(selectedDeviceNumber);

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

    if (requireThresholdWarmup) {
      await maybeWarmThresholdSigningSessions(baseDeviceNumber);
    }

    await persistSuccessfulLoginState(baseDeviceNumber);

    const loginResult: LoginAndCreateSessionResult = requireThresholdWarmup
      ? {
          success: true,
          loggedInNearAccountId: String(nearAccountId),
          clientNearPublicKey: userData.clientNearPublicKey,
          nearAccountId,
          ...requireThresholdWarmLoginBundle('login'),
        }
      : {
          success: true,
          loggedInNearAccountId: String(nearAccountId),
          clientNearPublicKey: userData.clientNearPublicKey,
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
  return Number.isSafeInteger(deviceNumber) && (deviceNumber as number) >= 1
    ? (deviceNumber as number)
    : fallback;
}

function prioritizeAuthenticatorsByDeviceNumber(
  authenticators: ClientAuthenticatorData[],
  deviceNumber: number | null,
): ClientAuthenticatorData[] {
  if (authenticators.length <= 1) return authenticators;
  if (deviceNumber === null) return authenticators;
  const preferred = authenticators.filter((a) => a.deviceNumber === deviceNumber);
  if (preferred.length === 0) return authenticators;
  const rest = authenticators.filter((a) => a.deviceNumber !== deviceNumber);
  return [...preferred, ...rest];
}

type CanonicalThresholdEcdsaWarmSessionContext = {
  thresholdSessionId: string | null;
  clientVerifyingShareB64u: string | null;
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
  const requested = Array.isArray(signersToWarm) && signersToWarm.length > 0
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
  signersToWarm?: ThresholdLoginWarmSigner[];
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
          participantIds: args.participantIds,
          sessionKind: 'jwt',
          ttlMs: args.ttlMs,
          remainingUses: args.remainingUses,
          sessionId: args.canonicalEcdsaContext.thresholdSessionId || undefined,
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
          await args.signingEngine.bootstrapEcdsaSession({
            nearAccountId: args.nearAccountId,
            chain: 'tempo',
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
export async function getLoginSession(
  context: PasskeyManagerContext,
  nearAccountId?: AccountId,
): Promise<LoginSession> {
  const login = await getLoginStateInternal(context, nearAccountId);
  const signingSession = login?.nearAccountId
    ? await context.signingEngine.getWarmSigningSessionStatus(login.nearAccountId).catch(() => null)
    : null;
  return { login, signingSession };
}

async function resolveThresholdEcdsaEthereumAddress(
  nearAccountId: AccountId,
): Promise<string | null> {
  try {
    const nearContext = await IndexedDBManager.clientDB.resolveNearAccountContext(nearAccountId);
    if (!nearContext?.profileId) return null;

    const chainAccounts = await IndexedDBManager.clientDB.listChainAccountsByProfile(
      nearContext.profileId,
    );
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

function resolveCanonicalThresholdEcdsaWarmSessionContext(
  signingEngine: unknown,
  nearAccountId: AccountId,
): CanonicalThresholdEcdsaWarmSessionContext {
  const getRecord = (
    signingEngine as {
      getThresholdEcdsaSessionRecordForSigning?: (args: {
        nearAccountId: AccountId | string;
        chain?: 'evm' | 'tempo';
      }) => { thresholdSessionId?: string; clientVerifyingShareB64u?: string };
    }
  )?.getThresholdEcdsaSessionRecordForSigning;
  if (typeof getRecord !== 'function') {
    return {
      thresholdSessionId: null,
      clientVerifyingShareB64u: null,
    };
  }
  try {
    const record = getRecord({ nearAccountId });
    const thresholdSessionId = String(record?.thresholdSessionId || '').trim();
    const clientVerifyingShareB64u = String(record?.clientVerifyingShareB64u || '').trim();
    return {
      thresholdSessionId: thresholdSessionId || null,
      clientVerifyingShareB64u: clientVerifyingShareB64u || null,
    };
  } catch {
    return {
      thresholdSessionId: null,
      clientVerifyingShareB64u: null,
    };
  }
}

function resolveThresholdEcdsaGroupPublicKeyB64u(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
): string | null {
  try {
    const record = context.signingEngine.getThresholdEcdsaSessionRecordForSigning({
      nearAccountId,
    });
    const groupPublicKeyB64u = String(record.groupPublicKeyB64u || '').trim();
    return groupPublicKeyB64u || null;
  } catch {
    return null;
  }
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

    if (!lastUser || (targetAccountId && lastUser.nearAccountId !== targetAccountId)) {
      return {
        isLoggedIn: false,
        nearAccountId: targetAccountId || null,
        publicKey: null,
        userData: null,
        thresholdEcdsaEthereumAddress: null,
        thresholdEcdsaGroupPublicKeyB64u: null,
      };
    }

    const userData = lastUser;
    const publicKey = userData?.clientNearPublicKey || null;
    const isLoggedIn = !!(userData && userData.clientNearPublicKey);
    const resolvedNearAccountId = targetAccountId ?? null;

    if (isLoggedIn && shouldRequireThresholdWarmSession(context)) {
      const warmStatus = resolvedNearAccountId
        ? await signingEngine.getWarmSigningSessionStatus(resolvedNearAccountId).catch(() => null)
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
export async function getRecentLogins(
  context: PasskeyManagerContext,
): Promise<GetRecentLoginsResult> {
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
 * Logout: clears last-user pointer and client-side caches.
 */
export async function logoutAndClearSession(context: PasskeyManagerContext): Promise<void> {
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
