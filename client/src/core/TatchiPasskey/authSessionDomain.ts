import { toError } from '@shared/utils/errors';
import type { NearClient } from '../near/NearClient';
import type { WebAuthnManager } from '../signing/api/WebAuthnManager';
import type { AccountId } from '../types/accountIds';
import { toAccountId } from '../types/accountIds';
import type { LoginHooksOptions } from '../types/sdkSentEvents';
import type {
  GetRecentLoginsResult,
  LoginAndCreateSessionResult,
  LoginSession,
} from '../types/tatchi';
import {
  getLoginSession as getLoginSessionCore,
  getRecentLogins as getRecentLoginsCore,
  loginAndCreateSession as loginAndCreateSessionCore,
  logoutAndClearSession as logoutAndClearSessionCore,
} from './login';
import type { PasskeyManagerContext } from './index';
import type { WalletIframeCoordinator } from './walletIframeCoordinator';

/**
 * TatchiPasskey auth/session domain call graph:
 * - loginAndCreateSessionDomain -> wallet router login OR local login workflow (`./login`)
 * - getLoginSessionDomain/getRecentLoginsDomain -> wallet router read path OR local IndexedDB/session read path
 * - logoutAndClearSessionDomain -> local logout + best-effort wallet-host logout
 */
export type AuthSessionDomainDeps = {
  getContext: () => PasskeyManagerContext;
  walletIframe: Pick<WalletIframeCoordinator, 'shouldUseWalletIframe' | 'requireRouter'>;
  webAuthnManager: WebAuthnManager;
  nearClient: NearClient;
  initWalletIframe: (nearAccountId?: string) => Promise<void>;
};

export async function loginAndCreateSessionDomain(
  deps: AuthSessionDomainDeps,
  nearAccountId: string,
  options?: LoginHooksOptions,
): Promise<LoginAndCreateSessionResult> {
  if (deps.walletIframe.shouldUseWalletIframe()) {
    try {
      const router = await deps.walletIframe.requireRouter(nearAccountId);
      const result = await router.loginAndCreateSession({
        nearAccountId,
        options: {
          onEvent: options?.onEvent,
          deviceNumber: options?.deviceNumber,
          // Pass through session so the wallet host calls relay to mint JWT/cookie sessions.
          session: options?.session,
          signingSession: options?.signingSession,
        },
      });
      // Best-effort warm-up after successful login (non-blocking).
      void (async () => {
        try {
          await deps.initWalletIframe(nearAccountId);
        } catch {}
      })();
      await options?.afterCall?.(true, result);
      return result;
    } catch (error: unknown) {
      const wrappedError = toError(error);
      await options?.onError?.(wrappedError);
      await options?.afterCall?.(false);
      throw wrappedError;
    }
  }

  const result = await loginAndCreateSessionCore(
    deps.getContext(),
    toAccountId(nearAccountId),
    options,
  );
  if (result?.success) {
    // Promote authenticated account to current-user state only after login succeeds.
    await deps.webAuthnManager.indexedDbRegistration.initializeCurrentUser(
      toAccountId(nearAccountId),
      deps.nearClient,
    );
  }
  // Best-effort warm-up after successful login (non-blocking).
  try {
    void deps.initWalletIframe(nearAccountId);
  } catch {}

  return result;
}

export async function logoutAndClearSessionDomain(
  deps: AuthSessionDomainDeps,
): Promise<void> {
  await logoutAndClearSessionCore(deps.getContext());
  if (!deps.walletIframe.shouldUseWalletIframe()) return;
  try {
    const router = await deps.walletIframe.requireRouter();
    await router.logout?.();
  } catch {}
}

export async function getLoginSessionDomain(
  deps: AuthSessionDomainDeps,
  nearAccountId?: string,
): Promise<LoginSession> {
  if (deps.walletIframe.shouldUseWalletIframe()) {
    const router = await deps.walletIframe.requireRouter(nearAccountId);
    const session = await router.getLoginSession(nearAccountId);
    try {
      await router.prefetchBlockheight();
    } catch {}
    return session;
  }

  return await getLoginSessionCore(
    deps.getContext(),
    nearAccountId ? toAccountId(nearAccountId) : undefined,
  );
}

export async function hasPasskeyCredentialDomain(
  deps: AuthSessionDomainDeps,
  nearAccountId: AccountId,
): Promise<boolean> {
  if (deps.walletIframe.shouldUseWalletIframe()) {
    const router = await deps.walletIframe.requireRouter();
    return await router.hasPasskeyCredential(nearAccountId);
  }

  const baseAccountId = toAccountId(nearAccountId);
  return await deps.webAuthnManager.indexedDbRegistration.hasPasskeyCredential(baseAccountId);
}

export async function getRecentLoginsDomain(
  deps: AuthSessionDomainDeps,
): Promise<GetRecentLoginsResult> {
  // In iframe mode, do not fall back to app-origin IndexedDB.
  if (deps.walletIframe.shouldUseWalletIframe()) {
    try {
      const router = await deps.walletIframe.requireRouter();
      return await router.getRecentLogins();
    } catch {
      return {
        accountIds: [],
        lastUsedAccount: null,
      };
    }
  }

  return await getRecentLoginsCore(deps.getContext());
}
