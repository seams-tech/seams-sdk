import { toError } from '@shared/utils/errors';
import type { NearClient } from '../rpcClients/near/NearClient';
import type {
  SigningEnginePublic,
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaLoginPrefillResult,
} from '../signingEngine/SigningEngine';
import type { AccountId } from '../types/accountIds';
import { toAccountId } from '../types/accountIds';
import type { LoginHooksOptions } from '../types/sdkSentEvents';
import type {
  GetRecentUnlocksResult,
  LoginAndCreateSessionResult,
  WalletSession,
} from '../types/seams';
import {
  getWalletSession as getWalletSessionCore,
  getRecentUnlocks as getRecentUnlocksCore,
  unlock as unlockCore,
  lock as lockCore,
} from './login';
import type { PasskeyManagerContext } from './index';
import type { WalletIframeCoordinator } from './walletIframeCoordinator';

/**
 * SeamsPasskey auth/session domain call graph:
 * - unlockDomain -> wallet router unlock OR local unlock workflow (`./login`)
 * - getWalletSessionDomain/getRecentUnlocksDomain -> wallet router read path OR local IndexedDB/session read path
 * - lockDomain -> local lock + best-effort wallet-host lock
 */
export type AuthSessionDomainDeps = {
  getContext: () => PasskeyManagerContext;
  walletIframe: Pick<WalletIframeCoordinator, 'shouldUseWalletIframe' | 'requireRouter'>;
  signingEngine: SigningEnginePublic;
  nearClient: NearClient;
  initWalletIframe: (nearAccountId?: string) => Promise<void>;
};

export async function unlockDomain(
  deps: AuthSessionDomainDeps,
  nearAccountId: string,
  options?: LoginHooksOptions,
): Promise<LoginAndCreateSessionResult> {
  if (deps.walletIframe.shouldUseWalletIframe()) {
    try {
      const router = await deps.walletIframe.requireRouter(nearAccountId);
      const result = await router.unlock({
        nearAccountId,
        options: {
          onEvent: options?.onEvent,
          signerSlot: options?.signerSlot,
          // Pass through session so the wallet host calls relay to mint JWT/cookie sessions.
          session: options?.session,
          signingSession: options?.signingSession,
        },
      });
      // Best-effort warm-up after successful unlock (non-blocking).
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

  const result = await unlockCore(
    deps.getContext(),
    toAccountId(nearAccountId),
    options,
  );
  if (result?.success) {
    // Promote authenticated account to current-user state only after unlock succeeds.
    await deps.signingEngine.initializeCurrentUser(toAccountId(nearAccountId), deps.nearClient);
  }
  // Best-effort warm-up after successful unlock (non-blocking).
  try {
    void deps.initWalletIframe(nearAccountId);
  } catch {}

  return result;
}

export async function lockDomain(deps: AuthSessionDomainDeps): Promise<void> {
  await lockCore(deps.getContext());
  if (!deps.walletIframe.shouldUseWalletIframe()) return;
  try {
    const router = await deps.walletIframe.requireRouter();
    await router.lock?.();
  } catch {}
}

export async function getWalletSessionDomain(
  deps: AuthSessionDomainDeps,
  nearAccountId?: string,
): Promise<WalletSession> {
  if (deps.walletIframe.shouldUseWalletIframe()) {
    const router = await deps.walletIframe.requireRouter(nearAccountId);
    const session = await router.getWalletSession(nearAccountId);
    try {
      await router.prefetchBlockheight();
    } catch {}
    return session;
  }

  return await getWalletSessionCore(
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
  return await deps.signingEngine.hasPasskeyCredential(baseAccountId);
}

export async function getRecentUnlocksDomain(
  deps: AuthSessionDomainDeps,
): Promise<GetRecentUnlocksResult> {
  // In iframe mode, do not fall back to app-origin IndexedDB.
  if (deps.walletIframe.shouldUseWalletIframe()) {
    try {
      const router = await deps.walletIframe.requireRouter();
      return await router.getRecentUnlocks();
    } catch {
      return {
        accountIds: [],
        lastUsedAccount: null,
      };
    }
  }

  return await getRecentUnlocksCore(deps.getContext());
}

export async function prefillThresholdEcdsaPresignPoolDomain(
  deps: AuthSessionDomainDeps,
  args: {
    nearAccountId: string;
    chain: ThresholdEcdsaActivationChain;
    waitForPoolReady?: boolean;
    poolReadyTimeoutMs?: number;
    poolReadyPollIntervalMs?: number;
    minRemainingUsesBeforePrefill?: number;
  },
): Promise<ThresholdEcdsaLoginPrefillResult> {
  const chain = args.chain;

  if (deps.walletIframe.shouldUseWalletIframe()) {
    const router = await deps.walletIframe.requireRouter(args.nearAccountId);
    return await router.prefillThresholdEcdsaPresignPool({
      nearAccountId: args.nearAccountId,
      options: {
        chain,
        ...(typeof args.waitForPoolReady === 'boolean'
          ? { waitForPoolReady: args.waitForPoolReady }
          : {}),
        ...(typeof args.poolReadyTimeoutMs === 'number'
          ? { poolReadyTimeoutMs: args.poolReadyTimeoutMs }
          : {}),
        ...(typeof args.poolReadyPollIntervalMs === 'number'
          ? { poolReadyPollIntervalMs: args.poolReadyPollIntervalMs }
          : {}),
        ...(typeof args.minRemainingUsesBeforePrefill === 'number'
          ? { minRemainingUsesBeforePrefill: args.minRemainingUsesBeforePrefill }
          : {}),
      },
    });
  }

  const nearAccountId = toAccountId(args.nearAccountId);
  const keyRef = deps.signingEngine.getThresholdEcdsaKeyRefForLookup({
    nearAccountId,
    chain,
    source: 'login',
  });
  return await deps.signingEngine.scheduleThresholdEcdsaLoginPresignPrefill({
    nearAccountId,
    chain,
    thresholdEcdsaKeyRef: keyRef,
    ...(typeof args.waitForPoolReady === 'boolean'
      ? { waitForPoolReady: args.waitForPoolReady }
      : {}),
    ...(typeof args.poolReadyTimeoutMs === 'number'
      ? { poolReadyTimeoutMs: args.poolReadyTimeoutMs }
      : {}),
    ...(typeof args.poolReadyPollIntervalMs === 'number'
      ? { poolReadyPollIntervalMs: args.poolReadyPollIntervalMs }
      : {}),
    ...(typeof args.minRemainingUsesBeforePrefill === 'number'
      ? { minRemainingUsesBeforePrefill: args.minRemainingUsesBeforePrefill }
      : {}),
  });
}
