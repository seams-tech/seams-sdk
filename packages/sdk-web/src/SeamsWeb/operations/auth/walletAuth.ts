import { toError } from '@shared/utils/errors';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { RouterAbEcdsaHssLoginPresignaturePrefillResult } from '@/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefill';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import type { LoginHooksOptions } from '@/core/types/sdkSentEvents';
import type {
  GetRecentUnlocksResult,
  LoginAndCreateSessionResult,
  WalletSession,
} from '@/core/types/seams';
import type { WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  getWalletSession as getWalletSessionCore,
  getRecentUnlocks as getRecentUnlocksCore,
  unlock as unlockCore,
  lock as lockCore,
} from '@/SeamsWeb/operations/auth/login';
import type {
  WalletAuthWebContext,
  EcdsaLoginSessionSurface,
  RegistrationAccountSurface,
} from '@/SeamsWeb/signingSurface/types';
import type { WalletIframeCoordinator } from '@/SeamsWeb/walletIframe/coordinator';
import { walletIframeUnlockRequestFromLoginHooks } from '@/SeamsWeb/walletIframe/shared/unlockOptions';

type WalletAuthSigningSurface = Pick<
  RegistrationAccountSurface,
  'activateAuthenticatedWalletState' | 'hasPasskeyCredential'
> &
  EcdsaLoginSessionSurface;

/**
 * SeamsWeb wallet-auth domain call graph:
 * - unlockDomain -> wallet router unlock OR local unlock workflow (`@/SeamsWeb/operations/auth/login`)
 * - getWalletSessionDomain/getRecentUnlocksDomain -> wallet router read path OR local IndexedDB/session read path
 * - lockDomain -> local lock + best-effort wallet-host lock
 */
export type WalletAuthDomainDeps = {
  getContext: () => WalletAuthWebContext;
  walletIframe: Pick<WalletIframeCoordinator, 'shouldUseWalletIframe' | 'requireRouter'>;
  signingEngine: WalletAuthSigningSurface;
  nearClient: NearClient;
  initWalletIframe: (walletId?: string) => Promise<void>;
};

export async function unlockDomain(
  deps: WalletAuthDomainDeps,
  nearAccountId: string,
  options?: LoginHooksOptions,
): Promise<LoginAndCreateSessionResult> {
  if (deps.walletIframe.shouldUseWalletIframe()) {
    try {
      const router = await deps.walletIframe.requireRouter(nearAccountId);
      const result = await router.unlock(
        walletIframeUnlockRequestFromLoginHooks({
          nearAccountId,
          options,
        }),
      );
      if (!result.success) {
        const unlockError = new Error(result.error || 'Login failed');
        await options?.onError?.(unlockError);
        await options?.afterCall?.(false, undefined, unlockError);
        return result;
      }
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

  const result = await unlockCore(deps.getContext(), toAccountId(nearAccountId), options);
  if (result?.success) {
    // Promote authenticated account to current-user state only after unlock succeeds.
    await deps.signingEngine.activateAuthenticatedWalletState({
      nearAccountId: toAccountId(nearAccountId),
      nearClient: deps.nearClient,
    });
  }
  // Best-effort warm-up after successful unlock (non-blocking).
  try {
    void deps.initWalletIframe(nearAccountId);
  } catch {}

  return result;
}

export async function lockDomain(deps: WalletAuthDomainDeps): Promise<void> {
  await lockCore(deps.getContext());
  if (!deps.walletIframe.shouldUseWalletIframe()) return;
  try {
    const router = await deps.walletIframe.requireRouter();
    await router.lock?.();
  } catch {}
}

export async function getWalletSessionDomain(
  deps: WalletAuthDomainDeps,
  walletId?: string,
): Promise<WalletSession> {
  if (deps.walletIframe.shouldUseWalletIframe()) {
    const router = await deps.walletIframe.requireRouter(walletId);
    const session = await router.getWalletSession(walletId);
    try {
      await router.prefetchBlockheight();
    } catch {}
    return session;
  }

  return await getWalletSessionCore(
    deps.getContext(),
    walletId ? toAccountId(walletId) : undefined,
  );
}

export async function hasPasskeyCredentialDomain(
  deps: WalletAuthDomainDeps,
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
  deps: WalletAuthDomainDeps,
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

export async function prefillRouterAbEcdsaHssPresignaturePoolDomain(
  deps: WalletAuthDomainDeps,
  args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    waitForPoolReady?: boolean;
    poolReadyTimeoutMs?: number;
    poolReadyPollIntervalMs?: number;
    minRemainingUsesBeforePrefill?: number;
  },
): Promise<RouterAbEcdsaHssLoginPresignaturePrefillResult> {
  if (deps.walletIframe.shouldUseWalletIframe()) {
    const router = await deps.walletIframe.requireRouter(args.walletSession.walletId);
    return await router.prefillRouterAbEcdsaHssPresignaturePool({
      walletSession: args.walletSession,
      options: {
        chainTarget: args.chainTarget,
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

  const ecdsaRecords = deps.signingEngine.listThresholdEcdsaSessionRecordsForWalletTarget({
    walletId: args.walletSession.walletId,
    chainTarget: args.chainTarget,
    source: 'login',
  });
  if (ecdsaRecords.length !== 1) {
    throw new Error(
      ecdsaRecords.length > 1
        ? `[SeamsWeb] ambiguous threshold ECDSA session record for wallet ${String(args.walletSession.walletId)} ${thresholdEcdsaChainTargetKey(args.chainTarget)}`
        : `[SeamsWeb] missing threshold ECDSA session record for wallet ${String(args.walletSession.walletId)} ${thresholdEcdsaChainTargetKey(args.chainTarget)}`,
    );
  }
  const record = ecdsaRecords[0]!;
  return await deps.signingEngine.scheduleRouterAbEcdsaHssLoginPresignaturePrefill({
    walletId: toWalletId(args.walletSession.walletId),
    chainTarget: record.chainTarget,
    thresholdEcdsaSessionRecord: record,
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
