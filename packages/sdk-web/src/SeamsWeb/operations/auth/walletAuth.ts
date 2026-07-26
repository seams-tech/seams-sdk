import { toError } from '@shared/utils/errors';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { RouterAbEcdsaDerivationLoginPresignaturePrefillResult } from '@/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefill';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
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
  unlockResolvedWalletSubjectSet as unlockCoreWithSubjectSet,
  lock as lockCore,
  type LockOperationContext,
} from '@/SeamsWeb/operations/auth/login';
import { IndexedDBManager } from '@/core/indexedDB';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type {
  WalletAuthWebContext,
  EcdsaLoginSessionSurface,
  RegistrationAccountSurface,
} from '@/SeamsWeb/signingSurface/types';
import type { WalletIframeCoordinator } from '@/SeamsWeb/walletIframe/coordinator';
import type { WalletIframeExactSessionState } from '@/SeamsWeb/walletIframe/shared/exactSessionState';
import { walletIframeUnlockRequestFromLoginHooks } from '@/SeamsWeb/walletIframe/shared/unlockOptions';
import {
  resolveWalletUnlockSubjectSet,
  type WalletUnlockCapabilityFamilyScope,
  type WalletUnlockSubject,
  type WalletUnlockSubjectSet,
} from './walletUnlockSubject';

type WalletAuthSigningSurface = Pick<
  RegistrationAccountSurface,
  'activateAuthenticatedWalletState'
> &
  EcdsaLoginSessionSurface;

/**
 * SeamsWeb wallet-auth domain call graph:
 * - unlockDomain -> wallet router unlock OR local unlock workflow (`@/SeamsWeb/operations/auth/login`)
 * - getWalletSessionDomain/getRecentUnlocksDomain -> wallet router read path OR local IndexedDB/session read path
 * - lockDomain -> local lock followed by acknowledged wallet-host lock
 */
export type WalletAuthDomainDeps = {
  getContext: () => WalletAuthWebContext;
  walletIframe: Pick<WalletIframeCoordinator, 'shouldUseWalletIframe' | 'requireRouter'>;
  signingEngine: WalletAuthSigningSurface;
  nearClient: NearClient;
  initWalletIframe: (walletId?: string) => Promise<WalletIframeExactSessionState>;
};

export type WalletLockDomainDeps = {
  getContext: () => LockOperationContext;
  walletIframe: {
    shouldUseWalletIframe(): boolean;
    requireRouter(): Promise<{ lock(): Promise<unknown> }>;
  };
};

function walletUnlockCapabilityScope(
  selection: LoginHooksOptions['unlockSelection'] | undefined,
): WalletUnlockCapabilityFamilyScope {
  switch (selection?.mode) {
    case 'ed25519_only':
      return { kind: 'near_ed25519_only' };
    case 'ecdsa_only':
      return { kind: 'evm_family_ecdsa_only' };
    case 'ed25519_and_ecdsa':
    case undefined:
      return { kind: 'all_registered_mpc' };
  }
  throw new Error('wallet unlock selection is unsupported');
}

async function requireWalletUnlockSubjectSet(args: {
  walletId: string;
  selection: LoginHooksOptions['unlockSelection'] | undefined;
}): Promise<WalletUnlockSubjectSet> {
  const resolution = await resolveWalletUnlockSubjectSet({
    walletId: args.walletId,
    requestedCapabilityFamilies: walletUnlockCapabilityScope(args.selection),
  });
  switch (resolution.kind) {
    case 'resolved':
      return resolution.subjectSet;
    case 'missing_requested_capability_subject':
      throw new Error('wallet unlock is missing the requested capability subject');
    case 'capability_subject_resolution_failed':
      throw new Error(`wallet unlock subject resolution failed: ${resolution.reason}`);
  }
  resolution satisfies never;
  throw new Error('wallet unlock subject resolution returned an unknown result');
}

function selectNearSubjectForActivation(
  subjectSet: WalletUnlockSubjectSet,
): Extract<WalletUnlockSubject, { kind: 'near_ed25519_wallet' }> | null {
  let match: Extract<WalletUnlockSubject, { kind: 'near_ed25519_wallet' }> | null = null;
  for (const subject of subjectSet.subjects) {
    if (subject.kind !== 'near_ed25519_wallet') continue;
    if (match) {
      throw new Error('wallet unlock resolved multiple NEAR Ed25519 subjects');
    }
    match = subject;
  }
  return match;
}

export async function unlockDomain(
  deps: WalletAuthDomainDeps,
  walletId: string,
  options?: LoginHooksOptions,
): Promise<LoginAndCreateSessionResult> {
  const resolvedWalletId = String(walletId || '').trim();
  if (!resolvedWalletId) throw new Error('unlock requires walletId');
  if (deps.walletIframe.shouldUseWalletIframe()) {
    try {
      const router = await deps.walletIframe.requireRouter(resolvedWalletId);
      const result = await router.unlock(
        walletIframeUnlockRequestFromLoginHooks({
          walletId: resolvedWalletId,
          options,
        }),
      );
      if (!result.success) {
        const unlockError = new Error(result.error || 'Login failed');
        await options?.onError?.(unlockError);
        await options?.afterCall?.(false, undefined, unlockError);
        return result;
      }
      await deps.initWalletIframe(resolvedWalletId);
      await options?.afterCall?.(true, result);
      return result;
    } catch (error: unknown) {
      const wrappedError = toError(error);
      await options?.onError?.(wrappedError);
      await options?.afterCall?.(false);
      throw wrappedError;
    }
  }

  const subjectSet = await requireWalletUnlockSubjectSet({
    walletId: resolvedWalletId,
    selection: options?.unlockSelection,
  });
  const result = await unlockCoreWithSubjectSet(deps.getContext(), subjectSet, options);
  let activatedWalletId: string | null = null;
  if (result?.success) {
    activatedWalletId = String(subjectSet.walletId);
    const nearSubject = selectNearSubjectForActivation(subjectSet);
    if (nearSubject) {
      await deps.signingEngine.activateAuthenticatedWalletState({
        walletId: nearSubject.walletId,
        nearAccountId: nearSubject.nearAccountId,
        signerSlot: nearSubject.signerSlot,
        nearClient: deps.nearClient,
      });
    }
  }
  await deps.initWalletIframe(activatedWalletId || undefined);

  return result;
}

export async function lockDomain(deps: WalletLockDomainDeps): Promise<void> {
  await lockCore(deps.getContext());
  if (!deps.walletIframe.shouldUseWalletIframe()) return;
  const router = await deps.walletIframe.requireRouter();
  await router.lock();
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

  return await getWalletSessionCore(deps.getContext(), walletId);
}

export async function hasPasskeyCredentialDomain(
  deps: WalletAuthDomainDeps,
  walletId: string,
): Promise<boolean> {
  const resolvedWalletId = String(walletId || '').trim();
  if (!resolvedWalletId) return false;
  if (deps.walletIframe.shouldUseWalletIframe()) {
    const router = await deps.walletIframe.requireRouter();
    return await router.hasPasskeyCredential(resolvedWalletId);
  }

  const records = await IndexedDBManager.listWalletAuthMethodsForWallet(resolvedWalletId).catch(
    () => [],
  );
  return records.some(
    (record) => record.kind === SIGNER_AUTH_METHODS.passkey && record.status === 'active',
  );
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
        walletIds: [],
        accountIds: [],
        lastUsedAccount: null,
      };
    }
  }

  return await getRecentUnlocksCore(deps.getContext());
}

export async function prefillRouterAbEcdsaDerivationPresignaturePoolDomain(
  deps: WalletAuthDomainDeps,
  args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    waitForPoolReady?: boolean;
    poolReadyTimeoutMs?: number;
    poolReadyPollIntervalMs?: number;
    minRemainingUsesBeforePrefill?: number;
  },
): Promise<RouterAbEcdsaDerivationLoginPresignaturePrefillResult> {
  if (deps.walletIframe.shouldUseWalletIframe()) {
    const router = await deps.walletIframe.requireRouter(args.walletSession.walletId);
    return await router.prefillRouterAbEcdsaDerivationPresignaturePool({
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
  return await deps.signingEngine.scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill({
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
