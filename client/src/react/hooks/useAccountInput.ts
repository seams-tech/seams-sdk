import { useState, useEffect, useCallback, useRef } from 'react';
import type { SeamsPasskey } from '@/core/SeamsPasskey';
import { checkNearAccountExistsBestEffort } from '@/core/rpcClients/near/rpcCalls';
import { awaitWalletIframeReady } from '../utils/walletIframe';
import { isObject } from '@shared/utils/validation';
import type { StoredAccountOption } from '../types';

async function discoverRelayerAccountFromHealthz(relayUrl: string): Promise<string | null> {
  const base = String(relayUrl || '')
    .trim()
    .replace(/\/$/, '');
  if (!base) return null;

  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), 1500) : null;

  try {
    const res = await fetch(`${base}/healthz`, {
      method: 'GET',
      ...(controller ? { signal: controller.signal } : {}),
    });
    if (!res.ok) return null;
    const jsonData: unknown = await res.json().catch(() => ({}));
    const json = isObject(jsonData) ? jsonData : {};
    const relayerAccount = typeof json.relayerAccount === 'string' ? json.relayerAccount : '';
    const normalized = String(relayerAccount).trim().replace(/^\./, '').toLowerCase();
    return normalized || null;
  } catch {
    return null;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export interface AccountInputState {
  inputUsername: string;
  lastLoggedInUsername: string;
  lastLoggedInDomain: string;
  targetAccountId: string;
  displayPostfix: string;
  isUsingExistingAccount: boolean;
  accountExists: boolean;
  indexDBAccounts: string[];
  indexDBAccountOptions: StoredAccountOption[];
}

export interface UseAccountInputOptions {
  seams: SeamsPasskey;
  /**
   * Account domain/postfix used to derive full accountIds from a username input
   * (e.g. `w3a-relayer.testnet` for `alice.w3a-relayer.testnet`).
   */
  accountDomain?: string;
  currentWalletId?: string | null;
  isLoggedIn: boolean;
}

export interface UseAccountInputReturn extends AccountInputState {
  setInputUsername: (username: string) => void;
  refreshAccountData: () => Promise<void>;
}

function extractUsernameFromAccountId(accountId: string | null | undefined): string {
  const normalized = String(accountId || '').trim();
  if (!normalized) return '';
  return normalized.split('.')[0] || '';
}

function normalizeStoredAccountOptions(input: {
  accountIds?: string[];
  accounts?: Array<{
    nearAccountId?: string | null;
    signerSlot?: number;
    authMethod?: StoredAccountOption['authMethod'];
  }> | null;
}): StoredAccountOption[] {
  const accounts: Array<{
    nearAccountId?: string | null;
    signerSlot?: number;
    authMethod?: StoredAccountOption['authMethod'];
  }> =
    input.accounts && input.accounts.length > 0
      ? input.accounts
      : (input.accountIds ?? []).map((nearAccountId) => ({ nearAccountId }));

  const byAccountId = new Map<string, StoredAccountOption>();
  for (const account of accounts) {
    const nearAccountId = String(account.nearAccountId || '').trim();
    if (!nearAccountId) continue;
    const authMethodKey = account.authMethod || 'passkey';
    byAccountId.set(`${nearAccountId}:${authMethodKey}`, {
      nearAccountId,
      ...(typeof account.signerSlot === 'number' ? { signerSlot: account.signerSlot } : {}),
      ...(account.authMethod ? { authMethod: account.authMethod } : {}),
    });
  }
  return [...byAccountId.values()];
}

export function useAccountInput({
  seams,
  accountDomain,
  currentWalletId,
  isLoggedIn,
}: UseAccountInputOptions): UseAccountInputReturn {
  const [discoveredRelayerAccount, setDiscoveredRelayerAccount] = useState<string>('');
  const accountExistsCheckIdRef = useRef(0);
  const suppressRefreshAutofillRef = useRef(false);

  // Best-effort: when the host app didn't explicitly configure `relayerAccount`, try to
  // discover it from the relay's `/healthz` response so atomic registration uses the
  // correct accountId postfix.
  useEffect(() => {
    const hasExplicitDomain = typeof accountDomain === 'string' && accountDomain.trim().length > 0;
    if (hasExplicitDomain) return;

    const cfgRelayer = String(seams.configs.network.relayer.accountId || '')
      .trim()
      .replace(/^\./, '')
      .toLowerCase();
    if (cfgRelayer) return;

    const relayUrl = String(seams.configs.network.relayer?.url || '').trim();
    if (!relayUrl) return;

    let cancelled = false;
    void (async () => {
      const discovered = await discoverRelayerAccountFromHealthz(relayUrl);
      if (cancelled || !discovered) return;
      setDiscoveredRelayerAccount(discovered);
    })();
    return () => {
      cancelled = true;
    };
  }, [accountDomain, seams]);

  const normalizedDomain = (
    accountDomain ||
    discoveredRelayerAccount ||
    seams.configs.network.relayer.accountId ||
    ''
  )
    .trim()
    .replace(/^\./, '')
    .toLowerCase();

  const [state, setState] = useState<AccountInputState>({
    inputUsername: '',
    lastLoggedInUsername: '',
    lastLoggedInDomain: '',
    targetAccountId: '',
    displayPostfix: '',
    isUsingExistingAccount: false,
    accountExists: false,
    indexDBAccounts: [],
    indexDBAccountOptions: [],
  });

  // Await wallet iframe readiness when needed
  const awaitWalletIframeIfNeeded = useCallback(async () => {
    if (seams.configs.wallet.mode !== 'iframe') return true;
    return await awaitWalletIframeReady(seams);
  }, [seams]);

  // Load recent accounts and determine account info
  const refreshAccountData = useCallback(async () => {
    try {
      await awaitWalletIframeIfNeeded();
      const recentUnlocks = await seams.auth.getRecentUnlocks();
      const accountIds = recentUnlocks.accountIds ?? [];
      const accounts = recentUnlocks.accounts ?? [];
      const lastUsedAccount = recentUnlocks.lastUsedAccount ?? null;
      const storedAccountOptions = normalizeStoredAccountOptions({ accountIds, accounts });

      const fallbackAccountId = accountIds[0] || '';
      const selectedPrefillAccountId = lastUsedAccount?.nearAccountId || fallbackAccountId;
      const parts = String(selectedPrefillAccountId || '').split('.');
      const lastUsername = parts[0] || '';
      const lastDomain = parts.length > 1 ? `.${parts.slice(1).join('.')}` : '';

      setState((prevState) => ({
        ...prevState,
        indexDBAccounts: accountIds,
        indexDBAccountOptions: storedAccountOptions,
        lastLoggedInUsername: lastUsername,
        lastLoggedInDomain: lastDomain,
        inputUsername:
          !suppressRefreshAutofillRef.current &&
          prevState.inputUsername.trim().length === 0 &&
          lastUsername
            ? lastUsername
            : prevState.inputUsername,
      }));
    } catch (error) {
      console.warn('Error loading account data:', error);
    }
  }, [awaitWalletIframeIfNeeded, seams]);

  // Check whether the account currently exists on-chain.
  // Registration availability should not be blocked by a stale local passkey.
  const checkAccountExists = useCallback(
    async (accountId: string) => {
      const checkId = ++accountExistsCheckIdRef.current;
      if (!accountId) {
        setState((prevState) =>
          checkId === accountExistsCheckIdRef.current
            ? { ...prevState, accountExists: false }
            : prevState,
        );
        return;
      }

      try {
        if (seams.configs.wallet.mode === 'iframe' && !seams.isWalletIframeReady()) {
          const ready = await awaitWalletIframeIfNeeded();
          if (!ready || !seams.isWalletIframeReady()) {
            // Avoid writing a false-negative while iframe auth surface is still booting.
            return;
          }
        }
        const accountExistsOnChain = await checkNearAccountExistsBestEffort(
          seams.getContext().nearClient,
          accountId,
        );
        setState((prevState) =>
          checkId === accountExistsCheckIdRef.current
            ? { ...prevState, accountExists: accountExistsOnChain }
            : prevState,
        );
      } catch (error) {
        console.warn('Error checking credentials:', error);
        setState((prevState) =>
          checkId === accountExistsCheckIdRef.current
            ? { ...prevState, accountExists: false }
            : prevState,
        );
      }
    },
    [awaitWalletIframeIfNeeded, seams],
  );

  // Update derived state when inputs change
  const updateDerivedState = useCallback(
    (username: string, accounts: string[]) => {
      // Normalize username to lowercase to avoid iOS autocapitalize causing invalid NEAR IDs
      const raw = (username || '').trim();
      const uname = raw.toLowerCase();

      if (!raw) {
        setState((prevState) => ({
          ...prevState,
          targetAccountId: '',
          displayPostfix: '',
          isUsingExistingAccount: false,
          accountExists: false,
        }));
        return;
      }

      // If user types a full accountId (or selects one via custom UI), prefer it when present in storage.
      const accountByExactInput = accounts.find((accountId) => accountId.toLowerCase() === uname);

      // If the user typed a full accountId, don't append any postfix.
      const typedFullAccountId = uname.includes('.');
      const derivedTarget = typedFullAccountId
        ? uname
        : normalizedDomain
          ? `${uname}.${normalizedDomain}`
          : uname;
      const derivedStoredMatch = accounts.find(
        (accountId) => accountId.toLowerCase() === derivedTarget,
      );

      // Username-only fallback:
      // - If a single stored account matches `${username}.<domain>`, use it.
      // - If multiple match, only auto-select the one that matches configured domain.
      // This preserves multi-domain safety while restoring expected recent-account resolution.
      const usernameMatches = typedFullAccountId
        ? []
        : accounts.filter((accountId) => accountId.toLowerCase().startsWith(`${uname}.`));
      const usernameMatchByConfiguredDomain =
        normalizedDomain && usernameMatches.length > 1
          ? usernameMatches.find((accountId) =>
              accountId.toLowerCase().endsWith(`.${normalizedDomain}`),
            )
          : undefined;
      const uniqueUsernameMatch = usernameMatches.length === 1 ? usernameMatches[0] : undefined;
      const usernameFallbackMatch = usernameMatchByConfiguredDomain || uniqueUsernameMatch;

      const existingAccount = accountByExactInput || derivedStoredMatch || usernameFallbackMatch;

      let targetAccountId: string;
      let displayPostfix: string;
      let isUsingExistingAccount: boolean;

      if (existingAccount) {
        // Use existing account's full ID
        targetAccountId = existingAccount;
        const parts = existingAccount.split('.');
        // If the user typed the full accountId, don't show an extra postfix overlay.
        displayPostfix = accountByExactInput ? '' : `.${parts.slice(1).join('.')}`;
        isUsingExistingAccount = true;
      } else {
        targetAccountId = derivedTarget;
        displayPostfix = !typedFullAccountId && normalizedDomain ? `.${normalizedDomain}` : '';
        isUsingExistingAccount = false;
      }

      setState((prevState) => ({
        ...prevState,
        targetAccountId,
        displayPostfix,
        isUsingExistingAccount,
      }));

      // Check if account has credentials
      void checkAccountExists(targetAccountId);
    },
    [checkAccountExists, normalizedDomain],
  );

  // Handle username input changes
  const setInputUsername = useCallback(
    (username: string) => {
      const uname = (username || '').toLowerCase();
      suppressRefreshAutofillRef.current = uname.trim().length === 0;
      setState((prevState) => ({ ...prevState, inputUsername: uname }));
    },
    [],
  );

  // onInitialMount: Load last logged in user and prefill
  useEffect(() => {
    const initializeAccountInput = async () => {
      await refreshAccountData();

      if (isLoggedIn && currentWalletId) {
        // User is logged in, show their username
        const username = extractUsernameFromAccountId(currentWalletId);
        setState((prevState) => ({ ...prevState, inputUsername: username }));
      } else {
        // No logged-in user, try to get last used account
        await awaitWalletIframeIfNeeded();
        const recentUnlocks = await seams.auth.getRecentUnlocks();
        const lastUsedAccount = recentUnlocks.lastUsedAccount ?? null;
        const accountIds = recentUnlocks.accountIds ?? [];
        const prefillAccountId = lastUsedAccount?.nearAccountId || accountIds?.[0] || '';
        if (prefillAccountId) {
          const username = extractUsernameFromAccountId(prefillAccountId);
          setState((prevState) => ({ ...prevState, inputUsername: username }));
        }
      }
    };

    initializeAccountInput();
  }, [awaitWalletIframeIfNeeded, currentWalletId, isLoggedIn, refreshAccountData, seams]);

  // onLock: reset to last used account
  useEffect(() => {
    const handleLockReset = async () => {
      // Only reset if user just locked (isLoggedIn is false but we had a wallet id before)
      if (!isLoggedIn && !currentWalletId) {
        try {
          await awaitWalletIframeIfNeeded();
          const recentUnlocks = await seams.auth.getRecentUnlocks();
          const lastUsedAccount = recentUnlocks.lastUsedAccount ?? null;
          const accountIds = recentUnlocks.accountIds ?? [];
          const prefillAccountId = lastUsedAccount?.nearAccountId || accountIds?.[0] || '';
          if (prefillAccountId) {
            const username = extractUsernameFromAccountId(prefillAccountId);
            setState((prevState) => ({ ...prevState, inputUsername: username }));
          }
        } catch (error) {
          console.warn('Error resetting username after lock:', error);
        }
      }
    };

    handleLockReset();
  }, [awaitWalletIframeIfNeeded, currentWalletId, isLoggedIn, seams]);

  // Update derived state when dependencies change
  useEffect(() => {
    updateDerivedState(state.inputUsername, state.indexDBAccounts);
  }, [state.inputUsername, state.indexDBAccounts, updateDerivedState]);

  // In iframe mode, account existence checks can race wallet boot.
  // Re-run checks once iframe becomes ready so login state is accurate.
  useEffect(() => {
    if (seams.configs.wallet.mode !== 'iframe') return;
    const offReady = seams.onWalletIframeReady(() => {
      void refreshAccountData();
      const target = String(state.targetAccountId || '').trim();
      if (target) {
        void checkAccountExists(target);
      }
    });
    return () => {
      offReady();
    };
  }, [checkAccountExists, refreshAccountData, state.targetAccountId, seams]);

  return {
    ...state,
    setInputUsername,
    refreshAccountData,
  };
}
