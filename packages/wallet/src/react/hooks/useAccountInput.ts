import { useState, useEffect, useCallback, useRef } from 'react';
import type { SeamsWeb } from '@/SeamsWeb';
import { checkNearAccountExistsBestEffort } from '@/core/rpcClients/near/rpcCalls';
import { awaitWalletIframeReady } from '../utils/walletIframe';
import { isObject } from '@shared/utils/validation';
import { compactImplicitNearAccountId } from '@shared/utils/near';
import {
  isWalletAuthMethod,
  type WalletAuthMethod,
  WALLET_AUTH_METHODS,
} from '@shared/utils/signerDomain';
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
  /** Sponsored named NEAR account target used only by named-account registration. */
  targetAccountId: string;
  /** Wallet identity used for passkey login/session operations. */
  targetWalletId: string;
  displayPostfix: string;
  isUsingExistingAccount: boolean;
  /** On-chain NEAR account existence for sponsored named-account registration. */
  accountExists: boolean;
  /** Local passkey credential existence for wallet-scoped passkey login. */
  passkeyCredentialExists: boolean;
  indexDBAccounts: string[];
  indexDBAccountOptions: StoredAccountOption[];
}

export interface UseAccountInputOptions {
  seams: SeamsWeb;
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

export function extractUsernameFromAccountId(accountId: string | null | undefined): string {
  const normalized = String(accountId || '').trim();
  if (!normalized) return '';
  const compactImplicit = compactImplicitNearAccountId(normalized);
  if (compactImplicit) return compactImplicit;
  return normalized.split('.')[0] || '';
}

function normalizeStoredAccountOptions(input: {
  accounts?: Array<{
    walletId?: string | null;
    nearAccountId?: string | null;
    displayName?: string | null;
    signerSlot?: number;
    lastLogin?: number | null;
    authMethod?: unknown;
  }> | null;
}): StoredAccountOption[] {
  const accounts: Array<{
    walletId?: string | null;
    nearAccountId?: string | null;
    displayName?: string | null;
    signerSlot?: number;
    lastLogin?: number | null;
    authMethod?: unknown;
  }> =
    input.accounts && input.accounts.length > 0 ? input.accounts : [];

  const byWalletAuth = new Map<string, StoredAccountOption>();
  for (const account of accounts) {
    const walletId = String(account.walletId || '').trim();
    if (!walletId) continue;
    const displayName = String(account.displayName || walletId).trim() || walletId;
    const nearAccountId = String(account.nearAccountId || '').trim();
    const authMethod = parseStoredAccountOptionAuthMethod(account.authMethod);
    if (authMethod === null) continue;
    byWalletAuth.set(`${walletId}:${authMethod}:${displayName}`, {
      walletId,
      displayName,
      authMethod,
      ...(nearAccountId ? { nearAccountId } : {}),
      ...(typeof account.signerSlot === 'number' ? { signerSlot: account.signerSlot } : {}),
      ...(typeof account.lastLogin === 'number' ? { lastLogin: account.lastLogin } : {}),
    });
  }
  return [...byWalletAuth.values()];
}

function parseStoredAccountOptionAuthMethod(value: unknown): WalletAuthMethod | null {
  return isWalletAuthMethod(value) ? value : null;
}

function isPasskeyStoredAccountOption(option: StoredAccountOption): boolean {
  return option.authMethod === WALLET_AUTH_METHODS.passkey;
}

export function useAccountInput({
  seams,
  accountDomain,
  currentWalletId,
  isLoggedIn,
}: UseAccountInputOptions): UseAccountInputReturn {
  const [discoveredRelayerAccount, setDiscoveredRelayerAccount] = useState<string>('');
  const accountExistsCheckIdRef = useRef(0);
  const passkeyCredentialExistsCheckIdRef = useRef(0);
  const suppressRefreshAutofillRef = useRef(false);

  // Best-effort: when the host app didn't explicitly configure `relayerAccount`, try to
  // discover it from the Router API `/healthz` response so atomic registration uses the
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
    targetWalletId: '',
    displayPostfix: '',
    isUsingExistingAccount: false,
    accountExists: false,
    passkeyCredentialExists: false,
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
      const storedAccountOptions = normalizeStoredAccountOptions({ accounts });

      const fallbackAccountId = storedAccountOptions[0]?.walletId || '';
      const selectedPrefillAccountId = lastUsedAccount?.walletId || fallbackAccountId;
      const selectedDisplayName =
        lastUsedAccount?.displayName ||
        storedAccountOptions.find((option) => option.walletId === selectedPrefillAccountId)
          ?.displayName ||
        selectedPrefillAccountId;
      const parts = String(selectedDisplayName || '').split('.');
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
          selectedPrefillAccountId
            ? selectedPrefillAccountId
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

  const checkPasskeyCredentialExists = useCallback(
    async (walletId: string) => {
      const checkId = ++passkeyCredentialExistsCheckIdRef.current;
      const candidateWalletId = String(walletId || '').trim();
      if (!candidateWalletId) {
        setState((prevState) =>
          checkId === passkeyCredentialExistsCheckIdRef.current
            ? { ...prevState, passkeyCredentialExists: false }
            : prevState,
        );
        return;
      }

      try {
        if (seams.configs.wallet.mode === 'iframe' && !seams.isWalletIframeReady()) {
          const ready = await awaitWalletIframeIfNeeded();
          if (!ready || !seams.isWalletIframeReady()) return;
        }
        const passkeyExists = await seams.auth.hasPasskeyCredential(candidateWalletId);
        setState((prevState) => {
          if (checkId !== passkeyCredentialExistsCheckIdRef.current) return prevState;
          if (!passkeyExists) return { ...prevState, passkeyCredentialExists: false };
          return {
            ...prevState,
            targetWalletId: candidateWalletId,
            displayPostfix: '',
            isUsingExistingAccount: true,
            passkeyCredentialExists: true,
          };
        });
      } catch (error) {
        console.warn('Error checking passkey credential:', error);
        setState((prevState) =>
          checkId === passkeyCredentialExistsCheckIdRef.current
            ? { ...prevState, passkeyCredentialExists: false }
            : prevState,
        );
      }
    },
    [awaitWalletIframeIfNeeded, seams],
  );

  // Update derived state when inputs change
  const updateDerivedState = useCallback(
    (username: string, accounts: string[], accountOptions: StoredAccountOption[]) => {
      // Normalize the input to avoid iOS autocapitalize breaking wallet/name matching.
      const raw = (username || '').trim();
      const uname = raw.toLowerCase();

      if (!raw) {
        setState((prevState) => ({
          ...prevState,
          targetAccountId: '',
          targetWalletId: '',
          displayPostfix: '',
          isUsingExistingAccount: false,
          accountExists: false,
          passkeyCredentialExists: false,
        }));
        return;
      }

      // If the user typed a full accountId, don't append any postfix.
      const typedFullAccountId = uname.includes('.');
      const derivedTarget = typedFullAccountId
        ? uname
        : normalizedDomain
          ? `${uname}.${normalizedDomain}`
          : uname;
      const existingOption = accountOptions.find((option) => {
        const walletId = String(option.walletId || '').trim().toLowerCase();
        const displayName = String(option.displayName || '').trim().toLowerCase();
        return walletId === uname || displayName === uname;
      });
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

      const existingAccount = derivedStoredMatch || usernameFallbackMatch;

      let targetAccountId: string;
      let targetWalletId: string;
      let displayPostfix: string;
      let isUsingExistingAccount: boolean;

      if (existingOption) {
        targetWalletId = existingOption.walletId;
        targetAccountId = String(existingOption.nearAccountId || '');
        displayPostfix = '';
        isUsingExistingAccount = true;
      } else if (existingAccount) {
        targetWalletId = '';
        targetAccountId = existingAccount;
        const parts = existingAccount.split('.');
        displayPostfix = typedFullAccountId ? '' : `.${parts.slice(1).join('.')}`;
        isUsingExistingAccount = true;
      } else {
        targetWalletId = '';
        targetAccountId = derivedTarget;
        displayPostfix = !typedFullAccountId && normalizedDomain ? `.${normalizedDomain}` : '';
        isUsingExistingAccount = false;
      }

      setState((prevState) => ({
        ...prevState,
        targetAccountId,
        targetWalletId,
        displayPostfix,
        isUsingExistingAccount,
        passkeyCredentialExists: existingOption
          ? isPasskeyStoredAccountOption(existingOption)
          : false,
      }));

      if (!existingOption) void checkPasskeyCredentialExists(uname);
      void checkAccountExists(targetAccountId);
    },
    [checkAccountExists, checkPasskeyCredentialExists, normalizedDomain],
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
        const storedAccountOptions = normalizeStoredAccountOptions({
          accounts: recentUnlocks.accounts ?? [],
        });
        const prefillAccountId =
          lastUsedAccount?.walletId || storedAccountOptions[0]?.walletId || '';
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
          const storedAccountOptions = normalizeStoredAccountOptions({
            accounts: recentUnlocks.accounts ?? [],
          });
          const prefillAccountId =
            lastUsedAccount?.walletId || storedAccountOptions[0]?.walletId || '';
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
    updateDerivedState(state.inputUsername, state.indexDBAccounts, state.indexDBAccountOptions);
  }, [state.inputUsername, state.indexDBAccounts, state.indexDBAccountOptions, updateDerivedState]);

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
