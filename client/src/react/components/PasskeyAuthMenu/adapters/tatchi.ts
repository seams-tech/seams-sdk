import { useTatchi } from '@/react/context';
import type { TatchiPasskey } from '@/core/TatchiPasskey';
import { type SDKFlowRuntime, type StoredAccountOption } from '@/react/types';

export interface PasskeyAuthMenuRuntime {
  tatchiPasskey: TatchiPasskey;
  accountExists: boolean;
  inputUsername: string;
  targetAccountId: string;
  accountOptions?: StoredAccountOption[];
  setInputUsername: (v: string) => void;
  refreshLoginState: (nearAccountId?: string) => Promise<void>;
  sdkFlow: SDKFlowRuntime;
  displayPostfix?: string;
  isUsingExistingAccount?: boolean;
  stopDevice2LinkingFlow?: () => Promise<void>;
}

export function usePasskeyAuthMenuRuntime(): PasskeyAuthMenuRuntime {
  const ctx = useTatchi();
  const accountExists = !!ctx.accountInputState?.accountExists;
  return {
    tatchiPasskey: ctx.tatchi,
    accountExists,
    inputUsername: ctx.accountInputState?.inputUsername ?? '',
    targetAccountId: ctx.accountInputState?.targetAccountId ?? '',
    accountOptions:
      ctx.accountInputState?.indexDBAccountOptions ??
      (ctx.accountInputState?.indexDBAccounts ?? []).map((nearAccountId) => ({ nearAccountId })),
    setInputUsername: ctx.setInputUsername,
    refreshLoginState: ctx.refreshLoginState,
    sdkFlow: ctx.sdkFlow,
    displayPostfix: ctx.accountInputState?.displayPostfix,
    isUsingExistingAccount: ctx.accountInputState?.isUsingExistingAccount,
    stopDevice2LinkingFlow: ctx.stopDevice2LinkingFlow,
  };
}

export default usePasskeyAuthMenuRuntime;
