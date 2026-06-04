import { useSeams } from '@/react/context';
import type { SeamsWeb } from '@/web/SeamsWeb';
import { type SDKFlowRuntime, type StoredAccountOption } from '@/react/types';

export interface PasskeyAuthMenuRuntime {
  seamsWeb: SeamsWeb;
  accountExists: boolean;
  inputUsername: string;
  targetAccountId: string;
  accountOptions?: StoredAccountOption[];
  setInputUsername: (v: string) => void;
  refreshLoginState: (walletId?: string) => Promise<void>;
  sdkFlow: SDKFlowRuntime;
  displayPostfix?: string;
  isUsingExistingAccount?: boolean;
  stopDevice2LinkingFlow?: () => Promise<void>;
}

export function usePasskeyAuthMenuRuntime(): PasskeyAuthMenuRuntime {
  const ctx = useSeams();
  const accountExists = !!ctx.accountInputState?.accountExists;
  return {
    seamsWeb: ctx.seams,
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
