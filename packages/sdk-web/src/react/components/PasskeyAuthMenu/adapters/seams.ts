import { useSeams } from '@/react/context';
import type { SeamsWeb } from '@/SeamsWeb';
import { type SDKFlowRuntime, type StoredAccountOption } from '@/react/types';

export interface PasskeyAuthMenuRuntime {
  seamsWeb: SeamsWeb;
  accountExists: boolean;
  passkeyCredentialExists: boolean;
  inputUsername: string;
  targetWalletId: string;
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
  const passkeyCredentialExists = !!ctx.accountInputState?.passkeyCredentialExists;
  return {
    seamsWeb: ctx.seams,
    accountExists,
    passkeyCredentialExists,
    inputUsername: ctx.accountInputState?.inputUsername ?? '',
    targetWalletId: ctx.accountInputState?.targetWalletId ?? '',
    accountOptions: ctx.accountInputState?.indexDBAccountOptions ?? [],
    setInputUsername: ctx.setInputUsername,
    refreshLoginState: ctx.refreshLoginState,
    sdkFlow: ctx.sdkFlow,
    displayPostfix: ctx.accountInputState?.displayPostfix,
    isUsingExistingAccount: ctx.accountInputState?.isUsingExistingAccount,
    stopDevice2LinkingFlow: ctx.stopDevice2LinkingFlow,
  };
}

export default usePasskeyAuthMenuRuntime;
