import { useCallback, useEffect, useState } from 'react';
import { useSeams } from '@seams/sdk/react';
import { toast } from 'sonner';

import { FRONTEND_CONFIG } from '@/config';
import { isEvmAddress, readTempoTokenBalanceRaw, readTempoUserFeeToken } from '../demoEvmHelpers';
import type { EvmAddress } from './demoThresholdTypes';

type UseDemoThresholdAccountStateArgs = {
  isLoggedIn: boolean;
  walletId?: string | null;
  thresholdEcdsaEthereumAddress?: string | null;
  seams: ReturnType<typeof useSeams>['seams'];
};

type ThresholdOwnerAddressReadResult =
  | {
      ok: true;
      address: EvmAddress;
      reason?: never;
    }
  | {
      ok: false;
      reason: 'not_logged_in' | 'wallet_session_read_failed' | 'missing_wallet_session_address';
      address?: never;
    };

function normalizeDemoEvmAddress(value: string | null | undefined): EvmAddress | null {
  const normalized = String(value || '').trim();
  return isEvmAddress(normalized) ? normalized : null;
}

export function useDemoThresholdAccountState(args: UseDemoThresholdAccountStateArgs) {
  const { isLoggedIn, walletId, thresholdEcdsaEthereumAddress, seams } = args;
  const [thresholdOwnerAddress, setThresholdOwnerAddress] = useState<string | null>(null);
  const [tempoUserFeeToken, setTempoUserFeeToken] = useState<EvmAddress | null>(null);
  const loginStateThresholdOwnerAddress = normalizeDemoEvmAddress(thresholdEcdsaEthereumAddress);

  const readWalletSessionThresholdOwnerAddress =
    useCallback(async (): Promise<ThresholdOwnerAddressReadResult> => {
      if (!isLoggedIn || !walletId) {
        return { ok: false, reason: 'not_logged_in' };
      }
      try {
        const session = await seams.auth.getWalletSession(walletId);
        const address = String(session.login.thresholdEcdsaEthereumAddress || '').trim();
        if (!isEvmAddress(address)) {
          return { ok: false, reason: 'missing_wallet_session_address' };
        }
        return { ok: true, address };
      } catch {
        return { ok: false, reason: 'wallet_session_read_failed' };
      }
    }, [isLoggedIn, seams, walletId]);

  const refreshThresholdOwnerAddress = useCallback(async () => {
    if (!isLoggedIn || !walletId) {
      setThresholdOwnerAddress(null);
      return null;
    }
    if (loginStateThresholdOwnerAddress) {
      setThresholdOwnerAddress(loginStateThresholdOwnerAddress);
      return loginStateThresholdOwnerAddress;
    }

    const result = await readWalletSessionThresholdOwnerAddress();
    if (!result.ok) {
      setThresholdOwnerAddress(null);
      return null;
    }
    setThresholdOwnerAddress(result.address);
    return result.address;
  }, [
    isLoggedIn,
    loginStateThresholdOwnerAddress,
    readWalletSessionThresholdOwnerAddress,
    walletId,
  ]);

  const resolveThresholdOwnerAddressForEvmFamily = useCallback(async (): Promise<EvmAddress> => {
    let resolvedThresholdOwnerAddress = isEvmAddress(String(thresholdOwnerAddress || '').trim())
      ? thresholdOwnerAddress
      : null;
    if (!resolvedThresholdOwnerAddress && loginStateThresholdOwnerAddress) {
      resolvedThresholdOwnerAddress = loginStateThresholdOwnerAddress;
      setThresholdOwnerAddress(loginStateThresholdOwnerAddress);
    }
    if (!resolvedThresholdOwnerAddress) {
      const storedAddress = await readWalletSessionThresholdOwnerAddress();
      if (storedAddress.ok) {
        resolvedThresholdOwnerAddress = storedAddress.address;
        setThresholdOwnerAddress(storedAddress.address);
      }
    }
    if (!resolvedThresholdOwnerAddress) {
      resolvedThresholdOwnerAddress = await refreshThresholdOwnerAddress();
    }
    if (!resolvedThresholdOwnerAddress || !isEvmAddress(resolvedThresholdOwnerAddress)) {
      throw new Error(
        'Threshold EVM owner address is unavailable. Registration should provision threshold ECDSA; refresh the wallet session, then retry.',
      );
    }
    return resolvedThresholdOwnerAddress;
  }, [
    loginStateThresholdOwnerAddress,
    readWalletSessionThresholdOwnerAddress,
    refreshThresholdOwnerAddress,
    thresholdOwnerAddress,
  ]);

  const refreshTempoUserFeeToken = useCallback(
    async (opts?: { silent?: boolean; userAddress?: EvmAddress | null }) => {
      const maybeAddress = String(opts?.userAddress || thresholdOwnerAddress || '').trim();
      if (!isEvmAddress(maybeAddress)) {
        setTempoUserFeeToken(null);
        return null;
      }

      try {
        const token = await readTempoUserFeeToken({
          rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
          userAddress: maybeAddress,
        });
        setTempoUserFeeToken(token);
        return token;
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        setTempoUserFeeToken(null);
        if (!opts?.silent) {
          toast.error(`Tempo fee-token check failed: ${message}`);
        }
        return null;
      }
    },
    [thresholdOwnerAddress],
  );

  const refreshTempoUserFeeTokenBalance = useCallback(
    async (opts?: {
      silent?: boolean;
      userAddress?: EvmAddress | null;
      feeToken?: EvmAddress | null;
    }) => {
      const maybeAddress = String(opts?.userAddress || thresholdOwnerAddress || '').trim();
      const maybeToken = String(opts?.feeToken || tempoUserFeeToken || '').trim();
      if (!isEvmAddress(maybeAddress) || !isEvmAddress(maybeToken)) {
        return null;
      }
      try {
        const balance = await readTempoTokenBalanceRaw({
          rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
          userAddress: maybeAddress,
          tokenAddress: maybeToken,
        });
        return balance;
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        if (!opts?.silent) {
          toast.error(`Tempo fee-token balance check failed: ${message}`);
        }
        return null;
      }
    },
    [tempoUserFeeToken, thresholdOwnerAddress],
  );

  useEffect(() => {
    if (!isLoggedIn || !walletId) return;
    if (loginStateThresholdOwnerAddress) {
      setThresholdOwnerAddress(loginStateThresholdOwnerAddress);
      return;
    }
    void refreshThresholdOwnerAddress();
  }, [isLoggedIn, loginStateThresholdOwnerAddress, refreshThresholdOwnerAddress, walletId]);

  useEffect(() => {
    if (!thresholdOwnerAddress || !isEvmAddress(thresholdOwnerAddress)) {
      setTempoUserFeeToken(null);
      return;
    }
    void refreshTempoUserFeeToken({ silent: true, userAddress: thresholdOwnerAddress });
  }, [refreshTempoUserFeeToken, thresholdOwnerAddress]);

  return {
    thresholdOwnerAddress,
    tempoUserFeeToken,
    refreshThresholdOwnerAddress,
    resolveThresholdOwnerAddressForEvmFamily,
    refreshTempoUserFeeToken,
    refreshTempoUserFeeTokenBalance,
  };
}
