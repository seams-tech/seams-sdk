import { useCallback, useEffect, useState } from 'react';
import { useSeams } from '@seams/sdk/react';
import { toast } from 'sonner';

import { FRONTEND_CONFIG, type FrontendConfig } from '@/config';
import { isEvmAddress, readTempoTokenBalanceRaw, readTempoUserFeeToken } from '../demoEvmHelpers';
import type { EvmAddress } from './demoThresholdTypes';

type UseDemoThresholdAccountStateArgs = {
  isLoggedIn: boolean;
  nearAccountId?: string | null;
  seams: ReturnType<typeof useSeams>['seams'];
  frontendConfig?: Pick<FrontendConfig, 'chains' | 'relayerUrl'>;
};

export function useDemoThresholdAccountState(args: UseDemoThresholdAccountStateArgs) {
  const { isLoggedIn, nearAccountId, seams } = args;
  const [thresholdOwnerAddress, setThresholdOwnerAddress] = useState<string | null>(null);
  const [tempoUserFeeToken, setTempoUserFeeToken] = useState<EvmAddress | null>(null);

  const readWalletSessionThresholdOwnerAddress = useCallback(async () => {
    if (!isLoggedIn || !nearAccountId) {
      return null;
    }
    try {
      const session = await seams.auth.getWalletSession(nearAccountId);
      const address = String(session.login.thresholdEcdsaEthereumAddress || '').trim();
      return address || null;
    } catch {
      return null;
    }
  }, [isLoggedIn, nearAccountId, seams]);

  const refreshThresholdOwnerAddress = useCallback(async () => {
    if (!isLoggedIn || !nearAccountId) {
      setThresholdOwnerAddress(null);
      return null;
    }

    try {
      const address = await readWalletSessionThresholdOwnerAddress();
      const normalized = isEvmAddress(String(address || '').trim()) ? String(address).trim() : null;
      setThresholdOwnerAddress(normalized);
      return normalized;
    } catch {
      setThresholdOwnerAddress(null);
      return null;
    }
  }, [isLoggedIn, nearAccountId, readWalletSessionThresholdOwnerAddress]);

  const resolveThresholdOwnerAddressForEvmFamily = useCallback(
    async (opts?: {
      chain?: 'tempo' | 'evm';
      bootstrapIfMissing?: boolean;
    }): Promise<EvmAddress> => {
      if (opts?.bootstrapIfMissing) {
        const storedAddress = await readWalletSessionThresholdOwnerAddress();
        if (storedAddress && isEvmAddress(storedAddress)) {
          setThresholdOwnerAddress(storedAddress);
          return storedAddress;
        }
        throw new Error('Threshold EVM owner address is unavailable');
      }
      let resolvedThresholdOwnerAddress = isEvmAddress(String(thresholdOwnerAddress || '').trim())
        ? thresholdOwnerAddress
        : null;
      if (!resolvedThresholdOwnerAddress) {
        const storedAddress = await readWalletSessionThresholdOwnerAddress();
        resolvedThresholdOwnerAddress = isEvmAddress(String(storedAddress || '').trim())
          ? String(storedAddress).trim()
          : null;
        if (resolvedThresholdOwnerAddress) {
          setThresholdOwnerAddress(resolvedThresholdOwnerAddress);
        }
      }
      if (!resolvedThresholdOwnerAddress) {
        resolvedThresholdOwnerAddress = await refreshThresholdOwnerAddress();
      }
      if (!resolvedThresholdOwnerAddress || !isEvmAddress(resolvedThresholdOwnerAddress)) {
        throw new Error('Threshold EVM owner address is unavailable');
      }
      return resolvedThresholdOwnerAddress;
    },
    [readWalletSessionThresholdOwnerAddress, refreshThresholdOwnerAddress, thresholdOwnerAddress],
  );

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
    if (!isLoggedIn || !nearAccountId) return;
    void refreshThresholdOwnerAddress();
  }, [isLoggedIn, nearAccountId, refreshThresholdOwnerAddress]);

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
