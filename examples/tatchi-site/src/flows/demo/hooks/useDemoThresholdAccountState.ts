import { useCallback, useEffect, useState } from 'react';
import { useTatchi } from '@tatchi-xyz/sdk/react';
import { toast } from 'sonner';

import { FRONTEND_CONFIG } from '@/config';
import { isEvmAddress, readTempoTokenBalanceRaw, readTempoUserFeeToken } from '../demoEvmHelpers';
import type { EvmAddress } from './demoThresholdTypes';

type UseDemoThresholdAccountStateArgs = {
  isLoggedIn: boolean;
  nearAccountId?: string | null;
  tatchi: ReturnType<typeof useTatchi>['tatchi'];
};

export function useDemoThresholdAccountState(args: UseDemoThresholdAccountStateArgs) {
  const { isLoggedIn, nearAccountId, tatchi } = args;
  const [thresholdEvmFundingAddress, setThresholdEvmFundingAddress] = useState<string | null>(null);
  const [tempoUserFeeToken, setTempoUserFeeToken] = useState<EvmAddress | null>(null);

  const refreshThresholdEvmFundingAddress = useCallback(async () => {
    if (!isLoggedIn || !nearAccountId) {
      setThresholdEvmFundingAddress(null);
      return null;
    }
    try {
      const session = await tatchi.auth.getSession(nearAccountId);
      const address = String(session.login.thresholdEcdsaEthereumAddress || '').trim();
      setThresholdEvmFundingAddress(address || null);
      return address || null;
    } catch {
      setThresholdEvmFundingAddress(null);
      return null;
    }
  }, [isLoggedIn, nearAccountId, tatchi]);

  const resolveThresholdSenderForEvmFamily = useCallback(async (): Promise<EvmAddress> => {
    const thresholdSender =
      thresholdEvmFundingAddress || (await refreshThresholdEvmFundingAddress());
    if (!thresholdSender || !isEvmAddress(thresholdSender)) {
      throw new Error('Threshold EVM sender address is unavailable');
    }
    return thresholdSender;
  }, [refreshThresholdEvmFundingAddress, thresholdEvmFundingAddress]);

  const refreshTempoUserFeeToken = useCallback(
    async (opts?: { silent?: boolean; userAddress?: EvmAddress | null }) => {
      const maybeAddress = String(opts?.userAddress || thresholdEvmFundingAddress || '').trim();
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
    [thresholdEvmFundingAddress],
  );

  const refreshTempoUserFeeTokenBalance = useCallback(
    async (opts?: {
      silent?: boolean;
      userAddress?: EvmAddress | null;
      feeToken?: EvmAddress | null;
    }) => {
      const maybeAddress = String(opts?.userAddress || thresholdEvmFundingAddress || '').trim();
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
    [tempoUserFeeToken, thresholdEvmFundingAddress],
  );

  useEffect(() => {
    if (!isLoggedIn || !nearAccountId) return;
    void refreshThresholdEvmFundingAddress();
  }, [isLoggedIn, nearAccountId, refreshThresholdEvmFundingAddress]);

  useEffect(() => {
    if (!thresholdEvmFundingAddress || !isEvmAddress(thresholdEvmFundingAddress)) {
      setTempoUserFeeToken(null);
      return;
    }
    void refreshTempoUserFeeToken({ silent: true, userAddress: thresholdEvmFundingAddress });
  }, [refreshTempoUserFeeToken, thresholdEvmFundingAddress]);

  return {
    thresholdEvmFundingAddress,
    tempoUserFeeToken,
    refreshThresholdEvmFundingAddress,
    resolveThresholdSenderForEvmFamily,
    refreshTempoUserFeeToken,
    refreshTempoUserFeeTokenBalance,
  };
}
