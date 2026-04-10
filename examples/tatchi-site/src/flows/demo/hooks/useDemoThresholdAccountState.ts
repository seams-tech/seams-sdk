import { useCallback, useEffect, useState } from 'react';
import { useTatchi } from '@tatchi-xyz/sdk/react';
import { toast } from 'sonner';

import { FRONTEND_CONFIG, type FrontendConfig } from '@/config';
import { isEvmAddress, readTempoTokenBalanceRaw, readTempoUserFeeToken } from '../demoEvmHelpers';
import type { EvmAddress } from './demoThresholdTypes';

type UseDemoThresholdAccountStateArgs = {
  isLoggedIn: boolean;
  nearAccountId?: string | null;
  tatchi: ReturnType<typeof useTatchi>['tatchi'];
  frontendConfig?: Pick<FrontendConfig, 'relayerUrl'>;
};

export function useDemoThresholdAccountState(args: UseDemoThresholdAccountStateArgs) {
  const { isLoggedIn, nearAccountId, tatchi, frontendConfig = FRONTEND_CONFIG } = args;
  const [thresholdEvmFundingAddress, setThresholdEvmFundingAddress] = useState<string | null>(null);
  const [tempoUserFeeToken, setTempoUserFeeToken] = useState<EvmAddress | null>(null);

  const readWalletSessionThresholdEvmFundingAddress = useCallback(async () => {
    if (!isLoggedIn || !nearAccountId) {
      return null;
    }
    try {
      const session = await tatchi.auth.getWalletSession(nearAccountId);
      const address = String(session.login.thresholdEcdsaEthereumAddress || '').trim();
      return address || null;
    } catch {
      return null;
    }
  }, [isLoggedIn, nearAccountId, tatchi]);

  const ensureThresholdEcdsaReadyForChain = useCallback(
    async (chain: 'tempo' | 'evm'): Promise<string | null> => {
      if (!isLoggedIn || !nearAccountId) return null;

      const bootstrap =
        chain === 'tempo'
          ? await tatchi.tempo.bootstrapEcdsaSession({
              nearAccountId,
              options: {
                ...(frontendConfig.relayerUrl ? { relayerUrl: frontendConfig.relayerUrl } : {}),
              },
            })
          : await tatchi.evm.bootstrapEcdsaSession({
              nearAccountId,
              options: {
                ...(frontendConfig.relayerUrl ? { relayerUrl: frontendConfig.relayerUrl } : {}),
              },
            });

      const maybeAddress = String(
        bootstrap.keygen.counterfactualAddress ||
          bootstrap.keygen.ethereumAddress ||
          bootstrap.thresholdEcdsaKeyRef.ethereumAddress ||
          '',
      ).trim();
      if (!isEvmAddress(maybeAddress)) {
        throw new Error('Threshold ECDSA bootstrap did not return a usable EVM sender address');
      }
      setThresholdEvmFundingAddress(maybeAddress);
      return maybeAddress;
    },
    [frontendConfig.relayerUrl, isLoggedIn, nearAccountId, tatchi],
  );

  const refreshThresholdEvmFundingAddress = useCallback(
    async (opts?: { bootstrap?: boolean; chain?: 'tempo' | 'evm' }) => {
      if (!isLoggedIn || !nearAccountId) {
        setThresholdEvmFundingAddress(null);
        return null;
      }

      try {
        let address = await readWalletSessionThresholdEvmFundingAddress();
        if ((!address || !isEvmAddress(address)) && opts?.bootstrap) {
          address = await ensureThresholdEcdsaReadyForChain(opts.chain || 'tempo');
        }
        const normalized = isEvmAddress(String(address || '').trim()) ? String(address).trim() : null;
        setThresholdEvmFundingAddress(normalized);
        return normalized;
      } catch (error: unknown) {
        setThresholdEvmFundingAddress(null);
        if (opts?.bootstrap) throw error;
        return null;
      }
    },
    [
      ensureThresholdEcdsaReadyForChain,
      isLoggedIn,
      nearAccountId,
      readWalletSessionThresholdEvmFundingAddress,
    ],
  );

  const resolveThresholdSenderForEvmFamily = useCallback(
    async (opts?: { chain?: 'tempo' | 'evm'; ensureReady?: boolean }): Promise<EvmAddress> => {
      const requestedChain = opts?.chain || 'tempo';
      const thresholdSender =
        (isEvmAddress(String(thresholdEvmFundingAddress || '').trim())
          ? thresholdEvmFundingAddress
          : null) ||
        (opts?.ensureReady
          ? await ensureThresholdEcdsaReadyForChain(requestedChain)
          : await refreshThresholdEvmFundingAddress({
              bootstrap: true,
              chain: requestedChain,
            }));
      if (!thresholdSender || !isEvmAddress(thresholdSender)) {
        throw new Error('Threshold EVM sender address is unavailable');
      }
      return thresholdSender;
    },
    [
      ensureThresholdEcdsaReadyForChain,
      refreshThresholdEvmFundingAddress,
      thresholdEvmFundingAddress,
    ],
  );

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
    ensureThresholdEcdsaReadyForChain,
    refreshThresholdEvmFundingAddress,
    resolveThresholdSenderForEvmFamily,
    refreshTempoUserFeeToken,
    refreshTempoUserFeeTokenBalance,
  };
}
