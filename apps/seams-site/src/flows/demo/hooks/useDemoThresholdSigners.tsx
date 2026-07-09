import { useCallback, useState } from 'react';
import { useSeams } from '@seams/sdk/react';

import type { FrontendConfig } from '@/config';
import { isTempoAlphaUsdFeeToken } from '../demoEvmHelpers';
import { useDemoArcSigningActions } from './useDemoArcSigningActions';
import { useDemoEip1559FeeCaps } from './useDemoEip1559FeeCaps';
import { useDemoEvmGreetings } from './useDemoEvmGreetings';
import { useDemoTempoFeeTokenActions } from './useDemoTempoFeeTokenActions';
import { useDemoTempoSigningActions } from './useDemoTempoSigningActions';
import { useDemoThresholdAccountState } from './useDemoThresholdAccountState';
import type { EvmAddress } from './demoThresholdTypes';

async function readFreshTempoUserFeeToken(input: {
  readonly resolveThresholdOwnerAddressForEvmFamily: () => Promise<EvmAddress>;
  readonly refreshTempoUserFeeToken: (opts: {
    silent: true;
    userAddress: EvmAddress;
  }) => Promise<EvmAddress | null>;
}): Promise<EvmAddress | null> {
  try {
    const thresholdOwnerAddress = await input.resolveThresholdOwnerAddressForEvmFamily();
    return await input.refreshTempoUserFeeToken({
      silent: true,
      userAddress: thresholdOwnerAddress,
    });
  } catch {
    return null;
  }
}

type UseDemoThresholdSignersArgs = {
  isLoggedIn: boolean;
  walletId?: string | null;
  thresholdEcdsaEthereumAddress?: string | null;
  seams: ReturnType<typeof useSeams>['seams'];
  frontendConfig?: Pick<FrontendConfig, 'chains' | 'tempoExplorerUrl' | 'tempoRpcUrl'>;
  tempoGreetingInput: string;
  arcGreetingInput: string;
};

export function useDemoThresholdSigners(args: UseDemoThresholdSignersArgs) {
  const {
    isLoggedIn,
    walletId,
    thresholdEcdsaEthereumAddress,
    seams,
    frontendConfig,
    tempoGreetingInput,
    arcGreetingInput,
  } = args;

  const { tempoEip1559FeeCaps, arcEip1559FeeCaps } = useDemoEip1559FeeCaps();
  const {
    tempoGreeting,
    arcGreeting,
    tempoGreetingLoading,
    arcGreetingLoading,
    tempoGreetingError,
    arcGreetingError,
    fetchTempoGreeting,
    fetchArcGreeting,
  } = useDemoEvmGreetings({ isLoggedIn });
  const {
    thresholdOwnerAddress,
    refreshThresholdOwnerAddress,
    resolveThresholdOwnerAddressForEvmFamily,
    refreshTempoUserFeeToken,
    refreshTempoUserFeeTokenBalance,
  } = useDemoThresholdAccountState({
    isLoggedIn,
    walletId,
    thresholdEcdsaEthereumAddress,
    seams,
  });

  const canSignTempo = Boolean(tempoGreetingInput.trim()) && isLoggedIn && Boolean(walletId);
  const canSignEvm = Boolean(arcGreetingInput.trim()) && isLoggedIn && Boolean(walletId);
  const [tempoFeeTokenPrepareLoading, setTempoFeeTokenPrepareLoading] = useState(false);

  const { tempoFeeTokenConfigLoading, handleSetTempoFeeTokenAlphaUsd } =
    useDemoTempoFeeTokenActions({
      isLoggedIn,
      walletId,
      seams,
      tempoEip1559FeeCaps,
      resolveThresholdOwnerAddressForEvmFamily,
      refreshTempoUserFeeToken,
      refreshTempoUserFeeTokenBalance,
    });

  const {
    tempoThresholdSignLoading,
    tempoFeeTokenFundingLoading,
    tempoPreparationUnavailableReason,
    handleFundTempoFeeTokens,
    handleSignTempoThresholdTx,
  } = useDemoTempoSigningActions({
    isLoggedIn,
    walletId,
    seams,
    frontendConfig,
    canSignTempo,
    tempoGreetingInput,
    tempoEip1559FeeCaps,
    resolveThresholdOwnerAddressForEvmFamily,
    refreshTempoUserFeeToken,
    refreshTempoUserFeeTokenBalance,
    fetchTempoGreeting,
    refreshThresholdOwnerAddress,
  });

  const { evmThresholdSignLoading, handleSignEvmThresholdTx } = useDemoArcSigningActions({
    canSignEvm,
    walletId,
    seams,
    arcGreetingInput,
    arcEip1559FeeCaps,
    fetchArcGreeting,
    refreshThresholdOwnerAddress,
    resolveThresholdOwnerAddressForEvmFamily,
  });

  const refreshTempoGreeting = useCallback(async () => {
    return await fetchTempoGreeting();
  }, [fetchTempoGreeting]);

  const refreshArcGreeting = useCallback(async () => {
    return await fetchArcGreeting();
  }, [fetchArcGreeting]);

  const handlePrepareTempoFeeToken = useCallback(async () => {
    if (tempoFeeTokenPrepareLoading) return;
    setTempoFeeTokenPrepareLoading(true);
    try {
      const feeTokensReady = await handleFundTempoFeeTokens();
      if (!feeTokensReady) return;

      const refreshedFeeToken = await readFreshTempoUserFeeToken({
        refreshTempoUserFeeToken,
        resolveThresholdOwnerAddressForEvmFamily,
      });
      if (isTempoAlphaUsdFeeToken(refreshedFeeToken)) return;
      await handleSetTempoFeeTokenAlphaUsd();
    } finally {
      setTempoFeeTokenPrepareLoading(false);
    }
  }, [
    handleSetTempoFeeTokenAlphaUsd,
    handleFundTempoFeeTokens,
    refreshTempoUserFeeToken,
    resolveThresholdOwnerAddressForEvmFamily,
    tempoFeeTokenPrepareLoading,
  ]);

  return {
    tempoThresholdSignLoading,
    tempoPreparationUnavailableReason,
    tempoFeeTokenPrepareLoading:
      tempoFeeTokenPrepareLoading || tempoFeeTokenFundingLoading || tempoFeeTokenConfigLoading,
    evmThresholdSignLoading,
    tempoGreeting,
    arcGreeting,
    tempoGreetingLoading,
    arcGreetingLoading,
    tempoGreetingError,
    arcGreetingError,
    thresholdOwnerAddress,
    handlePrepareTempoFeeToken,
    handleSignTempoThresholdTx,
    handleSignEvmThresholdTx,
    refreshTempoGreeting,
    refreshArcGreeting,
    canSignTempo,
    canSignEvm,
  };
}
