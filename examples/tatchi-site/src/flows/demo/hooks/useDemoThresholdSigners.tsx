import { useCallback } from 'react';
import { useTatchi } from '@tatchi-xyz/sdk/react';

import type { FrontendConfig } from '@/config';
import { TEMPO_ALPHA_USD_FEE_TOKEN } from '../demoEvmHelpers';
import { useDemoArcSigningActions } from './useDemoArcSigningActions';
import { useDemoEip1559FeeCaps } from './useDemoEip1559FeeCaps';
import { useDemoEvmGreetings } from './useDemoEvmGreetings';
import { useDemoTempoFeeTokenActions } from './useDemoTempoFeeTokenActions';
import { useDemoTempoSigningActions } from './useDemoTempoSigningActions';
import { useDemoThresholdAccountState } from './useDemoThresholdAccountState';

type UseDemoThresholdSignersArgs = {
  isLoggedIn: boolean;
  nearAccountId?: string | null;
  tatchi: ReturnType<typeof useTatchi>['tatchi'];
  frontendConfig?: Pick<
    FrontendConfig,
    'managedRegistration' | 'relayerUrl' | 'tempoExplorerUrl' | 'tempoRpcUrl'
  >;
  tempoGreetingInput: string;
  arcGreetingInput: string;
};

export function useDemoThresholdSigners(args: UseDemoThresholdSignersArgs) {
  const { isLoggedIn, nearAccountId, tatchi, frontendConfig, tempoGreetingInput, arcGreetingInput } =
    args;

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
  } = useDemoEvmGreetings({ isLoggedIn, nearAccountId });
  const {
    thresholdEvmFundingAddress,
    tempoUserFeeToken,
    refreshThresholdEvmFundingAddress,
    resolveThresholdSenderForEvmFamily,
    refreshTempoUserFeeToken,
    refreshTempoUserFeeTokenBalance,
  } = useDemoThresholdAccountState({
    isLoggedIn,
    nearAccountId,
    tatchi,
    frontendConfig,
  });

  const canSignTempo =
    Boolean(tempoGreetingInput.trim()) && isLoggedIn && Boolean(nearAccountId);
  const canSignEvm = Boolean(arcGreetingInput.trim()) && isLoggedIn && Boolean(nearAccountId);
  const tempoFeeTokenIsAlpha =
    String(tempoUserFeeToken || '').toLowerCase() === TEMPO_ALPHA_USD_FEE_TOKEN.toLowerCase();

  const {
    tempoFeeTokenConfigLoading,
    tempoFeeTokenConfigTarget,
    handleSetTempoFeeTokenAlphaUsd,
  } = useDemoTempoFeeTokenActions({
    isLoggedIn,
    nearAccountId,
    tatchi,
    tempoEip1559FeeCaps,
    resolveThresholdSenderForEvmFamily,
    refreshTempoUserFeeToken,
    refreshTempoUserFeeTokenBalance,
  });

  const {
    tempoThresholdSignLoading,
    tempoDripLoading,
    tempoSponsorshipUnavailableReason,
    handleTempoDripToken,
    handleSignTempoThresholdTx,
  } = useDemoTempoSigningActions({
    isLoggedIn,
    nearAccountId,
    tatchi,
    frontendConfig,
    canSignTempo,
    tempoGreetingInput,
    tempoEip1559FeeCaps,
    tempoUserFeeToken,
    resolveThresholdSenderForEvmFamily,
    refreshTempoUserFeeTokenBalance,
    fetchTempoGreeting,
    refreshThresholdEvmFundingAddress,
  });

  const { evmThresholdSignLoading, handleSignEvmThresholdTx } = useDemoArcSigningActions({
    canSignEvm,
    nearAccountId,
    tatchi,
    arcGreetingInput,
    arcEip1559FeeCaps,
    fetchArcGreeting,
    refreshThresholdEvmFundingAddress,
  });

  const refreshTempoGreeting = useCallback(async () => {
    return await fetchTempoGreeting();
  }, [fetchTempoGreeting]);

  const refreshArcGreeting = useCallback(async () => {
    return await fetchArcGreeting();
  }, [fetchArcGreeting]);

  return {
    tempoThresholdSignLoading,
    tempoDripLoading,
    tempoSponsorshipUnavailableReason,
    tempoFeeTokenConfigLoading,
    tempoFeeTokenConfigTarget,
    evmThresholdSignLoading,
    tempoGreeting,
    arcGreeting,
    tempoGreetingLoading,
    arcGreetingLoading,
    tempoGreetingError,
    arcGreetingError,
    thresholdEvmFundingAddress,
    tempoFeeTokenIsAlpha,
    handleSetTempoFeeTokenAlphaUsd,
    handleTempoDripToken,
    handleSignTempoThresholdTx,
    handleSignEvmThresholdTx,
    refreshTempoGreeting,
    refreshArcGreeting,
    canSignTempo,
    canSignEvm,
  };
}
