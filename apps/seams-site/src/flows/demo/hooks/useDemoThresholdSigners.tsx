import { useCallback } from 'react';
import { useSeams } from '@seams/sdk/react';

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
  walletId?: string | null;
  seams: ReturnType<typeof useSeams>['seams'];
  frontendConfig?: Pick<
    FrontendConfig,
    | 'chains'
    | 'managedRegistration'
    | 'relayerUrl'
    | 'tempoExplorerUrl'
    | 'tempoFeeToken'
    | 'tempoRpcUrl'
  >;
  tempoGreetingInput: string;
  arcGreetingInput: string;
};

export function useDemoThresholdSigners(args: UseDemoThresholdSignersArgs) {
  const {
    isLoggedIn,
    walletId,
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
    tempoUserFeeToken,
    refreshThresholdOwnerAddress,
    resolveThresholdOwnerAddressForEvmFamily,
    refreshTempoUserFeeToken,
    refreshTempoUserFeeTokenBalance,
  } = useDemoThresholdAccountState({
    isLoggedIn,
    walletId,
    seams,
    frontendConfig,
  });

  const canSignTempo =
    Boolean(tempoGreetingInput.trim()) && isLoggedIn && Boolean(walletId);
  const canSignEvm = Boolean(arcGreetingInput.trim()) && isLoggedIn && Boolean(walletId);
  const tempoFeeTokenIsAlpha =
    String(tempoUserFeeToken || '').toLowerCase() === TEMPO_ALPHA_USD_FEE_TOKEN.toLowerCase();

  const {
    tempoFeeTokenConfigLoading,
    tempoFeeTokenConfigTarget,
    handleSetTempoFeeTokenAlphaUsd,
  } = useDemoTempoFeeTokenActions({
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
    tempoDripLoading,
    tempoSponsorshipUnavailableReason,
    handleTempoDripToken,
    handleSignTempoThresholdTx,
  } = useDemoTempoSigningActions({
    isLoggedIn,
    walletId,
    seams,
    frontendConfig,
    canSignTempo,
    tempoGreetingInput,
    tempoEip1559FeeCaps,
    tempoUserFeeToken,
    resolveThresholdOwnerAddressForEvmFamily,
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
    thresholdOwnerAddress,
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
