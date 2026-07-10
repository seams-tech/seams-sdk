import React, { useState } from 'react';
import { toast } from 'sonner';

import { useSeams } from '@seams/sdk/react';

import { AnimatedHeight } from '@/components/AnimatedHeight';
import { useSetGreeting } from '@/shared/hooks/useSetGreeting';
import {
  ChainSigningSection,
  type DemoChainId,
  type DemoChainView,
} from './sections/ChainSigningSection';
import { createChainDefaultGreeting } from './demoEvmHelpers';
import {
  useDemoNearAccountFundingStatus,
  type DemoNearAccountFundingStatus,
} from './hooks/useDemoNearAccountFundingStatus';
import { useDemoNearActions } from './hooks/useDemoNearActions';
import { useDemoThresholdGasStatus } from './hooks/useDemoThresholdGasStatus';
import { useDemoThresholdSigners } from './hooks/useDemoThresholdSigners';
import './DemoPage.css';

function nearFundingStatusText(status: DemoNearAccountFundingStatus): string | null {
  switch (status.kind) {
    case 'checking':
      return 'Checking NEAR account funding...';
    case 'needs_funding':
      return 'NEAR account needs funding before signing.';
    case 'unknown':
      return `NEAR funding status unavailable: ${status.message}`;
    case 'not_available':
    case 'ready':
      return null;
    default: {
      const exhaustive: never = status;
      return exhaustive;
    }
  }
}

export const DemoPage: React.FC = () => {
  const {
    loginState: {
      isLoggedIn,
      walletId,
      nearAccountId,
      nearPublicKey,
      thresholdEcdsaEthereumAddress,
    },
    seams,
  } = useSeams();

  const { onchainGreeting, isLoading, fetchGreeting, error } = useSetGreeting();

  const [selectedChainId, setSelectedChainId] = useState<DemoChainId>('near');
  const [tempoGreetingInput, setTempoGreetingInput] = useState(() =>
    createChainDefaultGreeting('Tempo'),
  );
  const [arcGreetingInput, setArcGreetingInput] = useState(() => createChainDefaultGreeting('Arc'));

  const nearAccountFunding = useDemoNearAccountFundingStatus({
    isLoggedIn,
    nearAccountId,
    nearPublicKey,
  });
  const canStartNearTransaction =
    nearAccountFunding.status.kind === 'ready' ||
    nearAccountFunding.status.kind === 'needs_funding';

  const nearActions = useDemoNearActions({
    isLoggedIn,
    canStartNearTransaction,
    canSignDelegate: nearAccountFunding.canSignNear,
    walletId,
    nearAccountId,
    nearPublicKey,
    seams,
    fetchGreeting,
  });

  const thresholdSigners = useDemoThresholdSigners({
    isLoggedIn,
    walletId,
    thresholdEcdsaEthereumAddress,
    seams,
    tempoGreetingInput,
    arcGreetingInput,
  });

  const thresholdGas = useDemoThresholdGasStatus({
    isLoggedIn,
    thresholdOwnerAddress: thresholdSigners.thresholdOwnerAddress,
  });

  if (!isLoggedIn || !walletId) {
    return null;
  }

  /* One interaction, three target chains: each entry normalizes a chain's
     greeting state + signing action for the shared section. */
  const chains: DemoChainView[] = [
    {
      id: 'near',
      label: 'NEAR',
      greeting: onchainGreeting,
      greetingLoading: isLoading,
      onRefreshGreeting: fetchGreeting,
      greetingInput: nearActions.greetingInput,
      onGreetingInputChange: nearActions.setGreetingInput,
      statusText: nearFundingStatusText(nearAccountFunding.status),
      errorText: error != null ? `Error: ${String(error)}` : null,
      onSign: nearActions.handleSetGreeting,
      signLoading: nearActions.txLoading,
      canSign: nearActions.canSetGreeting,
      signLabel: 'Sign on NEAR',
    },
    {
      id: 'tempo',
      label: 'Tempo',
      greeting: thresholdSigners.tempoGreeting,
      greetingLoading: thresholdSigners.tempoGreetingLoading,
      onRefreshGreeting: thresholdSigners.refreshTempoGreeting,
      greetingInput: tempoGreetingInput,
      onGreetingInputChange: setTempoGreetingInput,
      statusText: null,
      errorText: thresholdSigners.tempoGreetingError
        ? `Tempo greeting error: ${thresholdSigners.tempoGreetingError}`
        : null,
      onSign: thresholdSigners.handleSignTempoThresholdTx,
      signLoading: thresholdSigners.tempoThresholdSignLoading,
      canSign: thresholdSigners.canSignTempo,
      signLabel: 'Sign on Tempo',
      setupDefaultOpen: thresholdGas.tempo === 'needs_gas',
    },
    {
      id: 'arc',
      label: 'Arc',
      greeting: thresholdSigners.arcGreeting,
      greetingLoading: thresholdSigners.arcGreetingLoading,
      onRefreshGreeting: thresholdSigners.refreshArcGreeting,
      greetingInput: arcGreetingInput,
      onGreetingInputChange: setArcGreetingInput,
      statusText: null,
      errorText: thresholdSigners.arcGreetingError
        ? `Arc greeting error: ${thresholdSigners.arcGreetingError}`
        : null,
      onSign: thresholdSigners.handleSignEvmThresholdTx,
      signLoading: thresholdSigners.evmThresholdSignLoading,
      canSign: thresholdSigners.canSignEvm,
      signLabel: 'Sign on Arc',
      setupDefaultOpen: thresholdGas.arc === 'needs_gas',
    },
  ];

  return (
    <AnimatedHeight>
      <div className="action-section">
        <div className="demo-page-header">
          <h2 className="demo-title">Welcome</h2>
        </div>
      </div>

      <ChainSigningSection
        chains={chains}
        selectedChainId={selectedChainId}
        onSelectChain={setSelectedChainId}
        onSignDelegate={nearActions.handleSignDelegateGreeting}
        delegateLoading={nearActions.delegateLoading}
        canSignDelegate={nearActions.canSignDelegate}
        thresholdOwnerAddress={thresholdSigners.thresholdOwnerAddress}
        onCopyThresholdOwnerAddress={() => {
          toast.success('Address copied');
        }}
        onPrepareTempoFeeToken={thresholdSigners.handlePrepareTempoFeeToken}
        tempoFeeTokenPrepareLoading={thresholdSigners.tempoFeeTokenPrepareLoading}
        tempoPreparationUnavailableReason={thresholdSigners.tempoPreparationUnavailableReason}
      />
    </AnimatedHeight>
  );
};

export default DemoPage;
