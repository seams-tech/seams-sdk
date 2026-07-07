import React, { useState } from 'react';
import { toast } from 'sonner';

import { useSeams } from '@seams/sdk/react';

import { useSetGreeting } from '@/shared/hooks/useSetGreeting';
import { NearGreetingSection } from './sections/NearGreetingSection';
import { ThresholdSignerSection } from './sections/ThresholdSignerSection';
import { createChainDefaultGreeting } from './demoEvmHelpers';
import { useDemoNearAccountFundingStatus } from './hooks/useDemoNearAccountFundingStatus';
import { useDemoNearActions } from './hooks/useDemoNearActions';
import { useDemoThresholdSigners } from './hooks/useDemoThresholdSigners';
import './DemoPage.css';

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
    nearAccountFunding.status.kind === 'ready' || nearAccountFunding.status.kind === 'needs_funding';

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

  if (!isLoggedIn || !walletId) {
    return null;
  }

  return (
    <div>
      <div className="action-section">
        <div className="demo-page-header">
          <h2 className="demo-title">Welcome</h2>
        </div>
      </div>

      <NearGreetingSection
        onchainGreeting={onchainGreeting}
        isLoading={isLoading}
        greetingInput={nearActions.greetingInput}
        onGreetingInputChange={nearActions.setGreetingInput}
        onRefresh={() => {
          void fetchGreeting();
        }}
        onSetGreeting={nearActions.handleSetGreeting}
        txLoading={nearActions.txLoading}
        onSignDelegate={nearActions.handleSignDelegateGreeting}
        delegateLoading={nearActions.delegateLoading}
        canSetGreeting={nearActions.canSetGreeting}
        canSignDelegate={nearActions.canSignDelegate}
        nearAccountFundingStatus={nearAccountFunding.status}
        error={error}
      />

      <ThresholdSignerSection
        thresholdOwnerAddress={thresholdSigners.thresholdOwnerAddress}
        onCopyThresholdOwnerAddress={() => {
          toast.success('Address copied');
        }}
        onSetTempoFeeToken={thresholdSigners.handleSetTempoFeeTokenAlphaUsd}
        tempoFeeTokenConfigLoading={thresholdSigners.tempoFeeTokenConfigLoading}
        tempoFeeTokenConfigTarget={thresholdSigners.tempoFeeTokenConfigTarget}
        tempoFeeTokenIsAlpha={thresholdSigners.tempoFeeTokenIsAlpha}
        onTempoDripToken={thresholdSigners.handleTempoDripToken}
        tempoDripLoading={thresholdSigners.tempoDripLoading}
        tempoSponsorshipUnavailableReason={thresholdSigners.tempoSponsorshipUnavailableReason}
        tempoGreeting={thresholdSigners.tempoGreeting}
        tempoGreetingLoading={thresholdSigners.tempoGreetingLoading}
        onRefreshTempoGreeting={thresholdSigners.refreshTempoGreeting}
        tempoGreetingInput={tempoGreetingInput}
        onTempoGreetingInputChange={setTempoGreetingInput}
        tempoGreetingError={thresholdSigners.tempoGreetingError}
        onSignTempoTransaction={thresholdSigners.handleSignTempoThresholdTx}
        tempoThresholdSignLoading={thresholdSigners.tempoThresholdSignLoading}
        canSignTempo={thresholdSigners.canSignTempo}
        arcGreeting={thresholdSigners.arcGreeting}
        arcGreetingLoading={thresholdSigners.arcGreetingLoading}
        onRefreshArcGreeting={thresholdSigners.refreshArcGreeting}
        arcGreetingInput={arcGreetingInput}
        onArcGreetingInputChange={setArcGreetingInput}
        arcGreetingError={thresholdSigners.arcGreetingError}
        onSignEvmTransaction={thresholdSigners.handleSignEvmThresholdTx}
        evmThresholdSignLoading={thresholdSigners.evmThresholdSignLoading}
        canSignEvm={thresholdSigners.canSignEvm}
      />
    </div>
  );
};

export default DemoPage;
