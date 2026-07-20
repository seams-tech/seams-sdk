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
  canStartDemoNearTransaction,
  demoNearFundingStatusText,
} from './demoNearAccountFundingState';
import { useDemoNearAccountFundingStatus } from './hooks/useDemoNearAccountFundingStatus';
import { useDemoNearActions } from './hooks/useDemoNearActions';
import { useDemoTempoFundingStatus } from './hooks/useDemoTempoFundingStatus';
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
      currentAuthMethod,
    },
    seams,
  } = useSeams();

  /* the section heading names the credential that will actually confirm the
     signature: passkey accounts prompt WebAuthn, email-OTP accounts prompt a
     one-time code */
  const signingHeading =
    currentAuthMethod.kind === 'selected' && currentAuthMethod.binding.kind === 'email_otp'
      ? 'Sign a transaction with a one-time password (email)'
      : 'Sign a transaction with your passkey';

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
  const canStartNearTransaction = canStartDemoNearTransaction(nearAccountFunding.status);

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

  /* gates the Fund Tempo Account button: hidden once the AlphaUSD fee token
     is set and funded (native gas alone is not Tempo readiness) */
  const tempoFunding = useDemoTempoFundingStatus({
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
      statusText: demoNearFundingStatusText(nearAccountFunding.status),
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
    },
  ];

  /* The header is constant across tabs; only the chain section changes height.
     AnimatedHeight eases that resize between NEAR/Tempo/Arc. The fixed-height
     .h2-hero__demo cell (card centered) absorbs the change, so the container
     never shifts the page around it. */
  return (
    <div className="demo-card-reveal">
      <div className="demo-page-header">
        <h2 className="demo-title">Welcome</h2>
      </div>

      <AnimatedHeight>
      <ChainSigningSection
        chains={chains}
        heading={signingHeading}
        selectedChainId={selectedChainId}
        onSelectChain={setSelectedChainId}
        onSignDelegate={nearActions.handleSignDelegateGreeting}
        delegateLoading={nearActions.delegateLoading}
        canSignDelegate={nearActions.canSignDelegate}
        thresholdOwnerAddress={thresholdSigners.thresholdOwnerAddress}
        onCopyThresholdOwnerAddress={() => {
          toast.success('Address copied');
        }}
        onPrepareTempoFeeToken={async () => {
          /* re-probe after the funding attempt so the button hides itself
             once the fee token is set and funded */
          try {
            await thresholdSigners.handlePrepareTempoFeeToken();
          } finally {
            tempoFunding.refresh();
          }
        }}
        tempoFeeTokenPrepareLoading={thresholdSigners.tempoFeeTokenPrepareLoading}
        tempoPreparationUnavailableReason={thresholdSigners.tempoPreparationUnavailableReason}
        tempoFundingStatus={tempoFunding.status}
      />
      </AnimatedHeight>
    </div>
  );
};

export default DemoPage;
