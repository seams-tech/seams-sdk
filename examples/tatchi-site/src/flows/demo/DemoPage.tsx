import React, { useEffect, useState } from 'react';
import { toast } from 'sonner';

import { useTatchi } from '@tatchi-xyz/sdk/react';

import { useSetGreeting } from '@/shared/hooks/useSetGreeting';
import { NearGreetingSection } from './sections/NearGreetingSection';
import { SigningSessionSection } from './sections/SigningSessionSection';
import { ThresholdSignerSection } from './sections/ThresholdSignerSection';
import { createChainDefaultGreeting } from './demoEvmHelpers';
import { useDemoNearActions } from './hooks/useDemoNearActions';
import { useDemoSigningSession } from './hooks/useDemoSigningSession';
import { useDemoThresholdSigners } from './hooks/useDemoThresholdSigners';
import './DemoPage.css';

type DemoPageTestOverrides = {
  useTatchiHook?: typeof useTatchi;
  useSetGreetingHook?: typeof useSetGreeting;
};

type DemoPageProps = {
  __testOverrides?: DemoPageTestOverrides;
};

export const DemoPage: React.FC<DemoPageProps> = (props) => {
  const useTatchiHook = props.__testOverrides?.useTatchiHook || useTatchi;
  const useSetGreetingHook = props.__testOverrides?.useSetGreetingHook || useSetGreeting;

  const [clockMs, setClockMs] = useState(() => Date.now());

  // Lightweight clock for TTL countdown display
  useEffect(() => {
    const id = window.setInterval(() => setClockMs(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const {
    loginState: { isLoggedIn, nearAccountId },
    tatchi,
  } = useTatchiHook();

  const { onchainGreeting, isLoading, fetchGreeting, error } = useSetGreetingHook();

  const [tempoGreetingInput, setTempoGreetingInput] = useState(() =>
    createChainDefaultGreeting('Tempo'),
  );
  const [arcGreetingInput, setArcGreetingInput] = useState(() => createChainDefaultGreeting('Arc'));

  const nearActions = useDemoNearActions({
    isLoggedIn,
    nearAccountId,
    tatchi,
    fetchGreeting,
  });

  const signingSession = useDemoSigningSession({
    clockMs,
    isLoggedIn,
    nearAccountId,
    tatchi,
  });

  const thresholdSigners = useDemoThresholdSigners({
    isLoggedIn,
    nearAccountId,
    tatchi,
    tempoGreetingInput,
    arcGreetingInput,
  });

  if (!isLoggedIn || !nearAccountId) {
    return null;
  }

  const accountName = nearAccountId.split('.')?.[0];

  return (
    <div>
      <div className="action-section">
        <div className="demo-page-header">
          <h2 className="demo-title">Welcome, {accountName}</h2>
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
        canSubmit={nearActions.canSubmit}
        error={error}
      />

      <ThresholdSignerSection
        thresholdEvmFundingAddress={thresholdSigners.thresholdEvmFundingAddress}
        onCopyFundingAddress={() => {
          toast.success('Address copied');
        }}
        onSetTempoFeeToken={thresholdSigners.handleSetTempoFeeTokenAlphaUsd}
        tempoFeeTokenConfigLoading={thresholdSigners.tempoFeeTokenConfigLoading}
        tempoFeeTokenConfigTarget={thresholdSigners.tempoFeeTokenConfigTarget}
        tempoFeeTokenIsAlpha={thresholdSigners.tempoFeeTokenIsAlpha}
        onTempoDripToken={thresholdSigners.handleTempoDripToken}
        tempoDripLoading={thresholdSigners.tempoDripLoading}
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

      <SigningSessionSection
        sessionRemainingUsesInput={signingSession.sessionRemainingUsesInput}
        onSessionRemainingUsesInputChange={signingSession.setSessionRemainingUsesInput}
        sessionTtlSecondsInput={signingSession.sessionTtlSecondsInput}
        onSessionTtlSecondsInputChange={signingSession.setSessionTtlSecondsInput}
        onCreateSession={signingSession.handleUnlockSession}
        unlockLoading={signingSession.unlockLoading}
        sessionStatus={signingSession.sessionStatus}
        expiresInSec={signingSession.expiresInSec}
      />
    </div>
  );
};

export default DemoPage;
