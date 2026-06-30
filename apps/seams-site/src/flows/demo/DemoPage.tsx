import React, { useEffect, useState } from 'react';
import { toast } from 'sonner';

import { useSeams } from '@seams/sdk/react';

import type { FrontendConfig } from '@/config';
import { useSetGreeting } from '@/shared/hooks/useSetGreeting';
import { NearGreetingSection } from './sections/NearGreetingSection';
import { SigningSessionSection } from './sections/SigningSessionSection';
import { ThresholdSignerSection } from './sections/ThresholdSignerSection';
import { createChainDefaultGreeting } from './demoEvmHelpers';
import { useDemoNearAccountFundingStatus } from './hooks/useDemoNearAccountFundingStatus';
import { useDemoNearActions } from './hooks/useDemoNearActions';
import { useDemoSigningSession } from './hooks/useDemoSigningSession';
import { useDemoThresholdSigners } from './hooks/useDemoThresholdSigners';
import './DemoPage.css';

type DemoPageTestOverrides = {
  useSeamsHook?: typeof useSeams;
  useSetGreetingHook?: typeof useSetGreeting;
  frontendConfig?: Pick<
    FrontendConfig,
    'chains' | 'managedRegistration' | 'relayerUrl' | 'tempoExplorerUrl' | 'tempoRpcUrl'
  >;
};

type DemoPageProps = {
  __testOverrides?: DemoPageTestOverrides;
};

export const DemoPage: React.FC<DemoPageProps> = (props) => {
  const useSeamsHook = props.__testOverrides?.useSeamsHook || useSeams;
  const useSetGreetingHook = props.__testOverrides?.useSetGreetingHook || useSetGreeting;

  const [clockMs, setClockMs] = useState(() => Date.now());

  // Lightweight clock for TTL countdown display
  useEffect(() => {
    const id = window.setInterval(() => setClockMs(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const {
    loginState: { isLoggedIn, walletId, nearAccountId, nearPublicKey },
    seams,
  } = useSeamsHook();

  const { onchainGreeting, isLoading, fetchGreeting, error } = useSetGreetingHook();

  const [tempoGreetingInput, setTempoGreetingInput] = useState(() =>
    createChainDefaultGreeting('Tempo'),
  );
  const [arcGreetingInput, setArcGreetingInput] = useState(() => createChainDefaultGreeting('Arc'));

  const nearAccountFunding = useDemoNearAccountFundingStatus({
    isLoggedIn,
    nearAccountId,
    nearPublicKey,
  });

  const nearActions = useDemoNearActions({
    isLoggedIn,
    canSignNear: nearAccountFunding.canSignNear,
    walletId,
    nearAccountId,
    nearPublicKey,
    seams,
    fetchGreeting,
  });

  const signingSession = useDemoSigningSession({
    clockMs,
    isLoggedIn,
    walletId,
    seams,
  });

  const thresholdSigners = useDemoThresholdSigners({
    isLoggedIn,
    walletId,
    seams,
    frontendConfig: props.__testOverrides?.frontendConfig,
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
        canSubmit={nearActions.canSubmit}
        nearAccountFundingStatus={nearAccountFunding.status}
        onFundAccount={nearAccountFunding.openFunding}
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

      <SigningSessionSection
        sessionRemainingUsesInput={signingSession.sessionRemainingUsesInput}
        onSessionRemainingUsesInputChange={signingSession.setSessionRemainingUsesInput}
        sessionTtlSecondsInput={signingSession.sessionTtlSecondsInput}
        onSessionTtlSecondsInputChange={signingSession.setSessionTtlSecondsInput}
        onCreateSession={signingSession.handleUnlockSession}
        unlockLoading={signingSession.unlockLoading}
        sessionStatus={signingSession.sessionStatus}
        expiresInSec={signingSession.expiresInSec}
        walletSession={signingSession.walletSession}
        sessionStatusLoading={signingSession.sessionStatusLoading}
        sessionStatusError={signingSession.sessionStatusError}
        onRefreshSessionStatus={signingSession.refreshSessionStatus}
      />
    </div>
  );
};

export default DemoPage;
