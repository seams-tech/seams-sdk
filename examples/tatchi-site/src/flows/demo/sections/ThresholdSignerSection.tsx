import React from 'react';

import { CopyButton } from '@/components/CopyButton';
import { LoadingButton } from '@/components/LoadingButton';
import Refresh from '@/components/icons/Refresh';

type ThresholdSignerSectionProps = {
  thresholdEvmFundingAddress: string | null;
  onCopyFundingAddress: () => void;
  onSetTempoFeeToken: () => void | Promise<void>;
  tempoFeeTokenConfigLoading: boolean;
  tempoFeeTokenConfigTarget: 'alpha' | null;
  tempoFeeTokenIsAlpha: boolean;
  onTempoDripToken: () => void | Promise<void>;
  tempoDripLoading: boolean;
  tempoGreeting: string | null;
  tempoGreetingLoading: boolean;
  onRefreshTempoGreeting: () => void | Promise<unknown>;
  tempoGreetingInput: string;
  onTempoGreetingInputChange: (value: string) => void;
  tempoGreetingError: string | null;
  onSignTempoTransaction: () => void | Promise<void>;
  tempoThresholdSignLoading: boolean;
  canSignTempo: boolean;
  arcGreeting: string | null;
  arcGreetingLoading: boolean;
  onRefreshArcGreeting: () => void | Promise<unknown>;
  arcGreetingInput: string;
  onArcGreetingInputChange: (value: string) => void;
  arcGreetingError: string | null;
  onSignEvmTransaction: () => void | Promise<void>;
  evmThresholdSignLoading: boolean;
  canSignEvm: boolean;
};

export function ThresholdSignerSection(props: ThresholdSignerSectionProps) {
  return (
    <div className="action-section">
      <div className="demo-divider" aria-hidden="true" />
      <h2 className="demo-subtitle">Tempo + EVM Threshold Signers</h2>
      <div className="action-text funding-instructions">
        <span>
          Fund this threshold EVM signer address with Arc native gas. Tempo setUserToken is
          configured via the buttons below.
        </span>
        <div className="funding-address-row">
          <span className="funding-address-text">
            {props.thresholdEvmFundingAddress ||
              'Address unavailable. Sign once to bootstrap threshold ECDSA.'}
          </span>
          {props.thresholdEvmFundingAddress ? (
            <CopyButton
              text={props.thresholdEvmFundingAddress}
              ariaLabel="Copy funding address"
              className="funding-address-copy"
              size={18}
              onCopy={props.onCopyFundingAddress}
            />
          ) : (
            <span className="funding-address-copy-placeholder" aria-hidden="true" />
          )}
        </div>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: 10,
            marginTop: 10,
          }}
        >
          <LoadingButton
            onClick={props.onSetTempoFeeToken}
            loading={props.tempoFeeTokenConfigLoading && props.tempoFeeTokenConfigTarget === 'alpha'}
            loadingText="Configuring..."
            variant="secondary"
            size="medium"
            style={{ width: '100%' }}
            disabled={props.tempoFeeTokenConfigLoading || props.tempoFeeTokenIsAlpha}
          >
            Set Tempo Fee Token
          </LoadingButton>
          <LoadingButton
            onClick={props.onTempoDripToken}
            loading={props.tempoDripLoading}
            loadingText="Dripping..."
            variant="secondary"
            size="medium"
            style={{ width: '100%' }}
            disabled={props.tempoDripLoading || props.tempoFeeTokenConfigLoading}
          >
            Drip Fee Tokens
          </LoadingButton>
        </div>
      </div>

      <div style={{ display: 'grid', gap: 10, marginTop: 12 }}>
        <div className="evm-greeting-stack" style={{ display: 'grid', gap: 8 }}>
          <div style={{ fontSize: '0.9rem', color: 'var(--fe-text-secondary)' }}>Tempo Greeting</div>
          <div className="on-chain-greeting-box">
            <button
              onClick={props.onRefreshTempoGreeting}
              disabled={props.tempoGreetingLoading}
              title="Refresh Tempo Greeting"
              className="refresh-icon-button"
              aria-busy={props.tempoGreetingLoading}
            >
              <Refresh size={22} strokeWidth={2} />
            </button>
            <p>
              <strong>{props.tempoGreeting ?? '...'}</strong>
            </p>
          </div>
          <div className="greeting-input-group" style={{ marginBottom: 0 }}>
            <input
              type="text"
              name="tempo-greeting"
              value={props.tempoGreetingInput}
              onChange={(event) => props.onTempoGreetingInputChange(event.target.value)}
              placeholder="Enter Tempo greeting"
            />
          </div>
        </div>
        {props.tempoGreetingError ? (
          <div className="error-message">Tempo greeting error: {props.tempoGreetingError}</div>
        ) : null}
        <LoadingButton
          onClick={props.onSignTempoTransaction}
          loading={props.tempoThresholdSignLoading}
          loadingText="Signing..."
          variant="primary"
          size="medium"
          style={{ width: '100%' }}
          disabled={!props.canSignTempo || props.tempoThresholdSignLoading}
        >
          Sign Tempo Transaction
        </LoadingButton>

        <div className="evm-greeting-stack" style={{ display: 'grid', gap: 8 }}>
          <div style={{ fontSize: '0.9rem', color: 'var(--fe-text-secondary)' }}>Arc Greeting</div>
          <div className="on-chain-greeting-box">
            <button
              onClick={props.onRefreshArcGreeting}
              disabled={props.arcGreetingLoading}
              title="Refresh Arc Greeting"
              className="refresh-icon-button"
              aria-busy={props.arcGreetingLoading}
            >
              <Refresh size={22} strokeWidth={2} />
            </button>
            <p>
              <strong>{props.arcGreeting ?? '...'}</strong>
            </p>
          </div>
          <div className="greeting-input-group" style={{ marginBottom: 0 }}>
            <input
              type="text"
              name="arc-greeting"
              value={props.arcGreetingInput}
              onChange={(event) => props.onArcGreetingInputChange(event.target.value)}
              placeholder="Enter Arc greeting"
            />
          </div>
        </div>
        {props.arcGreetingError ? (
          <div className="error-message">Arc greeting error: {props.arcGreetingError}</div>
        ) : null}

        <LoadingButton
          onClick={props.onSignEvmTransaction}
          loading={props.evmThresholdSignLoading}
          loadingText="Signing..."
          variant="primary"
          size="medium"
          style={{ width: '100%' }}
          disabled={!props.canSignEvm || props.evmThresholdSignLoading}
        >
          Sign EVM Transaction
        </LoadingButton>
      </div>
    </div>
  );
}
