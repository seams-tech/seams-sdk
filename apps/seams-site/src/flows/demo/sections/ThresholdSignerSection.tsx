import React from 'react';

import { CopyButton } from '@/components/CopyButton';
import { LoadingButton } from '@/components/LoadingButton';
import Refresh from '@/components/icons/Refresh';

type ThresholdSignerSectionProps = {
  thresholdOwnerAddress: string | null;
  onCopyThresholdOwnerAddress: () => void;
  onPrepareTempoFeeToken: () => void | Promise<void>;
  tempoFeeTokenPrepareLoading: boolean;
  tempoPreparationUnavailableReason: string | null;
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
          Fund this threshold owner address with Arc native gas for Arc signing. Prepare AlphaUSD
          fee tokens before signing Tempo transactions.
        </span>
        <div className="funding-address-row">
          <span className="funding-address-text">
            {props.thresholdOwnerAddress ||
              'Threshold ECDSA address unavailable. Refresh the wallet session before funding or signing.'}
          </span>
          {props.thresholdOwnerAddress ? (
            <CopyButton
              text={props.thresholdOwnerAddress}
              ariaLabel="Copy threshold owner address"
              className="funding-address-copy"
              size={18}
              onCopy={props.onCopyThresholdOwnerAddress}
            />
          ) : (
            <span className="funding-address-copy-placeholder" aria-hidden="true" />
          )}
        </div>
        <div
          style={{
            display: 'grid',
            gap: 10,
            marginTop: 10,
          }}
        >
          <LoadingButton
            onClick={props.onPrepareTempoFeeToken}
            loading={props.tempoFeeTokenPrepareLoading}
            loadingText="Preparing..."
            variant="secondary"
            size="medium"
            style={{ width: '100%' }}
            disabled={
              props.tempoFeeTokenPrepareLoading || Boolean(props.tempoPreparationUnavailableReason)
            }
          >
            Prepare Tempo Fee Token
          </LoadingButton>
        </div>
        {props.tempoPreparationUnavailableReason ? (
          <div className="demo-capability-note" style={{ marginTop: 10 }}>
            {props.tempoPreparationUnavailableReason}
          </div>
        ) : null}
      </div>

      <div style={{ display: 'grid', gap: 10, marginTop: 12 }}>
        <div className="evm-greeting-stack" style={{ display: 'grid', gap: 8 }}>
          <div style={{ fontSize: '0.9rem', color: 'var(--site-text-secondary)' }}>
            Tempo Greeting
          </div>
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
          Sign Tempo EIP-2718 Transaction
        </LoadingButton>

        <div className="evm-greeting-stack" style={{ display: 'grid', gap: 8 }}>
          <div style={{ fontSize: '0.9rem', color: 'var(--site-text-secondary)' }}>
            Arc Greeting
          </div>
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
        <div style={{ fontSize: '0.9rem', color: 'var(--site-text-secondary)' }}>
          Need test funds?{' '}
          <a href="https://faucet.circle.com/" target="_blank" rel="noreferrer">
            Circle Faucet
          </a>
        </div>

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
