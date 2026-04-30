import React from 'react';

import { LoadingButton } from '@/components/LoadingButton';
import Refresh from '@/components/icons/Refresh';

type NearGreetingSectionProps = {
  onchainGreeting: string | null | undefined;
  isLoading: boolean;
  greetingInput: string;
  onGreetingInputChange: (value: string) => void;
  onRefresh: () => void | Promise<void>;
  onSetGreeting: () => void | Promise<void>;
  txLoading: boolean;
  onSignDelegate: () => void | Promise<void>;
  delegateLoading: boolean;
  canSubmit: boolean;
  error: unknown;
};

export function NearGreetingSection(props: NearGreetingSectionProps) {
  return (
    <div className="action-section">
      <h2 className="demo-subtitle">Sign Transactions with TouchId</h2>
      <div className="action-text">Sign transactions securely in an cross-origin iframe.</div>

      <div className="greeting-controls-box">
        <div className="on-chain-greeting-box">
          <button
            onClick={props.onRefresh}
            disabled={props.isLoading}
            title="Refresh Greeting"
            className="refresh-icon-button"
            aria-busy={props.isLoading}
          >
            <Refresh size={22} strokeWidth={2} />
          </button>
          <p>
            <strong>{props.onchainGreeting ?? '...'}</strong>
          </p>
        </div>

        <div className="greeting-input-group">
          <input
            type="text"
            name="greeting"
            value={props.greetingInput}
            onChange={(event) => props.onGreetingInputChange(event.target.value)}
            placeholder="Enter new greeting"
          />
        </div>
        <LoadingButton
          onClick={props.onSetGreeting}
          loading={props.txLoading}
          loadingText="Processing..."
          variant="primary"
          size="medium"
          className="greeting-btn"
          disabled={!props.canSubmit || props.txLoading}
          style={{ width: 200 }}
        >
          Set Greeting
        </LoadingButton>
        <LoadingButton
          onClick={props.onSignDelegate}
          loading={props.delegateLoading}
          loadingText="Signing delegate..."
          variant="secondary"
          size="medium"
          className="greeting-btn"
          disabled={!props.canSubmit || props.delegateLoading}
          style={{ width: 200, marginTop: '0.5rem' }}
        >
          Send Delegate Action
        </LoadingButton>

        {props.error != null ? (
          <div className="error-message">Error: {String(props.error)}</div>
        ) : null}
      </div>
    </div>
  );
}
