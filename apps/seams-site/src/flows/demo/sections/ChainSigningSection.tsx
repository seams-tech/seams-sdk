import React from 'react';

import { CopyButton } from '@/components/CopyButton';
import { LoadingButton } from '@/components/LoadingButton';
import Refresh from '@/components/icons/Refresh';
import type { DemoTempoFundingStatus } from '../hooks/useDemoTempoFundingStatus';

export type DemoChainId = 'near' | 'tempo' | 'arc';

/* Normalized per-chain view: the demo is the same interaction (read greeting,
   type greeting, sign with passkey) against three chains, so one section
   renders the selected chain instead of stacking three lookalike stanzas. */
export type DemoChainView = {
  id: DemoChainId;
  label: string;
  greeting: string | null | undefined;
  greetingLoading: boolean;
  onRefreshGreeting: () => void | Promise<unknown>;
  greetingInput: string;
  onGreetingInputChange: (value: string) => void;
  statusText: string | null;
  errorText: string | null;
  onSign: () => void | Promise<void>;
  signLoading: boolean;
  canSign: boolean;
  signLabel: string;
};

type ChainSigningSectionProps = {
  chains: readonly DemoChainView[];
  /* names the credential that confirms the signature (passkey vs email OTP) */
  heading: string;
  selectedChainId: DemoChainId;
  onSelectChain: (id: DemoChainId) => void;
  /* NEAR-only secondary action (kept for delegate-signing testing) */
  onSignDelegate: () => void | Promise<void>;
  delegateLoading: boolean;
  canSignDelegate: boolean;
  /* testnet plumbing for the threshold-signer chains */
  thresholdOwnerAddress: string | null;
  onCopyThresholdOwnerAddress: () => void;
  onPrepareTempoFeeToken: () => void | Promise<void>;
  tempoFeeTokenPrepareLoading: boolean;
  tempoPreparationUnavailableReason: string | null;
  /* hides the funding button when 'ready' (AlphaUSD fee token set + funded) */
  tempoFundingStatus: DemoTempoFundingStatus;
};

export function ChainSigningSection(props: ChainSigningSectionProps) {
  const chain = props.chains.find((c) => c.id === props.selectedChainId) ?? props.chains[0];
  const activeIndex = Math.max(
    0,
    props.chains.findIndex((c) => c.id === chain.id),
  );

  return (
    <div className="action-section">
      <h2 className="demo-subtitle">{props.heading}</h2>

      {/* segmented control matching the SeamsAuthMenu seg: track + sliding pill */}
      <div
        className="demo-chain-seg"
        role="tablist"
        aria-label="Demo chain"
        style={{ '--demo-seg-index': activeIndex } as React.CSSProperties}
      >
        <span className="demo-chain-seg__pill" aria-hidden />
        <div className="demo-chain-seg__grid">
          {props.chains.map((c) => (
            <button
              key={c.id}
              type="button"
              role="tab"
              aria-selected={c.id === chain.id}
              className={`demo-chain-seg__btn${c.id === chain.id ? ' is-active' : ''}`}
              onClick={() => props.onSelectChain(c.id)}
            >
              {c.label}
            </button>
          ))}
        </div>
      </div>

      {/* keyed by chain: remount fades the new view in */}
      <div className="demo-chain-view" key={chain.id}>
      <div className="greeting-controls-box">
        <div className="on-chain-greeting-box">
          <button
            onClick={() => void chain.onRefreshGreeting()}
            disabled={chain.greetingLoading}
            title="Refresh greeting"
            className="refresh-icon-button"
            aria-busy={chain.greetingLoading}
          >
            <Refresh size={22} strokeWidth={2} />
          </button>
          <p>
            <strong>{chain.greeting ?? '...'}</strong>
          </p>
        </div>

        <div className="greeting-input-group">
          <input
            type="text"
            name={`${chain.id}-greeting`}
            value={chain.greetingInput}
            onChange={(event) => chain.onGreetingInputChange(event.target.value)}
            placeholder="Enter a new greeting"
          />
        </div>

        {chain.statusText ? <div className="near-funding-status">{chain.statusText}</div> : null}
        {chain.errorText ? <div className="error-message">{chain.errorText}</div> : null}

        {/* funding is the precondition, so it leads; hidden once the probe
            confirms the AlphaUSD fee token is set and funded ('ready'), and
            held disabled while the probe is in flight */}
        {chain.id === 'tempo' && props.tempoFundingStatus !== 'ready' ? (
          <>
            <LoadingButton
              onClick={props.onPrepareTempoFeeToken}
              loading={props.tempoFeeTokenPrepareLoading}
              loadingText="Funding..."
              variant="secondary"
              size="medium"
              style={{ width: '100%' }}
              disabled={
                props.tempoFeeTokenPrepareLoading ||
                props.tempoFundingStatus === 'checking' ||
                Boolean(props.tempoPreparationUnavailableReason)
              }
            >
              Fund Tempo Account
            </LoadingButton>
            {props.tempoPreparationUnavailableReason ? (
              <div className="demo-capability-note">
                {props.tempoPreparationUnavailableReason}
              </div>
            ) : null}
          </>
        ) : null}

        <LoadingButton
          onClick={chain.onSign}
          loading={chain.signLoading}
          loadingText="Signing..."
          variant="primary"
          size="medium"
          style={{ width: '100%' }}
          disabled={!chain.canSign || chain.signLoading}
        >
          {chain.signLabel}
        </LoadingButton>

        {chain.id === 'near' ? (
          <LoadingButton
            onClick={props.onSignDelegate}
            loading={props.delegateLoading}
            loadingText="Signing delegate..."
            variant="secondary"
            size="medium"
            style={{ width: '100%' }}
            disabled={!props.canSignDelegate || props.delegateLoading}
          >
            Send Delegate Action
          </LoadingButton>
        ) : null}
      </div>

      {chain.id === 'arc' ? (
        <div className="demo-funding">
          <div className="demo-funding__hint">
            Fund this signer address with test gas from the{' '}
            <a href="https://faucet.circle.com/" target="_blank" rel="noreferrer">
              Circle Faucet
            </a>
            :
          </div>
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
        </div>
      ) : null}
      </div>
    </div>
  );
}
