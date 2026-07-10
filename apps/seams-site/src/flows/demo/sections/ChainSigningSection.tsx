import React from 'react';

import { CopyButton } from '@/components/CopyButton';
import { LoadingButton } from '@/components/LoadingButton';
import Refresh from '@/components/icons/Refresh';

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
  /* open the testnet-setup disclosure by default (e.g. the signer has no
     gas, so funding is the user's actual next step) */
  setupDefaultOpen?: boolean;
};

/* Details with a default-open signal that can arrive late (async balance
   probe): follows the prop until the user toggles it themselves. */
function TestnetSetupDetails(props: {
  defaultOpen: boolean;
  children: React.ReactNode;
}): React.JSX.Element {
  const [open, setOpen] = React.useState(props.defaultOpen);
  const userToggledRef = React.useRef(false);

  React.useEffect(() => {
    if (!userToggledRef.current) {
      setOpen(props.defaultOpen);
    }
  }, [props.defaultOpen]);

  return (
    <details
      className="demo-setup"
      open={open}
      onToggle={(event) => setOpen((event.target as HTMLDetailsElement).open)}
    >
      <summary
        onClick={() => {
          userToggledRef.current = true;
        }}
      >
        Testnet setup
      </summary>
      {props.children}
    </details>
  );
}

type ChainSigningSectionProps = {
  chains: readonly DemoChainView[];
  selectedChainId: DemoChainId;
  onSelectChain: (id: DemoChainId) => void;
  /* NEAR-only secondary action (kept for delegate-signing testing) */
  onSignDelegate: () => void | Promise<void>;
  delegateLoading: boolean;
  canSignDelegate: boolean;
  /* testnet plumbing for the threshold-signer chains, demoted to a
     collapsed disclosure: it is a precondition, not demo content */
  thresholdOwnerAddress: string | null;
  onCopyThresholdOwnerAddress: () => void;
  onPrepareTempoFeeToken: () => void | Promise<void>;
  tempoFeeTokenPrepareLoading: boolean;
  tempoPreparationUnavailableReason: string | null;
};

export function ChainSigningSection(props: ChainSigningSectionProps) {
  const chain = props.chains.find((c) => c.id === props.selectedChainId) ?? props.chains[0];
  const activeIndex = Math.max(
    0,
    props.chains.findIndex((c) => c.id === chain.id),
  );

  return (
    <div className="action-section">
      <h2 className="demo-subtitle">Sign a transaction with your passkey</h2>

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

      {/* keyed by chain: remount fades the new view in (and resets the
          per-chain setup disclosure to closed) */}
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

        <LoadingButton
          onClick={chain.onSign}
          loading={chain.signLoading}
          loadingText="Signing..."
          variant="primary"
          size="medium"
          style={{ width: '100%', marginTop: '0.5rem' }}
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
            style={{ width: '100%', marginTop: '0.5rem' }}
            disabled={!props.canSignDelegate || props.delegateLoading}
          >
            Send Delegate Action
          </LoadingButton>
        ) : null}
      </div>

      {chain.id !== 'near' ? (
        <TestnetSetupDetails defaultOpen={Boolean(chain.setupDefaultOpen)}>
          <div className="demo-setup__body">
            <div className="demo-setup__hint">
              Fund this signer address with test gas
              {chain.id === 'tempo' ? ', then prepare AlphaUSD fee tokens:' : ':'}
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
            {chain.id === 'tempo' ? (
              <LoadingButton
                onClick={props.onPrepareTempoFeeToken}
                loading={props.tempoFeeTokenPrepareLoading}
                loadingText="Preparing..."
                variant="secondary"
                size="medium"
                style={{ width: '100%' }}
                disabled={
                  props.tempoFeeTokenPrepareLoading ||
                  Boolean(props.tempoPreparationUnavailableReason)
                }
              >
                Prepare Tempo Fee Token
              </LoadingButton>
            ) : null}
            {chain.id === 'tempo' && props.tempoPreparationUnavailableReason ? (
              <div className="demo-capability-note">
                {props.tempoPreparationUnavailableReason}
              </div>
            ) : null}
            <div className="demo-setup__hint">
              Need test funds?{' '}
              <a href="https://faucet.circle.com/" target="_blank" rel="noreferrer">
                Circle Faucet
              </a>
            </div>
          </div>
        </TestnetSetupDetails>
      ) : null}
      </div>
    </div>
  );
}
