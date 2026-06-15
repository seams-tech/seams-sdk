import React from 'react';

import { LoadingButton } from '@/components/LoadingButton';
import type {
  DemoSigningSessionStatus,
  DemoWalletSessionSnapshot,
} from '../hooks/useDemoSigningSession';
import { WalletSessionStatusIndicator } from './WalletSessionStatusIndicator';

type SigningSessionSectionProps = {
  sessionRemainingUsesInput: number;
  onSessionRemainingUsesInputChange: (value: number) => void;
  sessionTtlSecondsInput: number;
  onSessionTtlSecondsInputChange: (value: number) => void;
  onCreateSession: () => void | Promise<void>;
  unlockLoading: boolean;
  sessionStatus: DemoSigningSessionStatus | null;
  expiresInSec: number | null;
  walletSession: DemoWalletSessionSnapshot | null;
  sessionStatusLoading: boolean;
  sessionStatusError: string;
  onRefreshSessionStatus: () => void | Promise<void>;
};

export function SigningSessionSection(props: SigningSessionSectionProps) {
  return (
    <div className="action-section">
      <div className="demo-divider" aria-hidden="true" />
      <h2 className="demo-subtitle">Signing Session</h2>
      <div className="action-text">
        Create a warm signing session with configurable <code>remaining_uses</code> and TTL.
        Authorize once with the active wallet auth method, then sign multiple times while the
        session is active.
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'flex-end' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, minWidth: 180, flex: 1 }}>
          <label style={{ fontSize: '0.9rem', color: 'var(--site-text-secondary)' }}>
            Remaining uses
          </label>
          <input
            type="number"
            min={0}
            step={1}
            value={props.sessionRemainingUsesInput}
            onChange={(event) =>
              props.onSessionRemainingUsesInputChange(parseInt(event.target.value || '0', 10))
            }
            style={{
              height: 44,
              padding: '0 12px',
              backgroundColor: 'var(--w3a-colors-surface2)',
              border: '1px solid var(--site-border)',
              borderRadius: 'var(--site-radius-lg)',
              color: 'var(--site-text-primary)',
              fontSize: '0.9rem',
            }}
          />
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, minWidth: 180, flex: 1 }}>
          <label style={{ fontSize: '0.9rem', color: 'var(--site-text-secondary)' }}>
            TTL (seconds)
          </label>
          <input
            type="number"
            min={0}
            step={1}
            value={props.sessionTtlSecondsInput}
            onChange={(event) =>
              props.onSessionTtlSecondsInputChange(parseInt(event.target.value || '0', 10))
            }
            style={{
              height: 44,
              padding: '0 12px',
              backgroundColor: 'var(--w3a-colors-surface2)',
              border: '1px solid var(--site-border)',
              borderRadius: 'var(--site-radius-lg)',
              color: 'var(--site-text-primary)',
              fontSize: '0.9rem',
            }}
          />
        </div>

        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <LoadingButton
            onClick={props.onCreateSession}
            loading={props.unlockLoading}
            loadingText="Creating..."
            variant="primary"
            size="medium"
            style={{ width: 180 }}
          >
            Create Session
          </LoadingButton>
        </div>
      </div>

      <div
        style={{
          marginTop: 12,
          background: 'var(--site-surface-muted)',
          border: '1px solid var(--site-border)',
          borderRadius: 'var(--site-radius-lg)',
          padding: 'var(--site-space-3)',
          fontSize: '0.9rem',
          color: 'var(--site-text-primary)',
        }}
      >
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <strong>Status:</strong>&nbsp;{props.sessionStatus?.status ?? '…'}
          </div>
          <div>
            <strong>Remaining uses:</strong>&nbsp;
            {typeof props.sessionStatus?.remainingUses === 'number'
              ? props.sessionStatus.remainingUses
              : '—'}
          </div>
          <div>
            <strong>TTL:</strong>&nbsp;
            {props.expiresInSec == null
              ? '—'
              : props.sessionStatus?.status === 'active'
                ? `${props.expiresInSec}s remaining`
                : `${props.expiresInSec}s`}
          </div>
        </div>
      </div>

      <div className="signing-session-status-footer">
        <WalletSessionStatusIndicator
          walletSession={props.walletSession}
          signingSession={props.sessionStatus}
          expiresInSec={props.expiresInSec}
          loading={props.sessionStatusLoading}
          error={props.sessionStatusError}
          onRefresh={props.onRefreshSessionStatus}
        />
      </div>
    </div>
  );
}
