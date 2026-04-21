import React from 'react';

import Refresh from '@/components/icons/Refresh';
import type {
  DemoSigningSessionStatus,
  DemoWalletSessionSnapshot,
} from '../hooks/useDemoSigningSession';

type WalletSessionStatusIndicatorProps = {
  walletSession: DemoWalletSessionSnapshot | null;
  signingSession: DemoSigningSessionStatus | null;
  expiresInSec: number | null;
  loading: boolean;
  error: string;
  onRefresh: () => void | Promise<void>;
};

function formatAuthMethod(value: unknown): string {
  const normalized = String(value || '').trim();
  if (!normalized) return '-';
  if (normalized === 'email_otp') return 'Email OTP';
  if (normalized === 'passkey') return 'Passkey';
  return normalized
    .split('_')
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

function formatSigningStatus(status: DemoSigningSessionStatus | null, loading: boolean): string {
  if (loading && !status) return 'Checking';
  if (!status) return 'Not ready';
  if (status.status === 'active') return 'Active';
  if (status.status === 'not_found') return 'Not found';
  return status.status.charAt(0).toUpperCase() + status.status.slice(1);
}

function formatTtl(args: {
  status: DemoSigningSessionStatus | null;
  expiresInSec: number | null;
}): string {
  if (!args.status || typeof args.expiresInSec !== 'number') return '-';
  if (args.status.status === 'active') return `${args.expiresInSec}s`;
  return args.expiresInSec > 0 ? `${args.expiresInSec}s` : '0s';
}

function statusTone(args: {
  walletSession: DemoWalletSessionSnapshot | null;
  signingSession: DemoSigningSessionStatus | null;
  error: string;
}): 'active' | 'warning' | 'muted' {
  if (args.error) return 'warning';
  if (args.signingSession?.status === 'active') return 'active';
  if (args.walletSession?.login.isLoggedIn) return 'warning';
  return 'muted';
}

export function WalletSessionStatusIndicator(
  props: WalletSessionStatusIndicatorProps,
): React.JSX.Element {
  const walletUnlocked = props.walletSession?.login.isLoggedIn === true;
  const tone = statusTone({
    walletSession: props.walletSession,
    signingSession: props.signingSession,
    error: props.error,
  });
  const authMethod =
    props.signingSession?.authMethod ||
    props.walletSession?.authMethod ||
    props.walletSession?.login.authMethod;
  const retention = props.signingSession?.retention || props.walletSession?.retention || '-';

  return (
    <section className="wallet-session-status" aria-label="Wallet session status">
      <div className="wallet-session-status__title">
        <span className={`wallet-session-status__dot is-${tone}`} aria-hidden="true" />
        <span>Wallet Session</span>
      </div>

      <div className="wallet-session-status__grid">
        <div className="wallet-session-status__metric">
          <span className="wallet-session-status__label">Wallet</span>
          <span className="wallet-session-status__value">
            {walletUnlocked ? 'Unlocked' : props.loading ? 'Checking' : 'Locked'}
          </span>
        </div>
        <div className="wallet-session-status__metric">
          <span className="wallet-session-status__label">Auth</span>
          <span className="wallet-session-status__value">{formatAuthMethod(authMethod)}</span>
        </div>
        <div className="wallet-session-status__metric">
          <span className="wallet-session-status__label">Signing</span>
          <span className="wallet-session-status__value">
            {formatSigningStatus(props.signingSession, props.loading)}
          </span>
        </div>
        <div className="wallet-session-status__metric">
          <span className="wallet-session-status__label">Uses</span>
          <span className="wallet-session-status__value">
            {typeof props.signingSession?.remainingUses === 'number'
              ? props.signingSession.remainingUses
              : '-'}
          </span>
        </div>
        <div className="wallet-session-status__metric">
          <span className="wallet-session-status__label">TTL</span>
          <span className="wallet-session-status__value">
            {formatTtl({ status: props.signingSession, expiresInSec: props.expiresInSec })}
          </span>
        </div>
        <div className="wallet-session-status__metric">
          <span className="wallet-session-status__label">Retention</span>
          <span className="wallet-session-status__value">{String(retention || '-')}</span>
        </div>
      </div>

      <button
        type="button"
        className="wallet-session-status__refresh refresh-icon-button"
        onClick={() => {
          void props.onRefresh();
        }}
        aria-label="Refresh wallet session status"
        title="Refresh wallet session status"
        aria-busy={props.loading}
        disabled={props.loading}
      >
        <Refresh size={16} strokeWidth={2} />
      </button>
    </section>
  );
}

