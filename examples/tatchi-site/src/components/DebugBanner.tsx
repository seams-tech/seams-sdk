import React, { useEffect, useState } from 'react';
import { useTatchi } from '@tatchi-xyz/sdk/react';

export const DebugBanner: React.FC = () => {
  const { walletIframeConnected, accountInputState, tatchi } = useTatchi();
  const [recentCount, setRecentCount] = useState<number>(
    accountInputState.indexDBAccounts?.length || 0,
  );
  const [connecting, setConnecting] = useState<boolean>(false);
  const shouldHideOnMobile = React.useMemo(() => {
    try {
      const ua = (typeof navigator !== 'undefined' ? navigator.userAgent : '') || '';
      const coarse =
        typeof window !== 'undefined' &&
        !!window.matchMedia &&
        window.matchMedia('(pointer: coarse)').matches;
      const mobileUA = /Mobi|Android|iPhone|iPad|iPod/i.test(ua);
      return coarse || mobileUA;
    } catch {
      return false;
    }
  }, []);

  useEffect(() => {
    setRecentCount(accountInputState.indexDBAccounts?.length || 0);
  }, [accountInputState.indexDBAccounts]);

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        setConnecting(true);
        // Force-init wallet iframe if configured to surface READY state quickly
        await tatchi.initWalletIframe?.();
      } catch {
      } finally {
        if (mounted) setConnecting(false);
      }
    })();
    return () => {
      mounted = false;
    };
  }, [tatchi]);

  const status = walletIframeConnected
    ? 'connected'
    : connecting
      ? 'connecting…'
      : 'waiting for READY';

  if (shouldHideOnMobile) return null;

  return (
    <div
      style={{
        position: 'absolute',
        bottom: '-1rem',
        left: '0rem',
        color: walletIframeConnected ? 'rgba(66,140,240,0.4)' : 'rgba(234,179,8,0.4)',
        padding: '4px 4px 0px 4px',
        lineHeight: '0.75rem',
        fontSize: '10px',
        display: 'flex',
        gap: '6px',
        alignItems: 'center',
      }}
    >
      <strong>wallet iframe:</strong> <span>{status}</span>
      {walletIframeConnected && (
        <>
          <span>|</span>
          <strong>accounts:</strong> <span>{recentCount}</span>
        </>
      )}
    </div>
  );
};

export default DebugBanner;
