import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useSeams } from '../../context';
import {
  nearAccountRefFromAccountId,
  walletSessionRefFromSession,
} from '../../../core/signingEngine/interfaces/ecdsaChainTarget';
import './LinkedDevicesSection.css';

type RouterApiAuthenticatorRow = {
  signerSlot?: number;
  publicKey?: string;
};

type SignerRow = {
  credentialId: string;
  signerSlot: number;
  nearPublicKey: string | null;
};

function shortenKey(key: string): string {
  const value = key.trim();
  if (value.length <= 28) return value;
  return `${value.slice(0, 18)}...${value.slice(-8)}`;
}

export interface LinkedDevicesSectionProps {
  walletId: string | null;
  nearAccountId: string | null;
  isOpen?: boolean;
  className?: string;
  style?: React.CSSProperties;
}

/** Expandable panel under the Linked Devices menu item: lists the wallet's
 * linked signers (on-chain access keys annotated with signer slots), inline
 * instead of in a modal. */
export const LinkedDevicesSection: React.FC<LinkedDevicesSectionProps> = ({
  walletId,
  nearAccountId,
  isOpen = false,
  className,
  style,
}) => {
  const { seams, loginState, viewAccessKeyList } = useSeams();
  const [rows, setRows] = useState<SignerRow[]>([]);
  const [currentSignerSlot, setCurrentSignerSlot] = useState<number | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const loadedForRef = useRef<string | null>(null);

  const loadSigners = useCallback(async () => {
    if (!seams || !walletId || !nearAccountId) return;

    setIsLoading(true);
    setError(null);

    try {
      // Resolve current signer slot for highlighting
      let currentSignerSlotFromState: number | null = null;
      try {
        const { login } = await seams.auth.getWalletSession(walletId);
        const slot = (login as any)?.userData?.signerSlot;
        currentSignerSlotFromState =
          typeof slot === 'number' && Number.isFinite(slot) ? Math.floor(slot) : null;
      } catch {
        currentSignerSlotFromState = null;
      }
      setCurrentSignerSlot(currentSignerSlotFromState);

      const keys = await viewAccessKeyList({
        walletSession: walletSessionRefFromSession({
          walletId,
          walletSessionUserId: walletId,
        }),
        nearAccount: nearAccountRefFromAccountId(nearAccountId),
      });

      const keyMetaByPublicKey = new Map<string, { signerSlot?: number }>();

      // Best-effort: annotate access keys with signer slots from the
      // relay-private WebAuthn stores (auth-protected).
      const relayMetaByPublicKey = new Map<string, RouterApiAuthenticatorRow>();
      try {
        const relayerUrl = String((seams as any)?.configs?.network.relayer?.url || '')
          .trim()
          .replace(/\/$/, '');
        if (relayerUrl) {
          try {
            const resp = await fetch(`${relayerUrl}/near/public-keys`, {
              method: 'GET',
              credentials: 'include',
            });
            const json = await resp.json().catch(() => ({}) as any);
            const list =
              resp.ok && json?.ok === true && Array.isArray(json?.keys) ? (json.keys as any[]) : [];
            for (const row of list) {
              const pk = typeof row?.publicKey === 'string' ? row.publicKey.trim() : '';
              if (!pk) continue;
              const signerSlot =
                typeof row?.signerSlot === 'number' && Number.isFinite(row.signerSlot)
                  ? Math.floor(row.signerSlot)
                  : undefined;
              keyMetaByPublicKey.set(pk, {
                ...(signerSlot ? { signerSlot } : {}),
              });
            }
          } catch {
            // ignore
          }

          const rpIdOverride = String((seams as any)?.configs?.rpIdOverride || '').trim();
          const rpId =
            rpIdOverride ||
            (typeof window !== 'undefined' ? String(window.location.hostname || '').trim() : '');
          const url = `${relayerUrl}/webauthn/authenticators${rpId ? `?rpId=${encodeURIComponent(rpId)}` : ''}`;
          const resp = await fetch(url, { method: 'GET', credentials: 'include' });
          const json = await resp.json().catch(() => ({}) as any);
          const list: RouterApiAuthenticatorRow[] =
            resp.ok && json?.ok === true && Array.isArray(json?.authenticators)
              ? json.authenticators
              : [];
          for (const row of list) {
            const pk = typeof row?.publicKey === 'string' ? row.publicKey.trim() : '';
            if (!pk) continue;
            relayMetaByPublicKey.set(pk, row);
          }
        }
      } catch {
        // Ignore Router API metadata failures; fallback is pure on-chain access key listing.
      }

      const currentKey = loginState?.nearPublicKey || null;

      const nextSignerSlot = (() => {
        let next = 1;
        return () => {
          while (currentSignerSlotFromState != null && next === currentSignerSlotFromState) next++;
          return next++;
        };
      })();

      const nextRows: SignerRow[] = [];
      const items = Array.isArray((keys as any)?.keys)
        ? ((keys as any).keys as Array<{ public_key?: unknown }>)
        : [];
      for (const item of items) {
        const publicKey = typeof item?.public_key === 'string' ? item.public_key : null;
        const isCurrent = !!publicKey && !!currentKey && publicKey === currentKey;
        const keyMeta = publicKey ? keyMetaByPublicKey.get(publicKey) : undefined;
        const relayMeta = publicKey ? relayMetaByPublicKey.get(publicKey) : undefined;
        const metaSignerSlot =
          keyMeta && typeof keyMeta.signerSlot === 'number' && Number.isFinite(keyMeta.signerSlot)
            ? Math.floor(keyMeta.signerSlot)
            : null;
        const relaySignerSlot =
          relayMeta &&
          typeof relayMeta.signerSlot === 'number' &&
          Number.isFinite(relayMeta.signerSlot)
            ? Math.floor(relayMeta.signerSlot)
            : null;
        const signerSlot =
          isCurrent && currentSignerSlotFromState != null
            ? currentSignerSlotFromState
            : metaSignerSlot && metaSignerSlot >= 1
              ? metaSignerSlot
              : relaySignerSlot && relaySignerSlot >= 1
                ? relaySignerSlot
                : nextSignerSlot();
        nextRows.push({
          credentialId: publicKey || `access-key-${signerSlot}`,
          signerSlot,
          nearPublicKey: publicKey,
        });
      }
      // Active signer first, then by slot
      nextRows.sort((a, b) => {
        const aActive = currentSignerSlotFromState != null && a.signerSlot === currentSignerSlotFromState;
        const bActive = currentSignerSlotFromState != null && b.signerSlot === currentSignerSlotFromState;
        if (aActive !== bActive) return aActive ? -1 : 1;
        return a.signerSlot - b.signerSlot;
      });
      setRows(nextRows);
    } catch (err: any) {
      setError(err?.message || 'Failed to load linked signers or access keys');
    } finally {
      setIsLoading(false);
    }
  }, [seams, walletId, nearAccountId, loginState?.nearPublicKey, viewAccessKeyList]);

  // Load on first expand (and again when the wallet identity changes)
  useEffect(() => {
    if (!isOpen || !walletId || !nearAccountId) return;
    const loadKey = `${walletId}:${nearAccountId}`;
    if (loadedForRef.current === loadKey) return;
    loadedForRef.current = loadKey;
    void loadSigners();
  }, [isOpen, walletId, nearAccountId, loadSigners]);

  const copyKey = async (key: string) => {
    try {
      await navigator.clipboard.writeText(key);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey((prev) => (prev === key ? null : prev)), 2000);
    } catch (err) {
      console.error('Failed to copy to clipboard:', err);
    }
  };

  const handleClick = (e: React.MouseEvent) => {
    e.stopPropagation();
  };

  return (
    <div
      className={`w3a-dropdown-linked-devices-root ${isOpen ? 'is-expanded' : ''} ${className || ''}`}
      style={style}
      onClick={handleClick}
    >
      <div className="w3a-dropdown-linked-devices-clip">
        <div
          className="w3a-dropdown-linked-devices-content"
          aria-hidden={!isOpen}
          style={{ pointerEvents: isOpen ? 'auto' : 'none' }}
        >
          {isLoading && <div className="w3a-linked-devices-status">Loading signers…</div>}
          {!isLoading && error && (
            <div className="w3a-linked-devices-status">
              <span>{error}</span>
              <button
                type="button"
                className="w3a-linked-devices-retry"
                tabIndex={isOpen ? 0 : -1}
                onClick={() => void loadSigners()}
              >
                Retry
              </button>
            </div>
          )}
          {!isLoading && !error && rows.length === 0 && (
            <div className="w3a-linked-devices-status">No linked signers found.</div>
          )}
          {!isLoading && !error && rows.length > 0 && (
            <div className="w3a-linked-devices-list">
              {rows.map((row) => {
                const isActive =
                  currentSignerSlot != null && row.signerSlot === currentSignerSlot;
                const key = row.nearPublicKey;
                return (
                  <button
                    key={row.credentialId}
                    type="button"
                    className="w3a-linked-devices-row"
                    disabled={!key}
                    tabIndex={isOpen ? 0 : -1}
                    title={key ? `${key}\nClick to copy` : undefined}
                    onClick={() => key && void copyKey(key)}
                  >
                    <span className="w3a-linked-devices-slot">Signer {row.signerSlot}</span>
                    {isActive && <span className="w3a-linked-devices-active">active</span>}
                    <span className="w3a-linked-devices-key">
                      {key ? (copiedKey === key ? 'Copied!' : shortenKey(key)) : '—'}
                    </span>
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
