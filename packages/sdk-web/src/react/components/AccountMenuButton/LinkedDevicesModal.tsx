import React, { useState, useEffect } from 'react';
import { useSeams } from '../../context';
import './LinkedDevicesModal.css';
import { useTheme, Theme } from '../theme';
import {
  nearAccountRefFromAccountId,
  walletSessionRefFromSession,
} from '../../../core/signingEngine/interfaces/ecdsaChainTarget';

interface LinkedDevicesModalProps {
  walletId: string;
  nearAccountId: string;
  isOpen: boolean;
  onClose: () => void;
}

type RouterApiAuthenticatorRow = {
  signerSlot?: number;
  publicKey?: string;
};

export const LinkedDevicesModal: React.FC<LinkedDevicesModalProps> = ({
  walletId,
  nearAccountId,
  isOpen,
  onClose,
}) => {
  const { seams, loginState, viewAccessKeyList } = useSeams();
  const { theme, tokens } = useTheme();
  const scopedTokens = React.useMemo(
    () => (theme === 'dark' ? { dark: tokens } : { light: tokens }),
    [theme, tokens],
  );
  const pageSize = 3;
  // Authenticators list: credentialId + signer slot
  const [authRows, setAuthRows] = useState<
    Array<{
      credentialId: string;
      signerSlot: number;
      nearPublicKey: string | null;
    }>
  >([
    {
      credentialId: 'placeholder',
      signerSlot: 0,
      nearPublicKey: null,
    },
  ]);
  const [page, setPage] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tooltipVisible, setTooltipVisible] = useState<number | null>(null);
  const [currentSignerSlot, setCurrentSignerSlot] = useState<number | null>(null);

  useEffect(() => {
    if (isOpen) {
      setPage(0);
      loadAuthenticators();
    }
  }, [isOpen, walletId, nearAccountId]);

  useEffect(() => {
    if (!isOpen) return;
    setPage(0);
  }, [isOpen, authRows.length]);

  // Close on ESC press while modal is open
  useEffect(() => {
    if (!isOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' || e.key === 'Esc') {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [isOpen, onClose]);

  const loadAuthenticators = async () => {
    if (!seams) return;

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

      // Best-effort: fetch signer metadata from relay-private WebAuthn stores (auth-protected).
      // This annotates access keys with signer slots.
      const relayMetaByPublicKey = new Map<string, RouterApiAuthenticatorRow>();
      try {
        const relayerUrl = String((seams as any)?.configs?.network.relayer?.url || '')
          .trim()
          .replace(/\/$/, '');
        if (relayerUrl) {
          // Prefer the dedicated key metadata endpoint when available.
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
        // Ignore relay metadata failures; fallback is pure on-chain access key listing.
      }

      const currentKey = loginState?.nearPublicKey || null;

      const nextSignerSlot = (() => {
        let next = 1;
        return () => {
          while (currentSignerSlotFromState != null && next === currentSignerSlotFromState)
            next++;
          return next++;
        };
      })();

      const rows: Array<{
        credentialId: string;
        signerSlot: number;
        nearPublicKey: string | null;
      }> = [];
      const items = Array.isArray((keys as any)?.keys)
        ? ((keys as any).keys as Array<{ public_key?: unknown }>)
        : [];
      for (const item of items) {
        const publicKey = typeof item?.public_key === 'string' ? item.public_key : null;
        const isCurrent = !!publicKey && !!currentKey && publicKey === currentKey;
        const keyMeta = publicKey ? keyMetaByPublicKey.get(publicKey) : undefined;
        const relayMeta = publicKey ? relayMetaByPublicKey.get(publicKey) : undefined;
        const metaSignerSlot =
          keyMeta &&
          typeof keyMeta.signerSlot === 'number' &&
          Number.isFinite(keyMeta.signerSlot)
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
        rows.push({
          credentialId: publicKey || `access-key-${signerSlot}`,
          signerSlot,
          nearPublicKey: publicKey,
        });
      }
      setAuthRows(rows);
    } catch (err: any) {
      setError(err.message || 'Failed to load linked signers or access keys');
    } finally {
      setIsLoading(false);
    }
  };

  const copyToClipboard = async (text: string, keyIndex: number) => {
    try {
      await navigator.clipboard.writeText(text);

      // Fire custom event for copy action
      const copyEvent = new CustomEvent('accessKeyCopied', {
        detail: {
          publicKey: text,
          keyIndex: keyIndex,
          timestamp: Date.now(),
        },
      });
      window.dispatchEvent(copyEvent);

      // Show brief tooltip feedback
      setTooltipVisible(keyIndex);
      setTimeout(() => setTooltipVisible(null), 2000);
    } catch (err) {
      console.error('Failed to copy to clipboard:', err);
    }
  };

  if (!isOpen) return null;

  // Prevent any events from bubbling up to parent components
  const handleBackdropClick = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    onClose();
  };

  const handleModalContentClick = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    // Don't call onClose here - we want to keep the modal open
  };

  return (
    <Theme theme={theme} tokens={scopedTokens}>
      <div
        className={`w3a-access-keys-modal-backdrop theme-${theme}`}
        onClick={handleBackdropClick}
        onMouseDown={(e) => e.stopPropagation()}
        onMouseUp={(e) => e.stopPropagation()}
      >
        <div
          className="w3a-access-keys-modal-content"
          onClick={handleModalContentClick}
          onMouseDown={(e) => e.stopPropagation()}
          onMouseUp={(e) => e.stopPropagation()}
        >
          <div className="w3a-access-keys-modal-header">
            <h2 className="w3a-access-keys-modal-title">Linked Signers</h2>
          </div>
          <button
            className="w3a-access-keys-modal-close"
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              onClose();
            }}
          >
            ✕
          </button>

          {error && (
            <div className="w3a-access-keys-error">
              <p>{error}</p>
              <button
                onClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  loadAuthenticators();
                }}
                className="w3a-btn w3a-btn-primary"
              >
                Try Again
              </button>
            </div>
          )}

          {!isLoading &&
            !error &&
            authRows.filter((r) => r.credentialId !== 'placeholder').length === 0 && (
              <div className="w3a-access-keys-empty">
                <p>No linked signers found.</p>
              </div>
            )}

          {!error && authRows.filter((r) => r.credentialId !== 'placeholder').length > 0 && (
            <div className="w3a-keys-list">
              {(() => {
                const rows = authRows.filter((r) => r.credentialId !== 'placeholder');
                const current =
                  currentSignerSlot != null
                    ? rows.find((r) => r.signerSlot === currentSignerSlot)
                    : null;
                const othersAll =
                  currentSignerSlot != null
                    ? rows.filter((r) => r.signerSlot !== currentSignerSlot)
                    : rows;

                const totalOthers = othersAll.length;
                const totalPages = Math.max(1, Math.ceil(totalOthers / pageSize));
                const pageSafe = Math.min(page, Math.max(0, totalPages - 1));
                const startIndex = pageSafe * pageSize;
                const endIndex = Math.min(totalOthers, startIndex + pageSize);
                const others = othersAll.slice(startIndex, endIndex);

                const items: React.ReactNode[] = [];

                if (current) {
                  const index = 0;
                  const currentKey = current.nearPublicKey || loginState?.nearPublicKey || null;
                  items.push(
                    <div key={`current-${current.signerSlot}`} className="w3a-key-item">
                      <div className="w3a-key-content">
                        <div className="w3a-key-details">
                          <div className="w3a-key-header">
                            <div className="mono w3a-signer-row">
                              <span className="w3a-signer-badge">
                                Signer {current.signerSlot}
                              </span>
                              <span className="w3a-current-signer-text">(active signer)</span>
                            </div>
                          </div>
                          {currentKey && (
                            <div
                              className="mono w3a-copyable-key w3a-access-key-current"
                              onClick={(e) => {
                                e.stopPropagation();
                                copyToClipboard(currentKey, index);
                              }}
                              onMouseEnter={() => setTooltipVisible(index)}
                              onMouseLeave={() => setTooltipVisible(null)}
                              title="Click to copy"
                            >
                              Access Key: {currentKey}
                              {tooltipVisible === index && (
                                <div className="w3a-copy-tooltip">Click to copy</div>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>,
                  );
                }

                others.forEach((item, i) => {
                  const globalIndex = startIndex + i;
                  items.push(
                    <div key={`other-${item.signerSlot}-${i}`} className="w3a-key-item">
                      <div className="w3a-key-content">
                        <div className="w3a-key-details">
                          <div className="w3a-key-header">
                            <div className="mono w3a-signer-row">
                              <span className="w3a-signer-badge">Signer {item.signerSlot}</span>
                            </div>
                          </div>
                          {item.nearPublicKey && (
                            <div
                              className="mono w3a-copyable-key"
                              onClick={(e) => {
                                e.stopPropagation();
                                copyToClipboard(item.nearPublicKey!, 10 + globalIndex);
                              }}
                              onMouseEnter={() => setTooltipVisible(10 + globalIndex)}
                              onMouseLeave={() => setTooltipVisible(null)}
                              title="Click to copy"
                            >
                              Access Key: {item.nearPublicKey}
                              {tooltipVisible === 10 + globalIndex && (
                                <div className="w3a-copy-tooltip">Click to copy</div>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>,
                  );
                });

                return items;
              })()}
            </div>
          )}

          {!error &&
            authRows.filter((r) => r.credentialId !== 'placeholder').length > 0 &&
            (() => {
              const rows = authRows.filter((r) => r.credentialId !== 'placeholder');
              const current =
                currentSignerSlot != null
                  ? rows.find((r) => r.signerSlot === currentSignerSlot)
                  : null;
              const othersAll =
                currentSignerSlot != null && current
                  ? rows.filter((r) => r.signerSlot !== currentSignerSlot)
                  : rows;
              const totalOthers = othersAll.length;
              const totalPages = Math.max(1, Math.ceil(totalOthers / pageSize));
              const pageSafe = Math.min(page, Math.max(0, totalPages - 1));
              const startIndex = pageSafe * pageSize;
              const endIndex = Math.min(totalOthers, startIndex + pageSize);
              if (totalPages <= 1) return null;

              return (
                <div className="w3a-pagination" onClick={(e) => e.stopPropagation()}>
                  <button
                    type="button"
                    className="w3a-btn w3a-btn-primary"
                    disabled={pageSafe <= 0}
                    onClick={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                      setPage((p) => Math.max(0, p - 1));
                    }}
                  >
                    Prev
                  </button>
                  <div className="w3a-pagination-info">
                    {startIndex + 1}-{endIndex} of {totalOthers} (page {pageSafe + 1}/{totalPages})
                  </div>
                  <button
                    type="button"
                    className="w3a-btn w3a-btn-primary"
                    disabled={pageSafe >= totalPages - 1}
                    onClick={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                      setPage((p) => Math.min(totalPages - 1, p + 1));
                    }}
                  >
                    Next
                  </button>
                </div>
              );
            })()}

        </div>
      </div>
    </Theme>
  );
};
