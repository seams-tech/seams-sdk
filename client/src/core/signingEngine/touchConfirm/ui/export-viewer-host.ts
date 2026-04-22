import type { ThemeTokenOverridesInput } from '@/core/types/tatchi';
import type { ExportGuidance, ExportPrivateKeyDisplayEntry } from '../shared/confirmTypes';
import { addLitCancelListener } from './lit-events';
import { ensureDefined, W3A_EXPORT_VIEWER_IFRAME_ID } from './registry';
import type { ExportViewerIframeElement } from './lit-components/ExportPrivateKey/iframe-host';

export type UpsertExportViewerHostArgs = {
  theme: 'dark' | 'light';
  variant: 'drawer' | 'modal';
  accountId: string;
  sessionId?: string;
  publicKey?: string;
  privateKey?: string;
  keys?: ExportPrivateKeyDisplayEntry[];
  guidance?: ExportGuidance;
  tokens?: ThemeTokenOverridesInput;
  loading?: boolean;
  errorMessage?: string;
};

const EXPORT_VIEWER_SESSION_ATTR = 'data-w3a-export-viewer-session-id';

function postExportViewerMessage(type: 'WALLET_EXPORT_VIEWER_OPENED' | 'WALLET_UI_CLOSED'): void {
  try {
    if (typeof window === 'undefined') return;
    window.parent?.postMessage(
      type === 'WALLET_UI_CLOSED' ? { type, source: 'export_viewer' } : { type },
      '*',
    );
  } catch {}
}

function getMountedExportViewerHost(): ExportViewerIframeElement | null {
  if (typeof document === 'undefined') return null;
  return document.querySelector(W3A_EXPORT_VIEWER_IFRAME_ID) as ExportViewerIframeElement | null;
}

export function isExportViewerSessionOpen(sessionId: string): boolean {
  const expectedSessionId = String(sessionId || '').trim();
  if (!expectedSessionId) return false;
  const host = getMountedExportViewerHost();
  if (!host) return false;
  return String(host.getAttribute(EXPORT_VIEWER_SESSION_ATTR) || '').trim() === expectedSessionId;
}

export async function upsertExportViewerHost(
  args: UpsertExportViewerHostArgs,
): Promise<ExportViewerIframeElement> {
  if (typeof document === 'undefined') {
    throw new Error('Export viewer host requires a DOM environment');
  }
  await ensureDefined(
    W3A_EXPORT_VIEWER_IFRAME_ID,
    () => import('./lit-components/ExportPrivateKey/iframe-host'),
  );

  let host = getMountedExportViewerHost();
  if (!host) {
    host = document.createElement(W3A_EXPORT_VIEWER_IFRAME_ID) as ExportViewerIframeElement;
    window.parent?.postMessage({ type: 'WALLET_UI_OPENED' }, '*');
    postExportViewerMessage('WALLET_EXPORT_VIEWER_OPENED');
    document.body.appendChild(host);
    addLitCancelListener(
      host,
      () => {
        postExportViewerMessage('WALLET_UI_CLOSED');
        host?.remove();
      },
      { once: true },
    );
  } else {
    postExportViewerMessage('WALLET_EXPORT_VIEWER_OPENED');
  }

  const sessionId = String(args.sessionId || '').trim();
  if (sessionId) {
    host.setAttribute(EXPORT_VIEWER_SESSION_ATTR, sessionId);
  } else {
    host.removeAttribute(EXPORT_VIEWER_SESSION_ATTR);
  }
  host.theme = args.theme;
  host.variant = args.variant;
  host.accountId = args.accountId;
  host.publicKey = String(args.publicKey || '').trim();
  host.privateKey = String(args.privateKey || '').trim() || undefined;
  host.keys = Array.isArray(args.keys) ? args.keys : undefined;
  host.guidance = args.guidance;
  host.tokens = args.tokens;
  host.loading = args.loading === true;
  host.errorMessage = String(args.errorMessage || '').trim() || undefined;
  return host;
}

export function removeExportViewerHostIfPresent(): void {
  if (typeof document === 'undefined') return;
  const host = getMountedExportViewerHost();
  if (!host) return;
  host.remove();
  postExportViewerMessage('WALLET_UI_CLOSED');
}
