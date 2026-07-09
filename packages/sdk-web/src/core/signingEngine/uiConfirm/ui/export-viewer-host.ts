import type { AppearanceConfig } from '@/core/types/seams';
import type { ExportGuidance, ExportPrivateKeyDisplayEntry } from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import { addLitEventListener, LitComponentEvents } from './lit-events';
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
  appearance?: AppearanceConfig;
  loading?: boolean;
  errorMessage?: string;
  onLifecycle?: (event: 'opened' | 'closed') => void;
};

const EXPORT_VIEWER_SESSION_ATTR = 'data-w3a-export-viewer-session-id';
const exportViewerLifecycleByHost = new WeakMap<
  ExportViewerIframeElement,
  (event: 'opened' | 'closed') => void
>();
const exportViewerClosedHosts = new WeakSet<ExportViewerIframeElement>();

function emitExportViewerLifecycle(
  host: ExportViewerIframeElement | null | undefined,
  event: 'opened' | 'closed',
): void {
  if (!host) return;
  if (event === 'opened') {
    exportViewerClosedHosts.delete(host);
  } else if (exportViewerClosedHosts.has(host)) {
    return;
  }
  if (event === 'closed') {
    exportViewerClosedHosts.add(host);
  }
  const listener = exportViewerLifecycleByHost.get(host);
  try {
    listener?.(event);
  } catch {}
  if (event === 'closed') {
    exportViewerLifecycleByHost.delete(host);
  }
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
    document.body.appendChild(host);
    if (args.onLifecycle) {
      exportViewerLifecycleByHost.set(host, args.onLifecycle);
    }
    emitExportViewerLifecycle(host, 'opened');
    const closeViewer = () => {
      emitExportViewerLifecycle(host, 'closed');
      host?.remove();
    };
    addLitEventListener(
      host,
      LitComponentEvents.CONFIRM,
      closeViewer,
      { once: true },
    );
    addLitEventListener(
      host,
      LitComponentEvents.CANCEL,
      closeViewer,
      { once: true },
    );
  } else {
    if (args.onLifecycle) {
      exportViewerLifecycleByHost.set(host, args.onLifecycle);
    }
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
  host.appearance = args.appearance;
  host.loading = args.loading === true;
  host.errorMessage = String(args.errorMessage || '').trim() || undefined;
  return host;
}

export function removeExportViewerHostIfPresent(): void {
  if (typeof document === 'undefined') return;
  const host = getMountedExportViewerHost();
  if (!host) return;
  emitExportViewerLifecycle(host, 'closed');
  host.remove();
}
