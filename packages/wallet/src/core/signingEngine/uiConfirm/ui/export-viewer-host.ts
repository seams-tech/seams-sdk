import type { AppearanceConfig } from '@/core/types/seams';
import type {
  ExportGuidance,
  ExportPrivateKeyDisplayEntry,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import { addLitEventListener, LitComponentEvents } from './lit-events';
import { ensureDefined, W3A_EXPORT_VIEWER_IFRAME_ID } from './registry';
import type { ExportViewerIframeElement } from './lit-components/ExportPrivateKey/iframe-host';
import type { UiConfirmSurfaceMeasurementBinding } from '../uiConfirm.types';
import {
  createWalletIframeSurfaceMeasurementReporter,
  type WalletIframeSurfaceMeasurementReporter,
} from '@/SeamsWeb/walletIframe/host/lit-ui/surface-measurement-reporter';

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
  surfaceMeasurementBinding: UiConfirmSurfaceMeasurementBinding;
};

const EXPORT_VIEWER_SESSION_ATTR = 'data-w3a-export-viewer-session-id';
const EXPORT_VIEWER_SURFACE_ATTR = 'data-w3a-export-surface';
const exportViewerLifecycleByHost = new WeakMap<
  ExportViewerIframeElement,
  (event: 'opened' | 'closed') => void
>();
const exportViewerClosedHosts = new WeakSet<ExportViewerIframeElement>();
const exportViewerMeasurementReporters = new WeakMap<
  ExportViewerIframeElement,
  WalletIframeSurfaceMeasurementReporter
>();
const exportViewerMeasurementBindings = new WeakMap<
  ExportViewerIframeElement,
  UiConfirmSurfaceMeasurementBinding
>();

/**
 * `wallet-iframe` means the parent measured this element and sized the host box
 * to hug it; `standalone` means the element owns a full-viewport canvas and
 * positions itself inside it. The HOST BOX shape decides, not what the viewer
 * renders — see applyConfirmSurfaceMode in confirm-ui.ts for why the two are
 * separate values.
 */
function exportViewerSurfacePresentation(
  variant: UpsertExportViewerHostArgs['variant'] | undefined,
  binding: UiConfirmSurfaceMeasurementBinding,
): 'standalone' | 'wallet-iframe' {
  if (binding.kind !== 'wallet_iframe') return 'standalone';
  const hostBoxVariant = binding.hostSurfaceVariant ?? variant;
  return hostBoxVariant === 'modal' ? 'wallet-iframe' : 'standalone';
}

function sameExportViewerMeasurementBinding(
  left: UiConfirmSurfaceMeasurementBinding | undefined,
  right: UiConfirmSurfaceMeasurementBinding,
): boolean {
  if (!left || left.kind !== right.kind) return false;
  switch (left.kind) {
    case 'disabled':
      return right.kind === 'disabled';
    case 'wallet_iframe':
      return (
        right.kind === 'wallet_iframe' &&
        left.requestId === right.requestId &&
        left.postMeasurement === right.postMeasurement &&
        left.hostSurfaceVariant === right.hostSurfaceVariant
      );
  }
}

function disconnectExportViewerMeasurementReporter(
  host: ExportViewerIframeElement | null | undefined,
): void {
  if (!host) return;
  exportViewerMeasurementReporters.get(host)?.disconnect();
  exportViewerMeasurementReporters.delete(host);
  exportViewerMeasurementBindings.delete(host);
}

function bindExportViewerMeasurementReporter(
  host: ExportViewerIframeElement,
  binding: UiConfirmSurfaceMeasurementBinding,
): void {
  host.setAttribute(
    EXPORT_VIEWER_SURFACE_ATTR,
    exportViewerSurfacePresentation(host.variant, binding),
  );
  if (sameExportViewerMeasurementBinding(exportViewerMeasurementBindings.get(host), binding)) {
    return;
  }
  disconnectExportViewerMeasurementReporter(host);
  exportViewerMeasurementBindings.set(host, binding);
  host.requestUpdate?.();
  if (binding.kind !== 'wallet_iframe') return;
  exportViewerMeasurementReporters.set(
    host,
    createWalletIframeSurfaceMeasurementReporter({
      kind: 'request_surface',
      element: host,
      requestId: binding.requestId,
      postMeasurement: binding.postMeasurement,
    }),
  );
}

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
    host.variant = args.variant;
    host.setAttribute(
      EXPORT_VIEWER_SURFACE_ATTR,
      exportViewerSurfacePresentation(args.variant, args.surfaceMeasurementBinding),
    );
    document.body.appendChild(host);
    if (args.onLifecycle) {
      exportViewerLifecycleByHost.set(host, args.onLifecycle);
    }
    emitExportViewerLifecycle(host, 'opened');
    const closeViewer = () => {
      disconnectExportViewerMeasurementReporter(host);
      emitExportViewerLifecycle(host, 'closed');
      host?.remove();
    };
    addLitEventListener(host, LitComponentEvents.CONFIRM, closeViewer, { once: true });
    addLitEventListener(host, LitComponentEvents.CANCEL, closeViewer, { once: true });
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
  bindExportViewerMeasurementReporter(host, args.surfaceMeasurementBinding);
  return host;
}

export function removeExportViewerHostIfPresent(): void {
  if (typeof document === 'undefined') return;
  const host = getMountedExportViewerHost();
  if (!host) return;
  disconnectExportViewerMeasurementReporter(host);
  emitExportViewerLifecycle(host, 'closed');
  host.remove();
}
