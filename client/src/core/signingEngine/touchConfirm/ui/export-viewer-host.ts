import type { ThemeTokenOverridesInput } from '@/core/types/tatchi';
import type {
  ExportGuidance,
  ExportPrivateKeyDisplayEntry,
} from '../shared/confirmTypes';
import { addLitCancelListener } from './lit-events';
import { ensureDefined, W3A_EXPORT_VIEWER_IFRAME_ID } from './registry';
import type { ExportViewerIframeElement } from './lit-components/ExportPrivateKey/iframe-host';

export type UpsertExportViewerHostArgs = {
  theme: 'dark' | 'light';
  variant: 'drawer' | 'modal';
  accountId: string;
  publicKey?: string;
  privateKey?: string;
  keys?: ExportPrivateKeyDisplayEntry[];
  guidance?: ExportGuidance;
  tokens?: ThemeTokenOverridesInput;
  loading?: boolean;
  errorMessage?: string;
};

function getMountedExportViewerHost(): ExportViewerIframeElement | null {
  return document.querySelector(W3A_EXPORT_VIEWER_IFRAME_ID) as ExportViewerIframeElement | null;
}

export async function upsertExportViewerHost(
  args: UpsertExportViewerHostArgs,
): Promise<ExportViewerIframeElement> {
  await ensureDefined(
    W3A_EXPORT_VIEWER_IFRAME_ID,
    () => import('./lit-components/ExportPrivateKey/iframe-host'),
  );

  let host = getMountedExportViewerHost();
  if (!host) {
    host = document.createElement(W3A_EXPORT_VIEWER_IFRAME_ID) as ExportViewerIframeElement;
    window.parent?.postMessage({ type: 'WALLET_UI_OPENED' }, '*');
    document.body.appendChild(host);
    addLitCancelListener(
      host,
      () => {
        window.parent?.postMessage({ type: 'WALLET_UI_CLOSED' }, '*');
        host?.remove();
      },
      { once: true },
    );
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
  const host = getMountedExportViewerHost();
  if (!host) return;
  host.remove();
  window.parent?.postMessage({ type: 'WALLET_UI_CLOSED' }, '*');
}
