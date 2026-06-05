import { isObject, isString, isBoolean } from '@shared/utils/validation';
import { LitComponentEvents, type LitComponentEventDetailMap } from '../../lit-events';
import { W3A_DRAWER_ID, W3A_EXPORT_KEY_VIEWER_ID } from '../../registry';
import type {
  ExportGuidance,
  ExportPrivateKeyDisplayEntry,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import type { ThemeTokenOverridesInput } from '@/core/types/seams';
import {
  createCspStylesheetManager,
  getDefaultCspNonce,
} from '@/core/browser/walletIframe/csp-stylesheet';

type MessageType =
  | 'READY'
  | 'ETX_DEFINED'
  | 'SET_INIT'
  | 'SET_EXPORT_DATA'
  | 'SET_LOADING'
  | 'SET_ERROR'
  | 'SET_PRIVATE_KEY'
  | 'CONFIRM'
  | 'CANCEL'
  | 'COPY';

type MessagePayloads = {
  READY: undefined;
  ETX_DEFINED: undefined;
  SET_INIT: { targetOrigin: string };
  SET_EXPORT_DATA: {
    theme?: 'dark' | 'light';
    variant?: 'drawer' | 'modal';
    accountId: string;
    publicKey?: string;
    keys?: ExportPrivateKeyDisplayEntry[];
    guidance?: ExportGuidance;
    tokens?: ThemeTokenOverridesInput;
  };
  SET_LOADING: boolean;
  SET_ERROR: string;
  SET_PRIVATE_KEY: { privateKey: string };
  CONFIRM: undefined;
  CANCEL: undefined;
  COPY: { type: 'publicKey' | 'privateKey'; value: string };
};

type ExportDrawerElement = HTMLElement & {
  theme?: string;
  open?: boolean;
  height?: string;
  showCloseButton?: boolean;
  overpullPx?: number;
  dragToClose?: boolean;
  closeOnOverlayClick?: boolean;
  contentRoot?: Element | null;
};

type ExportViewerElement = HTMLElement & {
  theme?: string;
  variant?: string;
  accountId?: string;
  publicKey?: string;
  privateKey?: string;
  keys?: ExportPrivateKeyDisplayEntry[];
  guidance?: ExportGuidance;
  loading?: boolean;
  errorMessage?: string;
};

let PARENT_ORIGIN: string | undefined;
const EXPORT_TOKEN_RULE_ID = 'w3a-export-token-overrides';
const EXPORT_HOST_SELECTORS = ['w3a-drawer', 'w3a-export-key-viewer'] as const;
const EXPORT_DARK_SELECTOR = EXPORT_HOST_SELECTORS.join(',\n');
const EXPORT_LIGHT_SELECTOR = EXPORT_HOST_SELECTORS.map(
  (selector) => `:root[data-w3a-theme="light"] ${selector}`,
).join(',\n');
let exportTokenStyleManager: ReturnType<typeof createCspStylesheetManager> | null = null;

function getExportTokenStyleManager(): ReturnType<typeof createCspStylesheetManager> {
  if (!exportTokenStyleManager) {
    exportTokenStyleManager = createCspStylesheetManager({
      doc: document,
      baseCss: '',
      dynamicStyleDataAttr: 'data-w3a-export-token-overrides',
      nonce: () => getDefaultCspNonce(),
    });
  }
  return exportTokenStyleManager;
}

function toStringRecord(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object') return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (typeof v === 'string') out[k] = v;
  }
  return out;
}

function sanitizeTokenName(name: string): string | null {
  const trimmed = name.trim();
  if (!trimmed) return null;
  return /^[A-Za-z][A-Za-z0-9_-]*$/.test(trimmed) ? trimmed : null;
}

function sanitizeTokenValue(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (trimmed.length > 1024) return null;
  if (/[{};\n\r]/.test(trimmed)) return null;
  return trimmed;
}

function serializeColorOverrides(colors: Record<string, string>): string[] {
  const lines: string[] = [];
  for (const [rawName, rawValue] of Object.entries(colors)) {
    const tokenName = sanitizeTokenName(rawName);
    if (!tokenName) continue;
    const tokenValue = sanitizeTokenValue(rawValue);
    if (!tokenValue) continue;
    lines.push(`  --w3a-colors-${tokenName}: ${tokenValue} !important;`);
  }
  return lines;
}

function upsertExportTokenOverrides(tokens?: ThemeTokenOverridesInput): void {
  const lightColors = toStringRecord(tokens?.light?.colors);
  const darkColors = toStringRecord(tokens?.dark?.colors);
  const darkLines = serializeColorOverrides(darkColors);
  const lightLines = serializeColorOverrides(lightColors);
  const cssBlocks: string[] = [];

  if (darkLines.length > 0) {
    cssBlocks.push(`${EXPORT_DARK_SELECTOR} {\n${darkLines.join('\n')}\n}`);
  }
  if (lightLines.length > 0) {
    cssBlocks.push(`${EXPORT_LIGHT_SELECTOR} {\n${lightLines.join('\n')}\n}`);
  }

  const cssText = cssBlocks.join('\n\n').trim();
  if (!cssText) {
    getExportTokenStyleManager().deleteDynamicRule(EXPORT_TOKEN_RULE_ID);
    return;
  }
  getExportTokenStyleManager().setDynamicRule(EXPORT_TOKEN_RULE_ID, cssText);
}

function whenDefined(tag: string): Promise<void> {
  if (window.customElements?.whenDefined) {
    return window.customElements.whenDefined(tag).then(() => void 0);
  }
  return Promise.resolve();
}

function postToParent<T extends MessageType>(type: T, payload?: MessagePayloads[T]) {
  window.parent.postMessage({ type, payload }, PARENT_ORIGIN || '*');
}

function isSetExportDataPayload(payload: unknown): payload is MessagePayloads['SET_EXPORT_DATA'] {
  if (!isObject(payload)) return false;
  const p = payload as { accountId?: unknown };
  return isString(p.accountId);
}

function isCopyPayload(payload: unknown): payload is MessagePayloads['COPY'] {
  if (!isObject(payload)) return false;
  const p = payload as { type?: unknown; value?: unknown };
  return (p.type === 'publicKey' || p.type === 'privateKey') && isString(p.value);
}

// Ensure a drawer element exists in body; use id 'exp'
function getDrawer(): ExportDrawerElement {
  let el = document.getElementById('exp') as ExportDrawerElement | null;
  if (!el) {
    el = document.createElement(W3A_DRAWER_ID) as ExportDrawerElement;
    el.id = 'exp';
    document.body.appendChild(el);
  }
  return el;
}

// Ensure viewer element is a child of drawer
function getViewer(): ExportViewerElement {
  const drawer = getDrawer();
  let viewer = drawer.querySelector(W3A_EXPORT_KEY_VIEWER_ID) as ExportViewerElement | null;
  if (!viewer) {
    viewer = document.createElement(W3A_EXPORT_KEY_VIEWER_ID) as ExportViewerElement;
    // Prefer appending directly into the drawer's declared content root when present
    const target =
      drawer.contentRoot ||
      drawer.querySelector('.above-fold') ||
      drawer.querySelector('.body') ||
      drawer;
    target.appendChild(viewer);
  }
  return viewer;
}

function onMessage(e: MessageEvent<{ type?: unknown; payload?: unknown }>) {
  const data = e?.data;
  if (!data || !isObject(data) || !('type' in data)) return;
  const type = (data as { type?: unknown }).type;
  if (!isString(type)) return;
  const payload = (data as { payload?: unknown }).payload;

  switch (type) {
    case 'SET_INIT': {
      if (isObject(payload)) {
        const p = payload as { targetOrigin?: string };
        if (p.targetOrigin && isString(p.targetOrigin)) {
          PARENT_ORIGIN = p.targetOrigin;
        }
      }
      whenDefined(W3A_EXPORT_KEY_VIEWER_ID).then(() => postToParent('ETX_DEFINED'));
      break;
    }
    case 'SET_EXPORT_DATA': {
      if (!isSetExportDataPayload(payload)) break;
      upsertExportTokenOverrides(payload.tokens);
      const viewer = getViewer();
      if (payload.theme && isString(payload.theme)) {
        // Reflect theme to viewer and document root so host-scoped tokens update
        viewer.theme = payload.theme;
        try {
          document.documentElement.setAttribute('data-w3a-theme', payload.theme);
        } catch {}
      }
      if (payload.variant && isString(payload.variant)) viewer.variant = payload.variant;
      viewer.accountId = payload.accountId;
      viewer.publicKey = payload.publicKey || '';
      viewer.keys = Array.isArray(payload.keys) ? payload.keys : undefined;
      viewer.guidance = payload.guidance;

      const drawer = getDrawer();
      if (payload.theme && isString(payload.theme)) drawer.theme = payload.theme;
      // Auto-fit to content: let Drawer compute visible height from content above the fold.
      drawer.height = undefined;
      drawer.showCloseButton = true;
      drawer.dragToClose = false;
      drawer.closeOnOverlayClick = false;
      drawer.overpullPx = 160;
      // Defer open by two frames so slot content renders before initial measurement
      requestAnimationFrame(() =>
        requestAnimationFrame(() => {
          drawer.open = true;
        }),
      );
      break;
    }
    case 'SET_LOADING': {
      if (!isBoolean(payload)) break;
      const viewer = getViewer();
      viewer.loading = !!payload;
      break;
    }
    case 'SET_ERROR': {
      const viewer = getViewer();
      if (isString(payload)) viewer.errorMessage = payload;
      break;
    }
    case 'SET_PRIVATE_KEY': {
      if (!isObject(payload)) break;
      const p = payload as { privateKey?: string };
      const viewer = getViewer();
      if (p.privateKey && isString(p.privateKey)) viewer.privateKey = p.privateKey;
      viewer.loading = false;
      break;
    }
  }
}

// Forward decision/copy events to parent
document.addEventListener(LitComponentEvents.CONFIRM, () => postToParent('CONFIRM'));
let cancelPosted = false;
document.addEventListener(LitComponentEvents.CANCEL, () => {
  if (cancelPosted) return;
  cancelPosted = true;
  postToParent('CANCEL');
});
document.addEventListener(LitComponentEvents.COPY, (e: Event) => {
  const detail = (e as CustomEvent<LitComponentEventDetailMap[typeof LitComponentEvents.COPY]>)
    .detail;
  if (isCopyPayload(detail)) postToParent('COPY', detail);
});

window.addEventListener('message', onMessage);
// signal ready to parent immediately
postToParent('READY');
