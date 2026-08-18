// Direct-mount host for the Export Private Key viewer (drawer or modal variant).
//
// This element used to wrap the viewer in a nested srcdoc iframe driven by an
// 11-message postMessage protocol. That inner document was same-origin with
// this one (sandbox="allow-scripts allow-same-origin") and inherited the
// embedder's CSP, so it was never a security boundary — while costing a second
// load of every asset, a protocol for each prop, and the measured-surface
// sizing loop (an iframe cannot be content-sized, so the host had to sample
// it). The viewer and drawer now render directly in this document, matching
// how the tx confirmer already mounts; lit events bubble to export-viewer-host
// with no forwarding.
//
// The tag name keeps its historical "-iframe" suffix: tests and the export
// host address the element by tag, and renaming it is presentation-neutral
// churn best done on its own.
import { html, type PropertyValues } from 'lit';
import { LitElementWithProps } from '../LitElementWithProps';
import { W3A_DRAWER_ID, W3A_EXPORT_KEY_VIEWER_ID } from '../../registry';
// BINDING imports, not side-effect imports: the per-file ESM build honors
// sideEffects and drops a bare `import './viewer'`, which shipped a host whose
// drawer upgraded (the tx-confirmer bundle happens to define it) around a
// never-upgraded, zero-height viewer — an empty sheet. Importing the classes
// and defining them below survives every build shape.
import ExportPrivateKeyViewer from './viewer';
import DrawerElement from '../Drawer';
import { ensureExternalStyles } from '../css/css-loader';

if (!customElements.get(W3A_EXPORT_KEY_VIEWER_ID)) {
  customElements.define(W3A_EXPORT_KEY_VIEWER_ID, ExportPrivateKeyViewer);
}
void DrawerElement; // Drawer/index self-defines on import; the binding keeps the import.
import type {
  ExportGuidance,
  ExportPrivateKeyDisplayEntry,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import type { AppearanceConfig } from '@/core/types/seams';
import type { ExportViewerVariant, ExportViewerTheme } from './viewer';
import {
  createCspStylesheetManager,
  getDefaultCspNonce,
} from '@/core/browser/walletIframe/csp-stylesheet';

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

// Appearance color overrides live on a document-level constructed stylesheet.
// The nested document used to take these to its grave; in the shared document
// they must be removed when the host disconnects.
const EXPORT_TOKEN_RULE_ID = 'w3a-export-token-overrides';
const EXPORT_HOST_SELECTORS = [W3A_DRAWER_ID, W3A_EXPORT_KEY_VIEWER_ID] as const;
const EXPORT_DARK_SELECTOR = EXPORT_HOST_SELECTORS.map(
  (selector) =>
    `${selector}[theme="dark"],\n:root[data-w3a-theme="dark"] ${selector}:not([theme="light"])`,
).join(',\n');
const EXPORT_LIGHT_SELECTOR = EXPORT_HOST_SELECTORS.map(
  (selector) =>
    `${selector}[theme="light"],\n:root[data-w3a-theme="light"] ${selector}:not([theme="dark"])`,
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

function coerceTheme(value: unknown): 'dark' | 'light' | undefined {
  return value === 'dark' || value === 'light' ? value : undefined;
}

function upsertExportAppearanceOverrides(appearance?: AppearanceConfig): void {
  const mode = coerceTheme(appearance?.theme.mode);
  const colors = toStringRecord(appearance?.theme.colors);
  const lines = serializeColorOverrides(colors);
  if (!mode || lines.length === 0) {
    getExportTokenStyleManager().deleteDynamicRule(EXPORT_TOKEN_RULE_ID);
    return;
  }
  const selector = mode === 'light' ? EXPORT_LIGHT_SELECTOR : EXPORT_DARK_SELECTOR;
  getExportTokenStyleManager().setDynamicRule(
    EXPORT_TOKEN_RULE_ID,
    `${selector} {\n${lines.join('\n')}\n}`,
  );
}

export class IframeExportHost extends LitElementWithProps {
  static properties = {
    theme: { type: String },
    variant: { type: String },
    accountId: { type: String, attribute: 'account-id' },
    publicKey: { type: String, attribute: 'public-key' },
    privateKey: { type: String, attribute: 'private-key' },
    keys: { attribute: false },
    guidance: { attribute: false },
    appearance: { attribute: false },
    loading: { type: Boolean },
    errorMessage: { type: String },
    // Reflected by export-viewer-host; re-render when the surface changes so
    // the drawer attribute below tracks it.
    surface: { type: String, attribute: 'data-w3a-export-surface', reflect: false },
  } as const;

  declare theme: 'dark' | 'light';
  declare variant: 'drawer' | 'modal';
  declare accountId: string;
  declare publicKey: string;
  declare privateKey?: string;
  declare keys?: ExportPrivateKeyDisplayEntry[];
  declare guidance?: ExportGuidance;
  declare appearance?: AppearanceConfig;
  declare loading: boolean;
  declare errorMessage?: string;
  declare surface?: string;

  private drawerEl: ExportDrawerElement | null = null;
  private viewerEl: ExportViewerElement | null = null;
  private openFrame: number | null = null;
  // Hold the first child mount until export-iframe.css is adopted: the host is
  // a MEASURED surface, and an unstyled first layout would post a wrong height
  // before the real one.
  private stylesReady = false;
  private stylePromise: Promise<void> | null = null;

  constructor() {
    super();
    this.theme = 'dark';
    this.variant = 'drawer';
    this.accountId = '';
    this.publicKey = '';
    this.privateKey = undefined;
    this.keys = undefined;
    this.guidance = undefined;
    this.appearance = undefined;
    this.loading = false;
  }

  protected createRenderRoot(): HTMLElement | DocumentFragment {
    const root = super.createRenderRoot();
    this.stylePromise = ensureExternalStyles(
      root as ShadowRoot | DocumentFragment | HTMLElement,
      'export-iframe.css',
      'data-w3a-export-iframe-css',
    ).catch(() => {});
    return root;
  }

  protected shouldUpdate(_changed: PropertyValues): boolean {
    if (this.stylesReady) return true;
    void (this.stylePromise ?? Promise.resolve()).then(() => {
      this.stylesReady = true;
      this.requestUpdate();
    });
    return false;
  }

  protected getComponentPrefix(): string {
    return 'export-iframe';
  }

  disconnectedCallback(): void {
    super.disconnectedCallback();
    if (this.openFrame !== null) cancelAnimationFrame(this.openFrame);
    this.openFrame = null;
    getExportTokenStyleManager().deleteDynamicRule(EXPORT_TOKEN_RULE_ID);
    this.drawerEl = null;
    this.viewerEl = null;
  }

  /**
   * The drawer owns its inner shell and adopts host children into its content
   * slot, so build the pair imperatively — the same topology the nested
   * document produced — rather than fighting it with a lit template.
   */
  private ensureDrawerAndViewer(): { drawer: ExportDrawerElement; viewer: ExportViewerElement } {
    let drawer = this.drawerEl;
    if (!drawer || !drawer.isConnected) {
      drawer = document.createElement(W3A_DRAWER_ID) as ExportDrawerElement;
      this.appendChild(drawer);
      this.drawerEl = drawer;
      this.viewerEl = null;
    }
    let viewer = this.viewerEl;
    if (!viewer || !viewer.isConnected) {
      viewer = document.createElement(W3A_EXPORT_KEY_VIEWER_ID) as ExportViewerElement;
      const target =
        drawer.contentRoot ||
        drawer.querySelector('.above-fold') ||
        drawer.querySelector('.body') ||
        drawer;
      target.appendChild(viewer);
      this.viewerEl = viewer;
    }
    return { drawer, viewer };
  }

  protected updated(changed: PropertyValues): void {
    super.updated(changed);
    const { drawer, viewer } = this.ensureDrawerAndViewer();
    const surface =
      this.getAttribute('data-w3a-export-surface') === 'wallet-iframe'
        ? 'wallet-iframe'
        : 'standalone';
    const resolvedTheme = coerceTheme(this.appearance?.theme.mode) ?? coerceTheme(this.theme);

    upsertExportAppearanceOverrides(this.appearance);

    if (resolvedTheme) {
      viewer.theme = resolvedTheme;
      drawer.theme = resolvedTheme;
    }
    viewer.variant = this.variant;
    viewer.accountId = this.accountId;
    viewer.publicKey = this.publicKey || '';
    viewer.keys = Array.isArray(this.keys) ? this.keys : undefined;
    viewer.guidance = this.guidance;
    viewer.loading = !!this.loading;
    if (typeof this.errorMessage === 'string') viewer.errorMessage = this.errorMessage;
    if (this.privateKey) {
      viewer.privateKey = this.privateKey;
      viewer.loading = false;
    }

    drawer.setAttribute('data-w3a-export-surface', surface);
    // Auto-fit to content: the drawer computes its visible height from the
    // content above the fold.
    drawer.height = undefined;
    drawer.showCloseButton = true;
    drawer.dragToClose = true;
    drawer.closeOnOverlayClick = false;
    drawer.overpullPx = 160;
    if (!drawer.open && this.openFrame === null) {
      // Defer open by two frames so slot content renders before the drawer's
      // initial content measurement.
      this.openFrame = requestAnimationFrame(() => {
        this.openFrame = requestAnimationFrame(() => {
          this.openFrame = null;
          if (this.drawerEl?.isConnected) this.drawerEl.open = true;
        });
      });
    }
  }

  render(): unknown {
    // The drawer and viewer are light-DOM children (managed in updated()):
    // they are styled by document-level component CSS, which cannot pierce
    // this shadow root. The shadow tree exists only so export-iframe.css can
    // size the host via :host() — all content flows through the slot.
    return html`<slot></slot>`;
  }
}

// Strongly-typed element shape for 'w3a-export-viewer-iframe'
export type ExportViewerIframeElement = HTMLElement & {
  requestUpdate?: () => void;
  theme?: ExportViewerTheme;
  variant?: ExportViewerVariant;
  accountId?: string;
  publicKey?: string;
  privateKey?: string;
  keys?: ExportPrivateKeyDisplayEntry[];
  guidance?: ExportGuidance;
  appearance?: AppearanceConfig;
  loading?: boolean;
  errorMessage?: string;
};

import { W3A_EXPORT_VIEWER_IFRAME_ID } from '../../registry';
customElements.define(W3A_EXPORT_VIEWER_IFRAME_ID, IframeExportHost);

export default IframeExportHost;
