import { html, type PropertyValues } from 'lit';
import { LitElementWithProps } from '../LitElementWithProps';
import { dispatchLitCancel, dispatchLitConfirm } from '../../lit-events';

import type { TransactionInputWasm } from '@/core/types';
import { fromTransactionInputsWasm } from '@/core/types/actions';
import type { UserConfirmSecurityContext } from '@/core/types';
import TxTree from '../TxTree';
import { buildDisplayTreeFromModel, buildDisplayTreeFromTxPayloads } from '../TxTree/tx-tree-utils';
import { ensureExternalStyles } from '../css/css-loader';
import { W3A_TX_TREE_ID } from '../../registry';
import type { ThemeName } from '../../confirm-ui-types';
import type {
  TxDisplayModel,
  TxDisplayOperation,
} from '@/core/signingEngine/touchConfirm/shared/displayModel';

/**
 * Shared confirmation content surface used by both Modal and Drawer containers.
 * - Renders summary, TxTree, and confirm/cancel actions
 * - Emits semantic events: `lit-confirm` and `lit-cancel` (containers bridge to w3a:* events)
 * - Does not own backdrop, focus traps, or ESC handling
 */
export class TxConfirmContentElement extends LitElementWithProps {
  // Fail fast in dev if nested custom elements are not defined
  static requiredChildTags = [W3A_TX_TREE_ID, 'tx-tree'];
  static keepDefinitions = [TxTree];
  static properties = {
    nearAccountId: { type: String, attribute: 'near-account-id' },
    txSigningRequests: { attribute: false },
    model: { attribute: false },
    intentDigest: { type: String, attribute: 'intent-digest' },
    securityContext: { type: Object },
    theme: { type: String },
    loading: { type: Boolean },
    errorMessage: { type: String },
    title: { type: String },
    confirmText: { type: String },
    cancelText: { type: String },
    // Treat internal tree node as reactive state so setting it re-renders immediately
    _treeNode: { attribute: false, state: true },
    // Optional: set tooltip width via CSS var for nested components
    tooltipWidth: { type: String, attribute: 'tooltip-width' },
    // Optional: pass explorer base URL down to TxTree
    nearExplorerUrl: { type: String, attribute: 'near-explorer-url' },
    tempoExplorerUrl: { type: String, attribute: 'tempo-explorer-url' },
    evmExplorerUrl: { type: String, attribute: 'evm-explorer-url' },
    // Forwarded flag to control TxTree's shadow wrapper (drop shadow)
    showShadow: { type: Boolean, attribute: 'show-shadow' },
  } as const;

  declare nearAccountId: string;
  declare txSigningRequests: TransactionInputWasm[];
  declare model?: TxDisplayModel;
  declare intentDigest?: string;
  declare securityContext?: Partial<UserConfirmSecurityContext>;
  declare theme: ThemeName;
  declare loading: boolean;
  declare errorMessage?: string;
  declare title: string;
  declare confirmText: string;
  declare cancelText: string;
  declare tooltipWidth?: string | number;
  declare nearExplorerUrl?: string;
  declare tempoExplorerUrl?: string;
  declare evmExplorerUrl?: string;
  declare showShadow: boolean;

  private _treeNode: unknown | null = null;
  // Keep essential custom elements from being tree-shaken
  private _ensureTreeDefinition = TxTree;

  // No static styles: structural styles are provided by tx-confirmer.css

  // Styles gating to avoid first-paint before tx-tree.css is ready
  private _stylesReady = false;
  private _stylePromises: Promise<void>[] = [];
  private _stylesAwaiting: Promise<void> | null = null;
  private static readonly _STYLE_MARKERS = [
    'data-w3a-tx-tree-css',
    'data-w3a-tx-confirmer-css',
    'data-w3a-components-css',
  ] as const;
  private _treeBuildVersion = 0;
  // Guard against "ghost" confirm clicks caused by the same user gesture that
  // mounted the confirmer. We arm confirm after initial paint frames.
  private _confirmArmed = false;
  private _confirmArmRaf1: number | null = null;
  private _confirmArmRaf2: number | null = null;

  constructor() {
    super();
    // Pre-ensure document-level styles to warm the cache and await link loads
    const root = (document?.documentElement || null) as unknown as HTMLElement | null;
    if (root) {
      this._stylePromises.push(
        ensureExternalStyles(root, 'tx-tree.css', 'data-w3a-tx-tree-css'),
        ensureExternalStyles(root, 'tx-confirmer.css', 'data-w3a-tx-confirmer-css'),
        ensureExternalStyles(root, 'w3a-components.css', 'data-w3a-components-css'),
      );
    }
    this.nearAccountId = '';
    this.txSigningRequests = [];
    this.model = undefined;
    this.theme = 'dark';
    this.loading = false;
    this.title = 'Review Transaction';
    this.confirmText = 'Confirm';
    this.cancelText = 'Cancel';
    this.showShadow = false;
    // Leave tooltipWidth undefined by default so CSS responsive var applies.
  }

  protected getComponentPrefix(): string {
    return 'tx-confirm-content';
  }

  protected createRenderRoot(): HTMLElement | DocumentFragment {
    const root = this as unknown as HTMLElement;
    // Ensure tx-tree.css for nested light-DOM TxTree
    this._stylePromises.push(ensureExternalStyles(root, 'tx-tree.css', 'data-w3a-tx-tree-css'));
    // Also ensure tx-confirmer.css for shared confirmer styles
    this._stylePromises.push(
      ensureExternalStyles(root, 'tx-confirmer.css', 'data-w3a-tx-confirmer-css'),
    );
    return root;
  }

  connectedCallback(): void {
    super.connectedCallback();
    // Reflect tooltip width var for nested components
    this._applyTooltipWidthVar();
    this._scheduleConfirmArm();
    // Prevent drawer drag initiation from content area
    this.addEventListener('pointerdown', this._stopDragStart as EventListener);
    this.addEventListener('mousedown', this._stopDragStart as EventListener);
    this.addEventListener(
      'touchstart',
      this._stopDragStart as EventListener,
      { passive: false } as AddEventListenerOptions,
    );
  }

  disconnectedCallback(): void {
    this._cancelConfirmArm();
    this.removeEventListener('pointerdown', this._stopDragStart as EventListener);
    this.removeEventListener('mousedown', this._stopDragStart as EventListener);
    this.removeEventListener('touchstart', this._stopDragStart as EventListener);
    // No resize listener to clean up (width is CSS-driven)
    super.disconnectedCallback();
  }

  protected shouldUpdate(_changed: PropertyValues): boolean {
    if (this._stylesReady) return true;
    if (this._hasPreloadedDocumentStyles()) {
      this._stylesReady = true;
      return true;
    }
    if (!this._stylesAwaiting) {
      const p = Promise.all(this._stylePromises).then(
        () =>
          new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r()))),
      );
      this._stylesAwaiting = p.then(() => {
        this._stylesReady = true;
        // While style gating is active, Lit can drop changed-property bookkeeping.
        // Rebuild from the latest props once styles are ready so first render has TxTree.
        this._rebuildTree();
      });
    }
    return false;
  }

  private _hasPreloadedDocumentStyles(): boolean {
    const doc = this.ownerDocument ?? (typeof document !== 'undefined' ? document : null);
    if (!doc?.head) return false;
    for (const marker of TxConfirmContentElement._STYLE_MARKERS) {
      const link = doc.head.querySelector(`link[${marker}]`) as HTMLLinkElement | null;
      if (!link) return false;
      const statefulLink = link as HTMLLinkElement & { _w3aLoaded?: boolean };
      if (!(statefulLink._w3aLoaded || link.sheet)) return false;
    }
    return true;
  }

  protected willUpdate(changed: PropertyValues): void {
    super.willUpdate(changed);
    if (changed.has('txSigningRequests') || changed.has('model')) {
      // Build the tree before render so the first painted frame already has
      // the tx body and does not grow a frame later.
      this._rebuildTree({ requestRender: false });
    }
  }

  updated(changed: PropertyValues) {
    super.updated(changed);
    if (changed.has('tooltipWidth')) {
      this._applyTooltipWidthVar();
    }
  }

  private _applyTooltipWidthVar() {
    const w = this._normalizeWidth(this.tooltipWidth);
    // Only set when a caller explicitly provides a width; otherwise
    // keep the responsive CSS default defined on :host.
    if (w) this.setCssVars({ '--tooltip-width': w });
  }

  private _normalizeWidth(val?: string | number): string | undefined {
    if (val === undefined || val === null) return undefined;
    if (typeof val === 'number' && Number.isFinite(val)) return `${val}px`;
    const s = String(val).trim();
    return s.length ? s : undefined;
  }

  private _operationHasAbiDecodeHint(operation: TxDisplayOperation): boolean {
    const hint = operation.abiDecodeHint;
    if (hint && Array.isArray(hint.abi) && hint.abi.length > 0) {
      const dataHex = String(hint.dataHex || '').trim();
      if (dataHex && dataHex !== '0x') return true;
    }
    const children = Array.isArray(operation.children) ? operation.children : [];
    for (const child of children) {
      if (this._operationHasAbiDecodeHint(child)) return true;
    }
    return false;
  }

  private _modelHasAbiDecodeHints(model: TxDisplayModel): boolean {
    const operations = Array.isArray(model.operations) ? model.operations : [];
    for (const operation of operations) {
      if (this._operationHasAbiDecodeHint(operation)) return true;
    }
    return false;
  }

  private async _enrichTreeWithAbi(args: { model: TxDisplayModel; buildVersion: number }) {
    try {
      const module = await import('../TxTree/abi/enrichDisplayModelWithAbi');
      if (args.buildVersion !== this._treeBuildVersion) return;
      const enrichedModel = module.enrichDisplayModelWithAbi(args.model);
      if (args.buildVersion !== this._treeBuildVersion) return;
      this._treeNode = buildDisplayTreeFromModel(enrichedModel);
      this.requestUpdate();
    } catch (error) {
      console.warn('[TxConfirmContent] failed to lazy-load ABI display enrichment', error);
    }
  }

  private _rebuildTree(options?: { requestRender?: boolean }) {
    const shouldRequestRender = options?.requestRender ?? true;
    const maybeRequestUpdate = () => {
      if (shouldRequestRender) this.requestUpdate();
    };
    const buildVersion = ++this._treeBuildVersion;
    try {
      const txs = Array.isArray(this.txSigningRequests) ? this.txSigningRequests : [];
      if (txs.length > 0) {
        const uiTxs = fromTransactionInputsWasm(txs);
        this._treeNode = buildDisplayTreeFromTxPayloads(uiTxs);
        maybeRequestUpdate();
        return;
      }
      if (this.model) {
        const operations = Array.isArray(this.model.operations) ? this.model.operations : [];
        const warnings = Array.isArray(this.model.warnings) ? this.model.warnings : [];
        if (operations.length === 0 && warnings.length === 0) {
          this._treeNode = null;
          maybeRequestUpdate();
          return;
        }
        this._treeNode = buildDisplayTreeFromModel(this.model);
        maybeRequestUpdate();
        if (this._modelHasAbiDecodeHints(this.model)) {
          void this._enrichTreeWithAbi({
            model: this.model,
            buildVersion,
          });
        }
        return;
      }
      this._treeNode = null;
    } catch (e) {
      console.warn('[TxConfirmContent] failed to build TxTree', e);
      this._treeNode = null;
    }
    // Ensure view refreshes even if this runs in firstUpdated before Lit schedules next frame
    maybeRequestUpdate();
  }

  private _stopDragStart = (e: Event) => {
    e.stopPropagation();
  };

  private onConfirm = () => {
    if (this.loading || !this._confirmArmed) return;
    // Emit semantic event for containers to bridge to canonical events
    dispatchLitConfirm(this);
  };

  private onCancel = () => {
    dispatchLitCancel(this);
  };

  render() {
    const treeTheme: 'dark' | 'light' = this.theme === 'dark' ? 'dark' : 'light';
    const nearExplorerBase = this.nearExplorerUrl || 'https://testnet.nearblocks.io';
    return html`
      <div class="txc-root">
        ${this.errorMessage ? html`<div class="error">${this.errorMessage}</div>` : null}
        ${this._treeNode
          ? html`<div class="tooltip-width">
              <w3a-tx-tree
                light-dom
                .node=${this._treeNode}
                .theme=${treeTheme}
                .nearExplorerUrl=${nearExplorerBase}
                .tempoExplorerUrl=${this.tempoExplorerUrl}
                .evmExplorerUrl=${this.evmExplorerUrl}
                .showShadow=${this.showShadow}
              ></w3a-tx-tree>
            </div>`
          : null}
        <div class="actions">
          <button class="cancel" @click=${this.onCancel}>
            ${this.cancelText}
          </button>
          <button
            class="confirm ${this.loading ? 'loading' : ''}"
            @click=${this.onConfirm}
            ?disabled=${this.loading || !this._confirmArmed}
          >
            ${this.loading
              ? html`<span class="loading-indicator" role="progressbar" aria-label="Loading"></span
                  ><span class="sr-only">Loading</span>`
              : html`${this.confirmText}`}
          </button>
        </div>
      </div>
    `;
  }

  private _scheduleConfirmArm(): void {
    this._cancelConfirmArm();
    this._confirmArmed = false;
    this._confirmArmRaf1 = requestAnimationFrame(() => {
      this._confirmArmRaf1 = null;
      this._confirmArmRaf2 = requestAnimationFrame(() => {
        this._confirmArmRaf2 = null;
        this._confirmArmed = true;
        this.requestUpdate();
      });
    });
  }

  private _cancelConfirmArm(): void {
    if (this._confirmArmRaf1 != null) {
      cancelAnimationFrame(this._confirmArmRaf1);
      this._confirmArmRaf1 = null;
    }
    if (this._confirmArmRaf2 != null) {
      cancelAnimationFrame(this._confirmArmRaf2);
      this._confirmArmRaf2 = null;
    }
  }
}

import { W3A_TX_CONFIRM_CONTENT_ID } from '../../registry';

if (!customElements.get(W3A_TX_CONFIRM_CONTENT_ID)) {
  customElements.define(W3A_TX_CONFIRM_CONTENT_ID, TxConfirmContentElement);
}

export default TxConfirmContentElement;
