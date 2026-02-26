import { html, type PropertyValues } from 'lit';
import { createRef, Ref, ref } from 'lit/directives/ref.js';
import { LitElementWithProps } from '../LitElementWithProps';
import type { ConfirmUIElement, ThemeName } from '../../confirm-ui-types';
import { WalletIframeDomEvents } from '@/core/WalletIframe/events';
import type { UserConfirmSecurityContext } from '@/core/types';
import { W3A_TX_CONFIRMER_ID } from '../../registry';
import { DrawerTxConfirmerElement } from './viewer-drawer';
import { ModalTxConfirmElement } from './viewer-modal';
import type { TxDisplayModel } from '@/core/signingEngine/touchConfirm/shared/displayModel';
import type { TransactionInputWasm } from '@/core/types';

const DEFAULT_VARIANT: Variant = 'modal';

export type Variant = 'modal' | 'drawer';

export type TxConfirmerVariantElement = (ConfirmUIElement & HTMLElement) & {
  nearAccountId?: string;
  txSigningRequests?: TransactionInputWasm[];
  model?: TxDisplayModel;
  securityContext?: Partial<UserConfirmSecurityContext>;
  theme?: ThemeName;
  loading?: boolean;
  errorMessage?: string;
  body?: string;
  title?: string;
  confirmText?: string;
  cancelText?: string;
  deferClose?: boolean;
  nearExplorerUrl?: string;
  tempoExplorerUrl?: string;
  evmExplorerUrl?: string;
  requestUpdate?: () => void;
  close?: (confirmed: boolean) => void;
};

/**
 * Thin wrapper that renders the modal or drawer confirmer inline instead of
 * inside a nested iframe. It forwards props to the active variant element,
 * performs intent digest validation, and re-emits canonical events.
 */
export class TxConfirmerWrapperElement extends LitElementWithProps {
  static properties = {
    variant: { type: String, reflect: true },
    nearAccountId: { type: String, attribute: 'near-account-id' },
    txSigningRequests: { attribute: false },
    model: { attribute: false },
    securityContext: { type: Object },
    theme: { type: String },
    loading: { type: Boolean },
    errorMessage: { type: String, attribute: 'error-message' },
    intentDigest: { type: String, attribute: 'intent-digest' },
    body: { type: String },
    title: { type: String },
    confirmText: { type: String, attribute: 'confirm-text' },
    cancelText: { type: String, attribute: 'cancel-text' },
    deferClose: { type: Boolean, attribute: 'defer-close' },
    nearExplorerUrl: { type: String, attribute: 'near-explorer-url' },
    tempoExplorerUrl: { type: String, attribute: 'tempo-explorer-url' },
    evmExplorerUrl: { type: String, attribute: 'evm-explorer-url' },
  } as const;

  static keepDefinitions = [ModalTxConfirmElement, DrawerTxConfirmerElement];

  declare variant: Variant;
  declare nearAccountId: string;
  declare txSigningRequests?: TransactionInputWasm[];
  declare model?: TxDisplayModel;
  declare securityContext?: Partial<UserConfirmSecurityContext>;
  declare theme: ThemeName;
  declare loading: boolean;
  declare errorMessage?: string;
  declare intentDigest?: string;
  declare body: string;
  declare title: string;
  declare confirmText: string;
  declare cancelText: string;
  declare deferClose: boolean;
  declare nearExplorerUrl?: string;
  declare tempoExplorerUrl?: string;
  declare evmExplorerUrl?: string;

  private readonly childRef: Ref<TxConfirmerVariantElement> = createRef();
  private redispatchingEvent = false;
  private currentChild: TxConfirmerVariantElement | null = null;
  private boundConfirmListener = (event: Event) => { this.handleChildConfirm(event); };
  private boundCancelListener = (_event: Event) => { this.handleChildCancel(); };

  constructor() {
    super();
    this.variant = DEFAULT_VARIANT;
    this.nearAccountId = '';
    this.txSigningRequests = undefined;
    this.model = undefined;
    this.theme = 'dark';
    this.loading = false;
    this.deferClose = true;
    this.body = '';
    this.title = '';
    this.confirmText = 'Confirm';
    this.cancelText = 'Cancel';
  }

  protected createRenderRoot(): HTMLElement | DocumentFragment {
    // Render into light DOM so the variant element controls stacking/context.
    return this;
  }

  protected updated(changed: PropertyValues<this>): void {
    super.updated(changed);
    this.syncChildProps();
    if (changed.has('errorMessage')) {
      this.syncErrorAttribute();
    }
  }

  render() {
    const variant = this.variant === 'drawer' ? 'drawer' : 'modal';

    if (variant === 'drawer') {
      return html`
        <w3a-drawer-tx-confirmer
          ${ref(this.childRef)}
          .nearAccountId=${this.nearAccountId}
          .txSigningRequests=${this.txSigningRequests}
          .model=${this.model}
          .securityContext=${this.securityContext}
          .theme=${this.theme}
          .nearExplorerUrl=${this.nearExplorerUrl}
          .tempoExplorerUrl=${this.tempoExplorerUrl}
          .evmExplorerUrl=${this.evmExplorerUrl}
          .loading=${this.loading}
          .errorMessage=${this.errorMessage || ''}
          .body=${this.body}
          .title=${this.title}
          .confirmText=${this.confirmText}
          .cancelText=${this.cancelText}
          .deferClose=${this.deferClose}
        ></w3a-drawer-tx-confirmer>
      `;
    }

    return html`
      <w3a-modal-tx-confirmer
        ${ref(this.childRef)}
        .nearAccountId=${this.nearAccountId}
        .txSigningRequests=${this.txSigningRequests}
        .model=${this.model}
        .securityContext=${this.securityContext}
        .theme=${this.theme}
        .nearExplorerUrl=${this.nearExplorerUrl}
        .tempoExplorerUrl=${this.tempoExplorerUrl}
        .evmExplorerUrl=${this.evmExplorerUrl}
        .loading=${this.loading}
        .errorMessage=${this.errorMessage || ''}
        .body=${this.body}
        .title=${this.title}
        .confirmText=${this.confirmText}
        .cancelText=${this.cancelText}
        .deferClose=${this.deferClose}
      ></w3a-modal-tx-confirmer>
    `;
  }

  private syncChildProps(): void {
    const child = this.childRef.value;
    if (!child) return;
    child.nearAccountId = this.nearAccountId;
    child.txSigningRequests = this.txSigningRequests;
    child.model = this.model;
    child.securityContext = this.securityContext;
    child.theme = this.theme;
    child.loading = this.loading;
    child.errorMessage = this.errorMessage;
    child.body = this.body;
    child.title = this.title;
    child.confirmText = this.confirmText;
    child.cancelText = this.cancelText;
    child.deferClose = this.deferClose;
    child.nearExplorerUrl = this.nearExplorerUrl;
    child.tempoExplorerUrl = this.tempoExplorerUrl;
    child.evmExplorerUrl = this.evmExplorerUrl;
    child.requestUpdate?.();
    this.attachChildListeners();
  }

  private syncErrorAttribute(): void {
    if (this.errorMessage) {
      this.setAttribute('data-error-message', this.errorMessage);
    } else {
      this.removeAttribute('data-error-message');
    }
  }

  private attachChildListeners(): void {
    const child = this.childRef.value;
    if (!child || child === this.currentChild) return;
    if (this.currentChild) {
      this.detachChildListeners();
    }
    child.addEventListener(WalletIframeDomEvents.TX_CONFIRMER_CONFIRM, this.boundConfirmListener as EventListener);
    child.addEventListener(WalletIframeDomEvents.TX_CONFIRMER_CANCEL, this.boundCancelListener as EventListener);
    this.currentChild = child;
  }

  private detachChildListeners(): void {
    if (!this.currentChild) return;
    this.currentChild.removeEventListener(WalletIframeDomEvents.TX_CONFIRMER_CONFIRM, this.boundConfirmListener as EventListener);
    this.currentChild.removeEventListener(WalletIframeDomEvents.TX_CONFIRMER_CANCEL, this.boundCancelListener as EventListener);
    this.currentChild = null;
  }

  disconnectedCallback(): void {
    super.disconnectedCallback();
    this.detachChildListeners();
    // Remove capture-phase fallback listener
    this.removeEventListener(WalletIframeDomEvents.TX_CONFIRMER_CONFIRM, this.boundConfirmListener as EventListener, true);
  }

  connectedCallback(): void {
    super.connectedCallback();
    // Capture-phase fallback: ensure we catch early CONFIRM events even if child listeners
    // are not yet attached due to rendering/refs timing.
    this.addEventListener(
      WalletIframeDomEvents.TX_CONFIRMER_CONFIRM,
      this.boundConfirmListener as EventListener,
      true
    );
  }

  private handleChildCancel(): void {
    if (this.loading) {
      this.loading = false;
      this.syncChildProps();
    }
  }

  private handleChildConfirm(event: Event): void {
    if (this.redispatchingEvent) return;
    const child = this.childRef.value;
    const detail = (event as CustomEvent<{ confirmed?: boolean; error?: string }> | undefined)?.detail;
    const confirmed = detail?.confirmed !== false;
    const error: string | undefined = typeof detail?.error === 'string' ? detail.error : undefined;

    this.redispatchingEvent = true;
    try {
      event.stopImmediatePropagation();

      if (confirmed) {
        if (!this.loading) {
          this.loading = true;
          this.syncChildProps();
        }
        this.dispatchEvent(new CustomEvent(WalletIframeDomEvents.TX_CONFIRMER_CONFIRM, {
          detail: { confirmed: true },
          bubbles: true,
          composed: true,
        }));
        return;
      }

      this.loading = false;
      this.syncChildProps();
      // Close the child element if it exposes a close API; otherwise remove wrapper to avoid stale UI
      if (child?.close) {
        child.close(false);
      } else {
        this.remove();
      }

      const detail: { confirmed: false; error?: string } = { confirmed: false };
      if (typeof error === 'string') detail.error = error;

      this.dispatchEvent(new CustomEvent(WalletIframeDomEvents.TX_CONFIRMER_CANCEL, {
        detail,
        bubbles: true,
        composed: true,
      }));
    } finally {
      this.redispatchingEvent = false;
    }
  }
}

if (!customElements.get(W3A_TX_CONFIRMER_ID)) {
  customElements.define(W3A_TX_CONFIRMER_ID, TxConfirmerWrapperElement);
}
