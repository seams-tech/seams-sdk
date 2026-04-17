import { html, type PropertyValues } from 'lit';
import { LitElementWithProps } from '../LitElementWithProps';
import DrawerElement from '../Drawer';
import { W3A_DRAWER_ID } from '../../registry';
import TxConfirmContentElement from './tx-confirm-content';
import PadlockIconElement from '../common/PadlockIcon';
import { ensureExternalStyles } from '../css/css-loader';
import { WalletIframeDomEvents } from '@/core/WalletIframe/events';
import type { UserConfirmSecurityContext } from '@/core/types';
import type { TransactionInputWasm } from '@/core/types';
import type { ThemeName } from '../../confirm-ui-types';
import type { ConfirmUIElement } from '../../confirm-ui-types';
import type { TxDisplayModel } from '@/core/signingEngine/touchConfirm/shared/displayModel';
import type {
  EmailOtpConfirmPrompt,
  SigningAuthMode,
} from '@/core/signingEngine/touchConfirm/shared/confirmTypes';

/**
 * DrawerTxConfirmer: Drawer variant of the transaction confirmer
 */
export class DrawerTxConfirmerElement extends LitElementWithProps implements ConfirmUIElement {
  static requiredChildTags = ['w3a-tx-confirm-content', 'w3a-drawer'];
  static strictChildDefinitions = true;
  // Prevent bundlers from dropping nested custom element definitions used via templates
  static keepDefinitions = [TxConfirmContentElement, PadlockIconElement];
  static properties = {
    nearAccountId: { type: String, attribute: 'near-account-id' },
    txSigningRequests: { attribute: false },
    model: { attribute: false },
    securityContext: { type: Object },
    theme: { type: String, reflect: true },
    loading: { type: Boolean },
    errorMessage: { type: String },
    body: { type: String },
    title: { type: String },
    confirmText: { type: String },
    cancelText: { type: String },
    // Two‑phase close: when true, host controls removal
    deferClose: { type: Boolean, attribute: 'defer-close' },
    nearExplorerUrl: { type: String, attribute: 'near-explorer-url' },
    tempoExplorerUrl: { type: String, attribute: 'tempo-explorer-url' },
    evmExplorerUrl: { type: String, attribute: 'evm-explorer-url' },
    signingAuthMode: { type: String, attribute: 'signing-auth-mode' },
    emailOtpPrompt: { attribute: false },
    otpCode: { type: String, attribute: false },
    otpError: { type: String, attribute: false },
  } as const;

  declare nearAccountId: string;
  declare txSigningRequests?: TransactionInputWasm[];
  declare model?: TxDisplayModel;
  declare securityContext?: Partial<UserConfirmSecurityContext>;
  // Theme tokens now come from external CSS (tx-confirmer.css)
  // style injection has been removed to satisfy strict CSP.
  declare theme: ThemeName;
  declare loading: boolean;
  declare errorMessage?: string;
  declare body: string;
  declare title: string;
  declare confirmText: string;
  declare cancelText: string;
  declare deferClose: boolean;
  declare nearExplorerUrl?: string;
  declare tempoExplorerUrl?: string;
  declare evmExplorerUrl?: string;
  declare intentDigest?: string;
  declare signingAuthMode?: SigningAuthMode;
  declare emailOtpPrompt?: EmailOtpConfirmPrompt;
  otpCode = '';
  otpError = '';

  // Keep essential custom elements from being tree-shaken
  private _ensureDrawerDefinition = DrawerElement;
  private _drawerEl: InstanceType<typeof DrawerElement> | null = null;
  private _open: boolean = false;
  private _ownsThemeAttr = false;

  private _onWindowMessage = (ev: MessageEvent) => {
    const data =
      ev && ev.data && typeof ev.data === 'object'
        ? (ev.data as { type?: unknown; payload?: unknown })
        : undefined;
    if (!data || typeof data.type !== 'string') return;
    if (data.type === 'MODAL_TIMEOUT') {
      const msg =
        typeof data.payload === 'string' && data.payload ? data.payload : 'Operation timed out';
      this.loading = false;
      this.errorMessage = msg;
      // Best-effort close and emit cancel so host resolves and cleans up
      this._drawerEl?.handleClose?.();
      this.dispatchEvent(
        new CustomEvent(WalletIframeDomEvents.TX_CONFIRMER_CANCEL, {
          bubbles: true,
          composed: true,
          detail: { confirmed: false },
        }),
      );
    }
  };

  private _onKeyDown = (e: KeyboardEvent) => {
    if (e.key === 'Escape' || e.key === 'Esc') {
      if (this.loading) return;
      e.preventDefault();
      this._drawerEl?.handleClose();
      if (!this._drawerEl) {
        this.dispatchEvent(
          new CustomEvent(WalletIframeDomEvents.TX_CONFIRMER_CANCEL, {
            bubbles: true,
            composed: true,
            detail: { confirmed: false },
          }),
        );
      }
      // Rely on drawer's `cancel` event -> onDrawerCancel to emit w3a:modal-cancel
    }
  };

  private _chainLabelForModel(): string {
    switch (this.model?.chain) {
      case 'tempo':
        return 'Tempo';
      case 'evm':
        return 'EVM';
      case 'near':
        return 'NEAR';
      default:
        return 'Unknown';
    }
  }

  private _securityDetailsText(): string {
    const chainId = String(this.model?.chainId || '').trim();
    if (chainId) return `${this._chainLabelForModel()} | ChainID: ${chainId}`;
    const blockHeight = String(this.securityContext?.blockHeight || '').trim();
    return blockHeight ? `block ${blockHeight}` : '';
  }

  private _isSecurityDetailsLoading(): boolean {
    const chainId = String(this.model?.chainId || '').trim();
    if (chainId) return false;
    const blockHeight = String(this.securityContext?.blockHeight || '').trim();
    return this.loading && !blockHeight;
  }

  private _isEmailOtpMode(): boolean {
    return this.signingAuthMode === 'emailOtp';
  }

  private _onOtpInput = (event: Event): void => {
    const input = event.currentTarget as HTMLInputElement | null;
    this.otpCode = String(input?.value || '').replace(/\D/g, '').slice(0, 6);
    this.otpError = '';
  };

  private _renderEmailOtpPrompt() {
    if (!this._isEmailOtpMode()) return '';
    const helper =
      String(this.emailOtpPrompt?.helperText || '').trim() ||
      'Enter the 6-digit code sent to your email to authorize this transaction.';
    return html`
      <div class="email-otp-confirm">
        <label class="email-otp-confirm__label" for="drawer-email-otp-confirm-code">Email code</label>
        <input
          id="drawer-email-otp-confirm-code"
          class="email-otp-confirm__input"
          inputmode="numeric"
          autocomplete="one-time-code"
          pattern="[0-9]*"
          maxlength="6"
          .value=${this.otpCode}
          ?disabled=${this.loading}
          @input=${this._onOtpInput}
          aria-label="6-digit Email OTP code"
        />
        <div class="email-otp-confirm__helper">${helper}</div>
        ${this.otpError ? html`<div class="email-otp-confirm__error">${this.otpError}</div>` : ''}
      </div>
    `;
  }

  constructor() {
    super();
    this.nearAccountId = '';
    this.txSigningRequests = undefined;
    this.model = undefined;
    this.theme = 'dark';
    this.loading = false;
    this.body = '';
    this.title = '';
    this.confirmText = 'Next';
    this.cancelText = 'Cancel';
    this.deferClose = false;
  }

  protected getComponentPrefix(): string {
    return 'drawer-tx';
  }

  protected createRenderRoot(): HTMLElement | DocumentFragment {
    // Light DOM root so tokens cascade without Shadow DOM boundaries
    const root = this as unknown as HTMLElement;
    // Preload tokens + styles on host
    ensureExternalStyles(root, 'w3a-components.css', 'data-w3a-components-css').catch(() => {});
    ensureExternalStyles(root, 'tx-tree.css', 'data-w3a-tx-tree-css').catch(() => {});
    ensureExternalStyles(root, 'tx-confirmer.css', 'data-w3a-tx-confirmer-css').catch(() => {});
    return root;
  }

  connectedCallback(): void {
    super.connectedCallback();
    // Ensure root token theme is applied immediately on mount
    try {
      const docEl = this.ownerDocument?.documentElement as HTMLElement | undefined;
      if (docEl && this.theme) {
        const current = docEl.getAttribute('data-w3a-theme');
        if (!current || current === 'dark' || current === 'light') {
          docEl.setAttribute('data-w3a-theme', this.theme);
          this._ownsThemeAttr = true;
        }
      }
    } catch {}
    // Also ensure tokens CSS on document root for host-scoped variables
    try {
      const docEl = this.ownerDocument?.documentElement as HTMLElement | undefined;
      if (docEl)
        ensureExternalStyles(docEl, 'w3a-components.css', 'data-w3a-components-css').catch(
          () => {},
        );
    } catch {}
    window.addEventListener('keydown', this._onKeyDown);
    window.addEventListener('message', this._onWindowMessage as EventListener);
    // Ensure immediate keyboard handling (e.g., ESC) by focusing host/iframe
    const hostEl = this as unknown as HTMLElement;
    if (hostEl.tabIndex === undefined || hostEl.tabIndex === null) {
      hostEl.tabIndex = -1;
    }
    hostEl.focus({ preventScroll: true } as FocusOptions);
    if (typeof window.focus === 'function') {
      window.focus();
    }
  }

  async firstUpdated(): Promise<void> {
    this._drawerEl = (this as unknown as HTMLElement).querySelector(W3A_DRAWER_ID) as InstanceType<
      typeof DrawerElement
    > | null;
    // Ensure external styles are ready before opening (await Promise-based loader)
    const root = this.renderRoot as unknown as ShadowRoot | DocumentFragment | HTMLElement;
    await Promise.all([
      ensureExternalStyles(root, 'w3a-components.css', 'data-w3a-components-css'),
      ensureExternalStyles(root, 'tx-tree.css', 'data-w3a-tx-tree-css'),
      ensureExternalStyles(root, 'tx-confirmer.css', 'data-w3a-tx-confirmer-css'),
      // Preload drawer.css so fallback <link> is loaded before opening
      ensureExternalStyles(root, 'drawer.css', 'data-w3a-drawer-css'),
    ]);
    // Open after mount with double-rAF to let layout/styles settle
    await new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r())));
    this._open = true;
    this.requestUpdate();
  }

  disconnectedCallback(): void {
    window.removeEventListener('keydown', this._onKeyDown);
    window.removeEventListener('message', this._onWindowMessage as EventListener);
    super.disconnectedCallback();
  }

  updated(changed: PropertyValues) {
    super.updated(changed);
    // Keep the iframe/root document's theme in sync so :root[data-w3a-theme] tokens apply
    if (changed.has('theme')) {
      const docEl = this.ownerDocument?.documentElement as HTMLElement | undefined;
      if (docEl && this.theme && this._ownsThemeAttr) {
        docEl.setAttribute('data-w3a-theme', this.theme);
      }
    }
  }

  private onDrawerCancel = () => {
    if (this.loading) return;
    // Close drawer locally to ensure animation
    this._open = false;
    this.requestUpdate();
    this.dispatchEvent(
      new CustomEvent(WalletIframeDomEvents.TX_CONFIRMER_CANCEL, {
        bubbles: true,
        composed: true,
        detail: { confirmed: false },
      }),
    );
  };

  private onContentConfirm = () => {
    if (this.loading) return;
    if (this._isEmailOtpMode()) {
      const code = String(this.otpCode || '').replace(/\D/g, '').slice(0, 6);
      if (!/^\d{6}$/.test(code)) {
        this.otpCode = code;
        this.otpError = 'Enter the 6-digit Email OTP code.';
        this.requestUpdate();
        return;
      }
      this.otpCode = code;
      this.otpError = '';
    }
    this.loading = true;
    this.requestUpdate();
    // Bridge semantic event to canonical event
    this.dispatchEvent(
      new CustomEvent(WalletIframeDomEvents.TX_CONFIRMER_CONFIRM, {
        bubbles: true,
        composed: true,
        detail: {
          confirmed: true,
          ...(this._isEmailOtpMode() ? { otpCode: this.otpCode } : {}),
          ...(this._isEmailOtpMode() && this.emailOtpPrompt?.challengeId
            ? { emailOtpChallengeId: this.emailOtpPrompt.challengeId }
            : {}),
        },
      }),
    );
  };

  private onContentCancel = () => {
    if (this.loading) return;
    this._drawerEl?.handleClose();
    this._open = false;
    this.requestUpdate();
    this.dispatchEvent(
      new CustomEvent(WalletIframeDomEvents.TX_CONFIRMER_CANCEL, {
        bubbles: true,
        composed: true,
        detail: { confirmed: false },
      }),
    );
  };

  // Public method for two‑phase close from host/bootstrap
  close(_confirmed: boolean) {
    if (!this._open) return;
    this._open = false;
    this.requestUpdate();
  }

  render() {
    const securityDetailsText = this._securityDetailsText();
    const securityDetailsLoading = this._isSecurityDetailsLoading();
    return html`
      <w3a-drawer
        .open=${this._open}
        theme=${this.theme}
        .loading=${this.loading}
        .errorMessage=${this.errorMessage || ''}
        .height=${'auto'}
        .overpullPx=${160}
        .dragToClose=${true}
        .showCloseButton=${true}
        @lit-cancel=${this.onDrawerCancel}
      >
        <div class="drawer-tx-confirmer-root">
          <div class="section responsive-card margin-left1">
            <div class="drawer-header">
              ${(() => {
                const operationCount = Array.isArray(this.model?.operations)
                  ? this.model.operations.length
                  : 0;
                const isRegistration = operationCount === 0;
                const fallback = this._isEmailOtpMode()
                  ? 'Confirm with Email OTP'
                  : isRegistration
                    ? 'Register with Passkey'
                    : 'Confirm with Passkey';
                const titleText = (this.title || '').trim();
                const promptTitle = String(this.emailOtpPrompt?.title || '').trim();
                const heading = this._isEmailOtpMode()
                  ? promptTitle || fallback
                  : titleText || fallback;
                return html`<h2 class="drawer-title">${heading}</h2>`;
              })()}
            </div>
          </div>

          <div class="section responsive-card margin-left1">
            <div class="rpid-wrapper">
              <div class="rpid">
                <div class="secure-indicator">
                  <w3a-padlock-icon class="padlock-icon"></w3a-padlock-icon>
                  ${this.securityContext?.rpId
                    ? html`<span class="domain-text">${this.securityContext.rpId}</span>`
                    : ''}
                </div>
                ${securityDetailsText || securityDetailsLoading
                  ? html` <span class="security-details">
                      ${securityDetailsLoading
                        ? html`
                            <span
                              class="loading-indicator security-loading-indicator"
                              role="progressbar"
                              aria-label="Loading block height"
                            ></span>
                            <span>Loading block...</span>
                          `
                        : html`
                            <svg
                              xmlns="http://www.w3.org/2000/svg"
                              class="block-height-icon"
                              viewBox="0 0 24 24"
                              fill="none"
                              stroke="currentColor"
                              stroke-width="2"
                              stroke-linecap="round"
                              stroke-linejoin="round"
                            >
                              <path
                                d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"
                              />
                              <path d="m3.3 7 8.7 5 8.7-5" />
                              <path d="M12 22V12" />
                            </svg>
                            ${securityDetailsText}
                          `}
                    </span>`
                  : ''}
              </div>
            </div>
            ${this.body && this.body.trim()
              ? html`<div class="confirmation-body">${this.body}</div>`
              : ''}
            ${this._renderEmailOtpPrompt()}
          </div>
          <div class="section responsive-card responsive-card-center">
            <w3a-tx-confirm-content
              .nearAccountId=${this.nearAccountId || ''}
              .txSigningRequests=${this.txSigningRequests}
              .model=${this.model}
              .intentDigest=${this.intentDigest}
              .securityContext=${this.securityContext}
              .theme=${this.theme}
              .nearExplorerUrl=${this.nearExplorerUrl}
              .tempoExplorerUrl=${this.tempoExplorerUrl}
              .evmExplorerUrl=${this.evmExplorerUrl}
              .showShadow=${false}
              .loading=${this.loading}
              .errorMessage=${this.errorMessage || ''}
              .title=${this.title}
              .confirmText=${this._isEmailOtpMode() ? 'Verify code' : this.confirmText}
              .cancelText=${this.cancelText}
              @lit-confirm=${this.onContentConfirm}
              @lit-cancel=${this.onContentCancel}
            ></w3a-tx-confirm-content>
          </div>
        </div>
      </w3a-drawer>
    `;
  }
}

import { W3A_DRAWER_TX_CONFIRMER_ID } from '../../registry';

// Define canonical tag
if (!customElements.get(W3A_DRAWER_TX_CONFIRMER_ID)) {
  customElements.define(W3A_DRAWER_TX_CONFIRMER_ID, DrawerTxConfirmerElement);
}

export default DrawerTxConfirmerElement;
