import { html, type PropertyValues } from 'lit';
import { LitElementWithProps } from '../LitElementWithProps';

import type { PasskeyRegistrationConfirmDisplay, UserConfirmSecurityContext } from '@/core/types';
import type { TransactionInputWasm } from '@/core/types';
import type { TxDisplayModel } from '@/core/signingEngine/interfaces/display';

import TxTree from '../TxTree';
import { ensureExternalStyles } from '../css/css-loader';
import TxConfirmContentElement from './tx-confirm-content';
import type { ThemeMode } from '../../confirm-ui-types';
import type { AppearanceConfig } from '@/core/types/seams';
import type {
  EmailOtpConfirmPrompt,
  SigningAuthMode,
} from '@/core/signingEngine/stepUpConfirmation/types';
import { formatEmailOtpSentText } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/promptText';
// Ensure required custom elements are defined in this bundle (avoid tree-shake drops)
import HaloBorderElement from '../HaloBorder';
import PasskeyHaloLoadingElement from '../PasskeyHaloLoading';
import type { ConfirmUIElement } from '../../confirm-ui-types';
import { WalletIframeDomEvents } from '@/core/browser/walletIframe/events';
import {
  copyTextToClipboard,
  isNearTransactionSubmittingNotice,
  parseNearAccountFundingNotice,
} from '@/core/signingEngine/uiConfirm/nearFundingNotice';

const EMAIL_OTP_SUBMIT_FADE_MS = 150;

export interface SecureTxSummary {
  to?: string;
  totalAmount?: string;
  method?: string;
  fingerprint?: string; // short digest for display
}

// TxAction from wasm-worker
export interface TxAction {
  action_type: string;
  method_name?: string;
  args?: string;
  gas?: string;
  deposit?: string;
  [key: string]: string | number | boolean | null | undefined | object;
}

function formatEmailOtpResendError(error: unknown): string {
  const code =
    error && typeof error === 'object' && 'code' in error
      ? String((error as { code?: unknown }).code || '')
      : '';
  const retryAfterMs =
    error && typeof error === 'object' && 'retryAfterMs' in error
      ? Number((error as { retryAfterMs?: unknown }).retryAfterMs)
      : NaN;
  if (code === 'rate_limited') {
    if (Number.isFinite(retryAfterMs) && retryAfterMs > 0) {
      return `Too many requests. Try again in ${Math.max(1, Math.ceil(retryAfterMs / 1000))}s.`;
    }
    return 'Too many requests. Try again shortly.';
  }
  return error instanceof Error && error.message ? error.message : 'Could not send code.';
}

/**
 * Modal transaction confirmation component with multiple display variants.
 * Built with Lit with strict CSP for XSS protection and reactive updates.
 */
export class ModalTxConfirmElement extends LitElementWithProps implements ConfirmUIElement {
  static requiredChildTags = ['w3a-tx-confirm-content'];
  static strictChildDefinitions = true;
  // Prevent bundlers from dropping nested custom element definitions used via templates
  static keepDefinitions = [TxConfirmContentElement];
  // Component properties (automatically reactive)
  static properties = {
    nearAccountId: { type: String, attribute: 'near-account-id' },
    txSigningRequests: { attribute: false },
    to: { type: String },
    totalAmount: { type: String },
    method: { type: String },
    fingerprint: { type: String },
    body: { type: String },
    title: { type: String },
    cancelText: { type: String },
    confirmText: { type: String },
    model: { attribute: false },
    securityContext: { type: Object },
    loading: { type: Boolean },
    errorMessage: { type: String },
    theme: { type: String, attribute: 'theme', reflect: true },
    appearance: { attribute: false },
    nearExplorerUrl: { type: String, attribute: 'near-explorer-url' },
    tempoExplorerUrl: { type: String, attribute: 'tempo-explorer-url' },
    evmExplorerUrl: { type: String, attribute: 'evm-explorer-url' },
    signingAuthMode: { type: String, attribute: 'signing-auth-mode' },
    emailOtpPrompt: { attribute: false },
    otpCode: { type: String, attribute: false },
    otpError: { type: String, attribute: false },
    otpResendBusy: { type: Boolean, attribute: false },
    otpResendUntilMs: { type: Number, attribute: false },
    otpResendStatus: { type: String, attribute: false },
    otpSubmitAnimating: { type: Boolean, attribute: false },
  };

  totalAmount = '';
  method = '';
  fingerprint = '';
  body = '';
  title = '';
  cancelText = 'Cancel';
  confirmText = 'Next';
  model?: TxDisplayModel;
  securityContext?: Partial<UserConfirmSecurityContext>;
  loading = false;
  errorMessage: string | undefined = undefined;
  theme: ThemeMode = 'dark';
  appearance?: AppearanceConfig;
  nearExplorerUrl?: string;
  tempoExplorerUrl?: string;
  evmExplorerUrl?: string;
  signingAuthMode?: SigningAuthMode;
  emailOtpPrompt?: EmailOtpConfirmPrompt;
  otpCode = '';
  otpError = '';
  otpResendBusy = false;
  otpResendUntilMs = 0;
  otpResendStatus = '';
  otpSubmitAnimating = false;
  private _otpResendTimer: number | null = null;
  private _otpSubmitTimer: number | null = null;
  private _lastAutoOtpSubmitCode = '';
  intentDigest?: string;
  declare nearAccountId: string;
  declare txSigningRequests?: TransactionInputWasm[];
  // When true, this element will NOT remove itself on confirm/cancel.
  // The host is responsible for sending a CLOSE_MODAL instruction.
  deferClose = false;
  // Styles gating to avoid first-paint FOUC
  private _stylesReady = false;
  private _stylePromises: Promise<void>[] = [];
  private _stylesAwaiting: Promise<void> | null = null;

  // Keep essential custom elements from being tree-shaken
  private _ensureTreeDefinition = TxTree;
  private _ensureHaloElements = [HaloBorderElement, PasskeyHaloLoadingElement];

  // Removed fixed JS breakpoints; rely on CSS/container sizing for zoom resilience
  private _onKeyDown = (e: KeyboardEvent) => {
    if (e.key === 'Escape' || e.key === 'Esc') {
      // Only close for modal-style render modes
      e.preventDefault();
      this._handleCancel();
    }
  };
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
      // Emit cancel so the host resolves and removes this element via two‑phase close
      this._handleCancel();
    }
  };
  // Guard to prevent immediate backdrop-cancel due to the click that mounted the modal
  private _backdropArmed = false;

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
    const submittingTransaction = isNearTransactionSubmittingNotice(String(this.body || ''));
    return (this.loading || submittingTransaction) && !blockHeight;
  }

  private _isEmailOtpMode(): boolean {
    return this.signingAuthMode === 'emailOtp';
  }

  private _isWarmSessionMode(): boolean {
    return this.signingAuthMode === 'warmSession';
  }

  private _authHeadingFallback(): string {
    if (this._passkeyRegistrationDisplay()) return 'Create your passkey';
    if (this._isEmailOtpMode()) return 'Enter email code to sign';
    if (this._isWarmSessionMode()) return 'Review transaction';
    const operationCount = Array.isArray(this.model?.operations) ? this.model.operations.length : 0;
    const isRegistration = operationCount === 0;
    return isRegistration ? 'Register with Passkey' : 'Confirm with Passkey';
  }

  private _passkeyRegistrationDisplay(): PasskeyRegistrationConfirmDisplay | undefined {
    const display = this.securityContext?.passkeyRegistration;
    if (display?.kind !== 'passkey_registration_confirm_display_v1') return undefined;
    return display;
  }

  private _passkeyRegistrationBody(): string {
    return (
      (this.body || '').trim() ||
      'Use Touch ID or your device passkey to create credentials for this account.'
    );
  }

  private _passkeyRegistrationConfirmText(): string {
    return this.loading ? 'Creating passkey...' : 'Create passkey';
  }

  private _renderPasskeyRegistrationDetails(display: PasskeyRegistrationConfirmDisplay) {
    return html`
      <div class="passkey-registration-confirm__identity" aria-label="Passkey registration details">
        <div class="passkey-registration-confirm__row">
          <span class="passkey-registration-confirm__label">Account</span>
          <span class="passkey-registration-confirm__value" title=${display.intendedUserName}
            >${display.intendedUserName}</span
          >
        </div>
        <div class="passkey-registration-confirm__row">
          <span class="passkey-registration-confirm__label">Website</span>
          <span class="passkey-registration-confirm__value" title=${display.rpId}
            >${display.rpId}</span
          >
        </div>
      </div>
    `;
  }

  private _renderPasskeyRegistrationActions() {
    return html`
      <div class="passkey-registration-confirm__actions">
        <button
          type="button"
          class="btn btn-cancel"
          @click=${this._handleCancel}
        >
          ${this.cancelText || 'Cancel'}
        </button>
        <button
          type="button"
          class="btn btn-confirm"
          ?disabled=${this.loading}
          @click=${this._onPasskeyRegistrationConfirm}
        >
          ${this.loading
            ? html`<span
                  class="loading-indicator passkey-registration-confirm__spinner"
                  role="progressbar"
                  aria-label="Creating passkey"
                ></span>
                <span class="passkey-registration-confirm__busy-label"
                  >${this._passkeyRegistrationConfirmText()}</span
                >`
            : this._passkeyRegistrationConfirmText()}
        </button>
      </div>
    `;
  }

  private _onPasskeyRegistrationConfirm = (): void => {
    this._finishConfirm();
  };

  private _renderPasskeyRegistrationModal(display: PasskeyRegistrationConfirmDisplay) {
    return html`
      <div class="modal-backdrop-blur" @click=${this._handleBackdropClick}></div>
      <div class="modal-backdrop" @click=${this._handleContentClick}>
        <div class="modal-container-root passkey-registration-confirm">
          <div class="responsive-card">
            <div class="hero passkey-registration-confirm__hero">
              <w3a-passkey-halo-loading
                .theme=${this.theme}
                .appearance=${this.appearance}
                .animated=${this.loading && !this.errorMessage}
                .ringGap=${4}
                .ringWidth=${4}
                .ringBorderRadius=${'1.125rem'}
                .ringBackground=${this.loading && !this.errorMessage
                  ? 'var(--w3a-modal__passkey-halo-loading__ring-background)'
                  : 'transparent'}
                .innerPadding=${'0px'}
                .innerBackground=${'var(--w3a-modal__passkey-halo-loading__inner-background)'}
                .iconVariant=${'fingerprint'}
                .height=${44}
                .width=${44}
              ></w3a-passkey-halo-loading>
              <div class="hero-container passkey-registration-confirm__hero-copy">
                <h2 class="hero-heading">${(this.title || '').trim() || 'Create your passkey'}</h2>
                <p class="passkey-registration-confirm__body">${this._passkeyRegistrationBody()}</p>
              </div>
            </div>
            ${this.errorMessage ? html`<div class="error-banner">${this.errorMessage}</div>` : ''}
            ${this._renderPasskeyRegistrationDetails(display)}
            ${this._renderPasskeyRegistrationActions()}
          </div>
        </div>
      </div>
    `;
  }

  private _onOtpInput = (event: Event): void => {
    const input = event.currentTarget as HTMLInputElement | null;
    const code = String(input?.value || '')
      .replace(/\D/g, '')
      .slice(0, 6);
    this.otpCode = code;
    this.otpError = '';
    if (code.length < 6) {
      this._lastAutoOtpSubmitCode = '';
      this._resetOtpSubmitAnimation();
      return;
    }
    if (this.loading || this._lastAutoOtpSubmitCode === code) return;
    this._lastAutoOtpSubmitCode = code;
    this._submitEmailOtpAfterFade(code);
  };

  private _clearOtpSubmitTimer(): void {
    if (this._otpSubmitTimer != null) window.clearTimeout(this._otpSubmitTimer);
    this._otpSubmitTimer = null;
  }

  private _resetOtpSubmitAnimation(): void {
    this._clearOtpSubmitTimer();
    if (!this.otpSubmitAnimating) return;
    this.otpSubmitAnimating = false;
    this.requestUpdate();
  }

  private _submitEmailOtpAfterFade(code: string): void {
    this._clearOtpSubmitTimer();
    this.otpSubmitAnimating = true;
    this.requestUpdate();
    this._otpSubmitTimer = window.setTimeout(() => {
      this._otpSubmitTimer = null;
      if (!this.loading && this.otpCode === code) this._finishConfirm({ otpCode: code });
    }, EMAIL_OTP_SUBMIT_FADE_MS);
  }

  private _startOtpResendCountdown(durationMs: number): void {
    if (this._otpResendTimer != null) window.clearInterval(this._otpResendTimer);
    this.otpResendUntilMs = Date.now() + Math.max(1000, Math.floor(durationMs || 10_000));
    this._otpResendTimer = window.setInterval(() => {
      if (Date.now() >= this.otpResendUntilMs) {
        if (this._otpResendTimer != null) window.clearInterval(this._otpResendTimer);
        this._otpResendTimer = null;
      }
      this.requestUpdate();
    }, 250);
  }

  private _otpResendLabel(): string {
    if (this.otpResendBusy) return 'Sending...';
    const remainingMs = this.otpResendUntilMs - Date.now();
    if (remainingMs > 0) return `Resend in ${Math.ceil(remainingMs / 1000)}s`;
    return this.otpResendStatus || 'Resend code';
  }

  private _onOtpResend = (): void => {
    const resend = this.emailOtpPrompt?.onResend;
    if (typeof resend !== 'function' || this.otpResendBusy || this.loading) return;
    if (this.otpResendUntilMs > Date.now()) return;
    this.otpError = '';
    this.otpResendStatus = '';
    this._lastAutoOtpSubmitCode = '';
    this._resetOtpSubmitAnimation();
    this.otpResendBusy = true;
    this._startOtpResendCountdown(Number(this.emailOtpPrompt?.resendDebounceMs) || 10_000);
    this.requestUpdate();
    void (async () => {
      try {
        const result = await resend();
        const challengeId = String(result?.challengeId || '').trim();
        const emailHint = String(result?.emailHint || '').trim();
        if (challengeId) {
          this.emailOtpPrompt = {
            ...this.emailOtpPrompt,
            challengeId,
            ...(emailHint ? { emailHint } : {}),
          };
        }
        this.otpResendStatus = 'Code sent';
      } catch (error: unknown) {
        this.otpError = formatEmailOtpResendError(error);
      } finally {
        this.otpResendBusy = false;
        this.requestUpdate();
      }
    })();
  };

  private _renderEmailOtpPrompt() {
    if (!this._isEmailOtpMode()) return '';
    const helper =
      String(this.emailOtpPrompt?.helperText || '').trim() ||
      formatEmailOtpSentText(this.emailOtpPrompt?.emailHint);
    return html`
      <div class="email-otp-confirm">
        <label class="email-otp-confirm__label" for="email-otp-confirm-code">Email code</label>
        <div class="email-otp-confirm__code-field" data-disabled=${this.loading ? 'true' : 'false'}>
          <input
            id="email-otp-confirm-code"
            class="email-otp-confirm__input"
            inputmode="numeric"
            autocomplete="one-time-code"
            pattern="[0-9]*"
            maxlength="6"
            .value=${this.otpCode}
            ?disabled=${this.loading || this.otpSubmitAnimating}
            @input=${this._onOtpInput}
          />
          <div
            class="email-otp-confirm__slots${this.otpSubmitAnimating ? ' is-submitting' : ''}"
            aria-hidden="true"
          >
            ${[0, 1, 2, 3, 4, 5].map((index) => {
              const digit = this.otpCode[index] || '';
              return html`<span class="email-otp-confirm__slot${digit ? ' is-filled' : ''}"
                >${digit}</span
              >`;
            })}
          </div>
        </div>
        <div class="email-otp-confirm__helper">${helper}</div>
        ${this.otpError ? html`<div class="email-otp-confirm__error">${this.otpError}</div>` : ''}
        ${typeof this.emailOtpPrompt?.onResend === 'function'
          ? html`<button
              type="button"
              class="email-otp-confirm__resend"
              ?disabled=${this.loading || this.otpResendBusy || this.otpResendUntilMs > Date.now()}
              @click=${this._onOtpResend}
            >
              ${this._otpResendLabel()}
            </button>`
          : ''}
      </div>
    `;
  }

  private _onFundingNoticeCopy = (event: Event): void => {
    const target = event.currentTarget as HTMLElement | null;
    const accountId = String(target?.dataset.copyValue || '').trim();
    void copyTextToClipboard(accountId);
  };

  private _renderConfirmationBody() {
    const body = String(this.body || '').trim();
    if (!body) return '';
    if (isNearTransactionSubmittingNotice(body)) {
      return html`<div class="confirmation-body confirmation-body--status">${body}</div>`;
    }
    const fundingNotice = parseNearAccountFundingNotice(body);
    if (!fundingNotice) {
      return html`<div class="confirmation-body">${body}</div>`;
    }
    return html`
      <div class="confirmation-body confirmation-body--funding">
        NEAR account
        <button
          type="button"
          class="confirmation-body__copy-target"
          data-copy-value=${fundingNotice.accountId}
          title=${`Copy ${fundingNotice.accountId}`}
          aria-label=${`Copy NEAR account ${fundingNotice.accountId}`}
          @click=${this._onFundingNoticeCopy}
        >
          ${fundingNotice.shortAccountId}
        </button>
        needs funding
      </div>
    `;
  }

  // Render in light DOM to simplify CSS variable flow across nested components
  // (Shadow DOM disabled by returning the host element as the render root)

  // No inline static styles; see tx-confirmer.css
  constructor() {
    super();
    // Pre-ensure document-level styles so link loads can complete before first render
    const root = (document?.documentElement || null) as unknown as HTMLElement | null;
    if (root) {
      this._stylePromises.push(
        ensureExternalStyles(root, 'w3a-components.css', 'data-w3a-components-css'),
        ensureExternalStyles(root, 'tx-tree.css', 'data-w3a-tx-tree-css'),
        ensureExternalStyles(root, 'tx-confirmer.css', 'data-w3a-tx-confirmer-css'),
        // Preload nested visuals to avoid first-paint jank when halo/loader mount
        ensureExternalStyles(root, 'halo-border.css', 'data-w3a-halo-border-css'),
        ensureExternalStyles(root, 'passkey-halo-loading.css', 'data-w3a-passkey-halo-loading-css'),
      );
    }
  }

  private _ownsThemeAttr = false;

  updated(changedProperties: PropertyValues) {
    super.updated(changedProperties);
    if (changedProperties.has('theme') || changedProperties.has('appearance')) {
      this.applyAppearanceTokenVars();
    }
    if (
      this._isEmailOtpMode() &&
      this.otpSubmitAnimating &&
      !this.loading &&
      (changedProperties.has('loading') ||
        changedProperties.has('errorMessage') ||
        changedProperties.has('otpError')) &&
      (this.otpError || this.errorMessage)
    ) {
      this._lastAutoOtpSubmitCode = '';
      this._resetOtpSubmitAnimation();
    }
    // Keep the iframe/root document's theme in sync so :root[data-w3a-theme] tokens apply
    if (changedProperties.has('theme')) {
      try {
        const docEl = this.ownerDocument?.documentElement as HTMLElement | undefined;
        if (docEl && this.theme && this._ownsThemeAttr) {
          docEl.setAttribute('data-w3a-theme', this.theme);
        }
      } catch {}
    }
  }

  protected getComponentPrefix(): string {
    return 'modal';
  }

  protected createRenderRoot(): HTMLElement | DocumentFragment {
    const root = this as unknown as HTMLElement;
    // tx-tree.css for nested TxTree visuals inside the modal
    this._stylePromises.push(ensureExternalStyles(root, 'tx-tree.css', 'data-w3a-tx-tree-css'));
    // tx-confirmer.css for modal layout + tokens
    this._stylePromises.push(
      ensureExternalStyles(root, 'tx-confirmer.css', 'data-w3a-tx-confirmer-css'),
    );
    // Ensure nested loader/halo styles are present before first paint to avoid FOUC
    this._stylePromises.push(
      ensureExternalStyles(root, 'halo-border.css', 'data-w3a-halo-border-css'),
    );
    this._stylePromises.push(
      ensureExternalStyles(root, 'passkey-halo-loading.css', 'data-w3a-passkey-halo-loading-css'),
    );
    return root;
  }

  // Dynamic style application removed; CSS variables come from tx-confirmer.css

  disconnectedCallback() {
    window.removeEventListener('keydown', this._onKeyDown);
    window.removeEventListener('message', this._onWindowMessage as EventListener);
    if (this._otpResendTimer != null) window.clearInterval(this._otpResendTimer);
    this._otpResendTimer = null;
    this._clearOtpSubmitTimer();
    super.disconnectedCallback();
  }

  connectedCallback(): void {
    super.connectedCallback();
    this.applyAppearanceTokenVars();
    // Ensure root token theme is applied immediately on mount
    try {
      const docEl = this.ownerDocument?.documentElement as HTMLElement | undefined;
      if (docEl && this.theme) {
        const current = docEl.getAttribute('data-w3a-theme');
        // If missing or already using built-in values, take ownership and set
        if (!current || current === 'dark' || current === 'light') {
          docEl.setAttribute('data-w3a-theme', this.theme);
          this._ownsThemeAttr = true;
        }
      }
    } catch {}
    // Arm backdrop after the current event loop to avoid capturing the mounting click
    setTimeout(() => {
      this._backdropArmed = true;
    }, 0);
    // Listen globally so Escape works regardless of focus target
    window.addEventListener('keydown', this._onKeyDown);
    // Listen for global timeout notification (posted by SignerWorkerManager on operation timeout)
    window.addEventListener('message', this._onWindowMessage as EventListener);
    // Ensure this iframe/host receives keyboard focus so ESC works immediately
    // Make host focusable and focus it without scrolling
    const hostEl = this as unknown as HTMLElement;
    hostEl.tabIndex = hostEl.tabIndex ?? -1;
    hostEl.focus({ preventScroll: true } as FocusOptions);
    // Also attempt to focus the frame window in case we're inside an iframe
    if (typeof window.focus === 'function') {
      window.focus();
    }
  }

  protected shouldUpdate(_changed: PropertyValues): boolean {
    if (this._stylesReady) return true;
    if (!this._stylesAwaiting) {
      const p = Promise.all(this._stylePromises).then(
        () =>
          new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r()))),
      );
      this._stylesAwaiting = p.then(() => {
        this._stylesReady = true;
        this.requestUpdate();
      });
    }
    return false;
  }

  render() {
    const passkeyRegistration = this._passkeyRegistrationDisplay();
    if (passkeyRegistration) {
      return this._renderPasskeyRegistrationModal(passkeyRegistration);
    }

    const securityDetailsText = this._securityDetailsText();
    const securityDetailsLoading = this._isSecurityDetailsLoading();
    return html`
      <!-- Separate backdrop layer for independent animation -->
      <div class="modal-backdrop-blur" @click=${this._handleBackdropClick}></div>
      <!-- Modal content layer -->
      <div class="modal-backdrop" @click=${this._handleContentClick}>
        <div class="modal-container-root">
          <div class="responsive-card">
            <div class="hero">
              <w3a-passkey-halo-loading
                .theme=${this.theme}
                .appearance=${this.appearance}
                .animated=${!this.errorMessage ? true : false}
                .ringGap=${4}
                .ringWidth=${4}
                .ringBorderRadius=${'1.125rem'}
                .ringBackground=${'var(--w3a-modal__passkey-halo-loading__ring-background)'}
                .innerPadding=${'0px'}
                .innerBackground=${'var(--w3a-modal__passkey-halo-loading__inner-background)'}
                .iconVariant=${this._isEmailOtpMode() ? 'mail' : 'fingerprint'}
                .height=${36}
                .width=${36}
              ></w3a-passkey-halo-loading>
              <div class="hero-container">
                <!-- Hero heading -->
                ${(() => {
                  const fallback = this._authHeadingFallback();
                  const titleText = (this.title || '').trim();
                  const promptTitle = String(this.emailOtpPrompt?.title || '').trim();
                  const heading = this._isEmailOtpMode()
                    ? promptTitle || fallback
                    : this.signingAuthMode === 'webauthn' || this._isWarmSessionMode()
                      ? fallback
                      : titleText || fallback;
                  return html`<h2 class="hero-heading">${heading}</h2>`;
                })()}
                ${this.errorMessage
                  ? html`<div class="error-banner">${this.errorMessage}</div>`
                  : ''}
                <!-- RpID Section -->
                <div class="rpid-wrapper">
                  <div class="rpid">
                    <div class="secure-indicator">
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        class="padlock-icon"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="2"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                      >
                        <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
                        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                      </svg>
                      ${this.securityContext?.rpId
                        ? html`<span class="domain-text">${this.securityContext.rpId}</span>`
                        : ''}
                    </div>
                    <span class="security-details">
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
                                d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A 2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"
                              />
                              <path d="m3.3 7 8.7 5 8.7-5" />
                              <path d="M12 22V12" />
                            </svg>
                            ${securityDetailsText || 'block'}
                          `}
                    </span>
                  </div>
                </div>
              </div>
            </div>
            ${this._renderConfirmationBody()}
            ${this._renderEmailOtpPrompt()}
          </div>

          <div class="responsive-card">
            <w3a-tx-confirm-content
              .nearAccountId=${this['nearAccountId'] || ''}
              .txSigningRequests=${this.txSigningRequests}
              .model=${this.model}
              .intentDigest=${this.intentDigest}
              .securityContext=${this.securityContext}
              .theme=${this.theme}
              .appearance=${this.appearance}
              .nearExplorerUrl=${this.nearExplorerUrl}
              .tempoExplorerUrl=${this.tempoExplorerUrl}
              .evmExplorerUrl=${this.evmExplorerUrl}
              .showShadow=${false}
              .loading=${this.loading}
              .errorMessage=${this.errorMessage || ''}
              .title=${this.title}
              .confirmText=${this._isEmailOtpMode() ? 'Confirm Code' : this.confirmText}
              .cancelText=${this.cancelText}
              @lit-confirm=${this._handleConfirm}
              @lit-cancel=${this._handleCancel}
            ></w3a-tx-confirm-content>
          </div>
        </div>
      </div>
    `;
  }

  private _handleCancel() {
    // Canonical event (include a consistent detail payload)
    this.dispatchEvent(
      new CustomEvent(WalletIframeDomEvents.TX_CONFIRMER_CANCEL, {
        bubbles: true,
        composed: true,
        detail: { confirmed: false },
      }),
    );
    if (!this.deferClose) {
      this._resolveAndCleanup(false);
    }
  }

  private _handleConfirm() {
    if (this.loading || this.otpSubmitAnimating) return;
    if (this._isEmailOtpMode()) {
      const code = String(this.otpCode || '')
        .replace(/\D/g, '')
        .slice(0, 6);
      if (!/^\d{6}$/.test(code)) {
        this.otpCode = code;
        this.otpError = 'Enter the 6-digit Email OTP code.';
        this.requestUpdate();
        return;
      }
      this.otpCode = code;
      this.otpError = '';
      this._lastAutoOtpSubmitCode = code;
      this._submitEmailOtpAfterFade(code);
      return;
    }
    this._finishConfirm();
  }

  private _finishConfirm(opts?: { otpCode?: string }) {
    if (this.loading) return;
    if (this._isEmailOtpMode() && opts?.otpCode) {
      this.otpCode = opts.otpCode;
      this.otpError = '';
    }
    this.loading = true;
    this.requestUpdate();
    // Canonical event (include a consistent detail payload)
    this.dispatchEvent(
      new CustomEvent(WalletIframeDomEvents.TX_CONFIRMER_CONFIRM, {
        bubbles: true,
        composed: true,
        detail: {
          confirmed: true,
          ...(this._isEmailOtpMode() ? { otpCode: opts?.otpCode || this.otpCode } : {}),
          ...(this._isEmailOtpMode() && this.emailOtpPrompt?.challengeId
            ? { emailOtpChallengeId: this.emailOtpPrompt.challengeId }
            : {}),
        },
      }),
    );
    if (!this.deferClose) {
      this._resolveAndCleanup(true);
    }
  }

  private _handleBackdropClick() {
    // Ignore the first click that may have triggered mounting the modal
    if (!this._backdropArmed) return;
    this._handleCancel();
  }

  private _handleContentClick(e: Event) {
    e.stopPropagation();
  }

  private _resolveAndCleanup(_confirmed: boolean) {
    this.remove();
  }

  // Public method for two-phase close from host/bootstrap
  close(confirmed: boolean) {
    this._resolveAndCleanup(confirmed);
  }

  private applyAppearanceTokenVars(): void {
    this.setAppearanceCssVars(this.appearance);
  }
}

// Register the custom element
import { W3A_MODAL_TX_CONFIRMER_ID } from '../../registry';

// Define canonical tag
if (!customElements.get(W3A_MODAL_TX_CONFIRMER_ID)) {
  customElements.define(W3A_MODAL_TX_CONFIRMER_ID, ModalTxConfirmElement);
}
