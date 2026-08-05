import { html } from 'lit';
import { LitElementWithProps } from '@/core/signingEngine/uiConfirm/ui/lit-components/LitElementWithProps';
import PasskeyHaloLoadingElement from '@/core/signingEngine/uiConfirm/ui/lit-components/PasskeyHaloLoading';
import { ensureExternalStyles } from '@/core/signingEngine/uiConfirm/ui/lit-components/css/css-loader';
import {
  dispatchAuthMenuIntent,
  isAuthMenuActionReady,
  isAuthMenuLoadingStatus,
  isAuthMenuReady,
  type AuthMenuIntent,
  type AuthMenuViewModel,
} from './auth-menu-domain';

const AUTH_MENU_TAG = 'seams-auth-menu-surface';
const AUTH_MENU_CSS_MARKER = 'data-w3a-auth-menu-css';
const AUTH_MENU_TITLE_ID = 'w3a-auth-menu-title';

export class SeamsAuthMenuSurfaceElement extends LitElementWithProps {
  static properties = {
    viewModel: { attribute: false },
  } as const;

  static keepDefinitions = [PasskeyHaloLoadingElement];
  static requiredChildTags = ['w3a-passkey-halo-loading'];

  declare viewModel: AuthMenuViewModel;

  private readonly stylePromises: Promise<void>[] = [];
  private stylesReady = false;
  private stylesAwaiting: Promise<void> | null = null;
  private previouslyFocusedElement: HTMLElement | null = null;
  private shouldFocusInitialControl = false;
  private reducedMotionQuery: MediaQueryList | null = null;
  private prefersReducedMotion = false;

  protected createRenderRoot(): HTMLElement | DocumentFragment {
    const root = this as unknown as HTMLElement;
    const stylePromise = ensureExternalStyles(root, 'auth-menu.css', AUTH_MENU_CSS_MARKER);
    this.stylePromises.push(stylePromise);
    stylePromise.catch(() => {});
    return root;
  }

  connectedCallback(): void {
    const activeElement = document.activeElement;
    if (activeElement instanceof HTMLElement && !this.contains(activeElement)) {
      this.previouslyFocusedElement = activeElement;
    }
    this.shouldFocusInitialControl = true;
    this.setupReducedMotionQuery();
    super.connectedCallback();
    this.applyAppearanceTokens();
  }

  disconnectedCallback(): void {
    this.teardownReducedMotionQuery();
    this.restoreFocus();
    super.disconnectedCallback();
  }

  protected shouldUpdate(): boolean {
    if (this.stylesReady) return true;
    if (!this.stylesAwaiting) {
      const settle = Promise.all(this.stylePromises).then(
        () =>
          new Promise<void>((resolve) => {
            if (typeof requestAnimationFrame !== 'function') {
              resolve();
              return;
            }
            requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
          }),
      );
      this.stylesAwaiting = settle.then(() => {
        this.stylesReady = true;
        this.requestUpdate();
      });
    }
    return false;
  }

  protected updated(changedProperties: Map<string | number | symbol, unknown>): void {
    super.updated(changedProperties);
    if (changedProperties.has('viewModel')) {
      this.applyAppearanceTokens();
    }
    if (this.shouldFocusInitialControl) {
      this.focusInitialControl();
    }
  }

  private applyAppearanceTokens(): void {
    this.setAppearanceCssVars(this.viewModel?.appearance);
  }

  private setupReducedMotionQuery(): void {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return;
    const query = window.matchMedia('(prefers-reduced-motion: reduce)');
    this.reducedMotionQuery = query;
    this.prefersReducedMotion = query.matches;
    query.addEventListener?.('change', this.onReducedMotionChange);
  }

  private teardownReducedMotionQuery(): void {
    this.reducedMotionQuery?.removeEventListener?.('change', this.onReducedMotionChange);
    this.reducedMotionQuery = null;
  }

  private onReducedMotionChange = (event: MediaQueryListEvent): void => {
    this.prefersReducedMotion = event.matches;
    this.requestUpdate();
  };

  private focusInitialControl(): void {
    if (!this.isConnected || !this.shouldFocusInitialControl) return;
    this.shouldFocusInitialControl = false;
    const activeElement = document.activeElement;
    if (activeElement instanceof HTMLElement && this.contains(activeElement)) return;
    const closeButton = this.querySelector<HTMLButtonElement>('[data-auth-menu-close]');
    closeButton?.focus();
  }

  private restoreFocus(): void {
    const target = this.previouslyFocusedElement;
    this.previouslyFocusedElement = null;
    if (!target?.isConnected) return;
    target.focus();
  }

  private onKeydown = (event: KeyboardEvent): void => {
    if (event.key === 'Escape') {
      event.preventDefault();
      this.emitIntent({ kind: 'close', reason: 'escape' });
      return;
    }
    if (event.key !== 'Tab') return;
    const focusable = this.focusableElements();
    if (focusable.length === 0) return;
    const active = document.activeElement;
    const activeIndex = focusable.indexOf(active instanceof HTMLElement ? active : focusable[0]);
    if (event.shiftKey && activeIndex <= 0) {
      event.preventDefault();
      focusable[focusable.length - 1]?.focus();
    } else if (!event.shiftKey && activeIndex === focusable.length - 1) {
      event.preventDefault();
      focusable[0]?.focus();
    }
  };

  private focusableElements(): HTMLElement[] {
    return Array.from(
      this.querySelectorAll<HTMLElement>(
        'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])',
      ),
    );
  }

  private onCloseClick = (): void => {
    this.emitIntent({ kind: 'close', reason: 'close_button' });
  };

  private onModeSelect = (event: Event): void => {
    if (!(event.currentTarget instanceof HTMLButtonElement)) return;
    const mode = event.currentTarget.dataset.authMenuMode;
    if (mode !== 'login' && mode !== 'register') return;
    this.emitIntent({ kind: 'mode_selected', mode });
  };

  private onRegistrationReroll = (): void => {
    this.emitIntent({ kind: 'registration_reroll' });
  };

  private onPasskeyNameInput = (event: Event): void => {
    if (!(event.currentTarget instanceof HTMLInputElement)) return;
    this.emitIntent({ kind: 'passkey_name_changed', passkeyName: event.currentTarget.value });
  };

  private onLoginAccountSelect = (event: Event): void => {
    if (!(event.currentTarget instanceof HTMLSelectElement)) return;
    this.emitIntent({ kind: 'login_account_selected', walletId: event.currentTarget.value });
  };

  private onPrimaryClick = (): void => {
    const viewModel = this.viewModel;
    if (!viewModel || !isAuthMenuActionReady(viewModel)) return;
    if (viewModel.kind === 'google_otp_login') {
      this.emitIntent({ kind: 'google_otp_submit' });
      return;
    }
    if (viewModel.kind === 'google_registration') {
      this.emitIntent({ kind: 'google_registration_complete' });
      return;
    }
    const intent: AuthMenuIntent =
      viewModel.mode === 'register'
        ? { kind: 'submit', mode: 'register', passkeyName: viewModel.passkeyName }
        : { kind: 'submit', mode: 'login' };
    this.emitIntent(intent);
  };

  private onGoogleOtpCodeInput = (event: Event): void => {
    if (!(event.currentTarget instanceof HTMLInputElement)) return;
    this.emitIntent({ kind: 'google_otp_code_changed', code: event.currentTarget.value });
  };

  private onGoogleOtpKeydown = (event: KeyboardEvent): void => {
    if (event.key !== 'Enter') return;
    event.preventDefault();
    this.emitIntent({ kind: 'google_otp_submit' });
  };

  private onGoogleOtpResend = (): void => {
    this.emitIntent({ kind: 'google_otp_resend' });
  };

  private onGoogleRegistrationReroll = (): void => {
    this.emitIntent({ kind: 'google_registration_reroll' });
  };

  private onRetry = (): void => {
    this.emitIntent({ kind: 'retry' });
  };

  private onExternalAuthClick = (event: Event): void => {
    if (!(event.currentTarget instanceof HTMLButtonElement)) return;
    const provider = event.currentTarget.dataset.authMenuProvider;
    if (provider !== 'google') return;
    this.emitIntent({ kind: 'external_auth', provider });
  };

  private emitIntent(intent: AuthMenuIntent): void {
    dispatchAuthMenuIntent(this, intent);
  }

  render() {
    const viewModel = this.viewModel;
    if (!viewModel) return html``;

    const loading = isAuthMenuLoadingStatus(viewModel.status);
    const primaryDisabled = !isAuthMenuActionReady(viewModel);
    const theme = viewModel.appearance.theme.mode;

    return html`
      <div
        class="auth-menu-root ${theme}"
        role="dialog"
        aria-modal="true"
        aria-labelledby=${AUTH_MENU_TITLE_ID}
        aria-busy=${loading ? 'true' : 'false'}
        tabindex="-1"
        @keydown=${this.onKeydown}
      >
        <section class="auth-menu-card">
          <header class="auth-menu-header">
            <svg
              class="auth-menu-link-icon"
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
              aria-hidden="true"
              focusable="false"
            >
              <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.71 1.71" />
              <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
            </svg>
            <span class="auth-menu-hostname">${viewModel.hostname}</span>
            <button
              class="auth-menu-close"
              type="button"
              data-auth-menu-close
              aria-label=${viewModel.closeLabel}
              @click=${this.onCloseClick}
            >
              <svg
                width="18"
                height="18"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
                aria-hidden="true"
                focusable="false"
              >
                <path d="M18 6 6 18" />
                <path d="m6 6 12 12" />
              </svg>
            </button>
          </header>

          <div class="auth-menu-content">
            <h1 class="auth-menu-heading" id=${AUTH_MENU_TITLE_ID}>${viewModel.heading}</h1>
            <p class="auth-menu-subtitle">${viewModel.subtitle}</p>

            <div class="auth-menu-mode-switch" role="tablist" aria-label="Authentication mode">
              ${(['login', 'register'] as const).map(
                (mode) => html`
                  <button
                    class="auth-menu-mode-option"
                    type="button"
                    role="tab"
                    aria-selected=${viewModel.mode === mode ? 'true' : 'false'}
                    data-auth-menu-mode=${mode}
                    ?disabled=${viewModel.mode === mode || viewModel.status.kind === 'performing'}
                    @click=${this.onModeSelect}
                  >
                    ${mode === 'login' ? 'Sign in' : 'Create wallet'}
                  </button>
                `,
              )}
            </div>

            ${viewModel.kind === 'passkey' &&
            viewModel.mode === 'login' &&
            viewModel.accountOptions.length > 1
              ? html`
                  <div class="auth-menu-form">
                    <label class="auth-menu-label" for="w3a-auth-menu-login-account">
                      Wallet
                    </label>
                    <select
                      class="auth-menu-input"
                      id="w3a-auth-menu-login-account"
                      .value=${viewModel.selectedWalletId ?? ''}
                      @change=${this.onLoginAccountSelect}
                    >
                      ${viewModel.accountOptions.map(
                        (account) => html`
                          <option value=${account.walletId}>${account.displayName}</option>
                        `,
                      )}
                    </select>
                  </div>
                `
              : null}
            ${viewModel.kind === 'passkey' &&
            viewModel.mode === 'register' &&
            viewModel.showRegistrationInput
              ? html`
                  <div class="auth-menu-form">
                    <label class="auth-menu-label" for="w3a-auth-menu-passkey-name">
                      ${viewModel.passkeyNameLabel}
                    </label>
                    <input
                      class="auth-menu-input"
                      id="w3a-auth-menu-passkey-name"
                      type="text"
                      autocomplete="nickname"
                      .value=${viewModel.passkeyName}
                      ?readonly=${viewModel.passkeyNameReadOnly}
                      ?disabled=${viewModel.status.kind === 'performing'}
                      @input=${this.onPasskeyNameInput}
                    />
                  </div>
                  ${viewModel.passkeyNameReadOnly
                    ? html`
                        <button
                          class="auth-menu-provider auth-menu-registration-reroll"
                          type="button"
                          @click=${this.onRegistrationReroll}
                          ?disabled=${!isAuthMenuReady(viewModel)}
                        >
                          Generate another name
                        </button>
                      `
                    : null}
                `
              : null}
            ${this.renderGoogleContent(viewModel)}
            ${loading ? this.renderProgress(viewModel) : null}
            ${viewModel.status.kind === 'error' || viewModel.status.kind === 'expired'
              ? html`<p class="auth-menu-error" role="alert">${viewModel.status.message}</p>`
              : null}
          </div>

          <button
            class="auth-menu-primary"
            type="button"
            data-auth-menu-primary
            ?disabled=${primaryDisabled}
            @click=${this.onPrimaryClick}
          >
            ${viewModel.ctaLabel}
          </button>
          ${viewModel.status.kind === 'error' || viewModel.status.kind === 'expired'
            ? html`
                <button
                  class="auth-menu-provider auth-menu-retry"
                  type="button"
                  @click=${this.onRetry}
                >
                  Retry
                </button>
              `
            : null}
          ${this.renderExternalProviders(viewModel)}
        </section>
      </div>
    `;
  }

  private renderGoogleContent(viewModel: AuthMenuViewModel) {
    if (viewModel.kind === 'google_otp_login') {
      const deliveryMessage =
        viewModel.delivery.status === 'reused'
          ? `Use the code already sent to ${viewModel.emailHint}.`
          : `A 6-digit code was sent to ${viewModel.emailHint}.`;
      return html`
        <div class="auth-menu-google-flow" aria-live="polite">
          <div class="auth-menu-google-account" title=${viewModel.walletId}>
            <span class="auth-menu-google-account-label">Wallet</span>
            <span class="auth-menu-google-account-value">${viewModel.walletId}</span>
          </div>
          <label class="auth-menu-label" for="w3a-auth-menu-google-otp">Email code</label>
          <input
            class="auth-menu-input auth-menu-google-otp"
            id="w3a-auth-menu-google-otp"
            type="text"
            inputmode="numeric"
            autocomplete="one-time-code"
            pattern="[0-9]*"
            maxlength="6"
            .value=${viewModel.otpCode}
            ?disabled=${viewModel.submitBusy}
            @input=${this.onGoogleOtpCodeInput}
            @keydown=${this.onGoogleOtpKeydown}
          />
          <p class="auth-menu-google-delivery">${deliveryMessage}</p>
          ${viewModel.error
            ? html`<p class="auth-menu-error" role="alert">${viewModel.error}</p>`
            : null}
          <button
            class="auth-menu-provider auth-menu-google-resend"
            type="button"
            @click=${this.onGoogleOtpResend}
            ?disabled=${viewModel.resendBusy || viewModel.submitBusy}
          >
            ${viewModel.resendBusy ? 'Sending…' : 'Resend code'}
          </button>
        </div>
      `;
    }
    if (viewModel.kind === 'google_registration') {
      return html`
        <div class="auth-menu-google-flow" aria-live="polite">
          <div class="auth-menu-google-account" title=${viewModel.walletId}>
            <span class="auth-menu-google-account-label">Wallet</span>
            <span class="auth-menu-google-account-value">${viewModel.walletId}</span>
          </div>
          <button
            class="auth-menu-provider auth-menu-google-reroll"
            type="button"
            @click=${this.onGoogleRegistrationReroll}
            ?disabled=${viewModel.rerollBusy || viewModel.submitBusy}
          >
            ${viewModel.rerollBusy ? 'Generating…' : 'Generate another name'}
          </button>
          ${viewModel.error
            ? html`<p class="auth-menu-error" role="alert">${viewModel.error}</p>`
            : null}
        </div>
      `;
    }
    return html``;
  }

  private renderExternalProviders(viewModel: AuthMenuViewModel) {
    if (viewModel.kind !== 'passkey') return html``;
    const providers = viewModel.enabledExternalProviders ?? [];
    if (providers.length === 0) return html``;
    return html`
      <div class="auth-menu-providers" aria-label="Other sign-in options">
        ${providers.map(
          (provider) => html`
            <button
              class="auth-menu-provider"
              type="button"
              data-auth-menu-provider=${provider}
              ?disabled=${!isAuthMenuReady(viewModel)}
              @click=${this.onExternalAuthClick}
            >
              ${provider === 'google' ? 'Continue with Google' : provider}
            </button>
          `,
        )}
      </div>
    `;
  }

  private renderProgress(viewModel: AuthMenuViewModel) {
    const status = viewModel.status;
    if (status.kind !== 'preparing' && status.kind !== 'performing') return html``;
    const message = viewModel.showProgress ? status.message : '';
    return html`
      <div class="auth-menu-progress" role="status" aria-live="polite">
        <w3a-passkey-halo-loading
          .theme=${viewModel.appearance.theme.mode}
          .appearance=${viewModel.appearance}
          .animated=${!this.prefersReducedMotion}
          .height=${32}
          .width=${32}
          .ringGap=${3}
          .ringWidth=${3}
        ></w3a-passkey-halo-loading>
        ${message ? html`<span>${message}</span>` : null}
      </div>
    `;
  }
}

if (!customElements.get(AUTH_MENU_TAG)) {
  customElements.define(AUTH_MENU_TAG, SeamsAuthMenuSurfaceElement);
}

export default SeamsAuthMenuSurfaceElement;
