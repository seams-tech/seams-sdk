import { html, type TemplateResult } from 'lit';
import { keyed } from 'lit/directives/keyed.js';
import { LitElementWithProps } from '@/core/signingEngine/uiConfirm/ui/lit-components/LitElementWithProps';
import { ensureExternalStyles } from '@/core/signingEngine/uiConfirm/ui/lit-components/css/css-loader';
import {
  dispatchAuthMenuIntent,
  isAuthMenuActionReady,
  isAuthMenuActionable,
  isAuthMenuLoadingStatus,
  isAuthMenuReady,
  type AuthMenuIntent,
  type AuthMenuLinkDeviceState,
  type AuthMenuLoginViewModel,
  type AuthMenuRegisterViewModel,
  type AuthMenuViewModel,
} from './auth-menu-domain';

const AUTH_MENU_TAG = 'seams-auth-menu-surface';
const AUTH_MENU_CSS_MARKER = 'data-w3a-auth-menu-css';
const AUTH_MENU_TITLE_ID = 'w3a-auth-menu-title';
const AUTH_MENU_ACCOUNT_LIST_ID = 'w3a-auth-menu-account-list';

function authViewKey(viewModel: AuthMenuViewModel): string {
  return `${viewModel.kind}:${viewModel.mode}:${viewModel.status.kind}`;
}

function modeSwitchCopy(mode: AuthMenuViewModel['mode']): {
  prompt: string;
  action: string;
  nextMode: 'login' | 'register';
} {
  return mode === 'register'
    ? { prompt: 'Already have an account?', action: 'Sign in', nextMode: 'login' }
    : { prompt: "Don't have an account?", action: 'Sign up', nextMode: 'register' };
}

function passkeyButtonLabel(mode: AuthMenuViewModel['mode']): string {
  return mode === 'register' ? 'Sign up with Passkey' : 'Sign in with Passkey';
}

function googleButtonLabel(mode: AuthMenuViewModel['mode']): string {
  return mode === 'register' ? 'Sign up with Google' : 'Sign in with Google';
}

function fingerprintIcon(): TemplateResult {
  return html`
    <svg
      width="22"
      height="22"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.5"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <path d="M6.405 19.048c.184-.443.353-.894.507-1.351" />
      <path d="M14.343 20.693c.266-.751.502-1.516.707-2.294.186-.706.346-1.422.478-2.147" />
      <path
        d="M19.448 17.058c.364-1.964.555-3.989.555-6.058 0-4.418-3.582-8-8-8-1.255 0-2.443.289-3.501.805"
      />
      <path d="M3.523 15.025c.314-1.29.48-2.638.48-4.025 0-1.74.556-3.351 1.499-4.664" />
      <path d="M12.003 11c0 2.76-.447 5.416-1.273 7.899-.213.639-.451 1.266-.712 1.881" />
      <path
        d="M7.712 14.5c.191-1.138.291-2.308.291-3.5 0-2.209 1.791-4 4-4s4 1.791 4 4c0 .617-.02 1.229-.058 1.836"
      />
    </svg>
  `;
}

function googleIcon(): TemplateResult {
  return html`
    <svg
      width="22"
      height="22"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="2"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <path d="M10.88 21.94 15.46 14" />
      <path d="M21.17 8H12" />
      <path d="M3.95 6.06 8.54 14" />
      <circle cx="12" cy="12" r="10" />
      <circle cx="12" cy="12" r="4" />
    </svg>
  `;
}

function arrowIcon(): TemplateResult {
  return html`
    <div class="stripe-arrow w3a-auth-method-arrow">
      <svg class="HoverArrow" width="16" height="16" viewBox="0 0 10 10" aria-hidden="true">
        <g fill-rule="evenodd">
          <path class="HoverArrow__linePath" d="M0 5h7" />
          <path class="HoverArrow__tipPath" d="M1 1l4 4-4 4" />
        </g>
      </svg>
    </div>
  `;
}

function accountDropdownIcon(): TemplateResult {
  return html`
    <svg
      class="w3a-account-dropdown-arrow"
      viewBox="0 0 24 24"
      aria-hidden="true"
      focusable="false"
    >
      <path d="M9.75 3h4.5v10.28l4.3-4.3 3.18 3.18L12 21.9l-9.73-9.74 3.18-3.18 4.3 4.3V3Z" />
    </svg>
  `;
}

function backIcon(): TemplateResult {
  return html`
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="2.25"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <path d="m15 18-6-6 6-6" />
    </svg>
  `;
}

function linkDeviceIcon(): TemplateResult {
  return html`
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
    >
      <rect width="5" height="5" x="3" y="3" rx="1" />
      <rect width="5" height="5" x="16" y="3" rx="1" />
      <rect width="5" height="5" x="3" y="16" rx="1" />
      <path d="M21 16h-3a2 2 0 0 0-2 2v3" />
      <path d="M21 21v.01" />
      <path d="M12 7v3a2 2 0 0 1-2 2H7" />
      <path d="M3 12h.01" />
      <path d="M12 3h.01" />
      <path d="M12 16v.01" />
      <path d="M16 12h1" />
      <path d="M21 12v.01" />
      <path d="M12 21v-1" />
    </svg>
  `;
}

function approvedDeviceIcon(): TemplateResult {
  return html`
    <svg
      width="28"
      height="28"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="2.25"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <path d="m5 12 4 4L19 6" />
    </svg>
  `;
}

function linkFailedIcon(): TemplateResult {
  return html`
    <svg
      width="26"
      height="26"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="2"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <path d="M9 17H7A5 5 0 0 1 7 7h2" />
      <path d="M15 7h2a5 5 0 0 1 3.54 8.54" />
      <path d="m2 2 20 20" />
      <path d="M8 12h3" />
    </svg>
  `;
}

function rerollIcon(): TemplateResult {
  return html`
    <svg
      class="w3a-input-action-icon"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="2"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8" />
      <path d="M21 3v5h-5" />
      <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16" />
      <path d="M8 16H3v5" />
    </svg>
  `;
}

function selectedLoginAccount(viewModel: AuthMenuLoginViewModel) {
  return (
    viewModel.accountOptions.find((account) => account.walletId === viewModel.selectedWalletId) ??
    viewModel.accountOptions[0] ??
    null
  );
}

export class SeamsAuthMenuSurfaceElement extends LitElementWithProps {
  static properties = {
    viewModel: { attribute: false },
    accountMenuOpen: { state: true },
  } as const;

  /* Typed with `!` rather than `declare`: both erase without emitting a class
     field that would shadow the accessors `static properties` installs, but
     the test runner's bundled Babel rejects a `declare` field outright, which
     makes this module unimportable from a unit test. */
  viewModel!: AuthMenuViewModel;
  private accountMenuOpen!: boolean;

  private readonly stylePromises: Promise<void>[] = [];
  private stylesReady = false;
  private stylesAwaiting: Promise<void> | null = null;
  private previouslyFocusedElement: HTMLElement | null = null;
  private shouldFocusInitialControl = false;
  private contentResizeObserver: ResizeObserver | null = null;
  private contentHeightFrame: number | null = null;
  private previousLinkDeviceStateKind: AuthMenuLinkDeviceState['kind'] | null = null;

  constructor() {
    super();
    this.accountMenuOpen = false;
  }

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
    document.addEventListener('pointerdown', this.onDocumentPointerDown);
    // Capture phase: the key must reach this handler even when focus sits on a
    // control inside the surface.
    document.addEventListener('keydown', this.onKeyDown, true);
    super.connectedCallback();
  }

  disconnectedCallback(): void {
    this.contentResizeObserver?.disconnect();
    this.contentResizeObserver = null;
    if (this.contentHeightFrame !== null) cancelAnimationFrame(this.contentHeightFrame);
    this.contentHeightFrame = null;
    window.removeEventListener('resize', this.queueContentHeightSync);
    document.removeEventListener('pointerdown', this.onDocumentPointerDown);
    document.removeEventListener('keydown', this.onKeyDown, true);
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
    if (this.shouldFocusInitialControl) this.focusInitialControl();
    this.focusLinkDevicePasskeyAction();
    this.observeContentSize();
    this.queueContentHeightSync();
  }

  private focusLinkDevicePasskeyAction(): void {
    const currentKind =
      this.viewModel.kind === 'link_device' ? this.viewModel.linkDevice.kind : null;
    const shouldFocus =
      currentKind === 'passkey_required' && this.previousLinkDeviceStateKind !== currentKind;
    this.previousLinkDeviceStateKind = currentKind;
    if (shouldFocus) {
      this.querySelector<HTMLElement>('[data-link-device-passkey-action]')?.focus();
    }
  }

  private observeContentSize(): void {
    if (this.contentResizeObserver) return;
    const sizer = this.querySelector<HTMLElement>('.w3a-content-sizer');
    if (!sizer) return;
    this.contentResizeObserver = new ResizeObserver(this.queueContentHeightSync);
    this.contentResizeObserver.observe(sizer);
    window.addEventListener('resize', this.queueContentHeightSync);
  }

  private readonly queueContentHeightSync = (): void => {
    if (this.contentHeightFrame !== null) cancelAnimationFrame(this.contentHeightFrame);
    this.contentHeightFrame = requestAnimationFrame(this.syncContentHeight);
  };

  private readonly syncContentHeight = (): void => {
    this.contentHeightFrame = null;
    const switcher = this.querySelector<HTMLElement>('.w3a-content-switcher');
    const sizer = this.querySelector<HTMLElement>('.w3a-content-sizer');
    if (!switcher || !sizer) return;
    switcher.style.height = `${sizer.scrollHeight}px`;
  };

  private focusInitialControl(): void {
    if (!this.isConnected || !this.shouldFocusInitialControl) return;
    this.shouldFocusInitialControl = false;
    const activeElement = document.activeElement;
    if (activeElement instanceof HTMLElement && this.contains(activeElement)) return;
    this.querySelector<HTMLElement>('[data-auth-menu-input], [data-auth-menu-primary]')?.focus();
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
      if (this.accountMenuOpen) {
        this.accountMenuOpen = false;
        return;
      }
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

  private onBackClick = (): void => {
    this.emitIntent({ kind: 'back' });
  };

  /**
   * Escape backs out of the in-progress views the back arrow already serves.
   * The host dialog is opened non-modally, so it never receives the UA's
   * `cancel` event — without this the key does nothing while a ceremony is
   * pending. Deliberately scoped to those views: from the menu itself Escape
   * belongs to the embedding page, not to us.
   */
  private readonly onKeyDown = (event: KeyboardEvent): void => {
    if (event.key !== 'Escape' || event.defaultPrevented) return;
    const viewModel = this.viewModel;
    if (!viewModel || !isAuthMenuLoadingStatus(viewModel.status)) return;
    event.preventDefault();
    event.stopPropagation();
    this.emitIntent({ kind: 'back' });
  };

  private onIntentSwitchClick = (): void => {
    const viewModel = this.viewModel;
    if (!viewModel) return;
    this.emitIntent({ kind: 'mode_selected', mode: modeSwitchCopy(viewModel.mode).nextMode });
  };

  private onRegistrationReroll = (): void => {
    this.emitIntent({ kind: 'registration_reroll' });
  };

  private onPasskeyNameInput = (event: Event): void => {
    if (!(event.currentTarget instanceof HTMLInputElement)) return;
    this.emitIntent({ kind: 'passkey_name_changed', passkeyName: event.currentTarget.value });
  };

  private onLoginAccountSelect = (event: Event): void => {
    if (!(event.currentTarget instanceof HTMLButtonElement)) return;
    const walletId = event.currentTarget.dataset.walletId;
    if (!walletId) return;
    this.accountMenuOpen = false;
    this.emitIntent({ kind: 'login_account_selected', walletId });
  };

  private onAccountMenuToggle = (): void => {
    this.accountMenuOpen = !this.accountMenuOpen;
  };

  private onDocumentPointerDown = (event: PointerEvent): void => {
    if (!this.accountMenuOpen || !(event.target instanceof Node)) return;
    if (this.querySelector('.w3a-account-menu')?.contains(event.target)) return;
    this.accountMenuOpen = false;
  };

  private onPrimaryClick = (): void => {
    const viewModel = this.viewModel;
    if (!viewModel || !isAuthMenuActionReady(viewModel)) return;
    if (viewModel.kind === 'link_device') return;
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

  private onGoogleClick = (): void => {
    this.emitIntent({ kind: 'external_auth', provider: 'google' });
  };

  private onLinkDeviceOpen = (): void => {
    this.emitIntent({ kind: 'link_device_open' });
  };

  private onLinkDeviceCreatePasskey = (): void => {
    this.emitIntent({ kind: 'link_device_create_passkey' });
  };

  private emitIntent(intent: AuthMenuIntent): void {
    dispatchAuthMenuIntent(this, intent);
  }

  render(): TemplateResult {
    const viewModel = this.viewModel;
    if (!viewModel) return html``;

    const loading = isAuthMenuLoadingStatus(viewModel.status);
    const linkDevice = viewModel.kind === 'link_device';
    const otpPrompt = viewModel.kind === 'google_otp_login';
    const registrationPrompt = viewModel.kind === 'google_registration';

    return html`
      <div
        class="w3a-signup-menu-root auth-menu-root"
        data-mode=${viewModel.mode}
        data-waiting=${loading ? 'true' : 'false'}
        data-scan-device=${linkDevice ? 'true' : 'false'}
        data-otp-prompt=${otpPrompt ? 'true' : 'false'}
        data-registration-prompt=${registrationPrompt ? 'true' : 'false'}
        aria-labelledby=${AUTH_MENU_TITLE_ID}
        aria-busy=${loading ? 'true' : 'false'}
        tabindex="-1"
        @keydown=${this.onKeydown}
      >
        <div class="w3a-content-switcher">
          <button
            class="w3a-back-button ${loading || linkDevice || otpPrompt || registrationPrompt
              ? 'is-visible'
              : ''}"
            type="button"
            aria-label="Back"
            data-auth-menu-close
            @click=${this.onBackClick}
          >
            ${backIcon()}
          </button>
          <div class="w3a-content-area">
            <div class="w3a-content-sizer">
              ${loading
                ? this.renderWaiting(viewModel)
                : html`
                    <div class="w3a-signin-menu">
                      ${keyed(authViewKey(viewModel), this.renderActiveView(viewModel))}
                    </div>
                  `}
            </div>
          </div>
        </div>
      </div>
    `;
  }

  private renderActiveView(viewModel: AuthMenuViewModel): TemplateResult {
    if (viewModel.kind === 'link_device') return this.renderLinkDevice(viewModel);
    if (viewModel.kind === 'google_otp_login') return this.renderGoogleOtp(viewModel);
    if (viewModel.kind === 'google_registration') return this.renderGoogleRegistration(viewModel);
    return html`
      ${this.renderHeader(viewModel)} ${this.renderPasskeyInput(viewModel)}
      ${this.renderAuthMethods(viewModel)} ${this.renderOtherOptions(viewModel)}
      ${this.renderIntentSwitch(viewModel)}
    `;
  }

  private renderHeader(viewModel: AuthMenuViewModel): TemplateResult {
    return html`
      <div class="w3a-header">
        <div>
          <div class="w3a-title" id=${AUTH_MENU_TITLE_ID}>${viewModel.heading}</div>
          <div class="w3a-subhead">${viewModel.subtitle}</div>
        </div>
      </div>
    `;
  }

  private renderPasskeyInput(
    viewModel: AuthMenuLoginViewModel | AuthMenuRegisterViewModel,
  ): TemplateResult {
    if (viewModel.mode === 'login') {
      const selected = selectedLoginAccount(viewModel);
      const hasAccounts = viewModel.accountOptions.length > 0;
      return html`
        <div class="w3a-passkey-row">
          <div class="w3a-input-pill">
            <div class="w3a-input-wrap">
              <input
                id="w3a-auth-menu-login-account"
                class="w3a-input"
                data-auth-menu-input
                type="text"
                name="passkey"
                aria-label="Saved account"
                autocomplete="off"
                autocapitalize="none"
                autocorrect="off"
                spellcheck="false"
                placeholder="Enter your username"
                .value=${selected?.displayName ?? ''}
                readonly
              />
            </div>
            ${hasAccounts
              ? html`
                  <div class="w3a-account-menu ${this.accountMenuOpen ? 'is-open' : ''}">
                    <button
                      class="w3a-account-menu-trigger"
                      type="button"
                      aria-label="Saved accounts"
                      aria-haspopup="listbox"
                      aria-expanded=${this.accountMenuOpen ? 'true' : 'false'}
                      aria-controls=${AUTH_MENU_ACCOUNT_LIST_ID}
                      @click=${this.onAccountMenuToggle}
                    >
                      ${accountDropdownIcon()}
                    </button>
                    ${this.accountMenuOpen
                      ? html`
                          <div
                            id=${AUTH_MENU_ACCOUNT_LIST_ID}
                            class="w3a-account-menu-popover"
                            role="listbox"
                          >
                            <div class="w3a-account-menu-group">
                              <div class="w3a-account-menu-group-label">Passkey</div>
                              ${viewModel.accountOptions.map((account) => {
                                const isSelected = account.walletId === selected?.walletId;
                                return html`
                                  <button
                                    class="w3a-account-menu-option ${isSelected
                                      ? 'is-selected'
                                      : ''}"
                                    type="button"
                                    role="option"
                                    aria-selected=${isSelected ? 'true' : 'false'}
                                    title=${account.displayName}
                                    data-wallet-id=${account.walletId}
                                    @click=${this.onLoginAccountSelect}
                                  >
                                    <span class="w3a-account-menu-check" aria-hidden="true"></span>
                                    <span class="w3a-account-menu-account">
                                      <span class="w3a-account-menu-account-primary"
                                        >${account.displayName}</span
                                      >
                                    </span>
                                  </button>
                                `;
                              })}
                            </div>
                          </div>
                        `
                      : null}
                  </div>
                `
              : null}
          </div>
        </div>
      `;
    }

    if (!viewModel.showRegistrationInput) return html``;
    return html`
      <div class="w3a-passkey-row">
        <div class="w3a-input-pill">
          <div class="w3a-input-wrap">
            <input
              id="w3a-auth-menu-passkey-name"
              class="w3a-input"
              data-auth-menu-input
              type="text"
              autocomplete="nickname"
              placeholder=${viewModel.passkeyNameLabel}
              .value=${viewModel.passkeyName}
              ?readonly=${viewModel.passkeyNameReadOnly}
              ?disabled=${isAuthMenuLoadingStatus(viewModel.status)}
              @input=${this.onPasskeyNameInput}
            />
          </div>
          ${viewModel.passkeyNameReadOnly
            ? html`
                <button
                  class="w3a-input-action-trigger auth-menu-registration-reroll"
                  type="button"
                  title="Generate another name"
                  aria-label="Generate another name"
                  @click=${this.onRegistrationReroll}
                  ?disabled=${!isAuthMenuReady(viewModel)}
                >
                  ${rerollIcon()}
                </button>
              `
            : null}
        </div>
      </div>
    `;
  }

  private renderAuthMethods(
    viewModel: AuthMenuLoginViewModel | AuthMenuRegisterViewModel,
  ): TemplateResult {
    const googleEnabled = viewModel.enabledExternalProviders?.includes('google') ?? false;
    return html`
      <div class="w3a-auth-methods">
        <div class="w3a-auth-method-stack">
          <button
            class="w3a-auth-method-btn w3a-auth-method-btn-primary"
            type="button"
            data-auth-menu-primary
            ?disabled=${!isAuthMenuActionReady(viewModel)}
            @click=${this.onPrimaryClick}
          >
            ${viewModel.mode === 'login' ? fingerprintIcon() : null}
            <span>${passkeyButtonLabel(viewModel.mode)}</span>
            ${arrowIcon()}
          </button>
          ${googleEnabled
            ? html`
                <div class="w3a-auth-method-stack w3a-social-stack">
                  <div class="w3a-social-provider">
                    <button
                      class="w3a-auth-method-btn w3a-auth-method-btn-secondary"
                      type="button"
                      data-auth-menu-provider="google"
                      ?disabled=${!isAuthMenuActionable(viewModel)}
                      @click=${this.onGoogleClick}
                    >
                      ${googleIcon()}
                      <span>${googleButtonLabel(viewModel.mode)}</span>
                      ${arrowIcon()}
                    </button>
                  </div>
                </div>
              `
            : null}
        </div>
      </div>
    `;
  }

  private renderOtherOptions(viewModel: AuthMenuLoginViewModel | AuthMenuRegisterViewModel) {
    return html`
      <div class="w3a-scan-device-row">
        <div class="w3a-section-divider">
          <span class="w3a-section-divider-text">Other options</span>
        </div>
        <div class="w3a-secondary-actions">
          <button class="w3a-link-device-btn" type="button" @click=${this.onLinkDeviceOpen}>
            ${linkDeviceIcon()} Scan and Link Device
          </button>
        </div>
      </div>
    `;
  }

  private renderIntentSwitch(viewModel: AuthMenuLoginViewModel | AuthMenuRegisterViewModel) {
    const copy = modeSwitchCopy(viewModel.mode);
    return html`
      <div class="w3a-auth-intent-switch">
        <span>${copy.prompt}</span>
        <button
          type="button"
          data-auth-menu-mode=${copy.nextMode}
          @click=${this.onIntentSwitchClick}
        >
          ${copy.action}
        </button>
      </div>
    `;
  }

  private renderWaiting(viewModel: AuthMenuViewModel): TemplateResult {
    const status = viewModel.status;
    if (status.kind !== 'busy') return html``;
    // `headline` is required on the busy status, so there is no fallback to
    // inherit here — every wait names itself.
    const waitingText = status.headline;
    return html`
      <div class="w3a-waiting" role="status" aria-live="polite">
        <div class="w3a-waiting-message">
          <span class="w3a-waiting-text">${waitingText}</span>
          ${viewModel.showProgress && status.detail && status.detail !== waitingText
            ? html`<span class="w3a-waiting-sdk-events">${status.detail}</span>`
            : null}
        </div>
        <div aria-label="Loading" class="w3a-spinner"></div>
      </div>
    `;
  }

  private renderLinkDevice(
    viewModel: Extract<AuthMenuViewModel, { kind: 'link_device' }>,
  ): TemplateResult {
    const linkDevice = viewModel.linkDevice;
    if (linkDevice.kind === 'passkey_required' || linkDevice.kind === 'creating_passkey') {
      return this.renderLinkDevicePasskeyConfirmation(linkDevice);
    }
    if (linkDevice.kind === 'activating') return this.renderLinkedDeviceActivation(linkDevice);
    if (linkDevice.kind === 'error' || linkDevice.kind === 'activation_error') {
      return this.renderLinkDeviceFailure(linkDevice);
    }
    // The code plate keeps its box while the QR is still being generated, so the
    // title/instruction/status stack below it never shifts when the image lands —
    // the placeholder simply dissolves into the code.
    const ready = linkDevice.kind === 'ready';
    return html`
      <div class="w3a-scan-device-content">
        <div class="qr-code-container">
          <div class="qr-body">
            <div class="qr-code-section">
              <div class="qr-code-display">
                ${ready
                  ? html`
                      <img
                        src=${linkDevice.qrCodeDataURL}
                        alt="QR code to link this device"
                        class="qr-code-image"
                      />
                    `
                  : html`
                      <div class="qr-code-placeholder">
                        <span class="w3a-spinner" aria-hidden="true"></span>
                      </div>
                    `}
              </div>
              <div class="qr-header">
                <h2 class="qr-title" id=${AUTH_MENU_TITLE_ID}>${viewModel.heading}</h2>
              </div>
              <div class="qr-instruction">
                ${ready ? viewModel.subtitle : 'Preparing a one-time code for your other device.'}
              </div>
              <div class="qr-status" role="status" aria-live="polite">
                ${ready ? linkDevice.message : 'Generating QR code'}<span
                  class="animated-ellipsis"
                ></span>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  private renderLinkDeviceFailure(
    linkDevice: Extract<AuthMenuLinkDeviceState, { kind: 'error' | 'activation_error' }>,
  ): TemplateResult {
    const activationFailed = linkDevice.kind === 'activation_error';
    return html`
      <div class="w3a-link-device-confirmation w3a-link-device-failure">
        <div class="w3a-link-device-failure-icon">${linkFailedIcon()}</div>
        <h2 class="qr-title" id=${AUTH_MENU_TITLE_ID}>
          ${activationFailed ? 'Device linked' : "Couldn't link device"}
        </h2>
        <p class="w3a-link-device-failure-detail" role="alert">
          ${activationFailed
            ? html`Unable to open the wallet. Return to sign in and try again. ${linkDevice.message}`
            : linkDevice.message}
        </p>
        <button
          class="w3a-link-device-btn"
          type="button"
          data-auth-menu-primary
          data-link-device-error-dismiss
          @click=${this.onBackClick}
        >
          Return to sign in
        </button>
      </div>
    `;
  }

  private renderLinkedDeviceActivation(
    linkDevice: Extract<AuthMenuLinkDeviceState, { kind: 'activating' }>,
  ): TemplateResult {
    return html`
      <div class="w3a-link-device-confirmation">
        <span class="w3a-spinner" aria-hidden="true"></span>
        <h2 class="qr-title" id=${AUTH_MENU_TITLE_ID}>Opening linked wallet</h2>
        <p class="w3a-link-device-confirmation-copy" role="status" aria-live="polite">
          ${linkDevice.message}
        </p>
      </div>
    `;
  }

  private renderLinkDevicePasskeyConfirmation(
    linkDevice: Extract<AuthMenuLinkDeviceState, { kind: 'passkey_required' | 'creating_passkey' }>,
  ): TemplateResult {
    const creating = linkDevice.kind === 'creating_passkey';
    return html`
      <div class="w3a-link-device-confirmation">
        <div class="w3a-link-device-approved-icon">${approvedDeviceIcon()}</div>
        <h2 class="qr-title" id=${AUTH_MENU_TITLE_ID}>
          ${creating ? 'Finish on this device' : 'Device approved'}
        </h2>
        <p class="w3a-link-device-confirmation-copy" role="status" aria-live="polite">
          ${creating
            ? linkDevice.message
            : 'Use Touch ID or your device screen lock to finish linking.'}
        </p>
        <button
          class="w3a-link-device-btn w3a-link-device-btn-primary"
          type="button"
          data-auth-menu-primary
          data-link-device-passkey-action
          ?disabled=${creating}
          @click=${this.onLinkDeviceCreatePasskey}
        >
          ${creating ? html`<span class="w3a-spinner" aria-hidden="true"></span>` : null}
          ${creating ? 'Waiting for passkey' : 'Continue with passkey'}
        </button>
      </div>
    `;
  }

  private renderGoogleOtp(viewModel: Extract<AuthMenuViewModel, { kind: 'google_otp_login' }>) {
    const deliveryMessage =
      viewModel.delivery.status === 'reused'
        ? `Use the code already sent to ${viewModel.emailHint}.`
        : `A 6-digit code was sent to ${viewModel.emailHint}.`;
    const digits = viewModel.otpCode.padEnd(6, ' ').slice(0, 6).split('');
    return html`
      <div class="w3a-otp-prompt" aria-live="polite">
        <div class="w3a-otp-prompt-copy">
          <div class="w3a-otp-title" id=${AUTH_MENU_TITLE_ID}>${viewModel.heading}</div>
          <p class="w3a-otp-description">${deliveryMessage}</p>
          <div class="w3a-otp-account" title=${viewModel.walletId}>
            <span class="w3a-otp-account-label">Wallet</span>
            <span class="w3a-otp-account-value">${viewModel.walletId}</span>
          </div>
        </div>
        <label class="w3a-field-label" for="w3a-auth-menu-google-otp">Email code</label>
        <div class="w3a-otp-code-field" data-disabled=${viewModel.submitBusy ? 'true' : 'false'}>
          <input
            class="w3a-otp-input"
            id="w3a-auth-menu-google-otp"
            data-auth-menu-input
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
          <div class="w3a-otp-slots" aria-hidden="true">
            ${digits.map(
              (digit) =>
                html`<span class="w3a-otp-slot ${digit.trim() ? 'is-filled' : ''}">${digit}</span>`,
            )}
          </div>
        </div>
        <p class="w3a-otp-helper">${viewModel.prompt.helperText ?? ''}</p>
        <button
          class="w3a-auth-method-btn w3a-auth-method-btn-primary"
          type="button"
          data-auth-menu-primary
          ?disabled=${!isAuthMenuActionReady(viewModel)}
          @click=${this.onPrimaryClick}
        >
          ${viewModel.submitBusy ? 'Unlocking…' : viewModel.ctaLabel}
        </button>
        <button
          class="w3a-otp-resend auth-menu-google-resend"
          type="button"
          ?disabled=${viewModel.resendBusy || viewModel.submitBusy}
          @click=${this.onGoogleOtpResend}
        >
          ${viewModel.resendBusy ? 'Sending…' : 'Resend Code'}
        </button>
      </div>
    `;
  }

  private renderGoogleRegistration(
    viewModel: Extract<AuthMenuViewModel, { kind: 'google_registration' }>,
  ) {
    return html`
      <div class="w3a-otp-prompt" aria-live="polite">
        <div class="w3a-otp-prompt-copy">
          <div class="w3a-otp-title" id=${AUTH_MENU_TITLE_ID}>${viewModel.heading}</div>
          <p class="w3a-otp-description">${viewModel.subtitle}</p>
          <div class="w3a-otp-account" title=${viewModel.walletId}>
            <span class="w3a-otp-account-label">Wallet</span>
            <span class="w3a-otp-account-value">${viewModel.walletId}</span>
          </div>
          <button
            class="w3a-otp-reroll"
            type="button"
            ?disabled=${viewModel.rerollBusy || viewModel.submitBusy}
            @click=${this.onGoogleRegistrationReroll}
          >
            ${viewModel.rerollBusy ? 'Generating…' : 'Generate another name'}
          </button>
        </div>
        <button
          class="w3a-auth-method-btn w3a-auth-method-btn-primary"
          type="button"
          data-auth-menu-primary
          ?disabled=${!isAuthMenuActionReady(viewModel)}
          @click=${this.onPrimaryClick}
        >
          ${viewModel.submitBusy ? 'Creating...' : viewModel.ctaLabel}
        </button>
      </div>
    `;
  }
}

if (!customElements.get(AUTH_MENU_TAG)) {
  customElements.define(AUTH_MENU_TAG, SeamsAuthMenuSurfaceElement);
}

export default SeamsAuthMenuSurfaceElement;
