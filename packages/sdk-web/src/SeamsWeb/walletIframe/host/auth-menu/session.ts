import type { AppearanceConfig } from '@/core/types/seams';
import type { RegistrationResult } from '@/core/types/seams';
import {
  AUTH_MENU_INTENT_EVENT,
  type AuthMenuAccountOption,
  type AuthMenuIntent,
  type AuthMenuGoogleLoginViewModel,
  type AuthMenuGoogleRegistrationViewModel,
  type AuthMenuViewModel,
  isAuthMenuIntent,
} from '../lit-ui/auth-menu/auth-menu-domain';
import type { SeamsAuthMenuSurfaceElement } from '../lit-ui/auth-menu/seams-auth-menu-surface';
import {
  hostedAuthMenuExternalAuthRequestIdFromBoundary,
  type HostedAuthMenuExternalAuthRequest,
  type HostedAuthMenuExternalAuthResolution,
  type HostedAuthMenuExternalProvider,
  type HostedAuthMenuMode,
  type HostedAuthMenuOpenRequest,
  type HostedAuthMenuOutcome,
  type HostedAuthMenuSessionId,
} from '../../shared/messages';
import type {
  GoogleEmailOtpWalletAuthFlow,
  GoogleEmailOtpWalletAuthLoginFlow,
  GoogleEmailOtpWalletAuthRegistrationFlow,
} from '@/SeamsWeb/publicApi/types';
import type { ChildToParentEnvelope } from '../../shared/messages';
import type { WalletIframeRequestId } from '@/core/types/walletIframeIdentity';
import type { WebAuthnPromptCancellation } from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/webauthnPromptCoordinator';
import {
  cancelHostedPasskeyRegistration,
  registerPreparedHostedPasskeyRegistration,
  startHostedPasskeyRegistrationCredential,
  type HostedPasskeyRegistrationPrepared,
} from '@/SeamsWeb/operations/registration/registration';
import {
  cancelHostedPasskeyPreparation,
  completeHostedPasskeyAccountSync,
  completeHostedPasskeyLogin,
  startHostedPasskeyAccountSyncCredential,
  startHostedPasskeyLoginCredential,
  type HostedPasskeyPrepared,
} from './passkey';
import { parseWalletId } from '@shared/utils/domainIds';
import { createReadableWalletId } from '@shared/utils/registrationIntent';

type HostedPasskeyMenuPrepared = HostedPasskeyRegistrationPrepared | HostedPasskeyPrepared;

function cancelHostedPasskeyMenuPreparation(prepared: HostedPasskeyMenuPrepared): void {
  if (prepared.kind === 'hosted_passkey_registration_prepared_v1') {
    cancelHostedPasskeyRegistration(prepared);
    return;
  }
  cancelHostedPasskeyPreparation(prepared);
}

export type AuthMenuSessionIdentity = {
  readonly authMenuSessionId: HostedAuthMenuSessionId;
  readonly requestId: WalletIframeRequestId;
};

export type AuthMenuSessionState =
  | {
      readonly kind: 'preparing';
      readonly viewModel: AuthMenuViewModel;
    }
  | {
      readonly kind: 'awaiting_external_auth';
      readonly viewModel: AuthMenuViewModel;
      readonly request: HostedAuthMenuExternalAuthRequest;
    }
  | {
      readonly kind: 'ready';
      readonly viewModel: AuthMenuViewModel;
      readonly prepared: HostedPasskeyMenuPrepared;
    }
  | {
      readonly kind: 'performing';
      readonly viewModel: AuthMenuViewModel;
      readonly prepared: HostedPasskeyMenuPrepared;
    }
  | {
      readonly kind: 'google_login';
      readonly viewModel: AuthMenuGoogleLoginViewModel;
      readonly flow: GoogleEmailOtpWalletAuthLoginFlow;
    }
  | {
      readonly kind: 'google_registration';
      readonly viewModel: AuthMenuGoogleRegistrationViewModel;
      readonly flow: GoogleEmailOtpWalletAuthRegistrationFlow;
    }
  | {
      readonly kind: 'complete';
      readonly outcome: HostedAuthMenuOutcome;
    };

export type AuthMenuSessionMount = {
  readonly appearance: AppearanceConfig;
  readonly hostname: string;
  readonly send: (message: ChildToParentEnvelope) => void;
};

type OutcomeResolver = (outcome: HostedAuthMenuOutcome) => void;
type PreparePasskey = (
  cancellation: Extract<WebAuthnPromptCancellation, { kind: 'abort_signal' }>,
) => Promise<HostedPasskeyMenuPrepared>;
type PrepareRegistration = (
  registrationValue: string,
  cancellation: Extract<WebAuthnPromptCancellation, { kind: 'abort_signal' }>,
) => Promise<HostedPasskeyMenuPrepared>;
type BeginGoogleEmailOtp = (args: {
  readonly idToken: string;
  readonly mode: HostedAuthMenuOpenRequest['initialMode'];
  readonly signal: AbortSignal;
}) => Promise<GoogleEmailOtpWalletAuthFlow>;
type PrepareLoginPasskey = (
  walletId: string | null,
  cancellation: Extract<WebAuthnPromptCancellation, { kind: 'abort_signal' }>,
) => Promise<HostedPasskeyMenuPrepared>;

const AUTH_MENU_TAG = 'seams-auth-menu-surface';

function createPreparingViewModel(args: {
  request: HostedAuthMenuOpenRequest;
  appearance: AppearanceConfig;
  hostname: string;
  mode?: HostedAuthMenuMode;
}): AuthMenuViewModel {
  const mode = args.mode ?? args.request.initialMode;
  const modeCopy = args.request.copy[mode];
  const common = {
    kind: 'passkey' as const,
    appearance: args.appearance,
    hostname: args.hostname,
    closeLabel: args.request.copy.common.closeLabel,
    heading: modeCopy.title,
    subtitle: modeCopy.subtitle,
    ctaLabel: modeCopy.passkeyCta,
    showProgress: args.request.showProgress,
    enabledExternalProviders: args.request.enabledExternalProviders,
    status: {
      kind: 'preparing' as const,
      message: 'Preparing passkey',
    },
  };
  return mode === 'register'
    ? {
        ...common,
        mode,
        showRegistrationInput:
          args.request.showRegistrationInput ||
          args.request.registrationAccountInput === 'sponsored_named_near_account',
        passkeyNameReadOnly: args.request.registrationAccountInput === 'implicit_wallet',
        passkeyName:
          args.request.registrationAccountInput === 'implicit_wallet'
            ? String(createReadableWalletId())
            : '',
        passkeyNameLabel: args.request.copy.register.passkeyNameLabel,
      }
    : { ...common, mode, accountOptions: [], selectedWalletId: null };
}

function normalizeHostname(value: string): string {
  const trimmed = value.trim();
  return trimmed || 'Wallet';
}

function closeReasonForIntent(_intent: Extract<AuthMenuIntent, { kind: 'close' }>): 'close_button' {
  return 'close_button';
}

function randomExternalAuthRequestId(): string {
  try {
    const uuid = globalThis.crypto?.randomUUID?.();
    if (uuid) return `auth-menu-external-${uuid}`;
  } catch {}
  return `auth-menu-external-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function googleViewModelBase(args: {
  base: AuthMenuViewModel;
  flow: GoogleEmailOtpWalletAuthFlow;
  status: AuthMenuViewModel['status'];
}): Pick<
  AuthMenuViewModel,
  'appearance' | 'hostname' | 'closeLabel' | 'showProgress' | 'enabledExternalProviders' | 'status'
> & {
  heading: string;
  subtitle: string;
  ctaLabel: string;
} {
  return {
    appearance: args.base.appearance,
    hostname: args.base.hostname,
    closeLabel: args.base.closeLabel,
    heading: args.flow.prompt.title,
    subtitle: args.flow.prompt.description,
    ctaLabel: args.flow.prompt.submitLabel,
    showProgress: args.base.showProgress,
    enabledExternalProviders: args.base.enabledExternalProviders,
    status: args.status,
  };
}

function googleLoginViewModel(args: {
  base: AuthMenuViewModel;
  flow: GoogleEmailOtpWalletAuthLoginFlow;
  otpCode?: string;
  resendBusy?: boolean;
  submitBusy?: boolean;
  error?: string;
  status?: AuthMenuViewModel['status'];
}): AuthMenuGoogleLoginViewModel {
  return {
    ...googleViewModelBase({
      base: args.base,
      flow: args.flow,
      status: args.status ?? { kind: 'ready' },
    }),
    kind: 'google_otp_login',
    mode: 'login',
    emailHint: args.flow.emailHint,
    walletId: String(args.flow.walletId),
    prompt: args.flow.prompt,
    delivery: args.flow.delivery,
    otpCode: args.otpCode ?? '',
    resendBusy: args.resendBusy ?? false,
    submitBusy: args.submitBusy ?? false,
    ...(args.error ? { error: args.error } : {}),
  };
}

function googleRegistrationViewModel(args: {
  base: AuthMenuViewModel;
  flow: GoogleEmailOtpWalletAuthRegistrationFlow;
  rerollBusy?: boolean;
  submitBusy?: boolean;
  error?: string;
  status?: AuthMenuViewModel['status'];
}): AuthMenuGoogleRegistrationViewModel {
  return {
    ...googleViewModelBase({
      base: args.base,
      flow: args.flow,
      status: args.status ?? { kind: 'ready' },
    }),
    kind: 'google_registration',
    mode: 'register',
    emailHint: args.flow.emailHint,
    walletId: String(args.flow.walletId),
    prompt: args.flow.prompt,
    rerollBusy: args.rerollBusy ?? false,
    submitBusy: args.submitBusy ?? false,
    ...(args.error ? { error: args.error } : {}),
  };
}

function errorMessage(error: unknown): string {
  return error instanceof Error && error.message.trim() ? error.message.trim() : String(error);
}

export class AuthMenuSession {
  readonly identity: AuthMenuSessionIdentity;
  readonly request: HostedAuthMenuOpenRequest;

  private stateValue: AuthMenuSessionState;
  private element: SeamsAuthMenuSurfaceElement | null = null;
  private outcomeResolver: OutcomeResolver | null = null;
  private outcomePromise: Promise<HostedAuthMenuOutcome> | null = null;
  private cleanedUp = false;
  private externalAuthResolution: HostedAuthMenuExternalAuthResolution | null = null;
  private prepared: HostedPasskeyMenuPrepared | null = null;
  private preparePasskey: PreparePasskey | null = null;
  private registrationPreparation: PrepareRegistration | null = null;
  private registrationCancellation: AbortController | null = null;
  private googleCancellation: AbortController | null = null;
  private beginGoogleEmailOtp: BeginGoogleEmailOtp;
  private loginPreparation: PrepareLoginPasskey | null = null;
  private loginAccountOptions: readonly AuthMenuAccountOption[] = [];
  private selectedLoginWalletId: string | null = null;
  private sendToParent: ((message: ChildToParentEnvelope) => void) | null = null;
  private preparationGeneration = 0;
  private googleGeneration = 0;
  private preparationExpiryTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(args: {
    request: HostedAuthMenuOpenRequest;
    requestId: WalletIframeRequestId;
    appearance: AppearanceConfig;
    hostname: string;
    beginGoogleEmailOtp: BeginGoogleEmailOtp;
  }) {
    this.identity = {
      authMenuSessionId: args.request.authMenuSessionId,
      requestId: args.requestId,
    };
    this.request = args.request;
    this.beginGoogleEmailOtp = args.beginGoogleEmailOtp;
    this.stateValue = {
      kind: 'preparing',
      viewModel: createPreparingViewModel({
        request: args.request,
        appearance: args.appearance,
        hostname: normalizeHostname(args.hostname),
      }),
    };
  }

  get state(): AuthMenuSessionState {
    return this.stateValue;
  }

  get externalResolution(): HostedAuthMenuExternalAuthResolution | null {
    return this.externalAuthResolution;
  }

  setRegistrationPreparation(prepare: PrepareRegistration): void {
    this.registrationPreparation = prepare;
    if (this.stateValue.kind !== 'complete' && this.currentViewModel().mode === 'register') {
      this.preparePasskey = null;
      this.startPasskeyPreparation();
    }
  }

  setPasskeyPreparation(prepare: PreparePasskey): void {
    this.preparePasskey = prepare;
    this.startPasskeyPreparation();
  }

  setLoginPreparation(args: {
    prepare: PrepareLoginPasskey;
    accountOptions: readonly AuthMenuAccountOption[];
    selectedWalletId: string | null;
  }): void {
    const activeViewModel = this.stateValue.kind === 'complete' ? null : this.currentViewModel();
    if (
      activeViewModel?.kind === 'passkey' &&
      activeViewModel.mode === 'login' &&
      (this.stateValue.kind === 'preparing' || this.stateValue.kind === 'ready')
    ) {
      this.invalidatePreparation();
    }
    this.loginPreparation = args.prepare;
    this.loginAccountOptions = args.accountOptions;
    this.selectedLoginWalletId = args.selectedWalletId;
    this.updateLoginSelectionViewModel();
    if (
      (this.stateValue.kind === 'preparing' || this.stateValue.kind === 'ready') &&
      this.currentViewModel().mode === 'login'
    ) {
      this.setPasskeyPreparation(this.prepareSelectedLogin);
    }
  }

  private prepareSelectedLogin = (
    cancellation: Extract<WebAuthnPromptCancellation, { kind: 'abort_signal' }>,
  ): Promise<HostedPasskeyMenuPrepared> => {
    if (!this.loginPreparation) throw new Error('Hosted login preparation is unavailable');
    return this.loginPreparation(this.selectedLoginWalletId, cancellation);
  };

  private updateLoginSelectionViewModel(): void {
    const state = this.stateValue;
    if (
      (state.kind !== 'preparing' && state.kind !== 'ready') ||
      state.viewModel.kind !== 'passkey' ||
      state.viewModel.mode !== 'login'
    ) {
      return;
    }
    this.stateValue = {
      ...state,
      viewModel: {
        ...state.viewModel,
        accountOptions: this.loginAccountOptions,
        selectedWalletId: this.selectedLoginWalletId,
      },
    };
  }

  mount(args: AuthMenuSessionMount): void {
    if (this.element || this.cleanedUp) {
      throw new Error('Hosted auth-menu session is already mounted');
    }
    const existing = document.querySelectorAll(AUTH_MENU_TAG);
    if (existing.length > 0) {
      throw new Error('A hosted auth-menu surface is already mounted');
    }
    const element = document.createElement(AUTH_MENU_TAG) as SeamsAuthMenuSurfaceElement;
    this.sendToParent = args.send;
    element.viewModel = this.currentViewModel();
    element.addEventListener(AUTH_MENU_INTENT_EVENT, this.onIntent);
    const root = document.body || document.documentElement;
    if (!root) throw new Error('Wallet host document has no mount root');
    root.appendChild(element);
    this.element = element;
  }

  waitForOutcome(): Promise<HostedAuthMenuOutcome> {
    if (this.stateValue.kind === 'complete') return Promise.resolve(this.stateValue.outcome);
    if (!this.outcomePromise) {
      this.outcomePromise = new Promise<HostedAuthMenuOutcome>((resolve) => {
        this.outcomeResolver = resolve;
      });
    }
    return this.outcomePromise;
  }

  cancel(reason: 'close_button' | 'component_unmounted' | 'connection_closed'): void {
    this.invalidatePreparation();
    this.complete({
      kind: 'cancelled',
      authMenuSessionId: this.identity.authMenuSessionId,
      reason,
    });
  }

  private startPasskeyPreparation(): void {
    if (this.stateValue.kind === 'complete') return;
    const viewModel = this.currentViewModel();
    const registrationPreparation =
      viewModel.kind === 'passkey' && viewModel.mode === 'register'
        ? this.registrationPreparation
        : null;
    const prepare =
      viewModel.kind === 'passkey' && viewModel.mode === 'login' ? this.preparePasskey : null;
    if (!prepare && !registrationPreparation) return;

    if (
      registrationPreparation &&
      viewModel.kind === 'passkey' &&
      viewModel.mode === 'register' &&
      viewModel.showRegistrationInput &&
      viewModel.passkeyName.trim().length === 0
    ) {
      this.invalidatePreparation();
      this.stateValue = {
        kind: 'preparing',
        viewModel: {
          ...viewModel,
          status: { kind: 'input_required' },
        },
      };
      this.updateElement();
      return;
    }

    this.clearPreparationExpiryTimer();
    const generation = ++this.preparationGeneration;
    const cancellationController = new AbortController();
    this.registrationCancellation = cancellationController;
    const cancellation = {
      kind: 'abort_signal' as const,
      signal: cancellationController.signal,
    };
    this.stateValue = {
      kind: 'preparing',
      viewModel: {
        ...viewModel,
        status: { kind: 'preparing', message: 'Preparing passkey' },
      },
    };
    this.updateElement();
    const preparation = Promise.resolve().then(() =>
      registrationPreparation
        ? registrationPreparation(this.registrationValue(), cancellation)
        : prepare!(cancellation),
    );
    void preparation.then(
      (prepared) => {
        if (generation !== this.preparationGeneration || this.stateValue.kind === 'complete') {
          cancelHostedPasskeyMenuPreparation(prepared);
          return;
        }
        this.prepared = prepared;
        this.stateValue = {
          kind: 'ready',
          prepared,
          viewModel: {
            ...this.currentViewModel(),
            status: { kind: 'ready' },
          },
        };
        this.schedulePreparationExpiry(prepared);
        this.updateElement();
      },
      (error: unknown) => {
        if (generation !== this.preparationGeneration || this.stateValue.kind === 'complete')
          return;
        this.stateValue = {
          kind: 'preparing',
          viewModel: {
            ...this.currentViewModel(),
            status: {
              kind: 'error',
              message: error instanceof Error ? error.message : String(error),
            },
          },
        };
        this.updateElement();
      },
    );
  }

  private invalidatePreparation(): void {
    this.clearPreparationExpiryTimer();
    this.preparationGeneration += 1;
    this.registrationCancellation?.abort();
    this.registrationCancellation = null;
    this.googleGeneration += 1;
    this.googleCancellation?.abort();
    this.googleCancellation = null;
    const prepared = this.prepared;
    this.prepared = null;
    if (prepared) cancelHostedPasskeyMenuPreparation(prepared);
    if (this.stateValue.kind === 'performing') {
      cancelHostedPasskeyMenuPreparation(this.stateValue.prepared);
    }
    if (this.stateValue.kind === 'google_login' || this.stateValue.kind === 'google_registration') {
      void this.stateValue.flow.cancel().catch(() => {});
    }
  }

  private registrationValue(): string {
    const state = this.stateValue;
    if (
      (state.kind === 'preparing' || state.kind === 'ready') &&
      state.viewModel.kind === 'passkey' &&
      state.viewModel.mode === 'register'
    ) {
      return state.viewModel.passkeyName;
    }
    return '';
  }

  private clearPreparationExpiryTimer(): void {
    if (this.preparationExpiryTimer === null) return;
    clearTimeout(this.preparationExpiryTimer);
    this.preparationExpiryTimer = null;
  }

  private schedulePreparationExpiry(prepared: HostedPasskeyMenuPrepared): void {
    this.clearPreparationExpiryTimer();
    const delayMs = Math.max(0, prepared.expiresAtMs - Date.now());
    this.preparationExpiryTimer = setTimeout(() => {
      this.preparationExpiryTimer = null;
      if (
        this.stateValue.kind !== 'ready' ||
        this.stateValue.prepared !== prepared ||
        this.prepared !== prepared
      ) {
        return;
      }
      cancelHostedPasskeyMenuPreparation(prepared);
      this.prepared = null;
      this.stateValue = {
        kind: 'preparing',
        viewModel: {
          ...this.stateValue.viewModel,
          status: { kind: 'expired', message: 'Passkey preparation expired. Retry to continue.' },
        },
      };
      this.updateElement();
    }, delayMs);
  }

  private startGoogleFlow(idToken: string, mode: HostedAuthMenuOpenRequest['initialMode']): void {
    this.invalidatePreparation();
    const generation = ++this.googleGeneration;
    const cancellation = new AbortController();
    this.googleCancellation = cancellation;
    const baseViewModel = this.currentViewModel();
    this.stateValue = {
      kind: 'preparing',
      viewModel: {
        ...baseViewModel,
        status: { kind: 'preparing', message: 'Starting Google sign-in' },
      },
    };
    this.updateElement();
    void this.beginGoogleEmailOtp({ idToken, mode, signal: cancellation.signal }).then(
      (flow) => {
        if (
          generation !== this.googleGeneration ||
          cancellation.signal.aborted ||
          this.stateValue.kind === 'complete'
        ) {
          void flow.cancel().catch(() => {});
          return;
        }
        this.googleCancellation = null;
        if (flow.mode === 'login') {
          this.stateValue = {
            kind: 'google_login',
            flow,
            viewModel: googleLoginViewModel({ base: baseViewModel, flow }),
          };
        } else {
          this.stateValue = {
            kind: 'google_registration',
            flow,
            viewModel: googleRegistrationViewModel({ base: baseViewModel, flow }),
          };
        }
        this.updateElement();
      },
      (error: unknown) => {
        if (
          generation !== this.googleGeneration ||
          cancellation.signal.aborted ||
          this.stateValue.kind === 'complete'
        ) {
          return;
        }
        this.googleCancellation = null;
        this.stateValue = {
          kind: 'preparing',
          viewModel: {
            ...baseViewModel,
            status: { kind: 'error', message: errorMessage(error) },
          },
        };
        this.updateElement();
        this.startPasskeyPreparation();
      },
    );
  }

  requestExternalAuth(
    provider: HostedAuthMenuExternalAuthRequest['provider'],
    send: AuthMenuSessionMount['send'],
  ): HostedAuthMenuExternalAuthRequest | null {
    if (this.stateValue.kind === 'complete') return null;
    if (!this.request.enabledExternalProviders.includes(provider)) return null;
    if (this.stateValue.kind === 'awaiting_external_auth') return null;
    this.invalidatePreparation();
    const externalAuthRequestId = hostedAuthMenuExternalAuthRequestIdFromBoundary(
      randomExternalAuthRequestId(),
    );
    if (!externalAuthRequestId) return null;
    const request: HostedAuthMenuExternalAuthRequest = {
      kind: 'hosted_auth_menu_external_auth_request_v1',
      authMenuSessionId: this.identity.authMenuSessionId,
      externalAuthRequestId,
      provider,
      mode: this.currentViewModel().mode,
    };
    this.stateValue = {
      kind: 'awaiting_external_auth',
      viewModel: {
        ...this.currentViewModel(),
        status: { kind: 'preparing', message: 'Waiting for Google sign-in' },
      },
      request,
    };
    this.updateElement();
    send({
      type: 'AUTH_MENU_EXTERNAL_AUTH_REQUEST',
      requestId: this.identity.requestId,
      payload: request,
    });
    return request;
  }

  acceptExternalAuthResolution(resolution: HostedAuthMenuExternalAuthResolution): boolean {
    const state = this.stateValue;
    if (
      state.kind !== 'awaiting_external_auth' ||
      state.request.authMenuSessionId !== resolution.authMenuSessionId ||
      state.request.externalAuthRequestId !== resolution.externalAuthRequestId ||
      this.identity.requestId !== resolution.requestId
    ) {
      return false;
    }
    this.externalAuthResolution = resolution;
    switch (resolution.evidence.kind) {
      case 'google_id_token':
        this.startGoogleFlow(resolution.evidence.idToken, state.request.mode);
        return true;
      case 'cancelled':
      case 'failed': {
        const message =
          resolution.evidence.kind === 'cancelled'
            ? 'Google sign-in was cancelled'
            : resolution.evidence.message;
        this.stateValue = {
          kind: 'preparing',
          viewModel: {
            ...state.viewModel,
            status: { kind: 'error', message },
          },
        };
        this.updateElement();
        this.startPasskeyPreparation();
        return true;
      }
      default:
        return assertNeverHostedExternalAuthEvidence(resolution.evidence);
    }
  }

  cleanup(): void {
    if (this.cleanedUp) return;
    this.cleanedUp = true;
    this.invalidatePreparation();
    const element = this.element;
    this.element = null;
    if (!element) return;
    element.removeEventListener(AUTH_MENU_INTENT_EVENT, this.onIntent);
    element.remove();
  }

  private currentViewModel(): AuthMenuViewModel {
    switch (this.stateValue.kind) {
      case 'preparing':
      case 'awaiting_external_auth':
      case 'ready':
      case 'performing':
        return this.stateValue.viewModel;
      case 'google_login':
      case 'google_registration':
        return this.stateValue.viewModel;
      case 'complete':
        throw new Error('Completed auth-menu session has no view model');
    }
  }

  private updateElement(): void {
    if (this.element) this.element.viewModel = this.currentViewModel();
  }

  private onIntent = (event: Event): void => {
    if (!(event instanceof CustomEvent)) return;
    if (!isAuthMenuIntent(event.detail)) return;
    const intent: AuthMenuIntent = event.detail;
    switch (intent.kind) {
      case 'mode_selected':
        this.selectMode(intent.mode);
        return;
      case 'registration_reroll':
        this.rerollRegistrationWallet();
        return;
      case 'close':
        this.cancel(closeReasonForIntent(intent));
        return;
      case 'passkey_name_changed':
        const passkeyViewModel =
          this.stateValue.kind === 'preparing' || this.stateValue.kind === 'ready'
            ? this.stateValue.viewModel
            : null;
        if (
          passkeyViewModel?.kind === 'passkey' &&
          passkeyViewModel.mode === 'register' &&
          !passkeyViewModel.passkeyNameReadOnly
        ) {
          this.invalidatePreparation();
          this.stateValue = {
            kind: 'preparing',
            viewModel: {
              ...passkeyViewModel,
              passkeyName: intent.passkeyName,
              status: { kind: 'preparing', message: 'Preparing passkey' },
            },
          };
          this.updateElement();
          this.startPasskeyPreparation();
        }
        return;
      case 'login_account_selected':
        this.selectLoginAccount(intent.walletId);
        return;
      case 'submit':
        if (this.stateValue.kind === 'ready' && this.prepared === this.stateValue.prepared) {
          if (
            (intent.mode === 'register' &&
              this.stateValue.prepared.kind === 'hosted_passkey_registration_prepared_v1') ||
            (intent.mode === 'login' &&
              (this.stateValue.prepared.kind === 'hosted_passkey_login_prepared_v1' ||
                this.stateValue.prepared.kind === 'hosted_passkey_account_sync_prepared_v1'))
          ) {
            this.performPreparedPasskey(this.stateValue.prepared);
          }
        }
        return;
      case 'external_auth':
        this.requestExternalAuth(intent.provider, this.sendToParent ?? (() => {}));
        return;
      case 'google_otp_code_changed':
        this.updateGoogleOtpCode(intent.code);
        return;
      case 'google_otp_resend':
        this.resendGoogleOtp();
        return;
      case 'google_otp_submit':
        this.submitGoogleOtp();
        return;
      case 'google_registration_reroll':
        this.rerollGoogleRegistration();
        return;
      case 'google_registration_complete':
        this.completeGoogleRegistration();
        return;
      case 'retry':
        this.retryPreparation();
        return;
      default:
        return assertNeverAuthMenuIntent(intent);
    }
  };

  private selectMode(mode: HostedAuthMenuMode): void {
    const state = this.stateValue;
    if (state.kind === 'complete' || state.kind === 'performing') return;
    const currentViewModel = this.currentViewModel();
    if (currentViewModel.mode === mode) return;
    this.invalidatePreparation();
    this.externalAuthResolution = null;
    const nextViewModel = createPreparingViewModel({
      request: { ...this.request, initialMode: mode },
      appearance: currentViewModel.appearance,
      hostname: currentViewModel.hostname,
      mode,
    });
    this.stateValue = {
      kind: 'preparing',
      viewModel:
        nextViewModel.kind === 'passkey' && nextViewModel.mode === 'login'
          ? {
              ...nextViewModel,
              accountOptions: this.loginAccountOptions,
              selectedWalletId: this.selectedLoginWalletId,
            }
          : nextViewModel,
    };
    this.preparePasskey = mode === 'login' ? this.prepareSelectedLogin : null;
    this.updateElement();
    this.startPasskeyPreparation();
  }

  private rerollRegistrationWallet(): void {
    const state = this.stateValue;
    if (state.kind !== 'ready' && state.kind !== 'preparing') {
      return;
    }
    if (
      state.viewModel.kind !== 'passkey' ||
      state.viewModel.mode !== 'register' ||
      !state.viewModel.passkeyNameReadOnly ||
      !state.viewModel.showRegistrationInput
    ) {
      return;
    }
    this.invalidatePreparation();
    this.stateValue = {
      kind: 'preparing',
      viewModel: {
        ...state.viewModel,
        passkeyName: String(createReadableWalletId()),
        status: { kind: 'preparing', message: 'Preparing passkey' },
      },
    };
    this.updateElement();
    this.startPasskeyPreparation();
  }

  private selectLoginAccount(walletId: string): void {
    const selected = this.loginAccountOptions.find((account) => account.walletId === walletId);
    if (!selected || selected.walletId === this.selectedLoginWalletId) return;
    const state = this.stateValue;
    if (
      (state.kind !== 'preparing' && state.kind !== 'ready') ||
      state.viewModel.kind !== 'passkey' ||
      state.viewModel.mode !== 'login'
    ) {
      return;
    }
    this.selectedLoginWalletId = selected.walletId;
    this.invalidatePreparation();
    this.stateValue = {
      kind: 'preparing',
      viewModel: {
        ...state.viewModel,
        selectedWalletId: selected.walletId,
        status: { kind: 'preparing', message: 'Preparing passkey' },
      },
    };
    this.updateElement();
    this.startPasskeyPreparation();
  }

  private retryPreparation(): void {
    const state = this.stateValue;
    if (
      state.kind !== 'preparing' ||
      (state.viewModel.status.kind !== 'expired' && state.viewModel.status.kind !== 'error')
    ) {
      return;
    }
    this.invalidatePreparation();
    this.stateValue = {
      kind: 'preparing',
      viewModel: {
        ...state.viewModel,
        status: { kind: 'preparing', message: 'Preparing passkey' },
      },
    };
    this.updateElement();
    this.startPasskeyPreparation();
  }

  private updateGoogleOtpCode(value: string): void {
    const state = this.stateValue;
    if (state.kind !== 'google_login' || state.viewModel.submitBusy) return;
    const otpCode = value.replace(/\D/g, '').slice(0, 6);
    this.stateValue = {
      ...state,
      viewModel: { ...state.viewModel, otpCode, error: '' },
    };
    this.updateElement();
  }

  private resendGoogleOtp(): void {
    const state = this.stateValue;
    if (state.kind !== 'google_login' || state.viewModel.resendBusy) return;
    const flow = state.flow;
    this.stateValue = {
      ...state,
      viewModel: {
        ...state.viewModel,
        status: { kind: 'performing', message: 'Sending a new email code' },
        resendBusy: true,
        error: '',
      },
    };
    this.updateElement();
    void flow.resend().then(
      (result) => {
        if (this.stateValue.kind !== 'google_login' || this.stateValue.flow !== flow) {
          if (result.ok) void result.value.cancel().catch(() => {});
          return;
        }
        if (!result.ok) {
          this.stateValue = {
            ...this.stateValue,
            viewModel: {
              ...this.stateValue.viewModel,
              status: { kind: 'ready' },
              resendBusy: false,
              error: result.error.message,
            },
          };
          this.updateElement();
          return;
        }
        if (result.value.mode !== 'login') {
          void result.value.cancel().catch(() => {});
          this.stateValue = {
            ...this.stateValue,
            viewModel: {
              ...this.stateValue.viewModel,
              status: { kind: 'ready' },
              resendBusy: false,
              error: 'Google returned an unexpected registration flow.',
            },
          };
          this.updateElement();
          return;
        }
        const nextFlow = result.value;
        this.stateValue = {
          kind: 'google_login',
          flow: nextFlow,
          viewModel: googleLoginViewModel({ base: state.viewModel, flow: nextFlow }),
        };
        this.updateElement();
      },
      (error: unknown) => {
        if (this.stateValue.kind !== 'google_login' || this.stateValue.flow !== flow) return;
        this.stateValue = {
          ...this.stateValue,
          viewModel: {
            ...this.stateValue.viewModel,
            status: { kind: 'ready' },
            resendBusy: false,
            error: errorMessage(error),
          },
        };
        this.updateElement();
      },
    );
  }

  private submitGoogleOtp(): void {
    const state = this.stateValue;
    if (state.kind !== 'google_login' || state.viewModel.submitBusy) return;
    const otpCode = state.viewModel.otpCode;
    if (!/^\d{6}$/.test(otpCode)) {
      this.stateValue = {
        ...state,
        viewModel: {
          ...state.viewModel,
          status: { kind: 'ready' },
          error: 'Enter the 6-digit code from your email.',
        },
      };
      this.updateElement();
      return;
    }
    const flow = state.flow;
    this.stateValue = {
      ...state,
      viewModel: {
        ...state.viewModel,
        status: { kind: 'performing', message: 'Verifying your email code' },
        submitBusy: true,
        error: '',
      },
    };
    this.updateElement();
    void flow.submit({ otpCode }).then(
      (result) => {
        if (this.stateValue.kind !== 'google_login' || this.stateValue.flow !== flow) return;
        if (!result.ok) {
          this.stateValue = {
            ...this.stateValue,
            viewModel: {
              ...this.stateValue.viewModel,
              status: { kind: 'ready' },
              submitBusy: false,
              error: result.error.message,
            },
          };
          this.updateElement();
          return;
        }
        if (result.value.mode !== 'login') {
          this.stateValue = {
            ...this.stateValue,
            viewModel: {
              ...this.stateValue.viewModel,
              status: { kind: 'ready' },
              submitBusy: false,
              error: 'Google returned an unexpected registration result.',
            },
          };
          this.updateElement();
          return;
        }
        this.complete({
          kind: 'authenticated',
          authMenuSessionId: this.identity.authMenuSessionId,
          walletId: result.value.walletId,
          method: 'google_email_otp',
        });
      },
      (error: unknown) => {
        if (this.stateValue.kind !== 'google_login' || this.stateValue.flow !== flow) return;
        this.stateValue = {
          ...this.stateValue,
          viewModel: {
            ...this.stateValue.viewModel,
            status: { kind: 'ready' },
            submitBusy: false,
            error: errorMessage(error),
          },
        };
        this.updateElement();
      },
    );
  }

  private rerollGoogleRegistration(): void {
    const state = this.stateValue;
    if (state.kind !== 'google_registration' || state.viewModel.rerollBusy) return;
    const flow = state.flow;
    this.stateValue = {
      ...state,
      viewModel: {
        ...state.viewModel,
        status: { kind: 'performing', message: 'Generating another wallet name' },
        rerollBusy: true,
        error: '',
      },
    };
    this.updateElement();
    void flow.rerollWalletId().then(
      (result) => {
        if (this.stateValue.kind !== 'google_registration' || this.stateValue.flow !== flow) {
          if (result.ok) void result.value.cancel().catch(() => {});
          return;
        }
        if (!result.ok) {
          this.stateValue = {
            ...this.stateValue,
            viewModel: {
              ...this.stateValue.viewModel,
              status: { kind: 'ready' },
              rerollBusy: false,
              error: result.error.message,
            },
          };
          this.updateElement();
          return;
        }
        if (result.value.mode !== 'register') {
          void result.value.cancel().catch(() => {});
          this.stateValue = {
            ...this.stateValue,
            viewModel: {
              ...this.stateValue.viewModel,
              status: { kind: 'ready' },
              rerollBusy: false,
              error: 'Google returned an unexpected login flow.',
            },
          };
          this.updateElement();
          return;
        }
        const nextFlow = result.value;
        this.stateValue = {
          kind: 'google_registration',
          flow: nextFlow,
          viewModel: googleRegistrationViewModel({ base: state.viewModel, flow: nextFlow }),
        };
        this.updateElement();
      },
      (error: unknown) => {
        if (this.stateValue.kind !== 'google_registration' || this.stateValue.flow !== flow) {
          return;
        }
        this.stateValue = {
          ...this.stateValue,
          viewModel: {
            ...this.stateValue.viewModel,
            status: { kind: 'ready' },
            rerollBusy: false,
            error: errorMessage(error),
          },
        };
        this.updateElement();
      },
    );
  }

  private completeGoogleRegistration(): void {
    const state = this.stateValue;
    if (state.kind !== 'google_registration' || state.viewModel.submitBusy) return;
    const flow = state.flow;
    this.stateValue = {
      ...state,
      viewModel: {
        ...state.viewModel,
        status: { kind: 'performing', message: 'Creating your wallet' },
        submitBusy: true,
        error: '',
      },
    };
    this.updateElement();
    void flow.completeRegistration().then(
      (result) => {
        if (this.stateValue.kind !== 'google_registration' || this.stateValue.flow !== flow) {
          return;
        }
        if (!result.ok) {
          this.stateValue = {
            ...this.stateValue,
            viewModel: {
              ...this.stateValue.viewModel,
              status: { kind: 'ready' },
              submitBusy: false,
              error: result.error.message,
            },
          };
          this.updateElement();
          return;
        }
        this.complete({
          kind: 'registered',
          authMenuSessionId: this.identity.authMenuSessionId,
          walletId: result.value.walletId,
          method: 'google_email_otp',
        });
      },
      (error: unknown) => {
        if (this.stateValue.kind !== 'google_registration' || this.stateValue.flow !== flow) {
          return;
        }
        this.stateValue = {
          ...this.stateValue,
          viewModel: {
            ...this.stateValue.viewModel,
            status: { kind: 'ready' },
            submitBusy: false,
            error: errorMessage(error),
          },
        };
        this.updateElement();
      },
    );
  }

  private complete(outcome: HostedAuthMenuOutcome): void {
    if (this.stateValue.kind === 'complete') return;
    this.stateValue = { kind: 'complete', outcome };
    this.cleanup();
    const resolver = this.outcomeResolver;
    this.outcomeResolver = null;
    resolver?.(outcome);
  }

  private performPreparedPasskey(prepared: HostedPasskeyMenuPrepared): void {
    this.prepared = null;
    this.stateValue = {
      kind: 'performing',
      prepared,
      viewModel: {
        ...this.currentViewModel(),
        status: { kind: 'performing', message: 'Continue with your passkey' },
      },
    };
    this.updateElement();
    let authority: Promise<unknown>;
    try {
      // Each adapter starts WebAuthn synchronously while this click still owns
      // the wallet-origin activation. Continuations run only after the promise.
      authority = this.startPreparedCredential(prepared);
    } catch (error: unknown) {
      this.fail(error);
      return;
    }
    void authority.then(
      () => this.finishPreparedPasskey(prepared),
      (error: unknown) => this.fail(error),
    );
  }

  private startPreparedCredential(prepared: HostedPasskeyMenuPrepared): Promise<unknown> {
    if (prepared.kind === 'hosted_passkey_registration_prepared_v1') {
      return startHostedPasskeyRegistrationCredential(prepared);
    }
    if (prepared.kind === 'hosted_passkey_login_prepared_v1') {
      return startHostedPasskeyLoginCredential(prepared);
    }
    return startHostedPasskeyAccountSyncCredential(prepared);
  }

  private async finishPreparedPasskey(prepared: HostedPasskeyMenuPrepared): Promise<void> {
    try {
      switch (prepared.kind) {
        case 'hosted_passkey_registration_prepared_v1': {
          const result = await registerPreparedHostedPasskeyRegistration({ prepared });
          this.completeRegistrationResult(result);
          return;
        }
        case 'hosted_passkey_login_prepared_v1': {
          const result = await completeHostedPasskeyLogin(prepared);
          this.completeLoginResult(result);
          return;
        }
        case 'hosted_passkey_account_sync_prepared_v1': {
          const result = await completeHostedPasskeyAccountSync(prepared);
          this.completeAccountSyncResult(result);
          return;
        }
        default:
          return assertNeverHostedPasskeyPrepared(prepared);
      }
    } catch (error: unknown) {
      this.fail(error);
    }
  }

  private completeRegistrationResult(result: RegistrationResult): void {
    if (
      !result.success ||
      (result.kind !== 'wallet_registered' &&
        result.kind !== 'ecdsa_wallet_registered_near_pending')
    ) {
      this.fail(
        new Error(
          result.success ? 'Hosted registration returned an unexpected result' : result.error,
        ),
      );
      return;
    }
    const walletId = parseWalletId(String(result.walletId));
    if (!walletId.ok) {
      this.fail(new Error('Hosted registration returned an invalid wallet id'));
      return;
    }
    this.complete({
      kind: 'registered',
      authMenuSessionId: this.identity.authMenuSessionId,
      walletId: walletId.value,
      method: 'passkey',
    });
  }

  private completeLoginResult(
    result: Awaited<ReturnType<typeof completeHostedPasskeyLogin>>,
  ): void {
    if (!result.success) {
      this.fail(new Error(result.error));
      return;
    }
    const walletId = parseWalletId(String(result.walletId));
    if (!walletId.ok) {
      this.fail(new Error('Hosted login returned an invalid wallet id'));
      return;
    }
    this.complete({
      kind: 'authenticated',
      authMenuSessionId: this.identity.authMenuSessionId,
      walletId: walletId.value,
      method: 'passkey',
    });
  }

  private completeAccountSyncResult(
    result: Awaited<ReturnType<typeof completeHostedPasskeyAccountSync>>,
  ): void {
    if (!result.success) {
      this.fail(new Error(result.error));
      return;
    }
    const walletId = parseWalletId(String(result.walletId));
    if (!walletId.ok) {
      this.fail(new Error('Hosted account sync returned an invalid wallet id'));
      return;
    }
    this.complete({
      kind: 'account_synced',
      authMenuSessionId: this.identity.authMenuSessionId,
      walletId: walletId.value,
    });
  }

  private fail(error: unknown): void {
    if (this.stateValue.kind === 'performing') {
      cancelHostedPasskeyMenuPreparation(this.stateValue.prepared);
    }
    const message = error instanceof Error ? error.message : String(error);
    this.complete({
      kind: 'failed',
      authMenuSessionId: this.identity.authMenuSessionId,
      code: 'webauthn_failed',
      message,
    });
  }
}

function assertNeverAuthMenuIntent(value: never): never {
  throw new Error(`Unhandled auth-menu intent: ${String(value)}`);
}

function assertNeverHostedPasskeyPrepared(value: never): never {
  throw new Error(`Unhandled hosted passkey preparation: ${String(value)}`);
}

function assertNeverHostedExternalAuthEvidence(value: never): never {
  throw new Error(`Unhandled hosted external-auth evidence: ${String(value)}`);
}
