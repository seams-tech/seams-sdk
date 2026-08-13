import type { AppearanceConfig } from '@/core/types/seams';
import type { RegistrationResult } from '@/core/types/seams';
import {
  AUTH_MENU_INTENT_EVENT,
  type AuthMenuAccountOption,
  type AuthMenuIntent,
  type AuthMenuGoogleLoginViewModel,
  type AuthMenuGoogleRegistrationViewModel,
  type AuthMenuLinkDeviceViewModel,
  type AuthMenuViewModel,
  isAuthMenuIntent,
  passkeyCeremonyHeadline,
} from '../lit-ui/auth-menu/auth-menu-domain';
import { SeamsAuthMenuSurfaceElement } from '../lit-ui/auth-menu/seams-auth-menu-surface';
import {
  hostedAuthMenuExternalAuthRequestIdFromBoundary,
  parseHostedAuthMenuErrorEvent,
  type HostedAuthMenuExternalAuthRequest,
  type HostedAuthMenuExternalAuthResolution,
  type HostedAuthMenuDemoEmailOtpDelivery,
  type HostedAuthMenuExternalProvider,
  type HostedAuthMenuMode,
  type HostedAuthMenuOpenRequest,
  type HostedAuthMenuOutcome,
  type HostedAuthMenuSessionId,
  type WalletIframeSurfaceMeasurement,
} from '../../shared/messages';
import type {
  GoogleEmailOtpWalletAuthFlow,
  GoogleEmailOtpWalletAuthLoginFlow,
  GoogleEmailOtpWalletAuthRegistrationFlow,
} from '@/SeamsWeb/publicApi/types';
import type { ChildToParentEnvelope } from '../../shared/messages';
import type { WalletIframeRequestId } from '@/core/types/walletIframeIdentity';
import {
  createWalletIframeSurfaceMeasurementReporter,
  type WalletIframeSurfaceMeasurementReporter,
} from '../lit-ui/surface-measurement-reporter';
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
  type HostedPasskeyAccountSyncPrepared,
  type HostedPasskeyLoginOutcome,
  type HostedPasskeyPrepared,
} from './passkey';
import { parseWalletId } from '@shared/utils/domainIds';
import { createReadableWalletId } from '@shared/utils/registrationIntent';
import type { LinkDeviceFlowEvent } from '@/core/types/sdkSentEvents';
import type { StartDevice2LinkingFlowResults } from '@/core/types/linkDevice';

type HostedPasskeyMenuPrepared = HostedPasskeyRegistrationPrepared | HostedPasskeyPrepared;

/**
 * Why a passkey attempt ended. `dismissed` re-arms the menu in silence; every
 * other failure is shown. Callers state which one it is from where the cause is
 * still structured, so no stage has to guess from an error message.
 */
type AuthMenuFailure =
  | { readonly kind: 'dismissed' }
  | { readonly kind: 'error'; readonly error: unknown };

type PresentedAuthMenuError = {
  readonly mode: HostedAuthMenuMode;
  readonly message: string;
};

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

type AuthMenuReturnState =
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
    };

export type AuthMenuSessionState =
  | AuthMenuReturnState
  | {
      readonly kind: 'link_device';
      readonly viewModel: AuthMenuLinkDeviceViewModel;
      readonly returnState: AuthMenuReturnState;
    }
  | {
      readonly kind: 'complete';
      readonly outcome: HostedAuthMenuOutcome;
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
type StartDeviceLinking = (
  onEvent: (event: LinkDeviceFlowEvent) => void,
) => Promise<StartDevice2LinkingFlowResults>;
type StopDeviceLinking = () => Promise<void>;

const AUTH_MENU_TAG = 'seams-auth-menu-surface';
const AUTH_MENU_PASSKEY_PREPARATION_TIMEOUT_MS = 20_000;
const AUTH_MENU_PASSKEY_PREPARATION_TIMEOUT_MESSAGE =
  'Passkey preparation timed out. Retry to continue.';

function ensureAuthMenuSurfaceDefinition(): void {
  if (customElements.get(AUTH_MENU_TAG)) return;
  customElements.define(AUTH_MENU_TAG, SeamsAuthMenuSurfaceElement);
}

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
      kind: 'idle' as const,
      interaction: 'arming' as const,
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
      status: args.status ?? { kind: 'idle', interaction: 'actionable' },
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
      status: args.status ?? { kind: 'idle', interaction: 'actionable' },
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

function presentedAuthMenuError(viewModel: AuthMenuViewModel): PresentedAuthMenuError | null {
  switch (viewModel.kind) {
    case 'passkey':
      return viewModel.status.kind === 'recoverable'
        ? { mode: viewModel.mode, message: viewModel.status.message }
        : null;
    case 'google_otp_login':
    case 'google_registration':
      if (viewModel.error) return { mode: viewModel.mode, message: viewModel.error };
      return viewModel.status.kind === 'recoverable'
        ? { mode: viewModel.mode, message: viewModel.status.message }
        : null;
    case 'link_device':
      return null;
    default: {
      const exhaustive: never = viewModel;
      throw new Error(`Unknown auth-menu view model: ${JSON.stringify(exhaustive)}`);
    }
  }
}

function linkDeviceViewModel(base: AuthMenuViewModel): AuthMenuLinkDeviceViewModel {
  return {
    kind: 'link_device',
    appearance: base.appearance,
    hostname: base.hostname,
    closeLabel: base.closeLabel,
    heading: 'Scan and Link Device',
    subtitle: 'Scan to backup your other device.',
    ctaLabel: '',
    showProgress: base.showProgress,
    enabledExternalProviders: base.enabledExternalProviders,
    status: { kind: 'idle', interaction: 'actionable' },
    mode: base.mode,
    linkDevice: { kind: 'loading', message: 'Generating QR code...' },
  };
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
  private preparationCancellation: AbortController | null = null;
  private googleCancellation: AbortController | null = null;
  private beginGoogleEmailOtp: BeginGoogleEmailOtp;
  private readonly startDeviceLinking: StartDeviceLinking;
  private readonly stopDeviceLinking: StopDeviceLinking;
  private loginPreparation: PrepareLoginPasskey | null = null;
  private loginAccountOptions: readonly AuthMenuAccountOption[] = [];
  private selectedLoginWalletId: string | null = null;
  private readonly sendToParent: (message: ChildToParentEnvelope) => void;
  private measurementReporter: WalletIframeSurfaceMeasurementReporter | null = null;
  private preparationGeneration = 0;
  private googleGeneration = 0;
  private deviceLinkGeneration = 0;
  private preparationDeadlineTimer: ReturnType<typeof setTimeout> | null = null;
  private preparationExpiryTimer: ReturnType<typeof setTimeout> | null = null;
  private lastReportedError: string | null = null;

  constructor(args: {
    request: HostedAuthMenuOpenRequest;
    requestId: WalletIframeRequestId;
    appearance: AppearanceConfig;
    hostname: string;
    beginGoogleEmailOtp: BeginGoogleEmailOtp;
    startDeviceLinking: StartDeviceLinking;
    stopDeviceLinking: StopDeviceLinking;
    sendToParent: (message: ChildToParentEnvelope) => void;
  }) {
    this.identity = {
      authMenuSessionId: args.request.authMenuSessionId,
      requestId: args.requestId,
    };
    this.request = args.request;
    this.beginGoogleEmailOtp = args.beginGoogleEmailOtp;
    this.startDeviceLinking = args.startDeviceLinking;
    this.stopDeviceLinking = args.stopDeviceLinking;
    this.sendToParent = args.sendToParent;
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

  mount(): void {
    if (this.element || this.cleanedUp) {
      throw new Error('Hosted auth-menu session is already mounted');
    }
    ensureAuthMenuSurfaceDefinition();
    const existing = document.querySelectorAll(AUTH_MENU_TAG);
    if (existing.length > 0) {
      throw new Error('A hosted auth-menu surface is already mounted');
    }
    const element = document.createElement(AUTH_MENU_TAG) as SeamsAuthMenuSurfaceElement;
    element.viewModel = this.currentViewModel();
    element.addEventListener(AUTH_MENU_INTENT_EVENT, this.onIntent);
    const root = document.body || document.documentElement;
    if (!root) throw new Error('Wallet host document has no mount root');
    root.appendChild(element);
    this.element = element;
    this.measurementReporter = createWalletIframeSurfaceMeasurementReporter({
      kind: 'auth_menu_surface',
      element,
      requestId: this.identity.requestId,
      authMenuSessionId: this.identity.authMenuSessionId,
      postMeasurement: this.postSurfaceMeasurement,
    });
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
          status: { kind: 'idle', interaction: 'awaiting_input' },
        },
      };
      this.updateElement();
      return;
    }

    this.clearPreparationExpiryTimer();
    const generation = ++this.preparationGeneration;
    const cancellationController = new AbortController();
    this.preparationCancellation = cancellationController;
    const cancellation = {
      kind: 'abort_signal' as const,
      signal: cancellationController.signal,
    };
    this.stateValue = {
      kind: 'preparing',
      viewModel: {
        ...viewModel,
        status: { kind: 'idle', interaction: 'arming' },
      },
    };
    this.updateElement();
    this.schedulePreparationDeadline(generation, cancellationController);
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
        this.clearPreparationDeadlineTimer();
        this.prepared = prepared;
        this.stateValue = {
          kind: 'ready',
          prepared,
          viewModel: {
            ...this.currentViewModel(),
            status: { kind: 'idle', interaction: 'actionable' },
          },
        };
        this.schedulePreparationExpiry(prepared);
        this.updateElement();
      },
      (error: unknown) => {
        if (generation !== this.preparationGeneration || this.stateValue.kind === 'complete')
          return;
        this.clearPreparationDeadlineTimer();
        this.stateValue = {
          kind: 'preparing',
          viewModel: {
            ...this.currentViewModel(),
            status: {
              kind: 'recoverable',
              reason: 'error',
              message: error instanceof Error ? error.message : String(error),
            },
          },
        };
        this.updateElement();
      },
    );
  }

  private invalidatePreparation(): void {
    if (this.stateValue.kind === 'link_device') {
      this.deviceLinkGeneration += 1;
      void this.stopDeviceLinking().catch(() => {});
    }
    this.clearPreparationDeadlineTimer();
    this.clearPreparationExpiryTimer();
    this.preparationGeneration += 1;
    this.preparationCancellation?.abort();
    this.preparationCancellation = null;
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

  private clearPreparationDeadlineTimer(): void {
    if (this.preparationDeadlineTimer === null) return;
    clearTimeout(this.preparationDeadlineTimer);
    this.preparationDeadlineTimer = null;
  }

  private schedulePreparationDeadline(
    generation: number,
    cancellation: AbortController,
  ): void {
    this.clearPreparationDeadlineTimer();
    this.preparationDeadlineTimer = setTimeout(
      this.expirePasskeyPreparation.bind(this, generation, cancellation),
      AUTH_MENU_PASSKEY_PREPARATION_TIMEOUT_MS,
    );
  }

  private expirePasskeyPreparation(generation: number, cancellation: AbortController): void {
    const state = this.stateValue;
    if (
      generation !== this.preparationGeneration ||
      cancellation !== this.preparationCancellation ||
      state.kind !== 'preparing' ||
      state.viewModel.kind !== 'passkey' ||
      state.viewModel.status.kind !== 'idle' ||
      state.viewModel.status.interaction !== 'arming'
    ) {
      return;
    }
    this.clearPreparationDeadlineTimer();
    this.preparationGeneration += 1;
    this.preparationCancellation = null;
    cancellation.abort();
    this.stateValue = {
      kind: 'preparing',
      viewModel: {
        ...state.viewModel,
        status: {
          kind: 'recoverable',
          reason: 'error',
          message: AUTH_MENU_PASSKEY_PREPARATION_TIMEOUT_MESSAGE,
        },
      },
    };
    this.updateElement();
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
          status: {
            kind: 'recoverable',
            reason: 'expired',
            message: 'Passkey preparation expired. Retry to continue.',
          },
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
        // Stay on the waiting view, under the same headline the external-auth
        // request already showed. 'preparing' is not a loading status, so it
        // dropped the surface back to the main menu for the whole
        // beginGoogleEmailOtp round trip — a visible flash between the SSO
        // prompt and the OTP form.
        status: {
          kind: 'busy',
          headline: 'Waiting for Google SSO authentication…',
          detail: 'Starting Google sign-in',
        },
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
        const delivery = flow.delivery;
        if (
          delivery &&
          (delivery.kind === 'demo_code_response' || delivery.kind === 'provider_and_demo_code')
        ) {
          const payload: HostedAuthMenuDemoEmailOtpDelivery = {
            kind: 'hosted_auth_menu_demo_email_otp_delivery_v1',
            authMenuSessionId: this.identity.authMenuSessionId,
            delivery,
          };
          this.sendToParent({
            type: 'AUTH_MENU_DEMO_EMAIL_OTP_DELIVERY',
            requestId: this.identity.requestId,
            payload,
          });
        }
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
            status: { kind: 'recoverable', reason: 'error', message: errorMessage(error) },
          },
        };
        this.updateElement();
        this.startPasskeyPreparation();
      },
    );
  }

  requestExternalAuth(
    provider: HostedAuthMenuExternalAuthRequest['provider'],
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
        // 'performing' is what drives the surface's waiting view; 'preparing'
        // left the menu sitting on the form with no feedback during the SSO
        // round trip.
        status: {
          kind: 'busy',
          headline: 'Waiting for Google SSO authentication…',
          detail: 'Waiting for Google sign-in',
        },
      },
      request,
    };
    this.updateElement();
    this.sendToParent({
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
            status: { kind: 'recoverable', reason: 'error', message },
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
    this.measurementReporter?.disconnect();
    this.measurementReporter = null;
    const element = this.element;
    this.element = null;
    if (!element) return;
    element.removeEventListener(AUTH_MENU_INTENT_EVENT, this.onIntent);
    element.remove();
  }

  private postSurfaceMeasurement = (measurement: WalletIframeSurfaceMeasurement): void => {
    this.sendToParent({ type: 'SURFACE_MEASUREMENT', payload: measurement });
  };

  private currentViewModel(): AuthMenuViewModel {
    switch (this.stateValue.kind) {
      case 'preparing':
      case 'awaiting_external_auth':
      case 'ready':
      case 'performing':
        return this.stateValue.viewModel;
      case 'google_login':
      case 'google_registration':
      case 'link_device':
        return this.stateValue.viewModel;
      case 'complete':
        throw new Error('Completed auth-menu session has no view model');
    }
  }

  private updateElement(): void {
    const viewModel = this.currentViewModel();
    this.reportPresentedError(viewModel);
    if (this.element) this.element.viewModel = viewModel;
  }

  private reportPresentedError(viewModel: AuthMenuViewModel): void {
    const error = presentedAuthMenuError(viewModel);
    if (!error) {
      this.lastReportedError = null;
      return;
    }
    const errorKey = `${error.mode}:${error.message}`;
    if (errorKey === this.lastReportedError) return;
    this.lastReportedError = errorKey;
    const payload = parseHostedAuthMenuErrorEvent({
      kind: 'hosted_auth_menu_error_v1',
      authMenuSessionId: this.identity.authMenuSessionId,
      mode: error.mode,
      message: error.message,
    });
    if (!payload) throw new Error('Unable to emit hosted auth-menu error event');
    this.sendToParent({ type: 'AUTH_MENU_ERROR', requestId: this.identity.requestId, payload });
  }

  private onIntent = (event: Event): void => {
    if (!(event instanceof CustomEvent)) return;
    if (!isAuthMenuIntent(event.detail)) return;
    const intent: AuthMenuIntent = event.detail;
    switch (intent.kind) {
      case 'mode_selected':
        this.selectMode(intent.mode);
        return;
      case 'back':
        this.back();
        return;
      case 'link_device_open':
        this.openLinkDevice();
        return;
      case 'registration_reroll':
        this.rerollRegistrationWallet();
        return;
      case 'close':
        this.cancel(closeReasonForIntent(intent));
        return;
      case 'passkey_name_changed': {
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
              status: { kind: 'idle', interaction: 'arming' },
            },
          };
          this.updateElement();
          this.startPasskeyPreparation();
        }
        return;
      }
      case 'login_account_selected':
        this.selectLoginAccount(intent.walletId);
        return;
      case 'submit':
        // A failed or expired preparation has no live credential to consume, so
        // the primary action re-prepares instead. This replaces the separate
        // Retry control the surface used to render.
        if (
          this.stateValue.kind === 'preparing' &&
          this.stateValue.viewModel.status.kind === 'recoverable'
        ) {
          this.retryPreparation();
          return;
        }
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
        this.requestExternalAuth(intent.provider);
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
    if (state.kind === 'complete' || state.kind === 'performing' || state.kind === 'link_device') {
      return;
    }
    const currentViewModel = this.currentViewModel();
    if (currentViewModel.mode === mode) return;
    this.showPasskeyMode(mode);
  }

  private showPasskeyMode(mode: HostedAuthMenuMode): void {
    if (this.stateValue.kind === 'complete' || this.stateValue.kind === 'link_device') return;
    const currentViewModel = this.currentViewModel();
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

  private back(): void {
    if (this.stateValue.kind === 'link_device') {
      this.closeLinkDevice();
      return;
    }
    if (
      this.stateValue.kind === 'performing' ||
      this.stateValue.kind === 'awaiting_external_auth' ||
      this.stateValue.kind === 'google_login' ||
      this.stateValue.kind === 'google_registration'
    ) {
      this.showPasskeyMode(this.stateValue.viewModel.mode);
    }
  }

  private openLinkDevice(): void {
    const state = this.stateValue;
    if (
      (state.kind !== 'preparing' && state.kind !== 'ready') ||
      state.viewModel.kind !== 'passkey'
    ) {
      return;
    }
    const returnState: AuthMenuReturnState = {
      kind: 'preparing',
      viewModel: {
        ...state.viewModel,
        status: { kind: 'idle', interaction: 'arming' },
      },
    };
    this.invalidatePreparation();
    const generation = ++this.deviceLinkGeneration;
    this.stateValue = {
      kind: 'link_device',
      returnState,
      viewModel: linkDeviceViewModel(state.viewModel),
    };
    this.updateElement();
    void this.startDeviceLinking(this.onLinkDeviceEvent.bind(this, generation))
      .then(this.completeLinkDeviceOpen.bind(this, generation))
      .catch(this.failLinkDeviceOpen.bind(this, generation));
  }

  private onLinkDeviceEvent(generation: number, event: LinkDeviceFlowEvent): void {
    const state = this.stateValue;
    if (generation !== this.deviceLinkGeneration || state.kind !== 'link_device') return;
    const message = event.message?.trim();
    if (!message) return;
    const linkDevice =
      state.viewModel.linkDevice.kind === 'ready'
        ? { ...state.viewModel.linkDevice, message }
        : { kind: 'loading' as const, message };
    this.stateValue = {
      ...state,
      viewModel: { ...state.viewModel, linkDevice },
    };
    this.updateElement();
  }

  private completeLinkDeviceOpen(generation: number, result: StartDevice2LinkingFlowResults): void {
    const state = this.stateValue;
    if (generation !== this.deviceLinkGeneration || state.kind !== 'link_device') return;
    this.stateValue = {
      ...state,
      viewModel: {
        ...state.viewModel,
        linkDevice: {
          kind: 'ready',
          qrCodeDataURL: result.qrCodeDataURL,
          message: 'Waiting for device to scan',
        },
      },
    };
    this.updateElement();
  }

  private failLinkDeviceOpen(generation: number, error: unknown): void {
    const state = this.stateValue;
    if (generation !== this.deviceLinkGeneration || state.kind !== 'link_device') return;
    this.stateValue = {
      ...state,
      viewModel: {
        ...state.viewModel,
        linkDevice: { kind: 'error', message: errorMessage(error) },
      },
    };
    this.updateElement();
  }

  private closeLinkDevice(): void {
    const state = this.stateValue;
    if (state.kind !== 'link_device') return;
    this.deviceLinkGeneration += 1;
    void this.stopDeviceLinking().catch(() => {});
    this.stateValue = state.returnState;
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
        status: { kind: 'idle', interaction: 'arming' },
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
        status: { kind: 'idle', interaction: 'arming' },
      },
    };
    this.updateElement();
    this.startPasskeyPreparation();
  }

  private retryPreparation(): void {
    const state = this.stateValue;
    if (state.kind !== 'preparing' || state.viewModel.status.kind !== 'recoverable') {
      return;
    }
    this.invalidatePreparation();
    this.stateValue = {
      kind: 'preparing',
      viewModel: {
        ...state.viewModel,
        status: { kind: 'idle', interaction: 'arming' },
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
    // A complete code is an unambiguous intent — submit it rather than making
    // the user confirm what they just finished typing. submitGoogleOtp re-reads
    // state and no-ops while a submit is already in flight, so a paste that
    // lands the sixth digit cannot double-submit.
    if (/^\d{6}$/.test(otpCode)) this.submitGoogleOtp();
  }

  private resendGoogleOtp(): void {
    const state = this.stateValue;
    if (state.kind !== 'google_login' || state.viewModel.resendBusy) return;
    const flow = state.flow;
    this.stateValue = {
      ...state,
      viewModel: {
        ...state.viewModel,
        status: { kind: 'busy', headline: 'Sending a new email code' },
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
              status: { kind: 'idle', interaction: 'actionable' },
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
              status: { kind: 'idle', interaction: 'actionable' },
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
            status: { kind: 'idle', interaction: 'actionable' },
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
          status: { kind: 'idle', interaction: 'actionable' },
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
        status: { kind: 'busy', headline: 'Verifying your email code' },
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
              status: { kind: 'idle', interaction: 'actionable' },
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
              status: { kind: 'idle', interaction: 'actionable' },
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
            status: { kind: 'idle', interaction: 'actionable' },
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
        status: { kind: 'busy', headline: 'Generating another wallet name' },
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
              status: { kind: 'idle', interaction: 'actionable' },
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
              status: { kind: 'idle', interaction: 'actionable' },
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
            status: { kind: 'idle', interaction: 'actionable' },
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
        status: { kind: 'busy', headline: 'Creating your wallet' },
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
              status: { kind: 'idle', interaction: 'actionable' },
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
            status: { kind: 'idle', interaction: 'actionable' },
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
        status: {
          kind: 'busy',
          headline: passkeyCeremonyHeadline(this.currentViewModel().mode),
          detail: 'Continue with your passkey',
        },
      },
    };
    this.updateElement();
    if (prepared.kind === 'hosted_passkey_login_prepared_v1') {
      void this.finishPreparedPasskey(prepared);
      return;
    }
    let authority: Promise<unknown>;
    try {
      // Registration and account sync start WebAuthn while this click still owns activation.
      authority = this.startPreparedCredential(prepared);
    } catch (error: unknown) {
      this.fail(this.ceremonyFailure(prepared, error));
      return;
    }
    void authority.then(
      () => this.finishPreparedPasskey(prepared),
      (error: unknown) => this.fail(this.ceremonyFailure(prepared, error)),
    );
  }

  private startPreparedCredential(
    prepared: HostedPasskeyRegistrationPrepared | HostedPasskeyAccountSyncPrepared,
  ): Promise<unknown> {
    if (prepared.kind === 'hosted_passkey_registration_prepared_v1') {
      return startHostedPasskeyRegistrationCredential(prepared);
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
          const outcome = await completeHostedPasskeyLogin(prepared);
          this.completeLoginResult(outcome);
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
      this.fail(this.ceremonyFailure(prepared, error));
    }
  }

  private completeRegistrationResult(result: RegistrationResult): void {
    if (
      !result.success ||
      (result.kind !== 'wallet_registered' &&
        result.kind !== 'ecdsa_wallet_registered_near_pending')
    ) {
      this.fail({
        kind: 'error',
        error: new Error(
          result.success ? 'Hosted registration returned an unexpected result' : result.error,
        ),
      });
      return;
    }
    const walletId = parseWalletId(String(result.walletId));
    if (!walletId.ok) {
      this.fail({
        kind: 'error',
        error: new Error('Hosted registration returned an invalid wallet id'),
      });
      return;
    }
    this.complete({
      kind: 'registered',
      authMenuSessionId: this.identity.authMenuSessionId,
      walletId: walletId.value,
      method: 'passkey',
    });
  }

  private completeLoginResult(outcome: HostedPasskeyLoginOutcome): void {
    const result = outcome.result;
    if (!result.success) {
      // The unlock pipeline flattens a dismissed passkey sheet into a plain
      // failure message; it reports the cancellation on the event stream
      // instead, which the outcome latched while the cause was still typed.
      this.fail(
        outcome.cancelledByUser
          ? { kind: 'dismissed' }
          : { kind: 'error', error: new Error(result.error) },
      );
      return;
    }
    const walletId = parseWalletId(String(result.walletId));
    if (!walletId.ok) {
      this.fail({ kind: 'error', error: new Error('Hosted login returned an invalid wallet id') });
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
      this.fail({ kind: 'error', error: new Error(result.error) });
      return;
    }
    const walletId = parseWalletId(String(result.walletId));
    if (!walletId.ok) {
      this.fail({
        kind: 'error',
        error: new Error('Hosted account sync returned an invalid wallet id'),
      });
      return;
    }
    this.complete({
      kind: 'account_synced',
      authMenuSessionId: this.identity.authMenuSessionId,
      walletId: walletId.value,
    });
  }

  /**
   * Classify a rejection from the WebAuthn ceremony itself.
   *
   * Dismissing the platform authenticator sheet is a decision, not a failure,
   * and so is an abort this session issued (a mode switch or re-preparation
   * tears the ceremony down). Both re-arm the menu silently — its own buttons
   * are already the retry affordance.
   *
   * Classify on the DOMException name and on our own abort signal, never on
   * message text. Text matching also swallowed anything whose message merely
   * mentioned "AbortError" or "cancelled", so genuine failures re-armed the
   * menu with no explanation at all. An RP-ID misconfiguration arrives as a
   * SecurityError and therefore still surfaces.
   */
  private ceremonyFailure(prepared: HostedPasskeyMenuPrepared, error: unknown): AuthMenuFailure {
    if (prepared.cancellation.signal.aborted) return { kind: 'dismissed' };
    const name = error instanceof Error ? error.name : '';
    if (name === 'NotAllowedError' || name === 'AbortError') return { kind: 'dismissed' };
    return { kind: 'error', error };
  }

  private fail(failure: AuthMenuFailure): void {
    if (this.stateValue.kind !== 'performing') return;
    const viewModel = this.stateValue.viewModel;
    cancelHostedPasskeyMenuPreparation(this.stateValue.prepared);
    this.prepared = null;
    if (failure.kind === 'dismissed') {
      this.invalidatePreparation();
      this.stateValue = {
        kind: 'preparing',
        viewModel: {
          ...viewModel,
          status: { kind: 'idle', interaction: 'arming' },
        },
      };
      this.updateElement();
      this.startPasskeyPreparation();
      return;
    }
    const message = failure.error instanceof Error ? failure.error.message : String(failure.error);
    this.stateValue = {
      kind: 'preparing',
      viewModel: {
        ...viewModel,
        status: { kind: 'recoverable', reason: 'error', message },
      },
    };
    this.updateElement();
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
