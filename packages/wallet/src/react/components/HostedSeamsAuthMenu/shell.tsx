import React from 'react';
import { useSeams } from '@/react/context';
import {
  buildHostedAuthMenuOpenRequest,
  hostedAuthMenuExternalAuthRequestIdFromBoundary,
  hostedAuthMenuSessionIdFromBoundary,
  type HostedAuthMenuExternalAuthEvidence,
  type HostedAuthMenuExternalProvider,
  type HostedAuthMenuExternalAuthRequest,
  type HostedAuthMenuDemoEmailOtpDelivery,
  type HostedAuthMenuExternalAuthRequestId,
  type HostedAuthMenuMode,
  type HostedAuthMenuOutcome,
  type HostedAuthMenuSessionId,
} from '@/SeamsWeb/walletIframe/shared/messages';
import type { SeamsWeb } from '@/SeamsWeb';
import type { HostedAuthMenuExternalAuthBroker, HostedSeamsAuthMenuProps } from './types';

type SeamsAuthMenuBridge = Pick<
  SeamsWeb,
  | 'openHostedAuthMenu'
  | 'cancelHostedAuthMenu'
  | 'onHostedAuthMenuExternalAuthRequest'
  | 'onHostedAuthMenuDemoEmailOtpDelivery'
  | 'resolveHostedAuthMenuExternalAuth'
>;

type OutcomeRef = React.MutableRefObject<HostedSeamsAuthMenuProps['onOutcome']>;
type DemoEmailOtpRef = React.MutableRefObject<HostedSeamsAuthMenuProps['onDemoEmailOtp']>;
type BrokerRef = React.MutableRefObject<HostedAuthMenuExternalAuthBroker | null>;
type HostedAuthMenuFailureCode = Extract<HostedAuthMenuOutcome, { kind: 'failed' }>['code'];

type HostedAuthMenuSessionArgs = {
  seams: SeamsAuthMenuBridge;
  anchorElement: HTMLElement;
  authMenuSessionId: HostedAuthMenuSessionId;
  initialMode: HostedAuthMenuMode;
  registrationAccountInput: HostedSeamsAuthMenuProps['registrationAccountInput'];
  showRegistrationInput: boolean;
  showProgress: boolean;
  copy: HostedSeamsAuthMenuProps['copy'];
  externalAuthBroker: BrokerRef;
  onOutcome: OutcomeRef;
  onDemoEmailOtp: DemoEmailOtpRef;
};

type ExternalAuthEvidenceRecord = {
  kind?: unknown;
  idToken?: unknown;
  reason?: unknown;
  code?: unknown;
  message?: unknown;
};

type HostedAuthMenuEffectConfig = {
  readonly initialMode: HostedAuthMenuMode;
  readonly registrationAccountInput: HostedSeamsAuthMenuProps['registrationAccountInput'];
  readonly showRegistrationInput: boolean;
  readonly showProgress: boolean;
  readonly copy: HostedSeamsAuthMenuProps['copy'];
  readonly enabledExternalProviders: readonly HostedAuthMenuExternalProvider[];
};

let sessionCounter = 0;

function createHostedAuthMenuSessionId(): HostedAuthMenuSessionId {
  const randomId =
    typeof globalThis.crypto?.randomUUID === 'function'
      ? globalThis.crypto.randomUUID()
      : `${Date.now()}-${sessionCounter++}-${Math.random().toString(36).slice(2)}`;
  const sessionId = hostedAuthMenuSessionIdFromBoundary(`react-${randomId}`);
  if (!sessionId) throw new Error('Unable to create a hosted auth-menu session identity');
  return sessionId;
}

function errorMessage(error: unknown): string {
  if (error instanceof Error && error.message.trim()) return error.message.trim();
  if (typeof error === 'string' && error.trim()) return error.trim();
  return 'Hosted auth-menu operation failed';
}

function failureCodeForError(error: unknown): HostedAuthMenuFailureCode {
  const message = errorMessage(error).toLowerCase();
  if (message.includes('open configuration')) return 'invalid_request';
  if (
    message.includes('wallet iframe') &&
    (message.includes('configured') || message.includes('unavailable'))
  ) {
    return 'connection_closed';
  }
  return 'wallet_error';
}

function isExternalAuthEvidenceRecord(value: unknown): value is ExternalAuthEvidenceRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function invalidEvidence(message: string): HostedAuthMenuExternalAuthEvidence {
  return { kind: 'failed', code: 'invalid_evidence', message };
}

function externalProvidersForBroker(
  broker: HostedAuthMenuExternalAuthBroker | null,
): readonly HostedAuthMenuExternalProvider[] {
  return broker ? ['google'] : [];
}

function normalizeExternalAuthEvidence(value: unknown): HostedAuthMenuExternalAuthEvidence {
  if (!isExternalAuthEvidenceRecord(value)) {
    return invalidEvidence('External-auth broker returned an invalid evidence object');
  }

  switch (value.kind) {
    case 'google_id_token':
      return typeof value.idToken === 'string' && value.idToken.trim()
        ? { kind: 'google_id_token', idToken: value.idToken.trim() }
        : invalidEvidence('External-auth broker returned an empty Google ID token');
    case 'cancelled':
      return value.reason === 'user_cancelled'
        ? { kind: 'cancelled', reason: 'user_cancelled' }
        : invalidEvidence('External-auth broker returned an invalid cancellation reason');
    case 'failed':
      if (
        (value.code === 'provider_unavailable' ||
          value.code === 'provider_error' ||
          value.code === 'invalid_evidence') &&
        typeof value.message === 'string' &&
        value.message.trim()
      ) {
        return {
          kind: 'failed',
          code: value.code,
          message: value.message.trim(),
        };
      }
      return invalidEvidence('External-auth broker returned an invalid failure branch');
    default:
      return invalidEvidence('External-auth broker returned an unknown evidence branch');
  }
}

/** Outcomes after which an auth menu has done its job and must not re-open. */
function isTerminalHostedAuthMenuSuccess(outcome: HostedAuthMenuOutcome): boolean {
  return (
    outcome.kind === 'authenticated' ||
    outcome.kind === 'registered' ||
    outcome.kind === 'account_synced'
  );
}

function providerFailureEvidence(
  code: 'provider_unavailable' | 'provider_error',
  message: string,
): HostedAuthMenuExternalAuthEvidence {
  return { kind: 'failed', code, message };
}

function assertMatchingExternalAuthRequest(
  request: HostedAuthMenuExternalAuthRequest,
  authMenuSessionId: HostedAuthMenuSessionId,
): HostedAuthMenuExternalAuthRequestId | null {
  if (request.authMenuSessionId !== authMenuSessionId) return null;
  return hostedAuthMenuExternalAuthRequestIdFromBoundary(request.externalAuthRequestId);
}

function hostedAuthMenuEffectConfigKey(config: HostedAuthMenuEffectConfig): string {
  const configSessionId = hostedAuthMenuSessionIdFromBoundary('react-effect-config');
  if (!configSessionId) return 'invalid';

  try {
    const normalized = buildHostedAuthMenuOpenRequest({
      authMenuSessionId: configSessionId,
      initialMode: config.initialMode,
      registrationAccountInput: config.registrationAccountInput,
      showRegistrationInput: config.showRegistrationInput,
      showProgress: config.showProgress,
      copy: config.copy,
      enabledExternalProviders: config.enabledExternalProviders,
    });
    return JSON.stringify({
      initialMode: normalized.initialMode,
      registrationAccountInput: normalized.registrationAccountInput,
      showRegistrationInput: normalized.showRegistrationInput,
      showProgress: normalized.showProgress,
      copy: normalized.copy,
      enabledExternalProviders: normalized.enabledExternalProviders,
    });
  } catch {
    return 'invalid';
  }
}

class HostedAuthMenuSessionController {
  private readonly seams: SeamsAuthMenuBridge;
  private readonly anchorElement: HTMLElement;
  private readonly authMenuSessionId: HostedAuthMenuSessionId;
  private readonly initialMode: HostedAuthMenuMode;
  private readonly registrationAccountInput: HostedSeamsAuthMenuProps['registrationAccountInput'];
  private readonly showRegistrationInput: boolean;
  private readonly showProgress: boolean;
  private readonly copy: HostedSeamsAuthMenuProps['copy'];
  private readonly externalAuthBroker: BrokerRef;
  private readonly onOutcome: OutcomeRef;
  private readonly onDemoEmailOtp: DemoEmailOtpRef;
  private readonly externalAuthRequestIds = new Set<HostedAuthMenuExternalAuthRequestId>();
  private readonly handleExternalAuthRequestBound: (
    request: HostedAuthMenuExternalAuthRequest,
  ) => void;
  private unsubscribeExternalAuthRequest: (() => void) | null = null;
  private unsubscribeDemoEmailOtp: (() => void) | null = null;
  private isActive = false;
  private hasOpenRequest = false;
  private hasTerminalOutcome = false;
  private hasFinalizedCleanup = false;

  constructor(args: HostedAuthMenuSessionArgs) {
    this.seams = args.seams;
    this.anchorElement = args.anchorElement;
    this.authMenuSessionId = args.authMenuSessionId;
    this.initialMode = args.initialMode;
    this.registrationAccountInput = args.registrationAccountInput;
    this.showRegistrationInput = args.showRegistrationInput;
    this.showProgress = args.showProgress;
    this.copy = args.copy;
    this.externalAuthBroker = args.externalAuthBroker;
    this.onOutcome = args.onOutcome;
    this.onDemoEmailOtp = args.onDemoEmailOtp;
    this.handleExternalAuthRequestBound = this.handleExternalAuthRequest.bind(this);
  }

  start(): void {
    if (this.isActive) return;
    this.isActive = true;
    this.unsubscribeExternalAuthRequest = this.seams.onHostedAuthMenuExternalAuthRequest(
      this.handleExternalAuthRequestBound,
    );
    this.unsubscribeDemoEmailOtp = this.seams.onHostedAuthMenuDemoEmailOtpDelivery(
      this.handleDemoEmailOtpDelivery.bind(this),
    );
    void this.open();
  }

  cleanup(): void {
    if (this.hasFinalizedCleanup) return;
    this.hasFinalizedCleanup = true;
    this.isActive = false;
    this.unsubscribeExternalAuthRequest?.();
    this.unsubscribeExternalAuthRequest = null;
    this.unsubscribeDemoEmailOtp?.();
    this.unsubscribeDemoEmailOtp = null;
    this.externalAuthRequestIds.clear();
    if (this.hasOpenRequest) {
      void this.seams
        .cancelHostedAuthMenu({ authMenuSessionId: this.authMenuSessionId })
        .catch(() => {});
    }
  }

  private async open(): Promise<void> {
    await Promise.resolve();
    if (!this.isActive) return;

    let request;
    try {
      request = buildHostedAuthMenuOpenRequest({
        authMenuSessionId: this.authMenuSessionId,
        initialMode: this.initialMode,
        registrationAccountInput: this.registrationAccountInput,
        showRegistrationInput: this.showRegistrationInput,
        showProgress: this.showProgress,
        copy: this.copy,
        enabledExternalProviders: this.externalAuthBroker.current ? ['google'] : [],
      });
    } catch (error: unknown) {
      this.emitFailure(failureCodeForError(error), errorMessage(error));
      return;
    }

    try {
      this.hasOpenRequest = true;
      const outcome = await this.seams.openHostedAuthMenu(request, this.anchorElement);
      if (!this.isActive) return;
      if (outcome.authMenuSessionId !== this.authMenuSessionId) {
        this.emitFailure(
          'internal_error',
          'Hosted auth-menu returned a mismatched session identity',
        );
        return;
      }
      this.emitOutcome(outcome);
    } catch (error: unknown) {
      if (!this.isActive) return;
      this.emitFailure(failureCodeForError(error), errorMessage(error));
    }
  }

  private handleExternalAuthRequest(request: HostedAuthMenuExternalAuthRequest): void {
    if (!this.isActive) return;
    const requestId = assertMatchingExternalAuthRequest(request, this.authMenuSessionId);
    if (!requestId || this.externalAuthRequestIds.has(requestId)) return;
    this.externalAuthRequestIds.add(requestId);
    void this.resolveExternalAuthRequest(request, requestId);
  }

  private handleDemoEmailOtpDelivery(delivery: HostedAuthMenuDemoEmailOtpDelivery): void {
    if (!this.isActive || delivery.authMenuSessionId !== this.authMenuSessionId) return;
    this.onDemoEmailOtp.current?.(delivery.delivery);
  }

  private async resolveExternalAuthRequest(
    request: HostedAuthMenuExternalAuthRequest,
    requestId: HostedAuthMenuExternalAuthRequestId,
  ): Promise<void> {
    const broker = this.externalAuthBroker.current;
    let evidence: HostedAuthMenuExternalAuthEvidence;
    if (!broker) {
      evidence = providerFailureEvidence(
        'provider_unavailable',
        'No external-auth broker is configured for this auth-menu session',
      );
    } else {
      try {
        evidence = normalizeExternalAuthEvidence(await broker(request));
      } catch (error: unknown) {
        evidence = providerFailureEvidence('provider_error', errorMessage(error));
      }
    }

    if (!this.isActive) {
      this.externalAuthRequestIds.delete(requestId);
      return;
    }

    try {
      await this.seams.resolveHostedAuthMenuExternalAuth({
        kind: 'hosted_auth_menu_external_auth_resolution_v1',
        authMenuSessionId: this.authMenuSessionId,
        externalAuthRequestId: requestId,
        evidence,
      });
    } catch {
      // The router ignores stale resolutions after cancellation or a terminal outcome.
    } finally {
      this.externalAuthRequestIds.delete(requestId);
    }
  }

  private emitFailure(code: HostedAuthMenuFailureCode, message: string): void {
    this.emitOutcome({
      kind: 'failed',
      authMenuSessionId: this.authMenuSessionId,
      code,
      message,
    });
  }

  private emitOutcome(outcome: HostedAuthMenuOutcome): void {
    if (this.hasTerminalOutcome) return;
    this.hasTerminalOutcome = true;
    try {
      this.onOutcome.current(outcome);
    } catch {
      // An application callback cannot invalidate the wallet-host terminal state.
    }
  }
}

type HostedAuthMenuContext = {
  readonly seams: SeamsWeb | null;
  readonly isLoggedIn: boolean;
};

type HostedAuthMenuTerminalGate = {
  completed: boolean;
  observedLoggedIn: boolean;
};

const hostedAuthMenuTerminalGates = new WeakMap<SeamsWeb, HostedAuthMenuTerminalGate>();

function useOptionalSeams(): HostedAuthMenuContext {
  try {
    const context = useSeams();
    return {
      seams: context.seams,
      isLoggedIn: context.loginState.isLoggedIn,
    };
  } catch (error: unknown) {
    if (typeof window === 'undefined') return { seams: null, isLoggedIn: false };
    throw error;
  }
}

function terminalGateFor(seams: SeamsWeb | null): HostedAuthMenuTerminalGate | null {
  if (!seams) return null;
  const existing = hostedAuthMenuTerminalGates.get(seams);
  if (existing) return existing;
  const gate: HostedAuthMenuTerminalGate = {
    completed: false,
    observedLoggedIn: false,
  };
  hostedAuthMenuTerminalGates.set(seams, gate);
  return gate;
}

function syncTerminalGate(gate: HostedAuthMenuTerminalGate | null, isLoggedIn: boolean): void {
  if (!gate) return;
  if (isLoggedIn) {
    gate.completed = true;
    gate.observedLoggedIn = true;
    return;
  }
  if (!gate.observedLoggedIn) return;
  gate.completed = false;
  gate.observedLoggedIn = false;
}

function forwardHostedAuthMenuOutcome(
  terminalGateRef: React.MutableRefObject<HostedAuthMenuTerminalGate | null>,
  onOutcomeRef: OutcomeRef,
  outcome: HostedAuthMenuOutcome,
): void {
  if (isTerminalHostedAuthMenuSuccess(outcome) && terminalGateRef.current) {
    terminalGateRef.current.completed = true;
  }
  onOutcomeRef.current(outcome);
}

export const HostedSeamsAuthMenu: React.FC<HostedSeamsAuthMenuProps> = ({
  initialMode = 'login',
  registrationAccountInput = 'implicit_wallet',
  showRegistrationInput = false,
  showProgress = false,
  copy,
  externalAuthBroker = null,
  onDemoEmailOtp,
  onOutcome,
}) => {
  const { seams, isLoggedIn } = useOptionalSeams();
  const terminalGate = terminalGateFor(seams);
  syncTerminalGate(terminalGate, isLoggedIn);
  const effectConfigRef = React.useRef<HostedAuthMenuEffectConfig>({
    initialMode,
    registrationAccountInput,
    showRegistrationInput,
    showProgress,
    copy,
    enabledExternalProviders: externalProvidersForBroker(externalAuthBroker),
  });
  const externalAuthBrokerRef = React.useRef<HostedAuthMenuExternalAuthBroker | null>(
    externalAuthBroker,
  );
  const onOutcomeRef = React.useRef<HostedSeamsAuthMenuProps['onOutcome']>(onOutcome);
  const onDemoEmailOtpRef =
    React.useRef<HostedSeamsAuthMenuProps['onDemoEmailOtp']>(onDemoEmailOtp);
  const terminalGateRef = React.useRef<HostedAuthMenuTerminalGate | null>(terminalGate);
  const forwardedOutcomeRef = React.useRef<HostedSeamsAuthMenuProps['onOutcome']>(() => {});
  const anchorRef = React.useRef<HTMLSpanElement | null>(null);
  effectConfigRef.current = {
    initialMode,
    registrationAccountInput,
    showRegistrationInput,
    showProgress,
    copy,
    enabledExternalProviders: externalProvidersForBroker(externalAuthBroker),
  };
  externalAuthBrokerRef.current = externalAuthBroker;
  onOutcomeRef.current = onOutcome;
  onDemoEmailOtpRef.current = onDemoEmailOtp;
  terminalGateRef.current = terminalGate;
  forwardedOutcomeRef.current = forwardHostedAuthMenuOutcome.bind(
    null,
    terminalGateRef,
    onOutcomeRef,
  );
  const effectConfigKey = hostedAuthMenuEffectConfigKey(effectConfigRef.current);

  React.useEffect(() => {
    const anchorElement = anchorRef.current;
    if (!seams || !anchorElement || typeof window === 'undefined') return undefined;
    if (terminalGateRef.current?.completed) return undefined;

    const config = effectConfigRef.current;
    const session = new HostedAuthMenuSessionController({
      seams,
      anchorElement,
      authMenuSessionId: createHostedAuthMenuSessionId(),
      initialMode: config.initialMode,
      registrationAccountInput: config.registrationAccountInput,
      showRegistrationInput: config.showRegistrationInput,
      showProgress: config.showProgress,
      copy: config.copy,
      externalAuthBroker: externalAuthBrokerRef,
      onDemoEmailOtp: onDemoEmailOtpRef,
      onOutcome: forwardedOutcomeRef,
    });
    session.start();
    return session.cleanup.bind(session);
  }, [seams, effectConfigKey]);

  return (
    <span
      ref={anchorRef}
      data-seams-auth-menu-host="true"
      aria-hidden="true"
      style={{
        display: 'block',
        width: 'min(100%, 420px)',
        // The wallet host measures the menu and publishes its height back onto
        // this element, so the anchor reserves the space the menu paints over.
        minHeight: 'var(--seams-auth-menu-height, 450px)',
      }}
    />
  );
};

export default HostedSeamsAuthMenu;
