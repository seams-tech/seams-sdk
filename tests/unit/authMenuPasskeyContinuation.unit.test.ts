import { expect, test } from '@playwright/test';
import type { SeamsWebContext } from '@/SeamsWeb/signingSurface/types';
import {
  cancelHostedPasskeyPreparation,
  prepareHostedPasskeyAccountSync,
  prepareHostedPasskeyLogin,
  startHostedPasskeyAccountSyncCredential,
} from '@/SeamsWeb/walletIframe/host/auth-menu/passkey';
import { loginAccountOptions } from '@/SeamsWeb/walletIframe/host/auth-menu/account-options';
import { AuthMenuSession } from '@/SeamsWeb/walletIframe/host/auth-menu/session';
import {
  buildHostedAuthMenuExternalAuthResolution,
  buildHostedAuthMenuOpenRequest,
  hostedAuthMenuExternalAuthRequestIdFromBoundary,
  hostedAuthMenuSessionIdFromBoundary,
} from '@/SeamsWeb/walletIframe/shared/messages';
import { walletIframeRequestIdFromBoundary } from '@/core/types/walletIframeIdentity';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import type { AppearanceConfig } from '@/core/types/seams';
import type { GoogleEmailOtpWalletAuthLoginFlow } from '@/SeamsWeb/publicApi/types';
import { createLinkDeviceFlowEvent, LinkDeviceEventPhase } from '@/core/types/sdkSentEvents';
import { IndexedDBManager } from '@/core/indexedDB';
import type { HostedRecoveryPort } from '@/SeamsWeb/walletIframe/host/recovery-port';

type AuthMenuSessionArgs = ConstructorParameters<typeof AuthMenuSession>[0];
type StartDeviceLinkingCallbacks = Parameters<AuthMenuSessionArgs['startDeviceLinking']>[1];

const APPEARANCE = {
  theme: { id: 'default', mode: 'dark', colors: {} },
  palette: 'default',
} as const satisfies AppearanceConfig;

const UNAVAILABLE_RECOVERY_PORT: HostedRecoveryPort = {
  prepare: async () => ({ kind: 'refused' }),
  createPasskey: async () => ({ kind: 'refused' }),
  finalize: async () => ({ kind: 'refused' }),
  cancel: async () => {},
};

async function unavailableRecoveredLogin(): Promise<never> {
  throw new Error('Recovered login fixture was not configured');
}

function authMenuSession(
  args: {
    mode?: 'login' | 'register';
    registrationAccountInput?: 'implicit_wallet' | 'sponsored_named_near_account';
    showRegistrationInput?: boolean;
    providers?: readonly 'google'[];
    beginGoogleEmailOtp?: (args: {
      idToken: string;
      mode: 'login' | 'register';
      signal: AbortSignal;
    }) => Promise<GoogleEmailOtpWalletAuthLoginFlow>;
    sendToParent?: (message: unknown) => void;
    startDeviceLinking?: AuthMenuSessionArgs['startDeviceLinking'];
  } = {},
): AuthMenuSession {
  const sessionId = hostedAuthMenuSessionIdFromBoundary(
    `auth-menu-session-${Math.random().toString(36).slice(2)}`,
  );
  if (!sessionId) throw new Error('auth-menu session fixture is invalid');
  const request = buildHostedAuthMenuOpenRequest({
    authMenuSessionId: sessionId,
    initialMode: args.mode,
    registrationAccountInput: args.registrationAccountInput,
    showRegistrationInput: args.showRegistrationInput,
    enabledExternalProviders: args.providers ?? [],
  });
  return new AuthMenuSession({
    request,
    requestId: walletIframeRequestIdFromBoundary(`auth-menu-request-${String(sessionId)}`),
    appearance: APPEARANCE,
    hostname: 'wallet.example.test',
    beginGoogleEmailOtp:
      args.beginGoogleEmailOtp ??
      (async () => {
        throw new Error('Google flow fixture was not configured');
      }),
    startDeviceLinking:
      args.startDeviceLinking ??
      (async () => {
        throw new Error('Device-linking flow fixture was not configured');
      }),
    cancelDeviceLinking: async () => {},
    recoveryPort: UNAVAILABLE_RECOVERY_PORT,
    prepareRecoveredLogin: unavailableRecoveredLogin,
    sendToParent: args.sendToParent ?? (() => {}),
  });
}

function openAndStartPasskeyDeviceLinking(session: AuthMenuSession): void {
  Reflect.apply(Reflect.get(session, 'openLinkDevice'), session, []);
  Reflect.apply(Reflect.get(session, 'startSelectedDeviceLinking'), session, []);
}

function googleLoginFlow(
  delivery: GoogleEmailOtpWalletAuthLoginFlow['delivery'] = {
    kind: 'provider',
    status: 'sent',
    emailHint: 'g***@example.test',
  },
): GoogleEmailOtpWalletAuthLoginFlow {
  const flow: GoogleEmailOtpWalletAuthLoginFlow = {
    kind: 'google_email_otp_wallet_auth_flow_v1',
    flowId: 'google-flow-test',
    requestedMode: 'login',
    mode: 'login',
    state: 'challenge_sent',
    walletId: walletIdFromString('wallet-google-test'),
    emailHint: 'g***@example.test',
    prompt: {
      title: 'Verify your email',
      description: 'Enter the code we sent.',
      submitLabel: 'Verify',
      helperText: '',
    },
    delivery,
    expiresAtMs: Date.now() + 60_000,
    cancel: async () => {},
    resend: async () => ({
      ok: false,
      error: { code: 'flow_expired', message: 'fixture resend is unavailable' },
    }),
    submit: async () => ({
      ok: false,
      error: { code: 'flow_expired', message: 'fixture submit is unavailable' },
    }),
  };
  return flow;
}

function contextForPreparedAccountSync(calls: unknown[]): SeamsWebContext {
  return {
    configs: {
      network: { relayer: { url: 'https://relay.example.test' } },
    },
    signingEngine: {
      getRpId: () => 'wallet.example.test',
      getAuthenticationCredentialsSerialized: (args: unknown) => {
        calls.push(args);
        return Promise.resolve({ id: 'credential', rawId: 'credential', response: {} });
      },
    },
  } as unknown as SeamsWebContext;
}

test.describe('hosted auth-menu passkey continuation', () => {
  test('uses verified account sync when a recent local wallet has no readable capability subject', async () => {
    const originalFetch = globalThis.fetch;
    const originalListActiveWalletSigners = IndexedDBManager.listActiveWalletSigners;
    const walletId = 'river-garden-2fprg7';
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({
          ok: true,
          challengeId: 'sync-challenge-local-repair',
          challengeB64u: 'sync-challenge-local-repair-b64u',
          credentialIds: ['credential-local-repair'],
          walletBinding: {
            walletId,
            nearAccountId: `${walletId}.testnet`,
            nearEd25519SigningKeyId: 'ed25519ks_local_repair',
            rpId: 'wallet.example.test',
            credentialIdB64u: 'credential-local-repair',
            signerSlot: 4,
          },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    IndexedDBManager.listActiveWalletSigners = async () => {
      throw new Error('local capability projection is unavailable');
    };
    try {
      const authMenuSessionId = hostedAuthMenuSessionIdFromBoundary('auth-menu-local-repair-test');
      if (!authMenuSessionId) throw new Error('auth-menu session fixture is invalid');
      const prepared = await prepareHostedPasskeyLogin({
        context: contextForPreparedAccountSync([]),
        walletId,
        authMenuSessionId,
        requestId: walletIframeRequestIdFromBoundary('auth-menu-local-repair-request'),
        cancellation: { kind: 'abort_signal', signal: new AbortController().signal },
      });

      expect(prepared).toMatchObject({
        kind: 'hosted_passkey_account_sync_prepared_v1',
        challenge: {
          walletId,
          syncOptions: {
            challengeId: 'sync-challenge-local-repair',
            credentialIds: ['credential-local-repair'],
          },
        },
      });
      cancelHostedPasskeyPreparation(prepared);
    } finally {
      IndexedDBManager.listActiveWalletSigners = originalListActiveWalletSigners;
      globalThis.fetch = originalFetch;
    }
  });

  test('prepares sync options before the CTA and starts credential collection inline', async () => {
    const originalFetch = globalThis.fetch;
    const calls: unknown[] = [];
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({
          ok: true,
          challengeId: 'sync-challenge-1',
          challengeB64u: 'challenge-b64u',
          credentialIds: ['credential-id'],
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    try {
      const authMenuSessionId = hostedAuthMenuSessionIdFromBoundary('auth-menu-sync-test');
      if (!authMenuSessionId) throw new Error('auth-menu session fixture is invalid');
      const requestId = walletIframeRequestIdFromBoundary('auth-menu-sync-request');
      const prepared = await prepareHostedPasskeyAccountSync({
        context: contextForPreparedAccountSync(calls),
        walletId: null,
        authMenuSessionId,
        requestId,
        cancellation: { kind: 'abort_signal', signal: new AbortController().signal },
      });

      const authority = startHostedPasskeyAccountSyncCredential(prepared);
      expect(calls).toHaveLength(1);
      expect(calls[0]).toMatchObject({
        subjectId: 'account-sync',
        challengeB64u: 'challenge-b64u',
        includeSecondPrfOutput: false,
      });
      await expect(authority).resolves.toMatchObject({ id: 'credential' });

      cancelHostedPasskeyPreparation(prepared);
      expect(() => startHostedPasskeyAccountSyncCredential(prepared)).toThrow(/no longer usable/);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('keeps the auth-menu outcome resolver alive across an early close', async () => {
    const session = authMenuSession();
    const outcomePromise = session.waitForOutcome();
    session.cancel('close_button');

    await expect(outcomePromise).resolves.toMatchObject({
      kind: 'cancelled',
      reason: 'close_button',
    });
  });

  test('completes authentication after the linking flow establishes the signing session', async () => {
    let onEvent: StartDeviceLinkingCallbacks['onEvent'] | null = null;
    let resolveLinkDevice: ((result: { qrCodeDataURL: string }) => void) | null = null;
    const session = authMenuSession({
      startDeviceLinking: async (_targetFactor, callbacks) => {
        onEvent = callbacks.onEvent;
        return await new Promise((resolve) => {
          resolveLinkDevice = resolve;
        });
      },
    });
    const outcome = session.waitForOutcome();
    openAndStartPasskeyDeviceLinking(session);
    if (!onEvent) throw new Error('Device-linking flow did not publish its event callback');
    onEvent(
      createLinkDeviceFlowEvent({
        flowId: 'linked-device-terminal-test',
        phase: LinkDeviceEventPhase.STEP_02_QR_SCAN_STARTED,
        status: 'succeeded',
        message: 'Linked device active',
        walletId: 'wallet-linked-device-test',
        data: { enrollmentId: 'enrollment-linked-device-test' },
      }),
    );

    await expect(outcome).resolves.toMatchObject({
      kind: 'authenticated',
      walletId: 'wallet-linked-device-test',
      method: 'passkey',
    });
    expect(session.state.kind).toBe('complete');
    if (!resolveLinkDevice) throw new Error('Device-linking flow did not start');
    resolveLinkDevice({ qrCodeDataURL: 'data:image/svg+xml,late-result' });
    await Promise.resolve();
  });

  test('shows a recoverable error when linked activation omits its wallet identity', async () => {
    let onEvent: StartDeviceLinkingCallbacks['onEvent'] | null = null;
    const session = authMenuSession({
      startDeviceLinking: async (_targetFactor, callbacks) => {
        onEvent = callbacks.onEvent;
        return await new Promise<never>(() => {});
      },
    });

    openAndStartPasskeyDeviceLinking(session);
    if (!onEvent) throw new Error('Device-linking flow did not publish its event callback');
    onEvent(
      createLinkDeviceFlowEvent({
        flowId: 'linked-device-missing-wallet-test',
        phase: LinkDeviceEventPhase.STEP_02_QR_SCAN_STARTED,
        status: 'succeeded',
        message: 'Linked device active',
      }),
    );

    expect(session.state).toMatchObject({
      kind: 'link_device',
      viewModel: {
        linkDevice: {
          kind: 'activation_error',
          message: 'Linked-device activation omitted its wallet identity',
        },
      },
    });
    session.cleanup();
  });

  test('does not return to the QR screen after linked passkey creation starts', async () => {
    let callbacks: StartDeviceLinkingCallbacks | null = null;
    let resolveLinkDevice: ((result: { qrCodeDataURL: string }) => void) | null = null;
    let resolvePasskey: (() => void) | null = null;
    const session = authMenuSession({
      startDeviceLinking: async (_targetFactor, nextCallbacks) => {
        callbacks = nextCallbacks;
        return await new Promise((resolve) => {
          resolveLinkDevice = resolve;
        });
      },
    });

    openAndStartPasskeyDeviceLinking(session);
    if (!callbacks) throw new Error('Device-linking flow did not publish its callbacks');
    callbacks.onTargetFactorRequired({
      kind: 'linked_device_target_passkey_activation_v1',
      createPasskey: async () => {
        await new Promise<void>((resolve) => {
          resolvePasskey = resolve;
        });
      },
    });
    Reflect.apply(Reflect.get(session, 'completeLinkDeviceOpen'), session, [
      Reflect.get(session, 'deviceLinkGeneration'),
      { qrCodeDataURL: 'data:image/svg+xml,fixture' },
    ]);
    Reflect.apply(Reflect.get(session, 'createLinkedDevicePasskey'), session, []);

    expect(session.state).toMatchObject({
      kind: 'link_device',
      viewModel: { linkDevice: { kind: 'creating_passkey' } },
    });
    if (!resolveLinkDevice) throw new Error('Device-linking flow did not start');
    resolveLinkDevice({ qrCodeDataURL: 'data:image/svg+xml,late-result' });
    await Promise.resolve();

    expect(session.state).toMatchObject({
      kind: 'link_device',
      viewModel: { linkDevice: { kind: 'creating_passkey' } },
    });
    resolvePasskey?.();
    session.cleanup();
  });

  test('links with Email OTP without starting a Passkey ceremony', async () => {
    let callbacks: StartDeviceLinkingCallbacks | null = null;
    let selectedFactor: string | null = null;
    let sendCalls = 0;
    const submittedCodes: string[] = [];
    const session = authMenuSession({
      startDeviceLinking: async (targetFactor, nextCallbacks) => {
        selectedFactor = targetFactor.kind;
        callbacks = nextCallbacks;
        return await new Promise<never>(() => {});
      },
    });
    const outcome = session.waitForOutcome();
    Reflect.apply(Reflect.get(session, 'openLinkDevice'), session, []);
    Reflect.apply(Reflect.get(session, 'selectLinkedDeviceTargetFactor'), session, [
      { kind: 'email_otp' },
    ]);
    Reflect.apply(Reflect.get(session, 'startSelectedDeviceLinking'), session, []);
    if (!callbacks) throw new Error('Device-linking flow did not publish its callbacks');
    callbacks.onTargetFactorRequired({
      kind: 'linked_device_target_email_otp_activation_v1',
      state: { kind: 'sending', maskedEmailHint: 'a***@example.test' },
      sendCode: async () => {
        sendCalls += 1;
      },
      resendCode: async () => undefined,
      submitCode: async (otpCode) => {
        submittedCodes.push(otpCode);
      },
    });
    await Promise.resolve();
    callbacks.onTargetFactorRequired({
      kind: 'linked_device_target_email_otp_activation_v1',
      state: {
        kind: 'code_input',
        maskedEmailHint: 'a***@example.test',
        expiresAtMs: Date.now() + 60_000,
        resendAvailableAtMs: Date.now(),
      },
      sendCode: async () => undefined,
      resendCode: async () => undefined,
      submitCode: async (otpCode) => {
        submittedCodes.push(otpCode);
      },
    });
    Reflect.apply(Reflect.get(session, 'changeLinkedDeviceEmailOtpCode'), session, ['123456']);
    await Promise.resolve();
    callbacks.onEvent(
      createLinkDeviceFlowEvent({
        flowId: 'linked-device-email-terminal-test',
        phase: LinkDeviceEventPhase.STEP_02_QR_SCAN_STARTED,
        status: 'succeeded',
        message: 'Linked device active',
        walletId: 'wallet-linked-email-device-test',
        data: { enrollmentId: 'enrollment-linked-email-device-test' },
      }),
    );

    expect(selectedFactor).toBe('email_otp');
    expect(sendCalls).toBe(1);
    expect(submittedCodes).toEqual(['123456']);
    await expect(outcome).resolves.toMatchObject({
      kind: 'authenticated',
      walletId: 'wallet-linked-email-device-test',
      method: 'google_email_otp',
    });
  });

  test('does not prepare sponsored registration until its required name is entered', () => {
    const session = authMenuSession({
      mode: 'register',
      registrationAccountInput: 'sponsored_named_near_account',
    });
    let preparationCount = 0;
    session.setRegistrationPreparation(async () => {
      preparationCount += 1;
      throw new Error('registration preparation should wait for input');
    });

    expect(preparationCount).toBe(0);
    expect(session.state.kind).toBe('preparing');
    if (session.state.kind === 'preparing') {
      expect(session.state.viewModel.kind).toBe('passkey');
      expect(session.state.viewModel.mode).toBe('register');
      expect(session.state.viewModel.showRegistrationInput).toBe(true);
      expect(session.state.viewModel.passkeyName).toBe('');
      expect(session.state.viewModel.status).toEqual({
        kind: 'idle',
        interaction: 'awaiting_input',
      });
    }
    session.cleanup();
  });

  test('filters email-OTP-only accounts and keeps linked-device accounts in the selector', () => {
    const options = loginAccountOptions({
      walletIds: ['wallet-passkey', 'wallet-email', 'wallet-linked'],
      accountIds: [],
      accounts: [
        {
          walletId: 'wallet-passkey',
          nearAccountId: 'passkey.testnet',
          displayName: 'Passkey wallet',
          signerSlot: 0,
          authMethod: 'passkey',
        },
        {
          walletId: 'wallet-email',
          nearAccountId: 'email.testnet',
          displayName: 'Email wallet',
          signerSlot: 0,
          authMethod: 'email_otp',
        },
        {
          walletId: 'wallet-linked',
          nearAccountId: 'linked.testnet',
          displayName: 'Linked wallet',
          signerSlot: 0,
          authMethod: 'linked_device',
        },
      ],
      lastUsedAccount: null,
    });

    expect(options).toEqual([
      { walletId: 'wallet-passkey', displayName: 'Passkey wallet' },
      { walletId: 'wallet-linked', displayName: 'Linked wallet' },
    ]);
  });

  test('requires exact external-auth request identity before starting Google OTP', async () => {
    const receivedTokens: string[] = [];
    const session = authMenuSession({
      providers: ['google'],
      beginGoogleEmailOtp: async ({ idToken }) => {
        receivedTokens.push(idToken);
        return googleLoginFlow();
      },
    });
    const externalRequest = session.requestExternalAuth('google');
    if (!externalRequest) throw new Error('external auth request fixture is invalid');
    const wrongRequestId = walletIframeRequestIdFromBoundary('different-open-request');
    const wrongResolution = buildHostedAuthMenuExternalAuthResolution({
      authMenuSessionId: externalRequest.authMenuSessionId,
      externalAuthRequestId: externalRequest.externalAuthRequestId,
      requestId: wrongRequestId,
      evidence: { kind: 'google_id_token', idToken: 'wrong-request-token' },
    });
    expect(session.acceptExternalAuthResolution(wrongResolution)).toBe(false);
    expect(session.state.kind).toBe('awaiting_external_auth');

    const requestId = session.identity.requestId;
    const correctResolution = buildHostedAuthMenuExternalAuthResolution({
      authMenuSessionId: externalRequest.authMenuSessionId,
      externalAuthRequestId: externalRequest.externalAuthRequestId,
      requestId,
      evidence: { kind: 'google_id_token', idToken: 'correct-token' },
    });
    expect(session.acceptExternalAuthResolution(correctResolution)).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(receivedTokens).toEqual(['correct-token']);
    expect(session.state.kind).toBe('google_login');
  });

  test('forwards demo Google OTP delivery to the app-origin auth-menu session', async () => {
    const messages: unknown[] = [];
    const session = authMenuSession({
      providers: ['google'],
      beginGoogleEmailOtp: async () =>
        googleLoginFlow({
          kind: 'demo_code_response',
          status: 'sent',
          emailHint: 'g***@example.test',
          otpCode: '654321',
        }),
      sendToParent: messages.push.bind(messages),
    });
    const externalRequest = session.requestExternalAuth('google');
    if (!externalRequest) throw new Error('external auth request fixture is invalid');
    const resolution = buildHostedAuthMenuExternalAuthResolution({
      authMenuSessionId: externalRequest.authMenuSessionId,
      externalAuthRequestId: externalRequest.externalAuthRequestId,
      requestId: session.identity.requestId,
      evidence: { kind: 'google_id_token', idToken: 'demo-token' },
    });

    expect(session.acceptExternalAuthResolution(resolution)).toBe(true);
    await expect.poll(() => messages.length).toBe(2);
    expect(messages[1]).toMatchObject({
      type: 'AUTH_MENU_DEMO_EMAIL_OTP_DELIVERY',
      requestId: session.identity.requestId,
      payload: {
        kind: 'hosted_auth_menu_demo_email_otp_delivery_v1',
        authMenuSessionId: session.identity.authMenuSessionId,
        delivery: { otpCode: '654321' },
      },
    });
    session.cleanup();
  });

  test('keeps Google OTP start failures visible until the user retries', async () => {
    const messages: unknown[] = [];
    const session = authMenuSession({
      providers: ['google'],
      beginGoogleEmailOtp: async () => {
        throw new Error('Email delivery failed');
      },
      sendToParent: messages.push.bind(messages),
    });
    const externalRequest = session.requestExternalAuth('google');
    if (!externalRequest) throw new Error('external auth request fixture is invalid');
    const resolution = buildHostedAuthMenuExternalAuthResolution({
      authMenuSessionId: externalRequest.authMenuSessionId,
      externalAuthRequestId: externalRequest.externalAuthRequestId,
      requestId: session.identity.requestId,
      evidence: { kind: 'google_id_token', idToken: 'failing-token' },
    });

    expect(session.acceptExternalAuthResolution(resolution)).toBe(true);
    await expect.poll(() => session.state.kind).toBe('preparing');
    if (session.state.kind === 'preparing') {
      expect(session.state.viewModel.status).toEqual({
        kind: 'recoverable',
        reason: 'error',
        message: 'Email delivery failed',
      });
    }
    expect(messages).toHaveLength(2);
    expect(messages).toContainEqual({
      type: 'AUTH_MENU_ERROR',
      requestId: session.identity.requestId,
      payload: {
        kind: 'hosted_auth_menu_error_v1',
        authMenuSessionId: session.identity.authMenuSessionId,
        mode: 'login',
        message: 'Email delivery failed',
      },
    });
    session.cleanup();
  });

  test('marks idle prepared passkey state expired without starting a replacement preparation', async () => {
    const originalFetch = globalThis.fetch;
    const originalSetTimeout = globalThis.setTimeout;
    const originalClearTimeout = globalThis.clearTimeout;
    const messages: unknown[] = [];
    let expiryCallback: (() => void) | null = null;
    let preparationCount = 0;
    let preparationDeadlineCleared = false;
    const preparationDeadlineHandle = 2 as ReturnType<typeof setTimeout>;
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({
          ok: true,
          challengeId: 'expiry-challenge',
          challengeB64u: 'expiry-challenge-b64u',
          credentialIds: [],
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    globalThis.setTimeout = ((handler: TimerHandler, delay?: number, ...args: unknown[]) => {
      if (typeof handler === 'function' && Number(delay) === 20_000) {
        return preparationDeadlineHandle;
      }
      if (typeof handler === 'function' && Number(delay) > 60_000) {
        expiryCallback = () => handler(...args);
        return 1 as ReturnType<typeof setTimeout>;
      }
      return originalSetTimeout(handler, delay, ...args);
    }) as typeof setTimeout;
    globalThis.clearTimeout = ((handle: ReturnType<typeof setTimeout>) => {
      if (handle === preparationDeadlineHandle) {
        preparationDeadlineCleared = true;
        return;
      }
      if (handle !== 1) originalClearTimeout(handle);
    }) as typeof clearTimeout;
    try {
      const session = authMenuSession({ sendToParent: messages.push.bind(messages) });
      session.setLoginPreparation({
        accountOptions: [],
        selectedWalletId: null,
        prepare: async (_walletId, cancellation) => {
          preparationCount += 1;
          return await prepareHostedPasskeyAccountSync({
            context: contextForPreparedAccountSync([]),
            walletId: null,
            authMenuSessionId: session.identity.authMenuSessionId,
            requestId: session.identity.requestId,
            cancellation,
          });
        },
      });
      await expect.poll(() => session.state.kind, { timeout: 2_000 }).toBe('ready');
      expect(preparationDeadlineCleared).toBe(true);
      expect(expiryCallback).not.toBeNull();
      expiryCallback?.();
      expect(preparationCount).toBe(1);
      expect(session.state.kind).toBe('preparing');
      if (session.state.kind === 'preparing') {
        expect(session.state.viewModel.status).toEqual({
          kind: 'recoverable',
          reason: 'expired',
          message: 'Passkey preparation expired. Retry to continue.',
        });
      }
      expect(messages).toContainEqual({
        type: 'AUTH_MENU_ERROR',
        requestId: session.identity.requestId,
        payload: {
          kind: 'hosted_auth_menu_error_v1',
          authMenuSessionId: session.identity.authMenuSessionId,
          mode: 'login',
          message: 'Passkey preparation expired. Retry to continue.',
        },
      });
      session.cleanup();
    } finally {
      globalThis.fetch = originalFetch;
      globalThis.setTimeout = originalSetTimeout;
      globalThis.clearTimeout = originalClearTimeout;
    }
  });

  test('times out a never-settling registration preparation and enables retry', async () => {
    const originalSetTimeout = globalThis.setTimeout;
    const originalClearTimeout = globalThis.clearTimeout;
    const messages: unknown[] = [];
    let deadlineCallback: (() => void) | null = null;
    let preparationSignal: AbortSignal | null = null;
    let deadlineCleared = false;
    const deadlineHandle = 2 as ReturnType<typeof setTimeout>;
    globalThis.setTimeout = ((handler: TimerHandler, delay?: number, ...args: unknown[]) => {
      if (typeof handler === 'function' && Number(delay) === 20_000) {
        deadlineCallback = () => handler(...args);
        return deadlineHandle;
      }
      return originalSetTimeout(handler, delay, ...args);
    }) as typeof setTimeout;
    globalThis.clearTimeout = ((handle: ReturnType<typeof setTimeout>) => {
      if (handle === deadlineHandle) {
        deadlineCleared = true;
        return;
      }
      originalClearTimeout(handle);
    }) as typeof clearTimeout;
    try {
      const session = authMenuSession({
        mode: 'register',
        sendToParent: messages.push.bind(messages),
      });
      session.setRegistrationPreparation((_registrationValue, cancellation) => {
        preparationSignal = cancellation.signal;
        return new Promise<never>(() => {});
      });
      await Promise.resolve();

      expect(deadlineCallback).not.toBeNull();
      expect(session.state.kind).toBe('preparing');
      deadlineCallback?.();

      expect(deadlineCleared).toBe(true);
      expect(preparationSignal?.aborted).toBe(true);
      expect(session.state.kind).toBe('preparing');
      if (session.state.kind === 'preparing') {
        expect(session.state.viewModel.status).toEqual({
          kind: 'recoverable',
          reason: 'error',
          message: 'Passkey preparation timed out. Retry to continue.',
        });
      }
      expect(messages).toContainEqual({
        type: 'AUTH_MENU_ERROR',
        requestId: session.identity.requestId,
        payload: {
          kind: 'hosted_auth_menu_error_v1',
          authMenuSessionId: session.identity.authMenuSessionId,
          mode: 'register',
          message: 'Passkey preparation timed out. Retry to continue.',
        },
      });
      session.cleanup();
    } finally {
      globalThis.setTimeout = originalSetTimeout;
      globalThis.clearTimeout = originalClearTimeout;
    }
  });
});
