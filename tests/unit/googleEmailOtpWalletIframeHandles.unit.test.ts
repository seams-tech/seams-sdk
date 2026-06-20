import { expect, test } from '@playwright/test';
import { createEmailOtpWalletIframeHandlers } from '@/SeamsWeb/walletIframe/host/handlers/emailOtp';
import type { HandlerDeps } from '@/SeamsWeb/walletIframe/host/handlers/walletIframeHandler.types';
import type {
  GoogleEmailOtpWalletAuthFlow,
  GoogleEmailOtpWalletAuthLoginFlow,
  GoogleEmailOtpWalletAuthRegistrationCompleted,
  GoogleEmailOtpWalletAuthRegistrationFlow,
  GoogleEmailOtpWalletAuthSubmitSuccess,
} from '@/SeamsWeb/publicApi/types';
import type {
  PMGoogleEmailOtpWalletAuthHandlePayload,
  PMGoogleEmailOtpWalletAuthSubmitPayload,
  PMGoogleEmailOtpWalletAuthWireFlow,
} from '@/SeamsWeb/walletIframe/shared/messages';
import { walletIdFromString } from '@shared/utils/registrationIntent';

function walletId(value: string) {
  return walletIdFromString(value);
}

function submitSuccess(value: {
  walletId?: string;
  mode?: 'login' | 'register';
} = {}): GoogleEmailOtpWalletAuthSubmitSuccess {
  return {
    walletId: walletId(value.walletId ?? 'alice.testnet'),
    mode: value.mode ?? 'login',
    session: {
      login: {
        isLoggedIn: true,
        nearAccountId: walletId(value.walletId ?? 'alice.testnet'),
        publicKey: null,
        userData: null,
      },
      signingSession: null,
    },
  };
}

function registrationCompleted(value: {
  walletId?: string;
} = {}): GoogleEmailOtpWalletAuthRegistrationCompleted {
  return {
    walletId: walletId(value.walletId ?? 'alice.testnet'),
    mode: 'register',
    session: {
      login: {
        isLoggedIn: true,
        nearAccountId: walletId(value.walletId ?? 'alice.testnet'),
        publicKey: null,
        userData: null,
      },
      signingSession: null,
    },
  };
}

function makeLoginFlow(overrides?: Partial<GoogleEmailOtpWalletAuthLoginFlow>): GoogleEmailOtpWalletAuthLoginFlow {
  return {
    kind: 'google_email_otp_wallet_auth_flow_v1',
    state: 'challenge_sent',
    flowId: 'login-flow-1',
    requestedMode: 'login',
    mode: 'login',
    walletId: walletId('alice.testnet'),
    emailHint: 'alice@example.com',
    prompt: {
      title: 'Check your email',
      description: 'Enter the code.',
      submitLabel: 'Unlock wallet',
      helperText: 'Use the code from your email.',
    },
    delivery: 'sent',
    expiresAtMs: Date.now() + 60_000,
    resend: async () => ({ ok: true, value: makeLoginFlow({ flowId: 'flow-resend' }) }),
    submit: async () => ({
      ok: true,
      value: submitSuccess(),
    }),
    cancel: async () => undefined,
    ...overrides,
  };
}

function makeRegistrationFlow(
  overrides?: Partial<GoogleEmailOtpWalletAuthRegistrationFlow>,
): GoogleEmailOtpWalletAuthRegistrationFlow {
  return {
    kind: 'google_email_otp_wallet_auth_flow_v1',
    state: 'registration_ready',
    flowId: 'registration-flow-1',
    requestedMode: 'register',
    mode: 'register',
    walletId: walletId('alice.testnet'),
    emailHint: 'alice@example.com',
    prompt: {
      title: 'Create your Email OTP wallet',
      description: 'Google verified alice@example.com.',
      submitLabel: 'Create wallet',
      helperText: 'Choose this wallet name or generate another one.',
    },
    expiresAtMs: Date.now() + 60_000,
    completeRegistration: async () => ({
      ok: true,
      value: registrationCompleted(),
    }),
    rerollWalletId: async () => ({
      ok: true,
      value: makeRegistrationFlow({
        flowId: 'registration-flow-rerolled',
        walletId: walletId('alice-2.testnet'),
      }),
    }),
    cancel: async () => undefined,
    ...overrides,
  };
}

function makeHarness(flow: GoogleEmailOtpWalletAuthFlow): {
  handlers: ReturnType<typeof createEmailOtpWalletIframeHandlers>;
  posted: unknown[];
} {
  const posted: unknown[] = [];
  const deps: HandlerDeps = {
    getSeamsWeb: () =>
      ({
        auth: {
          beginGoogleEmailOtpWalletAuth: async () => ({ ok: true, value: flow }),
        },
      }) as unknown as ReturnType<HandlerDeps['getSeamsWeb']>,
    post: (message) => {
      posted.push(message);
    },
    postProgress: () => undefined,
    isCancelled: () => false,
    respondIfCancelled: () => false,
  };
  return { handlers: createEmailOtpWalletIframeHandlers(deps), posted };
}

async function beginFlow(input?: { flow?: GoogleEmailOtpWalletAuthFlow }): Promise<{
  handlers: ReturnType<typeof createEmailOtpWalletIframeHandlers>;
  posted: unknown[];
  wireFlow: PMGoogleEmailOtpWalletAuthWireFlow;
}> {
  const { handlers, posted } = makeHarness(input?.flow ?? makeLoginFlow());
  await handlers.PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH?.({
    type: 'PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH',
    requestId: 'begin-1',
    payload: { idToken: 'google-id-token', mode: input?.flow?.mode ?? 'login' },
  });
  const response = posted.at(-1) as {
    payload: { result: { ok: true; value: unknown } };
  };
  return { handlers, posted, wireFlow: parseWireFlow(response.payload.result.value) };
}

function parseWireFlow(value: unknown): PMGoogleEmailOtpWalletAuthWireFlow {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('expected wire flow object');
  }
  const flow = value as Record<string, unknown>;
  const mode = flow.mode;
  const requestedMode = flow.requestedMode;
  if (
    typeof flow.flowHandleId !== 'string' ||
    typeof flow.flowId !== 'string' ||
    typeof flow.walletId !== 'string' ||
    typeof flow.emailHint !== 'string' ||
    typeof flow.expiresAtMs !== 'number' ||
    (mode !== 'login' && mode !== 'register') ||
    (requestedMode !== 'login' && requestedMode !== 'register')
  ) {
    throw new Error('wire flow shape is invalid');
  }
  if (mode === 'login') {
    if (flow.state !== 'challenge_sent' || flow.delivery !== 'sent') {
      throw new Error('login wire flow shape is invalid');
    }
  } else if (flow.state !== 'registration_ready' || 'delivery' in flow) {
    throw new Error('registration wire flow shape is invalid');
  }
  return value as PMGoogleEmailOtpWalletAuthWireFlow;
}

function handlePayload(
  wireFlow: PMGoogleEmailOtpWalletAuthWireFlow,
): PMGoogleEmailOtpWalletAuthHandlePayload {
  return {
    flowHandleId: wireFlow.flowHandleId,
    flowId: wireFlow.flowId,
    walletId: wireFlow.walletId,
    mode: wireFlow.mode,
  };
}

function submitPayload(
  wireFlow: PMGoogleEmailOtpWalletAuthWireFlow,
  otpCode: string,
): PMGoogleEmailOtpWalletAuthSubmitPayload {
  return { ...handlePayload(wireFlow), otpCode };
}

test.describe('Google Email OTP wallet iframe flow handles', () => {
  test('serializes login and registration flow shapes separately', async () => {
    const login = await beginFlow({ flow: makeLoginFlow() });
    expect(login.wireFlow).toMatchObject({
      state: 'challenge_sent',
      mode: 'login',
      delivery: 'sent',
    });

    const registration = await beginFlow({ flow: makeRegistrationFlow() });
    expect(registration.wireFlow).toMatchObject({
      state: 'registration_ready',
      mode: 'register',
      walletId: 'alice.testnet',
    });
    expect(registration.wireFlow).not.toHaveProperty('delivery');
  });

  test('registration begin wire result exposes only display metadata', async () => {
    const leakedRegistrationFlow = Object.assign(makeRegistrationFlow(), {
      appSessionJwt: 'secret-app-session',
      runtimePolicyScope: { orgId: 'org-1' },
      recoveryKeys: ['secret-code-1'],
      bootstrap: { secret: true },
      googleEmailOtpRegistrationOfferId: 'offer-secret',
      googleEmailOtpRegistrationAttemptId: 'attempt-secret',
    });
    const registration = await beginFlow({
      flow: leakedRegistrationFlow as GoogleEmailOtpWalletAuthRegistrationFlow,
    });

    expect(registration.wireFlow).toMatchObject({
      state: 'registration_ready',
      mode: 'register',
      walletId: 'alice.testnet',
      emailHint: 'alice@example.com',
    });
    expect(JSON.stringify(registration.wireFlow)).not.toContain('appSessionJwt');
    expect(JSON.stringify(registration.wireFlow)).not.toContain('runtimePolicyScope');
    expect(JSON.stringify(registration.wireFlow)).not.toContain('recoveryKeys');
    expect(JSON.stringify(registration.wireFlow)).not.toContain('bootstrap');
    expect(JSON.stringify(registration.wireFlow)).not.toContain('offer-secret');
    expect(JSON.stringify(registration.wireFlow)).not.toContain('attempt-secret');
  });

  test('rejects register begin messages with OTP challenge fields', async () => {
    const { handlers } = makeHarness(makeRegistrationFlow());
    const invalidPayload = {
      idToken: 'google-id-token',
      mode: 'register' as const,
      otpCode: '123456',
    };

    await expect(
      handlers.PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH?.({
        type: 'PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH',
        requestId: 'begin-register-otp-field',
        payload: invalidPayload,
      }),
    ).rejects.toThrow(/must not include otpCode/);
  });

  test('rejects a handle used with the wrong wallet id', async () => {
    const { handlers, wireFlow } = await beginFlow();

    await expect(
      handlers.PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_SUBMIT?.({
        type: 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_SUBMIT',
        requestId: 'submit-1',
        payload: {
          ...handlePayload(wireFlow),
          walletId: 'mallory.testnet',
          otpCode: '123456',
        },
      }),
    ).rejects.toThrow(/does not match wallet/);
  });

  test('burns a login handle after successful submit', async () => {
    const { handlers, wireFlow } = await beginFlow();
    const payload = submitPayload(wireFlow, '123456');

    await expect(
      handlers.PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_SUBMIT?.({
        type: 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_SUBMIT',
        requestId: 'submit-1',
        payload,
      }),
    ).resolves.toBeUndefined();

    await expect(
      handlers.PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_SUBMIT?.({
        type: 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_SUBMIT',
        requestId: 'submit-2',
        payload,
      }),
    ).rejects.toThrow(/not active/);
  });

  test('keeps a login handle active after failed submit result', async () => {
    let attempts = 0;
    const { handlers, posted, wireFlow } = await beginFlow({
      flow: makeLoginFlow({
        submit: async () => {
          attempts += 1;
          if (attempts === 1) {
            return {
              ok: false,
              error: {
                code: 'email_otp_invalid_code',
                message: 'Enter the 6-digit code from your email.',
              },
            };
          }
          return { ok: true, value: submitSuccess() };
        },
      }),
    });
    const payload = submitPayload(wireFlow, '000000');

    await handlers.PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_SUBMIT?.({
      type: 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_SUBMIT',
      requestId: 'submit-invalid',
      payload,
    });
    expect(
      (posted.at(-1) as { payload: { result: { ok: boolean } } }).payload.result.ok,
    ).toBe(false);

    await handlers.PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_SUBMIT?.({
      type: 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_SUBMIT',
      requestId: 'submit-retry',
      payload: { ...payload, otpCode: '123456' },
    });
    expect(
      (posted.at(-1) as { payload: { result: { ok: boolean } } }).payload.result.ok,
    ).toBe(true);
  });

  test('burns a registration handle after successful completion', async () => {
    const { handlers, wireFlow } = await beginFlow({ flow: makeRegistrationFlow() });
    const payload = handlePayload(wireFlow);

    await expect(
      handlers.PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION?.({
        type: 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION',
        requestId: 'complete-1',
        payload,
      }),
    ).resolves.toBeUndefined();

    await expect(
      handlers.PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION?.({
        type: 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION',
        requestId: 'complete-2',
        payload,
      }),
    ).rejects.toThrow(/not active/);
  });

  test('strips recovery codes from iframe registration completion result', async () => {
    const leakedCompletion = Object.assign(registrationCompleted(), {
      recoveryKeys: ['secret-code-1'],
      appSessionJwt: 'secret-app-session',
      bootstrap: { secret: true },
    });
    const { handlers, posted, wireFlow } = await beginFlow({
      flow: makeRegistrationFlow({
        completeRegistration: async () => ({
          ok: true,
          value: leakedCompletion,
        }),
      }),
    });

    await handlers.PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION?.({
      type: 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION',
      requestId: 'complete-strip-secrets',
      payload: handlePayload(wireFlow),
    });

    const response = posted.at(-1) as {
      payload: { result: { ok: true; value: Record<string, unknown> } };
    };
    expect(response.payload.result.value).toMatchObject({
      walletId: 'alice.testnet',
      mode: 'register',
    });
    expect(JSON.stringify(response.payload.result.value)).not.toContain('recoveryKeys');
    expect(JSON.stringify(response.payload.result.value)).not.toContain('secret-code-1');
    expect(JSON.stringify(response.payload.result.value)).not.toContain('secret-app-session');
    expect(JSON.stringify(response.payload.result.value)).not.toContain('bootstrap');
  });

  test('rejects registration completion with OTP fields without burning the handle', async () => {
    const { handlers, wireFlow } = await beginFlow({ flow: makeRegistrationFlow() });
    const payload = handlePayload(wireFlow);
    const invalidPayload = { ...payload, otpCode: '123456' };

    await expect(
      handlers.PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION?.({
        type: 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION',
        requestId: 'complete-with-otp-field',
        payload: invalidPayload,
      }),
    ).rejects.toThrow(/must not include otpCode/);

    await expect(
      handlers.PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION?.({
        type: 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION',
        requestId: 'complete-after-rejected-otp-field',
        payload,
      }),
    ).resolves.toBeUndefined();
  });

  test('burns the old registration handle after wallet-id reroll', async () => {
    const { handlers, posted, wireFlow } = await beginFlow({ flow: makeRegistrationFlow() });
    const payload = handlePayload(wireFlow);

    await expect(
      handlers.PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_REROLL_WALLET_ID?.({
        type: 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_REROLL_WALLET_ID',
        requestId: 'reroll-1',
        payload,
      }),
    ).resolves.toBeUndefined();

    const response = posted.at(-1) as {
      payload: { result: { ok: true; value: Record<string, unknown> } };
    };
    expect(response.payload.result.value).toMatchObject({
      flowId: 'registration-flow-rerolled',
      walletId: 'alice-2.testnet',
      mode: 'register',
      state: 'registration_ready',
    });
    expect(response.payload.result.value).not.toHaveProperty('delivery');
    expect(JSON.stringify(response.payload.result.value)).not.toContain('appSessionJwt');
    expect(JSON.stringify(response.payload.result.value)).not.toContain('runtimePolicyScope');
    expect(JSON.stringify(response.payload.result.value)).not.toContain('recoveryKeys');
    expect(JSON.stringify(response.payload.result.value)).not.toContain('bootstrap');

    await expect(
      handlers.PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION?.({
        type: 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION',
        requestId: 'complete-old-reroll',
        payload,
      }),
    ).rejects.toThrow(/not active/);
  });

  test('keeps a registration handle active after failed reroll result', async () => {
    const { handlers, posted, wireFlow } = await beginFlow({
      flow: makeRegistrationFlow({
        rerollWalletId: async () => ({
          ok: false,
          error: {
            code: 'google_exchange_failed',
            message: 'reroll unavailable',
          },
        }),
      }),
    });
    const payload = handlePayload(wireFlow);

    await handlers.PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_REROLL_WALLET_ID?.({
      type: 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_REROLL_WALLET_ID',
      requestId: 'reroll-failed',
      payload,
    });
    expect(
      (posted.at(-1) as { payload: { result: { ok: boolean } } }).payload.result.ok,
    ).toBe(false);

    await handlers.PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION?.({
      type: 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION',
      requestId: 'complete-after-failed-reroll',
      payload,
    });
    expect(
      (posted.at(-1) as { payload: { result: { ok: boolean } } }).payload.result.ok,
    ).toBe(true);
  });

  test('cancels registration flow when handle expires', async () => {
    let cancelCalls = 0;
    const { handlers, wireFlow } = await beginFlow({
      flow: makeRegistrationFlow({
        expiresAtMs: Date.now() - 1,
        cancel: async () => {
          cancelCalls += 1;
        },
      }),
    });

    await expect(
      handlers.PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION?.({
        type: 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION',
        requestId: 'complete-expired-registration',
        payload: handlePayload(wireFlow),
      }),
    ).rejects.toThrow(/expired/);
    expect(cancelCalls).toBe(1);
  });
});
