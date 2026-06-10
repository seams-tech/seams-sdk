import { expect, test } from '@playwright/test';
import type { WebAuthnAuthenticationCredential } from '../../packages/sdk-web/src/core/types/webauthn';
import {
  prepareStepUpAuth,
  requireStepUpAuth,
} from '../../packages/sdk-web/src/core/signingEngine/stepUpConfirmation/requireStepUpAuth';
import {
  selectStepUpMethod,
  StepUpMethodSelectionError,
} from '../../packages/sdk-web/src/core/signingEngine/stepUpConfirmation/methodSelection';

const TEST_WEBAUTHN_CREDENTIAL = {
  id: 'credential-id',
  rawId: 'raw-id',
  type: 'public-key',
  authenticatorAttachment: 'platform',
  response: {
    clientDataJSON: 'client-data',
    authenticatorData: 'authenticator-data',
    signature: 'signature',
    userHandle: undefined,
  },
  clientExtensionResults: {
    prf: {
      results: {
        first: 'first-prf',
        second: undefined,
      },
    },
  },
} satisfies WebAuthnAuthenticationCredential;

test.describe('step-up adaptor method selection', () => {
  test('selects passkey from the selected lane when a passkey runner exists', () => {
    const route = selectStepUpMethod({
      selectedLane: { authMethod: 'passkey' as const },
      policy: { kind: 'use_selected_lane' as const },
      methods: {
        passkey: {
          method: 'passkey',
          prepare: async () => ({ title: 'Passkey' }),
          complete: async () => ({ proof: 'passkey-proof' }),
        },
      },
    });

    expect(route.method).toBe('passkey');
  });

  test('selects email otp from the selected lane when an Email OTP runner exists', () => {
    const route = selectStepUpMethod({
      selectedLane: { authMethod: 'email_otp' as const },
      policy: { kind: 'use_selected_lane' as const },
      methods: {
        emailOtp: {
          method: 'email_otp',
          prepareChallenge: async () => ({ challengeId: 'otp-1', emailHint: 'a***@x.test' }),
          complete: async () => ({ proof: 'otp-proof' }),
        },
      },
    });

    expect(route.method).toBe('email_otp');
  });

  test('force_method overrides the selected lane method', () => {
    const route = selectStepUpMethod({
      selectedLane: { authMethod: 'email_otp' as const },
      policy: { kind: 'force_method' as const, method: 'passkey' as const },
      methods: {
        passkey: {
          method: 'passkey',
          prepare: async () => ({ title: 'Passkey' }),
          complete: async () => ({ proof: 'passkey-proof' }),
        },
      },
    });

    expect(route.method).toBe('passkey');
  });

  test('reuse_warm_session returns the provided warm-session authorization', () => {
    const route = selectStepUpMethod({
      selectedLane: { authMethod: 'passkey' as const },
      policy: {
        kind: 'reuse_warm_session' as const,
        authorization: {
          method: 'passkey',
          sessionId: 'warm-1',
          expiresAtMs: 123,
          remainingUses: 2,
        },
      },
      methods: {},
    });

    expect(route).toEqual({
      method: 'warm_session',
      authorization: {
        method: 'passkey',
        sessionId: 'warm-1',
        expiresAtMs: 123,
        remainingUses: 2,
      },
    });
  });

  test('missing runner fails before confirmation starts', async () => {
    let confirmationCalls = 0;

    await expect(
      requireStepUpAuth({
        operation: { kind: 'transaction_sign' },
        selectedLane: { authMethod: 'passkey' as const },
        policy: { kind: 'use_selected_lane' as const },
        confirmation: {
          confirmPasskey: async () => {
            confirmationCalls += 1;
            return { credential: TEST_WEBAUTHN_CREDENTIAL };
          },
          confirmEmailOtp: async () => {
            confirmationCalls += 1;
            return { otpCode: '000000' };
          },
        },
        methods: {},
      }),
    ).rejects.toMatchObject({
      name: 'StepUpMethodSelectionError',
      code: 'missing_step_up_runner',
      method: 'passkey',
    } satisfies Partial<StepUpMethodSelectionError>);

    expect(confirmationCalls).toBe(0);
  });

  test('prepares an Email OTP prompt without starting confirmation', async () => {
    let completed = false;
    const prepared = await prepareStepUpAuth({
      operation: { kind: 'transaction_sign' },
      selectedLane: { authMethod: 'email_otp' as const },
      policy: { kind: 'use_selected_lane' as const },
      methods: {
        emailOtp: {
          method: 'email_otp',
          prepareChallenge: async () => ({ challengeId: 'otp-1', emailHint: 'a***@x.test' }),
          complete: async ({ confirmation, prompt }) => {
            completed = true;
            return {
              otpCode: confirmation.otpCode,
              challengeId: prompt.challengeId,
            };
          },
        },
      },
    });

    expect(prepared.method).toBe('email_otp');
    if (prepared.method !== 'email_otp') throw new Error('expected Email OTP route');
    expect(prepared.prompt.challengeId).toBe('otp-1');
    expect(completed).toBe(false);
    await expect(prepared.complete({ otpCode: '123456' })).resolves.toEqual({
      otpCode: '123456',
      challengeId: 'otp-1',
    });
  });
});
