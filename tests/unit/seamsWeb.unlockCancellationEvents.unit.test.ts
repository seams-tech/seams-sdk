import { expect, test } from '@playwright/test';
import { unlock } from '@/SeamsWeb/operations/auth/login';
import { SeamsWeb } from '@/SeamsWeb';
import { createUnlockFlowEvent, UnlockEventPhase } from '@/core/types/sdkSentEvents';

test.describe('SeamsWeb unlock cancellation events', () => {
  test('passkey unlock emits unlock.cancelled for WebAuthn cancellation errors', async () => {
    const events: any[] = [];
    const afterCalls: any[] = [];
    const onErrors: string[] = [];
    const cancellation = new Error('The operation either timed out or was not allowed');
    cancellation.name = 'NotAllowedError';

    const result = await unlock(
      {
        signingEngine: {
          assertSealedRefreshStartupParity: async () => undefined,
          getLastUser: async () => ({
            nearAccountId: 'alice.testnet',
            signerSlot: 1,
            operationalPublicKey: 'ed25519:alice',
            authMethod: 'passkey',
          }),
          nearAuthenticatorsByAccount: async () => [{ credentialId: 'cred-1', signerSlot: 1 }],
          getAuthenticationCredentialsSerialized: async () => {
            throw cancellation;
          },
        },
      } as any,
      'alice.testnet' as any,
      {
        onEvent: (event: any) => events.push(event),
        onError: (error: Error) => onErrors.push(error.message),
        afterCall: async (ok: boolean) => afterCalls.push(ok),
      } as any,
    );

    expect(result).toEqual({
      success: false,
      error: "Login was cancelled. Please try again when you're ready to authenticate.",
    });
    expect(events.map((event) => event.phase)).toEqual([
      UnlockEventPhase.STEP_01_STARTED,
      UnlockEventPhase.STEP_02_ACCOUNT_LOOKUP_STARTED,
      UnlockEventPhase.STEP_02_ACCOUNT_LOOKUP_SUCCEEDED,
      UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_SKIPPED,
      UnlockEventPhase.STEP_03_PASSKEY_PROMPT_STARTED,
      UnlockEventPhase.CANCELLED,
    ]);
    expect(events.map((event) => event.status)).toEqual([
      'started',
      'running',
      'succeeded',
      'skipped',
      'waiting_for_user',
      'cancelled',
    ]);
    expect(events[5]).toMatchObject({
      flow: 'unlock',
      phase: 'unlock.cancelled',
      step: 0,
      message: 'Wallet unlock cancelled',
      interaction: { kind: 'passkey_assert', overlay: 'hide' },
      error: {
        message: "Login was cancelled. Please try again when you're ready to authenticate.",
      },
    });
    expect(afterCalls).toEqual([false]);
    expect(onErrors).toEqual(['The operation either timed out or was not allowed']);
  });

  test('passkey prompt is not blocked by slow sealed-refresh parity check', async () => {
    const events: any[] = [];
    let promptStarted = false;
    const result = await unlock(
      {
        signingEngine: {
          assertSealedRefreshStartupParity: async () => {
            await new Promise(() => undefined);
          },
          getLastUser: async () => ({
            nearAccountId: 'alice.testnet',
            signerSlot: 1,
            operationalPublicKey: 'ed25519:alice',
            authMethod: 'passkey',
          }),
          nearAuthenticatorsByAccount: async () => [{ credentialId: 'cred-1', signerSlot: 1 }],
          getAuthenticationCredentialsSerialized: async () => {
            promptStarted = true;
            return {
              id: 'cred-1',
              rawId: 'cred-1',
              type: 'public-key',
              response: {
                clientDataJSON: 'client-data-json',
                authenticatorData: 'authenticator-data',
                signature: 'signature',
              },
              clientExtensionResults: {},
            };
          },
          setLastUser: async () => undefined,
          updateLastLogin: async () => undefined,
          getNonceCoordinator: () => ({
            recoverDurableLeases: async () => undefined,
          }),
        },
      } as any,
      'alice.testnet' as any,
      {
        onEvent: (event: any) => events.push(event),
      } as any,
    );

    expect(promptStarted).toBe(true);
    expect(result.success).toBe(true);
    expect(events.map((event) => event.phase)).toContain(
      UnlockEventPhase.STEP_03_PASSKEY_PROMPT_STARTED,
    );
    expect(events.map((event) => event.phase)).toContain(UnlockEventPhase.STEP_07_COMPLETED);
  });

  test('Email OTP unlock failure helper emits unlock.cancelled for cancellation errors', () => {
    const events: any[] = [];
    const cancellation = Object.assign(new Error('User cancelled Email OTP unlock'), {
      code: 'cancelled',
    });
    const harness = {
      emitEmailOtpUnlockEvent: (
        onEvent: ((event: unknown) => void) | undefined,
        input: Parameters<typeof createUnlockFlowEvent>[0],
      ) => {
        onEvent?.(createUnlockFlowEvent(input));
      },
    };

    (SeamsWeb.prototype as any).emitEmailOtpUnlockFailure.call(
      harness,
      (event: any) => events.push(event),
      {
        flowId: 'email-otp-unlock:alice.testnet:challenge-1',
        accountId: 'alice.testnet',
        authMethod: 'email_otp',
        requestId: 'challenge-1',
        error: cancellation,
      },
    );

    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      flow: 'unlock',
      phase: 'unlock.cancelled',
      status: 'cancelled',
      step: 0,
      message: 'Wallet unlock cancelled',
      authMethod: 'email_otp',
      requestId: 'challenge-1',
      interaction: { kind: 'otp_input', overlay: 'hide' },
      error: { message: 'User cancelled Email OTP unlock' },
    });
  });
});
