import { expect, test } from '@playwright/test';
import { unlock } from '@/web/SeamsWeb/login';
import { SeamsWeb } from '@/web/SeamsWeb';
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
          assertSealedRefreshStartupParity: async () => {
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
      UnlockEventPhase.CANCELLED,
    ]);
    expect(events.map((event) => event.status)).toEqual(['started', 'cancelled']);
    expect(events[1]).toMatchObject({
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
