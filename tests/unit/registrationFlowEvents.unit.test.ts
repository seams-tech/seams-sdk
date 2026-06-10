import { expect, test } from '@playwright/test';
import { createRegistrationLifecycleEvent } from '../../packages/sdk-web/src/SeamsWeb/operations/registration/registration';
import { RegistrationEventPhase } from '../../packages/sdk-web/src/core/types/sdkSentEvents';

test.describe('registration flow events', () => {
  test('passkey events use passkey-scoped registration flow identity by default', () => {
    const event = createRegistrationLifecycleEvent({
      accountId: 'alice.testnet',
      event: {
        phase: RegistrationEventPhase.STEP_01_STARTED,
        status: 'started',
      },
    });

    expect(event).toMatchObject({
      flow: 'registration',
      flowId: 'registration:passkey:alice.testnet',
      accountId: 'alice.testnet',
      authMethod: 'passkey',
      phase: RegistrationEventPhase.STEP_01_STARTED,
      status: 'started',
    });
  });

  test('Email OTP events use Email OTP-scoped registration flow identity', () => {
    const event = createRegistrationLifecycleEvent({
      accountId: 'alice.testnet',
      event: {
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_04_OTP_CHALLENGE_STARTED,
        status: 'started',
      },
    });

    expect(event).toMatchObject({
      flow: 'registration',
      flowId: 'registration:email_otp:alice.testnet',
      accountId: 'alice.testnet',
      authMethod: 'email_otp',
      phase: RegistrationEventPhase.STEP_04_OTP_CHALLENGE_STARTED,
      status: 'started',
    });
  });
});
