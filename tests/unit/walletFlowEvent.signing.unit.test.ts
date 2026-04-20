import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  tatchiTypes: '/sdk/esm/core/types/sdkSentEvents.js',
} as const;

test.describe('wallet flow event invariants', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('maps every numbered phase enum member to its declared step and message', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const events = await import(paths.tatchiTypes);
        const enumNames = [
          'RegistrationEventPhase',
          'UnlockEventPhase',
          'SigningEventPhase',
          'LinkDeviceEventPhase',
          'EmailRecoveryFlowEventPhase',
          'AccountSyncEventPhase',
        ] as const;

        const failures: string[] = [];
        for (const enumName of enumNames) {
          const eventEnum = events[enumName] as Record<string, string>;
          for (const [member, phase] of Object.entries(eventEnum)) {
            const step = events.WALLET_FLOW_EVENT_STEPS[phase];
            const message = events.WALLET_FLOW_EVENT_MESSAGES[phase];

            if (typeof step !== 'number') {
              failures.push(`${enumName}.${member} missing step for ${phase}`);
            }
            if (typeof message !== 'string' || message.length === 0) {
              failures.push(`${enumName}.${member} missing message for ${phase}`);
            }

            const numberedStep = /^STEP_(\d+)_/.exec(member)?.[1];
            if (numberedStep && step !== Number(numberedStep)) {
              failures.push(
                `${enumName}.${member} expected step ${Number(numberedStep)} got ${step}`,
              );
            }

            if ((member === 'FAILED' || member === 'CANCELLED') && step !== 0) {
              failures.push(`${enumName}.${member} expected terminal step 0 got ${step}`);
            }
          }
        }

        return failures;
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual([]);
  });

  test('creates cancelled terminal events with hide overlay metadata for core flows', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const events = await import(paths.tatchiTypes);
        return [
          events.createRegistrationFlowEvent({
            phase: events.RegistrationEventPhase.CANCELLED,
            status: 'cancelled',
            flowId: 'registration:alice.testnet:cancelled',
            accountId: 'alice.testnet',
          }),
          events.createUnlockFlowEvent({
            phase: events.UnlockEventPhase.CANCELLED,
            status: 'cancelled',
            flowId: 'unlock:alice.testnet:cancelled',
            accountId: 'alice.testnet',
          }),
          events.createSigningFlowEvent({
            phase: events.SigningEventPhase.CANCELLED,
            status: 'cancelled',
            flowId: 'signing:alice.testnet:cancelled',
            accountId: 'alice.testnet',
          }),
          events.createLinkDeviceFlowEvent({
            phase: events.LinkDeviceEventPhase.CANCELLED,
            status: 'cancelled',
            flowId: 'link-device:cancelled',
          }),
          events.createEmailRecoveryFlowEvent({
            phase: events.EmailRecoveryFlowEventPhase.CANCELLED,
            status: 'cancelled',
            flowId: 'email-recovery:alice.testnet:cancelled',
            accountId: 'alice.testnet',
          }),
        ];
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual([
      expect.objectContaining({
        version: 2,
        flow: 'registration',
        step: 0,
        phase: 'registration.cancelled',
        status: 'cancelled',
        message: 'Registration cancelled',
        interaction: { kind: 'none', overlay: 'hide' },
      }),
      expect.objectContaining({
        version: 2,
        flow: 'unlock',
        step: 0,
        phase: 'unlock.cancelled',
        status: 'cancelled',
        message: 'Wallet unlock cancelled',
        interaction: { kind: 'none', overlay: 'hide' },
      }),
      expect.objectContaining({
        version: 2,
        flow: 'signing',
        step: 0,
        phase: 'signing.cancelled',
        status: 'cancelled',
        message: 'Transaction signing cancelled',
        interaction: { kind: 'none', overlay: 'hide' },
      }),
      expect.objectContaining({
        version: 2,
        flow: 'link_device',
        step: 0,
        phase: 'link_device.cancelled',
        status: 'cancelled',
        message: 'Device link cancelled',
        interaction: { kind: 'none', overlay: 'hide' },
      }),
      expect.objectContaining({
        version: 2,
        flow: 'email_recovery',
        step: 0,
        phase: 'email_recovery.cancelled',
        status: 'cancelled',
        message: 'Email recovery cancelled',
        interaction: { kind: 'none', overlay: 'hide' },
      }),
    ]);
  });
});

test.describe('signing wallet flow events', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('derives stable step numbers and canonical messages from signing phases', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const events = await import(paths.tatchiTypes);
        const warmSessionEvent = events.createSigningFlowEvent({
          phase: events.SigningEventPhase.STEP_06_AUTH_WARM_SESSION_CLAIMED,
          status: 'succeeded',
          flowId: 'signing:evm:alice.testnet:warm',
          accountId: 'alice.testnet',
          authMethod: 'warm_session',
          interaction: { kind: 'none', overlay: 'none' },
          data: { sessionId: 'warm-session-1', remainingUses: 3, expiresAtMs: 123 },
        });
        const readinessEvent = events.createSigningFlowEvent({
          phase: events.SigningEventPhase.STEP_04_ACCOUNT_READINESS_SUCCEEDED,
          status: 'succeeded',
          flowId: 'signing:evm:alice.testnet:readiness',
          accountId: 'alice.testnet',
          interaction: { kind: 'none', overlay: 'none' },
        });
        const appStateSyncEvent = events.createSigningFlowEvent({
          phase: events.SigningEventPhase.STEP_14_APP_STATE_SYNC_STARTED,
          status: 'running',
          flowId: 'signing:evm:alice.testnet:app-state',
          accountId: 'alice.testnet',
          interaction: { kind: 'none', overlay: 'none' },
        });
        const nonceEvent = events.createSigningFlowEvent({
          phase: events.SigningEventPhase.STEP_13_NONCE_RECONCILE_SUCCEEDED,
          status: 'succeeded',
          flowId: 'signing:evm:alice.testnet:nonce',
          accountId: 'alice.testnet',
          interaction: { kind: 'none', overlay: 'none' },
        });
        const completedEvent = events.createSigningFlowEvent({
          phase: events.SigningEventPhase.STEP_15_COMPLETED,
          status: 'succeeded',
          flowId: 'signing:evm:alice.testnet:complete',
          accountId: 'alice.testnet',
          interaction: { kind: 'none', overlay: 'none' },
        });
        const failedEvent = events.createSigningFlowEvent({
          phase: events.SigningEventPhase.FAILED,
          status: 'failed',
          flowId: 'signing:evm:alice.testnet:failed',
          accountId: 'alice.testnet',
        });

        return {
          warmSessionEvent,
          readinessEvent,
          appStateSyncEvent,
          nonceEvent,
          completedEvent,
          failedEvent,
          isWalletFlowEvent: events.isWalletFlowEvent(warmSessionEvent),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.warmSessionEvent).toMatchObject({
      version: 2,
      flow: 'signing',
      step: 6,
      phase: 'signing.auth.warm_session.claimed',
      status: 'succeeded',
      message: 'Signing session authorized',
      authMethod: 'warm_session',
      interaction: { kind: 'none', overlay: 'none' },
    });
    expect(result.readinessEvent).toMatchObject({
      step: 4,
      phase: 'signing.account.readiness.succeeded',
      message: 'Account ready',
    });
    expect(result.appStateSyncEvent).toMatchObject({
      step: 14,
      phase: 'signing.app_state.sync.started',
      message: 'Refreshing app state',
    });
    expect(result.nonceEvent).toMatchObject({
      step: 13,
      phase: 'signing.nonce.reconcile.succeeded',
      message: 'Nonce state updated',
    });
    expect(result.completedEvent).toMatchObject({
      step: 15,
      phase: 'signing.completed',
      message: 'Transaction complete',
    });
    expect(result.failedEvent).toMatchObject({
      step: 0,
      phase: 'signing.failed',
      status: 'failed',
      message: 'Transaction signing failed',
      interaction: { kind: 'none', overlay: 'hide' },
    });
    expect(result.isWalletFlowEvent).toBe(true);
  });
});

test.describe('account sync wallet flow events', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('derives account sync steps, messages, and terminal overlay metadata', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const events = await import(paths.tatchiTypes);
        const promptEvent = events.createAccountSyncFlowEvent({
          phase: events.AccountSyncEventPhase.STEP_02_PASSKEY_PROMPT_STARTED,
          status: 'waiting_for_user',
          flowId: 'account-sync:alice.testnet',
          accountId: 'alice.testnet',
          interaction: { kind: 'passkey_assert', overlay: 'show' },
        });
        const completedEvent = events.createAccountSyncFlowEvent({
          phase: events.AccountSyncEventPhase.STEP_06_COMPLETED,
          status: 'succeeded',
          flowId: 'account-sync:alice.testnet',
          accountId: 'alice.testnet',
        });
        const failedEvent = events.createAccountSyncFlowEvent({
          phase: events.AccountSyncEventPhase.FAILED,
          status: 'failed',
          flowId: 'account-sync:alice.testnet',
          accountId: 'alice.testnet',
        });

        return {
          promptEvent,
          completedEvent,
          failedEvent,
          isWalletFlowEvent: events.isWalletFlowEvent(completedEvent),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.promptEvent).toMatchObject({
      version: 2,
      flow: 'account_sync',
      step: 2,
      phase: 'account_sync.auth.passkey.prompt.started',
      status: 'waiting_for_user',
      message: 'Confirm with passkey',
      interaction: { kind: 'passkey_assert', overlay: 'show' },
    });
    expect(result.completedEvent).toMatchObject({
      step: 6,
      phase: 'account_sync.completed',
      message: 'Account synced',
    });
    expect(result.failedEvent).toMatchObject({
      step: 0,
      phase: 'account_sync.failed',
      status: 'failed',
      message: 'Account sync failed',
      interaction: { kind: 'none', overlay: 'hide' },
    });
    expect(result.isWalletFlowEvent).toBe(true);
  });
});
