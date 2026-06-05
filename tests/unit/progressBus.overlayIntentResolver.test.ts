import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  progressBus: '/sdk/esm/web/SeamsWeb/walletIframe/client/progress/on-events-progress-bus.js',
  seamsTypes: '/sdk/esm/core/types/sdkSentEvents.js',
} as const;

test.describe('defaultOverlayIntentResolver', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('returns show/hide/none from event interaction metadata', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const progress = await import(paths.progressBus);
        const phases = await import(paths.seamsTypes);
        const resolveOverlayIntent = progress.defaultOverlayIntentResolver as (
          p: any,
        ) => 'show' | 'hide' | 'none';

        const show1 = resolveOverlayIntent({
          phase: phases.SigningEventPhase.STEP_06_AUTH_PASSKEY_PROMPT_STARTED,
          interaction: { kind: 'passkey_assert', overlay: 'show' },
        });
        const show2 = resolveOverlayIntent({
          phase: phases.RegistrationEventPhase.STEP_04_PASSKEY_CREATE_STARTED,
          interaction: { kind: 'passkey_create', overlay: 'show' },
        });
        const hide1 = resolveOverlayIntent({
          phase: phases.SigningEventPhase.STEP_07_AUTHENTICATION_COMPLETE,
          interaction: { kind: 'passkey_assert', overlay: 'hide' },
        });
        const terminalEvent = phases.createSigningFlowEvent({
          phase: phases.SigningEventPhase.FAILED,
          status: 'failed',
          flowId: 'signing:test',
        });
        const hide2 = resolveOverlayIntent(terminalEvent);
        const hide3 = resolveOverlayIntent({ phase: 'cancelled' });
        const none1 = resolveOverlayIntent({
          phase: phases.SigningEventPhase.STEP_10_COMMIT_STARTED,
          interaction: { kind: 'none', overlay: 'none' },
        });
        const none2 = resolveOverlayIntent({ phase: 'some-unknown-phase' });
        const none3 = resolveOverlayIntent({});

        return { show1, show2, hide1, hide2, hide3, none1, none2, none3 };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.show1).toBe('show');
    expect(result.show2).toBe('show');
    expect(result.hide1).toBe('hide');
    expect(result.hide2).toBe('hide');
    expect(result.hide3).toBe('none');
    expect(result.none1).toBe('none');
    expect(result.none2).toBe('none');
    expect(result.none3).toBe('none');
  });

  test('tracks v2 flow, phase, and status stats', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const progress = await import(paths.progressBus);
        const events = await import(paths.seamsTypes);
        const bus = new progress.OnEventsProgressBus(
          { show: () => undefined, hide: () => undefined },
          progress.defaultOverlayIntentResolver,
        );
        bus.register({ requestId: 'request-1', sticky: false });
        bus.dispatch({
          requestId: 'request-1',
          payload: events.createSigningFlowEvent({
            phase: events.SigningEventPhase.STEP_10_COMMIT_STARTED,
            status: 'running',
            flowId: 'signing:test',
            interaction: { kind: 'none', overlay: 'none' },
          }),
        });
        const stats = bus.getStats('request-1');
        return {
          count: stats?.count,
          flow: stats?.flow,
          phase: stats?.phase,
          status: stats?.status,
          lastAtType: typeof stats?.lastAt,
          hasLegacyLastPhase: Object.prototype.hasOwnProperty.call(stats || {}, 'lastPhase'),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toMatchObject({
      count: 1,
      flow: 'signing',
      phase: 'signing.commit.started',
      status: 'running',
      lastAtType: 'number',
      hasLegacyLastPhase: false,
    });
  });
});
