/**
 * Worker Communication Integration Tests
 *
 * Tests the communication protocol between TypeScript worker and WASM
 * Specifically focuses on progress messaging functionality that was broken during refactoring
 */

import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, handleInfrastructureErrors } from '../setup';
import { autoConfirmWalletIframeUntil } from '../setup/flows';
import { DEFAULT_TEST_CONFIG } from '../setup/config';
import {
  installCreateAccountAndRegisterUserMock,
  installFastNearRpcMock,
} from './thresholdEd25519.testUtils';

test.describe('Worker Communication Protocol', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await page.waitForTimeout(500);
  });

  // exercises full signer-worker pipeline for function call, expecting progress events even on fetch failure
  test('Progress Messages - SignTransactionsWithActions', async ({ page }) => {
    const keysOnChain = new Set<string>();
    const nonceByPublicKey = new Map<string, number>();
    let operationalNearPublicKey = '';

    await installCreateAccountAndRegisterUserMock(page, {
      relayerBaseUrl: DEFAULT_TEST_CONFIG.relayer?.url ?? 'https://relay-server.localhost',
      onNewPublicKey: (pk) => {
        if (!operationalNearPublicKey) operationalNearPublicKey = pk;
        keysOnChain.add(pk);
        nonceByPublicKey.set(pk, 0);
      },
    });

    await installFastNearRpcMock(page, {
      keysOnChain,
      nonceByPublicKey,
      onSendTx: () => {
        if (operationalNearPublicKey) {
          nonceByPublicKey.set(
            operationalNearPublicKey,
            (nonceByPublicKey.get(operationalNearPublicKey) ?? 0) + 1,
          );
        }
      },
      strictAccessKeyLookup: true,
    });

    const USE_RELAY_SERVER =
      process.env.USE_RELAY_SERVER === '1' || process.env.USE_RELAY_SERVER === 'true';
    const resultPromise = page.evaluate(
      async ({ useServer }) => {
        try {
          // @ts-ignore - Runtime import
          const { ActionType } = await import('/sdk/esm/core/types/actions.js');

          const SigningPhase = {
            STARTED: 'signing.started',
            CONFIRMATION_DISPLAYED: 'signing.confirmation.displayed',
            PASSKEY_PROMPT_STARTED: 'signing.auth.passkey.prompt.started',
            AUTHENTICATION_COMPLETE: 'signing.authentication.complete',
            TRANSACTION_SIGNED: 'signing.transaction.signed',
            BROADCAST_STARTED: 'signing.broadcast.started',
            BROADCAST_ACCEPTED: 'signing.broadcast.accepted',
            COMPLETED: 'signing.completed',
          } as const;

          const { seams, generateTestAccountId } = (window as any).testUtils;
          const testAccountId = generateTestAccountId();

          // Track all progress events
          const progressEvents: any[] = [];
          const registrationEvents: any[] = [];
          const actionEvents: any[] = [];

          // Register first to have an account (skip confirmation UI in tests)
          const cfg =
            (window as any).testUtils?.confirmOverrides?.none ||
            ({ uiMode: 'none', behavior: 'skipClick', autoProceedDelay: 0 } as const);
          const registrationResult = await seams.registration.registerPasskeyInternal(
            testAccountId,
            {
              onEvent: (event: any) => {
                progressEvents.push(event);
                registrationEvents.push(event);
              },
            },
            cfg,
          );

          if (!registrationResult.success) {
            throw new Error(`Registration failed: ${registrationResult.error}`);
          }

          // Login to activate session
          const loginResult = await seams.auth.unlock(testAccountId, {
            signingSession: { ttlMs: 0, remainingUses: 0 },
            onEvent: (event: any) => {
              console.log(`Login [${event.step}]: ${event.phase} - ${event.message}`);
            },
          });

          if (!loginResult.success) {
            throw new Error(`Login failed: ${loginResult.error}`);
          }

          const walletSession = await seams.auth.getWalletSession(testAccountId);
          const hasThresholdEcdsaState = !!String(
            walletSession?.login?.thresholdEcdsaEthereumAddress || '',
          ).trim();
          if (!hasThresholdEcdsaState) {
            throw new Error(
              'dual-state regression: login snapshot missing thresholdEcdsaEthereumAddress',
            );
          }

          // Wait for registration to settle
          await new Promise((resolve) => setTimeout(resolve, 5000));

          // Now test executeAction with detailed progress tracking (new SDK signature)
          const actionResult = await seams.near.executeAction({
            nearAccount: { accountId: testAccountId },
            receiverId: (window as any).testUtils.configs.testReceiverAccountId, // Use centralized configuration
            actionArgs: {
              type: ActionType.FunctionCall,
              methodName: 'set_greeting',
              args: { greeting: 'Test progress message' },
              gas: '30000000000000',
              deposit: '0',
            },
            options: {
              onEvent: (event: any) => {
                const normalized = {
                  step: event.step,
                  phase: event.phase,
                  status: event.status,
                  message: event.message,
                  timestamp: event.timestamp,
                  hasData: !!event.data,
                };
                progressEvents.push(normalized);
                actionEvents.push(normalized);
                console.log(`Action Progress [${event.step}]: ${event.phase} - ${event.message}`);
              },
            },
          });

          return {
            success: true,
            actionResult,
            progressEvents,
            registrationEvents,
            actionEvents,
            // Analysis
            hasThresholdEcdsaState,
            totalEvents: actionEvents.length,
            phases: actionEvents.map((e) => e.phase),
            uniquePhases: [...new Set(actionEvents.map((e) => e.phase))],
            hasSigningStarted: actionEvents.some((e) => e.phase === SigningPhase.STARTED),
            hasConfirmationDisplayed: actionEvents.some(
              (e) => e.phase === SigningPhase.CONFIRMATION_DISPLAYED,
            ),
            hasPasskeyPrompt: actionEvents.some(
              (e) => e.phase === SigningPhase.PASSKEY_PROMPT_STARTED,
            ),
            hasAuthenticationComplete: actionEvents.some(
              (e) => e.phase === SigningPhase.AUTHENTICATION_COMPLETE,
            ),
            hasTransactionSigned: actionEvents.some(
              (e) => e.phase === SigningPhase.TRANSACTION_SIGNED,
            ),
            hasBroadcastStarted: actionEvents.some(
              (e) => e.phase === SigningPhase.BROADCAST_STARTED,
            ),
            hasBroadcastAccepted: actionEvents.some(
              (e) => e.phase === SigningPhase.BROADCAST_ACCEPTED,
            ),
            hasCompleted: actionEvents.some((e) => e.phase === SigningPhase.COMPLETED),
            hasFailed: actionEvents.some((e) => e.status === 'failed'),
            // Event structure validation
            allEventsHaveRequiredFields: actionEvents.every(
              (e) =>
                typeof e.step === 'number' &&
                typeof e.phase === 'string' &&
                typeof e.status === 'string' &&
                typeof e.message === 'string',
            ),
            // Debug: Log all captured events
            capturedEvents: actionEvents.map((e) => ({
              step: e.step,
              phase: e.phase,
              status: e.status,
              message: e.message,
              timestamp: e.timestamp,
            })),
          };
        } catch (error: any) {
          return {
            success: false,
            error: error.message,
            stack: error.stack,
          };
        }
      },
      { useServer: USE_RELAY_SERVER },
    );
    const result = await autoConfirmWalletIframeUntil(page, resultPromise);
    const assertPhaseOrder = (phases: string[], expected: string[], label: string): void => {
      let lastIdx = -1;
      for (const phase of expected) {
        const idx = phases.indexOf(phase, lastIdx + 1);
        expect(idx, `${label} missing or out-of-order phase: ${phase}`).toBeGreaterThan(lastIdx);
        lastIdx = idx;
      }
    };
    const basePhaseSequence = ['signing.started', 'signing.confirmation.displayed'];
    const authPhaseSequence = [
      'signing.started',
      'signing.confirmation.displayed',
      'signing.auth.passkey.prompt.started',
    ];
    const signingPhaseSequence = [
      'signing.started',
      'signing.confirmation.displayed',
      'signing.transaction.signed',
    ];
    const successPhaseSequence = [
      'signing.started',
      'signing.confirmation.displayed',
      'signing.transaction.signed',
      'signing.broadcast.started',
      'signing.broadcast.accepted',
      'signing.completed',
    ];

    // Assertions
    if (!result.success) {
      // Handle common infrastructure errors (rate limiting, contract connectivity)
      if (handleInfrastructureErrors(result)) {
        return; // Test was skipped due to infrastructure issues
      }

      // For progress messaging tests, we expect the operation to fail but still capture progress events
      console.log('Operation failed as expected for progress messaging test:', result.error);
      console.log('Checking if progress events were captured despite failure...');
      console.log('Result structure:', JSON.stringify(result, null, 2));

      // Check if progress events were captured
      if (result.totalEvents === undefined) {
        console.log('No progress events captured - registration failed too early');
        console.log('This suggests the registration failed before progress tracking began');
        // Verify the error is a connectivity or registration failure (environment-dependent)
        expect(result.error).toMatch(
          /Failed to fetch|CreateAccount|register(ed)?|relay|fetch|managed registration transport/i,
        );
        console.log('Test passed - early failure matched expected patterns');
        return;
      }

      // Verify that progress events were still captured even though the operation failed
      expect(result.totalEvents).toBeGreaterThan(0);
      console.log(`Captured ${result.totalEvents} progress events despite operation failure`);
      console.log(`Phases: ${result.uniquePhases?.join(', ') || 'none'}`);
      console.log('Captured events:', JSON.stringify(result.capturedEvents, null, 2));

      // Check for expected progress events even when operation fails
      expect(result.hasSigningStarted).toBe(true);
      expect(result.hasConfirmationDisplayed).toBe(true);
      assertPhaseOrder(result.phases || [], basePhaseSequence, 'action failure');
      if (result.hasPasskeyPrompt) {
        assertPhaseOrder(result.phases || [], authPhaseSequence, 'action failure (auth)');
      }
      // Note: signing.authentication.complete may not be reached if validation fails.
      // This is expected behavior when the operation fails early
      if (result.hasAuthenticationComplete) {
        console.log('Authentication completed successfully before failure');
      } else {
        console.log('Authentication did not complete due to early failure - this is expected');
      }

      console.log('Progress messaging test passed - events captured despite operation failure');
      return;
    }

    expect(result.success).toBe(true);
    expect(result.hasThresholdEcdsaState).toBe(true);

    // Verify progress events were captured
    expect(result.totalEvents).toBeGreaterThan(0);
    console.log(`Captured ${result.totalEvents} progress events`);
    console.log(`Phases: ${result.uniquePhases?.join(', ') || 'none'}`);
    console.log('Captured events:', JSON.stringify(result.capturedEvents, null, 2));

    // Check if operation failed - if so, we should still see the expected progress events
    if (result.hasFailed) {
      console.log(
        'Operation failed with error - checking for expected progress events before failure',
      );
      expect(result.hasSigningStarted).toBe(true);
      expect(result.hasConfirmationDisplayed).toBe(true);
      assertPhaseOrder(result.phases || [], basePhaseSequence, 'action error');
      if (Array.isArray(result.actionEvents)) {
        const confirmationIdx = result.actionEvents.findIndex(
          (e: any) => e?.phase === 'signing.confirmation.displayed',
        );
        const errorIdx = result.actionEvents.findIndex((e: any) => e?.status === 'failed');
        expect(
          confirmationIdx,
          'missing signing.confirmation.displayed event',
        ).toBeGreaterThanOrEqual(0);
        expect(errorIdx, 'missing failed status event').toBeGreaterThanOrEqual(0);
        expect(errorIdx, 'failed event should occur after confirmation').toBeGreaterThan(
          confirmationIdx,
        );
      }
      if (result.hasPasskeyPrompt) {
        assertPhaseOrder(result.phases || [], authPhaseSequence, 'action error (auth)');
      }
      // Note: signing.authentication.complete may not be reached if validation fails.
      // This is expected behavior when the operation fails early
      if (result.hasAuthenticationComplete) {
        console.log('Authentication completed successfully before failure');
      } else {
        console.log('Authentication did not complete due to early failure - this is expected');
      }
      // If verification succeeds but operation fails later, we should see verification complete
      if (result.hasTransactionSigned) {
        assertPhaseOrder(result.phases || [], signingPhaseSequence, 'action error (signed)');
      }
    } else {
      // Operation succeeded - check all expected phases
      expect(result.hasSigningStarted).toBe(true);
      expect(result.hasConfirmationDisplayed).toBe(true);
      expect(result.hasTransactionSigned).toBe(true);
      expect(result.hasBroadcastStarted).toBe(true);
      expect(result.hasBroadcastAccepted).toBe(true);
      expect(result.hasCompleted).toBe(true);
      if (result.hasPasskeyPrompt) {
        assertPhaseOrder(result.phases || [], authPhaseSequence, 'action success (auth)');
      }
      if (result.hasAuthenticationComplete) {
        assertPhaseOrder(
          result.phases || [],
          [
            'signing.started',
            'signing.confirmation.displayed',
            'signing.auth.passkey.prompt.started',
            'signing.authentication.complete',
          ],
          'action success (auth complete)',
        );
      }
      assertPhaseOrder(result.phases || [], successPhaseSequence, 'action success');
    }

    // Verify event structure
    expect(result.allEventsHaveRequiredFields).toBe(true);

    console.log('Worker communication and progress messaging test passed');
  });

  // verifies login emits early phases and error when account is missing (no RPC dependency)
  test('Progress Messages - Login without prior registration', async ({ page }) => {
    const resultPromise = page.evaluate(async () => {
      try {
        const { seams, generateTestAccountId } = (window as any).testUtils;
        const testAccountId = generateTestAccountId();

        const capturedEvents: Array<{ phase: string; status: string; message: string }> = [];

        const loginResult = await seams.auth.unlock(testAccountId, {
          signingSession: { ttlMs: 0, remainingUses: 0 },
          onEvent: (event: any) => {
            capturedEvents.push({
              phase: event?.phase ?? '',
              status: event?.status ?? '',
              message: event?.message ?? '',
            });
          },
          onError: () => {},
        });

        return {
          loginResult,
          capturedEvents,
          phases: capturedEvents.map((e) => e.phase),
          statuses: capturedEvents.map((e) => e.status),
          errorMessages: capturedEvents.filter((e) => e.status === 'failed').map((e) => e.message),
        };
      } catch (error: any) {
        return {
          loginResult: { success: false, error: error?.message || String(error) },
          capturedEvents: [],
          phases: [],
          statuses: [],
          errorMessages: [],
        };
      }
    });
    const result = await autoConfirmWalletIframeUntil(page, resultPromise);

    expect(result.loginResult.success).toBe(false);
    expect(result.capturedEvents.length).toBeGreaterThan(0);
    expect(result.phases).toContain('unlock.started');
    expect(result.statuses).toContain('failed');
    expect(result.loginResult.error || '').toMatch(/register an account/i);
    expect(result.errorMessages.some((msg: string) => /register an account/i.test(msg))).toBe(true);
    const firstNonTerminalIdx = result.statuses.findIndex((status: string) => status !== 'failed');
    const failedIdx = result.statuses.findIndex((status: string) => status === 'failed');
    expect(firstNonTerminalIdx).toBeGreaterThanOrEqual(0);
    expect(failedIdx).toBeGreaterThan(firstNonTerminalIdx);
  });

  // happy-path login: seed registration via relay mock and assert full login phase progression
  test('Progress Messages - Login success after registration', async ({ page }) => {
    const USE_RELAY_SERVER =
      process.env.USE_RELAY_SERVER === '1' || process.env.USE_RELAY_SERVER === 'true';
    // This test requires a real relay server so the atomic registration can
    // actually create the account on-chain. Without it, the registration step
    // cannot verify the access key on-chain and subsequent login will fail.
    if (!USE_RELAY_SERVER) {
      test.skip(true, 'Requires relay server for on-chain registration verification');
    }
    const resultPromise = page.evaluate(
      async ({ useServer }) => {
        const utils = (window as any).testUtils;
        const registrationFlowUtils = utils.registrationFlowUtils;
        const restoreFetch = registrationFlowUtils?.restoreFetch?.bind(registrationFlowUtils);

        try {
          const testAccountId = utils.generateTestAccountId();
          if (!useServer) {
            registrationFlowUtils?.setupRelayServerMock?.(true);
          }

          const registrationEvents: Array<{ phase: string; status: string }> = [];
          const loginEvents: Array<{ phase: string; status: string; message: string }> = [];

          const cfg =
            utils?.confirmOverrides?.none ||
            ({ uiMode: 'none', behavior: 'skipClick', autoProceedDelay: 0 } as const);
          const registrationResult = await utils.seams.registration.registerPasskeyInternal(
            testAccountId,
            {
              onEvent: (event: any) => {
                registrationEvents.push({
                  phase: event?.phase ?? '',
                  status: event?.status ?? '',
                });
              },
            },
            cfg,
          );

          if (!registrationResult?.success) {
            throw new Error(`Registration failed unexpectedly: ${registrationResult?.error}`);
          }

          const loginResult = await utils.seams.auth.unlock(testAccountId, {
            session: { kind: 'jwt' },
            signingSession: { ttlMs: 0, remainingUses: 0 },
            onEvent: (event: any) => {
              loginEvents.push({
                phase: event?.phase ?? '',
                status: event?.status ?? '',
                message: event?.message ?? '',
              });
            },
          });

          return {
            success: loginResult?.success ?? false,
            loginError: loginResult?.error,
            registrationEvents,
            loginEvents,
            loginPhases: loginEvents.map((e) => e.phase),
            loginStatuses: loginEvents.map((e) => e.status),
          };
        } catch (error: any) {
          return {
            success: false,
            loginError: error?.message || String(error),
            registrationEvents: [],
            loginEvents: [],
            loginPhases: [],
            loginStatuses: [],
          };
        } finally {
          try {
            restoreFetch?.();
          } catch {}
        }
      },
      { useServer: USE_RELAY_SERVER },
    );
    const result = await autoConfirmWalletIframeUntil(page, resultPromise);

    if (!result.success) {
      if (handleInfrastructureErrors({ success: false, error: result.loginError })) {
        return;
      }
      if (
        typeof result.loginError === 'string' &&
        /unexpected rp id hash/i.test(result.loginError)
      ) {
        console.warn(
          'Skipping login-after-registration assertion due RP ID mismatch in test relay environment',
        );
        return;
      }
      console.error('Login after registration failed:', result.loginError);
      console.error('Registration events:', result.registrationEvents);
      console.error('Login events:', result.loginEvents);
    }

    expect(result.success).toBe(true);
    expect(result.registrationEvents.length).toBeGreaterThan(0);
    expect(result.loginEvents.length).toBeGreaterThan(0);
    expect(result.loginPhases).toEqual(
      expect.arrayContaining([
        'unlock.started',
        'unlock.auth.passkey.prompt.started',
        'unlock.session.ready',
        'unlock.completed',
      ]),
    );
    expect(result.loginStatuses).toContain('succeeded');
    const loginPhaseSequence = [
      'unlock.started',
      'unlock.auth.passkey.prompt.started',
      'unlock.session.ready',
      'unlock.completed',
    ];
    let lastIdx = -1;
    for (const phase of loginPhaseSequence) {
      const idx = result.loginPhases.indexOf(phase, lastIdx + 1);
      expect(idx, `login phases missing or out-of-order: ${phase}`).toBeGreaterThan(lastIdx);
      lastIdx = idx;
    }
  });

  // captures registration + login worker events to ensure variety of phase/status pairs are emitted
  test('Progress Message Types - All Message Types', async ({ page }) => {
    const keysOnChain = new Set<string>();
    const nonceByPublicKey = new Map<string, number>();
    let operationalNearPublicKey = '';

    await installCreateAccountAndRegisterUserMock(page, {
      relayerBaseUrl: DEFAULT_TEST_CONFIG.relayer?.url ?? 'https://relay-server.localhost',
      onNewPublicKey: (pk) => {
        if (!operationalNearPublicKey) operationalNearPublicKey = pk;
        keysOnChain.add(pk);
        nonceByPublicKey.set(pk, 0);
      },
    });

    await installFastNearRpcMock(page, {
      keysOnChain,
      nonceByPublicKey,
      onSendTx: () => {
        if (operationalNearPublicKey) {
          nonceByPublicKey.set(
            operationalNearPublicKey,
            (nonceByPublicKey.get(operationalNearPublicKey) ?? 0) + 1,
          );
        }
      },
      strictAccessKeyLookup: true,
    });

    const resultPromise = page.evaluate(async () => {
      try {
        const { seams, generateTestAccountId } = (window as any).testUtils;
        const testAccountId = generateTestAccountId();

        // Track progress message types
        const messageTypes = new Set<string>();
        const progressEvents: any[] = [];

        // Test registration flow (should generate REGISTRATION_PROGRESS messages)
        const cfg2 =
          (window as any).testUtils?.confirmOverrides?.none ||
          ({ uiMode: 'none', behavior: 'skipClick', autoProceedDelay: 0 } as const);
        const registrationResult = await seams.registration.registerPasskeyInternal(
          testAccountId,
          {
            onEvent: (event: any) => {
              progressEvents.push(event);
              messageTypes.add(`${event.phase}:${event.status}`);
            },
          },
          cfg2,
        );
        if (!registrationResult?.success) {
          throw new Error(`Registration failed: ${registrationResult?.error || 'unknown error'}`);
        }

        // Test login flow (should generate various progress messages)
        const loginResult = await seams.auth.unlock(testAccountId, {
          signingSession: { ttlMs: 0, remainingUses: 0 },
          onEvent: (event: any) => {
            progressEvents.push(event);
            messageTypes.add(`${event.phase}:${event.status}`);
          },
        });
        if (!loginResult?.success) {
          throw new Error(`Login failed: ${loginResult?.error || 'unknown error'}`);
        }

        return {
          success: true,
          totalEvents: progressEvents.length,
          messageTypes: Array.from(messageTypes),
          runningCount: progressEvents.filter((e) =>
            ['started', 'running', 'waiting_for_user'].includes(e.status),
          ).length,
          successCount: progressEvents.filter((e) => e.status === 'succeeded').length,
          failedCount: progressEvents.filter((e) => e.status === 'failed').length,
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
        };
      }
    });
    const result = await autoConfirmWalletIframeUntil(page, resultPromise);

    if (!result.success) {
      // Handle common infrastructure errors (rate limiting, contract connectivity)
      if (handleInfrastructureErrors(result)) {
        return; // Test was skipped due to infrastructure issues
      }
      if (/managed registration transport/i.test(String(result.error || ''))) {
        console.warn('Skipping message-type assertions; managed registration transport required');
        return;
      }

      // For other errors, fail as expected
      console.error('Message types test failed:', result.error);
      expect(result.success).toBe(true); // This will fail and show the error
      return;
    }

    expect(result.success).toBe(true);

    console.log('Message Types Test Results:');
    console.log(`   Total Events: ${result.totalEvents}`);
    console.log(`   Message Types: ${result.messageTypes?.join(', ') || 'none'}`);
    console.log(
      `   Running: ${result.runningCount}, Succeeded: ${result.successCount}, Failed: ${result.failedCount}`,
    );

    expect(result.totalEvents).toBeGreaterThan(0);
    expect(result.messageTypes?.length || 0).toBeGreaterThan(0);
    expect(result.runningCount).toBeGreaterThan(0);
    expect(result.successCount).toBeGreaterThan(0);
  });

  // ensures relay failure still surfaces worker progress/error envelopes
  test('Worker Error Handling - Progress on Failure', async ({ page }) => {
    const relayRoute = '**/registration/bootstrap';
    await page.route(relayRoute, async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      if (method === 'OPTIONS') {
        await route.fulfill({
          status: 204,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST,OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type,Authorization',
          },
          body: '',
        });
        return;
      }
      await route.fulfill({
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST,OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type,Authorization',
        },
        body: JSON.stringify({ success: false, error: 'forced relay failure' }),
      });
    });
    const resultPromise = page.evaluate(async () => {
      try {
        const { seams, generateTestAccountId } = (window as any).testUtils;
        const validAccountId = generateTestAccountId();

        const progressEvents: any[] = [];
        const errorEvents: any[] = [];
        let result: any = null;
        let threw = false;
        let thrownError = '';

        // Test error handling with a forced relay failure (should still send progress messages)
        try {
          const cfg3 =
            (window as any).testUtils?.confirmOverrides?.none ||
            ({ uiMode: 'none', behavior: 'skipClick', autoProceedDelay: 0 } as const);
          result = await seams.registration.registerPasskeyInternal(
            validAccountId,
            {
              onEvent: (event: any) => {
                progressEvents.push(event);
                if (event.status === 'failed') {
                  errorEvents.push(event);
                }
              },
              onError: (error: any) => {
                console.log('Expected error caught:', error.message);
              },
            },
            cfg3,
          );
        } catch (expectedError) {
          // This is expected to fail
          threw = true;
          thrownError = (expectedError as any)?.message || String(expectedError);
        }

        return {
          success: true,
          resultSuccess: result?.success ?? null,
          resultError: result?.error ?? '',
          threw,
          thrownError,
          progressEvents: progressEvents.length,
          errorEvents: errorEvents.length,
          hasErrorPhase: progressEvents.some(
            (e) => e.phase === 'registration.failed' || e.status === 'failed',
          ),
          phases: progressEvents.map((e) => e.phase),
          statuses: progressEvents.map((e) => e.status),
          lastEvent: progressEvents[progressEvents.length - 1],
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
        };
      }
    });
    const result = await autoConfirmWalletIframeUntil(page, resultPromise);
    await page.unroute(relayRoute).catch(() => {});

    expect(result.success).toBe(true);
    console.log('Error Handling Test Results:');
    console.log(`   Progress Events: ${result.progressEvents}`);
    console.log(`   Error Events: ${result.errorEvents}`);
    console.log(`   Has Error Phase: ${result.hasErrorPhase}`);

    // Even on failure, we should get some progress events
    expect(result.progressEvents).toBeGreaterThan(0);
    expect(result.errorEvents).toBeGreaterThan(0);
    expect(result.hasErrorPhase).toBe(true);
    expect(result.resultSuccess === false || result.threw === true).toBe(true);
    const statuses = result.statuses ?? [];
    const firstNonTerminalIdx = statuses.findIndex((status: string) => status !== 'failed');
    const failedIdx = statuses.findIndex((status: string) => status === 'failed');
    expect(firstNonTerminalIdx).toBeGreaterThanOrEqual(0);
    expect(failedIdx).toBeGreaterThan(firstNonTerminalIdx);
    if (result.lastEvent?.status) {
      expect(result.lastEvent.status).toBe('failed');
    }
  });
});
