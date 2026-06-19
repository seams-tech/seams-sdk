import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

// awaitUserConfirmationV2 is exposed from the UserConfirm worker bundle.
const WORKER_PATH = '/sdk/workers/passkey-confirm.worker.js';

test.describe('awaitUserConfirmationV2 - error handling', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('rejects on invalid input and missing fields', async ({ page }) => {
    const result = await page.evaluate(
      async ({ workerPath }) => {
        // Load the UserConfirm worker bundle; it exposes awaitUserConfirmationV2 on globalThis
        await import(workerPath);
        const awaitUserConfirmation = (globalThis as any).awaitUserConfirmationV2 as (
          req: any,
          opts?: any,
        ) => Promise<any>;
        const errors: string[] = [];
        try {
          await awaitUserConfirmation('not-json');
        } catch (e: any) {
          errors.push(String(e?.message || e));
        }
        try {
          await awaitUserConfirmation({});
        } catch (e: any) {
          errors.push(String(e?.message || e));
        }
        try {
          await awaitUserConfirmation({ type: 'signTransaction', summary: {}, payload: {} });
        } catch (e: any) {
          errors.push(String(e?.message || e));
        }
        try {
          await awaitUserConfirmation({ requestId: 'id-1', summary: {}, payload: {} });
        } catch (e: any) {
          errors.push(String(e?.message || e));
        }
        return { errors };
      },
      { workerPath: WORKER_PATH },
    );
    expect(result.errors.length).toBe(4);
    expect(result.errors.join(' ')).toContain('JSON strings are not supported');
    expect(result.errors.join(' ')).toContain('missing requestId');
    expect(result.errors.join(' ')).toContain('missing type');
  });

  test('rejects immediately when aborted', async ({ page }) => {
    const result = await page.evaluate(
      async ({ workerPath }) => {
        await import(workerPath);
        const awaitUserConfirmation = (globalThis as any).awaitUserConfirmationV2 as (
          req: any,
          opts?: any,
        ) => Promise<any>;
        const controller = new AbortController();
        controller.abort();
        try {
          await awaitUserConfirmation(
            {
              requestId: 'id-2',
              type: 'signTransaction',
              summary: {},
              payload: {
                signingAuthPlan: { kind: 'passkeyReauth', method: 'passkey' },
              },
            },
            { signal: controller.signal },
          );
          return { ok: true };
        } catch (e: any) {
          return { ok: false, message: String(e?.message || e) };
        }
      },
      { workerPath: WORKER_PATH },
    );
    expect(result.ok).toBe(false);
    expect(result.message).toContain('confirmation aborted');
  });

  test('times out when no matching response is received', async ({ page }) => {
    const result = await page.evaluate(
      async ({ workerPath }) => {
        await import(workerPath);
        const awaitUserConfirmation = (globalThis as any).awaitUserConfirmationV2 as (
          req: any,
          opts?: any,
        ) => Promise<any>;
        const originalPost = (self as any).postMessage;
        // Stub to avoid Window.postMessage signature issues when used by worker-style code
        (self as any).postMessage = (_msg: unknown) => {};
        try {
          await awaitUserConfirmation(
            {
              requestId: 'id-3',
              type: 'signTransaction',
              summary: {},
              payload: {
                signingAuthPlan: { kind: 'passkeyReauth', method: 'passkey' },
              },
            },
            { timeoutMs: 50 },
          );
          return { ok: true };
        } catch (e: any) {
          return { ok: false, message: String(e?.message || e) };
        } finally {
          (self as any).postMessage = originalPost;
        }
      },
      { workerPath: WORKER_PATH },
    );
    expect(result.ok).toBe(false);
    expect(result.message).toContain('confirmation timed out');
  });

  test('ignores mismatched response requestId', async ({ page }) => {
    const result = await page.evaluate(
      async ({ workerPath }) => {
        await import(workerPath);
        const awaitUserConfirmation = (globalThis as any).awaitUserConfirmationV2 as (
          req: any,
          opts?: any,
        ) => Promise<any>;
        const originalPost = (self as any).postMessage;
        (self as any).postMessage = (_msg: unknown) => {};
        const payload = {
          requestId: 'id-4',
          type: 'signTransaction',
          summary: {},
          payload: {
            signingAuthPlan: { kind: 'passkeyReauth', method: 'passkey' },
          },
        };
        setTimeout(() => {
          // Dispatch a message event with a mismatched requestId; listener should ignore it
          self.dispatchEvent(
            new MessageEvent('message', {
              data: {
                type: 'USER_PASSKEY_CONFIRM_RESPONSE',
                data: { requestId: 'DIFFERENT', confirmed: true },
              },
            }),
          );
        }, 10);
        try {
          await awaitUserConfirmation(payload, { timeoutMs: 60 });
          return { ok: true };
        } catch (e: any) {
          return { ok: false, message: String(e?.message || e) };
        } finally {
          (self as any).postMessage = originalPost;
        }
      },
      { workerPath: WORKER_PATH },
    );
    expect(result.ok).toBe(false);
    expect(result.message).toContain('confirmation timed out');
  });

  test('happy path: LocalOnly decrypt request returns confirmation response', async ({ page }) => {
    const result = await page.evaluate(
      async ({ workerPath }) => {
        await import(workerPath);
        const awaitUserConfirmation = (globalThis as any).awaitUserConfirmationV2 as (
          req: any,
          opts?: any,
        ) => Promise<any>;

        const request = {
          requestId: 'sess-1',
          type: 'decryptPrivateKeyWithPrf',
          summary: {
            operation: 'Decrypt Private Key',
            accountId: 'alice.testnet',
            publicKey: '',
            warning: 'Decrypting your private key grants full control of your account.',
          },
          payload: {
            nearAccountId: 'alice.testnet',
            publicKey: '',
          },
        };

        const originalAdd = self.addEventListener.bind(self);
        // Intercept PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD and synthesize a matching response
        self.addEventListener = ((type: string, listener: any, options?: any) => {
          if (type === 'message') {
            const wrapped = (ev: MessageEvent) => {
              const data: any = ev.data;
              if (data?.type === 'PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD') {
                self.dispatchEvent(
                  new MessageEvent('message', {
                    data: {
                      type: 'USER_PASSKEY_CONFIRM_RESPONSE',
                      requestId: data.requestId,
                      channelToken: data.channelToken,
                      data: {
                        requestId: data.data.requestId,
                        confirmed: true,
                      },
                    },
                  }),
                );
              }
              listener(ev);
            };
            return originalAdd(type, wrapped, options);
          }
          return originalAdd(type, listener, options);
        }) as any;

        const resp = await awaitUserConfirmation(request, { timeoutMs: 250 });
        return {
          requestId: resp?.request_id,
          confirmed: resp?.confirmed,
        };
      },
      { workerPath: WORKER_PATH },
    );

    expect(result.requestId).toBe('sess-1');
    expect(result.confirmed).toBe(true);
  });

  test('preserves Email OTP code and challenge id across the worker confirmation bridge', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ workerPath }) => {
        await import(workerPath);
        const awaitUserConfirmation = (globalThis as any).awaitUserConfirmationV2 as (
          req: any,
          opts?: any,
        ) => Promise<any>;

        const request = {
          requestId: 'email-otp-export-1',
          type: 'signIntentDigest',
          summary: {
            operation: 'Export Private Key',
            accountId: 'alice.testnet',
            publicKey: 'ed25519:test',
            warning: 'Exporting this private key grants full control of the account.',
          },
          payload: {
            nearAccountId: 'alice.testnet',
            challengeB64u: 'challenge-1',
            signingAuthPlan: {
              kind: 'emailOtpReauth',
              method: 'email_otp',
              emailOtpPrompt: {
                challengeId: 'email-otp-challenge-1',
                title: 'Enter email code to export',
                body: 'This one-time code authorizes private key export only.',
              },
            },
          },
          intentDigest: 'export-keys:alice.testnet:near:ed25519:email-otp',
        };

        const originalAdd = self.addEventListener.bind(self);
        self.addEventListener = ((type: string, listener: any, options?: any) => {
          if (type === 'message') {
            const wrapped = (ev: MessageEvent) => {
              const data: any = ev.data;
              if (data?.type === 'PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD') {
                self.dispatchEvent(
                  new MessageEvent('message', {
                    data: {
                      type: 'USER_PASSKEY_CONFIRM_RESPONSE',
                      requestId: data.requestId,
                      channelToken: data.channelToken,
                      data: {
                        requestId: data.data.requestId,
                        confirmed: true,
                        otpCode: '565253',
                        emailOtpChallengeId: 'email-otp-challenge-1',
                      },
                    },
                  }),
                );
              }
              listener(ev);
            };
            return originalAdd(type, wrapped, options);
          }
          return originalAdd(type, listener, options);
        }) as any;

        const resp = await awaitUserConfirmation(request, { timeoutMs: 250 });
        return {
          requestId: resp?.request_id,
          confirmed: resp?.confirmed,
          otpCode: resp?.otp_code,
          emailOtpChallengeId: resp?.email_otp_challenge_id,
        };
      },
      { workerPath: WORKER_PATH },
    );

    expect(result).toEqual({
      requestId: 'email-otp-export-1',
      confirmed: true,
      otpCode: '565253',
      emailOtpChallengeId: 'email-otp-challenge-1',
    });
  });

  test('ignores response with mismatched channel token', async ({ page }) => {
    const result = await page.evaluate(
      async ({ workerPath }) => {
        await import(workerPath);
        const awaitUserConfirmation = (globalThis as any).awaitUserConfirmationV2 as (
          req: any,
          opts?: any,
        ) => Promise<any>;

        const request = {
          requestId: 'sess-channel-mismatch',
          type: 'decryptPrivateKeyWithPrf',
          summary: {
            operation: 'Decrypt Private Key',
            accountId: 'alice.testnet',
            publicKey: '',
            warning: 'Decrypting your private key grants full control of your account.',
          },
          payload: {
            nearAccountId: 'alice.testnet',
            publicKey: '',
          },
        };

        const originalAdd = self.addEventListener.bind(self);
        self.addEventListener = ((type: string, listener: any, options?: any) => {
          if (type === 'message') {
            const wrapped = (ev: MessageEvent) => {
              const data: any = ev.data;
              if (data?.type === 'PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD') {
                self.dispatchEvent(
                  new MessageEvent('message', {
                    data: {
                      type: 'USER_PASSKEY_CONFIRM_RESPONSE',
                      requestId: data.requestId,
                      channelToken: 'wrong-token',
                      data: {
                        requestId: data.data.requestId,
                        confirmed: true,
                      },
                    },
                  }),
                );
              }
              listener(ev);
            };
            return originalAdd(type, wrapped, options);
          }
          return originalAdd(type, listener, options);
        }) as any;

        try {
          await awaitUserConfirmation(request, { timeoutMs: 80 });
          return { ok: true };
        } catch (e: any) {
          return { ok: false, message: String(e?.message || e) };
        }
      },
      { workerPath: WORKER_PATH },
    );

    expect(result.ok).toBe(false);
    expect(result.message).toContain('confirmation timed out');
  });
});
