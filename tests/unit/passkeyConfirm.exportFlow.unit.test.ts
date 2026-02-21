import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const WORKER_PATH = '/sdk/workers/passkey-confirm.worker.js';

test.describe('passkey-confirm export flow worker', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('returns cancelled when user cancels at first confirmation step', async ({ page }) => {
    const result = await page.evaluate(async ({ workerPath }) => {
      await import(workerPath);

      const originalPostMessage = (self as any).postMessage;
      const prompts: any[] = [];
      const responses: any[] = [];

      (self as any).postMessage = (message: any) => {
        if (message?.type === 'PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD') {
          prompts.push(message);
          self.dispatchEvent(new MessageEvent('message', {
            data: {
              type: 'USER_PASSKEY_CONFIRM_RESPONSE',
              requestId: message.requestId,
              channelToken: message.channelToken,
              data: {
                requestId: message.data?.requestId,
                confirmed: false,
                error: 'User cancelled export request',
              },
            },
          }));
          return;
        }
        responses.push(message);
      };

      try {
        (self as any).onmessage?.({
          data: {
            id: 'export-op-1',
            type: 'EXPORT_PRIVATE_KEYS_WITH_UI',
            payload: {
              nearAccountId: 'alice.testnet',
              deviceNumber: 1,
              hasThresholdKeyMaterial: true,
              schemes: ['ed25519'],
            },
          },
        });

        const workerResponse = await new Promise<any>((resolve, reject) => {
          const deadline = Date.now() + 3_000;
          const poll = () => {
            const found = responses.find((entry) => entry?.id === 'export-op-1');
            if (found) {
              resolve(found);
              return;
            }
            if (Date.now() >= deadline) {
              reject(new Error('Timed out waiting for export worker response'));
              return;
            }
            setTimeout(poll, 0);
          };
          poll();
        });

        return {
          promptCount: prompts.length,
          response: workerResponse,
        };
      } finally {
        (self as any).postMessage = originalPostMessage;
      }
    }, { workerPath: WORKER_PATH });

    expect(result.promptCount).toBe(1);
    expect(result.response).toMatchObject({
      id: 'export-op-1',
      success: true,
      data: {
        ok: false,
        cancelled: true,
        accountId: 'alice.testnet',
        exportedSchemes: [],
      },
    });
    expect(String(result.response?.data?.error || '')).toContain('User cancelled export request');
  });

  test('returns cancelled when user cancels at final export display step', async ({ page }) => {
    const result = await page.evaluate(async ({ workerPath }) => {
      await import(workerPath);

      const toB64u = (bytes: Uint8Array): string => {
        const binary = String.fromCharCode(...Array.from(bytes));
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
      };

      const prfFirst = toB64u(new Uint8Array(32).fill(7));
      const prfSecond = toB64u(new Uint8Array(32).fill(11));

      const originalPostMessage = (self as any).postMessage;
      const prompts: any[] = [];
      const responses: any[] = [];

      (self as any).postMessage = (message: any) => {
        if (message?.type === 'PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD') {
          prompts.push(message);
          const promptNumber = prompts.length;
          if (promptNumber === 1) {
            self.dispatchEvent(new MessageEvent('message', {
              data: {
                type: 'USER_PASSKEY_CONFIRM_RESPONSE',
                requestId: message.requestId,
                channelToken: message.channelToken,
                data: {
                  requestId: message.data?.requestId,
                  confirmed: true,
                  credential: {
                    clientExtensionResults: {
                      prf: { results: { first: prfFirst, second: prfSecond } },
                    },
                  },
                },
              },
            }));
            return;
          }

          self.dispatchEvent(new MessageEvent('message', {
            data: {
              type: 'USER_PASSKEY_CONFIRM_RESPONSE',
              requestId: message.requestId,
              channelToken: message.channelToken,
              data: {
                requestId: message.data?.requestId,
                confirmed: false,
                error: 'User cancelled export viewer',
              },
            },
          }));
          return;
        }
        responses.push(message);
      };

      try {
        (self as any).onmessage?.({
          data: {
            id: 'export-op-2',
            type: 'EXPORT_PRIVATE_KEYS_WITH_UI',
            payload: {
              nearAccountId: 'alice.testnet',
              deviceNumber: 1,
              hasThresholdKeyMaterial: true,
              schemes: ['secp256k1'],
              variant: 'drawer',
              theme: 'dark',
            },
          },
        });

        const workerResponse = await new Promise<any>((resolve, reject) => {
          const deadline = Date.now() + 5_000;
          const poll = () => {
            const found = responses.find((entry) => entry?.id === 'export-op-2');
            if (found) {
              resolve(found);
              return;
            }
            if (Date.now() >= deadline) {
              reject(new Error('Timed out waiting for export worker response'));
              return;
            }
            setTimeout(poll, 0);
          };
          poll();
        });

        return {
          promptCount: prompts.length,
          firstPromptType: prompts[0]?.data?.type || '',
          secondPromptType: prompts[1]?.data?.type || '',
          response: workerResponse,
        };
      } finally {
        (self as any).postMessage = originalPostMessage;
      }
    }, { workerPath: WORKER_PATH });

    expect(result.promptCount).toBe(2);
    expect(result.firstPromptType).toBe('decryptPrivateKeyWithPrf');
    expect(result.secondPromptType).toBe('showSecurePrivateKeyUi');
    expect(result.response).toMatchObject({
      id: 'export-op-2',
      success: true,
      data: {
        ok: false,
        cancelled: true,
        accountId: 'alice.testnet',
        exportedSchemes: [],
      },
    });
    expect(String(result.response?.data?.error || '')).toContain('User cancelled export viewer');
  });

  test('treats abort-like first-step error as cancelled', async ({ page }) => {
    const result = await page.evaluate(async ({ workerPath }) => {
      await import(workerPath);

      const originalPostMessage = (self as any).postMessage;
      const responses: any[] = [];

      (self as any).postMessage = (message: any) => {
        if (message?.type === 'PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD') {
          self.dispatchEvent(new MessageEvent('message', {
            data: {
              type: 'USER_PASSKEY_CONFIRM_RESPONSE',
              requestId: message.requestId,
              channelToken: message.channelToken,
              data: {
                requestId: message.data?.requestId,
                confirmed: false,
                error: 'NotAllowedError: user aborted or timeout',
              },
            },
          }));
          return;
        }
        responses.push(message);
      };

      try {
        (self as any).onmessage?.({
          data: {
            id: 'export-op-3',
            type: 'EXPORT_PRIVATE_KEYS_WITH_UI',
            payload: {
              nearAccountId: 'alice.testnet',
              deviceNumber: 1,
              hasThresholdKeyMaterial: true,
              schemes: ['ed25519'],
            },
          },
        });

        return await new Promise<any>((resolve, reject) => {
          const deadline = Date.now() + 3_000;
          const poll = () => {
            const found = responses.find((entry) => entry?.id === 'export-op-3');
            if (found) {
              resolve(found);
              return;
            }
            if (Date.now() >= deadline) {
              reject(new Error('Timed out waiting for export worker response'));
              return;
            }
            setTimeout(poll, 0);
          };
          poll();
        });
      } finally {
        (self as any).postMessage = originalPostMessage;
      }
    }, { workerPath: WORKER_PATH });

    expect(result).toMatchObject({
      id: 'export-op-3',
      success: true,
      data: {
        ok: false,
        cancelled: true,
        accountId: 'alice.testnet',
        exportedSchemes: [],
      },
    });
    expect(String(result?.data?.error || '')).toContain('NotAllowedError');
  });

  test('treats abort-like final-step error as cancelled', async ({ page }) => {
    const result = await page.evaluate(async ({ workerPath }) => {
      await import(workerPath);

      const toB64u = (bytes: Uint8Array): string => {
        const binary = String.fromCharCode(...Array.from(bytes));
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
      };

      const prfFirst = toB64u(new Uint8Array(32).fill(3));
      const prfSecond = toB64u(new Uint8Array(32).fill(5));

      const originalPostMessage = (self as any).postMessage;
      const prompts: any[] = [];
      const responses: any[] = [];

      (self as any).postMessage = (message: any) => {
        if (message?.type === 'PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD') {
          prompts.push(message);
          const promptNumber = prompts.length;
          if (promptNumber === 1) {
            self.dispatchEvent(new MessageEvent('message', {
              data: {
                type: 'USER_PASSKEY_CONFIRM_RESPONSE',
                requestId: message.requestId,
                channelToken: message.channelToken,
                data: {
                  requestId: message.data?.requestId,
                  confirmed: true,
                  credential: {
                    clientExtensionResults: {
                      prf: { results: { first: prfFirst, second: prfSecond } },
                    },
                  },
                },
              },
            }));
            return;
          }
          self.dispatchEvent(new MessageEvent('message', {
            data: {
              type: 'USER_PASSKEY_CONFIRM_RESPONSE',
              requestId: message.requestId,
              channelToken: message.channelToken,
              data: {
                requestId: message.data?.requestId,
                confirmed: false,
                error: 'AbortError: user aborted on export viewer',
              },
            },
          }));
          return;
        }
        responses.push(message);
      };

      try {
        (self as any).onmessage?.({
          data: {
            id: 'export-op-4',
            type: 'EXPORT_PRIVATE_KEYS_WITH_UI',
            payload: {
              nearAccountId: 'alice.testnet',
              deviceNumber: 1,
              hasThresholdKeyMaterial: true,
              schemes: ['secp256k1'],
              variant: 'drawer',
              theme: 'dark',
            },
          },
        });

        return await new Promise<any>((resolve, reject) => {
          const deadline = Date.now() + 5_000;
          const poll = () => {
            const found = responses.find((entry) => entry?.id === 'export-op-4');
            if (found) {
              resolve(found);
              return;
            }
            if (Date.now() >= deadline) {
              reject(new Error('Timed out waiting for export worker response'));
              return;
            }
            setTimeout(poll, 0);
          };
          poll();
        });
      } finally {
        (self as any).postMessage = originalPostMessage;
      }
    }, { workerPath: WORKER_PATH });

    expect(result).toMatchObject({
      id: 'export-op-4',
      success: true,
      data: {
        ok: false,
        cancelled: true,
        accountId: 'alice.testnet',
        exportedSchemes: [],
      },
    });
    expect(String(result?.data?.error || '')).toContain('AbortError');
  });
});
