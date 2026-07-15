import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const WORKER_PATH = '/sdk/workers/passkey-confirm.worker.js';

test.describe('passkey-confirm export flow worker', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('returns cancelled when user cancels at final export display step', async ({ page }) => {
    const result = await page.evaluate(
      async ({ workerPath }) => {
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
              self.dispatchEvent(
                new MessageEvent('message', {
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
                }),
              );
              return;
            }
            if (promptNumber === 2) {
              self.dispatchEvent(
                new MessageEvent('message', {
                  data: {
                    type: 'USER_PASSKEY_CONFIRM_RESPONSE',
                    requestId: message.requestId,
                    channelToken: message.channelToken,
                    data: {
                      requestId: message.data?.requestId,
                      confirmed: true,
                    },
                  },
                }),
              );
              return;
            }

            self.dispatchEvent(
              new MessageEvent('message', {
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
              }),
            );
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
                walletId: 'frost-vermillion-k7p9m2',
                chainTarget: {
                  kind: 'evm',
                  namespace: 'eip155',
                  chainId: 5042002,
                  networkSlug: 'arc-testnet',
                },
                variant: 'drawer',
                theme: 'dark',
              },
            },
          });

          const workerResponse = await new Promise<any>((resolve, reject) => {
            const deadline = Date.now() + 10_000;
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
            thirdPromptType: prompts[2]?.data?.type || '',
            response: workerResponse,
          };
        } finally {
          (self as any).postMessage = originalPostMessage;
        }
      },
      { workerPath: WORKER_PATH },
    );

    expect(result.promptCount).toBe(3);
    expect(result.firstPromptType).toBe('decryptPrivateKeyWithPrf');
    expect(result.secondPromptType).toBe('showSecurePrivateKeyUi');
    expect(result.thirdPromptType).toBe('showSecurePrivateKeyUi');
    expect(result.response).toMatchObject({
      id: 'export-op-2',
      success: true,
      data: {
        ok: false,
        cancelled: true,
        accountId: 'frost-vermillion-k7p9m2',
        exportedSchemes: [],
      },
    });
    expect(String(result.response?.data?.error || '')).toContain('User cancelled export viewer');
  });

  test('treats abort-like final-step error as cancelled', async ({ page }) => {
    const result = await page.evaluate(
      async ({ workerPath }) => {
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
              self.dispatchEvent(
                new MessageEvent('message', {
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
                }),
              );
              return;
            }
            if (promptNumber === 2) {
              self.dispatchEvent(
                new MessageEvent('message', {
                  data: {
                    type: 'USER_PASSKEY_CONFIRM_RESPONSE',
                    requestId: message.requestId,
                    channelToken: message.channelToken,
                    data: {
                      requestId: message.data?.requestId,
                      confirmed: true,
                    },
                  },
                }),
              );
              return;
            }
            self.dispatchEvent(
              new MessageEvent('message', {
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
              }),
            );
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
                walletId: 'frost-vermillion-k7p9m2',
                chainTarget: {
                  kind: 'evm',
                  namespace: 'eip155',
                  chainId: 5042002,
                  networkSlug: 'arc-testnet',
                },
                variant: 'drawer',
                theme: 'dark',
              },
            },
          });

          return await new Promise<any>((resolve, reject) => {
            const deadline = Date.now() + 10_000;
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
      },
      { workerPath: WORKER_PATH },
    );

    expect(result).toMatchObject({
      id: 'export-op-4',
      success: true,
      data: {
        ok: false,
        cancelled: true,
        accountId: 'frost-vermillion-k7p9m2',
        exportedSchemes: [],
      },
    });
    expect(String(result?.data?.error || '')).toContain('AbortError');
  });

  test('rejects retired ecdsa-hss secp256k1 key artifact kind without prompting', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ workerPath }) => {
        await import(workerPath);

        const originalPostMessage = (self as any).postMessage;
        const prompts: any[] = [];
        const responses: any[] = [];

        (self as any).postMessage = (message: any) => {
          if (message?.type === 'PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD') {
            prompts.push(message);
            return;
          }
          responses.push(message);
        };

        try {
          (self as any).onmessage?.({
            data: {
              id: 'export-op-retired-ecdsa-hss-kind',
              type: 'EXPORT_PRIVATE_KEYS_WITH_UI',
              payload: {
                walletId: 'frost-vermillion-k7p9m2',
                chainTarget: {
                  kind: 'evm',
                  namespace: 'eip155',
                  chainId: 5042002,
                  networkSlug: 'arc-testnet',
                },
                artifactKind: 'ecdsa-hss-secp256k1-key-v1',
                publicKeyHex: `0x${'02'}${'11'.repeat(32)}`,
                privateKeyHex: `0x${'22'.repeat(32)}`,
                ethereumAddress: `0x${'33'.repeat(20)}`,
                theme: 'dark',
              },
            },
          });

          const workerResponse = await new Promise<any>((resolve, reject) => {
            const deadline = Date.now() + 3_000;
            const poll = () => {
              const found = responses.find(
                (entry) => entry?.id === 'export-op-retired-ecdsa-hss-kind',
              );
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
      },
      { workerPath: WORKER_PATH },
    );

    expect(result.promptCount).toBe(0);
    expect(result.response).toMatchObject({
      id: 'export-op-retired-ecdsa-hss-kind',
      success: false,
      error: 'Invalid EXPORT_PRIVATE_KEYS_WITH_UI payload',
    });
  });
});
