import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import bs58 from 'bs58';
import { ed25519 } from '@noble/curves/ed25519.js';

const WORKER_PATH = '/sdk/workers/passkey-confirm.worker.js';

function toB64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

function deriveExpectedPublicKey(seedBytes: Uint8Array): string {
  const publicKeyBytes = ed25519.getPublicKey(seedBytes);
  return `ed25519:${bs58.encode(publicKeyBytes)}`;
}

test.describe('passkey-confirm export flow worker', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('returns cancelled when user cancels at first confirmation step', async ({ page }) => {
    const seedBytes = new Uint8Array(32).fill(7);
    const result = await page.evaluate(
      async ({ workerPath, seedB64u, expectedPublicKey }) => {
        await import(workerPath);

        const originalPostMessage = (self as any).postMessage;
        const prompts: any[] = [];
        const responses: any[] = [];

        (self as any).postMessage = (message: any) => {
          if (message?.type === 'PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD') {
            prompts.push(message);
            self.dispatchEvent(
              new MessageEvent('message', {
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
              }),
            );
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
                chain: 'near',
                artifactKind: 'near-ed25519-seed-v1',
                expectedPublicKey,
                seedB64u,
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
      },
      {
        workerPath: WORKER_PATH,
        seedB64u: toB64u(seedBytes),
        expectedPublicKey: deriveExpectedPublicKey(seedBytes),
      },
    );

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
                nearAccountId: 'alice.testnet',
                deviceNumber: 1,
                chain: 'evm',
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
            response: workerResponse,
          };
        } finally {
          (self as any).postMessage = originalPostMessage;
        }
      },
      { workerPath: WORKER_PATH },
    );

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
    const seedBytes = new Uint8Array(32).fill(9);
    const result = await page.evaluate(
      async ({ workerPath, seedB64u, expectedPublicKey }) => {
        await import(workerPath);

        const originalPostMessage = (self as any).postMessage;
        const responses: any[] = [];

        (self as any).postMessage = (message: any) => {
          if (message?.type === 'PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD') {
            self.dispatchEvent(
              new MessageEvent('message', {
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
              }),
            );
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
                chain: 'near',
                artifactKind: 'near-ed25519-seed-v1',
                expectedPublicKey,
                seedB64u,
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
      },
      {
        workerPath: WORKER_PATH,
        seedB64u: toB64u(seedBytes),
        expectedPublicKey: deriveExpectedPublicKey(seedBytes),
      },
    );

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
                nearAccountId: 'alice.testnet',
                deviceNumber: 1,
                chain: 'evm',
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
        accountId: 'alice.testnet',
        exportedSchemes: [],
      },
    });
    expect(String(result?.data?.error || '')).toContain('AbortError');
  });

  test('fails closed when seed does not match expected public key', async ({ page }) => {
    const seedBytes = new Uint8Array(32).fill(13);
    const wrongExpectedPublicKey = deriveExpectedPublicKey(new Uint8Array(32).fill(17));

    const result = await page.evaluate(
      async ({ workerPath, seedB64u, expectedPublicKey }) => {
        await import(workerPath);

        const originalPostMessage = (self as any).postMessage;
        const prompts: any[] = [];
        const responses: any[] = [];

        (self as any).postMessage = (message: any) => {
          if (message?.type === 'PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD') {
            prompts.push(message);
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
                      clientExtensionResults: { prf: { results: {} } },
                    },
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
              id: 'export-op-near-mismatch',
              type: 'EXPORT_PRIVATE_KEYS_WITH_UI',
              payload: {
                nearAccountId: 'alice.testnet',
                deviceNumber: 1,
                chain: 'near',
                artifactKind: 'near-ed25519-seed-v1',
                expectedPublicKey,
                seedB64u,
                theme: 'dark',
              },
            },
          });

          const workerResponse = await new Promise<any>((resolve, reject) => {
            const deadline = Date.now() + 10_000;
            const poll = () => {
              const found = responses.find((entry) => entry?.id === 'export-op-near-mismatch');
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
      {
        workerPath: WORKER_PATH,
        seedB64u: toB64u(seedBytes),
        expectedPublicKey: wrongExpectedPublicKey,
      },
    );

    expect(result.promptCount).toBe(1);
    expect(result.response).toMatchObject({
      id: 'export-op-near-mismatch',
      success: false,
    });
    expect(String(result.response?.error || '')).toContain('unexpected public key');
  });

  test('completes NEAR seed export happy path', async ({ page }) => {
    const seedBytes = new Uint8Array(32).fill(29);
    const expectedPublicKey = deriveExpectedPublicKey(seedBytes);

    const result = await page.evaluate(
      async ({ workerPath, seedB64u, expectedPublicKey }) => {
        await import(workerPath);

        const originalPostMessage = (self as any).postMessage;
        const prompts: any[] = [];
        const responses: any[] = [];
        let finalPromptKeys: any[] = [];

        (self as any).postMessage = (message: any) => {
          if (message?.type === 'PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD') {
            prompts.push(message);
            const promptType = String(message?.data?.type || '');
            if (promptType === 'decryptPrivateKeyWithPrf') {
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
                        id: 'cred-1',
                        rawId: 'cred-1',
                        type: 'public-key',
                        response: {
                          clientDataJSON: 'eyJjaGFsbGVuZ2UiOiJ0ZXN0In0',
                          authenticatorData: 'Ag',
                          signature: 'Aw',
                          userHandle: null,
                        },
                        clientExtensionResults: { prf: { results: {} } },
                      },
                    },
                  },
                }),
              );
              return;
            }

            if (promptType === 'showSecurePrivateKeyUi') {
              finalPromptKeys = Array.isArray(message?.data?.payload?.keys)
                ? message.data.payload.keys
                : [];
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
          }
          responses.push(message);
        };

        try {
          (self as any).onmessage?.({
            data: {
              id: 'export-op-near-happy-path',
              type: 'EXPORT_PRIVATE_KEYS_WITH_UI',
              payload: {
                nearAccountId: 'alice.testnet',
                deviceNumber: 1,
                chain: 'near',
                artifactKind: 'near-ed25519-seed-v1',
                expectedPublicKey,
                seedB64u,
                theme: 'dark',
              },
            },
          });

          const workerResponse = await new Promise<any>((resolve, reject) => {
            const deadline = Date.now() + 10_000;
            const poll = () => {
              const found = responses.find((entry) => entry?.id === 'export-op-near-happy-path');
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
            promptTypes: prompts.map((entry) => String(entry?.data?.type || '')),
            finalPromptKeys,
            response: workerResponse,
          };
        } finally {
          (self as any).postMessage = originalPostMessage;
        }
      },
      {
        workerPath: WORKER_PATH,
        seedB64u: toB64u(seedBytes),
        expectedPublicKey,
      },
    );

    expect(result.promptCount).toBe(2);
    expect(result.promptTypes).toEqual(['decryptPrivateKeyWithPrf', 'showSecurePrivateKeyUi']);
    expect(result.finalPromptKeys).toHaveLength(1);
    expect(result.finalPromptKeys[0]).toMatchObject({
      scheme: 'ed25519',
      publicKey: expectedPublicKey,
    });
    expect(String(result.finalPromptKeys[0]?.privateKey || '')).toMatch(/^ed25519:/);
    expect(result.response).toMatchObject({
      id: 'export-op-near-happy-path',
      success: true,
      data: {
        ok: true,
        accountId: 'alice.testnet',
        exportedSchemes: ['ed25519'],
      },
    });
  });

  test('completes canonical ecdsa-hss EVM export without PRF.second', async ({ page }) => {
    const publicKeyHex = `0x${'02'}${'44'.repeat(32)}`;
    const privateKeyHex = `0x${'55'.repeat(32)}`;
    const ethereumAddress = `0x${'66'.repeat(20)}`;

    const result = await page.evaluate(
      async ({ workerPath, publicKeyHex, privateKeyHex, ethereumAddress }) => {
        await import(workerPath);

        const originalPostMessage = (self as any).postMessage;
        const prompts: any[] = [];
        const responses: any[] = [];
        let firstPromptCredential: any = 'unset';
        let finalPromptKeys: any[] = [];

        (self as any).postMessage = (message: any) => {
          if (message?.type === 'PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD') {
            prompts.push(message);
            const promptType = String(message?.data?.type || '');
            if (promptType === 'decryptPrivateKeyWithPrf') {
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

            if (promptType === 'showSecurePrivateKeyUi') {
              firstPromptCredential = prompts[0]?.data?.credential;
              finalPromptKeys = Array.isArray(message?.data?.payload?.keys)
                ? message.data.payload.keys
                : [];
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
          }
          responses.push(message);
        };

        try {
          (self as any).onmessage?.({
            data: {
              id: 'export-op-ecdsa-hss-happy-path',
              type: 'EXPORT_PRIVATE_KEYS_WITH_UI',
              payload: {
                nearAccountId: 'alice.testnet',
                deviceNumber: 1,
                chain: 'evm',
                artifactKind: 'ecdsa-hss-secp256k1-key-v1',
                publicKeyHex,
                privateKeyHex,
                ethereumAddress,
                theme: 'dark',
              },
            },
          });

          const workerResponse = await new Promise<any>((resolve, reject) => {
            const deadline = Date.now() + 10_000;
            const poll = () => {
              const found = responses.find(
                (entry) => entry?.id === 'export-op-ecdsa-hss-happy-path',
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
            promptTypes: prompts.map((entry) => String(entry?.data?.type || '')),
            firstPromptCredential,
            finalPromptKeys,
            response: workerResponse,
          };
        } finally {
          (self as any).postMessage = originalPostMessage;
        }
      },
      {
        workerPath: WORKER_PATH,
        publicKeyHex,
        privateKeyHex,
        ethereumAddress,
      },
    );

    expect(result.promptCount).toBe(2);
    expect(result.promptTypes).toEqual(['decryptPrivateKeyWithPrf', 'showSecurePrivateKeyUi']);
    expect(result.firstPromptCredential).toBeUndefined();
    expect(result.finalPromptKeys).toHaveLength(1);
    expect(result.finalPromptKeys[0]).toMatchObject({
      scheme: 'secp256k1',
      publicKey: publicKeyHex,
      privateKey: privateKeyHex,
      address: ethereumAddress,
    });
    expect(result.response).toMatchObject({
      id: 'export-op-ecdsa-hss-happy-path',
      success: true,
      data: {
        ok: true,
        accountId: 'alice.testnet',
        exportedSchemes: ['secp256k1'],
      },
    });
  });
});
