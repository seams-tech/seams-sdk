import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import { hkdfSync } from 'node:crypto';
import bs58 from 'bs58';
import { ed25519 } from '@noble/curves/ed25519.js';

const WORKER_PATH = '/sdk/workers/passkey-confirm.worker.js';
const RECOVERY_DOMAIN_TAG_V1 = 'option-b-recovery:v1';
const RECOVERY_CLIENT_SHARE_SALT_V1 = 'tatchi/lite/threshold-ed25519/recovery/client-share:v1';

function toB64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

function buildRecoveryDerivationInfo(input: {
  nearAccountId: string;
  rpId: string;
  keyVersion: string;
}): Buffer {
  const info = Buffer.concat([
    Buffer.from(RECOVERY_DOMAIN_TAG_V1, 'utf8'),
    Buffer.from([0]),
    Buffer.from(input.nearAccountId, 'utf8'),
    Buffer.from([0]),
    Buffer.from(input.rpId, 'utf8'),
    Buffer.from([0]),
    Buffer.from(input.keyVersion, 'utf8'),
    Buffer.from([0]),
    Buffer.from([0, 1]),
    Buffer.from([0, 2]),
    Buffer.from([0, 0, 0, 1]),
  ]);
  return info;
}

function deriveExpectedRecoveryPublicKey(input: {
  prfFirst: Uint8Array;
  nearAccountId: string;
  rpId: string;
  keyVersion: string;
}): string {
  const recoverySeed = hkdfSync(
    'sha256',
    Buffer.from(input.prfFirst),
    Buffer.from(RECOVERY_CLIENT_SHARE_SALT_V1, 'utf8'),
    buildRecoveryDerivationInfo(input),
    32,
  );
  const publicKeyBytes = ed25519.getPublicKey(new Uint8Array(recoverySeed));
  return `ed25519:${bs58.encode(publicKeyBytes)}`;
}

test.describe('passkey-confirm export flow worker', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('returns cancelled when user cancels at first confirmation step', async ({ page }) => {
    const result = await page.evaluate(
      async ({ workerPath }) => {
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
                artifactKind: 'near-ed25519-option-b-v1',
                keyVersion: 'option-b-v1',
                recoveryExportCapable: true,
                relayerUrl: 'https://relay.example.test',
                relayerKeyId: 'ed25519:operational-key',
                rpId: 'wallet.example.test',
                recoveryPublicKey: 'ed25519:expected-recovery-key',
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
      { workerPath: WORKER_PATH },
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
                hasThresholdKeyMaterial: true,
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
    const result = await page.evaluate(
      async ({ workerPath }) => {
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
                artifactKind: 'near-ed25519-option-b-v1',
                keyVersion: 'option-b-v1',
                recoveryExportCapable: true,
                relayerUrl: 'https://relay.example.test',
                relayerKeyId: 'ed25519:operational-key',
                rpId: 'wallet.example.test',
                recoveryPublicKey: 'ed25519:expected-recovery-key',
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
      { workerPath: WORKER_PATH },
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
                hasThresholdKeyMaterial: true,
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

  test('fails closed when recovered NEAR recovery keypair does not match expected public key', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ workerPath }) => {
        await import(workerPath);

        const toB64u = (bytes: Uint8Array): string => {
          const binary = String.fromCharCode(...Array.from(bytes));
          return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
        };

        const prfFirst = toB64u(new Uint8Array(32).fill(13));
        const prfSecond = toB64u(new Uint8Array(32).fill(17));

        const originalPostMessage = (self as any).postMessage;
        const originalFetch = globalThis.fetch;
        const prompts: any[] = [];
        const responses: any[] = [];
        const fetchCalls: Array<{ url: string; body: any }> = [];

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
          responses.push(message);
        };

        globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
          const url = String(input);
          if (!url.includes('/threshold-ed25519/export/')) {
            return await originalFetch(input, init);
          }
          const body = init?.body ? JSON.parse(String(init.body)) : null;
          fetchCalls.push({ url, body });
          if (url.endsWith('/threshold-ed25519/export/init')) {
            return new Response(
              JSON.stringify({
                ok: true,
                exportId: 'export-near-1',
                relayerKeyId: 'ed25519:operational-key',
                artifactKind: 'near-ed25519-option-b-v1',
                recoveryPublicKey: 'ed25519:expected-recovery-key',
                keyVersion: 'option-b-v1',
                recoveryExportCapable: true,
                participantIds: [1, 2],
              }),
              { status: 200, headers: { 'Content-Type': 'application/json' } },
            );
          }
          if (url.endsWith('/threshold-ed25519/export/combine')) {
            return new Response(
              JSON.stringify({
                ok: true,
                exportId: 'export-near-1',
                relayerKeyId: 'ed25519:operational-key',
                artifactKind: 'near-ed25519-option-b-v1',
                recoveryPublicKey: 'ed25519:expected-recovery-key',
                keyVersion: 'option-b-v1',
                recoveryExportCapable: true,
                participantIds: [1, 2],
                serverCiphertextB64u: body?.clientCiphertextB64u,
              }),
              { status: 200, headers: { 'Content-Type': 'application/json' } },
            );
          }
          throw new Error(`Unexpected fetch: ${url}`);
        }) as typeof fetch;

        try {
          (self as any).onmessage?.({
            data: {
              id: 'export-op-near-mismatch',
              type: 'EXPORT_PRIVATE_KEYS_WITH_UI',
              payload: {
                nearAccountId: 'alice.testnet',
                deviceNumber: 1,
                chain: 'near',
                artifactKind: 'near-ed25519-option-b-v1',
                keyVersion: 'option-b-v1',
                recoveryExportCapable: true,
                relayerUrl: 'https://relay.example.test',
                relayerKeyId: 'ed25519:operational-key',
                rpId: 'wallet.example.test',
                recoveryPublicKey: 'ed25519:expected-recovery-key',
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
          fetchCallCount: fetchCalls.length,
        };
        } finally {
          (self as any).postMessage = originalPostMessage;
          globalThis.fetch = originalFetch;
        }
      },
      { workerPath: WORKER_PATH },
    );

    expect(result.promptCount).toBe(1);
    expect(result.fetchCallCount).toBeGreaterThanOrEqual(1);
    expect(result.response).toMatchObject({
      id: 'export-op-near-mismatch',
      success: false,
    });
    expect(String(result.response?.error || '')).toContain('does not match the expected public key');
  });

  test('completes live NEAR recovery export happy path with worker-owned Paillier flow', async ({
    page,
  }) => {
    const prfFirstBytes = new Uint8Array(32).fill(29);
    const expectedRecoveryPublicKey = deriveExpectedRecoveryPublicKey({
      prfFirst: prfFirstBytes,
      nearAccountId: 'alice.testnet',
      rpId: 'wallet.example.test',
      keyVersion: 'option-b-v1',
    });

    const result = await page.evaluate(
      async ({ workerPath, prfFirstB64u, expectedRecoveryPublicKey }) => {
        await import(workerPath);

        const originalPostMessage = (self as any).postMessage;
        const originalFetch = globalThis.fetch;
        const prompts: any[] = [];
        const responses: any[] = [];
        const fetchCalls: Array<{ url: string; body: any }> = [];
        let finalPromptKeys: any[] = [];
        let finalPromptGuidance: any = null;

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
                        clientExtensionResults: {
                          prf: { results: { first: prfFirstB64u } },
                        },
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
              finalPromptGuidance = message?.data?.payload?.guidance || null;
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

        globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
          const url = String(input);
          if (!url.includes('/threshold-ed25519/export/')) {
            return await originalFetch(input, init);
          }
          const body = init?.body ? JSON.parse(String(init.body)) : null;
          fetchCalls.push({ url, body });
          if (url.endsWith('/threshold-ed25519/export/init')) {
            return new Response(
              JSON.stringify({
                ok: true,
                exportId: 'export-near-happy-path',
                relayerKeyId: 'ed25519:operational-key',
                artifactKind: 'near-ed25519-option-b-v1',
                recoveryPublicKey: expectedRecoveryPublicKey,
                keyVersion: 'option-b-v1',
                recoveryExportCapable: true,
                participantIds: [1, 2],
              }),
              { status: 200, headers: { 'Content-Type': 'application/json' } },
            );
          }
          if (url.endsWith('/threshold-ed25519/export/combine')) {
            return new Response(
              JSON.stringify({
                ok: true,
                exportId: 'export-near-happy-path',
                relayerKeyId: 'ed25519:operational-key',
                artifactKind: 'near-ed25519-option-b-v1',
                recoveryPublicKey: expectedRecoveryPublicKey,
                keyVersion: 'option-b-v1',
                recoveryExportCapable: true,
                participantIds: [1, 2],
                serverCiphertextB64u: String(body?.clientCiphertextB64u || ''),
              }),
              { status: 200, headers: { 'Content-Type': 'application/json' } },
            );
          }
          throw new Error(`Unexpected fetch: ${url}`);
        }) as typeof fetch;

        try {
          (self as any).onmessage?.({
            data: {
              id: 'export-op-near-happy-path',
              type: 'EXPORT_PRIVATE_KEYS_WITH_UI',
              payload: {
                nearAccountId: 'alice.testnet',
                deviceNumber: 1,
                chain: 'near',
                artifactKind: 'near-ed25519-option-b-v1',
                keyVersion: 'option-b-v1',
                recoveryExportCapable: true,
                relayerUrl: 'https://relay.example.test',
                relayerKeyId: 'ed25519:operational-key',
                rpId: 'wallet.example.test',
                recoveryPublicKey: expectedRecoveryPublicKey,
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
            fetchCalls,
            finalPromptKeys,
            finalPromptGuidance,
            response: workerResponse,
          };
        } finally {
          (self as any).postMessage = originalPostMessage;
          globalThis.fetch = originalFetch;
        }
      },
      {
        workerPath: WORKER_PATH,
        prfFirstB64u: toB64u(prfFirstBytes),
        expectedRecoveryPublicKey,
      },
    );

    expect(result.promptCount).toBe(2);
    expect(result.promptTypes).toEqual(['decryptPrivateKeyWithPrf', 'showSecurePrivateKeyUi']);
    expect(result.fetchCalls).toHaveLength(2);
    expect(String(result.fetchCalls[0]?.url || '')).toContain('/threshold-ed25519/export/init');
    expect(String(result.fetchCalls[1]?.url || '')).toContain('/threshold-ed25519/export/combine');
    expect(String(result.fetchCalls[0]?.body?.webauthn_authentication?.id || '')).toBe('cred-1');
    expect(String(result.fetchCalls[1]?.body?.paillierPublicKeyB64u || '')).not.toBe('');
    expect(String(result.fetchCalls[1]?.body?.clientCiphertextB64u || '')).not.toBe('');
    expect(result.finalPromptKeys).toHaveLength(1);
    expect(result.finalPromptKeys[0]).toMatchObject({
      scheme: 'ed25519',
      publicKey: expectedRecoveryPublicKey,
    });
    expect(result.finalPromptGuidance).toMatchObject({
      title: 'Manual NEAR recovery',
    });
    expect(Array.isArray(result.finalPromptGuidance?.steps)).toBe(true);
    expect(result.finalPromptGuidance.steps).toHaveLength(3);
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

  test('fails closed when export-init step-up challenge is bound to a different account', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ workerPath }) => {
        await import(workerPath);

        const toB64u = (bytes: Uint8Array): string => {
          const binary = String.fromCharCode(...Array.from(bytes));
          return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
        };
        const fromB64u = (input: string): Uint8Array => {
          const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
          const padding = '='.repeat((4 - (normalized.length % 4)) % 4);
          const binary = atob(normalized + padding);
          return Uint8Array.from(binary, (char) => char.charCodeAt(0));
        };
        const normalizeValue = (value: any): any => {
          if (Array.isArray(value)) return value.map(normalizeValue);
          if (value && typeof value === 'object') {
            return Object.keys(value)
              .sort()
              .reduce((acc, key) => {
                acc[key] = normalizeValue(value[key]);
                return acc;
              }, {} as Record<string, unknown>);
          }
          return value;
        };
        const computeChallenge = async (input: {
          nearAccountId: string;
          rpId: string;
          relayerKeyId: string;
          keyVersion: string;
          recoveryPublicKey: string;
        }): Promise<string> => {
          const json = JSON.stringify(
            normalizeValue({
              version: 'threshold_ed25519_export_init_v1',
              artifactKind: 'near-ed25519-option-b-v1',
              nearAccountId: input.nearAccountId,
              rpId: input.rpId,
              relayerKeyId: input.relayerKeyId,
              keyVersion: input.keyVersion,
              recoveryPublicKey: input.recoveryPublicKey,
            }),
          );
          const digest = new Uint8Array(
            await crypto.subtle.digest('SHA-256', new TextEncoder().encode(json)),
          );
          return toB64u(digest);
        };

        const prfFirst = toB64u(new Uint8Array(32).fill(19));
        const originalPostMessage = (self as any).postMessage;
        const originalFetch = globalThis.fetch;
        const prompts: any[] = [];
        const responses: any[] = [];
        const fetchCalls: Array<{ url: string; body: any }> = [];
        let promptedChallengeB64u = '';
        let persistedChallengeB64u = '';

        (self as any).postMessage = (message: any) => {
          if (message?.type === 'PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD') {
            prompts.push(message);
            promptedChallengeB64u = String(message?.data?.payload?.challengeB64u || '');
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
                        clientDataJSON: toB64u(
                          new TextEncoder().encode(
                            JSON.stringify({
                              type: 'webauthn.get',
                              challenge: promptedChallengeB64u,
                              origin: 'https://wallet.example.test',
                            }),
                          ),
                        ),
                        authenticatorData: 'Ag',
                        signature: 'Aw',
                        userHandle: null,
                      },
                      clientExtensionResults: {
                        prf: { results: { first: prfFirst } },
                      },
                    },
                  },
                },
              }),
            );
            return;
          }
          responses.push(message);
        };

        globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
          const url = String(input);
          if (!url.includes('/threshold-ed25519/export/')) {
            return await originalFetch(input, init);
          }
          const body = init?.body ? JSON.parse(String(init.body)) : null;
          fetchCalls.push({ url, body });
          if (url.endsWith('/threshold-ed25519/export/init')) {
            persistedChallengeB64u = await computeChallenge({
              nearAccountId: 'alice.testnet',
              rpId: 'wallet.example.test',
              relayerKeyId: 'ed25519:operational-key',
              keyVersion: 'option-b-v1',
              recoveryPublicKey: 'ed25519:expected-recovery-key',
            });
            const clientDataJsonB64u = String(
              body?.webauthn_authentication?.response?.clientDataJSON || '',
            );
            const clientData = clientDataJsonB64u
              ? JSON.parse(new TextDecoder().decode(fromB64u(clientDataJsonB64u)))
              : {};
            if (String(clientData?.challenge || '') !== persistedChallengeB64u) {
              return new Response(
                JSON.stringify({
                  ok: false,
                  code: 'unauthorized',
                  message: 'Authentication verification failed',
                }),
                { status: 401, headers: { 'Content-Type': 'application/json' } },
              );
            }
            return new Response(
              JSON.stringify({
                ok: true,
                exportId: 'export-near-wrong-account',
                relayerKeyId: 'ed25519:operational-key',
                artifactKind: 'near-ed25519-option-b-v1',
                recoveryPublicKey: 'ed25519:expected-recovery-key',
                keyVersion: 'option-b-v1',
                recoveryExportCapable: true,
                participantIds: [1, 2],
              }),
              { status: 200, headers: { 'Content-Type': 'application/json' } },
            );
          }
          throw new Error(`Unexpected fetch: ${url}`);
        }) as typeof fetch;

        try {
          (self as any).onmessage?.({
            data: {
              id: 'export-op-near-wrong-account',
              type: 'EXPORT_PRIVATE_KEYS_WITH_UI',
              payload: {
                nearAccountId: 'mallory.testnet',
                deviceNumber: 1,
                chain: 'near',
                artifactKind: 'near-ed25519-option-b-v1',
                keyVersion: 'option-b-v1',
                recoveryExportCapable: true,
                relayerUrl: 'https://relay.example.test',
                relayerKeyId: 'ed25519:operational-key',
                rpId: 'wallet.example.test',
                recoveryPublicKey: 'ed25519:expected-recovery-key',
                theme: 'dark',
              },
            },
          });

          const workerResponse = await new Promise<any>((resolve, reject) => {
            const deadline = Date.now() + 10_000;
            const poll = () => {
              const found = responses.find(
                (entry) => entry?.id === 'export-op-near-wrong-account',
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
            fetchCallCount: fetchCalls.length,
            promptedChallengeB64u,
            persistedChallengeB64u,
            response: workerResponse,
          };
        } finally {
          (self as any).postMessage = originalPostMessage;
          globalThis.fetch = originalFetch;
        }
      },
      { workerPath: WORKER_PATH },
    );

    expect(result.promptCount).toBe(1);
    expect(result.fetchCallCount).toBe(1);
    expect(result.promptedChallengeB64u).not.toBe('');
    expect(result.persistedChallengeB64u).not.toBe('');
    expect(result.promptedChallengeB64u).not.toBe(result.persistedChallengeB64u);
    expect(result.response).toMatchObject({
      id: 'export-op-near-wrong-account',
      success: false,
    });
    expect(String(result.response?.error || '')).toContain('Authentication verification failed');
  });
});
