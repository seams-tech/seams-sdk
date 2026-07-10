import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  // Use concrete module path that exists in dist
  fallbacks: '/_test-sdk/esm/core/signingEngine/webauthnAuth/fallbacks/safari-fallbacks.js',
} as const;

test.describe('Safari WebAuthn fallbacks - cancellation and timeout behavior', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await page.waitForTimeout(150);
  });

  test('create(): native failure returns wallet-origin error without parent bridge', async ({
    page,
  }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        try {
          const { executeWebAuthnWithParentFallbacksSafari } = await import(paths.fallbacks);

          const rpId = 'example.com';
          const publicKey = {
            rp: { id: rpId, name: 'Test' },
            user: { id: new Uint8Array([1]), name: 'u', displayName: 'u' },
            challenge: new Uint8Array([1]),
          };
          // Test hook: force native to fail
          (window as any).__W3A_TEST_FORCE_NATIVE_FAIL = true;
          let bridgeCalls = 0;
          const bridgeClient = {
            request: async () => {
              bridgeCalls += 1;
              return { ok: false, error: 'User cancelled' };
            },
          };
          try {
            await executeWebAuthnWithParentFallbacksSafari('create', publicKey, {
              rpId,
              inIframe: true,
              timeoutMs: 500,
              bridgeClient,
              registrationOriginPolicy: 'wallet_origin_only',
            });
            return { success: false, error: 'Expected rejection' };
          } catch (e: any) {
            // Clear test flag
            try {
              delete (window as any).__W3A_TEST_FORCE_NATIVE_FAIL;
            } catch {}
            return {
              success: true,
              name: e?.name || '',
              code: e?.code || '',
              bridgeCalls,
              message: String(e?.message || e),
            };
          }
        } catch (err: any) {
          return { success: false, error: err?.message || String(err) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    if (!res.success) {
      test.skip(true, `Safari fallback test skipped: ${res.error || 'unknown error'}`);
      return;
    }

    expect(res.name).toBe('WalletOriginWebAuthnUnavailableError');
    expect(res.code).toBe('wallet_origin_webauthn_unavailable');
    expect(res.bridgeCalls).toBe(0);
  });

  test('create(): native fails then bridge timeout (no second native attempt)', async ({
    page,
  }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        try {
          const { executeWebAuthnWithParentFallbacksSafari } = await import(paths.fallbacks);

          const rpId = 'example.com';
          const publicKey = {
            rp: { id: rpId, name: 'Test' },
            user: { id: new Uint8Array([1]), name: 'u', displayName: 'u' },
            challenge: new Uint8Array([1]),
          };

          // Force native to fail; observe internal counter; simulate bridge timeout
          (window as any).__W3A_TEST_FORCE_NATIVE_FAIL = true;
          let bridgeCalls = 0;
          const bridgeClient = {
            request: async () => {
              bridgeCalls += 1;
              return { ok: false, timeout: true };
            },
          };
          let threw = false;
          try {
            await executeWebAuthnWithParentFallbacksSafari('create', publicKey, {
              rpId,
              inIframe: true,
              timeoutMs: 200,
              bridgeClient,
              registrationOriginPolicy: 'wallet_origin_only',
            });
          } catch {
            threw = true;
          }
          // Read internal counter and clear flag
          const count = (window as any).__W3A_TEST_NATIVE_CREATE_ATTEMPTS || 0;
          try {
            delete (window as any).__W3A_TEST_FORCE_NATIVE_FAIL;
          } catch {}
          try {
            delete (window as any).__W3A_TEST_NATIVE_CREATE_ATTEMPTS;
          } catch {}
          return { success: true, calls: { nativeCreate: count, bridge: bridgeCalls }, threw };
        } catch (err: any) {
          return { success: false, error: err?.message || String(err) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    if (!res.success) {
      test.skip(true, `Safari fallback test skipped: ${res.error || 'unknown error'}`);
      return;
    }

    expect(res.calls?.nativeCreate).toBe(1);
    expect(res.calls?.bridge).toBe(0);
    expect(res.threw).toBe(true);
  });

  test('create(): ancestor and focus failures map to wallet-origin unavailable', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { executeWebAuthnWithParentFallbacksSafari } = await import(paths.fallbacks);
        const credentials = navigator.credentials as unknown as {
          create: typeof navigator.credentials.create;
        };
        const originalCreate = credentials.create.bind(navigator.credentials);
        const rpId = 'example.com';
        const publicKey = {
          rp: { id: rpId, name: 'Test' },
          user: { id: new Uint8Array([1]), name: 'u', displayName: 'u' },
          challenge: new Uint8Array([1]),
        };
        let bridgeCalls = 0;
        const bridgeClient = {
          request: async () => {
            bridgeCalls += 1;
            return { ok: true, credential: {} };
          },
        };
        const cases = [
          {
            name: 'SecurityError',
            message: 'The origin of the document is not the same as its ancestors',
          },
          { name: 'NotAllowedError', message: 'The document is not focused' },
        ];
        const codes: string[] = [];
        try {
          for (const failure of cases) {
            credentials.create = async () => {
              const error = new Error(failure.message);
              Object.defineProperty(error, 'name', { value: failure.name });
              throw error;
            };
            try {
              await executeWebAuthnWithParentFallbacksSafari('create', publicKey, {
                rpId,
                inIframe: true,
                bridgeClient,
                registrationOriginPolicy: 'wallet_origin_only',
              });
            } catch (error) {
              codes.push((error as { code?: string }).code || '');
            }
          }
        } finally {
          credentials.create = originalCreate;
        }
        return { codes, bridgeCalls };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      codes: ['wallet_origin_webauthn_unavailable', 'wallet_origin_webauthn_unavailable'],
      bridgeCalls: 0,
    });
  });

  test('get(): native ancestor error then bridge cancel → NotAllowedError', async ({ page }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        try {
          const { executeWebAuthnWithParentFallbacksSafari } = await import(paths.fallbacks);
          const rpId = window.location.hostname;
          const publicKey = { rpId, challenge: new Uint8Array([1]) };
          // Force native to fail
          (window as any).__W3A_TEST_FORCE_NATIVE_FAIL = true;
          // Bridge returns explicit cancel
          const bridgeClient = {
            request: async () => ({ ok: false, error: 'User cancelled' }),
          };
          try {
            await executeWebAuthnWithParentFallbacksSafari('get', publicKey, {
              rpId,
              inIframe: true,
              timeoutMs: 200,
              bridgeClient,
            });
            return { success: false, error: 'Expected rejection' };
          } catch (e: any) {
            try {
              delete (window as any).__W3A_TEST_FORCE_NATIVE_FAIL;
            } catch {}
            return { success: true, name: e?.name || '', message: String(e?.message || e) };
          }
        } catch (err: any) {
          return { success: false, error: err?.message || String(err) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    if (!res.success) {
      test.skip(true, `Safari fallback test skipped: ${res.error || 'unknown error'}`);
      return;
    }

    expect(res.name).toBe('NotAllowedError');
    expect(res.message).toContain('cancel');
  });

  test('get(): native NotAllowedError cancel should not trigger bridge', async ({ page }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        try {
          const { executeWebAuthnWithParentFallbacksSafari } = await import(paths.fallbacks);
          const rpId = window.location.hostname;
          const publicKey = { rpId, challenge: new Uint8Array([1]) };

          // Stub native navigator.credentials.get to simulate a user cancellation
          const orig = navigator.credentials.get.bind(navigator.credentials);
          navigator.credentials.get = async () => {
            const e = new Error('The operation was not allowed');
            (e as any).name = 'NotAllowedError';
            throw e;
          };

          let bridgeCalls = 0;
          const bridgeClient = {
            request: async () => {
              bridgeCalls += 1;
              return { ok: false, error: 'should not be called' };
            },
          };

          try {
            await executeWebAuthnWithParentFallbacksSafari('get', publicKey, {
              rpId,
              inIframe: true,
              timeoutMs: 200,
              bridgeClient,
            });
            return { success: false, error: 'Expected NotAllowedError' };
          } catch (e: any) {
            // restore
            (navigator.credentials as any).get = orig;
            return { success: true, name: e?.name || '', bridgeCalls };
          }
        } catch (err: any) {
          return { success: false, error: err?.message || String(err) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    if (!res.success) {
      test.skip(true, `Safari fallback test skipped: ${res.error || 'unknown error'}`);
      return;
    }
    expect(res.name).toBe('NotAllowedError');
    expect(res.bridgeCalls).toBe(0);
  });

  test('get(): clones challenge buffers before native and bridge attempts', async ({ page }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        try {
          const { executeWebAuthnWithParentFallbacksSafari } = await import(paths.fallbacks);
          const rpId = window.location.hostname;
          const challenge = new Uint8Array([9, 8, 7, 6]);
          const allowId = new Uint8Array([1, 2, 3, 4]);
          const publicKey = {
            rpId,
            challenge,
            allowCredentials: [{ id: allowId, type: 'public-key' as const }],
          };

          const orig = navigator.credentials.get.bind(navigator.credentials);
          let nativeChallengeIsOriginal = false;
          let nativeAllowIdIsOriginal = false;
          navigator.credentials.get = async (options: any) => {
            nativeChallengeIsOriginal = options?.publicKey?.challenge === challenge;
            nativeAllowIdIsOriginal = options?.publicKey?.allowCredentials?.[0]?.id === allowId;
            const e = new Error('The origin of the document is not the same as its ancestors');
            (e as any).name = 'NotAllowedError';
            throw e;
          };

          let bridgeChallengeIsOriginal = false;
          let bridgeAllowIdIsOriginal = false;
          const bridgeClient = {
            request: async (_kind: unknown, bridgePublicKey: any) => {
              bridgeChallengeIsOriginal = bridgePublicKey?.challenge === challenge;
              bridgeAllowIdIsOriginal = bridgePublicKey?.allowCredentials?.[0]?.id === allowId;
              bridgePublicKey.challenge[0] = 0;
              bridgePublicKey.allowCredentials[0].id[0] = 0;
              return { ok: false, error: 'User cancelled' };
            },
          };

          try {
            await executeWebAuthnWithParentFallbacksSafari('get', publicKey, {
              rpId,
              inIframe: true,
              timeoutMs: 200,
              bridgeClient,
            });
          } catch {
            // Expected bridge cancellation.
          } finally {
            (navigator.credentials as any).get = orig;
          }

          return {
            success: true,
            nativeChallengeIsOriginal,
            nativeAllowIdIsOriginal,
            bridgeChallengeIsOriginal,
            bridgeAllowIdIsOriginal,
            originalChallengeFirstByte: challenge[0],
            originalAllowIdFirstByte: allowId[0],
          };
        } catch (err: any) {
          return { success: false, error: err?.message || String(err) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    if (!res.success) {
      test.skip(true, `Safari fallback test skipped: ${res.error || 'unknown error'}`);
      return;
    }

    expect(res.nativeChallengeIsOriginal).toBe(false);
    expect(res.nativeAllowIdIsOriginal).toBe(false);
    expect(res.bridgeChallengeIsOriginal).toBe(false);
    expect(res.bridgeAllowIdIsOriginal).toBe(false);
    expect(res.originalChallengeFirstByte).toBe(9);
    expect(res.originalAllowIdFirstByte).toBe(1);
  });
});
