import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  determine: '/sdk/esm/core/signingEngine/uiConfirm/handlers/determineConfirmationConfig.js',
  types: '/sdk/esm/core/signingEngine/stepUpConfirmation/channel/confirmTypes.js',
} as const;

test.describe('determineConfirmationConfig', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('merges request override over user prefs (top window)', async ({ page }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        // Import target function and enum from built ESM bundle
        const mod = await import(paths.determine);
        const types = await import(paths.types);
        const determine = mod.determineConfirmationConfig as Function;

        const ctx: any = {
          userPreferencesManager: {
            getConfirmationConfig: () => ({
              uiMode: 'modal',
              behavior: 'requireClick',
              autoProceedDelay: 42,
            }),
          },
        };

        const request = {
          type: types.UserConfirmationType.SIGN_TRANSACTION,
          confirmationConfig: {
            uiMode: 'drawer',
            behavior: 'skipClick',
            autoProceedDelay: 7,
          },
        } as any;

        const cfg = determine(ctx, request);
        return { cfg };
      },
      { paths: IMPORT_PATHS },
    );

    expect(res.cfg).toEqual({
      uiMode: 'drawer',
      behavior: 'skipClick',
      autoProceedDelay: 7,
    });
  });

  test('decryptPrivateKeyWithPrf defaults to uiMode=none and preserves behavior', async ({
    page,
  }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.determine);
        const types = await import(paths.types);
        const determine = mod.determineConfirmationConfig as Function;

        const ctx: any = {
          userPreferencesManager: {
            getConfirmationConfig: () => ({
              uiMode: 'modal',
              behavior: 'requireClick',
              autoProceedDelay: 0,
            }),
          },
        };

        const request = { type: types.UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF } as any;
        const cfg = determine(ctx, request);
        return { cfg };
      },
      { paths: IMPORT_PATHS },
    );

    expect(res.cfg.uiMode).toBe('none');
    expect(res.cfg.behavior).toBe('requireClick');
  });

  test('SHOW_SECURE_PRIVATE_KEY_UI uses modal/drawer UI', async ({ page }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.determine);
        const types = await import(paths.types);
        const determine = mod.determineConfirmationConfig as Function;

        const ctx: any = {
          userPreferencesManager: {
            getConfirmationConfig: () => ({
              uiMode: 'modal',
              behavior: 'requireClick',
              autoProceedDelay: 0,
            }),
          },
        };

        const req = { type: types.UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI } as any;
        const cfg = determine(ctx, req);
        return { cfg };
      },
      { paths: IMPORT_PATHS },
    );

    // The export viewer uses a full-screen modal/drawer; we only assert
    // that it does not get forced to 'none'.
    expect(res.cfg.uiMode === 'modal' || res.cfg.uiMode === 'drawer').toBe(true);
  });

  test('SIGN_INTENT_DIGEST respects configured click behavior when explicit activation is not required', async ({
    page,
  }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.determine);
        const types = await import(paths.types);
        const determine = mod.determineConfirmationConfig as Function;

        const ctx: any = {
          userPreferencesManager: {
            getConfirmationConfig: () => ({
              uiMode: 'none',
              behavior: 'skipClick',
              autoProceedDelay: 0,
            }),
          },
        };

        const request = {
          type: types.UserConfirmationType.SIGN_INTENT_DIGEST,
          confirmationConfig: {
            uiMode: 'none',
            behavior: 'skipClick',
            autoProceedDelay: 0,
          },
          payload: {
            nearAccountId: 'alice.testnet',
            challengeB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            signingAuthPlan: {
              kind: 'passkeyReauth',
              method: 'passkey',
            },
          },
        } as any;

        const cfg = determine(ctx, request);
        return { cfg };
      },
      { paths: IMPORT_PATHS },
    );

    expect(res.cfg).toEqual({
      uiMode: 'none',
      behavior: 'skipClick',
      autoProceedDelay: 0,
    });
  });

  test('in iframe + registration/link clamps to modal+requireClick when no override provided', async ({
    page,
  }) => {
    // Create a same-origin iframe and run the function inside that context
    const result = await (async () => {
      const frameHandle = await page.evaluateHandle(() => {
        const iframe = document.createElement('iframe');
        iframe.setAttribute('data-test', 'cfg-frame');
        document.body.appendChild(iframe);
        return iframe;
      });
      const element = frameHandle.asElement();
      if (!element) throw new Error('iframe element not found');
      const frame = await element.contentFrame();
      if (!frame) throw new Error('iframe content frame not available');

      // Ensure the iframe has the same import map as the top window so bare
      // module specifiers (e.g., "bs58") used by the built ESM bundle resolve.
      await frame.evaluate(() => {
        try {
          const parentImportMap = window.top?.document.querySelector<HTMLScriptElement>(
            'script[type="importmap"]',
          );
          if (!parentImportMap) return;

          const clone = document.createElement('script');
          clone.type = 'importmap';
          clone.textContent = parentImportMap.textContent;

          if (document.head.firstChild) {
            document.head.insertBefore(clone, document.head.firstChild);
          } else {
            document.head.appendChild(clone);
          }
        } catch {
          // If anything goes wrong here, fall back to the iframe's default
          // resolution (the test will surface any remaining issues).
        }
      });

      // Evaluate within the iframe so window.self !== window.top → true
      return await frame.evaluate(
        async ({ paths }) => {
          const mod = await import(paths.determine);
          const types = await import(paths.types);
          const determine = mod.determineConfirmationConfig as Function;
          const ctx: any = {
            userPreferencesManager: {
              getConfirmationConfig: () => ({
                uiMode: 'drawer',
                behavior: 'skipClick',
                autoProceedDelay: 5,
              }),
            },
          };
          const req1 = { type: types.UserConfirmationType.REGISTER_ACCOUNT } as any;
          const req2 = { type: types.UserConfirmationType.LINK_DEVICE } as any;
          const cfg1 = determine(ctx, req1);
          const cfg2 = determine(ctx, req2);
          return { cfg1, cfg2 };
        },
        { paths: IMPORT_PATHS },
      );
    })();

    // Should clamp to safe modal/requireClick.
    expect(result.cfg1).toEqual({ uiMode: 'modal', behavior: 'requireClick', autoProceedDelay: 5 });
    expect(result.cfg2).toEqual({ uiMode: 'modal', behavior: 'requireClick', autoProceedDelay: 5 });
  });

  test('in iframe + registration/link clamps request-level skipClick overrides', async ({
    page,
  }) => {
    const result = await (async () => {
      const frameHandle = await page.evaluateHandle(() => {
        const iframe = document.createElement('iframe');
        iframe.setAttribute('data-test', 'cfg-frame-explicit-override');
        document.body.appendChild(iframe);
        return iframe;
      });
      const element = frameHandle.asElement();
      if (!element) throw new Error('iframe element not found');
      const frame = await element.contentFrame();
      if (!frame) throw new Error('iframe content frame not available');

      await frame.evaluate(() => {
        const parentImportMap = window.top?.document.querySelector<HTMLScriptElement>(
          'script[type="importmap"]',
        );
        if (!parentImportMap) return;

        const clone = document.createElement('script');
        clone.type = 'importmap';
        clone.textContent = parentImportMap.textContent;
        document.head.insertBefore(clone, document.head.firstChild);
      });

      return await frame.evaluate(
        async ({ paths }) => {
          const mod = await import(paths.determine);
          const types = await import(paths.types);
          const determine = mod.determineConfirmationConfig as Function;
          const ctx: any = {
            userPreferencesManager: {
              getConfirmationConfig: () => ({
                uiMode: 'drawer',
                behavior: 'requireClick',
                autoProceedDelay: 5,
              }),
            },
          };
          const override = {
            uiMode: 'none',
            behavior: 'skipClick',
            autoProceedDelay: 0,
          };
          const req1 = {
            type: types.UserConfirmationType.REGISTER_ACCOUNT,
            confirmationConfig: override,
          } as any;
          const req2 = {
            type: types.UserConfirmationType.LINK_DEVICE,
            confirmationConfig: override,
          } as any;
          const cfg1 = determine(ctx, req1);
          const cfg2 = determine(ctx, req2);
          return { cfg1, cfg2 };
        },
        { paths: IMPORT_PATHS },
      );
    })();

    expect(result.cfg1).toEqual({ uiMode: 'modal', behavior: 'requireClick', autoProceedDelay: 0 });
    expect(result.cfg2).toEqual({ uiMode: 'modal', behavior: 'requireClick', autoProceedDelay: 0 });
  });

  test('in iframe + registration activation proof can skip the second modal click', async ({
    page,
  }) => {
    const result = await (async () => {
      const frameHandle = await page.evaluateHandle(() => {
        const iframe = document.createElement('iframe');
        iframe.setAttribute('data-test', 'cfg-frame-registration-activation');
        document.body.appendChild(iframe);
        return iframe;
      });
      const element = frameHandle.asElement();
      if (!element) throw new Error('iframe element not found');
      const frame = await element.contentFrame();
      if (!frame) throw new Error('iframe content frame not available');

      await frame.evaluate(() => {
        const parentImportMap = window.top?.document.querySelector<HTMLScriptElement>(
          'script[type="importmap"]',
        );
        if (!parentImportMap) return;

        const clone = document.createElement('script');
        clone.type = 'importmap';
        clone.textContent = parentImportMap.textContent;
        document.head.insertBefore(clone, document.head.firstChild);
      });

      return await frame.evaluate(
        async ({ paths }) => {
          const mod = await import(paths.determine);
          const types = await import(paths.types);
          const determine = mod.determineConfirmationConfig as Function;
          const ctx: any = {
            userPreferencesManager: {
              getConfirmationConfig: () => ({
                uiMode: 'drawer',
                behavior: 'requireClick',
                autoProceedDelay: 5,
              }),
            },
          };
          const req = {
            type: types.UserConfirmationType.REGISTER_ACCOUNT,
            payload: {
              walletIframeActivation: {
                kind: 'wallet_iframe_registration_activation_v1',
                activationId: 'activation-1',
                activatedAtMs: Date.now(),
              },
            },
          } as any;
          return determine(ctx, req);
        },
        { paths: IMPORT_PATHS },
      );
    })();

    expect(result).toEqual({ uiMode: 'none', behavior: 'skipClick', autoProceedDelay: 0 });
  });
});
