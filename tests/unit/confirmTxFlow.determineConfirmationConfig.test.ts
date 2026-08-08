import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  determine: '/_test-sdk/esm/core/signingEngine/uiConfirm/handlers/determineConfirmationConfig.js',
  types: '/_test-sdk/esm/core/signingEngine/stepUpConfirmation/channel/confirmTypes.js',
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
      kind: 'auto_proceed',
      uiMode: 'drawer',
      behavior: 'skipClick',
      autoProceedDelay: 7,
    });
  });

  test('decryptPrivateKeyWithPrf defaults to normalized silent mode', async ({ page }) => {
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
    expect(res.cfg.kind).toBe('silent');
    expect(res.cfg.behavior).toBeUndefined();
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

  test('warm-session transaction signing keeps the transaction confirmer enabled', async ({
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
              autoProceedDelay: 12,
            }),
          },
        };

        const req = {
          type: types.UserConfirmationType.SIGN_TRANSACTION,
          payload: {
            signingAuthPlan: {
              kind: 'warmSession',
              method: 'passkey',
              accountId: 'alice.testnet',
              intent: 'transactionSign',
              thresholdSessionId: 'threshold-session',
              retention: 'multi_use',
              expiresAtMs: Date.now() + 60_000,
              remainingUses: 2,
            },
          },
        } as any;
        const cfg = determine(ctx, req);
        return { cfg };
      },
      { paths: IMPORT_PATHS },
    );

    expect(res.cfg).toEqual({
      kind: 'interactive',
      uiMode: 'modal',
      behavior: 'requireClick',
    });
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
      kind: 'silent',
      uiMode: 'none',
    });
  });

  // An Email OTP code exists only in the user's inbox, so neither
  // non-interactive setting can produce one: uiMode 'none' confirms silently and
  // behavior 'skipClick' auto-confirms past the mounted prompt. Both used to
  // return a decision with no code, failing downstream with "requires a 6-digit
  // code".
  for (const [label, configured] of [
    ['silent uiMode', { uiMode: 'none', behavior: 'skipClick', autoProceedDelay: 0 }],
    ['auto-proceed behavior', { uiMode: 'modal', behavior: 'skipClick', autoProceedDelay: 0 }],
  ] as Array<[string, Record<string, unknown>]>) {
    test(`Email OTP step-up overrides ${label} so the code can be entered`, async ({ page }) => {
      const res = await page.evaluate(
        async ({ paths, configured }) => {
          const mod = await import(paths.determine);
          const types = await import(paths.types);
          const determine = mod.determineConfirmationConfig as Function;

          const ctx: any = {
            userPreferencesManager: {
              getConfirmationConfig: () => configured,
            },
          };

          const request = {
            type: types.UserConfirmationType.SIGN_INTENT_DIGEST,
            confirmationConfig: configured,
            payload: {
              nearAccountId: 'alice.testnet',
              challengeB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
              signingAuthPlan: {
                kind: 'emailOtpReauth',
                method: 'email_otp',
                emailOtpPrompt: { challengeId: 'email-otp-1' },
              },
            },
          } as any;

          return { cfg: determine(ctx, request) };
        },
        { paths: IMPORT_PATHS, configured },
      );

      expect(res.cfg.kind).toBe('interactive');
      expect(res.cfg.behavior).toBe('requireClick');
      expect(res.cfg.uiMode).toBe('modal');
    });
  }

  // An explicitly configured drawer is already a visible prompt, so it survives
  // the clamp — only the behavior is forced.
  test('Email OTP step-up keeps a configured drawer', async ({ page }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.determine);
        const types = await import(paths.types);
        const determine = mod.determineConfirmationConfig as Function;

        const ctx: any = {
          userPreferencesManager: {
            getConfirmationConfig: () => ({
              uiMode: 'drawer',
              behavior: 'skipClick',
              autoProceedDelay: 0,
            }),
          },
        };

        const request = {
          type: types.UserConfirmationType.SIGN_INTENT_DIGEST,
          payload: {
            nearAccountId: 'alice.testnet',
            challengeB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            signingAuthPlan: {
              kind: 'emailOtpReauth',
              method: 'email_otp',
              emailOtpPrompt: { challengeId: 'email-otp-2' },
            },
          },
        } as any;

        return { cfg: determine(ctx, request) };
      },
      { paths: IMPORT_PATHS },
    );

    expect(res.cfg).toEqual({
      kind: 'interactive',
      uiMode: 'drawer',
      behavior: 'requireClick',
    });
  });

  test('warm-session signing respects explicit transaction confirmation config', async ({
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
              autoProceedDelay: 25,
            }),
          },
        };

        const request = {
          type: types.UserConfirmationType.SIGN_TRANSACTION,
          confirmationConfig: {
            uiMode: 'modal',
            behavior: 'requireClick',
            autoProceedDelay: 10,
          },
          payload: {
            signingAuthPlan: {
              kind: 'warmSession',
              method: 'passkey',
              accountId: 'alice.testnet',
              intent: 'transaction_sign',
              curve: 'ed25519',
              thresholdSessionId: 'tsess-ready',
              expiresAtMs: Date.now() + 60_000,
              remainingUses: 3,
            },
          },
        } as any;

        const cfg = determine(ctx, request);
        return { cfg };
      },
      { paths: IMPORT_PATHS },
    );

    expect(res.cfg).toEqual({
      kind: 'interactive',
      uiMode: 'modal',
      behavior: 'requireClick',
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
    expect(result.cfg1).toEqual({
      kind: 'interactive',
      uiMode: 'modal',
      behavior: 'requireClick',
    });
    expect(result.cfg2).toEqual({
      kind: 'interactive',
      uiMode: 'modal',
      behavior: 'requireClick',
    });
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

    expect(result.cfg1).toEqual({
      kind: 'interactive',
      uiMode: 'modal',
      behavior: 'requireClick',
    });
    expect(result.cfg2).toEqual({
      kind: 'interactive',
      uiMode: 'modal',
      behavior: 'requireClick',
    });
  });
});
