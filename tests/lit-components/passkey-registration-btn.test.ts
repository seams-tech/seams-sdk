import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest, sdkEsmPath } from '../setup';
import { ensureComponentModule, mountComponent } from './harness';

const TAG_NAME = 'seams-passkey-registration-btn';
const MODULE_PATH = sdkEsmPath('sdk/seams-passkey-registration-btn.js');
const CONFIRM_UI_PATH = sdkEsmPath('core/signingEngine/uiConfirm/ui/confirm-ui.js');

type InteractionState = {
  kind: 'registration_activation_button_interaction_state_v1';
  hovered: boolean;
  focused: boolean;
  pressed: boolean;
  busy: boolean;
  disabled: boolean;
};

test.describe('seams-passkey-registration-btn', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    await ensureComponentModule(page, {
      modulePath: MODULE_PATH,
      tagName: TAG_NAME,
    });
  });

  test('emits activation once and mirrors hover, focus, busy, and disabled state', async ({
    page,
  }) => {
    await mountComponent(page, {
      tagName: TAG_NAME,
      props: {
        activationId: 'activation-1',
        label: 'Create with passkey',
        busyLabel: 'Creating passkey...',
        accessibleLabel: 'Create passkey account',
      },
    });

    const result = await page.evaluate(
      async ({ tagName, modulePath }) => {
        const mod = await import(modulePath);
        const startEvent = mod.SEAMS_PASSKEY_REGISTRATION_ACTIVATION_START_EVENT as string;
        const stateEvent = mod.SEAMS_PASSKEY_REGISTRATION_ACTIVATION_STATE_EVENT as string;
        const element = document.querySelector(tagName) as HTMLElement & {
          updateComplete?: Promise<unknown>;
        };
        await element.updateComplete;
        const button = element.querySelector('button') as HTMLButtonElement;
        const states: InteractionState[] = [];
        const starts: unknown[] = [];

        element.addEventListener(stateEvent, (event) => {
          states.push({ ...(event as CustomEvent<InteractionState>).detail });
        });
        element.addEventListener(startEvent, (event) => {
          starts.push((event as CustomEvent<unknown>).detail);
        });

        button.dispatchEvent(new PointerEvent('pointerenter', { bubbles: true }));
        button.dispatchEvent(new FocusEvent('focus', { bubbles: true }));
        button.click();
        button.click();
        await element.updateComplete;

        return {
          starts,
          states,
          disabled: button.disabled,
          text: button.textContent?.trim(),
        };
      },
      { tagName: TAG_NAME, modulePath: MODULE_PATH },
    );

    expect(result.starts).toEqual([{ activationId: 'activation-1' }]);
    expect(result.states).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ hovered: true, focused: false, busy: false, disabled: false }),
        expect.objectContaining({ hovered: true, focused: true, busy: false, disabled: false }),
        expect.objectContaining({
          hovered: true,
          focused: true,
          pressed: false,
          busy: true,
          disabled: true,
        }),
      ]),
    );
    expect(result.disabled).toBe(true);
    expect(result.text).toBe('Creating passkey...');
  });

  test('captures pointer and clears pressed state on cancel, drag, blur, and key release', async ({
    page,
  }) => {
    await mountComponent(page, {
      tagName: TAG_NAME,
      props: {
        activationId: 'activation-2',
        label: 'Create with passkey',
        busyLabel: 'Creating passkey...',
        accessibleLabel: 'Create passkey account',
      },
    });

    const result = await page.evaluate(
      async ({ tagName, modulePath }) => {
        const mod = await import(modulePath);
        const stateEvent = mod.SEAMS_PASSKEY_REGISTRATION_ACTIVATION_STATE_EVENT as string;
        const element = document.querySelector(tagName) as HTMLElement & {
          updateComplete?: Promise<unknown>;
        };
        await element.updateComplete;
        const button = element.querySelector('button') as HTMLButtonElement;
        const states: InteractionState[] = [];
        const capturedPointerIds: number[] = [];
        const releasedPointerIds: number[] = [];

        button.setPointerCapture = (pointerId: number): void => {
          capturedPointerIds.push(pointerId);
        };
        button.hasPointerCapture = (pointerId: number): boolean =>
          capturedPointerIds.includes(pointerId) && !releasedPointerIds.includes(pointerId);
        button.releasePointerCapture = (pointerId: number): void => {
          releasedPointerIds.push(pointerId);
        };
        button.getBoundingClientRect = (): DOMRect =>
          ({
            left: 0,
            top: 0,
            right: 100,
            bottom: 50,
            width: 100,
            height: 50,
            x: 0,
            y: 0,
            toJSON: () => ({}),
          }) as DOMRect;

        element.addEventListener(stateEvent, (event) => {
          states.push({ ...(event as CustomEvent<InteractionState>).detail });
        });

        button.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true, pointerId: 42 }));
        button.dispatchEvent(new PointerEvent('pointercancel', { bubbles: true, pointerId: 42 }));
        button.dispatchEvent(new DragEvent('dragstart', { bubbles: true }));
        button.dispatchEvent(new DragEvent('dragend', { bubbles: true, clientX: 10, clientY: 10 }));
        button.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, key: 'Enter' }));
        button.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: 'Enter' }));
        button.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, key: ' ' }));
        button.dispatchEvent(new FocusEvent('blur', { bubbles: true }));

        return {
          states,
          capturedPointerIds,
          releasedPointerIds,
        };
      },
      { tagName: TAG_NAME, modulePath: MODULE_PATH },
    );

    expect(result.capturedPointerIds).toEqual([42]);
    expect(result.releasedPointerIds).toEqual([42]);
    expect(result.states).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ pressed: true, busy: false, disabled: false }),
        expect.objectContaining({ pressed: false, busy: false, disabled: false }),
      ]),
    );
    expect(result.states.at(-1)).toEqual(
      expect.objectContaining({ focused: false, pressed: false, busy: false, disabled: false }),
    );
  });

  test('starts activation from keyboard Enter on the focused iframe button', async ({ page }) => {
    await mountComponent(page, {
      tagName: TAG_NAME,
      props: {
        activationId: 'activation-keyboard',
        label: 'Create with passkey',
        busyLabel: 'Creating passkey...',
        accessibleLabel: 'Create passkey account',
      },
    });

    await page.evaluate(
      async ({ tagName, modulePath }) => {
        const mod = await import(modulePath);
        const startEvent = mod.SEAMS_PASSKEY_REGISTRATION_ACTIVATION_START_EVENT as string;
        const element = document.querySelector(tagName) as HTMLElement & {
          updateComplete?: Promise<unknown>;
        };
        await element.updateComplete;
        const starts: unknown[] = [];
        element.addEventListener(startEvent, (event) => {
          starts.push((event as CustomEvent<unknown>).detail);
        });
        (globalThis as any).__seamsKeyboardActivationStarts = starts;
      },
      { tagName: TAG_NAME, modulePath: MODULE_PATH },
    );

    const button = page.locator(`${TAG_NAME} button`);
    await button.focus();
    await page.keyboard.press('Enter');

    const result = await page.evaluate(() => {
      const starts = (globalThis as any).__seamsKeyboardActivationStarts;
      delete (globalThis as any).__seamsKeyboardActivationStarts;
      return starts;
    });

    expect(result).toEqual([{ activationId: 'activation-keyboard' }]);
  });

  test('emits typed forward and backward focus exits for Tab navigation', async ({ page }) => {
    await mountComponent(page, {
      tagName: TAG_NAME,
      props: {
        activationId: 'activation-focus-exit',
        label: 'Create with passkey',
        busyLabel: 'Creating passkey...',
        accessibleLabel: 'Create passkey account',
      },
    });

    const result = await page.evaluate(
      async ({ tagName, modulePath }) => {
        const mod = await import(modulePath);
        const focusExitEvent = mod.SEAMS_PASSKEY_REGISTRATION_ACTIVATION_FOCUS_EXIT_EVENT as string;
        const element = document.querySelector(tagName) as HTMLElement & {
          updateComplete?: Promise<unknown>;
        };
        await element.updateComplete;
        const button = element.querySelector('button') as HTMLButtonElement;
        const directions: string[] = [];
        element.addEventListener(focusExitEvent, (event) => {
          directions.push((event as CustomEvent<{ direction: string }>).detail.direction);
        });
        button.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, key: 'Tab' }));
        button.dispatchEvent(
          new KeyboardEvent('keydown', { bubbles: true, key: 'Tab', shiftKey: true }),
        );
        return directions;
      },
      { tagName: TAG_NAME, modulePath: MODULE_PATH },
    );

    expect(result).toEqual(['forward', 'backward']);
  });

  test('starts a reserved credential create inline from the trusted button click', async ({
    page,
  }) => {
    await mountComponent(page, {
      tagName: TAG_NAME,
      props: {
        activationId: 'activation-inline-create',
        label: 'Create with passkey',
        busyLabel: 'Creating passkey...',
        accessibleLabel: 'Create passkey account',
      },
    });
    const touchIdPromptPath = sdkEsmPath(
      'core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt.js',
    );
    const coordinatorPath = sdkEsmPath(
      'core/signingEngine/stepUpConfirmation/passkeyPrompt/webauthnPromptCoordinator.js',
    );

    await page.evaluate(
      async ({ tagName, modulePath, touchIdPromptPath, coordinatorPath }) => {
        const componentModule = await import(modulePath);
        const promptModule = await import(touchIdPromptPath);
        const coordinatorModule = await import(coordinatorPath);
        const identity = {
          surfaceId: 'surface-inline-create',
          activationId: 'activation-inline-create',
          requestId: 'request-inline-create',
        };
        const owner = { kind: 'registration_activation' as const, identity };
        const reservation =
          await coordinatorModule.webAuthnPromptCoordinator.reserveRegistrationPrompt({
            owner,
            expiresAtMs: Date.now() + 10_000,
            cancellation: { kind: 'none' },
          });
        const prompt = new promptModule.TouchIdPrompt('example.localhost');
        const element = document.querySelector(tagName) as HTMLElement;
        const eventName =
          componentModule.SEAMS_PASSKEY_REGISTRATION_ACTIVATION_START_EVENT as string;
        const credentials = navigator.credentials as unknown as {
          create: typeof navigator.credentials.create;
        };
        const originalCreate = credentials.create.bind(navigator.credentials);
        let handlerReturned = false;
        let credentialCreate:
          | { calledBeforeHandlerReturned: boolean; userActivationActive: boolean }
          | undefined;
        credentials.create = async (): Promise<Credential | null> => {
          credentialCreate = {
            calledBeforeHandlerReturned: !handlerReturned,
            userActivationActive: navigator.userActivation.isActive,
          };
          return { id: 'credential-id', type: 'public-key' } as Credential;
        };
        element.addEventListener(
          eventName,
          () => {
            const operation = prompt.generateRegistrationCredentialsInternal({
              walletId: 'alice.testnet',
              challengeB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
              signerSlot: 1,
              intendedUserName: 'alice.testnet',
              prompt: {
                kind: 'reserved',
                reservation,
                owner,
                cancellation: { kind: 'none' },
              },
            });
            (globalThis as any).__seamsInlineCredentialOperation = operation.finally(() => {
              credentials.create = originalCreate;
            });
            handlerReturned = true;
          },
          { once: true },
        );
        (globalThis as any).__seamsInlineCredentialCreate = () => credentialCreate;
      },
      { tagName: TAG_NAME, modulePath: MODULE_PATH, touchIdPromptPath, coordinatorPath },
    );

    await page.locator(`${TAG_NAME} button`).click();
    const result = await page.evaluate(async () => {
      await (globalThis as any).__seamsInlineCredentialOperation;
      const value = (globalThis as any).__seamsInlineCredentialCreate();
      delete (globalThis as any).__seamsInlineCredentialOperation;
      delete (globalThis as any).__seamsInlineCredentialCreate;
      return value;
    });

    expect(result).toEqual({
      calledBeforeHandlerReturned: true,
      userActivationActive: true,
    });
  });

  test('fills the wallet iframe viewport so the whole CTA is clickable', async ({ page }) => {
    const result = await page.evaluate(
      async ({ modulePath, tagName }) => {
        const frame = document.createElement('iframe');
        frame.style.cssText =
          'position:absolute;left:0;top:0;width:320px;height:72px;border:0;visibility:hidden;';
        document.body.appendChild(frame);
        const doc = frame.contentDocument;
        if (!doc) throw new Error('missing iframe document');

        const resultPromise = new Promise<{
          bodyHeight: number;
          elementHeight: number;
          buttonHeight: number;
          buttonWidth: number;
          inlineStyleCount: number;
          stylesheetReady: boolean;
          error?: string;
        }>((resolve) => {
          const onMessage = (event: MessageEvent) => {
            if (event.source !== frame.contentWindow) return;
            const data = event.data as { type?: string };
            if (data?.type !== 'seams-passkey-registration-btn-rects') return;
            window.removeEventListener('message', onMessage);
            resolve(event.data);
          };
          window.addEventListener('message', onMessage);
        });

        doc.open();
        doc.write(`
          <!doctype html>
          <html>
            <head><meta charset="utf-8" /></head>
            <body>
              <script>
                window.__W3A_WALLET_SDK_BASE__ = '/_test-sdk/esm/sdk/';
              </script>
              <script type="module">
                const modulePath = ${JSON.stringify(modulePath)};
                const tagName = ${JSON.stringify(tagName)};
                const post = (payload) => parent.postMessage({
                  type: 'seams-passkey-registration-btn-rects',
                  ...payload,
                }, '*');
                try {
                  await import(modulePath);
                  await customElements.whenDefined(tagName);
                  const host = document.createElement('section');
                  host.style.cssText = 'inline-size:100%;block-size:100%;background:transparent;';
                  const element = document.createElement(tagName);
                  element.activationId = 'activation-iframe-fill';
                  element.label = 'Create with passkey';
                  element.busyLabel = 'Creating passkey...';
                  element.accessibleLabel = 'Create passkey account';
                  host.appendChild(element);
                  document.body.appendChild(host);
                  await element.activationReady();
                  await new Promise((resolve) => requestAnimationFrame(resolve));
                  const button = element.querySelector('button');
                  if (!button) throw new Error('missing internal button');
                  post({
                    bodyHeight: document.body.getBoundingClientRect().height,
                    elementHeight: element.getBoundingClientRect().height,
                    buttonHeight: button.getBoundingClientRect().height,
                    buttonWidth: button.getBoundingClientRect().width,
                    inlineStyleCount: [document.documentElement, document.body, element, button]
                      .filter((node) => node.hasAttribute('style')).length,
                    stylesheetReady: Boolean(document.head.querySelector('link[data-seams-passkey-registration-btn-css]')?.sheet),
                  });
                } catch (error) {
                  post({ bodyHeight: 0, elementHeight: 0, buttonHeight: 0, buttonWidth: 0, inlineStyleCount: -1, stylesheetReady: false, error: String(error?.message || error) });
                }
              </script>
            </body>
          </html>
        `);
        doc.close();

        const rects = await resultPromise;
        frame.remove();
        return rects;
      },
      { modulePath: MODULE_PATH, tagName: TAG_NAME },
    );

    expect(result.error).toBeUndefined();
    expect(result.bodyHeight).toBeGreaterThanOrEqual(71);
    expect(result.elementHeight).toBeGreaterThanOrEqual(71);
    expect(result.buttonHeight).toBeGreaterThanOrEqual(71);
    expect(result.buttonWidth).toBeGreaterThanOrEqual(319);
    expect(result.inlineStyleCount).toBe(0);
    expect(result.stylesheetReady).toBe(true);
  });

  test('uses the same rpID source for WebAuthn registration options', async ({ page }) => {
    const result = await page.evaluate(
      async ({ touchIdPromptPath }) => {
        const mod = await import(touchIdPromptPath);
        const prompt = new mod.TouchIdPrompt('example.localhost');
        const originalCreate = navigator.credentials.create.bind(navigator.credentials);
        let captured:
          | {
              rpId: string;
              userName: string;
              displayName: string;
              userId: string;
              fallbackRpId: string;
            }
          | undefined;

        const credentials = navigator.credentials as unknown as {
          create: typeof navigator.credentials.create;
        };
        credentials.create = async (
          options?: CredentialCreationOptions,
        ): Promise<Credential | null> => {
          const publicKey = options?.publicKey as PublicKeyCredentialCreationOptions;
          const user = publicKey.user;
          captured = {
            rpId: publicKey.rp.id || '',
            userName: user.name,
            displayName: user.displayName,
            userId: new TextDecoder().decode(user.id),
            fallbackRpId: prompt.getRpId(),
          };
          return {
            id: 'credential-id',
            type: 'public-key',
          } as Credential;
        };

        try {
          await prompt.generateRegistrationCredentialsInternal({
            walletId: 'alice.testnet',
            challengeB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            signerSlot: 1,
            intendedUserName: 'alice.testnet',
            prompt: {
              kind: 'immediate',
              requestId: 'rp-id-test',
              cancellation: { kind: 'none' },
            },
          });
        } finally {
          credentials.create = originalCreate;
        }

        return captured;
      },
      {
        touchIdPromptPath: sdkEsmPath(
          'core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt.js',
        ),
      },
    );

    expect(result).toEqual({
      rpId: 'example.localhost',
      userName: 'alice.testnet',
      displayName: 'alice.testnet',
      userId: 'alice.testnet',
      fallbackRpId: 'example.localhost',
    });
  });

  test('rejects WebAuthn registration when username does not match wallet ID', async ({ page }) => {
    const result = await page.evaluate(
      async ({ touchIdPromptPath }) => {
        const mod = await import(touchIdPromptPath);
        const prompt = new mod.TouchIdPrompt('example.localhost');
        try {
          await prompt.generateRegistrationCredentialsInternal({
            walletId: 'alice.testnet',
            challengeB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            signerSlot: 1,
            intendedUserName: 'alice',
            prompt: {
              kind: 'immediate',
              requestId: 'username-test',
              cancellation: { kind: 'none' },
            },
          });
          return { ok: true, message: '' };
        } catch (error) {
          return { ok: false, message: error instanceof Error ? error.message : String(error) };
        }
      },
      {
        touchIdPromptPath: sdkEsmPath(
          'core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt.js',
        ),
      },
    );

    expect(result).toEqual({
      ok: false,
      message: 'WebAuthn registration user.name must match walletId',
    });
  });

  test('renders registration modal intended user name and rpID without transaction tree', async ({
    page,
  }) => {
    await page.evaluate(
      async ({ confirmUiPath }) => {
        const mod = await import(confirmUiPath);
        const { mountConfirmUI } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');
        const handle = await mountConfirmUI({
          ctx: {
            userPreferencesManager: {
              getCurrentWalletId: () => 'alice.testnet',
            },
          } as any,
          summary: { intentDigest: 'register:alice.testnet:1' } as any,
          txSigningRequests: [],
          securityContext: {
            passkeyRegistration: {
              kind: 'passkey_registration_confirm_display_v1',
              intendedUserName: 'alice.testnet',
              accountId: 'alice.testnet',
              rpId: 'example.localhost',
              signerSlot: 1,
            },
          } as any,
          loading: false,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });
        (globalThis as any).__seamsPasskeyRegistrationModalHandle = handle;
      },
      {
        confirmUiPath: CONFIRM_UI_PATH,
      },
    );

    await page.waitForSelector('.passkey-registration-confirm__identity');
    const identity = page.locator('.passkey-registration-confirm__identity');
    await expect(identity).toContainText('Account');
    await expect(identity).toContainText('alice.testnet');
    await expect(identity).toContainText('Relying party');
    await expect(identity).toContainText('example.localhost');
    await expect(page.locator('w3a-tx-tree')).toHaveCount(0);

    await page.evaluate(() => {
      (globalThis as any).__seamsPasskeyRegistrationModalHandle?.close(true);
      delete (globalThis as any).__seamsPasskeyRegistrationModalHandle;
    });
  });
});
