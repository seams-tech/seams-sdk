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
          states.push({ ...((event as CustomEvent<InteractionState>).detail) });
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
          states.push({ ...((event as CustomEvent<InteractionState>).detail) });
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

  test('uses the same rpID source for WebAuthn registration options', async ({ page }) => {
    const result = await page.evaluate(async ({ touchIdPromptPath }) => {
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
      credentials.create = async (options?: CredentialCreationOptions): Promise<Credential | null> => {
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
          nearAccountId: 'alice.testnet',
          challengeB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          signerSlot: 1,
          intendedUserName: 'alice',
        });
      } finally {
        credentials.create = originalCreate;
      }

      return captured;
    }, {
      touchIdPromptPath: sdkEsmPath(
        'core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt.js',
      ),
    });

    expect(result).toEqual({
      rpId: 'example.localhost',
      userName: 'alice',
      displayName: 'alice',
      userId: 'alice.testnet',
      fallbackRpId: 'example.localhost',
    });
  });

  test('renders registration modal intended user name and rpID without transaction tree', async ({
    page,
  }) => {
    await page.evaluate(async ({ confirmUiPath }) => {
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
            intendedUserName: 'alice',
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
    }, {
      confirmUiPath: CONFIRM_UI_PATH,
    });

    await page.waitForSelector('.passkey-registration-confirm__identity');
    const identity = page.locator('.passkey-registration-confirm__identity');
    await expect(identity).toContainText('Account');
    await expect(identity).toContainText('alice');
    await expect(identity).toContainText('Relying party');
    await expect(identity).toContainText('example.localhost');
    await expect(page.locator('w3a-tx-tree')).toHaveCount(0);

    await page.evaluate(() => {
      (globalThis as any).__seamsPasskeyRegistrationModalHandle?.close(true);
      delete (globalThis as any).__seamsPasskeyRegistrationModalHandle;
    });
  });
});
