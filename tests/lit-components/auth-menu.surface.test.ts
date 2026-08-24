import { expect, test, type Page } from '@playwright/test';
import { setupBasicPasskeyTest, sdkEsmPath } from '../setup';
import { ensureComponentModule, mountComponent } from './harness';
import type { AuthMenuRecoveryViewModel } from '@/SeamsWeb/walletIframe/host/lit-ui/auth-menu/auth-menu-domain';

const AUTH_MENU_MODULE = sdkEsmPath(
  'SeamsWeb/walletIframe/host/lit-ui/auth-menu/seams-auth-menu-surface.js',
);
const AUTH_MENU_TAG = 'seams-auth-menu-surface';

const APPEARANCE = {
  theme: {
    id: 'default',
    mode: 'dark',
    colors: {},
  },
  palette: 'default',
} as const;

function registrationViewModel(
  status: unknown = { kind: 'idle', interaction: 'arming' },
  showRegistrationInput = true,
) {
  return {
    appearance: APPEARANCE,
    hostname: 'wallet.example.test',
    closeLabel: 'Close authentication menu',
    heading: 'Create your passkey',
    subtitle: 'Use a passkey to create your wallet.',
    ctaLabel: 'Create passkey',
    showProgress: true,
    kind: 'passkey' as const,
    mode: 'register' as const,
    showRegistrationInput,
    passkeyNameReadOnly: false,
    passkeyNameLabel: 'Passkey name',
    passkeyName: 'My wallet',
    status,
  };
}

function loginViewModel(status: unknown = { kind: 'idle', interaction: 'actionable' }) {
  return {
    appearance: { ...APPEARANCE, theme: { ...APPEARANCE.theme, mode: 'light' as const } },
    hostname: 'wallet.example.test',
    closeLabel: 'Close authentication menu',
    heading: 'Sign in',
    subtitle: 'Use your passkey to continue.',
    ctaLabel: 'Continue with passkey',
    showProgress: true,
    kind: 'passkey' as const,
    mode: 'login' as const,
    accountOptions: [],
    selectedWalletId: null,
    status,
  };
}

type RecoveryEntryViewModel = Extract<AuthMenuRecoveryViewModel, { readonly stage: 'enter_code' }>;

function recoveryEntryViewModel(
  overrides: Partial<{
    recoveryCode: string;
    recoveryCodeError: string | null;
  }> = {},
): RecoveryEntryViewModel {
  return {
    appearance: { ...APPEARANCE, theme: { ...APPEARANCE.theme, mode: 'light' as const } },
    hostname: 'wallet.example.test',
    closeLabel: 'Close authentication menu',
    kind: 'recovery',
    mode: 'login',
    heading: 'Recover account',
    subtitle: 'Enter one recovery code to create a new passkey for your wallet.',
    ctaLabel: 'Continue',
    showProgress: true,
    enabledExternalProviders: [],
    stage: 'enter_code',
    recoveryCode: overrides.recoveryCode ?? '',
    recoveryCodeError: overrides.recoveryCodeError ?? null,
    status: { kind: 'idle', interaction: 'actionable' },
  };
}

function recoveryFinalizingViewModel(): Extract<
  AuthMenuRecoveryViewModel,
  { readonly stage: 'finalizing' }
> {
  return {
    ...recoveryEntryViewModel(),
    walletId: 'wallet-1.test',
    stage: 'finalizing',
    recoveryCode: '',
    status: { kind: 'busy', headline: 'Finishing recovery…' },
  };
}

async function mountAuthMenu(page: Page, viewModel: unknown) {
  await mountComponent(page, {
    tagName: AUTH_MENU_TAG,
    props: { viewModel },
  });
  await page.waitForSelector(`${AUTH_MENU_TAG} [data-auth-menu-close]`, { state: 'attached' });
}

test.describe('wallet-host Lit auth menu surface', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await ensureComponentModule(page, {
      modulePath: AUTH_MENU_MODULE,
      tagName: AUTH_MENU_TAG,
    });
  });

  test('renders compact registration content and emits typed intents', async ({ page }) => {
    await mountAuthMenu(page, registrationViewModel());

    const initial = await page.evaluate((tagName) => {
      const element = document.querySelector(tagName) as HTMLElement;
      const root = element;
      const closeButton = root.querySelector('[data-auth-menu-close]') as HTMLButtonElement | null;
      const primary = root.querySelector('[data-auth-menu-primary]') as HTMLButtonElement | null;
      const input = root.querySelector('#w3a-auth-menu-passkey-name') as HTMLInputElement | null;
      return {
        closeLabel: closeButton?.getAttribute('aria-label') ?? '',
        hasPrimary: !!primary,
        primaryDisabled: primary?.disabled ?? false,
        heading: root.querySelector('.w3a-title')?.textContent?.trim() ?? '',
        subtitle: root.querySelector('.w3a-subhead')?.textContent?.trim() ?? '',
        hasFingerprint: !!root.querySelector('[data-auth-menu-primary] > svg'),
        hasPasskeyName: !!input,
        passkeyNameLabel: input?.getAttribute('placeholder') ?? '',
        waitingText: root.querySelector('.w3a-waiting-text')?.textContent?.trim() ?? '',
        hasCancelCopy: root.textContent?.includes('Cancel') ?? false,
        hasTick: !!root.querySelector('[data-verification-tick], .verification-tick'),
      };
    }, AUTH_MENU_TAG);

    expect(initial.closeLabel).toBe('Back');
    expect(initial.hasPrimary).toBe(true);
    expect(initial.primaryDisabled).toBe(true);
    expect(initial.heading).toBe('Create your passkey');
    expect(initial.subtitle).toBe('Use a passkey to create your wallet.');
    expect(initial.hasFingerprint).toBe(false);
    expect(initial.hasPasskeyName).toBe(true);
    expect(initial.passkeyNameLabel).toBe('Passkey name');
    expect(initial.waitingText).toBe('');
    expect(initial.hasCancelCopy).toBe(false);
    expect(initial.hasTick).toBe(false);

    const intents = await page.evaluate(async (tagName) => {
      const element = document.querySelector(tagName) as HTMLElement & {
        viewModel: unknown;
        updateComplete?: Promise<unknown>;
      };
      const received: unknown[] = [];
      element.addEventListener('w3a-auth-menu-intent', (event) => {
        received.push((event as CustomEvent<unknown>).detail);
      });
      element.viewModel = {
        ...(element.viewModel as Record<string, unknown>),
        passkeyName: 'Ledger passkey',
        status: { kind: 'idle', interaction: 'actionable' },
      };
      await element.updateComplete;
      const input = element.querySelector('#w3a-auth-menu-passkey-name') as HTMLInputElement;
      input.value = 'Ledger passkey';
      input.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
      (element.querySelector('[data-auth-menu-primary]') as HTMLButtonElement).click();
      (element.querySelector('[data-auth-menu-close]') as HTMLButtonElement).click();
      return received;
    }, AUTH_MENU_TAG);

    expect(intents).toEqual([
      { kind: 'passkey_name_changed', passkeyName: 'Ledger passkey' },
      { kind: 'submit', mode: 'register', passkeyName: 'Ledger passkey' },
      { kind: 'back' },
    ]);
  });

  test('keeps recovery in the hosted menu with accessible validation and focus return', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 320, height: 720 });
    await mountAuthMenu(page, loginViewModel());
    await page.evaluate((tagName) => {
      const element = document.querySelector(tagName) as HTMLElement & { intents?: unknown[] };
      element.intents = [];
      element.addEventListener('w3a-auth-menu-intent', (event) => {
        element.intents?.push((event as CustomEvent<unknown>).detail);
      });
    }, AUTH_MENU_TAG);

    await page.locator(`${AUTH_MENU_TAG} [data-recovery-action]`).click();
    expect(
      await page.evaluate(
        (tagName) =>
          (document.querySelector(tagName) as HTMLElement & { intents?: unknown[] }).intents,
        AUTH_MENU_TAG,
      ),
    ).toEqual([{ kind: 'recovery_open' }]);

    await page.evaluate(
      async ({ tagName, viewModel }) => {
        const element = document.querySelector(tagName) as HTMLElement & {
          viewModel: unknown;
          updateComplete: Promise<unknown>;
        };
        element.viewModel = viewModel;
        await element.updateComplete;
      },
      { tagName: AUTH_MENU_TAG, viewModel: recoveryEntryViewModel() },
    );

    const codeInput = page.locator(`${AUTH_MENU_TAG} [data-recovery-code]`);
    const recoveryFeedback = page.locator(`${AUTH_MENU_TAG} #w3a-recovery-code-feedback`);
    await expect(page.locator(`${AUTH_MENU_TAG} .w3a-title`)).toHaveCSS('text-align', 'center');
    await expect(page.locator(`${AUTH_MENU_TAG} .w3a-subhead`)).toHaveCSS('text-align', 'center');
    await expect(recoveryFeedback).toHaveText('Enter a recovery code to recover your wallet.');
    await expect(recoveryFeedback).toHaveCSS('margin', '4px');
    await expect(
      page.locator(`${AUTH_MENU_TAG} .w3a-header + #w3a-recovery-code-feedback`),
    ).toHaveCount(1);
    await expect(page.locator(`${AUTH_MENU_TAG} .w3a-recovery-form`)).toHaveCSS('gap', '8px');
    await expect(codeInput).toHaveAttribute('aria-invalid', 'false');
    await expect(codeInput).toHaveCSS('font-size', '16px');
    await expect(page.locator(`${AUTH_MENU_TAG} [data-auth-menu-primary]`)).toBeEnabled();
    await codeInput.fill('ABCD-EFGH');
    await page.locator(`${AUTH_MENU_TAG} form`).press('Enter');

    await page.evaluate(
      async ({ tagName, viewModel }) => {
        const element = document.querySelector(tagName) as HTMLElement & {
          viewModel: unknown;
          updateComplete: Promise<unknown>;
        };
        element.viewModel = viewModel;
        await element.updateComplete;
      },
      {
        tagName: AUTH_MENU_TAG,
        viewModel: recoveryEntryViewModel({
          recoveryCodeError: 'Enter a recovery code.',
        }),
      },
    );
    await expect(codeInput).toBeFocused();
    await expect(codeInput).toHaveAttribute('aria-describedby', 'w3a-recovery-code-feedback');
    await expect(recoveryFeedback).toHaveCount(1);
    await expect(recoveryFeedback).toHaveText('Enter a recovery code.');
    await expect(recoveryFeedback).toHaveClass(/w3a-recovery-error/);
    await expect(recoveryFeedback).toHaveAttribute('aria-hidden', 'false');

    await page.evaluate(() => {
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    });
    const intents = await page.evaluate(
      (tagName) =>
        (document.querySelector(tagName) as HTMLElement & { intents?: unknown[] }).intents,
      AUTH_MENU_TAG,
    );
    expect(intents).toEqual([
      { kind: 'recovery_open' },
      { kind: 'recovery_code_changed', recoveryCode: 'ABCD-EFGH' },
      { kind: 'recovery_submit' },
      { kind: 'back' },
    ]);

    await page.evaluate(
      async ({ tagName, viewModel }) => {
        const element = document.querySelector(tagName) as HTMLElement & {
          viewModel: unknown;
          updateComplete: Promise<unknown>;
        };
        element.viewModel = viewModel;
        await element.updateComplete;
      },
      { tagName: AUTH_MENU_TAG, viewModel: loginViewModel() },
    );
    await expect(page.locator(`${AUTH_MENU_TAG} [data-recovery-action]`)).toBeFocused();
    const reflow = await page
      .locator(`${AUTH_MENU_TAG} .w3a-signup-menu-root`)
      .evaluate((root) => ({
        clientWidth: root.clientWidth,
        scrollWidth: root.scrollWidth,
      }));
    expect(reflow.clientWidth).toBeGreaterThanOrEqual(318);
    expect(reflow.scrollWidth).toBeLessThanOrEqual(reflow.clientWidth);
  });

  test('locks Back and Escape while recovery finalization is irreversible', async ({ page }) => {
    await mountAuthMenu(page, recoveryFinalizingViewModel());
    await page.evaluate((tagName) => {
      const element = document.querySelector(tagName) as HTMLElement & { intents?: unknown[] };
      element.intents = [];
      element.addEventListener('w3a-auth-menu-intent', (event) => {
        element.intents?.push((event as CustomEvent<unknown>).detail);
      });
    }, AUTH_MENU_TAG);

    await expect(page.locator(`${AUTH_MENU_TAG} [data-auth-menu-close]`)).toBeDisabled();
    await page.keyboard.press('Escape');

    expect(
      await page.evaluate(
        (tagName) =>
          (document.querySelector(tagName) as HTMLElement & { intents?: unknown[] }).intents,
        AUTH_MENU_TAG,
      ),
    ).toEqual([]);
  });

  test('renders the device-link QR menu and returns through the Back control', async ({ page }) => {
    await mountAuthMenu(page, {
      ...loginViewModel(),
      kind: 'link_device',
      heading: 'Scan and Link Device',
      subtitle: 'Scan to backup your other device.',
      ctaLabel: '',
      linkDevice: {
        kind: 'ready',
        qrCodeDataURL: 'data:image/png;base64,iVBORw0KGgo=',
        message: 'Waiting for device to scan',
      },
    });

    const result = await page.evaluate((tagName) => {
      const element = document.querySelector(tagName) as HTMLElement;
      const received: unknown[] = [];
      element.addEventListener('w3a-auth-menu-intent', (event) => {
        received.push((event as CustomEvent<unknown>).detail);
      });
      const image = element.querySelector('.qr-code-image') as HTMLImageElement | null;
      (element.querySelector('[data-auth-menu-close]') as HTMLButtonElement).click();
      return {
        title: element.querySelector('.qr-title')?.textContent?.trim(),
        instruction: element.querySelector('.qr-instruction')?.textContent?.trim(),
        status: element.querySelector('.qr-status')?.textContent?.trim(),
        imageAlt: image?.alt,
        intents: received,
      };
    }, AUTH_MENU_TAG);

    expect(result).toEqual({
      title: 'Scan and Link Device',
      instruction: 'Scan to backup your other device.',
      status: 'Waiting for device to scan',
      imageAlt: 'QR code to link this device',
      intents: [{ kind: 'back' }],
    });
  });

  test('renders post-link activation without returning to QR generation', async ({ page }) => {
    await mountAuthMenu(page, {
      ...loginViewModel(),
      kind: 'link_device',
      heading: 'Scan and link device',
      subtitle: 'Scan this code with your other device.',
      ctaLabel: '',
      linkDevice: {
        kind: 'activating',
        message: 'Preparing this device for signing',
      },
    });

    const result = await page.evaluate((tagName) => {
      const element = document.querySelector(tagName) as HTMLElement;
      return {
        title: element.querySelector('.qr-title')?.textContent?.trim(),
        status: element.querySelector('[role="status"]')?.textContent?.trim(),
        live: element.querySelector('[role="status"]')?.getAttribute('aria-live'),
        hasQrImage: !!element.querySelector('.qr-code-image'),
        text: element.textContent ?? '',
      };
    }, AUTH_MENU_TAG);

    expect(result.title).toBe('Opening linked wallet');
    expect(result.status).toBe('Preparing this device for signing');
    expect(result.live).toBe('polite');
    expect(result.hasQrImage).toBe(false);
    expect(result.text).not.toContain('Generating QR code');
    expect(result.text).not.toContain('Preparing a one-time code');
  });

  test('renders linked-wallet activation failures with a recovery action', async ({ page }) => {
    await mountAuthMenu(page, {
      ...loginViewModel(),
      kind: 'link_device',
      heading: 'Scan and link device',
      subtitle: 'Scan this code with your other device.',
      ctaLabel: '',
      linkDevice: {
        kind: 'activation_error',
        message: 'Wallet Session renewal failed',
      },
    });

    const result = await page.evaluate((tagName) => {
      const element = document.querySelector(tagName) as HTMLElement;
      const intents: unknown[] = [];
      element.addEventListener('w3a-auth-menu-intent', (event) => {
        intents.push((event as CustomEvent<unknown>).detail);
      });
      (element.querySelector('[data-auth-menu-primary]') as HTMLButtonElement).click();
      return {
        title: element.querySelector('.qr-title')?.textContent?.trim(),
        alert: element.querySelector('[role="alert"]')?.textContent?.replace(/\s+/g, ' ').trim(),
        action: element.querySelector('[data-auth-menu-primary]')?.textContent?.trim(),
        intents,
      };
    }, AUTH_MENU_TAG);

    expect(result).toEqual({
      title: 'Device linked',
      alert:
        'Unable to open the wallet. Return to sign in and try again. Wallet Session renewal failed',
      action: 'Return to sign in',
      intents: [{ kind: 'back' }],
    });
  });

  test('keeps the Back control interactive while passkey authentication is running', async ({
    page,
  }) => {
    await mountAuthMenu(page, loginViewModel({ kind: 'busy', headline: 'Signing in…' }));
    await page.evaluate((tagName) => {
      const element = document.querySelector(tagName);
      if (!element) throw new Error('auth-menu surface is missing');
      (window as Window & { __authMenuIntents?: unknown[] }).__authMenuIntents = [];
      element.addEventListener('w3a-auth-menu-intent', (event) => {
        (window as Window & { __authMenuIntents?: unknown[] }).__authMenuIntents?.push(
          (event as CustomEvent<unknown>).detail,
        );
      });
    }, AUTH_MENU_TAG);

    await page.locator(`${AUTH_MENU_TAG} [data-auth-menu-close]`).click();

    const intents = await page.evaluate(
      () => (window as Window & { __authMenuIntents?: unknown[] }).__authMenuIntents ?? [],
    );
    expect(intents).toEqual([{ kind: 'back' }]);
  });

  test('animates into the waiting view with a rotating spinner', async ({ page }) => {
    await mountAuthMenu(page, loginViewModel({ kind: 'busy', headline: 'Signing in…' }));

    const waiting = await page.evaluate((tagName) => {
      const surface = document.querySelector(tagName) as HTMLElement;
      const spinner = surface.querySelector('.w3a-waiting > .w3a-spinner') as HTMLElement | null;
      const root = surface.querySelector('.w3a-signup-menu-root') as HTMLElement | null;
      const switcher = surface.querySelector('.w3a-content-switcher') as HTMLElement | null;
      if (!spinner || !root || !switcher) throw new Error('waiting view is missing');
      const spinnerStyle = getComputedStyle(spinner);
      // Read the token from the root: state-scoped overrides (the waiting
      // view runs faster) land there, and the invariant is that every part
      // shares the duration in effect for the CURRENT state.
      const resizeToken = getComputedStyle(root).getPropertyValue('--w3a-duration-resize').trim();
      return {
        spinnerAnimations: spinnerStyle.animationName,
        spinnerPlayState: spinnerStyle.animationPlayState,
        resizeSeconds: `${Number.parseFloat(resizeToken) / 1000}s`,
        rootTransition: getComputedStyle(root).transitionDuration,
        switcherTransition: getComputedStyle(switcher).transitionDuration,
      };
    }, AUTH_MENU_TAG);

    // The card owns the resize in both directions. Never add an `animation:`
    // shorthand to `.w3a-waiting > .w3a-spinner` — it shadows the rotation and
    // freezes it.
    expect(waiting.spinnerAnimations).toContain('w3a-spin');
    expect(waiting.spinnerPlayState).not.toContain('paused');
    // Assert the shared token, not a literal: the invariant is that every part
    // of the box settles on ONE duration. A part left on its own timing splits
    // one movement into two, which is the bug this guards. Retuning the
    // duration is a design call and must not fail here.
    expect(waiting.resizeSeconds).not.toBe('NaNs');
    expect(waiting.rootTransition).toContain(waiting.resizeSeconds);
    expect(waiting.switcherTransition).toContain(waiting.resizeSeconds);
  });

  test('Escape backs out of the waiting view but is ignored on the menu itself', async ({
    page,
  }) => {
    await mountAuthMenu(page, loginViewModel({ kind: 'busy', headline: 'Signing in…' }));

    const fromWaiting = await page.evaluate(async (tagName) => {
      const element = document.querySelector(tagName) as HTMLElement;
      const received: unknown[] = [];
      element.addEventListener('w3a-auth-menu-intent', (event) => {
        received.push((event as CustomEvent<unknown>).detail);
      });
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
      return received;
    }, AUTH_MENU_TAG);
    expect(fromWaiting).toEqual([{ kind: 'back' }]);

    await mountAuthMenu(page, loginViewModel({ kind: 'idle', interaction: 'actionable' }));
    const fromMenu = await page.evaluate(async (tagName) => {
      const element = document.querySelector(tagName) as HTMLElement;
      const received: unknown[] = [];
      element.addEventListener('w3a-auth-menu-intent', (event) => {
        received.push((event as CustomEvent<unknown>).detail);
      });
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
      return received;
    }, AUTH_MENU_TAG);
    // On the menu itself Escape belongs to the embedding page.
    expect(fromMenu).toEqual([]);
  });

  test('keeps required sponsored registration input quiet until a name is entered', async ({
    page,
  }) => {
    await mountAuthMenu(page, {
      ...registrationViewModel({ kind: 'idle', interaction: 'awaiting_input' }, true),
      passkeyName: '',
    });

    const snapshot = await page.evaluate(async (tagName) => {
      const root = document.querySelector(tagName) as HTMLElement;
      const input = root.querySelector('#w3a-auth-menu-passkey-name') as HTMLInputElement | null;
      return {
        ariaBusy: root.querySelector('.auth-menu-root')?.getAttribute('aria-busy') ?? '',
        ctaDisabled: (root.querySelector('[data-auth-menu-primary]') as HTMLButtonElement)
          ?.disabled,
        inputDisabled: input?.disabled ?? false,
        inputValue: input?.value ?? '',
        hasAlert: !!root.querySelector('[role="alert"]'),
        retryCount: root.querySelectorAll('.auth-menu-retry').length,
        hasProgress: !!root.querySelector('.w3a-waiting'),
      };
    }, AUTH_MENU_TAG);

    expect(snapshot).toEqual({
      ariaBusy: 'false',
      ctaDisabled: true,
      inputDisabled: false,
      inputValue: '',
      hasAlert: false,
      retryCount: 0,
      hasProgress: false,
    });
  });

  test('renders login without registration input and uses the original compact spinner', async ({
    page,
  }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await mountAuthMenu(
      page,
      loginViewModel({ kind: 'busy', headline: 'Signing in…', detail: 'Checking passkey' }),
    );

    const snapshot = await page.evaluate((tagName) => {
      const root = document.querySelector(tagName) as HTMLElement;
      return {
        hasPrimary: !!root.querySelector('[data-auth-menu-primary]'),
        hasPasskeyName: !!root.querySelector('#w3a-auth-menu-passkey-name'),
        hasHalo: !!root.querySelector('w3a-passkey-halo-loading'),
        heading: root.querySelector('.w3a-waiting-text')?.textContent?.trim() ?? '',
        spinnerLabel: root.querySelector('.w3a-spinner')?.getAttribute('aria-label') ?? '',
      };
    }, AUTH_MENU_TAG);

    expect(snapshot.hasPrimary).toBe(false);
    expect(snapshot.hasPasskeyName).toBe(false);
    expect(snapshot.hasHalo).toBe(false);
    expect(snapshot.heading).toBe('Signing in…');
    expect(snapshot.spinnerLabel).toBe('Loading');
  });

  test('hides the registration input when host configuration disables it', async ({ page }) => {
    await mountAuthMenu(page, {
      ...registrationViewModel({ kind: 'idle', interaction: 'actionable' }, false),
      enabledExternalProviders: ['google'],
    });

    const snapshot = await page.evaluate((tagName) => {
      const root = document.querySelector(tagName) as HTMLElement;
      return {
        hasPasskeyName: !!root.querySelector('#w3a-auth-menu-passkey-name'),
      };
    }, AUTH_MENU_TAG);

    expect(snapshot.hasPasskeyName).toBe(false);
  });

  test('preserves the original auth-menu spacing and social-provider structure', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 420, height: 900 });
    await mountAuthMenu(page, {
      ...loginViewModel(),
      enabledExternalProviders: ['google'],
    });

    const snapshot = await page.evaluate((tagName) => {
      const root = document.querySelector(tagName) as HTMLElement;
      const menu = root.querySelector('.w3a-signup-menu-root') as HTMLElement;
      const divider = root.querySelector('.w3a-section-divider') as HTMLElement;
      const dividerText = root.querySelector('.w3a-section-divider-text') as HTMLElement;
      const google = root.querySelector('[data-auth-menu-provider="google"]');
      return {
        padding: getComputedStyle(menu).padding,
        dividerMargin: getComputedStyle(divider).margin,
        dividerTextPadding: getComputedStyle(dividerText).padding,
        googleUsesOriginalWrappers:
          google?.parentElement?.classList.contains('w3a-social-provider'),
        socialStackUsesOriginalClasses:
          google?.parentElement?.parentElement?.classList.contains('w3a-auth-method-stack') &&
          google.parentElement.parentElement.classList.contains('w3a-social-stack'),
      };
    }, AUTH_MENU_TAG);

    expect(snapshot).toEqual({
      padding: '28px 24px 24px',
      dividerMargin: '16px 0px',
      dividerTextPadding: '0px 8px',
      googleUsesOriginalWrappers: true,
      socialStackUsesOriginalClasses: true,
    });
  });

  test('renders the implicit-wallet reroll and mode switch intents', async ({ page }) => {
    await mountAuthMenu(page, {
      ...registrationViewModel({ kind: 'idle', interaction: 'actionable' }),
      passkeyNameReadOnly: true,
      showRegistrationInput: true,
    });

    const intents = await page.evaluate(async (tagName) => {
      const element = document.querySelector(tagName) as HTMLElement;
      const received: unknown[] = [];
      element.addEventListener('w3a-auth-menu-intent', (event) => {
        received.push((event as CustomEvent<unknown>).detail);
      });
      (element.querySelector('[data-auth-menu-mode="login"]') as HTMLButtonElement).click();
      (element.querySelector('.auth-menu-registration-reroll') as HTMLButtonElement).click();
      return received;
    }, AUTH_MENU_TAG);

    expect(intents).toEqual([
      { kind: 'mode_selected', mode: 'login' },
      { kind: 'registration_reroll' },
    ]);
  });

  test('keeps the primary action live without rendering an expired preparation error', async ({
    page,
  }) => {
    await mountAuthMenu(page, {
      ...loginViewModel({
        kind: 'recoverable',
        reason: 'expired',
        message: 'Passkey preparation expired',
      }),
      enabledExternalProviders: ['google'],
    });

    const snapshot = await page.evaluate(async (tagName) => {
      const element = document.querySelector(tagName) as HTMLElement;
      return {
        ctaDisabled: (element.querySelector('[data-auth-menu-primary]') as HTMLButtonElement)
          .disabled,
        providerDisabled: (element.querySelector('[data-auth-menu-provider]') as HTMLButtonElement)
          ?.disabled,
        error: element.querySelector('[role="alert"]')?.textContent?.trim() ?? '',
        retryCount: element.querySelectorAll('.auth-menu-retry').length,
        modeSwitchEnabled: !(
          element.querySelector('[data-auth-menu-mode="register"]') as HTMLButtonElement
        ).disabled,
      };
    }, AUTH_MENU_TAG);

    // The primary button is the retry affordance now, so it must stay usable.
    expect(snapshot.ctaDisabled).toBe(false);
    expect(snapshot.providerDisabled).toBe(false);
    expect(snapshot.error).toBe('');
    expect(snapshot.retryCount).toBe(0);
    expect(snapshot.modeSwitchEnabled).toBe(true);

    const submitIntent = await page.evaluate(async (tagName) => {
      const element = document.querySelector(tagName) as HTMLElement;
      const received: unknown[] = [];
      element.addEventListener('w3a-auth-menu-intent', (event) => {
        received.push((event as CustomEvent<unknown>).detail);
      });
      (element.querySelector('[data-auth-menu-primary]') as HTMLButtonElement).click();
      return received;
    }, AUTH_MENU_TAG);
    expect(submitIntent).toEqual([{ kind: 'submit', mode: 'login' }]);
  });

  test('renders Google OTP controls and emits code, resend, and submit intents', async ({
    page,
  }) => {
    await mountAuthMenu(page, {
      ...loginViewModel({ kind: 'idle', interaction: 'actionable' }),
      kind: 'google_otp_login',
      mode: 'login',
      emailHint: 'g***@example.test',
      walletId: 'wallet-google-test',
      prompt: {
        title: 'Verify your email',
        description: 'Enter the code we sent.',
        submitLabel: 'Verify',
        helperText: '',
      },
      delivery: { kind: 'provider', status: 'sent', emailHint: 'g***@example.test' },
      otpCode: '',
      resendBusy: false,
      submitBusy: false,
    });

    const intents = await page.evaluate(async (tagName) => {
      const element = document.querySelector(tagName) as HTMLElement;
      const received: unknown[] = [];
      element.addEventListener('w3a-auth-menu-intent', (event) => {
        received.push((event as CustomEvent<unknown>).detail);
      });
      const input = element.querySelector('#w3a-auth-menu-google-otp') as HTMLInputElement;
      input.value = '123456';
      input.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
      (element.querySelector('.auth-menu-google-resend') as HTMLButtonElement).click();
      element.viewModel = {
        ...(element.viewModel as Record<string, unknown>),
        otpCode: '123456',
      };
      await (element as HTMLElement & { updateComplete?: Promise<unknown> }).updateComplete;
      (element.querySelector('[data-auth-menu-primary]') as HTMLButtonElement).click();
      return received;
    }, AUTH_MENU_TAG);

    expect(intents).toEqual([
      { kind: 'google_otp_code_changed', code: '123456' },
      { kind: 'google_otp_resend' },
      { kind: 'google_otp_submit' },
    ]);
  });

  test('renders a multi-wallet login selector and emits the selected wallet', async ({ page }) => {
    await mountAuthMenu(page, {
      ...loginViewModel(),
      kind: 'passkey',
      accountOptions: [
        { walletId: 'wallet-a', displayName: 'Wallet A' },
        { walletId: 'wallet-b', displayName: 'Wallet B' },
      ],
      selectedWalletId: 'wallet-a',
    });

    const selected = await page.evaluate(async (tagName) => {
      const element = document.querySelector(tagName) as HTMLElement;
      const received: unknown[] = [];
      element.addEventListener('w3a-auth-menu-intent', (event) => {
        received.push((event as CustomEvent<unknown>).detail);
      });
      (element.querySelector('.w3a-account-menu-trigger') as HTMLButtonElement).click();
      await (element as HTMLElement & { updateComplete?: Promise<unknown> }).updateComplete;
      (element.querySelector('[data-wallet-id="wallet-b"]') as HTMLButtonElement).click();
      return received;
    }, AUTH_MENU_TAG);

    expect(selected).toEqual([{ kind: 'login_account_selected', walletId: 'wallet-b' }]);
  });

  test('starts a ready login intent from the primary CTA and closes on Escape', async ({
    page,
  }) => {
    await mountAuthMenu(page, loginViewModel());

    const intents = await page.evaluate(async (tagName) => {
      const element = document.querySelector(tagName) as HTMLElement;
      const received: unknown[] = [];
      element.addEventListener('w3a-auth-menu-intent', (event) => {
        received.push((event as CustomEvent<unknown>).detail);
      });
      (element.querySelector('[data-auth-menu-primary]') as HTMLButtonElement).click();
      const root = element.querySelector('.auth-menu-root') as HTMLElement;
      root.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
      return received;
    }, AUTH_MENU_TAG);

    expect(intents).toEqual([
      { kind: 'submit', mode: 'login' },
      { kind: 'close', reason: 'escape' },
    ]);
  });
});
