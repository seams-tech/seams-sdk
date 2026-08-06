import { expect, test, type Page } from '@playwright/test';
import { setupBasicPasskeyTest, sdkEsmPath } from '../setup';
import { ensureComponentModule, mountComponent } from './harness';

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
  status: unknown = { kind: 'preparing', message: 'Preparing passkey' },
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

function loginViewModel(status: unknown = { kind: 'ready' }) {
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
        heading: root.querySelector('.w3a-title')?.textContent?.trim() ?? '',
        subtitle: root.querySelector('.w3a-subhead')?.textContent?.trim() ?? '',
        hasFingerprint: !!root.querySelector('[data-auth-menu-primary] svg'),
        hasPasskeyName: !!input,
        passkeyNameLabel: input?.getAttribute('placeholder') ?? '',
        waitingText: root.querySelector('.w3a-waiting-text')?.textContent?.trim() ?? '',
        hasCancelCopy: root.textContent?.includes('Cancel') ?? false,
        hasTick: !!root.querySelector('[data-verification-tick], .verification-tick'),
      };
    }, AUTH_MENU_TAG);

    expect(initial.closeLabel).toBe('Back');
    expect(initial.hasPrimary).toBe(false);
    expect(initial.heading).toBe('');
    expect(initial.subtitle).toBe('');
    expect(initial.hasFingerprint).toBe(false);
    expect(initial.hasPasskeyName).toBe(false);
    expect(initial.passkeyNameLabel).toBe('');
    expect(initial.waitingText).toBe('Preparing passkey');
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
        status: { kind: 'ready' },
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
      imageAlt: 'Device Linking QR Code',
      intents: [{ kind: 'back' }],
    });
  });

  test('keeps required sponsored registration input quiet until a name is entered', async ({
    page,
  }) => {
    await mountAuthMenu(page, {
      ...registrationViewModel({ kind: 'input_required' }, true),
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

  test('renders login without registration input and keeps the halo still for reduced motion', async ({
    page,
  }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await mountAuthMenu(page, loginViewModel({ kind: 'performing', message: 'Checking passkey' }));

    const snapshot = await page.evaluate((tagName) => {
      const root = document.querySelector(tagName) as HTMLElement;
      const halo = root.querySelector('w3a-passkey-halo-loading') as HTMLElement & {
        animated?: boolean;
        theme?: string;
      };
      return {
        hasPrimary: !!root.querySelector('[data-auth-menu-primary]'),
        hasPasskeyName: !!root.querySelector('#w3a-auth-menu-passkey-name'),
        haloAnimated: halo?.animated,
        heading: root.querySelector('.w3a-waiting-text')?.textContent?.trim() ?? '',
        theme: halo?.theme,
      };
    }, AUTH_MENU_TAG);

    expect(snapshot.hasPrimary).toBe(false);
    expect(snapshot.hasPasskeyName).toBe(false);
    expect(snapshot.haloAnimated).toBe(false);
    expect(snapshot.heading).toBe('Signing in…');
    expect(snapshot.theme).toBe('dark');
  });

  test('hides the registration input when host configuration disables it', async ({ page }) => {
    await mountAuthMenu(page, registrationViewModel({ kind: 'ready' }, false));

    const hasPasskeyName = await page.evaluate((tagName) => {
      const root = document.querySelector(tagName) as HTMLElement;
      return !!root.querySelector('#w3a-auth-menu-passkey-name');
    }, AUTH_MENU_TAG);

    expect(hasPasskeyName).toBe(false);
  });

  test('renders the implicit-wallet reroll and mode switch intents', async ({ page }) => {
    await mountAuthMenu(page, {
      ...registrationViewModel({ kind: 'ready' }),
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

  test('keeps expired preparation disabled and exposes a retry intent', async ({ page }) => {
    await mountAuthMenu(page, {
      ...loginViewModel({ kind: 'expired', message: 'Passkey preparation expired' }),
      enabledExternalProviders: ['google'],
    });

    const snapshot = await page.evaluate(async (tagName) => {
      const element = document.querySelector(tagName) as HTMLElement;
      const received: unknown[] = [];
      element.addEventListener('w3a-auth-menu-intent', (event) => {
        received.push((event as CustomEvent<unknown>).detail);
      });
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
        received,
      };
    }, AUTH_MENU_TAG);

    expect(snapshot.ctaDisabled).toBe(true);
    expect(snapshot.providerDisabled).toBe(true);
    expect(snapshot.error).toBe('Passkey preparation expired');
    expect(snapshot.retryCount).toBe(1);
    expect(snapshot.modeSwitchEnabled).toBe(true);

    const retryIntent = await page.evaluate(async (tagName) => {
      const element = document.querySelector(tagName) as HTMLElement;
      const received: unknown[] = [];
      element.addEventListener('w3a-auth-menu-intent', (event) => {
        received.push((event as CustomEvent<unknown>).detail);
      });
      (element.querySelector('.auth-menu-retry') as HTMLButtonElement).click();
      return received;
    }, AUTH_MENU_TAG);
    expect(retryIntent).toEqual([{ kind: 'retry' }]);
  });

  test('renders Google OTP controls and emits code, resend, and submit intents', async ({
    page,
  }) => {
    await mountAuthMenu(page, {
      ...loginViewModel({ kind: 'ready' }),
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
      (
        element.querySelector('[data-wallet-id="wallet-b"]') as HTMLButtonElement
      ).click();
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
