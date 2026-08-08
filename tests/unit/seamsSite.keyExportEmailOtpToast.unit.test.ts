import { expect, test } from '@playwright/test';

const KEY_EXPORT_MODULE = '/src/components/SeamsProfileSettingsButton.tsx';

const INPUT_REQUIRED = 'key_export.auth.email_otp.input.required';
const MATERIAL_PREPARE_STARTED = 'key_export.material.prepare.started';
const COMPLETED = 'key_export.completed';
const CANCELLED = 'key_export.cancelled';

type KeyExportToastProbe = {
  copiedCodes: string[];
  emit: (phase: string, demoOtpCode?: string | null) => void;
};

async function installKeyExportToastProbe(page: import('@playwright/test').Page): Promise<void> {
  await page.goto('/');
  await page.evaluate(async (modulePath) => {
    const copiedCodes: string[] = [];
    Object.assign(window, { __copiedDemoEmailOtpCodes: copiedCodes });
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async (value: string) => {
          copiedCodes.push(value);
        },
      },
    });
    const mod = await import(/* @vite-ignore */ modulePath);
    Object.assign(window, {
      __emitKeyExportEvent: (phase: string, demoOtpCode?: string | null) => {
        mod.handleKeyExportEvent({
          phase,
          status: 'waiting_for_user',
          authMethod: 'email_otp',
          data: { emailHint: 'a***@example.test', demoOtpCode: demoOtpCode ?? null },
        });
      },
    });
  }, KEY_EXPORT_MODULE);
}

function emit(page: import('@playwright/test').Page, phase: string, code?: string | null) {
  return page.evaluate(
    ([nextPhase, nextCode]) => {
      (
        window as typeof window & {
          __emitKeyExportEvent: (phase: string, demoOtpCode?: string | null) => void;
        }
      ).__emitKeyExportEvent(nextPhase as string, nextCode as string | null);
    },
    [phase, code ?? null],
  );
}

function demoToasts(page: import('@playwright/test').Page) {
  return page.locator('[data-sonner-toast]').filter({ hasText: 'Code' });
}

test('key-export demo OTP code is shown once, copied raw, and never logged', async ({ page }) => {
  const consoleMessages: string[] = [];
  page.on('console', (message) => consoleMessages.push(message.text()));
  await installKeyExportToastProbe(page);

  await emit(page, INPUT_REQUIRED, '123456');
  await emit(page, INPUT_REQUIRED, '654321');

  await expect(demoToasts(page)).toHaveCount(1);
  await expect(demoToasts(page)).toContainText('Code 654-321 copied!');
  await expect(demoToasts(page)).not.toContainText('123-456');

  await expect
    .poll(async () =>
      page.evaluate(
        () =>
          (window as typeof window & { __copiedDemoEmailOtpCodes?: string[] })
            .__copiedDemoEmailOtpCodes,
      ),
    )
    .toEqual(['123456', '654321']);

  expect(consoleMessages.join('\n')).not.toContain('123456');
  expect(consoleMessages.join('\n')).not.toContain('654321');
});

test('provider-only resend dismisses the key-export OTP toast', async ({ page }) => {
  await installKeyExportToastProbe(page);

  await emit(page, INPUT_REQUIRED, '123456');
  await expect(demoToasts(page)).toHaveCount(1);

  // A resend under provider-only delivery carries no code: the stale code must go.
  await emit(page, INPUT_REQUIRED, null);
  await expect(demoToasts(page)).toHaveCount(0);
});

for (const terminalPhase of [MATERIAL_PREPARE_STARTED, COMPLETED, CANCELLED]) {
  test(`key-export OTP toast is dismissed on ${terminalPhase}`, async ({ page }) => {
    await installKeyExportToastProbe(page);

    await emit(page, INPUT_REQUIRED, '123456');
    await expect(demoToasts(page)).toHaveCount(1);

    await emit(page, terminalPhase, null);
    await expect(demoToasts(page)).toHaveCount(0);
  });
}

export type { KeyExportToastProbe };
