import { expect, test } from '@playwright/test';

test('demo OTP delivery replaces the existing toast without logging the code', async ({ page }) => {
  const consoleMessages: string[] = [];
  page.on('console', (message) => consoleMessages.push(message.text()));
  await page.goto('/');

  await page.evaluate(async () => {
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
    const modulePath = '/src/flows/demo/PasskeyLoginMenu.tsx';
    const demo = await import(/* @vite-ignore */ modulePath);
    demo.showDemoEmailOtpToast({
      kind: 'demo_code_response',
      status: 'sent',
      emailHint: 'a***@example.test',
      otpCode: '123456',
    });
    demo.showDemoEmailOtpToast({
      kind: 'provider_and_demo_code',
      status: 'reused',
      emailHint: 'a***@example.test',
      otpCode: '654321',
    });
  });

  const demoToasts = page.locator('[data-sonner-toast]').filter({ hasText: 'Code' });
  await expect(demoToasts).toHaveCount(1);
  await expect(demoToasts).toContainText('Code 654-321 copied!');
  await expect(demoToasts).toContainText('Email delivery is not configured for this live demo.');
  await expect(demoToasts).not.toContainText('123-456');
  await expect
    .poll(
      async () =>
        await page.evaluate(
          () =>
            (
              window as typeof window & {
                __copiedDemoEmailOtpCodes?: string[];
              }
            ).__copiedDemoEmailOtpCodes,
        ),
    )
    .toEqual(['123456', '654321']);
  expect(consoleMessages.join('\n')).not.toContain('123456');
  expect(consoleMessages.join('\n')).not.toContain('654321');
});
