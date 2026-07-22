import { expect, test } from '@playwright/test';

test('demo OTP delivery replaces the existing toast without logging the code', async ({ page }) => {
  const consoleMessages: string[] = [];
  page.on('console', (message) => consoleMessages.push(message.text()));
  await page.goto('/');

  await page.evaluate(async () => {
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

  const demoToasts = page.locator('[data-sonner-toast]').filter({ hasText: 'Demo email code:' });
  await expect(demoToasts).toHaveCount(1);
  await expect(demoToasts).toContainText('Demo email code: 654321');
  await expect(demoToasts).not.toContainText('123456');
  expect(consoleMessages.join('\n')).not.toContain('123456');
  expect(consoleMessages.join('\n')).not.toContain('654321');
});
