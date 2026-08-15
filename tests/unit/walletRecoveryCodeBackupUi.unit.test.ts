import { resolve } from 'node:path';
import { expect, test, type Page } from '@playwright/test';

const MODULE_URL = `/@fs${resolve(
  process.cwd(),
  '../packages/sdk-web/src/SeamsWeb/operations/recovery/walletRecoveryCodeBackup.ts',
)}`;

function request(
  continuation: 'registration_may_defer' | 'pending_backup_must_finish' = 'registration_may_defer',
) {
  return {
    kind: 'wallet_recovery_code_backup_request_v1' as const,
    walletId: 'alice.testnet',
    continuation,
    recoveryCodes: Array.from(
      { length: 10 },
      (_, index) => `AAAAA-BBBBB-CCCCC-DDD${String(index).padStart(2, '0')}`,
    ),
  };
}

async function openDialog(
  page: Page,
  continuation: 'registration_may_defer' | 'pending_backup_must_finish' = 'registration_may_defer',
): Promise<void> {
  await page.goto('/');
  await page.evaluate(
    async ({ moduleUrl, backupRequest }) => {
      const module = await import(moduleUrl);
      const result = module.showWalletRecoveryCodeBackupUi(backupRequest);
      (
        window as unknown as { walletRecoveryBackupResult: Promise<unknown> }
      ).walletRecoveryBackupResult = result;
    },
    { moduleUrl: MODULE_URL, backupRequest: request(continuation) },
  );
}

async function readResult(page: Page): Promise<unknown> {
  return await page.evaluate(async () => {
    return await (window as unknown as { walletRecoveryBackupResult: Promise<unknown> })
      .walletRecoveryBackupResult;
  });
}

test('wallet recovery backup completes only through the acknowledged close control', async ({
  page,
}) => {
  await openDialog(page);
  const dialog = page.locator('[data-w3a-wallet-recovery-backup-dialog]');
  await expect(dialog).toBeVisible();
  await expect(
    dialog.getByRole('heading', { name: 'Save your wallet recovery codes' }),
  ).toBeVisible();
  await expect(dialog.getByRole('listitem')).toHaveCount(10);
  await expect(dialog.getByRole('button', { name: 'Finish backup' })).toHaveCount(0);

  await dialog
    .getByRole('checkbox', {
      name: 'I saved these recovery codes somewhere private (will be deleted locally).',
    })
    .check();
  // Acknowledging relabels the single control to name what closing now does.
  await expect(dialog.getByRole('button', { name: 'Back up later' })).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Finish backup' }).click();
  await expect(readResult(page)).resolves.toEqual({ kind: 'wallet_recovery_codes_backed_up_v1' });
  await expect(dialog).toHaveCount(0);
});

test('wallet recovery backup starts at the top with reachable actions and is keyboard completable', async ({
  page,
}) => {
  await page.setViewportSize({ width: 640, height: 600 });
  await openDialog(page);
  const dialog = page.getByRole('dialog');
  const acknowledgement = page.getByRole('checkbox', {
    name: 'I saved these recovery codes somewhere private (will be deleted locally).',
  });
  await expect(dialog).toBeFocused();
  await expect(acknowledgement).toBeVisible();
  await expect(dialog.getByRole('button', { name: 'Back up later' })).toBeInViewport();
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
  await page.keyboard.press('Space');
  await page.keyboard.press('Tab');
  await page.keyboard.press('Enter');
  await expect(readResult(page)).resolves.toEqual({ kind: 'wallet_recovery_codes_backed_up_v1' });
});

test('wallet recovery backup can be deferred to the account menu', async ({ page }) => {
  await openDialog(page);
  await page.getByRole('button', { name: 'Back up later' }).click();
  await expect(readResult(page)).resolves.toEqual({
    kind: 'wallet_recovery_code_backup_deferred_v1',
  });
  await expect(page.getByRole('dialog')).toHaveCount(0);
});

test('account-menu recovery backup closes without completing until acknowledged', async ({
  page,
}) => {
  await openDialog(page, 'pending_backup_must_finish');
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByRole('button', { name: 'Back up later' })).toHaveCount(0);
  await expect(dialog.getByRole('button', { name: 'Finish backup' })).toHaveCount(0);
  await dialog
    .getByRole('checkbox', {
      name: 'I saved these recovery codes somewhere private (will be deleted locally).',
    })
    .check();
  await expect(dialog.getByRole('button', { name: 'Close' })).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Finish backup' }).click();
  await expect(readResult(page)).resolves.toEqual({ kind: 'wallet_recovery_codes_backed_up_v1' });
});

test('account-menu recovery backup close without acknowledgement cancels', async ({ page }) => {
  await openDialog(page, 'pending_backup_must_finish');
  const dialog = page.getByRole('dialog');
  await dialog.getByRole('button', { name: 'Close' }).click();
  const error = await page.evaluate(async () => {
    try {
      await (window as unknown as { walletRecoveryBackupResult: Promise<unknown> })
        .walletRecoveryBackupResult;
      return '';
    } catch (cause: unknown) {
      return cause instanceof Error ? cause.message : String(cause);
    }
  });
  expect(error).toContain('cancelled');
  await expect(page.getByRole('dialog')).toHaveCount(0);
});

test('Escape cancels registration and removes the modal', async ({ page }) => {
  await openDialog(page);
  await expect(page.getByRole('dialog')).toBeVisible();
  await page.keyboard.press('Escape');
  const error = await page.evaluate(async () => {
    try {
      await (window as unknown as { walletRecoveryBackupResult: Promise<unknown> })
        .walletRecoveryBackupResult;
      return '';
    } catch (cause: unknown) {
      return cause instanceof Error ? cause.message : String(cause);
    }
  });
  expect(error).toContain('cancelled');
  await expect(page.getByRole('dialog')).toHaveCount(0);
});
