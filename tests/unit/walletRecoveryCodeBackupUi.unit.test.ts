import { expect, test, type Page } from '@playwright/test';
import { injectImportMap } from '../setup/bootstrap';
import { SDK_ESM_BASE_PATH } from '../setup/sdkEsmPaths';

// Built dist, not raw source over /@fs: the dialog is a lit component whose
// import graph relies on the SDK's path aliases, which only the build resolves.
const MODULE_URL = '/_test-sdk/esm/SeamsWeb/operations/recovery/walletRecoveryCodeBackup.js';

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
  // injectImportMap re-serves the *current* document with the map injected, so
  // it must follow the navigation — navigating afterwards would discard it.
  await injectImportMap(page);
  // The dialog loads its stylesheets from the SDK asset base. The example app's
  // dev server does not serve /sdk/* here, so point the base at the built dist
  // the test ESM route already serves; the dialog then styles itself exactly as
  // it does in the wallet iframe.
  await page.evaluate((base) => {
    (window as unknown as { __W3A_WALLET_SDK_BASE__?: string }).__W3A_WALLET_SDK_BASE__ = base;
  }, `${SDK_ESM_BASE_PATH}/sdk/`);
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

async function openAccountMenuRecoveryDialog(page: Page): Promise<void> {
  await page.route('**/_test-sdk/esm/sdk/recovery-code-backup.css', async (route) => {
    await new Promise<void>((resolve) => setTimeout(resolve, 100));
    await route.fallback();
  });
  await page.goto('/');
  await injectImportMap(page);
  await page.evaluate((base) => {
    (window as unknown as { __W3A_WALLET_SDK_BASE__?: string }).__W3A_WALLET_SDK_BASE__ = base;
  }, `${SDK_ESM_BASE_PATH}/sdk/`);
  await page.evaluate(
    async ({ moduleUrl, backupRequest }) => {
      const module = await import(moduleUrl);
      const result = module.showWalletRecoveryCodesUi({
        walletId: backupRequest.walletId,
        loadStatus: async () => ({
          kind: 'transport_failed' as const,
          message: 'Recovery status is temporarily unavailable',
        }),
        loadPendingBackup: async () => {
          await new Promise<void>((resolve) => window.setTimeout(resolve, 120));
          return backupRequest;
        },
      });
      (
        window as unknown as { walletRecoveryBackupResult: Promise<unknown> }
      ).walletRecoveryBackupResult = result;
    },
    { moduleUrl: MODULE_URL, backupRequest: request('pending_backup_must_finish') },
  );
}

test('account-menu recovery codes use one Lit dialog for summary, opening, and codes', async ({
  page,
}) => {
  await openAccountMenuRecoveryDialog(page);
  const dialog = page.locator('[data-w3a-wallet-recovery-backup-dialog]');
  const viewer = dialog.locator('w3a-recovery-code-backup-viewer');

  await expect(dialog).toHaveCount(1);
  await expect(dialog).toHaveAttribute('data-w3a-recovery-stage', 'summary');
  await expect(dialog.getByRole('heading', { name: 'Wallet recovery codes' })).toBeVisible();
  await expect(dialog.getByText('Could not load')).toBeVisible();
  const summaryTitle = dialog.getByRole('heading', { name: 'Wallet recovery codes' });
  await expect(summaryTitle).toBeFocused();
  await expect(summaryTitle).toHaveCSS('outline-style', 'none');
  const summaryBox = await dialog.boundingBox();
  await page.evaluate(() => {
    (
      window as typeof window & { recoveryDialogAtSummary?: HTMLDialogElement | null }
    ).recoveryDialogAtSummary = document.querySelector('[data-w3a-wallet-recovery-backup-dialog]');
  });

  await dialog.getByRole('button', { name: 'View recovery codes' }).click();
  await expect(dialog).toHaveAttribute('data-w3a-recovery-stage', 'opening');
  const openingButton = dialog.getByRole('button', { name: 'Opening recovery codes' });
  await expect(openingButton.locator('.recovery-summary-ellipsis')).toHaveAttribute(
    'aria-hidden',
    'true',
  );
  await expect(openingButton.locator('.recovery-summary-ellipsis > span')).toHaveCount(3);

  await expect(dialog).toHaveAttribute('data-w3a-recovery-stage', 'recovery_codes');
  await expect(
    dialog.getByRole('heading', { name: 'Save your wallet recovery codes' }),
  ).toBeFocused();
  await expect(dialog.getByRole('listitem')).toHaveCount(10);
  await expect(viewer).toHaveCSS('animation-name', 'w3a-recovery-codes-content-in');
  await page.waitForTimeout(250);
  const recoveryCodesBox = await dialog.boundingBox();
  const sameDialog = await page.evaluate(() => {
    const initial = (
      window as typeof window & { recoveryDialogAtSummary?: HTMLDialogElement | null }
    ).recoveryDialogAtSummary;
    return initial === document.querySelector('[data-w3a-wallet-recovery-backup-dialog]');
  });

  expect(sameDialog).toBe(true);
  expect(summaryBox).not.toBeNull();
  expect(recoveryCodesBox).not.toBeNull();
  expect(recoveryCodesBox!.width).toBeGreaterThan(summaryBox!.width);
  expect(recoveryCodesBox!.height).toBeGreaterThan(summaryBox!.height);
  await expect(dialog).toHaveCount(1);
});

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
      name: 'I saved these recovery codes (these codes will not be shown again).',
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
    name: 'I saved these recovery codes (these codes will not be shown again).',
  });
  await expect(
    dialog.getByRole('heading', { name: 'Save your wallet recovery codes' }),
  ).toBeFocused();
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

test('copying the codes crossfades the copy icon to a check', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await openDialog(page);
  const dialog = page.locator('[data-w3a-wallet-recovery-backup-dialog]');
  const copyButton = dialog.getByRole('button', { name: 'Copy codes' });
  const copyIcon = copyButton.locator('.copy-icon');
  await expect(copyIcon).toHaveCount(1);
  await expect(copyButton).not.toHaveClass(/copied/);

  await copyButton.click();
  await expect(dialog.getByRole('status')).toHaveText('Recovery codes copied.');
  await expect(copyButton).toHaveClass(/copied/);
  // The check is what the animation reveals; the copy glyph fades out.
  await expect(copyIcon.locator('.copy-icon-check')).toHaveCSS('opacity', '1');
  await expect(copyIcon.locator('.copy-icon-copy')).toHaveCSS('opacity', '0');

  // The flash is transient: the icon returns to its copy state on its own.
  await expect(copyButton).not.toHaveClass(/copied/, { timeout: 5_000 });
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
      name: 'I saved these recovery codes (these codes will not be shown again).',
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
