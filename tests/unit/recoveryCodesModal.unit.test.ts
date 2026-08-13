import { expect, test } from '@playwright/test';
import { injectImportMap } from '../setup/bootstrap';

const MODAL_URL = '/_test-sdk/esm/react/components/AccountMenuButton/RecoveryCodesModal.js';
const BACKUP_URL = '/_test-sdk/esm/SeamsWeb/operations/recovery/walletRecoveryCodeBackup.js';

test('account menu can view locally retained recovery codes when remote status is unavailable', async ({
  page,
}) => {
  await page.goto('about:blank');
  await injectImportMap(page);
  await page.evaluate(
    async ({ modalUrl, backupUrl }) => {
      const React = await import('react');
      const ReactDOMClient = await import('react-dom/client');
      const ReactDOM = await import('react-dom');
      const { default: RecoveryCodesModal } = await import(modalUrl);
      const { showWalletRecoveryCodeBackupUi } = await import(backupUrl);
      const mount = document.createElement('div');
      document.body.appendChild(mount);
      const recoveryCodes = Array.from(
        { length: 10 },
        (_, index) => `AAAAA-BBBBB-CCCCC-DDD${String(index).padStart(2, '0')}`,
      );
      const recovery = {
        getWalletRecoveryCodeStatus: async () => ({
          kind: 'transport_failed' as const,
          message: 'Recovery status is temporarily unavailable',
        }),
        acknowledgeWalletRecoveryCodeBackup: async () => {
          await showWalletRecoveryCodeBackupUi({
            kind: 'wallet_recovery_code_backup_request_v1',
            walletId: 'swift-sable-hgmrzh',
            recoveryCodes,
            continuation: 'pending_backup_must_finish',
          });
          return {
            kind: 'acknowledged' as const,
            walletId: 'swift-sable-hgmrzh',
            issuedAtMs: Date.now(),
          };
        },
      };
      const root = ReactDOMClient.createRoot(mount);
      ReactDOM.flushSync(() => {
        root.render(
          React.createElement(RecoveryCodesModal, {
            walletId: 'swift-sable-hgmrzh',
            isOpen: true,
            onClose: () => undefined,
            recovery,
          }),
        );
      });
    },
    { modalUrl: MODAL_URL, backupUrl: BACKUP_URL },
  );

  const accountMenuDialog = page.getByRole('dialog', { name: 'Wallet recovery codes' });
  await expect(accountMenuDialog.getByText('Could not load')).toBeVisible();
  await expect(
    accountMenuDialog.getByRole('button', { name: 'Close recovery codes' }),
  ).toBeFocused();
  await accountMenuDialog.getByRole('button', { name: 'View recovery codes' }).click();

  const backupDialog = page.getByRole('dialog', { name: 'Save your wallet recovery codes' });
  await expect(backupDialog.getByRole('listitem')).toHaveCount(10);
  await expect(backupDialog).toBeFocused();
});
