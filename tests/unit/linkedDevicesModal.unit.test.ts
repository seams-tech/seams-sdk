import { expect, test } from '@playwright/test';
import { injectImportMap } from '../setup/bootstrap';

const IMPORT_PATHS = {
  modal: '/_test-sdk/esm/react/components/AccountMenuButton/LinkedDevicesModal.js',
  context: '/_test-sdk/esm/react/context/index.js',
  theme: '/_test-sdk/esm/react/components/theme/ThemeProvider.js',
} as const;

const WALLET_ID = 'swift-sable-hgmrzh';

type DeviceState = 'provisioning' | 'active' | 'suspended' | 'expired' | 'revoked';

type DeviceFixture = {
  readonly deviceId: string;
  readonly enrollmentId: string;
  readonly walletId: string;
  readonly credential: {
    readonly kind: 'passkey';
    readonly walletAuthMethodId: string;
    readonly credentialIdB64u: string;
    readonly device: {
      readonly label: string;
      readonly browser: 'safari';
      readonly os: 'ios';
      readonly synced: true;
      readonly transports: readonly ['internal'];
      readonly provider: 'icloud-keychain';
      readonly providerLabel: 'iCloud Keychain';
    };
  };
  readonly permission: {
    readonly kind: 'owner_equivalent_signing';
    readonly administrationScope: 'signing_only';
    readonly localUserPresence: 'required';
  };
  readonly keyManifestDigestB64u: string;
  readonly coveredWalletKeys: readonly string[];
  readonly state: DeviceState;
  readonly createdAtMs: number;
  readonly lastActivityAtMs: number;
  readonly revocationEpoch: number;
};

function deviceFixture(
  deviceId: string,
  label: string,
  state: DeviceState,
  nowMs = Date.now(),
): DeviceFixture {
  return {
    deviceId,
    enrollmentId: `enrollment-${deviceId}`,
    walletId: WALLET_ID,
    credential: {
      kind: 'passkey',
      walletAuthMethodId: `passkey:wallet.example.localhost:credential-${deviceId}`,
      credentialIdB64u: `credential-${deviceId}`,
      device: {
        label,
        browser: 'safari',
        os: 'ios',
        synced: true,
        transports: ['internal'],
        provider: 'icloud-keychain',
        providerLabel: 'iCloud Keychain',
      },
    },
    permission: {
      kind: 'owner_equivalent_signing',
      administrationScope: 'signing_only',
      localUserPresence: 'required',
    },
    keyManifestDigestB64u: `manifest-${deviceId}`,
    coveredWalletKeys: [`wallet-key-${deviceId}`],
    state,
    createdAtMs: nowMs - 86_400_000,
    lastActivityAtMs: nowMs - 3_600_000,
    revocationEpoch: 0,
  };
}

async function renderModal(
  page: import('@playwright/test').Page,
  options: {
    readonly devices: readonly DeviceFixture[];
    readonly revokeOutcomes: readonly ('revoked' | 'not_found')[];
  },
): Promise<void> {
  await page.evaluate(
    async ({ paths, walletId, devices, revokeOutcomes }) => {
      const React = await import('react');
      const ReactDOMClient = await import('react-dom/client');
      const ReactDOM = await import('react-dom');
      const modalModule = await import(paths.modal);
      const contextModule = await import(paths.context);
      const themeModule = await import(paths.theme);
      const LinkedDevicesModal = modalModule.LinkedDevicesModal || modalModule.default;
      const Theme = themeModule.Theme;
      const SeamsContextProvider = contextModule.SeamsContextProvider;

      if (typeof LinkedDevicesModal !== 'function') {
        throw new Error('LinkedDevicesModal export missing');
      }
      if (typeof Theme !== 'function' || typeof SeamsContextProvider !== 'function') {
        throw new Error('React linked-device test providers are unavailable');
      }

      const controller = {
        devices: [...devices],
        revokeOutcomes: [...revokeOutcomes],
        revokeCalls: [] as string[],
      };

      const Harness: React.FC = () => {
        const { seams } = contextModule.useSeams();
        seams.devices.listLinkedDevices = async () => ({
          devices: controller.devices,
          nextCursor: null,
        });
        seams.devices.revokeLinkedDevice = async ({ deviceId }: { deviceId: string }) => {
          controller.revokeCalls.push(deviceId);
          const outcome = controller.revokeOutcomes.shift() ?? 'revoked';
          if (outcome === 'revoked') {
            controller.devices = controller.devices.filter(
              (device) => String(device.deviceId) !== deviceId,
            );
            return { kind: 'revoked' as const };
          }
          controller.devices = controller.devices.filter(
            (device) => String(device.deviceId) !== deviceId,
          );
          return { kind: 'not_found' as const };
        };
        return React.createElement(LinkedDevicesModal, {
          walletId,
          isOpen: true,
          onClose: () => undefined,
        });
      };

      const mount = document.createElement('div');
      document.getElementById('linked-devices-modal-test-root')?.remove();
      mount.id = 'linked-devices-modal-test-root';
      document.body.appendChild(mount);
      const root = ReactDOMClient.createRoot(mount);
      const config = {
        nearNetwork: 'testnet',
        nearRpcUrl: 'https://near.example.test',
        relayer: { url: 'https://router-api.example.test' },
        iframeWallet: { walletOrigin: 'https://wallet.example.localhost' },
      };
      ReactDOM.flushSync(() => {
        root.render(
          React.createElement(
            Theme,
            { theme: 'light' },
            React.createElement(SeamsContextProvider, { config }, React.createElement(Harness)),
          ),
        );
      });
    },
    {
      paths: IMPORT_PATHS,
      walletId: WALLET_ID,
      devices: options.devices,
      revokeOutcomes: options.revokeOutcomes,
    },
  );
}

test.describe('linked devices modal lifecycle', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('about:blank');
    await injectImportMap(page);
  });

  test('shows active and paused devices with remove actions and filters removed devices', async ({
    page,
  }) => {
    await renderModal(page, {
      devices: [
        deviceFixture('device-active', 'Phone passkey', 'active'),
        deviceFixture('device-paused', 'Laptop passkey', 'suspended'),
        deviceFixture('device-removed', 'Old passkey', 'revoked'),
      ],
      revokeOutcomes: [],
    });

    const dialog = page.getByRole('dialog', { name: 'Your devices' });
    await expect(dialog.getByText('Phone passkey')).toBeVisible();
    await expect(dialog.getByText('Laptop passkey')).toBeVisible();
    await expect(
      dialog.locator('.w3a-linked-devices-modal-item-name').filter({ hasText: 'Old passkey' }),
    ).toHaveCount(0);
    await expect(dialog.getByText('Can use this wallet', { exact: true })).toBeVisible();
    await expect(dialog.getByText('Paused', { exact: true })).toBeVisible();
    await expect(dialog.getByRole('button', { name: /Remove Phone passkey/ })).toBeVisible();
    await expect(dialog.getByRole('button', { name: /Remove Laptop passkey/ })).toBeVisible();
  });

  test('removes a device from the modal immediately and clears an already-gone error', async ({
    page,
  }) => {
    await renderModal(page, {
      devices: [deviceFixture('device-active', 'Phone passkey', 'active')],
      revokeOutcomes: ['revoked'],
    });

    const dialog = page.getByRole('dialog', { name: 'Your devices' });
    const removeButton = dialog.getByRole('button', { name: /Remove Phone passkey/ });
    await removeButton.click();
    await dialog.getByRole('button', { name: 'Yes, remove' }).click();
    await expect(
      dialog.locator('.w3a-linked-devices-modal-item-name').filter({ hasText: 'Phone passkey' }),
    ).toHaveCount(0);
    await expect(dialog.getByText('No other devices are using this wallet.')).toBeVisible();

    await renderModal(page, {
      devices: [deviceFixture('device-race', 'Race passkey', 'active')],
      revokeOutcomes: ['not_found'],
    });
    const raceDialog = page.getByRole('dialog', { name: 'Your devices' });
    await raceDialog.getByRole('button', { name: /Remove Race passkey/ }).click();
    await raceDialog.getByRole('button', { name: 'Yes, remove' }).click();
    await expect(
      raceDialog.locator('.w3a-linked-devices-modal-item-name').filter({ hasText: 'Race passkey' }),
    ).toHaveCount(0);
    await expect(raceDialog.getByRole('alert')).toHaveCount(0);
  });

  test('keeps the dialog usable in a narrow and short viewport', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 280 });
    await renderModal(page, {
      devices: [
        deviceFixture('device-active', 'Phone passkey', 'active'),
        deviceFixture('device-paused', 'Laptop passkey', 'suspended'),
      ],
      revokeOutcomes: [],
    });

    const dialog = page.getByRole('dialog', { name: 'Your devices' });
    await expect(dialog.getByText('Phone passkey')).toBeVisible();
    await expect(dialog.getByText('Laptop passkey')).toBeVisible();
    const geometry = await dialog.locator('.w3a-linked-devices-modal-body').evaluate((element) => {
      const rect = element.getBoundingClientRect();
      return {
        left: rect.left,
        right: rect.right,
        top: rect.top,
        bottom: rect.bottom,
        scrollable: element.scrollHeight > element.clientHeight,
      };
    });
    expect(geometry.left).toBeGreaterThanOrEqual(0);
    expect(geometry.right).toBeLessThanOrEqual(320);
    expect(geometry.top).toBeGreaterThanOrEqual(0);
    expect(geometry.bottom).toBeLessThanOrEqual(280);
    expect(geometry.scrollable).toBe(true);
  });
});
