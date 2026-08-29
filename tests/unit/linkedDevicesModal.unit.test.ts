import { expect, test } from '@playwright/test';
import { parseWalletAuthMethodId } from '@shared/utils/domainIds';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import {
  buildEmailOtpWalletAuthMethodBinding,
  buildPasskeyAuthScope,
  buildPasskeyWalletAuthMethodBinding,
  buildWalletIdentity,
  parseRpId,
  type WalletAuthMethodBinding,
} from '@shared/utils/walletCapabilityBindings';
import { injectImportMap } from '../setup/bootstrap';
import { activeWalletSessionFixture } from './helpers/walletSessionReadProjection.fixtures';

const IMPORT_PATHS = {
  modal: '/_test-sdk/esm/react/components/AccountMenuButton/LinkedDevicesModal.js',
  authenticationModal:
    '/_test-sdk/esm/react/components/AccountMenuButton/AuthenticationMethodsModal.js',
  loginStateBuilders: '/_test-sdk/esm/react/context/reactLoginStateBuilders.js',
  theme: '/_test-sdk/esm/react/components/theme/ThemeProvider.js',
} as const;

const WALLET_ID = 'swift-sable-hgmrzh';
const WALLET_AUTHORITY_ID = 'wallet-authority-owner';
const TEST_CONTEXT_ROUTE = '**/_test-sdk/esm/react/context/index.js';

type DeviceState = 'provisioning' | 'active' | 'suspended' | 'expired' | 'revoked';

type DeviceFixture = {
  readonly deviceId: string;
  readonly enrollmentId: string;
  readonly walletId: string;
  readonly credential:
    | {
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
      }
    | {
        readonly kind: 'email_otp';
        readonly walletAuthMethodId: string;
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

function emailOtpDeviceFixture(deviceId: string, state: DeviceState): DeviceFixture {
  return {
    ...deviceFixture(deviceId, 'unused', state),
    credential: {
      kind: 'email_otp',
      walletAuthMethodId: `email_otp:${WALLET_ID}:${'b'.repeat(64)}`,
    },
  };
}

type OwnerDeviceFixture = {
  readonly walletId: string;
  readonly walletAuthorityId: string;
  readonly credential: DeviceFixture['credential'];
  readonly createdAtMs: number;
  readonly lastActivityAtMs: number;
};

/** A founding owner passkey; created before every linked fixture so it sorts first. */
function ownerDeviceFixture(label: string, nowMs = Date.now()): OwnerDeviceFixture {
  return {
    walletId: WALLET_ID,
    walletAuthorityId: WALLET_AUTHORITY_ID,
    credential: {
      kind: 'passkey',
      walletAuthMethodId: `passkey:wallet.example.localhost:credential-owner`,
      credentialIdB64u: 'credential-owner',
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
    createdAtMs: nowMs - 2 * 86_400_000,
    lastActivityAtMs: nowMs - 3_600_000,
  };
}

function ownerEmailOtpDeviceFixture(nowMs = Date.now()): OwnerDeviceFixture {
  return {
    walletId: WALLET_ID,
    walletAuthorityId: WALLET_AUTHORITY_ID,
    credential: {
      kind: 'email_otp',
      walletAuthMethodId: `email_otp:${WALLET_ID}:${'b'.repeat(64)}`,
    },
    createdAtMs: nowMs - 86_400_000,
    lastActivityAtMs: nowMs - 1_800_000,
  };
}

function requireWalletAuthMethodId(value: string) {
  const parsed = parseWalletAuthMethodId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function ownerAuthMethodBinding(owner: OwnerDeviceFixture): WalletAuthMethodBinding {
  const wallet = buildWalletIdentity({ walletId: walletIdFromString(owner.walletId) });
  const walletAuthMethodId = requireWalletAuthMethodId(owner.credential.walletAuthMethodId);
  if (owner.credential.kind === 'email_otp') {
    return buildEmailOtpWalletAuthMethodBinding({
      walletAuthMethodId,
      wallet,
      emailHashHex: 'b'.repeat(64),
      registrationAuthorityId: owner.walletAuthorityId,
    });
  }
  const rpId = parseRpId('wallet.example.localhost');
  if (!rpId.ok) throw new Error(rpId.error.message);
  return buildPasskeyWalletAuthMethodBinding({
    walletAuthMethodId,
    scope: buildPasskeyAuthScope({ wallet, rpId: rpId.value }),
    credentialIdB64u: owner.credential.credentialIdB64u,
  });
}

function selectedOwnerSessionFixture(
  ownerDevices: readonly OwnerDeviceFixture[],
  authMethod: 'passkey' | 'email_otp',
) {
  return activeWalletSessionFixture({
    walletId: WALLET_ID,
    authMethod,
    authMethods: ownerDevices.map(ownerAuthMethodBinding),
  });
}

async function renderModal(
  page: import('@playwright/test').Page,
  options: {
    readonly component?: 'linked_devices' | 'authentication_methods';
    readonly devices: readonly DeviceFixture[];
    readonly ownerDevices?: readonly OwnerDeviceFixture[];
    readonly revokeOutcomes: readonly ('revoked' | 'not_found')[];
    readonly loadError?: string;
    readonly session?: ReturnType<typeof activeWalletSessionFixture>;
  },
): Promise<void> {
  await page.evaluate(
    async ({
      paths,
      walletId,
      devices,
      ownerDevices,
      revokeOutcomes,
      loadError,
      session,
      component,
    }) => {
      const React = await import('react');
      const ReactDOMClient = await import('react-dom/client');
      const ReactDOM = await import('react-dom');
      const modalModule = await import(paths.modal);
      const loginStateBuilders = await import(paths.loginStateBuilders);
      const themeModule = await import(paths.theme);
      const LinkedDevicesModal = modalModule.LinkedDevicesModal || modalModule.default;
      let Modal = LinkedDevicesModal;
      if (component === 'authentication_methods') {
        const authenticationModalModule = await import(paths.authenticationModal);
        Modal =
          authenticationModalModule.AuthenticationMethodsModal || authenticationModalModule.default;
      }
      const Theme = themeModule.Theme;

      if (typeof Modal !== 'function') {
        throw new Error('Account-menu modal export missing');
      }
      if (typeof Theme !== 'function') {
        throw new Error('React linked-device test theme is unavailable');
      }

      const controller = {
        devices: [...devices],
        ownerDevices: [...(ownerDevices ?? [])],
        revokeOutcomes: [...revokeOutcomes],
        loadError,
        revokeCalls: [] as Array<{ walletAuthMethodId: string; proofKind: string }>,
      };

      const seams = {
        configs: {
          wallet: { iframe: { rpIdOverride: 'wallet.example.localhost' } },
        },
        devices: {
          listLinkedDevices: async () => {
            if (controller.loadError) throw new Error(controller.loadError);
            return {
              devices: controller.devices,
              ownerDevices: controller.ownerDevices,
              nextCursor: null,
            };
          },
          revokeLinkedDevice: async ({
            walletAuthMethodId,
            sourceProof,
          }: {
            walletAuthMethodId: string;
            sourceProof: { kind: string };
          }) => {
            controller.revokeCalls.push({ walletAuthMethodId, proofKind: sourceProof.kind });
            const outcome = controller.revokeOutcomes.shift() ?? 'revoked';
            controller.devices = controller.devices.filter(
              (device) => String(device.credential.walletAuthMethodId) !== walletAuthMethodId,
            );
            controller.ownerDevices = controller.ownerDevices.filter(
              (device) => String(device.credential.walletAuthMethodId) !== walletAuthMethodId,
            );
            return { kind: outcome };
          },
        },
      };
      const loginState = session
        ? loginStateBuilders.buildReactLoggedInLoginStateFromSession(session)
        : loginStateBuilders.buildReactLoggedOutLoginState();
      if (!loginState) throw new Error('Linked-device test session did not project to login state');
      (
        globalThis as typeof globalThis & { __linkedDevicesModalTestContext?: unknown }
      ).__linkedDevicesModalTestContext = {
        seams,
        loginState,
        refreshLoginState: async () => undefined,
      };

      const Harness: React.FC = () => {
        return React.createElement(Modal, {
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
      ReactDOM.flushSync(() => {
        root.render(React.createElement(Theme, { theme: 'light' }, React.createElement(Harness)));
      });
    },
    {
      paths: IMPORT_PATHS,
      walletId: WALLET_ID,
      devices: options.devices,
      ownerDevices: options.ownerDevices ?? [],
      revokeOutcomes: options.revokeOutcomes,
      loadError: options.loadError,
      session: options.session,
      component: options.component ?? 'linked_devices',
    },
  );
}

test.describe('linked devices modal lifecycle', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('about:blank');
    await injectImportMap(page);
    await page.context().route(TEST_CONTEXT_ROUTE, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/javascript',
        body: [
          'export function useSeams() {',
          '  const value = globalThis.__linkedDevicesModalTestContext;',
          '  if (!value) throw new Error("Linked-device test context is unavailable");',
          '  return value;',
          '}',
        ].join('\n'),
      });
    });
  });

  test('uses a quick opacity-only entrance with the recovery modal backdrop', async ({ page }) => {
    const components = [
      { kind: 'authentication_methods' as const, name: 'Authentication methods' },
      { kind: 'linked_devices' as const, name: 'Your devices' },
    ];

    for (const component of components) {
      await renderModal(page, {
        component: component.kind,
        devices: [],
        revokeOutcomes: [],
      });

      const dialog = page.getByRole('dialog', { name: component.name });
      await expect(dialog).toBeVisible();
      const styles = await dialog.evaluate((element) => {
        const content = getComputedStyle(element);
        const backdropElement = element.parentElement;
        if (!backdropElement) throw new Error('Modal backdrop missing');
        const backdrop = getComputedStyle(backdropElement);
        return {
          backdropColor: backdrop.backgroundColor,
          backdropFilter: backdrop.backdropFilter,
          backdropAnimationDuration: backdrop.animationDuration,
          contentAnimationDuration: content.animationDuration,
          contentBorderStyle: content.borderStyle,
          contentTransform: content.transform,
        };
      });

      expect(styles).toEqual({
        backdropColor: 'rgba(0, 0, 0, 0.26)',
        backdropFilter: 'none',
        backdropAnimationDuration: '0.08s',
        contentAnimationDuration: '0.08s',
        contentBorderStyle: 'none',
        contentTransform: 'none',
      });
    }
  });

  test('offers the missing family for the selected authority', async ({ page }) => {
    const passkeyOwner = ownerDeviceFixture('Original passkey');
    await renderModal(page, {
      component: 'authentication_methods',
      ownerDevices: [passkeyOwner],
      devices: [],
      revokeOutcomes: [],
      session: selectedOwnerSessionFixture([passkeyOwner], 'passkey'),
    });

    const dialog = page.getByRole('dialog', { name: 'Authentication methods' });
    await expect(dialog.getByRole('heading', { name: 'Add Email OTP' })).toBeVisible();
    await expect(dialog.getByRole('button', { name: 'Add Email OTP' })).toBeVisible();
  });

  test('hides the add action once both families are active on the selected authority', async ({
    page,
  }) => {
    const passkeyOwner = ownerDeviceFixture('Original passkey');
    const emailOtpOwner = ownerEmailOtpDeviceFixture();
    const ownerDevices = [passkeyOwner, emailOtpOwner];
    await renderModal(page, {
      component: 'authentication_methods',
      ownerDevices,
      devices: [],
      revokeOutcomes: [],
      session: selectedOwnerSessionFixture(ownerDevices, 'passkey'),
    });

    const dialog = page.getByRole('dialog', { name: 'Authentication methods' });
    await expect(dialog.getByText('Passkey', { exact: true })).toBeVisible();
    await expect(dialog.getByText('Email OTP', { exact: true })).toBeVisible();
    await expect(dialog.getByRole('heading', { name: 'Add Passkey' })).toHaveCount(0);
    await expect(dialog.getByRole('heading', { name: 'Add Email OTP' })).toHaveCount(0);
  });

  test('shows active and paused devices with remove actions and filters removed devices', async ({
    page,
  }) => {
    await renderModal(page, {
      devices: [
        deviceFixture('device-active', 'Phone passkey', 'active'),
        deviceFixture('device-paused', 'Laptop passkey', 'suspended'),
        emailOtpDeviceFixture('device-email', 'active'),
        deviceFixture('device-removed', 'Old passkey', 'revoked'),
      ],
      revokeOutcomes: [],
    });

    const dialog = page.getByRole('dialog', { name: 'Your devices' });
    const names = dialog.locator('.w3a-linked-devices-modal-item-name');
    await expect(names.filter({ hasText: 'Phone passkey' })).toBeVisible();
    await expect(names.filter({ hasText: 'Email code' })).toBeVisible();
    await expect(names.filter({ hasText: 'Laptop passkey' })).toBeVisible();
    await expect(names.filter({ hasText: 'Old passkey' })).toHaveCount(0);
    await expect(
      dialog.locator('.w3a-linked-devices-modal-item[data-device-state="active"]'),
    ).toHaveCount(2);
    /* Healthy devices carry no chip; only interesting lifecycle states do. */
    await expect(dialog.locator('.w3a-linked-devices-modal-standing')).toHaveCount(1);
    await expect(dialog.getByText('Paused', { exact: true })).toBeVisible();
    await expect(
      dialog.getByRole('button', { name: /Remove Device 1, Phone passkey/ }),
    ).toBeVisible();
    await expect(
      dialog.getByRole('button', { name: /Remove Device 3, Laptop passkey/ }),
    ).toBeVisible();
  });

  test('lists the founding owner first and exposes exact sibling removal', async ({ page }) => {
    await renderModal(page, {
      ownerDevices: [ownerDeviceFixture('Original passkey')],
      devices: [deviceFixture('device-linked', 'Linked passkey', 'active')],
      revokeOutcomes: [],
    });

    const dialog = page.getByRole('dialog', { name: 'Your devices' });
    const names = dialog.locator('.w3a-linked-devices-modal-item-name');
    await expect(names.first()).toHaveText('Original passkey');
    await expect(names.nth(1)).toHaveText('Linked passkey');
    await expect(
      dialog.locator('.w3a-linked-devices-modal-item[data-device-kind="owner"]'),
    ).toHaveCount(1);
    await expect(
      dialog.locator(
        '.w3a-linked-devices-modal-item[data-device-kind="linked"][data-device-state="active"]',
      ),
    ).toHaveCount(1);
    await expect(dialog.getByText(/These devices can use this wallet/)).toHaveCount(0);
    await expect(dialog.getByText(/manage it from that device/)).toHaveCount(0);
    await expect(
      dialog.getByRole('button', { name: /Remove Device 1, Original passkey/ }),
    ).toBeVisible();
    await expect(
      dialog.getByRole('button', { name: /Remove Device 2, Linked passkey/ }),
    ).toBeVisible();
  });

  test('marks the signed-in method and explains removal in plain language', async ({ page }) => {
    const passkeyOwner = ownerDeviceFixture('Original passkey');
    const emailOtpOwner = ownerEmailOtpDeviceFixture();
    const ownerDevices = [passkeyOwner, emailOtpOwner];
    await renderModal(page, {
      ownerDevices,
      devices: [],
      revokeOutcomes: [],
      session: selectedOwnerSessionFixture(ownerDevices, 'passkey'),
    });

    const dialog = page.getByRole('dialog', { name: 'Your devices' });
    await expect(dialog.getByText('Anything listed here can unlock this wallet.')).toBeVisible();
    await expect(dialog.getByText('In use now', { exact: true })).toHaveCount(1);
    await expect(
      dialog.getByText(
        "You're signed in with this passkey. To remove it, sign in with your email code first.",
      ),
    ).toBeVisible();
    /* The signed-in method offers no Remove button; the sibling does. */
    await expect(
      dialog.getByRole('button', { name: /Remove Device 1, Original passkey/ }),
    ).toHaveCount(0);
    await expect(dialog.getByRole('button', { name: /Remove Device 2, Email code/ })).toBeVisible();
  });

  test('does not offer removal for the final wallet method', async ({ page }) => {
    await renderModal(page, {
      ownerDevices: [ownerDeviceFixture('Only passkey')],
      devices: [],
      revokeOutcomes: [],
    });

    const dialog = page.getByRole('dialog', { name: 'Your devices' });
    await expect(
      dialog.locator('.w3a-linked-devices-modal-item-name').filter({ hasText: 'Only passkey' }),
    ).toBeVisible();
    await expect(dialog.getByRole('button', { name: /Remove Device 1/ })).toHaveCount(0);
  });

  test('surfaces linked-device loading failures in the dialog', async ({ page }) => {
    await renderModal(page, {
      devices: [],
      revokeOutcomes: [],
      loadError: 'linked-device list linked devices failed with HTTP 500: projection unavailable',
    });

    const dialog = page.getByRole('dialog', { name: 'Your devices' });
    const alert = dialog.getByRole('alert');
    await expect(alert).toContainText(
      'Unable to load your devices: linked-device list linked devices failed with HTTP 500: projection unavailable',
    );
    await expect(alert.getByRole('button', { name: 'Try again' })).toBeVisible();
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
