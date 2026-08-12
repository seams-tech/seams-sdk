import { expect, test, type Frame, type Page } from '@playwright/test';

const enabled = process.env.SEAMS_LINKED_DEVICE_E2E === '1';
const appOrigin = String(process.env.SEAMS_LINKED_DEVICE_E2E_APP_URL || 'https://localhost')
  .trim()
  .replace(/\/+$/, '');

test.skip(!enabled, 'Set SEAMS_LINKED_DEVICE_E2E=1 with a composed linked-device backend');
test.setTimeout(420_000);

async function addVirtualAuthenticator(page: Page): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      hasPrf: true,
      automaticPresenceSimulation: true,
    },
  });
}

async function walletFrame(page: Page): Promise<Frame> {
  const iframe = page.locator('iframe[src*="/wallet-service"]');
  await iframe.waitFor({ state: 'attached', timeout: 30_000 });
  const frame = await iframe.contentFrame();
  if (!frame) throw new Error('Wallet service iframe is unavailable');
  return frame;
}

async function openWallet(page: Page): Promise<Frame> {
  await page.goto(`${appOrigin}/wallet`, { waitUntil: 'domcontentloaded' });
  return walletFrame(page);
}

async function acknowledgeRecoveryCodeBackup(wallet: Frame): Promise<void> {
  const acknowledgement = wallet.locator('[data-w3a-wallet-recovery-backup-acknowledgement]');
  await acknowledgement.waitFor({ state: 'visible', timeout: 120_000 });
  await acknowledgement.check();
  await wallet.getByRole('button', { name: 'Finish backup', exact: true }).click();
}

async function registerOwner(page: Page): Promise<void> {
  const wallet = await openWallet(page);
  const primary = wallet.locator('button[data-auth-menu-primary]');
  await primary.waitFor({ state: 'visible', timeout: 30_000 });
  await primary.click();
  await acknowledgeRecoveryCodeBackup(wallet);
  await page
    .locator('.w3a-profile-button-morphable')
    .waitFor({ state: 'visible', timeout: 120_000 });
}

async function installQrCamera(wallet: Frame, qrDataUrl: string): Promise<void> {
  await wallet.evaluate(async (dataUrl) => {
    const mediaDevices = navigator.mediaDevices;
    if (!mediaDevices) throw new Error('Device linking requires navigator.mediaDevices');
    Object.defineProperty(mediaDevices, 'enumerateDevices', {
      configurable: true,
      value: async () => [
        {
          deviceId: 'seams-linked-device-camera',
          groupId: 'seams-linked-device-camera',
          kind: 'videoinput',
          label: 'Seams linked-device camera',
          toJSON() {
            return this;
          },
        },
      ],
    });
    Object.defineProperty(mediaDevices, 'getUserMedia', {
      configurable: true,
      value: async () => {
        const canvas = document.createElement('canvas');
        canvas.width = 1024;
        canvas.height = 1024;
        const context = canvas.getContext('2d');
        if (!context) throw new Error('Unable to create linked-device QR camera canvas');
        context.fillStyle = '#fff';
        context.fillRect(0, 0, canvas.width, canvas.height);
        const image = new Image();
        image.onload = () => context.drawImage(image, 0, 0, canvas.width, canvas.height);
        image.src = dataUrl;
        return canvas.captureStream(30);
      },
    });
  }, qrDataUrl);
}

async function openDevice2Qr(page: Page): Promise<string> {
  const wallet = await openWallet(page);
  const linkButton = wallet.getByRole('button', { name: 'Scan and Link Device', exact: true });
  await linkButton.waitFor({ state: 'visible', timeout: 30_000 });
  await linkButton.click();
  const qr = wallet.locator('img[alt="Device Linking QR Code"]');
  await qr.waitFor({ state: 'visible', timeout: 60_000 });
  const src = await qr.getAttribute('src');
  if (!src?.startsWith('data:image/')) throw new Error('Device 2 did not expose a QR data URL');
  return src;
}

async function openOwnerScanner(page: Page, qrDataUrl: string): Promise<void> {
  await installQrCamera(page, qrDataUrl);
  const profile = page.locator('.w3a-profile-button-morphable').getByRole('button').first();
  await profile.click();
  const menu = page.locator('.w3a-profile-dropdown-morphed[data-state="open"]');
  await menu.getByRole('button', { name: 'Scan and Link Device', exact: true }).click();
  await page.locator('.qr-scanner-video').waitFor({ state: 'visible', timeout: 30_000 });
}

async function linkedSigning(page: Page): Promise<void> {
  await openWallet(page);
  const primary = page.locator('button[data-auth-menu-primary]');
  if (await primary.isVisible().catch(() => false)) await primary.click();
  await page.locator('.demo-page').waitFor({ state: 'visible', timeout: 120_000 });
  const nearTab = page.getByRole('tab', { name: 'NEAR', exact: true });
  if (await nearTab.isVisible().catch(() => false)) await nearTab.click();
  const sign = page.getByRole('button', { name: 'Sign on NEAR', exact: true });
  await sign.waitFor({ state: 'visible', timeout: 60_000 });
  await expect(sign).toBeEnabled();
  await sign.click();
  await expect(page.getByText(/transaction (complete|finalized)/i).first()).toBeVisible({
    timeout: 120_000,
  });
}

test('Device 2 QR → Device 1 scan → Wallet Session → linked signing → revocation', async ({
  browser,
}) => {
  const ownerContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const device2Context = await browser.newContext({ ignoreHTTPSErrors: true });
  const ownerPage = await ownerContext.newPage();
  const device2Page = await device2Context.newPage();
  try {
    await addVirtualAuthenticator(ownerPage);
    await addVirtualAuthenticator(device2Page);
    await registerOwner(ownerPage);

    const created = device2Page.waitForResponse(
      (response) =>
        new URL(response.url()).pathname.endsWith('/wallet/device-linking/v1/sessions') &&
        response.request().method() === 'POST' &&
        response.status() === 200,
      { timeout: 120_000 },
    );
    const qrDataUrl = await openDevice2Qr(device2Page);
    await created;
    const activeWalletSession = device2Page.waitForResponse(
      (response) =>
        response.url().includes('/wallet/device-linking/v1/sessions/') &&
        response.url().endsWith('/wallet-session') &&
        response.status() === 200,
      { timeout: 180_000 },
    );
    const claimed = ownerPage.waitForResponse(
      (response) =>
        response.url().includes('/wallet/device-linking/v1/sessions/') &&
        response.url().endsWith('/claim') &&
        response.request().method() === 'POST',
      { timeout: 120_000 },
    );
    await openOwnerScanner(ownerPage, qrDataUrl);
    await claimed;
    await activeWalletSession;
    const device2Wallet = await walletFrame(device2Page);
    await device2Wallet.getByText('Linked device active', { exact: true }).waitFor({
      state: 'visible',
      timeout: 180_000,
    });

    await linkedSigning(device2Page);

    await ownerPage.locator('.w3a-profile-button-morphable').getByRole('button').first().click();
    const profileMenu = ownerPage.locator('.w3a-profile-dropdown-morphed[data-state="open"]');
    await profileMenu.getByRole('button', { name: 'Linked Devices', exact: true }).click();
    await ownerPage
      .locator('.w3a-linked-devices-row')
      .waitFor({ state: 'visible', timeout: 60_000 });
    ownerPage.once('dialog', (dialog) => void dialog.accept());
    await ownerPage.getByRole('button', { name: 'Revoke device', exact: true }).click();
    await expect(ownerPage.getByRole('button', { name: 'Revoked', exact: true })).toBeVisible({
      timeout: 60_000,
    });
  } finally {
    await ownerContext.close();
    await device2Context.close();
  }
});
