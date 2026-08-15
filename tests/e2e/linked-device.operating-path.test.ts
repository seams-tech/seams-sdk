import {
  expect,
  test,
  type BrowserContext,
  type ConsoleMessage,
  type Frame,
  type Page,
  type Route,
} from '@playwright/test';

const enabled = process.env.SEAMS_LINKED_DEVICE_E2E === '1';
const appOrigin = String(process.env.SEAMS_LINKED_DEVICE_E2E_APP_URL || 'https://localhost')
  .trim()
  .replace(/\/+$/, '');
const nearStubBlockHash = '11111111111111111111111111111111';

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function nearRpcQueryResult(params: unknown): unknown {
  if (!isRecord(params)) return {};
  switch (params.request_type) {
    case 'view_access_key':
      return { nonce: 1, block_hash: nearStubBlockHash, permission: 'FullAccess' };
    case 'view_account':
      return {
        amount: '1000000000000000000000000',
        locked: '0',
        code_hash: nearStubBlockHash,
        storage_usage: 0,
        storage_paid_at: 0,
        block_height: 1,
        block_hash: nearStubBlockHash,
      };
    case 'call_function':
      return {
        result: Array.from(new TextEncoder().encode(JSON.stringify('Hello from local NEAR'))),
        logs: [],
        block_height: 1,
        block_hash: nearStubBlockHash,
      };
    default:
      return {};
  }
}

function nearRpcResult(method: string, params: unknown): unknown {
  switch (method) {
    case 'query':
      return nearRpcQueryResult(params);
    case 'block':
      return {
        author: 'linked-device-e2e',
        chunks: [],
        header: { hash: nearStubBlockHash, height: 1, prev_hash: nearStubBlockHash },
      };
    case 'send_tx':
      return {
        status: { SuccessValue: '' },
        transaction: { hash: 'linked-device-near-tx' },
        transaction_outcome: {
          id: 'linked-device-near-tx',
          outcome: { status: { SuccessValue: '' } },
        },
        receipts_outcome: [],
      };
    default:
      return {};
  }
}

async function fulfillNearRpc(route: Route): Promise<void> {
  const raw = route.request().postData() || '{}';
  const parsed: unknown = JSON.parse(raw);
  const request = isRecord(parsed) ? parsed : {};
  await route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: request.id ?? 'linked-device-near',
      result: nearRpcResult(String(request.method || ''), request.params),
    }),
  });
}

function linkedDeviceConsoleDiagnostic(message: ConsoleMessage): string | null {
  const text = message.text().replace(/\s+/g, ' ').trim().slice(0, 400);
  if (message.type() === 'error' || /camera|device linking|linked-device|qr|r102/i.test(text)) {
    return `[owner:${message.type()}] ${text}`;
  }
  return null;
}

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
  // Checked acknowledgement + the single close control completes the backup.
  await wallet.locator('[data-w3a-wallet-recovery-backup-close]').click();
}

async function registerOwner(page: Page, diagnostics: readonly string[]): Promise<void> {
  const wallet = await openWallet(page);
  const primary = wallet.locator('button[data-auth-menu-primary]');
  await primary.waitFor({ state: 'visible', timeout: 30_000 });
  await primary.click();
  try {
    await acknowledgeRecoveryCodeBackup(wallet);
  } catch (error) {
    throw new Error(`Owner registration did not reach recovery backup. ${diagnostics.join('\n')}`, {
      cause: error,
    });
  }
  await page
    .locator('.w3a-profile-button-morphable')
    .waitFor({ state: 'visible', timeout: 120_000 });
}

type QrCameraFrame = {
  readonly data: readonly number[];
  readonly height: number;
  readonly width: number;
};

async function decodeQrDataUrlInBrowser(dataUrl: string): Promise<QrCameraFrame> {
  const image = new Image();
  image.src = dataUrl;
  await image.decode();

  const canvas = document.createElement('canvas');
  canvas.width = image.naturalWidth;
  canvas.height = image.naturalHeight;
  const context = canvas.getContext('2d', { willReadFrequently: true });
  if (!context) throw new Error('Unable to decode linked-device QR image');
  context.drawImage(image, 0, 0);
  const pixels = context.getImageData(0, 0, canvas.width, canvas.height).data;
  return {
    data: [...pixels],
    height: canvas.height,
    width: canvas.width,
  };
}

async function installQrCameraRuntime(frame: QrCameraFrame): Promise<void> {
  const nativePlay = HTMLMediaElement.prototype.play;
  HTMLMediaElement.prototype.play = async function playStableMedia(): Promise<void> {
    try {
      await nativePlay.call(this);
    } catch (error) {
      if (!(error instanceof DOMException) || error.name !== 'AbortError') throw error;
    }
  };
  Object.defineProperty(HTMLMediaElement.prototype, 'readyState', {
    configurable: true,
    value: HTMLMediaElement.HAVE_ENOUGH_DATA,
  });
  Object.defineProperty(HTMLVideoElement.prototype, 'videoWidth', {
    configurable: true,
    value: frame.width,
  });
  Object.defineProperty(HTMLVideoElement.prototype, 'videoHeight', {
    configurable: true,
    value: frame.height,
  });

  const mediaDevices = navigator.mediaDevices;
  if (!mediaDevices) throw new Error('Device linking requires navigator.mediaDevices');
  Object.defineProperty(mediaDevices, 'enumerateDevices', {
    configurable: true,
    value: async () => [],
  });
  Object.defineProperty(mediaDevices, 'getUserMedia', {
    configurable: true,
    value: async () => {
      const canvas = document.createElement('canvas');
      canvas.width = frame.width;
      canvas.height = frame.height;
      const context = canvas.getContext('2d');
      if (!context) throw new Error('Unable to create linked-device QR camera canvas');
      context.imageSmoothingEnabled = false;
      context.putImageData(
        new ImageData(new Uint8ClampedArray(frame.data), frame.width, frame.height),
        0,
        0,
      );
      const qrFrame = context.getImageData(0, 0, canvas.width, canvas.height);
      function readQrFrame(): ImageData {
        return qrFrame;
      }
      Object.defineProperty(CanvasRenderingContext2D.prototype, 'getImageData', {
        configurable: true,
        value: readQrFrame,
      });
      Object.defineProperty(CanvasRenderingContext2D.prototype, 'drawImage', {
        configurable: true,
        value: context.clearRect.bind(context, 0, 0, 0, 0),
      });
      const stream = canvas.captureStream(4);
      return stream;
    },
  });
}

async function installQrCamera(page: Page, qrDataUrl: string): Promise<void> {
  const frame = await page.evaluate(decodeQrDataUrlInBrowser, qrDataUrl);
  await page.evaluate(installQrCameraRuntime, frame);
}

async function openDevice2Qr(page: Page): Promise<string> {
  const wallet = await openWallet(page);
  const linkButton = wallet.getByRole('button', { name: 'Scan and Link Device', exact: true });
  await linkButton.waitFor({ state: 'visible', timeout: 30_000 });
  await linkButton.click();
  const qr = wallet.locator('img[alt="Device Linking QR Code"]');
  try {
    await qr.waitFor({ state: 'visible', timeout: 60_000 });
  } catch (error) {
    const walletText = (await wallet.locator('body').innerText()).trim();
    throw new Error(`Device 2 QR did not become ready. Wallet state: ${walletText}`, {
      cause: error,
    });
  }
  const src = await qr.getAttribute('src');
  if (!src?.startsWith('data:image/')) throw new Error('Device 2 did not expose a QR data URL');
  return src;
}

async function openOwnerScanner(page: Page, qrDataUrl: string): Promise<void> {
  await installQrCamera(page, qrDataUrl);
  const profile = page.locator('.w3a-profile-button-morphable').getByRole('button').first();
  await profile.click();
  const menu = page.locator('.w3a-profile-dropdown-morphed[data-state="open"]');
  await menu.getByRole('button', { name: /^Scan and Link Device/ }).click();
  await page.locator('.qr-scanner-video').waitFor({ state: 'visible', timeout: 30_000 });
}

async function confirmWalletSigning(page: Page): Promise<void> {
  const iframe = page.locator('iframe[allow*="publickey-credentials-get"]').last();
  await iframe.waitFor({ state: 'attached', timeout: 60_000 });
  const frame = iframe.contentFrame();
  const confirm = frame
    .locator('#w3a-confirm-portal button.btn-confirm, #w3a-confirm-portal button.confirm')
    .first();
  await confirm.waitFor({ state: 'visible', timeout: 60_000 });
  await confirm.click();
}

async function linkedSigning(page: Page, diagnostics: readonly string[]): Promise<void> {
  const tempoTab = page.getByRole('tab', { name: 'Tempo', exact: true });
  try {
    await tempoTab.waitFor({ state: 'visible', timeout: 120_000 });
  } catch (error) {
    const wallet = await walletFrame(page);
    throw new Error(
      `Linked session was not projected to the host. Wallet state: ${(await wallet.locator('body').innerText()).trim()}\n${diagnostics.join('\n')}`,
      { cause: error },
    );
  }

  await tempoTab.click();
  const tempoFunding = page.getByRole('button', {
    name: /^(Fund Tempo Account|Tempo Account Funded)$/,
    exact: true,
  });
  await tempoFunding.waitFor({ state: 'visible', timeout: 60_000 });
  if ((await tempoFunding.textContent())?.trim() === 'Fund Tempo Account') {
    await expect(tempoFunding).toBeEnabled({ timeout: 120_000 });
    await tempoFunding.click();
    await confirmWalletSigning(page);
    await expect(tempoFunding).toBeEnabled({ timeout: 180_000 });
  }
  const tempoSign = page.getByRole('button', { name: 'Sign on Tempo', exact: true });
  await tempoSign.waitFor({ state: 'visible', timeout: 60_000 });
  await expect(tempoSign).toBeEnabled({ timeout: 120_000 });
  await tempoSign.click();
  await confirmWalletSigning(page);
  await expect(tempoSign).toBeEnabled({ timeout: 180_000 });

  const nearTab = page.getByRole('tab', { name: 'NEAR', exact: true });
  await nearTab.click();
  const sign = page.getByRole('button', { name: 'Sign on NEAR', exact: true });
  await sign.waitFor({ state: 'visible', timeout: 60_000 });
  await expect(sign).toBeEnabled();
  await sign.click();
  await expect(sign).toBeEnabled({ timeout: 180_000 });
}

function resolveContextCloseTimeout(resolve: () => void): void {
  globalThis.setTimeout(resolve, 5_000);
}

async function closeBrowserContexts(
  ownerContext: BrowserContext,
  device2Context: BrowserContext,
): Promise<void> {
  await Promise.race([
    Promise.allSettled([ownerContext.close(), device2Context.close()]),
    new Promise<void>(resolveContextCloseTimeout),
  ]);
}

test('Device 2 QR → Device 1 scan → Wallet Session → linked signing → revocation', async ({
  browser,
}) => {
  const ownerContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const device2Context = await browser.newContext({ ignoreHTTPSErrors: true });
  await device2Context.route(/https:\/\/[^/]*(?:near\.org|fastnear\.com)\//, fulfillNearRpc);
  const ownerPage = await ownerContext.newPage();
  const device2Page = await device2Context.newPage();
  const ownerDiagnostics: string[] = [];
  const device2Diagnostics: string[] = [];
  try {
    ownerPage.on('console', (message) => {
      const diagnostic = linkedDeviceConsoleDiagnostic(message);
      if (diagnostic) ownerDiagnostics.push(diagnostic);
    });
    device2Page.on('console', (message) => {
      const text = message.text().replace(/\s+/g, ' ').trim().slice(0, 400);
      if (message.type() === 'error' || /linked-device|WalletSession/i.test(text)) {
        device2Diagnostics.push(`[device2:${message.type()}] ${text}`);
      }
    });
    await addVirtualAuthenticator(ownerPage);
    await addVirtualAuthenticator(device2Page);
    await registerOwner(ownerPage, ownerDiagnostics);

    const created = device2Page.waitForResponse(
      (response) =>
        new URL(response.url()).pathname.endsWith('/wallet/device-linking/v1/sessions') &&
        response.request().method() === 'POST' &&
        response.status() === 200,
      { timeout: 120_000 },
    );
    const qrDataUrl = await openDevice2Qr(device2Page);
    await created;
    const activeWalletSession = device2Page
      .waitForResponse(
        (response) =>
          response.url().includes('/wallet/device-linking/v1/sessions/') &&
          response.url().endsWith('/wallet-session') &&
          response.status() === 200,
        { timeout: 90_000 },
      )
      .then(
        (response) => ({ kind: 'active' as const, response }),
        (error: unknown) => ({ error, kind: 'timeout' as const }),
      );
    const claimed = ownerPage
      .waitForResponse(
        (response) =>
          response.url().includes('/wallet/device-linking/v1/sessions/') &&
          response.url().endsWith('/claim') &&
          response.request().method() === 'POST',
        { timeout: 75_000 },
      )
      .then(
        (response) => ({ kind: 'claimed' as const, response }),
        (error: unknown) => ({ error, kind: 'timeout' as const }),
      );
    await openOwnerScanner(ownerPage, qrDataUrl);
    const claimResult = await claimed;
    if (claimResult.kind === 'timeout') {
      throw new Error(`Device 1 did not claim the linked session. ${ownerDiagnostics.join('\n')}`, {
        cause: claimResult.error,
      });
    }
    if (!claimResult.response.ok()) {
      throw new Error(`Device 1 claim failed (${claimResult.response.status()})`);
    }
    const walletSessionResult = await activeWalletSession;
    if (walletSessionResult.kind === 'timeout') {
      const device2Wallet = await walletFrame(device2Page);
      const walletState = (await device2Wallet.locator('body').innerText()).trim();
      throw new Error(
        `Device 2 did not receive an active Wallet Session. Wallet state: ${walletState}\n${ownerDiagnostics.join('\n')}`,
        { cause: walletSessionResult.error },
      );
    }
    const device2Wallet = await walletFrame(device2Page);
    await device2Wallet.getByText('Linked device active', { exact: true }).waitFor({
      state: 'visible',
      timeout: 180_000,
    });
    const linkedSigningRequests: Array<{ pathname: string; body: unknown }> = [];
    device2Page.on('request', (request) => {
      const pathname = new URL(request.url()).pathname;
      if (!pathname.includes('/router-ab/')) return;
      linkedSigningRequests.push({ pathname, body: request.postDataJSON() });
    });
    await linkedSigning(device2Page, device2Diagnostics);
    const linkedPaths = linkedSigningRequests.map((request) => request.pathname);
    if (linkedPaths.length === 0) {
      throw new Error(
        `Linked signing emitted no Router A/B requests. ${device2Diagnostics.join('\n')}`,
      );
    }
    expect(linkedPaths).toContain('/router-ab/ecdsa-derivation/linked-device/presign/init');
    expect(linkedPaths).toContain('/router-ab/ecdsa-derivation/linked-device/presign/step');
    expect(linkedPaths).toContain('/router-ab/ecdsa-derivation/sign');
    expect(linkedPaths).toContain('/router-ab/ed25519/sign/prepare');
    expect(linkedPaths).toContain('/router-ab/ed25519/sign');
    expect(linkedPaths).not.toContain('/router-ab/ecdsa-derivation/sign/prepare');
    for (const request of linkedSigningRequests) {
      if (
        request.pathname === '/router-ab/ecdsa-derivation/linked-device/presign/init' ||
        request.pathname === '/router-ab/ed25519/sign/prepare'
      ) {
        expect(request.body).toEqual(
          expect.objectContaining({
            linkedDeviceExecution: expect.objectContaining({ enrollmentId: expect.any(String) }),
            localPresenceAssertion: expect.objectContaining({ kind: expect.any(String) }),
          }),
        );
      }
    }

    await ownerPage.locator('.w3a-profile-button-morphable').getByRole('button').first().click();
    const profileMenu = ownerPage.locator('.w3a-profile-dropdown-morphed[data-state="open"]');
    await profileMenu.getByRole('button', { name: /^Linked Devices/ }).click();
    await ownerPage
      .locator('.w3a-linked-devices-row')
      .waitFor({ state: 'visible', timeout: 60_000 });
    ownerPage.once('dialog', (dialog) => void dialog.accept());
    await ownerPage.getByRole('button', { name: 'Revoke device', exact: true }).click();
    await expect(ownerPage.getByRole('button', { name: 'Revoked', exact: true })).toBeVisible({
      timeout: 60_000,
    });
  } finally {
    await closeBrowserContexts(ownerContext, device2Context);
  }
});
