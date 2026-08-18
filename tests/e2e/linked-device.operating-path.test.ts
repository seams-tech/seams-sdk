import {
  expect,
  test,
  type BrowserContext,
  type CDPSession,
  type ConsoleMessage,
  type FrameLocator,
  type Locator,
  type Page,
  type Response,
  type Route,
} from '@playwright/test';

const enabled = process.env.SEAMS_LINKED_DEVICE_E2E === '1';
const appOrigin = String(
  process.env.SEAMS_LINKED_DEVICE_E2E_APP_URL ||
    process.env.SEAMS_INTENDED_APP_URL ||
    'https://localhost',
)
  .trim()
  .replace(/\/+$/, '');
const nearStubBlockHash = '11111111111111111111111111111111';
const arcStubBlockHash = `0x${'11'.repeat(32)}`;
const arcStubTransactionHash = `0x${'22'.repeat(32)}`;
const arcGreetingContract = '0xeB7aB5A6F761072C96147A54B8a15F012e836691';
const arcState = {
  greeting: 'Hello from local Arc',
  pendingGreeting: 'Hello from linked Arc',
  transactionInput: '0x',
};

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

function utf8Hex(value: string): string {
  return Array.from(new TextEncoder().encode(value), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('');
}

function encodeArcGreetingResult(value: string): `0x${string}` {
  const valueHex = utf8Hex(value);
  const paddedValueHex = valueHex.padEnd(Math.ceil(valueHex.length / 64) * 64, '0');
  return `0x${(32).toString(16).padStart(64, '0')}${(valueHex.length / 2)
    .toString(16)
    .padStart(64, '0')}${paddedValueHex}`;
}

function encodeArcSetGreetingInput(value: string): `0x${string}` {
  return `0xa4136862${encodeArcGreetingResult(value).slice(2)}`;
}

function arcRpcResult(method: string): unknown {
  switch (method) {
    case 'eth_call':
      return encodeArcGreetingResult(arcState.greeting);
    case 'eth_chainId':
      return `0x${(5_042_002).toString(16)}`;
    case 'eth_getBalance':
      return '0x3635c9adc5dea00000';
    case 'eth_getTransactionCount':
      return '0x0';
    case 'eth_blockNumber':
      return '0x10';
    case 'eth_getBlockByNumber':
      return {
        number: '0x10',
        hash: arcStubBlockHash,
        baseFeePerGas: '0x3b9aca00',
      };
    case 'eth_maxPriorityFeePerGas':
    case 'eth_gasPrice':
      return '0x3b9aca00';
    case 'eth_sendRawTransaction':
      arcState.greeting = arcState.pendingGreeting;
      return arcStubTransactionHash;
    case 'eth_getTransactionReceipt':
      return {
        transactionHash: arcStubTransactionHash,
        transactionIndex: '0x0',
        blockHash: arcStubBlockHash,
        blockNumber: '0x10',
        from: '0x1111111111111111111111111111111111111111',
        to: arcGreetingContract,
        cumulativeGasUsed: '0x30d40',
        gasUsed: '0x30d40',
        effectiveGasPrice: '0x3b9aca00',
        contractAddress: null,
        logs: [],
        logsBloom: `0x${'00'.repeat(256)}`,
        status: '0x1',
        type: '0x2',
      };
    case 'eth_getTransactionByHash':
      return {
        hash: arcStubTransactionHash,
        nonce: '0x0',
        blockHash: arcStubBlockHash,
        blockNumber: '0x10',
        transactionIndex: '0x0',
        from: '0x1111111111111111111111111111111111111111',
        to: arcGreetingContract,
        value: '0x0',
        gas: '0x30d40',
        maxFeePerGas: '0x9502f9000',
        maxPriorityFeePerGas: '0x77359400',
        input: arcState.transactionInput,
        type: '0x2',
      };
    default:
      return null;
  }
}

async function fulfillArcRpc(route: Route): Promise<void> {
  const raw = route.request().postData() || '{}';
  const parsed: unknown = JSON.parse(raw);
  const request = isRecord(parsed) ? parsed : {};
  const method = String(request.method || '');
  const result = arcRpcResult(method);
  await route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: request.id ?? 'linked-device-arc',
      ...(result === null
        ? { error: { code: -32601, message: `Unsupported Arc RPC method: ${method}` } }
        : { result }),
    }),
  });
}

function linkedDeviceConsoleDiagnostic(message: ConsoleMessage): string | null {
  const text = message.text().replace(/\s+/g, ' ').trim().slice(0, 400);
  if (
    message.type() === 'error' ||
    /camera|custody|device linking|linked-device|qr|r102/i.test(text)
  ) {
    return `[owner:${message.type()}] ${text}`;
  }
  return null;
}

test.skip(!enabled, 'Set SEAMS_LINKED_DEVICE_E2E=1 with a composed linked-device backend');
// Registration, linking, five signing operations, a step-up retry, a refresh,
// and a lock/unlock cycle all run in one contract against live local services.
test.setTimeout(900_000);

async function addVirtualAuthenticator(page: Page): Promise<CDPSession> {
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
  return cdp;
}

async function walletFrame(page: Page): Promise<FrameLocator> {
  const iframe = page.locator('iframe[src*="/wallet-service"]');
  await iframe.waitFor({ state: 'attached', timeout: 30_000 });
  const frame = await iframe.contentFrame();
  if (!frame) throw new Error('Wallet service iframe is unavailable');
  return frame;
}

async function openWallet(page: Page): Promise<FrameLocator> {
  await page.goto(`${appOrigin}/wallet`, { waitUntil: 'domcontentloaded' });
  return walletFrame(page);
}

async function registerOwner(page: Page, diagnostics: readonly string[]): Promise<void> {
  const wallet = await openWallet(page);
  const primary = wallet.locator('button[data-auth-menu-primary]');
  await primary.waitFor({ state: 'visible', timeout: 30_000 });
  await primary.click();
  try {
    await page
      .locator('.w3a-profile-button-morphable')
      .waitFor({ state: 'visible', timeout: 120_000 });
  } catch (error) {
    throw new Error(`Owner registration did not complete. ${diagnostics.join('\n')}`, {
      cause: error,
    });
  }
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
  const qr = wallet.locator('img[alt="QR code to link this device"]');
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

const LINKED_DEVICE_PROFILE_ROWS = [
  'Export Keys',
  'Scan and Link Device',
  'Linked Devices',
] as const;

async function openProfileMenu(page: Page): Promise<Locator> {
  const profile = page.locator('.w3a-profile-button-morphable');
  await profile.waitFor({ state: 'visible', timeout: 30_000 });
  if ((await profile.getAttribute('data-state')) !== 'open') {
    await profile.locator('.w3a-user-account-button-trigger').click();
  }
  const menu = profile.locator('.w3a-profile-dropdown-morphed[data-state="open"]');
  await expect(menu).toBeVisible({ timeout: 10_000 });
  return menu;
}

async function assertOwnerProfileRows(page: Page): Promise<Locator> {
  const menu = await openProfileMenu(page);
  for (const label of LINKED_DEVICE_PROFILE_ROWS) {
    const row = menu.getByRole('button', { name: new RegExp(`^${label}\\b`) });
    await expect(row).toHaveCount(1);
    await expect(row).toBeVisible();
    await expect(row).toBeEnabled();
  }
  return menu;
}

async function openOwnerScanner(page: Page, qrDataUrl: string): Promise<void> {
  await installQrCamera(page, qrDataUrl);
  const profile = page.locator('.w3a-profile-button-morphable').getByRole('button').first();
  await profile.click();
  const menu = page.locator('.w3a-profile-dropdown-morphed[data-state="open"]');
  await menu.getByRole('button', { name: /^Scan and Link Device/ }).click();
  await page.locator('.qr-scanner-video').waitFor({ state: 'visible', timeout: 30_000 });
}

async function openOwnerLinkedDevices(page: Page): Promise<void> {
  const profile = page.locator('.w3a-profile-button-morphable');
  if ((await profile.getAttribute('data-state')) !== 'open') {
    await profile.locator('.w3a-user-account-button-trigger').click();
  }
  await expect(profile).toHaveAttribute('data-state', 'open', { timeout: 10_000 });
  await profile.getByRole('button', { name: /^Linked Devices/ }).click({ timeout: 10_000 });
}

async function unlockLinkedDevice(page: Page, diagnostics: readonly string[]): Promise<void> {
  const wallet = await walletFrame(page);
  const unlock = wallet.getByRole('button', { name: 'Sign in with Passkey', exact: true });
  await unlock.waitFor({ state: 'visible', timeout: 30_000 });
  const verified = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname === '/sync-account/verify',
    { timeout: 90_000 },
  );
  await unlock.click();
  const response = await verified;
  if (!response.ok()) {
    throw new Error(
      `Linked owner unlock failed (${response.status()}): ${await response.text()}\n${diagnostics.join('\n')}`,
    );
  }
  try {
    await page.getByRole('tab', { name: 'Tempo', exact: true }).waitFor({
      state: 'visible',
      timeout: 120_000,
    });
  } catch (error) {
    throw new Error(`Linked owner did not become active\n${diagnostics.join('\n')}`, {
      cause: error,
    });
  }
}

async function refreshLinkedDeviceForSigning(page: Page): Promise<void> {
  await page.reload({ waitUntil: 'domcontentloaded' });
  const wallet = await walletFrame(page);
  const tempoTab = page.getByRole('tab', { name: 'Tempo', exact: true });
  const unlock = wallet.getByRole('button', { name: 'Sign in with Passkey', exact: true });
  await tempoTab.waitFor({ state: 'visible', timeout: 120_000 });
  await expect(unlock).toBeHidden();
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

function isEcdsaFinalSignResponse(response: Response): boolean {
  return (
    response.request().method() === 'POST' &&
    new URL(response.url()).pathname === '/router-ab/ecdsa-derivation/sign'
  );
}

function isEd25519FinalSignResponse(response: Response): boolean {
  return (
    response.request().method() === 'POST' &&
    new URL(response.url()).pathname === '/router-ab/ed25519/sign'
  );
}

function isArcBroadcastResponse(response: Response): boolean {
  const body: unknown = response.request().postDataJSON();
  return isRecord(body) && body.method === 'eth_sendRawTransaction';
}

function isNearBroadcastResponse(response: Response): boolean {
  const body: unknown = response.request().postDataJSON();
  return isRecord(body) && body.method === 'send_tx';
}

async function requireSuccessfulRouterResponse(
  responsePromise: Promise<Response>,
  diagnostics: readonly string[],
): Promise<void> {
  let response: Response;
  try {
    response = await responsePromise;
  } catch (error: unknown) {
    throw new Error(`Linked signing did not reach Router finalization. ${diagnostics.join('\n')}`, {
      cause: error,
    });
  }
  const responseBody = await response.text();
  if (response.ok()) {
    const parsed: unknown = JSON.parse(responseBody);
    if (
      parsed === null ||
      typeof parsed !== 'object' ||
      Array.isArray(parsed) ||
      Reflect.get(parsed, 'ok') !== false
    ) {
      return;
    }
  }
  throw new Error(
    `Linked signing request failed (${response.status()}): ${responseBody}\nRequest: ${response.request().postData() ?? '<empty>'}`,
  );
}

async function requireSuccessfulJsonRpcResponse(
  responsePromise: Promise<Response>,
  label: string,
): Promise<void> {
  const response = await responsePromise;
  const responseBody = await response.text();
  const parsed: unknown = JSON.parse(responseBody);
  if (response.ok() && isRecord(parsed) && !Reflect.has(parsed, 'error')) return;
  throw new Error(`${label} failed (${response.status()}): ${responseBody}`);
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
    const fundingSigned = page.waitForResponse(isEcdsaFinalSignResponse, { timeout: 180_000 });
    await tempoFunding.click();
    await confirmWalletSigning(page);
    await requireSuccessfulRouterResponse(fundingSigned, diagnostics);
    await expect(tempoFunding).toHaveText('Tempo Account Funded', { timeout: 180_000 });
    await expect(tempoFunding).toBeDisabled();
  }
  const tempoSign = page.getByRole('button', { name: 'Sign on Tempo', exact: true });
  await tempoSign.waitFor({ state: 'visible', timeout: 60_000 });
  await expect(tempoSign).toBeEnabled({ timeout: 120_000 });
  const tempoSigned = page.waitForResponse(isEcdsaFinalSignResponse, { timeout: 180_000 });
  await tempoSign.click();
  await confirmWalletSigning(page);
  await requireSuccessfulRouterResponse(tempoSigned, diagnostics);
  await expect(tempoSign).toBeEnabled({ timeout: 180_000 });

  const arcTab = page.getByRole('tab', { name: 'Arc', exact: true });
  await arcTab.click();
  const arcGreetingInput = page.getByPlaceholder('Enter a new greeting');
  arcState.pendingGreeting = 'Hello from linked Arc';
  arcState.transactionInput = encodeArcSetGreetingInput(arcState.pendingGreeting);
  await arcGreetingInput.fill(arcState.pendingGreeting);
  const arcSign = page.getByRole('button', { name: 'Sign on Arc', exact: true });
  await expect(arcSign).toBeEnabled({ timeout: 120_000 });
  const arcSigned = page.waitForResponse(isEcdsaFinalSignResponse, { timeout: 180_000 });
  const arcBroadcast = page.waitForResponse(isArcBroadcastResponse, { timeout: 180_000 });
  await arcSign.click();
  await confirmWalletSigning(page);
  await requireSuccessfulRouterResponse(arcSigned, diagnostics);
  await requireSuccessfulJsonRpcResponse(arcBroadcast, 'Linked Arc transaction broadcast');

  const nearTab = page.getByRole('tab', { name: 'NEAR', exact: true });
  await nearTab.click();
  const sign = page.getByRole('button', { name: 'Sign on NEAR', exact: true });
  await sign.waitFor({ state: 'visible', timeout: 60_000 });
  await expect(sign).toBeEnabled();
  const nearSigned = page.waitForResponse(isEd25519FinalSignResponse, { timeout: 180_000 });
  const nearBroadcast = page.waitForResponse(isNearBroadcastResponse, { timeout: 180_000 });
  await sign.click();
  await confirmWalletSigning(page);
  await requireSuccessfulRouterResponse(nearSigned, diagnostics);
  await requireSuccessfulJsonRpcResponse(nearBroadcast, 'Linked NEAR transaction broadcast');

  await tempoTab.click();
  await expect(tempoSign).toBeEnabled({ timeout: 120_000 });
  const renewedTempoSigned = page.waitForResponse(isEcdsaFinalSignResponse, {
    timeout: 180_000,
  });
  await tempoSign.click();
  await confirmWalletSigning(page);
  await requireSuccessfulRouterResponse(renewedTempoSigned, diagnostics);
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

test('Device 2 links as an owner, unlocks, refreshes, signs, then is revoked', async ({
  browser,
}) => {
  const ownerContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const device2Context = await browser.newContext({ ignoreHTTPSErrors: true });
  await device2Context.route(/https:\/\/[^/]*(?:near\.org|fastnear\.com)\//, fulfillNearRpc);
  await device2Context.route(/https:\/\/[^/]*arc\.network\//, fulfillArcRpc);
  const ownerPage = await ownerContext.newPage();
  const device2Page = await device2Context.newPage();
  const ownerAuthenticator = await addVirtualAuthenticator(ownerPage);
  const device2Authenticator = await addVirtualAuthenticator(device2Page);
  const ownerCredentialAddedEvents: unknown[] = [];
  const ownerCredentialAssertedEvents: unknown[] = [];
  const device2CredentialAddedEvents: unknown[] = [];
  ownerAuthenticator.on('WebAuthn.credentialAdded', (event) => {
    ownerCredentialAddedEvents.push(event);
  });
  ownerAuthenticator.on('WebAuthn.credentialAsserted', (event) => {
    ownerCredentialAssertedEvents.push(event);
  });
  device2Authenticator.on('WebAuthn.credentialAdded', (event) => {
    device2CredentialAddedEvents.push(event);
  });
  const ownerDiagnostics: string[] = [];
  const device2Diagnostics: string[] = [];
  try {
    ownerPage.on('console', (message) => {
      const diagnostic = linkedDeviceConsoleDiagnostic(message);
      if (diagnostic) ownerDiagnostics.push(diagnostic);
    });
    device2Page.on('console', (message) => {
      const text = message.text().replace(/\s+/g, ' ').trim().slice(0, 400);
      if (
        message.type() === 'error' ||
        /linked-device|WalletSession|WebAuthn|bridge|passkey/i.test(text)
      ) {
        device2Diagnostics.push(`[device2:${message.type()}] ${text}`);
      }
    });
    await registerOwner(ownerPage, ownerDiagnostics);
    await assertOwnerProfileRows(ownerPage);
    await ownerPage
      .locator('.w3a-profile-button-morphable .w3a-user-account-button-trigger')
      .click();

    const created = device2Page.waitForResponse(
      (response) =>
        new URL(response.url()).pathname.endsWith('/wallet/device-linking/v1/sessions') &&
        response.request().method() === 'POST' &&
        response.status() === 200,
      { timeout: 120_000 },
    );
    const qrDataUrl = await openDevice2Qr(device2Page);
    await created;
    const ownerFinalize = device2Page
      .waitForResponse(
        (response) =>
          response.url().includes('/wallet/device-linking/v1/sessions/') &&
          response.url().endsWith('/owner-finalize') &&
          response.status() === 200,
        { timeout: 90_000 },
      )
      .then(
        (response) => ({ kind: 'finalized' as const, response }),
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
    const ownerCredentialAssertionsBeforeLinking = ownerCredentialAssertedEvents.length;
    const ownerCredentialCreationsBeforeLinking = ownerCredentialAddedEvents.length;
    await openOwnerScanner(ownerPage, qrDataUrl);
    const claimResult = await claimed;
    if (claimResult.kind === 'timeout') {
      throw new Error(`Device 1 did not claim the linked session. ${ownerDiagnostics.join('\n')}`, {
        cause: claimResult.error,
      });
    }
    if (!claimResult.response.ok()) {
      throw new Error(
        `Device 1 claim failed (${claimResult.response.status()}): ${await claimResult.response.text()}\n${device2Diagnostics.join('\n')}\n${ownerDiagnostics.join('\n')}`,
      );
    }
    const device2Wallet = await walletFrame(device2Page);
    const createTargetPasskey = device2Wallet.locator('[data-link-device-passkey-action]');
    await createTargetPasskey.waitFor({ state: 'visible', timeout: 120_000 });
    await createTargetPasskey.focus();
    await createTargetPasskey.press('Enter');
    const finalizeResult = await ownerFinalize;
    if (finalizeResult.kind === 'timeout') {
      const walletState = (await device2Wallet.locator('body').innerText()).trim();
      throw new Error(
        `Device 2 owner credential did not finalize. Page: ${device2Page.url()} Wallet state: ${walletState}\n${device2Diagnostics.join('\n')}\n${ownerDiagnostics.join('\n')}`,
        { cause: finalizeResult.error },
      );
    }
    await unlockLinkedDevice(device2Page, device2Diagnostics);
    await expect(device2Wallet.getByText('Generating QR code', { exact: false })).toBeHidden();
    await assertOwnerProfileRows(device2Page);
    expect(ownerCredentialAddedEvents.length).toBeGreaterThan(0);
    /* R103 zero-prompt handoff, asserted with real prompt counters: from the
       moment Device 1 opened the scanner through Device 2 finalizing its
       owner credential, Device 1's authenticator performed zero
       assertions and zero creations — the scan itself was the approval —
       while Device 2 created exactly one passkey, the credential it is
       enrolling. */
    expect(ownerCredentialAssertedEvents.slice(ownerCredentialAssertionsBeforeLinking)).toHaveLength(0);
    expect(ownerCredentialAddedEvents.slice(ownerCredentialCreationsBeforeLinking)).toHaveLength(0);
    expect(device2CredentialAddedEvents).toHaveLength(1);
    await refreshLinkedDeviceForSigning(device2Page);
    const linkedSigningPaths: string[] = [];
    device2Page.on('request', (request) => {
      const pathname = new URL(request.url()).pathname;
      if (!pathname.includes('/router-ab/')) return;
      linkedSigningPaths.push(pathname);
    });
    await linkedSigning(device2Page, device2Diagnostics);
    if (linkedSigningPaths.length === 0) {
      throw new Error(
        `Device 2 signing emitted no Router A/B requests. ${device2Diagnostics.join('\n')}`,
      );
    }
    expect(linkedSigningPaths).toContain('/router-ab/ecdsa-derivation/sign');
    expect(linkedSigningPaths).toContain('/router-ab/ed25519/sign');
    expect(linkedSigningPaths.some((pathname) => pathname.includes('/linked-device/'))).toBe(false);

    await openOwnerLinkedDevices(ownerPage);
    const linkedDevice = ownerPage.locator('.w3a-linked-devices-modal-item');
    await linkedDevice.waitFor({ state: 'visible', timeout: 60_000 });
    // The card's remove control is labelled `Remove <credential> (ID …)` so that
    // two same-labelled cards announce distinctly; match the prefix, not the
    // whole accessible name.
    await linkedDevice.getByRole('button', { name: /^Remove\b/ }).click();
    await linkedDevice.getByRole('button', { name: 'Yes, remove', exact: true }).click();
    // Removal revokes the enrollment. A revoked device is a historical record,
    // not a manageable entry, so it leaves the list rather than standing in it.
    await expect(linkedDevice).toHaveCount(0, { timeout: 60_000 });
    await expect(
      ownerPage.locator('.w3a-linked-devices-modal-placeholder', {
        hasText: 'No other devices are using this wallet.',
      }),
    ).toBeVisible({ timeout: 60_000 });
  } finally {
    await closeBrowserContexts(ownerContext, device2Context);
  }
});
