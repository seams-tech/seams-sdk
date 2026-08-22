import {
  expect,
  test,
  type Browser,
  type BrowserContext,
  type CDPSession,
  type ConsoleMessage,
  type Frame,
  type FrameLocator,
  type Locator,
  type Page,
  type Response,
  type Route,
} from '@playwright/test';
import { Buffer } from 'node:buffer';
import {
  parseActivateInstalledAuthorityResultV1,
  parseCommittedAuthorityPackagesV1,
  parseLinkedDeviceEmailOtpVerificationResultV1,
  parseLinkedDeviceListResultV1,
  parseLocalAuthorityActivationFinalAckV1,
  parseLinkedDeviceTargetCredentialRegistrationResultV1,
  parseLinkSessionProjectionV1,
  parseLinkSessionStateV1,
  parseLinkedDeviceTargetPreparationV1,
} from '@shared/device-linking';
import { parseTransaction, type Hex } from 'viem';

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
const localRouterOrigin = 'https://localhost:9444';
const arcState = {
  greeting: 'Hello from local Arc',
  transactionInput: '0x' as Hex,
  transactionTo: arcGreetingContract,
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

type WalletPublicIdentity = {
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly nearPublicKey: string;
  readonly ecdsaKeys: readonly string[];
};

type AuthenticatedOwnerSnapshot = {
  readonly credentialIdB64u: string;
  readonly publicIdentity: WalletPublicIdentity;
  readonly routerOrigin: string;
  readonly rpId: string;
};

type OwnerCredentialSnapshot = {
  readonly credentialIdB64u: string;
  readonly walletId: string;
  readonly routerOrigin: string;
  readonly rpId: string;
};

type ExportedPublicIdentity = {
  readonly accountId: string;
  readonly entries: readonly {
    readonly address: string;
    readonly publicKey: string;
    readonly scheme: string;
  }[];
};

type ExportWaitOutcome =
  | { readonly kind: 'response'; readonly response: Response }
  | { readonly kind: 'terminal-failure'; readonly diagnostic: string };

function emailLinkedDeviceStage(stage: string): void {
  console.info(`[email-linked-device] ${stage}`);
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  return value;
}

function requireStringField(record: Record<string, unknown>, field: string, label: string): string {
  const value = String(record[field] || '').trim();
  if (!value) throw new Error(`${label}.${field} must be a non-empty string`);
  return value;
}

function requireGoogleIdToken(): string {
  const token = String(process.env.SEAMS_INTENDED_GOOGLE_ID_TOKEN || '').trim();
  if (!token) throw new Error('SEAMS_INTENDED_GOOGLE_ID_TOKEN is required for Email OTP linking');
  return token;
}

function installGoogleIdentityStub(idToken: string): void {
  let credentialCallback: ((response: { readonly credential: string }) => void) | null = null;
  Reflect.set(window, 'google', {
    accounts: {
      id: {
        initialize(configuration: {
          readonly callback: (response: { readonly credential: string }) => void;
        }): void {
          credentialCallback = configuration.callback;
        },
        prompt(): void {
          if (!credentialCallback) throw new Error('Google Identity stub was not initialized');
          queueMicrotask(credentialCallback.bind(null, { credential: idToken }));
        },
        cancel(): void {},
      },
    },
  });
}

function enableSigningSessionDiagnostics(): void {
  localStorage.setItem('seams:debug:signing-session', '1');
}

function parseEcdsaWalletKeyIdentity(rawWalletKey: unknown, label: string): string {
  const walletKey = requireRecord(rawWalletKey, label);
  if (walletKey.thresholdEcdsaPublicKeyB64u && walletKey.thresholdOwnerAddress) {
    const publicKeyB64u = requireStringField(walletKey, 'thresholdEcdsaPublicKeyB64u', label);
    const publicKey = `0x${Buffer.from(publicKeyB64u, 'base64url').toString('hex')}`;
    const address = requireStringField(walletKey, 'thresholdOwnerAddress', label);
    return `${publicKey.toLowerCase()}:${address.toLowerCase()}`;
  }
  const publicCapability = requireRecord(walletKey.publicCapability, `${label}.publicCapability`);
  const publicIdentity = requireRecord(
    publicCapability.public_identity,
    `${label}.publicCapability.public_identity`,
  );
  const publicKeyB64u = requireStringField(
    publicIdentity,
    'threshold_public_key33_b64u',
    `${label}.publicCapability.public_identity`,
  );
  const publicKey = `0x${Buffer.from(publicKeyB64u, 'base64url').toString('hex')}`;
  const addressB64u = requireStringField(
    publicIdentity,
    'ethereum_address20_b64u',
    `${label}.publicCapability.public_identity`,
  );
  const address = `0x${Buffer.from(addressB64u, 'base64url').toString('hex')}`;
  return `${publicKey.toLowerCase()}:${address.toLowerCase()}`;
}

function parseEcdsaPublicIdentity(rawSigner: unknown, index: number): string {
  const signer = requireRecord(rawSigner, `sync-account ECDSA signer ${index}`);
  return parseEcdsaWalletKeyIdentity(
    signer.walletKey,
    `sync-account ECDSA signer ${index}.walletKey`,
  );
}

function parseRegisteredOwnerSnapshot(
  rawActivate: unknown,
  rawNear: unknown,
  routerOrigin: string,
): AuthenticatedOwnerSnapshot {
  const publicIdentity = parseRegisteredWalletPublicIdentity(rawActivate, rawNear);
  const activate = requireRecord(rawActivate, 'registration activate response');
  const authMethod = requireRecord(
    activate.authMethod,
    'registration activate response.authMethod',
  );
  return {
    credentialIdB64u: requireStringField(
      authMethod,
      'credentialIdB64u',
      'registration activate response.authMethod',
    ),
    routerOrigin,
    rpId: requireStringField(activate, 'rpId', 'registration activate response'),
    publicIdentity,
  };
}

function parseRegisteredWalletPublicIdentity(
  rawActivate: unknown,
  rawNear: unknown,
): WalletPublicIdentity {
  const activate = requireRecord(rawActivate, 'registration activate response');
  const near = requireRecord(rawNear, 'registration NEAR provisioning response');
  const ecdsa = requireRecord(activate.ecdsa, 'registration activate response.ecdsa');
  if (!Array.isArray(ecdsa.walletKeys) || ecdsa.walletKeys.length === 0) {
    throw new Error('registration activate response.ecdsa.walletKeys must contain a wallet key');
  }
  const ed25519 = requireRecord(near.ed25519, 'registration NEAR provisioning response.ed25519');
  const walletId = requireStringField(activate, 'walletId', 'registration activate response');
  if (
    requireStringField(near, 'walletId', 'registration NEAR provisioning response') !== walletId
  ) {
    throw new Error('registration responses disagree on wallet identity');
  }
  const ecdsaKeys = [
    ...new Set(
      ecdsa.walletKeys.map((walletKey, index) =>
        parseEcdsaWalletKeyIdentity(
          walletKey,
          `registration activate response.ecdsa.walletKeys[${index}]`,
        ),
      ),
    ),
  ];
  ecdsaKeys.sort();
  return {
    walletId,
    nearAccountId: requireStringField(
      ed25519,
      'nearAccountId',
      'registration NEAR provisioning response.ed25519',
    ),
    nearPublicKey: requireStringField(
      ed25519,
      'publicKey',
      'registration NEAR provisioning response.ed25519',
    ),
    ecdsaKeys,
  };
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

function decodeArcSetGreetingInput(input: Hex): string {
  if (!input.startsWith('0xa4136862')) {
    throw new Error('Arc signed transaction does not call setGreeting(string)');
  }
  const encoded = input.slice(10);
  if (encoded.length < 128) {
    throw new Error('Arc setGreeting calldata is truncated');
  }
  const byteLength = Number(BigInt(`0x${encoded.slice(64, 128)}`));
  const valueHex = encoded.slice(128, 128 + byteLength * 2);
  if (valueHex.length !== byteLength * 2) {
    throw new Error('Arc setGreeting string payload is truncated');
  }
  return Buffer.from(valueHex, 'hex').toString('utf8');
}

function captureArcSignedTransaction(params: unknown): void {
  if (!Array.isArray(params) || typeof params[0] !== 'string') {
    throw new Error('Arc eth_sendRawTransaction requires a serialized transaction');
  }
  const transaction = parseTransaction(params[0] as Hex);
  if (!transaction.data || !transaction.to) {
    throw new Error('Arc signed transaction is missing its destination or calldata');
  }
  arcState.transactionInput = transaction.data;
  arcState.transactionTo = transaction.to;
  arcState.greeting = decodeArcSetGreetingInput(transaction.data);
}

function arcRpcResult(method: string, params: unknown): unknown {
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
      captureArcSignedTransaction(params);
      return arcStubTransactionHash;
    case 'eth_getTransactionReceipt':
      return {
        transactionHash: arcStubTransactionHash,
        transactionIndex: '0x0',
        blockHash: arcStubBlockHash,
        blockNumber: '0x10',
        from: '0x1111111111111111111111111111111111111111',
        to: arcState.transactionTo,
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
        to: arcState.transactionTo,
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
  const result = arcRpcResult(method, request.params);
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

function isRegistrationActivateResponse(response: Response): boolean {
  return (
    response.request().method() === 'POST' &&
    new URL(response.url()).pathname === '/wallets/register/activate'
  );
}

function isRegistrationNearProvisioningResponse(response: Response): boolean {
  return (
    response.request().method() === 'POST' &&
    new URL(response.url()).pathname === '/wallets/register/near-provisioning'
  );
}

async function registerOwner(
  page: Page,
  diagnostics: readonly string[],
): Promise<AuthenticatedOwnerSnapshot> {
  const wallet = await openWallet(page);
  const primary = wallet.locator('button[data-auth-menu-primary]');
  await primary.waitFor({ state: 'visible', timeout: 30_000 });
  const activated = page.waitForResponse(isRegistrationActivateResponse, { timeout: 120_000 });
  const nearProvisioned = page.waitForResponse(isRegistrationNearProvisioningResponse, {
    timeout: 120_000,
  });
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
  const [activateResponse, nearResponse] = await Promise.all([activated, nearProvisioned]);
  if (!activateResponse.ok() || !nearResponse.ok()) {
    throw new Error(
      `Owner registration identity responses failed (${activateResponse.status()}, ${nearResponse.status()})`,
    );
  }
  return parseRegisteredOwnerSnapshot(
    await activateResponse.json(),
    await nearResponse.json(),
    new URL(activateResponse.url()).origin,
  );
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

async function openDevice2Qr(
  page: Page,
  factor: 'Passkey' | 'Email code' = 'Passkey',
): Promise<string> {
  const wallet = await openWallet(page);
  const linkButton = wallet.getByRole('button', { name: 'Scan and Link Device', exact: true });
  await linkButton.waitFor({ state: 'visible', timeout: 30_000 });
  await linkButton.click();
  const factorRadio = wallet.getByRole('radio', { name: factor, exact: true });
  await factorRadio.click({ force: true });
  await expect(factorRadio).toBeChecked({ timeout: 10_000 });
  const continueButton = wallet.getByRole('button', { name: 'Continue', exact: true });
  await continueButton.focus();
  await continueButton.press('Enter');
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
    await expect(row).toHaveCount(1, { timeout: 30_000 });
    await expect(row).toBeVisible({ timeout: 30_000 });
    await expect(row).toBeEnabled({ timeout: 30_000 });
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

async function lockActiveWallet(page: Page): Promise<void> {
  const menu = await openProfileMenu(page);
  await menu.getByRole('button', { name: 'Lock Wallet', exact: true }).click();
}

async function lockWallet(page: Page): Promise<void> {
  await lockActiveWallet(page);
  const wallet = await walletFrame(page);
  const unlock = wallet.getByRole('button', { name: 'Sign in with Passkey', exact: true });
  const switchToLogin = wallet.locator('button[data-auth-menu-mode="login"]');
  await unlock.or(switchToLogin).first().waitFor({ state: 'visible', timeout: 30_000 });
  if (await switchToLogin.isVisible()) await switchToLogin.click();
  await unlock.waitFor({
    state: 'visible',
    timeout: 30_000,
  });
}

async function readEmailOtpOutboxCode(input: {
  readonly context: BrowserContext;
  readonly walletId: string;
  readonly challengeId?: string;
}): Promise<string> {
  const deadline = Date.now() + 30_000;
  let lastFailure = 'outbox entry was unavailable';
  while (Date.now() < deadline) {
    const response = await input.context.request.post(
      `${localRouterOrigin}/wallet/email-otp/dev/otp-outbox`,
      {
        data: {
          idToken: requireGoogleIdToken(),
          walletId: input.walletId,
          ...(input.challengeId ? { challengeId: input.challengeId } : {}),
        },
      },
    );
    const body: unknown = await response.json().catch(() => null);
    if (response.ok()) {
      const record = requireRecord(body, 'Email OTP outbox response');
      const otpCode = requireStringField(record, 'otpCode', 'Email OTP outbox response');
      if (!/^\d{6}$/.test(otpCode)) throw new Error('Email OTP outbox returned an invalid code');
      return otpCode;
    }
    lastFailure = `${response.status()} ${JSON.stringify(body)}`;
    await new Promise<void>((resolve) => globalThis.setTimeout(resolve, 200));
  }
  throw new Error(`Email OTP outbox lookup failed: ${lastFailure}`);
}

async function completeVisibleEmailOtpPrompt(input: {
  readonly page: Page;
  readonly context: BrowserContext;
  readonly walletId: string;
}): Promise<boolean> {
  const wallet = await walletFrame(input.page);
  const otpInput = wallet
    .locator(
      '#email-otp-confirm-code, #drawer-email-otp-confirm-code, #w3a-auth-menu-google-otp, input[aria-label="Email verification code"]',
    )
    .first();
  if (await otpInput.isVisible().catch(() => false)) {
    if (!(await otpInput.isEnabled().catch(() => false))) return false;
    const promptWalletIdentity = wallet.locator('.w3a-otp-account-value');
    const promptWalletId = String(
      (await promptWalletIdentity.isVisible().catch(() => false))
        ? await promptWalletIdentity.textContent().catch(() => null)
        : '',
    ).trim();
    const walletId = promptWalletId || input.walletId;
    if (!walletId) throw new Error('Email OTP prompt does not expose its wallet identity');
    const challengeId = await otpInput.evaluate(readEmailOtpPromptChallengeId);
    const otpCode = await readEmailOtpOutboxCode({
      context: input.context,
      walletId,
      ...(challengeId ? { challengeId } : {}),
    });
    await otpInput.fill(otpCode);
    const submit = wallet
      .locator(
        '[data-auth-menu-primary], #w3a-confirm-portal button.btn-confirm, #w3a-confirm-portal button.confirm',
      )
      .first();
    if (await submit.isEnabled().catch(() => false)) await submit.click();
    return true;
  }
  const emailView = wallet.locator('.w3a-otp-prompt');
  const startSelector = (await emailView.isVisible().catch(() => false))
    ? '[data-auth-menu-primary]'
    : '[data-seams-registration-activation-start="true"], #w3a-confirm-portal button.btn-confirm, #w3a-confirm-portal button.confirm';
  const start = wallet.locator(startSelector).first();
  if (!(await start.isVisible().catch(() => false))) return false;
  if (!(await start.isEnabled().catch(() => false))) return false;
  await start.click();
  return true;
}

function readEmailOtpPromptChallengeId(anchor: Element): string | null {
  const roots: Array<Document | ShadowRoot> = [anchor.ownerDocument];
  for (let rootIndex = 0; rootIndex < roots.length; rootIndex += 1) {
    const root = roots[rootIndex];
    for (const element of Array.from(root.querySelectorAll('*'))) {
      const prompt = element as HTMLElement & {
        emailOtpPrompt?: { readonly challengeId?: unknown };
      };
      const challengeId = String(prompt.emailOtpPrompt?.challengeId || '').trim();
      if (challengeId) return challengeId;
      if (element.shadowRoot) roots.push(element.shadowRoot);
    }
  }
  return null;
}

async function readVisibleHostedAuthFailure(page: Page): Promise<string | null> {
  const toast = page.locator('[data-sonner-toast][data-type="error"]').last();
  if (await toast.isVisible().catch(() => false)) {
    const text = (await toast.textContent())?.replace(/\s+/g, ' ').trim();
    if (text) return text;
  }
  for (const frame of page.frames()) {
    const alert = frame.locator('.w3a-method-error, .w3a-otp-error, [role="alert"]').last();
    if (!(await alert.isVisible().catch(() => false))) continue;
    const text = (await alert.textContent())?.replace(/\s+/g, ' ').trim();
    if (text) return text;
  }
  return null;
}

async function completeEmailOtpPromptsUntil<T>(input: {
  readonly page: Page;
  readonly context: BrowserContext;
  readonly walletId: string;
  readonly task: Promise<T>;
}): Promise<T> {
  const settled = input.task.then(
    (value) => ({ kind: 'resolved' as const, value }),
    (error: unknown) => ({ kind: 'rejected' as const, error }),
  );
  const deadline = Date.now() + 180_000;
  while (Date.now() < deadline) {
    const step = await Promise.race([
      settled,
      completeVisibleEmailOtpPrompt(input).then(() => ({ kind: 'prompt_handled' as const })),
    ]);
    if (step.kind === 'resolved') return step.value;
    if (step.kind === 'rejected') throw step.error;
    const failure = await readVisibleHostedAuthFailure(input.page);
    if (failure) throw new Error(`Hosted Email OTP authentication failed: ${failure}`);
    await input.page.waitForTimeout(200);
  }
  throw new Error('Email OTP authenticated operation did not complete');
}

async function authenticateEmailOtpInHostedMenu(input: {
  readonly page: Page;
  readonly context: BrowserContext;
  readonly mode: 'register' | 'login';
  readonly walletId: string;
}): Promise<void> {
  const wallet = await walletFrame(input.page);
  const google = wallet.locator('[data-auth-menu-provider="google"]');
  const switchMode = wallet.locator(`button[data-auth-menu-mode="${input.mode}"]`);
  await google.or(switchMode).first().waitFor({ state: 'visible', timeout: 30_000 });
  if (await switchMode.isVisible()) await switchMode.click();
  await google.waitFor({ state: 'visible', timeout: 30_000 });
  const authenticated = input.page
    .getByRole('tab', { name: 'Tempo', exact: true })
    .waitFor({ state: 'visible', timeout: 180_000 });
  await google.click();
  await completeEmailOtpPromptsUntil({
    page: input.page,
    context: input.context,
    walletId: input.walletId,
    task: authenticated,
  });
}

async function unlockEmailOtpWallet(
  page: Page,
  context: BrowserContext,
  walletId: string,
): Promise<void> {
  await authenticateEmailOtpInHostedMenu({ page, context, mode: 'login', walletId });
  if ((await readActiveWalletId(page)) !== walletId) {
    throw new Error('Email OTP unlock returned the wrong wallet');
  }
}

async function registerEmailOwner(
  page: Page,
  context: BrowserContext,
): Promise<WalletPublicIdentity> {
  emailLinkedDeviceStage('registering owner');
  await openWallet(page);
  const activated = page.waitForResponse(isRegistrationActivateResponse, { timeout: 120_000 });
  const nearProvisioned = page.waitForResponse(isRegistrationNearProvisioningResponse, {
    timeout: 120_000,
  });
  await authenticateEmailOtpInHostedMenu({ page, context, mode: 'register', walletId: '' });
  const [activateResponse, nearResponse] = await Promise.all([activated, nearProvisioned]);
  if (!activateResponse.ok() || !nearResponse.ok()) {
    throw new Error(
      `Email owner registration identity responses failed (${activateResponse.status()}, ${nearResponse.status()})`,
    );
  }
  const identity = parseRegisteredWalletPublicIdentity(
    await activateResponse.json(),
    await nearResponse.json(),
  );
  if ((await readActiveWalletId(page)) !== identity.walletId) {
    throw new Error('Email owner registration activated a different wallet');
  }
  emailLinkedDeviceStage('owner registered');
  return identity;
}

async function unlockLinkedPasskeyWallet(
  page: Page,
  diagnostics: readonly string[],
): Promise<void> {
  const wallet = await walletFrame(page);
  const unlock = wallet.getByRole('button', { name: 'Sign in with Passkey', exact: true });
  const switchToLogin = wallet.locator('button[data-auth-menu-mode="login"]');
  await unlock.or(switchToLogin).first().waitFor({ state: 'visible', timeout: 30_000 });
  if (await switchToLogin.isVisible()) await switchToLogin.click();
  await unlock.waitFor({ state: 'visible', timeout: 30_000 });
  await unlock.click();
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

function credentialIdB64uFromAddedEvent(raw: unknown): string {
  const event = requireRecord(raw, 'WebAuthn credential-added event');
  const credential = requireRecord(event.credential, 'WebAuthn credential-added event.credential');
  return Buffer.from(
    requireStringField(credential, 'credentialId', 'WebAuthn credential-added event.credential'),
    'base64',
  ).toString('base64url');
}

async function waitForLinkedDeviceActive(
  page: Page,
  diagnostics: readonly string[],
  ownerDiagnostics: readonly string[],
): Promise<void> {
  try {
    await page.getByRole('tab', { name: 'Tempo', exact: true }).waitFor({
      state: 'visible',
      timeout: 180_000,
    });
  } catch (error) {
    throw new Error(
      `Linked device did not become active\n${diagnostics.join('\n')}\n${ownerDiagnostics.join('\n')}`,
      {
        cause: error,
      },
    );
  }
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

async function linkedSigning(
  page: Page,
  diagnostics: readonly string[],
  emailOtp?: { readonly context: BrowserContext; readonly walletId: string },
): Promise<void> {
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
    if (emailOtp) {
      await completeEmailOtpPromptsUntil({
        page,
        ...emailOtp,
        task: requireSuccessfulRouterResponse(fundingSigned, diagnostics),
      });
    } else {
      await confirmWalletSigning(page);
      await requireSuccessfulRouterResponse(fundingSigned, diagnostics);
    }
    await expect(tempoFunding).toHaveText('Tempo Account Funded', { timeout: 180_000 });
    await expect(tempoFunding).toBeDisabled();
    return;
  }
  const tempoSign = page.getByRole('button', { name: 'Sign on Tempo', exact: true });
  await tempoSign.waitFor({ state: 'visible', timeout: 60_000 });
  await expect(tempoSign).toBeEnabled({ timeout: 120_000 });
  const tempoSigned = page.waitForResponse(isEcdsaFinalSignResponse, { timeout: 180_000 });
  await tempoSign.click();
  if (emailOtp) {
    await completeEmailOtpPromptsUntil({
      page,
      ...emailOtp,
      task: requireSuccessfulRouterResponse(tempoSigned, diagnostics),
    });
  } else {
    await confirmWalletSigning(page);
    await requireSuccessfulRouterResponse(tempoSigned, diagnostics);
  }
}

function isNearFinalSignResponse(response: Response): boolean {
  const pathname = new URL(response.url()).pathname;
  return (
    response.request().method() === 'POST' &&
    pathname.startsWith('/router-ab/ed25519/') &&
    (pathname.endsWith('/sign') || pathname.endsWith('/sign/execute'))
  );
}

/** One greeting transaction on the Arc (EVM) or NEAR tab of the active demo. */
async function greetingSigning(
  page: Page,
  chain: 'Arc' | 'NEAR',
  diagnostics: readonly string[],
  emailOtp?: { readonly context: BrowserContext; readonly walletId: string },
): Promise<void> {
  const tab = page.getByRole('tab', { name: chain, exact: true });
  await tab.waitFor({ state: 'visible', timeout: 120_000 });
  await tab.click();
  const sign = page.getByRole('button', { name: `Sign on ${chain}`, exact: true });
  await sign.waitFor({ state: 'visible', timeout: 60_000 });
  await expect(sign).toBeEnabled({ timeout: 120_000 });
  const signed = page.waitForResponse(
    chain === 'Arc' ? isEcdsaFinalSignResponse : isNearFinalSignResponse,
    { timeout: 180_000 },
  );
  await sign.click();
  if (emailOtp) {
    await completeEmailOtpPromptsUntil({
      page,
      ...emailOtp,
      task: requireSuccessfulRouterResponse(signed, diagnostics),
    });
  } else {
    await confirmWalletSigning(page);
    await requireSuccessfulRouterResponse(signed, diagnostics);
  }
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

type LinkedOwnerPair = {
  readonly ownerContext: BrowserContext;
  readonly device2Context: BrowserContext;
  readonly ownerPage: Page;
  readonly device2Page: Page;
  readonly ownerDiagnostics: readonly string[];
  readonly device2Diagnostics: readonly string[];
  readonly owner: AuthenticatedOwnerSnapshot;
  readonly device2: OwnerCredentialSnapshot;
  readonly activation: LinkedActivationSnapshot;
};

type EmailLinkedOwnerPair = {
  readonly ownerContext: BrowserContext;
  readonly device2Context: BrowserContext;
  readonly ownerPage: Page;
  readonly device2Page: Page;
  readonly ownerDiagnostics: readonly string[];
  readonly device2Diagnostics: readonly string[];
  readonly publicIdentity: WalletPublicIdentity;
};

type BrowserPasskeyRevocationInput = {
  readonly actorCredentialIdB64u: string;
  readonly endpoint: string;
  readonly rpId: string;
  readonly targetCredentialIdB64u: string;
};

type BrowserPasskeyRevocationResult = {
  readonly body: unknown;
  readonly status: number;
};

type LinkedActivationSnapshot = {
  readonly linkSessionId: string;
  readonly authorityId: string;
  readonly authMethodId: string;
  readonly deviceId: string;
  readonly packageSetDigestB64u: string;
  readonly authorizationId: string;
};

type LinkedInventorySnapshot = {
  readonly deviceId: string;
  readonly enrollmentId: string;
  readonly authMethodId: string;
  readonly keyManifestDigestB64u: string;
  readonly state: string;
  readonly revocationEpoch: number;
};

function isRevokedWalletUnlockResponse(response: Response): boolean {
  return (
    response.request().method() === 'POST' &&
    new URL(response.url()).pathname === '/wallet/unlock/verify' &&
    response.status() === 409
  );
}

function isRevokedLinkedSessionSealResponse(response: Response): boolean {
  return (
    response.request().method() === 'POST' &&
    new URL(response.url()).pathname === '/wallet-session/seal/apply-server-seal' &&
    !response.ok()
  );
}

function isRevokedOwnerUnlockResponse(response: Response): boolean {
  return isRevokedWalletUnlockResponse(response) || isRevokedLinkedSessionSealResponse(response);
}

function isEcdsaExportResponse(response: Response): boolean {
  const pathname = new URL(response.url()).pathname;
  return (
    response.request().method() === 'POST' &&
    (pathname === '/router-ab/ecdsa-derivation/export' ||
      pathname === '/router-ab/ecdsa-derivation/linked-device/export/share')
  );
}

function emailOtpRequestOperation(response: Response): string | null {
  try {
    const body: unknown = response.request().postDataJSON();
    return isRecord(body) ? String(body.operation || '').trim() || null : null;
  } catch {
    return null;
  }
}

function isEmailOtpExportAuthorizationResponse(
  response: Response,
  pathname: '/wallet/email-otp/challenge' | '/wallet/email-otp/factor-release',
): boolean {
  return (
    response.request().method() === 'POST' &&
    new URL(response.url()).pathname === pathname &&
    emailOtpRequestOperation(response) === 'export_key'
  );
}

function isEmailOtpExportChallengeResponse(response: Response): boolean {
  return isEmailOtpExportAuthorizationResponse(response, '/wallet/email-otp/challenge');
}

function isEmailOtpExportFactorReleaseResponse(response: Response): boolean {
  return isEmailOtpExportAuthorizationResponse(response, '/wallet/email-otp/factor-release');
}

function isEd25519ExportResponse(response: Response): boolean {
  return (
    response.request().method() === 'POST' &&
    new URL(response.url()).pathname === '/router-ab/ed25519/yao/export/execute'
  );
}

function terminalKeyExportDiagnostic(message: ConsoleMessage): string | null {
  if (message.type() !== 'error') return null;
  const text = message.text().replace(/\s+/g, ' ').trim();
  const prefix = '[AccountMenuButton] Key export failed:';
  if (!text.startsWith(prefix)) return null;
  const diagnostic = text.slice(prefix.length).trim();
  return diagnostic || null;
}

function isTerminalKeyExportFailure(message: ConsoleMessage): boolean {
  return terminalKeyExportDiagnostic(message) !== null;
}

function exportResponseOutcome(response: Response): ExportWaitOutcome {
  return { kind: 'response', response };
}

function exportTerminalFailureOutcome(message: ConsoleMessage): ExportWaitOutcome {
  const diagnostic = terminalKeyExportDiagnostic(message);
  if (!diagnostic) {
    throw new Error('Terminal key-export console evidence did not include a diagnostic');
  }
  return { diagnostic, kind: 'terminal-failure' };
}

const keyExportWaitTimeoutMs = 60_000;

async function requireEmailOtpExportAuthorization(page: Page): Promise<void> {
  let challenge: Response;
  let factorRelease: Response;
  try {
    [challenge, factorRelease] = await Promise.all([
      page.waitForResponse(isEmailOtpExportChallengeResponse, {
        timeout: keyExportWaitTimeoutMs,
      }),
      page.waitForResponse(isEmailOtpExportFactorReleaseResponse, {
        timeout: keyExportWaitTimeoutMs,
      }),
    ]);
  } catch (error: unknown) {
    throw new Error(
      'Email OTP key export did not perform a fresh export_key challenge and factor release',
      { cause: error },
    );
  }
  expect(challenge.ok(), 'Email OTP export challenge failed').toBe(true);
  expect(factorRelease.ok(), 'Email OTP export factor release failed').toBe(true);
}

async function waitForExportResponseOrFailure(
  page: Page,
  chain: 'near' | 'evm',
  diagnostics: readonly string[],
): Promise<void> {
  let outcome: ExportWaitOutcome;
  try {
    outcome = await Promise.race([
      page
        .waitForResponse(chain === 'near' ? isEd25519ExportResponse : isEcdsaExportResponse, {
          timeout: keyExportWaitTimeoutMs,
        })
        .then(exportResponseOutcome),
      page
        .waitForEvent('console', {
          predicate: isTerminalKeyExportFailure,
          timeout: keyExportWaitTimeoutMs,
        })
        .then(exportTerminalFailureOutcome),
    ]);
  } catch (error: unknown) {
    throw new Error(`Key export did not reach Router finalization. ${diagnostics.join('\n')}`, {
      cause: error,
    });
  }
  if (outcome.kind === 'terminal-failure') {
    throw new Error(`Key export failed: ${outcome.diagnostic}`);
  }
  await requireSuccessfulRouterResponse(Promise.resolve(outcome.response), diagnostics);
}

async function findExportViewerFrame(page: Page): Promise<Frame> {
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    for (const frame of page.frames()) {
      const heading = frame.getByRole('heading', { name: 'Exported Keys', exact: true });
      if (await heading.isVisible().catch(() => false)) return frame;
    }
    await page.waitForTimeout(250);
  }
  throw new Error('Key export did not open the private-key viewer');
}

function readExportedKeyIdentity(element: Element): ExportedPublicIdentity & {
  readonly privateKeys: readonly string[];
} {
  const rawKeys = Reflect.get(element, 'keys');
  const keys = Array.isArray(rawKeys) ? rawKeys : [];
  const entries = keys
    .filter((entry): entry is Record<string, unknown> => {
      return Boolean(entry) && typeof entry === 'object' && !Array.isArray(entry);
    })
    .map((entry) => ({
      address: String(entry.address || '')
        .trim()
        .toLowerCase(),
      publicKey: String(entry.publicKey || '').trim(),
      scheme: String(entry.scheme || '').trim(),
    }));
  const privateKeys = keys
    .map((entry) => {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return '';
      return String(Reflect.get(entry, 'privateKey') || '').trim();
    })
    .filter(Boolean);
  return {
    accountId: String(Reflect.get(element, 'accountId') || '').trim(),
    entries,
    privateKeys,
  };
}

async function exportOwnerKey(
  page: Page,
  chain: 'near' | 'evm',
  diagnostics: readonly string[],
  emailOtp?: { readonly context: BrowserContext; readonly walletId: string },
): Promise<ExportedPublicIdentity> {
  const menu = await openProfileMenu(page);
  const rowLabel = chain === 'near' ? 'Export NEAR Key' : 'Export EVM Keys';
  const exportRow = menu.getByRole('button', { name: new RegExp(`^${rowLabel}\\b`) });
  if (!(await exportRow.isVisible())) {
    await menu.getByRole('button', { name: /^Export Keys\b/ }).click();
  }
  await expect(exportRow).toBeVisible();
  await expect(exportRow).toBeEnabled();
  const finishExport = waitForExportResponseOrFailure(page, chain, diagnostics);
  const exportAuthorization = emailOtp ? requireEmailOtpExportAuthorization(page) : null;
  await exportRow.click();
  if (emailOtp) {
    await Promise.all([
      completeEmailOtpPromptsUntil({ page, ...emailOtp, task: finishExport }),
      exportAuthorization,
    ]);
  } else {
    await finishExport;
  }

  const viewer = await findExportViewerFrame(page);
  const privateKey = viewer.getByRole('button', { name: 'Copy private key', exact: true }).first();
  await expect(privateKey).toBeVisible({ timeout: 60_000 });
  await expect(privateKey).toBeEnabled({ timeout: 60_000 });
  if (chain === 'near') {
    await expect(
      viewer.getByRole('button', { name: 'Copy public key', exact: true }).first(),
    ).toBeEnabled();
  } else {
    await expect(viewer.locator('.field-label', { hasText: 'Address' }).first()).toBeVisible();
  }
  const identity = await viewer.locator('w3a-export-key-viewer').evaluate(readExportedKeyIdentity);
  expect(identity.entries.length).toBeGreaterThan(0);
  expect(identity.privateKeys.length).toBeGreaterThan(0);
  for (const privateKeyValue of identity.privateKeys) {
    if (chain === 'near') {
      expect(privateKeyValue).toMatch(/^ed25519:[1-9A-HJ-NP-Za-km-z]{80,90}$/);
    } else {
      expect(privateKeyValue).toMatch(/^0x[0-9a-f]{64}$/i);
    }
  }
  await viewer.getByRole('button', { name: 'Close', exact: true }).click();
  await expect(viewer.getByRole('heading', { name: 'Exported Keys', exact: true })).toBeHidden({
    timeout: 10_000,
  });
  return { accountId: identity.accountId, entries: identity.entries };
}

async function revokePasskeyOwnerInBrowser(
  input: BrowserPasskeyRevocationInput,
): Promise<BrowserPasskeyRevocationResult> {
  const normalizedCredentialId = input.actorCredentialIdB64u.replace(/-/g, '+').replace(/_/g, '/');
  const paddedCredentialId = normalizedCredentialId.padEnd(
    normalizedCredentialId.length + ((4 - (normalizedCredentialId.length % 4)) % 4),
    '=',
  );
  const decodedCredentialId = globalThis.atob(paddedCredentialId);
  const allowCredentialId = new Uint8Array(decodedCredentialId.length);
  for (let index = 0; index < decodedCredentialId.length; index += 1) {
    allowCredentialId[index] = decodedCredentialId.charCodeAt(index);
  }

  const challenge = globalThis.crypto.getRandomValues(new Uint8Array(32));
  let challengeBinary = '';
  for (const value of challenge) challengeBinary += String.fromCharCode(value);
  const expectedChallengeDigestB64u = globalThis
    .btoa(challengeBinary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
  const rawCredential = await navigator.credentials.get({
    publicKey: {
      allowCredentials: [{ id: allowCredentialId, type: 'public-key' }],
      challenge,
      rpId: input.rpId,
      userVerification: 'required',
    },
  });
  if (!(rawCredential instanceof PublicKeyCredential)) {
    throw new Error('Owner revocation did not return a WebAuthn credential');
  }
  const serializableCredential = rawCredential as PublicKeyCredential & {
    toJSON(): unknown;
  };
  const response = await fetch(input.endpoint, {
    body: JSON.stringify({
      auth: {
        kind: 'webauthn_assertion',
        rpId: input.rpId,
        credential: serializableCredential.toJSON(),
        expectedChallengeDigestB64u,
      },
      target: {
        kind: 'passkey',
        rpId: input.rpId,
        credentialIdB64u: input.targetCredentialIdB64u,
      },
    }),
    headers: { 'content-type': 'application/json' },
    method: 'POST',
  });
  return { body: await response.json(), status: response.status };
}

async function revokeOwner(
  page: Page,
  actor: OwnerCredentialSnapshot,
  target: OwnerCredentialSnapshot,
): Promise<void> {
  const result = await attemptRevokeOwner(page, actor, target);
  const body = requireRecord(result.body, 'auth-method revoke response');
  if (result.status !== 200 || body.ok !== true) {
    throw new Error(`Owner revocation failed (${result.status}): ${JSON.stringify(result.body)}`);
  }
}

async function attemptRevokeOwner(
  page: Page,
  actor: OwnerCredentialSnapshot,
  target: OwnerCredentialSnapshot,
): Promise<BrowserPasskeyRevocationResult> {
  if (
    actor.walletId !== target.walletId ||
    actor.rpId !== target.rpId ||
    actor.routerOrigin !== target.routerOrigin
  ) {
    throw new Error('Owner revocation identities do not describe the same wallet deployment');
  }
  const endpoint = `${actor.routerOrigin}/wallets/${encodeURIComponent(actor.walletId)}/auth-methods/revoke`;
  const result = await page.evaluate(revokePasskeyOwnerInBrowser, {
    actorCredentialIdB64u: actor.credentialIdB64u,
    endpoint,
    rpId: actor.rpId,
    targetCredentialIdB64u: target.credentialIdB64u,
  });
  return result;
}

function isSuccessfulRevocation(result: BrowserPasskeyRevocationResult): boolean {
  const body = requireRecord(result.body, 'auth-method revoke response');
  return result.status === 200 && body.ok === true;
}

function isFailedRevocation(result: BrowserPasskeyRevocationResult): boolean {
  return result.status !== 200;
}

function ownerCredentialSnapshot(owner: AuthenticatedOwnerSnapshot): OwnerCredentialSnapshot {
  return {
    credentialIdB64u: owner.credentialIdB64u,
    walletId: owner.publicIdentity.walletId,
    routerOrigin: owner.routerOrigin,
    rpId: owner.rpId,
  };
}

async function readActiveWalletId(page: Page): Promise<string> {
  const value = await page
    .locator('.w3a-profile-button-morphable .w3a-user-account--account-id')
    .textContent();
  const walletId = String(value || '').trim();
  if (!walletId) throw new Error('Active owner profile does not expose its wallet id');
  return walletId;
}

async function assertRevokedOwnerCannotUnlock(page: Page): Promise<void> {
  const wallet = await walletFrame(page);
  const unlock = wallet.getByRole('button', { name: 'Sign in with Passkey', exact: true });
  await unlock.waitFor({ state: 'visible', timeout: 30_000 });
  const rejected = page.waitForResponse(isRevokedOwnerUnlockResponse, { timeout: 30_000 });
  await unlock.click();
  const response = await rejected;
  if (isRevokedWalletUnlockResponse(response)) {
    const failure = requireRecord(await response.json(), 'revoked owner wallet unlock response');
    expect(failure).toMatchObject({
      ok: false,
      code: 'custody_envelope_unavailable',
      message: 'Passkey wallet custody is unavailable',
    });
  } else {
    expect(response.ok()).toBe(false);
  }
  await expect(page.locator('.w3a-profile-button-morphable')).toBeHidden();
  await expect(unlock).toBeVisible();
}

async function openLinkedDevicesDialog(page: Page): Promise<Locator> {
  const menu = await openProfileMenu(page);
  const inventoryResponse = page.waitForResponse(isLinkedDeviceInventoryResponse, {
    timeout: 60_000,
  });
  await menu.getByRole('button', { name: /^Linked Devices\b/ }).click();
  const inventory = await inventoryResponse;
  const inventoryBody = await inventory.text();
  expect(inventory.status(), `Linked-devices inventory GET failed: ${inventoryBody}`).toBe(200);
  const dialog = page.getByRole('dialog', { name: 'Your devices', exact: true });
  await dialog.waitFor({ state: 'visible', timeout: 30_000 });
  return dialog;
}

async function readActiveLinkedDeviceInventory(page: Page): Promise<LinkedInventorySnapshot> {
  const menu = await openProfileMenu(page);
  const inventoryResponse = page.waitForResponse(isLinkedDeviceInventoryResponse, {
    timeout: 60_000,
  });
  await menu.getByRole('button', { name: /^Linked Devices\b/ }).click();
  const inventory = await inventoryResponse;
  const body = await inventory.json();
  const parsed = parseLinkedDeviceListResultV1(body);
  const activeDevices = parsed.devices.filter(isActiveLinkedDevice);
  if (activeDevices.length !== 1) {
    throw new Error(`Expected one active linked device, received ${activeDevices.length}`);
  }
  const device = activeDevices[0];
  const snapshot: LinkedInventorySnapshot = {
    authMethodId: String(device.credential.walletAuthMethodId),
    deviceId: String(device.deviceId),
    enrollmentId: String(device.enrollmentId),
    keyManifestDigestB64u: String(device.keyManifestDigestB64u),
    revocationEpoch: device.revocationEpoch,
    state: device.state,
  };
  const dialog = page.getByRole('dialog', { name: 'Your devices', exact: true });
  await dialog.waitFor({ state: 'visible', timeout: 30_000 });
  await dialog.locator('.w3a-linked-devices-modal-close').click();
  await expect(dialog).toBeHidden({ timeout: 10_000 });
  return snapshot;
}

function isActiveLinkedDevice(device: { readonly state: string }): boolean {
  return device.state === 'active';
}

async function assertLinkedDeviceInventoryLoaded(page: Page): Promise<void> {
  const dialog = await openLinkedDevicesDialog(page);
  const cards = dialog.locator('.w3a-linked-devices-modal-item');
  await expect(cards).toHaveCount(1, { timeout: 60_000 });
  await expect(cards.filter({ hasText: 'Email OTP' })).toHaveCount(1);
  await expect(cards.filter({ hasText: 'Can use this wallet' })).toHaveCount(1);
  await dialog.locator('.w3a-linked-devices-modal-close').click();
  await expect(dialog).toBeHidden({ timeout: 10_000 });
}

async function assertPasskeyInventoryLoaded(page: Page, expectedCardCount: number): Promise<void> {
  const dialog = await openLinkedDevicesDialog(page);
  const cards = dialog.locator('.w3a-linked-devices-modal-item');
  await expect(cards).toHaveCount(expectedCardCount, { timeout: 60_000 });
  await expect(dialog.getByText('Can use this wallet', { exact: true })).toHaveCount(
    expectedCardCount,
  );
  await dialog.locator('.w3a-linked-devices-modal-close').click();
  await expect(dialog).toBeHidden({ timeout: 10_000 });
}

async function revokeLinkedEmailDeviceFromUi(page: Page): Promise<void> {
  const dialog = await openLinkedDevicesDialog(page);
  /* Email OTP is an account factor rather than a device identity. The device
     inventory therefore contains only the durable linked enrollment. */
  const cards = dialog.locator('.w3a-linked-devices-modal-item');
  await expect(cards).toHaveCount(1, { timeout: 60_000 });
  await expect(cards.filter({ hasText: 'Email OTP' })).toHaveCount(1);
  await expect(cards.filter({ hasText: 'Can use this wallet' })).toHaveCount(1);
  const remove = dialog.getByRole('button', {
    name: /^Remove Device \d+, Email OTP \(ID /,
  });
  await expect(remove).toHaveCount(1, { timeout: 30_000 });
  await remove.click();
  await dialog.getByRole('button', { name: 'Yes, remove', exact: true }).click();
  await expect(dialog.getByRole('status')).toContainText('can no longer use this wallet', {
    timeout: 60_000,
  });
  await expect(cards).toHaveCount(0, { timeout: 60_000 });
  await expect(dialog).toContainText('No other devices are using this wallet.');
  await dialog.locator('.w3a-linked-devices-modal-close').click();
  await expect(dialog).toBeHidden({ timeout: 10_000 });
}

function isLinkedDeviceEmailOtpChallengeResponse(response: Response): boolean {
  return (
    response.request().method() === 'POST' &&
    new URL(response.url()).pathname.endsWith('/email-otp/challenge')
  );
}

function isLinkedDeviceInventoryResponse(response: Response): boolean {
  return (
    response.request().method() === 'GET' &&
    new URL(response.url()).pathname === '/wallet/device-linking/v1/devices'
  );
}

function isLinkedDeviceActionResponse(
  response: Response,
  action: string,
  method: 'GET' | 'POST',
): boolean {
  return (
    response.request().method() === method &&
    response.status() === 200 &&
    new URL(response.url()).pathname.endsWith(`/${action}`)
  );
}

function isLinkedDeviceOwnerApprovalResponse(response: Response): boolean {
  return isLinkedDeviceActionResponse(response, 'approval', 'POST');
}

function isLinkedDeviceTargetPreparationResponse(response: Response): boolean {
  return isLinkedDeviceActionResponse(response, 'target-preparation', 'GET');
}

function isLinkedDeviceEmailOtpVerificationResponse(response: Response): boolean {
  return isLinkedDeviceActionResponse(response, 'email-otp/challenge/verify', 'POST');
}

function isLinkedDeviceSessionProjectionResponse(response: Response): boolean {
  const pathname = new URL(response.url()).pathname;
  const prefix = '/wallet/device-linking/v1/sessions/';
  const suffix = pathname.startsWith(prefix) ? pathname.slice(prefix.length) : '';
  return (
    response.request().method() === 'GET' &&
    response.status() === 200 &&
    suffix.length > 0 &&
    !suffix.includes('/')
  );
}

async function isActiveLinkedDeviceSessionResponse(response: Response): Promise<boolean> {
  if (!isLinkedDeviceSessionProjectionResponse(response)) return false;
  try {
    const envelope = requireRecord(await response.json(), 'linked-device session response');
    return parseLinkSessionProjectionV1(envelope.session).state.state === 'active';
  } catch {
    return false;
  }
}

async function isCommittedAuthorityPackagesResponse(response: Response): Promise<boolean> {
  if (
    response.request().method() !== 'GET' ||
    response.status() !== 200 ||
    !new URL(response.url()).pathname.endsWith('/approval')
  ) {
    return false;
  }
  try {
    parseCommittedAuthorityPackagesV1(await response.json());
    return true;
  } catch {
    return false;
  }
}

function isAuthorityActivationResponse(response: Response): boolean {
  return isLinkedDeviceActionResponse(response, 'receipt', 'POST');
}

function isAuthorityActivationAcknowledgementResponse(response: Response): boolean {
  return (
    response.request().method() === 'POST' &&
    response.status() === 204 &&
    new URL(response.url()).pathname.endsWith('/receipt')
  );
}

function parseActiveLinkedSessionSnapshot(
  raw: unknown,
  label: string,
): {
  readonly linkSessionId: string;
  readonly authorityId: string;
  readonly deviceId: string;
} {
  const envelope = requireRecord(raw, label);
  const projection = parseLinkSessionProjectionV1(envelope.session);
  if (projection.state.state !== 'active') {
    throw new Error(`${label}.session.state must be active`);
  }
  return {
    linkSessionId: String(projection.linkSessionId),
    authorityId: String(projection.state.authorityId),
    deviceId: String(projection.state.deviceId),
  };
}

/** The QR v5 create request carries the factor choice; find its discriminator. */
function findTargetFactorKind(value: unknown): string | null {
  if (Array.isArray(value)) {
    for (const entry of value) {
      const found = findTargetFactorKind(entry);
      if (found) return found;
    }
    return null;
  }
  if (!isRecord(value)) return null;
  const targetFactor = value.targetFactor;
  if (isRecord(targetFactor) && typeof targetFactor.kind === 'string') return targetFactor.kind;
  for (const child of Object.values(value)) {
    const found = findTargetFactorKind(child);
    if (found) return found;
  }
  return null;
}

async function setupEmailLinkedOwnerPair(browser: Browser): Promise<EmailLinkedOwnerPair> {
  emailLinkedDeviceStage('creating browser contexts');
  const ownerContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const device2Context = await browser.newContext({ ignoreHTTPSErrors: true });
  await ownerContext.route(/https:\/\/[^/]*(?:near\.org|fastnear\.com)\//, fulfillNearRpc);
  await ownerContext.route(/https:\/\/[^/]*arc\.network\//, fulfillArcRpc);
  await device2Context.route(/https:\/\/[^/]*(?:near\.org|fastnear\.com)\//, fulfillNearRpc);
  await device2Context.route(/https:\/\/[^/]*arc\.network\//, fulfillArcRpc);
  await ownerContext.addInitScript(enableSigningSessionDiagnostics);
  await device2Context.addInitScript(enableSigningSessionDiagnostics);
  await ownerContext.addInitScript(installGoogleIdentityStub, requireGoogleIdToken());
  await device2Context.addInitScript(installGoogleIdentityStub, requireGoogleIdToken());
  const ownerPage = await ownerContext.newPage();
  const device2Page = await device2Context.newPage();
  device2Page.on('framenavigated', (frame) => {
    if (frame === device2Page.mainFrame()) {
      console.log(`[email-linked-device] Device 2 navigated to ${frame.url()}`);
    }
  });
  /* Virtual authenticators exist here only as tripwires: the Email OTP branch
     must never create or assert a WebAuthn credential on either device. */
  const ownerAuthenticator = await addVirtualAuthenticator(ownerPage);
  const device2Authenticator = await addVirtualAuthenticator(device2Page);
  const webauthnOperations: string[] = [];
  ownerAuthenticator.on('WebAuthn.credentialAdded', () => {
    webauthnOperations.push('owner:credential_added');
  });
  ownerAuthenticator.on('WebAuthn.credentialAsserted', () => {
    webauthnOperations.push('owner:credential_asserted');
  });
  device2Authenticator.on('WebAuthn.credentialAdded', () => {
    webauthnOperations.push('device2:credential_added');
  });
  device2Authenticator.on('WebAuthn.credentialAsserted', () => {
    webauthnOperations.push('device2:credential_asserted');
  });
  const ownerDiagnostics: string[] = [];
  const device2Diagnostics: string[] = [];
  let emailChallengeStarts = 0;
  let emailChallengeResends = 0;
  device2Page.on('request', (request) => {
    if (request.isNavigationRequest() && request.frame() === device2Page.mainFrame()) {
      console.log(
        `[email-linked-device] Device 2 main-frame request ${request.method()} ${request.url()}`,
      );
    }
    if (request.method() !== 'POST') return;
    let pathname: string;
    try {
      pathname = new URL(request.url()).pathname;
    } catch {
      return;
    }
    if (pathname.endsWith('/email-otp/challenge')) emailChallengeStarts += 1;
    if (pathname.endsWith('/email-otp/challenge/resend')) emailChallengeResends += 1;
  });
  device2Page.on('response', (response) => {
    let pathname: string;
    try {
      pathname = new URL(response.url()).pathname;
    } catch {
      return;
    }
    if (pathname.includes('/wallet/device-linking/')) {
      device2Diagnostics.push(
        `[device2:linking] ${response.status()} ${response.request().method()} ${pathname}`,
      );
    }
  });
  try {
    ownerPage.on('console', (message) => {
      const diagnostic = linkedDeviceConsoleDiagnostic(message);
      if (diagnostic) {
        ownerDiagnostics.push(diagnostic);
        if (message.type() === 'error') console.log(diagnostic);
      }
    });
    device2Page.on('console', (message) => {
      const text = message.text().replace(/\s+/g, ' ').trim().slice(0, 400);
      if (text.includes('[SigningLanes][active-ecdsa')) console.log(text);
      if (
        message.type() === 'error' ||
        /Device[12]Linking|linked-device|WalletSession|email|otp|bridge/i.test(text)
      ) {
        const diagnostic = `[device2:${message.type()}] ${text}`;
        device2Diagnostics.push(diagnostic);
        if (/\[Device2Linking\] failed/.test(text)) console.log(diagnostic);
      }
    });
    const publicIdentity = await registerEmailOwner(ownerPage, ownerContext);
    emailLinkedDeviceStage('opening Device 2 QR');
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
    const qrDataUrl = await openDevice2Qr(device2Page, 'Email code');
    const createdResponse = await created.catch((error: unknown) => {
      throw new Error(
        `Device 2 did not create an email-factor link session.\n${device2Diagnostics.join('\n')}`,
        { cause: error },
      );
    });
    /* The email factor was chosen before the QR existed: the session-create
       request itself carries the discriminator. */
    expect(findTargetFactorKind(createdResponse.request().postDataJSON())).toBe('email_otp');
    const ownerApproval = ownerPage.waitForResponse(isLinkedDeviceOwnerApprovalResponse, {
      timeout: 180_000,
    });
    const targetPreparation = device2Page.waitForResponse(isLinkedDeviceTargetPreparationResponse, {
      timeout: 180_000,
    });
    const emailOtpVerification = device2Page.waitForResponse(
      isLinkedDeviceEmailOtpVerificationResponse,
      { timeout: 180_000 },
    );
    const committedPackages = device2Page.waitForResponse(isCommittedAuthorityPackagesResponse, {
      timeout: 240_000,
    });
    const authorityActivation = device2Page.waitForResponse(isAuthorityActivationResponse, {
      timeout: 240_000,
    });
    const activationAcknowledgement = device2Page.waitForResponse(
      isAuthorityActivationAcknowledgementResponse,
      { timeout: 240_000 },
    );
    const activeSession = device2Page.waitForResponse(isActiveLinkedDeviceSessionResponse, {
      timeout: 240_000,
    });
    const claimed = ownerPage.waitForResponse(
      (response) =>
        response.request().method() === 'POST' &&
        new URL(response.url()).pathname.endsWith('/claim'),
      { timeout: 90_000 },
    );
    const emailChallenge = device2Page.waitForResponse(isLinkedDeviceEmailOtpChallengeResponse, {
      timeout: 120_000,
    });
    const targetCredentialCommit = device2Page.waitForResponse(
      (response) =>
        response.status() === 200 &&
        response.request().method() === 'POST' &&
        new URL(response.url()).pathname.endsWith('/credential'),
      { timeout: 180_000 },
    );
    await openOwnerScanner(ownerPage, qrDataUrl);
    emailLinkedDeviceStage('owner scanned Device 2 QR');
    const claimResponse = await completeEmailOtpPromptsUntil({
      page: ownerPage,
      context: ownerContext,
      walletId: publicIdentity.walletId,
      task: claimed,
    }).catch((error: unknown) => {
      throw new Error(
        `Owner did not claim the email-factor link session.\n${ownerDiagnostics.join('\n')}\n${device2Diagnostics.join('\n')}`,
        { cause: error },
      );
    });
    if (!claimResponse.ok()) {
      throw new Error(
        `Email linked-device claim failed (${claimResponse.status()}): ${await claimResponse.text()}`,
      );
    }
    const approvalResponse = await ownerApproval;
    expect(approvalResponse.ok()).toBe(true);
    const approval = requireRecord(
      await approvalResponse.json(),
      'Email linked-device approval response',
    );
    expect(approval.outcome).toBe('pending');
    const approvalState = parseLinkSessionStateV1(approval.state);
    if (approvalState.state !== 'awaiting_target_factor') {
      throw new Error('Email linked-device approval did not persist an awaiting target factor');
    }

    const challengeResponse = await emailChallenge;
    emailLinkedDeviceStage('Device 2 received Email OTP challenge');
    if (!challengeResponse.ok()) {
      throw new Error(
        `Email linked-device challenge failed (${challengeResponse.status()}): ${await challengeResponse.text()}`,
      );
    }
    const challenge = requireRecord(
      await challengeResponse.json(),
      'Email linked-device challenge response',
    );
    const challengeId = requireStringField(
      challenge,
      'challengeId',
      'Email linked-device challenge response',
    );
    /* The challenge names the base enrollment it protects. */
    requireStringField(challenge, 'maskedEmailHint', 'Email linked-device challenge response');
    const preparationResponse = await targetPreparation;
    const preparation = parseLinkedDeviceTargetPreparationV1(await preparationResponse.json());
    expect(preparation.walletId).toBe(publicIdentity.walletId);
    expect(preparation.targetFactor.kind).toBe('email_otp');
    expect(preparation.ordinarySignerMaterialRecipientRequirements.length).toBeGreaterThan(0);
    const device2Wallet = await walletFrame(device2Page);
    const otpInput = device2Wallet.getByRole('textbox', { name: 'Email verification code' });
    await otpInput.waitFor({ state: 'visible', timeout: 120_000 });
    const otpCode = await readEmailOtpOutboxCode({
      context: device2Context,
      walletId: publicIdentity.walletId,
      challengeId,
    });
    await otpInput.fill(otpCode);
    const verificationResponse = await emailOtpVerification;
    if (!verificationResponse.ok()) {
      throw new Error(
        `Email linked-device OTP verification failed (${verificationResponse.status()}): ${await verificationResponse.text()}`,
      );
    }
    const verification = parseLinkedDeviceEmailOtpVerificationResultV1(
      await verificationResponse.json(),
    );
    expect(verification.verificationGrant.challengeId).toBe(challengeId);
    expect(verification.verificationGrant.walletId).toBe(publicIdentity.walletId);
    expect(verification.factorRelease.challengeId).toBe(challengeId);
    const credentialCommitted = await targetCredentialCommit;
    emailLinkedDeviceStage('Device 2 submitted Email OTP');
    if (!credentialCommitted.ok()) {
      throw new Error(
        `Email linked-device credential commit failed (${credentialCommitted.status()}): ${await credentialCommitted.text()}`,
      );
    }
    const credentialResponse = requireRecord(
      await credentialCommitted.json(),
      'Email linked-device credential response',
    );
    const targetCredential = parseLinkedDeviceTargetCredentialRegistrationResultV1(
      credentialResponse.targetCredential,
    );
    expect(targetCredential.walletId).toBe(publicIdentity.walletId);
    expect(targetCredential.targetFactor.kind).toBe('verified_email_otp_target_v1');
    expect(targetCredential.ordinarySignerMaterialPreparations.length).toBeGreaterThan(0);
    expect(targetCredential.ordinarySignerMaterialRecipientRequests.length).toBe(
      preparation.ordinarySignerMaterialRecipientRequirements.length,
    );
    /* The emailed code is the only target-factor proof: linking sent exactly
       one challenge, never a resend, and neither device touched WebAuthn. */
    expect(emailChallengeStarts).toBe(1);
    expect(emailChallengeResends).toBe(0);
    expect(webauthnOperations).toEqual([]);
    const committed = parseCommittedAuthorityPackagesV1(await (await committedPackages).json());
    expect(committed.authority.walletId).toBe(publicIdentity.walletId);
    const activated = parseActivateInstalledAuthorityResultV1(
      await (await authorityActivation).json(),
    );
    expect(activated.kind).toBe('active');
    expect(activated.walletSession.walletId).toBe(publicIdentity.walletId);
    const acknowledgementResponse = await activationAcknowledgement;
    expect(acknowledgementResponse.status()).toBe(204);
    const acknowledgement = parseLocalAuthorityActivationFinalAckV1(
      acknowledgementResponse.request().postDataJSON(),
    );
    expect(acknowledgement.linkSessionId).toBe(preparation.linkSessionId);
    expect(acknowledgement.authorityId).toBe(activated.walletSession.authorityId);
    expect(acknowledgement.packageSetDigestB64u).toBe(committed.packageSetDigestB64u);
    expect(acknowledgement.authorizationId).toBe(activated.walletSession.authorizationId);
    const activeSessionResponse = await activeSession;
    const activeSessionSnapshot = parseActiveLinkedSessionSnapshot(
      await activeSessionResponse.json(),
      'active linked-device session response',
    );
    expect(activeSessionSnapshot.linkSessionId).toBe(String(preparation.linkSessionId));
    expect(activeSessionSnapshot.authorityId).toBe(String(activated.authority.authorityId));
    expect(activeSessionSnapshot.deviceId).toBe(String(committed.authority.principal.deviceId));
    await waitForLinkedDeviceActive(device2Page, device2Diagnostics, ownerDiagnostics);
    await device2Page.goto(`${appOrigin}/wallet`, { waitUntil: 'domcontentloaded' });
    await device2Page
      .locator('.w3a-profile-button-morphable')
      .waitFor({ state: 'visible', timeout: 120_000 });
    await device2Page.reload({ waitUntil: 'domcontentloaded' });
    await device2Page
      .locator('.w3a-profile-button-morphable')
      .waitFor({ state: 'visible', timeout: 120_000 });
    await lockActiveWallet(device2Page);
    emailLinkedDeviceStage('unlocking Device 2 after reload');
    await unlockEmailOtpWallet(device2Page, device2Context, publicIdentity.walletId);
    emailLinkedDeviceStage('Device 2 unlock complete');
    await assertOwnerProfileRows(device2Page);
    emailLinkedDeviceStage('Device 2 owner controls enabled');
    expect(await readActiveWalletId(device2Page)).toBe(publicIdentity.walletId);
    return {
      ownerContext,
      device2Context,
      ownerPage,
      device2Page,
      ownerDiagnostics,
      device2Diagnostics,
      publicIdentity,
    };
  } catch (error) {
    await closeBrowserContexts(ownerContext, device2Context);
    throw error;
  }
}

async function setupLinkedOwnerPair(browser: Browser): Promise<LinkedOwnerPair> {
  const ownerContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const device2Context = await browser.newContext({ ignoreHTTPSErrors: true });
  await ownerContext.route(/https:\/\/[^/]*(?:near\.org|fastnear\.com)\//, fulfillNearRpc);
  await ownerContext.route(/https:\/\/[^/]*arc\.network\//, fulfillArcRpc);
  await device2Context.route(/https:\/\/[^/]*(?:near\.org|fastnear\.com)\//, fulfillNearRpc);
  await device2Context.route(/https:\/\/[^/]*arc\.network\//, fulfillArcRpc);
  await ownerContext.addInitScript(enableSigningSessionDiagnostics);
  await device2Context.addInitScript(enableSigningSessionDiagnostics);
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
      if (text.includes('[SigningLanes][active-ecdsa')) console.log(text);
      if (
        message.type() === 'error' ||
        /linked-device|WalletSession|WebAuthn|bridge|passkey/i.test(text)
      ) {
        device2Diagnostics.push(`[device2:${message.type()}] ${text}`);
      }
    });
    const owner = await registerOwner(ownerPage, ownerDiagnostics);
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
    const qrDataUrl = await openDevice2Qr(device2Page, 'Passkey');
    await created;
    const targetPreparation = device2Page.waitForResponse(isLinkedDeviceTargetPreparationResponse, {
      timeout: 180_000,
    });
    const targetCredentialCommit = device2Page.waitForResponse(
      (response) =>
        response.status() === 200 &&
        response.request().method() === 'POST' &&
        new URL(response.url()).pathname.endsWith('/credential'),
      { timeout: 180_000 },
    );
    const committedPackages = device2Page.waitForResponse(isCommittedAuthorityPackagesResponse, {
      timeout: 240_000,
    });
    const authorityActivation = device2Page.waitForResponse(isAuthorityActivationResponse, {
      timeout: 240_000,
    });
    const activationAcknowledgement = device2Page.waitForResponse(
      isAuthorityActivationAcknowledgementResponse,
      { timeout: 240_000 },
    );
    const activeSession = device2Page.waitForResponse(isActiveLinkedDeviceSessionResponse, {
      timeout: 240_000,
    });
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
    const preparationResponse = await targetPreparation;
    const preparation = parseLinkedDeviceTargetPreparationV1(await preparationResponse.json());
    expect(preparation.walletId).toBe(owner.publicIdentity.walletId);
    expect(preparation.targetFactor.kind).toBe('passkey_prf');
    expect(preparation.passkeyCreationOptions.walletAuthMethodId).toBe(
      preparation.walletAuthMethodId,
    );
    expect(preparation.ordinarySignerMaterialRecipientRequirements.length).toBeGreaterThan(0);
    const credentialCommitted = await targetCredentialCommit;
    if (!credentialCommitted.ok()) {
      throw new Error(
        `Passkey linked-device credential commit failed (${credentialCommitted.status()}): ${await credentialCommitted.text()}`,
      );
    }
    const credentialResponse = requireRecord(
      await credentialCommitted.json(),
      'Passkey linked-device credential response',
    );
    const targetCredential = parseLinkedDeviceTargetCredentialRegistrationResultV1(
      credentialResponse.targetCredential,
    );
    expect(targetCredential.walletId).toBe(owner.publicIdentity.walletId);
    expect(targetCredential.targetFactor.kind).toBe('verified_passkey_target_v1');
    expect(targetCredential.ordinarySignerMaterialPreparations.length).toBeGreaterThan(0);
    expect(targetCredential.ordinarySignerMaterialRecipientRequests.length).toBe(
      preparation.ordinarySignerMaterialRecipientRequirements.length,
    );
    await expect(device2Wallet.getByText('Generating QR code', { exact: false })).toBeHidden();
    expect(ownerCredentialAddedEvents.length).toBeGreaterThan(0);
    /* The owner scanner is the sole approval action. Device 2 creates exactly
       one target passkey, and Device 1 performs no WebAuthn operation. */
    expect(
      ownerCredentialAssertedEvents.slice(ownerCredentialAssertionsBeforeLinking),
    ).toHaveLength(0);
    expect(ownerCredentialAddedEvents.slice(ownerCredentialCreationsBeforeLinking)).toHaveLength(0);
    expect(device2CredentialAddedEvents).toHaveLength(1);
    const committed = parseCommittedAuthorityPackagesV1(await (await committedPackages).json());
    expect(committed.authority.walletId).toBe(owner.publicIdentity.walletId);
    const activated = parseActivateInstalledAuthorityResultV1(
      await (await authorityActivation).json(),
    );
    expect(activated.kind).toBe('active');
    expect(activated.walletSession.walletId).toBe(owner.publicIdentity.walletId);
    const acknowledgementResponse = await activationAcknowledgement;
    expect(acknowledgementResponse.status()).toBe(204);
    const acknowledgement = parseLocalAuthorityActivationFinalAckV1(
      acknowledgementResponse.request().postDataJSON(),
    );
    expect(acknowledgement.linkSessionId).toBe(preparation.linkSessionId);
    expect(acknowledgement.authorityId).toBe(activated.walletSession.authorityId);
    expect(acknowledgement.packageSetDigestB64u).toBe(committed.packageSetDigestB64u);
    expect(acknowledgement.authorizationId).toBe(activated.walletSession.authorizationId);
    await activeSession;
    await waitForLinkedDeviceActive(device2Page, device2Diagnostics, ownerDiagnostics);
    const activation: LinkedActivationSnapshot = {
      authMethodId: String(committed.authMethod.walletAuthMethodId),
      authorizationId: String(activated.walletSession.authorizationId),
      authorityId: String(activated.authority.authorityId),
      deviceId: String(committed.authority.principal.deviceId),
      linkSessionId: String(preparation.linkSessionId),
      packageSetDigestB64u: String(committed.packageSetDigestB64u),
    };
    expect(activation.authorityId).toBe(String(acknowledgement.authorityId));
    expect(activation.packageSetDigestB64u).toBe(String(acknowledgement.packageSetDigestB64u));
    const inventoryBeforeReload = await readActiveLinkedDeviceInventory(ownerPage);
    expect(inventoryBeforeReload.deviceId).toBe(activation.deviceId);
    expect(inventoryBeforeReload.authMethodId).toBe(activation.authMethodId);
    const expectedDevice2: AuthenticatedOwnerSnapshot = {
      credentialIdB64u: credentialIdB64uFromAddedEvent(device2CredentialAddedEvents[0]),
      publicIdentity: owner.publicIdentity,
      routerOrigin: owner.routerOrigin,
      rpId: owner.rpId,
    };
    await device2Page.reload({ waitUntil: 'domcontentloaded' });
    await unlockLinkedPasskeyWallet(device2Page, device2Diagnostics);
    await lockWallet(device2Page);
    await unlockLinkedPasskeyWallet(device2Page, device2Diagnostics);
    await assertOwnerProfileRows(device2Page);
    const device2WalletId = await readActiveWalletId(device2Page);
    expect(device2WalletId).toBe(owner.publicIdentity.walletId);
    const inventoryAfterReload = await readActiveLinkedDeviceInventory(ownerPage);
    expect(inventoryAfterReload).toEqual(inventoryBeforeReload);
    expect(inventoryAfterReload.deviceId).toBe(activation.deviceId);
    expect(inventoryAfterReload.authMethodId).toBe(activation.authMethodId);
    expect(inventoryAfterReload.keyManifestDigestB64u).toBe(
      inventoryBeforeReload.keyManifestDigestB64u,
    );
    const device2 = ownerCredentialSnapshot(expectedDevice2);
    return {
      ownerContext,
      device2Context,
      ownerPage,
      device2Page,
      ownerDiagnostics,
      device2Diagnostics,
      owner,
      device2,
      activation,
    };
  } catch (error) {
    await closeBrowserContexts(ownerContext, device2Context);
    throw error;
  }
}

test('Device 1 revokes Device 2 while preserving wallet identity and owner operation', async ({
  browser,
}) => {
  const pair = await setupLinkedOwnerPair(browser);
  try {
    const device2Near = await exportOwnerKey(pair.device2Page, 'near', pair.device2Diagnostics);
    expect(device2Near.accountId).toBe(pair.owner.publicIdentity.nearAccountId);
    expect(device2Near.entries.map((entry) => entry.publicKey)).toEqual([
      pair.owner.publicIdentity.nearPublicKey,
    ]);
    const device2Evm = await exportOwnerKey(pair.device2Page, 'evm', pair.device2Diagnostics);
    const device2EcdsaKeys = device2Evm.entries
      .map((entry) => `${entry.publicKey.toLowerCase()}:${entry.address.toLowerCase()}`)
      .sort();
    expect(device2EcdsaKeys).toEqual(pair.owner.publicIdentity.ecdsaKeys);
    await lockWallet(pair.device2Page);
    await revokeOwner(pair.ownerPage, ownerCredentialSnapshot(pair.owner), pair.device2);
    await assertRevokedOwnerCannotUnlock(pair.device2Page);
    await linkedSigning(pair.ownerPage, pair.ownerDiagnostics);
  } finally {
    await closeBrowserContexts(pair.ownerContext, pair.device2Context);
  }
});

test('Device 2 revokes Device 1 while preserving Device 2 operation', async ({ browser }) => {
  const pair = await setupLinkedOwnerPair(browser);
  try {
    await lockWallet(pair.ownerPage);
    await revokeOwner(pair.device2Page, pair.device2, ownerCredentialSnapshot(pair.owner));
    await assertRevokedOwnerCannotUnlock(pair.ownerPage);
    await linkedSigning(pair.device2Page, pair.device2Diagnostics);
  } finally {
    await closeBrowserContexts(pair.ownerContext, pair.device2Context);
  }
});

test('final active auth method refuses self-revocation without changing the owner', async ({
  browser,
}) => {
  const pair = await setupLinkedOwnerPair(browser);
  try {
    await revokeOwner(pair.ownerPage, ownerCredentialSnapshot(pair.owner), pair.device2);
    await assertPasskeyInventoryLoaded(pair.ownerPage, 1);

    const finalMethodAttempt = await attemptRevokeOwner(
      pair.ownerPage,
      ownerCredentialSnapshot(pair.owner),
      ownerCredentialSnapshot(pair.owner),
    );
    const failure = requireRecord(finalMethodAttempt.body, 'final-method revoke response');
    expect(finalMethodAttempt.status).toBe(401);
    expect(failure).toMatchObject({
      ok: false,
      code: 'unauthorized',
    });
    expect(String(failure.message)).toMatch(/different active|different.*method/i);

    await lockWallet(pair.device2Page);
    await assertRevokedOwnerCannotUnlock(pair.device2Page);
    await linkedSigning(pair.ownerPage, pair.ownerDiagnostics);
    await assertPasskeyInventoryLoaded(pair.ownerPage, 1);
  } finally {
    await closeBrowserContexts(pair.ownerContext, pair.device2Context);
  }
});

test('competing revocations of the final two methods serialize to one survivor', async ({
  browser,
}) => {
  const pair = await setupLinkedOwnerPair(browser);
  try {
    const [ownerRevocation, device2Revocation] = await Promise.all([
      attemptRevokeOwner(pair.ownerPage, ownerCredentialSnapshot(pair.owner), pair.device2),
      attemptRevokeOwner(pair.device2Page, pair.device2, ownerCredentialSnapshot(pair.owner)),
    ]);
    const results = [ownerRevocation, device2Revocation];
    const successful = results.filter(isSuccessfulRevocation);
    expect(successful).toHaveLength(1);
    const failed = results.filter(isFailedRevocation);
    expect(failed).toHaveLength(1);
    const failedBody = requireRecord(failed[0].body, 'concurrent revoke failure response');
    expect(failedBody.ok).toBe(false);
    expect(['conflict', 'invalid_state', 'unauthorized']).toContain(failedBody.code);

    const ownerWon = ownerRevocation.status === 200;
    const survivorPage = ownerWon ? pair.ownerPage : pair.device2Page;
    const revokedPage = ownerWon ? pair.device2Page : pair.ownerPage;
    const survivorCredential = ownerWon ? ownerCredentialSnapshot(pair.owner) : pair.device2;
    const survivorDiagnostics = ownerWon ? pair.ownerDiagnostics : pair.device2Diagnostics;
    await lockWallet(revokedPage);
    await assertRevokedOwnerCannotUnlock(revokedPage);
    await lockWallet(survivorPage);
    await unlockLinkedPasskeyWallet(survivorPage, survivorDiagnostics);
    await linkedSigning(survivorPage, survivorDiagnostics);
    await assertPasskeyInventoryLoaded(survivorPage, 1);
    expect(survivorCredential.walletId).toBe(pair.owner.publicIdentity.walletId);
  } finally {
    await closeBrowserContexts(pair.ownerContext, pair.device2Context);
  }
});

test('linked authority IDs and digests remain exact across the browser reload retry', async ({
  browser,
}) => {
  const pair = await setupLinkedOwnerPair(browser);
  try {
    expect(pair.activation.linkSessionId).toBeTruthy();
    expect(pair.activation.authorityId).toBeTruthy();
    expect(pair.activation.authMethodId).toBeTruthy();
    expect(pair.activation.deviceId).toBeTruthy();
    expect(pair.activation.packageSetDigestB64u).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(pair.activation.authorizationId).toBeTruthy();
    await assertPasskeyInventoryLoaded(pair.ownerPage, 2);
    await linkedSigning(pair.device2Page, pair.device2Diagnostics);
  } finally {
    await closeBrowserContexts(pair.ownerContext, pair.device2Context);
  }
});

test('Email OTP owner links, restores, exports, signs, and revokes Device 2', async ({
  browser,
}) => {
  const pair = await setupEmailLinkedOwnerPair(browser);
  emailLinkedDeviceStage('linked pair ready');
  const emailOtp = {
    context: pair.device2Context,
    walletId: pair.publicIdentity.walletId,
  } as const;
  try {
    await assertLinkedDeviceInventoryLoaded(pair.ownerPage);
    const device2Near = await exportOwnerKey(
      pair.device2Page,
      'near',
      pair.device2Diagnostics,
      emailOtp,
    );
    emailLinkedDeviceStage('Device 2 NEAR export complete');
    expect(device2Near.accountId).toBe(pair.publicIdentity.nearAccountId);
    expect(device2Near.entries.map((entry) => entry.publicKey)).toEqual([
      pair.publicIdentity.nearPublicKey,
    ]);
    const device2Evm = await exportOwnerKey(
      pair.device2Page,
      'evm',
      pair.device2Diagnostics,
      emailOtp,
    );
    emailLinkedDeviceStage('Device 2 EVM export complete');
    expect(
      device2Evm.entries
        .map((entry) => `${entry.publicKey.toLowerCase()}:${entry.address.toLowerCase()}`)
        .sort(),
    ).toEqual(pair.publicIdentity.ecdsaKeys);
    await linkedSigning(pair.device2Page, pair.device2Diagnostics, emailOtp);
    await greetingSigning(pair.device2Page, 'Arc', pair.device2Diagnostics, emailOtp);
    await greetingSigning(pair.device2Page, 'NEAR', pair.device2Diagnostics, emailOtp);
    emailLinkedDeviceStage('Device 2 signing complete');
    await revokeLinkedEmailDeviceFromUi(pair.ownerPage);
    emailLinkedDeviceStage('Device 1 revoked Device 2');
    await lockActiveWallet(pair.device2Page);
    await expect(
      unlockEmailOtpWallet(pair.device2Page, pair.device2Context, pair.publicIdentity.walletId),
    ).rejects.toThrow();
    /* A reload must not resurrect the revoked enrollment either: the linked
       session cannot restore, so Device 2 lands back on sign-in. */
    await pair.device2Page.goto(`${appOrigin}/wallet`, { waitUntil: 'domcontentloaded' });
    const device2WalletAfterRevoke = await walletFrame(pair.device2Page);
    await device2WalletAfterRevoke
      .locator('button[data-auth-menu-primary], button[data-auth-menu-mode]')
      .first()
      .waitFor({ state: 'visible', timeout: 120_000 });
    await expect(pair.device2Page.locator('.w3a-profile-button-morphable')).toBeHidden();
    /* The base Email OTP factor stays fully operational for the owner. */
    await linkedSigning(pair.ownerPage, pair.ownerDiagnostics, {
      context: pair.ownerContext,
      walletId: pair.publicIdentity.walletId,
    });
  } finally {
    await closeBrowserContexts(pair.ownerContext, pair.device2Context);
  }
});
