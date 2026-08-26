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
  type Request,
  type Response,
  type Route,
} from '@playwright/test';
import { Buffer } from 'node:buffer';
import * as fs from 'node:fs';
import path from 'node:path';
import {
  parseActivateInstalledAuthorityResultV1,
  parseCommittedAuthorityPackagesV1,
  parseLinkedDeviceEmailOtpVerificationResultV1,
  parseLinkedDeviceListResultV1,
  parseLocalAuthorityActivationFinalAckV1,
  parseLinkedDeviceTargetCredentialRegistrationResultV1,
  parseLinkSessionStateV1,
  parseLinkedDeviceTargetPreparationV1,
} from '@shared/device-linking';
import { parseWalletAuthMethodId, parseWalletId } from '@shared/utils/domainIds';
import {
  computeWalletAuthMethodRevokeOperationFingerprintV1,
  type RegistrationSignerSetSelection,
} from '@shared/utils/registrationIntent';
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
const localRouterOrigin = 'https://localhost:4004';
const linkedDeviceTransitionTimeoutMs = 60_000;
const arcState = {
  greeting: 'Hello from local Arc',
  transactionInput: '0x' as Hex,
  transactionTo: arcGreetingContract,
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

type SignerProfile = 'ed25519' | 'ecdsa' | 'combined';

const SIGNER_PROFILES: readonly SignerProfile[] = ['ed25519', 'ecdsa', 'combined'];

type WalletPublicIdentity = {
  readonly walletId: string;
  readonly profile: SignerProfile;
  readonly near: {
    readonly accountId: string;
    readonly publicKey: string;
  } | null;
  readonly ecdsaKeys: readonly string[];
};

type RegisteredEmailOwnerIdentity = WalletPublicIdentity & {
  readonly emailAddress: string;
};

type AuthenticatedOwnerSnapshot = {
  readonly credentialIdB64u: string;
  readonly walletAuthMethodId: string;
  readonly publicIdentity: WalletPublicIdentity;
  readonly routerOrigin: string;
  readonly rpId: string;
};

type OwnerCredentialSnapshot = {
  readonly credentialIdB64u: string;
  readonly walletId: string;
  readonly walletAuthMethodId: string;
  readonly routerOrigin: string;
  readonly rpId: string;
};

type WalletAuthMethodRevocationTarget = Omit<OwnerCredentialSnapshot, 'credentialIdB64u'>;

type ExportedPublicIdentity = {
  readonly accountId: string;
  readonly entries: readonly {
    readonly address: string;
    readonly publicKey: string;
    readonly scheme: string;
  }[];
};

type EmailOtpPromptContext = {
  readonly context: BrowserContext;
  readonly walletId: string;
  readonly routerOrigin: string;
  readonly challengeSubjectId?: string;
};

type ExportWaitOutcome =
  | { readonly kind: 'response'; readonly response: Response }
  | { readonly kind: 'terminal-failure'; readonly diagnostic: string };

function emailLinkedDeviceStage(stage: string): void {
  console.info(`[email-linked-device] ${stage}`);
}

function passkeyLinkedDeviceStage(stage: string): void {
  console.info(`[passkey-linked-device] ${stage}`);
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

function parseRegisteredOwnerSnapshot(
  rawActivate: unknown,
  rawNear: unknown,
  routerOrigin: string,
  profile: SignerProfile,
): AuthenticatedOwnerSnapshot {
  const publicIdentity = parseRegisteredWalletPublicIdentity(rawActivate, rawNear, profile);
  const activate = requireRecord(rawActivate, 'registration activate response');
  const authority = requireRecord(activate.authority, 'registration activate response.authority');
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
    walletAuthMethodId: requireStringField(
      authority,
      'bindingId',
      'registration activate response.authority',
    ),
    routerOrigin,
    rpId: requireStringField(activate, 'rpId', 'registration activate response'),
    publicIdentity,
  };
}

function parseRegisteredWalletPublicIdentity(
  rawActivate: unknown,
  rawNear: unknown,
  profile: SignerProfile,
): WalletPublicIdentity {
  const activate = requireRecord(rawActivate, 'registration activate response');
  const walletId = requireStringField(activate, 'walletId', 'registration activate response');
  const activateKind = requireStringField(activate, 'kind', 'registration activate response');
  const hasEcdsaFamily = Object.prototype.hasOwnProperty.call(activate, 'ecdsa');
  const hasNearFamily = rawNear !== null;
  const expectedActivateKind =
    profile === 'ed25519'
      ? 'near_ed25519'
      : profile === 'ecdsa'
        ? 'evm_family_ecdsa'
        : 'evm_family_ecdsa';
  if (activateKind !== expectedActivateKind) {
    throw new Error(
      `registration activate response signer family ${activateKind} does not match ${profile}`,
    );
  }
  if (profile === 'ed25519' && hasEcdsaFamily) {
    throw new Error('registration activate response unexpectedly carries an ECDSA signer');
  }
  if (profile === 'ecdsa' && hasNearFamily) {
    throw new Error('registration response unexpectedly carries a NEAR signer');
  }
  if (profile === 'combined' && !hasNearFamily) {
    throw new Error('combined registration response is missing its NEAR signer');
  }
  const ecdsaKeys: string[] = [];
  if (profile !== 'ed25519') {
    const ecdsa = requireRecord(activate.ecdsa, 'registration activate response.ecdsa');
    if (!Array.isArray(ecdsa.walletKeys) || ecdsa.walletKeys.length === 0) {
      throw new Error('registration activate response.ecdsa.walletKeys must contain a wallet key');
    }
    ecdsaKeys.push(
      ...new Set(
        ecdsa.walletKeys.map((walletKey, index) =>
          parseEcdsaWalletKeyIdentity(
            walletKey,
            `registration activate response.ecdsa.walletKeys[${index}]`,
          ),
        ),
      ),
    );
  }
  let near: WalletPublicIdentity['near'] = null;
  if (profile !== 'ecdsa') {
    const nearResponse = requireRecord(rawNear, 'registration NEAR provisioning response');
    const ed25519 = requireRecord(
      nearResponse.ed25519,
      'registration NEAR provisioning response.ed25519',
    );
    if (
      requireStringField(nearResponse, 'walletId', 'registration NEAR provisioning response') !==
      walletId
    ) {
      throw new Error('registration responses disagree on wallet identity');
    }
    near = {
      accountId: requireStringField(
        ed25519,
        'nearAccountId',
        'registration NEAR provisioning response.ed25519',
      ),
      publicKey: requireStringField(
        ed25519,
        'publicKey',
        'registration NEAR provisioning response.ed25519',
      ),
    };
  }
  ecdsaKeys.sort();
  return {
    walletId,
    profile,
    near,
    ecdsaKeys,
  };
}

function requireNearIdentity(identity: WalletPublicIdentity): {
  readonly accountId: string;
  readonly publicKey: string;
} {
  if (!identity.near) {
    throw new Error(`Wallet ${identity.walletId} does not have an Ed25519 signer`);
  }
  return identity.near;
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

type LinkedDeviceFailureSource = {
  readonly label: 'owner' | 'device2';
  readonly page: Page;
  readonly diagnostics: string[];
};

type LinkedDeviceFailureListeners = {
  readonly source: LinkedDeviceFailureSource;
  readonly response: (response: Response) => void;
  readonly pageError: (error: Error) => void;
  readonly console: (message: ConsoleMessage) => void;
};

function linkedDeviceResponsePath(response: Response): string | null {
  try {
    const pathname = new URL(response.url()).pathname;
    return pathname.includes('/wallet/device-linking/') ? pathname : null;
  } catch {
    return null;
  }
}

function conciseLinkedDeviceFailureText(text: string): string {
  const concise = text.replace(/\s+/g, ' ').trim();
  return concise ? concise.slice(0, 2_000) : '<empty>';
}

function linkedDeviceFailureErrorText(error: unknown): string {
  return conciseLinkedDeviceFailureText(
    error instanceof Error ? error.stack || error.message : String(error),
  );
}

async function linkedDeviceFailureResponseBody(response: Response): Promise<string> {
  try {
    return conciseLinkedDeviceFailureText(await response.text());
  } catch (error) {
    return `<unavailable: ${linkedDeviceFailureErrorText(error)}>`;
  }
}

function throwLinkedDeviceFailure(error: Error): never {
  throw error;
}

class LinkedDeviceFailureMonitor {
  private readonly failure: Promise<Error>;
  private readonly listeners: LinkedDeviceFailureListeners[] = [];
  private resolveFailure: ((value: Error | PromiseLike<Error>) => void) | null = null;

  constructor(sources: readonly LinkedDeviceFailureSource[]) {
    this.failure = new Promise<Error>(this.captureFailureResolver.bind(this));
    for (const source of sources) {
      const response = this.handleResponse.bind(this, source);
      const pageError = this.handlePageError.bind(this, source);
      const console = this.handleConsole.bind(this, source);
      source.page.on('response', response);
      source.page.on('pageerror', pageError);
      source.page.on('console', console);
      this.listeners.push({ source, response, pageError, console });
    }
  }

  race<T>(task: Promise<T>): Promise<T> {
    return Promise.race([task, this.failure.then(throwLinkedDeviceFailure)]);
  }

  stop(): void {
    for (const listener of this.listeners) {
      listener.source.page.off('response', listener.response);
      listener.source.page.off('pageerror', listener.pageError);
      listener.source.page.off('console', listener.console);
    }
    this.listeners.length = 0;
  }

  private captureFailureResolver(resolve: (value: Error | PromiseLike<Error>) => void): void {
    this.resolveFailure = resolve;
  }

  private async handleResponse(
    source: LinkedDeviceFailureSource,
    response: Response,
  ): Promise<void> {
    const pathname = linkedDeviceResponsePath(response);
    if (!pathname || response.ok()) return;
    const diagnostic = `[${source.label}:response] ${response.request().method()} ${pathname} ${response.status()} body=${await linkedDeviceFailureResponseBody(response)}`;
    this.reportFailure(source, diagnostic);
  }

  private handlePageError(source: LinkedDeviceFailureSource, error: Error): void {
    this.reportFailure(
      source,
      `[${source.label}:pageerror] ${linkedDeviceFailureErrorText(error)}`,
    );
  }

  private handleConsole(source: LinkedDeviceFailureSource, message: ConsoleMessage): void {
    const text = conciseLinkedDeviceFailureText(message.text());
    if (
      message.type() !== 'error' ||
      (!text.includes('[Device2Linking] failed') &&
        !text.includes('[SeamsAuthMenu:login] Error') &&
        !text.includes('[DemoPage][TempoSignError]') &&
        !text.includes('[DemoPage][TempoWalletSessionExpired]') &&
        !text.includes('[DemoPage][TempoPreflightFailure]') &&
        !text.includes('wallet_iframe_surface_busy'))
    ) {
      return;
    }
    this.reportFailure(source, `[${source.label}:console] ${text}`);
  }

  private reportFailure(source: LinkedDeviceFailureSource, diagnostic: string): void {
    source.diagnostics.push(diagnostic);
    if (!this.resolveFailure) return;
    const resolveFailure = this.resolveFailure;
    this.resolveFailure = null;
    resolveFailure(new Error(`Linked-device browser failure: ${diagnostic}`));
  }
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

async function directRegistrationWalletFrame(page: Page): Promise<FrameLocator> {
  const iframe = page.locator('iframe[data-w3a-owner="linked-device-profile-registration"]');
  await iframe.waitFor({ state: 'attached', timeout: 30_000 });
  const frame = await iframe.contentFrame();
  if (!frame) throw new Error('Direct registration wallet service iframe is unavailable');
  return frame;
}

async function openWallet(page: Page): Promise<FrameLocator> {
  await page.goto(`${appOrigin}/wallet`, { waitUntil: 'domcontentloaded' });
  return walletFrame(page);
}

const ECDSA_CHAIN_TARGETS = [
  { kind: 'tempo', chainId: 42_431, networkSlug: 'tempo-testnet' },
  { kind: 'evm', namespace: 'eip155', chainId: 5_042_002, networkSlug: 'arc-testnet' },
] as const;

function registrationSignerSelectionForProfile(
  profile: SignerProfile,
): RegistrationSignerSetSelection {
  switch (profile) {
    case 'ed25519':
      return {
        kind: 'signer_set',
        signers: [
          {
            kind: 'near_ed25519',
            accountProvisioning: {
              kind: 'implicit_account',
              accountIdSource: 'ed25519_public_key',
            },
            signerSlot: 1,
            participantIds: [1, 2],
            derivationVersion: 1,
          },
        ],
      };
    case 'ecdsa':
      return {
        kind: 'signer_set',
        signers: [
          {
            kind: 'evm_family_ecdsa',
            chainTargets: ECDSA_CHAIN_TARGETS,
            participantIds: [1, 2],
          },
        ],
      };
    case 'combined':
      return {
        kind: 'signer_set',
        signers: [
          {
            kind: 'near_ed25519',
            accountProvisioning: {
              kind: 'implicit_account',
              accountIdSource: 'ed25519_public_key',
            },
            signerSlot: 1,
            participantIds: [1, 2],
            derivationVersion: 1,
          },
          {
            kind: 'evm_family_ecdsa',
            chainTargets: ECDSA_CHAIN_TARGETS,
            participantIds: [1, 2],
          },
        ],
      };
  }
}

type DirectRegistrationAuthMethod =
  | { readonly kind: 'passkey'; readonly rpId: string }
  | {
      readonly kind: 'email_otp';
      readonly proofKind: 'google_sso_registration';
      readonly email: string;
      readonly providerSubject: string;
      readonly googleEmailOtpRegistrationAttemptId: string;
      readonly googleEmailOtpRegistrationOfferId: string;
      readonly googleEmailOtpRegistrationCandidateId: string;
    };

type DirectRegistrationWallet =
  | { readonly kind: 'server_allocated' }
  | { readonly kind: 'provided'; readonly walletId: string };

type DirectRegistrationInput = {
  readonly profile: SignerProfile;
  readonly authMethod: DirectRegistrationAuthMethod;
  readonly wallet: DirectRegistrationWallet;
  readonly walletOrigin: string;
  readonly relayerUrl: string;
  readonly projectEnvironmentId: string;
  readonly publishableKey: string;
  readonly rpId: string;
};

function directRegistrationRepoRoot(): string {
  const configured = String(process.env.W3A_REPO_ROOT || '').trim();
  if (configured) return configured;
  const cwd = process.cwd();
  return fs.existsSync(path.join(cwd, 'packages/wallet')) ? cwd : path.resolve(cwd, '..');
}

function directRegistrationSdkModulePath(): string {
  const modulePath = path.join(
    directRegistrationRepoRoot(),
    'packages/wallet/dist/esm/SeamsWeb/walletIframe/client/router.js',
  );
  return `/@fs/${modulePath}`;
}

function indexedDbSdkModulePath(): string {
  return `${appOrigin}/@fs/${path.join(
    directRegistrationRepoRoot(),
    'packages/wallet/dist/esm/core/indexedDB/index.js',
  )}`;
}

async function resolveSelectedWalletAuthorityInBrowser(input: {
  readonly modulePath: string;
  readonly walletId: string;
}): Promise<unknown> {
  const { IndexedDBManager } = await import(input.modulePath);
  return await IndexedDBManager.resolveSelectedWalletAuthority(input.walletId);
}

async function readSelectedWalletAuthorityResolution(
  page: Page,
  walletId: string,
): Promise<unknown> {
  await walletFrame(page);
  const frame = page.frames().find((candidate) => candidate.url().includes('/wallet-service'));
  if (!frame) throw new Error('Wallet service frame is unavailable');
  return await frame.evaluate(resolveSelectedWalletAuthorityInBrowser, {
    modulePath: indexedDbSdkModulePath(),
    walletId,
  });
}

function assertSelectedWalletAuthorityResolved(resolution: unknown, boundary: string): void {
  const record = requireRecord(resolution, boundary);
  expect(record.kind, `${boundary}: ${JSON.stringify(resolution)}`).toBe('resolved');
}

async function directRegisterWalletInBrowser(input: {
  readonly authMethod: DirectRegistrationAuthMethod;
  readonly projectEnvironmentId: string;
  readonly publishableKey: string;
  readonly relayerUrl: string;
  readonly rpId: string;
  readonly sdkModulePath: string;
  readonly signerSelection: RegistrationSignerSetSelection;
  readonly wallet: DirectRegistrationWallet;
  readonly walletOrigin: string;
}): Promise<void> {
  const {
    authMethod,
    projectEnvironmentId,
    publishableKey,
    relayerUrl,
    rpId,
    sdkModulePath,
    signerSelection,
    wallet,
    walletOrigin,
  } = input;
  const { WalletIframeRouter } = await import(sdkModulePath);
  const router = new WalletIframeRouter({
    walletOrigin,
    servicePath: '/wallet-service',
    sdkBasePath: '/sdk',
    connectTimeoutMs: 20_000,
    requestTimeoutMs: 60_000,
    relayer: { url: relayerUrl },
    registration: {
      mode: 'managed',
      projectEnvironmentId,
      publishableKey,
      paymentMode: 'disabled',
    },
    rpIdOverride: rpId,
    testOptions: { ownerTag: 'linked-device-profile-registration' },
  });
  try {
    await router.init();
    const result = await router.registerWallet({
      wallet,
      authMethod,
      signerSelection,
      options: { recoveryCodeBackup: { kind: 'defer_to_account_menu' } },
    });
    if (!result.success) {
      throw new Error(result.error || 'Profile registration failed');
    }
  } finally {
    router.dispose();
  }
}

type IntendedEmailOtpUnlockBrowserRequest =
  | {
      readonly kind: 'request_challenge';
      readonly requestId: string;
      readonly walletId: string;
      readonly walletAuthMethodId: string;
    }
  | {
      readonly kind: 'complete_unlock';
      readonly requestId: string;
      readonly walletId: string;
      readonly walletAuthMethodId: string;
      readonly email: string;
      readonly providerSubjectId: string;
      readonly challengeId: string;
      readonly otpCode: string;
      readonly relayUrl: string;
    };

async function runIntendedEmailOtpUnlockActionInBrowser(
  input: IntendedEmailOtpUnlockBrowserRequest,
): Promise<Record<string, unknown>> {
  return await new Promise<Record<string, unknown>>((resolve, reject) => {
    const timeout = window.setTimeout(() => {
      window.removeEventListener('seams:intended-email-otp-unlock-result', onResult);
      reject(new Error('Intended Email OTP unlock action timed out'));
    }, 60_000);
    function onResult(event: Event): void {
      if (!(event instanceof CustomEvent) || !event.detail || typeof event.detail !== 'object') {
        return;
      }
      const result = event.detail as Record<string, unknown>;
      if (result.requestId !== input.requestId) return;
      window.clearTimeout(timeout);
      window.removeEventListener('seams:intended-email-otp-unlock-result', onResult);
      if (result.ok === true) resolve(result);
      else reject(new Error(String(result.error || 'Intended Email OTP unlock failed')));
    }
    window.addEventListener('seams:intended-email-otp-unlock-result', onResult);
    window.dispatchEvent(
      new CustomEvent('seams:intended-email-otp-unlock-request', { detail: input }),
    );
  });
}

async function unlockAddressEmailOtpWallet(input: {
  readonly context: BrowserContext;
  readonly page: Page;
  readonly routerOrigin: string;
  readonly walletAuthMethodId: string;
  readonly walletId: string;
}): Promise<void> {
  const config = directRegistrationConfig();
  const emailAddress = linkedTargetEmailAddress(input.walletId);
  const challengeRequestId = `linked-email-challenge:${input.walletAuthMethodId}`;
  const challengeResult = await input.page.evaluate(runIntendedEmailOtpUnlockActionInBrowser, {
    kind: 'request_challenge',
    requestId: challengeRequestId,
    walletId: input.walletId,
    walletAuthMethodId: input.walletAuthMethodId,
  });
  const challengeId = requireStringField(
    challengeResult,
    'challengeId',
    'Intended Email OTP unlock challenge',
  );
  const otpCode = await readEmailOtpOutboxCode({
    context: input.context,
    walletId: input.walletId,
    routerOrigin: input.routerOrigin,
    challengeId,
    challengeSubjectId: emailAddress,
  });
  await input.page.evaluate(runIntendedEmailOtpUnlockActionInBrowser, {
    kind: 'complete_unlock',
    requestId: `linked-email-unlock:${input.walletAuthMethodId}`,
    walletId: input.walletId,
    walletAuthMethodId: input.walletAuthMethodId,
    email: emailAddress,
    providerSubjectId: emailAddress,
    challengeId,
    otpCode,
    relayUrl: config.relayerUrl,
  });
  await input.page
    .locator('.w3a-profile-button-morphable')
    .waitFor({ state: 'visible', timeout: 120_000 });
  if ((await readActiveWalletId(input.page)) !== input.walletId) {
    throw new Error('Address-backed Email OTP unlock returned the wrong wallet');
  }
}

function linkedTargetEmailAddress(walletId: string): string {
  return `device-link-${walletId.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}@example.test`;
}

async function registerWalletWithSignerProfileInBrowser(
  page: Page,
  input: DirectRegistrationInput,
): Promise<void> {
  await page.goto(`${appOrigin}/seams-v9/manifest.txt`, { waitUntil: 'load' });
  await expect(page.locator('iframe.w3a-wallet-overlay')).toHaveCount(0);
  const registration = page.evaluate(directRegisterWalletInBrowser, {
    ...input,
    sdkModulePath: directRegistrationSdkModulePath(),
    signerSelection: registrationSignerSelectionForProfile(input.profile),
  });
  if (input.authMethod.kind === 'passkey') {
    const wallet = await directRegistrationWalletFrame(page);
    await wallet.getByRole('button', { name: 'Create passkey', exact: true }).click();
  }
  await registration;
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
    'combined',
  );
}

function directRegistrationConfig(): Pick<
  DirectRegistrationInput,
  'walletOrigin' | 'relayerUrl' | 'projectEnvironmentId' | 'publishableKey' | 'rpId'
> {
  const walletOrigin = String(
    process.env.VITE_WALLET_ORIGIN || process.env.SEAMS_INTENDED_WALLET_ORIGIN || '',
  ).trim();
  const relayerUrl = String(process.env.VITE_RELAYER_URL || localRouterOrigin).trim();
  const projectEnvironmentId = String(
    process.env.SEAMS_INTENDED_PROJECT_ENVIRONMENT_ID || '',
  ).trim();
  const publishableKey = String(process.env.SEAMS_INTENDED_PUBLISHABLE_KEY || '').trim();
  const rpId = String(
    process.env.VITE_RP_ID_BASE || (walletOrigin ? new URL(walletOrigin).hostname : 'localhost'),
  ).trim();
  if (!walletOrigin || !projectEnvironmentId || !publishableKey || !rpId) {
    throw new Error(
      'Profile registration requires VITE_WALLET_ORIGIN, SEAMS_INTENDED_PROJECT_ENVIRONMENT_ID, SEAMS_INTENDED_PUBLISHABLE_KEY, and VITE_RP_ID_BASE',
    );
  }
  return { walletOrigin, relayerUrl, projectEnvironmentId, publishableKey, rpId };
}

async function registerPasskeyOwnerForProfile(
  page: Page,
  profile: SignerProfile,
): Promise<AuthenticatedOwnerSnapshot> {
  await page.goto(appOrigin, { waitUntil: 'domcontentloaded' });
  const activated = page.waitForResponse(isRegistrationActivateResponse, { timeout: 120_000 });
  const nearProvisioned =
    profile === 'ecdsa'
      ? null
      : page.waitForResponse(isRegistrationNearProvisioningResponse, { timeout: 120_000 });
  const config = directRegistrationConfig();
  await registerWalletWithSignerProfileInBrowser(page, {
    profile,
    authMethod: { kind: 'passkey', rpId: config.rpId },
    wallet: { kind: 'server_allocated' },
    ...config,
  });
  const activateResponse = await activated;
  if (!activateResponse.ok()) {
    throw new Error(`Profile owner registration failed (${activateResponse.status()})`);
  }
  const nearResponse = nearProvisioned ? await nearProvisioned : null;
  if (nearResponse && !nearResponse.ok()) {
    throw new Error(`Profile owner NEAR provisioning failed (${nearResponse.status()})`);
  }
  const snapshot = parseRegisteredOwnerSnapshot(
    await activateResponse.json(),
    nearResponse ? await nearResponse.json() : null,
    new URL(activateResponse.url()).origin,
    profile,
  );
  await openWallet(page);
  await page.locator('.w3a-profile-button-morphable').waitFor({
    state: 'visible',
    timeout: 120_000,
  });
  await lockActiveWallet(page);
  await unlockLinkedPasskeyWallet(page, [], profile);
  return snapshot;
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

async function openDevice2Qr(page: Page, factor: 'Passkey'): Promise<string>;
async function openDevice2Qr(
  page: Page,
  factor: 'Email code',
  targetEmail: string,
): Promise<string>;
async function openDevice2Qr(
  page: Page,
  factor: 'Passkey' | 'Email code' = 'Passkey',
  targetEmail?: string,
): Promise<string> {
  const wallet = await openWallet(page);
  const linkButton = wallet.getByRole('button', { name: 'Scan and Link Device', exact: true });
  await linkButton.waitFor({ state: 'visible', timeout: 30_000 });
  await linkButton.click();
  const factorRadio = wallet.getByRole('radio', { name: factor, exact: true });
  await factorRadio.click({ force: true });
  await expect(factorRadio).toBeChecked({ timeout: 10_000 });
  if (factor === 'Email code') {
    if (!targetEmail) throw new Error('Device 2 Email OTP linking requires a target email');
    await wallet.getByRole('textbox', { name: 'Email address', exact: true }).fill(targetEmail);
  }
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

async function closeProfileMenu(page: Page): Promise<void> {
  const profile = page.locator('.w3a-profile-button-morphable');
  if ((await profile.getAttribute('data-state')) !== 'open') return;
  await profile.locator('.w3a-user-account-button-trigger').click();
  await expect(profile).toHaveAttribute('data-state', 'closed');
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

async function assertUnavailableAction(locator: Locator, label: string): Promise<void> {
  const count = await locator.count();
  if (count === 0) return;
  await expect(locator, label).toHaveCount(1);
  if (await locator.isVisible()) {
    await expect(locator, label).toBeDisabled();
    return;
  }
  await expect(locator, label).toBeHidden();
}

async function assertSignerProfileActions(page: Page, profile: SignerProfile): Promise<void> {
  const menu = await assertOwnerProfileRows(page);
  const exportKeys = menu.getByRole('button', { name: /^Export Keys\b/ });
  const exportNear = menu.getByRole('button', { name: /^Export NEAR Key\b/ });
  const exportEcdsa = menu.getByRole('button', { name: /^Export EVM Keys\b/ });
  if ((await exportKeys.count()) > 0 && (await exportKeys.isVisible())) {
    const nearVisible = await exportNear.isVisible().catch(() => false);
    const ecdsaVisible = await exportEcdsa.isVisible().catch(() => false);
    if (!nearVisible && !ecdsaVisible) await exportKeys.click();
  }
  if (profile === 'ecdsa') {
    await expect(exportEcdsa).toBeVisible();
    await expect(exportEcdsa).toBeEnabled();
    await assertUnavailableAction(exportNear, 'NEAR export must be unavailable for ECDSA-only');
  } else if (profile === 'ed25519') {
    await expect(exportNear).toBeVisible();
    await expect(exportNear).toBeEnabled();
    await assertUnavailableAction(exportEcdsa, 'ECDSA export must be unavailable for Ed25519-only');
  } else {
    await expect(exportNear).toBeVisible();
    await expect(exportNear).toBeEnabled();
    await expect(exportEcdsa).toBeVisible();
    await expect(exportEcdsa).toBeEnabled();
  }
  await closeProfileMenu(page);

  const nearTab = page.getByRole('tab', { name: 'NEAR', exact: true });
  const tempoTab = page.getByRole('tab', { name: 'Tempo', exact: true });
  const arcTab = page.getByRole('tab', { name: 'Arc', exact: true });
  if (profile === 'ecdsa') {
    await expect(tempoTab).toBeVisible();
    await expect(tempoTab).toBeEnabled();
    await expect(arcTab).toBeVisible();
    await expect(arcTab).toBeEnabled();
    await assertUnavailableAction(nearTab, 'NEAR signing must be unavailable for ECDSA-only');
  } else if (profile === 'ed25519') {
    await expect(nearTab).toBeVisible();
    await expect(nearTab).toBeEnabled();
    await assertUnavailableAction(tempoTab, 'Tempo signing must be unavailable for Ed25519-only');
    await assertUnavailableAction(arcTab, 'Arc signing must be unavailable for Ed25519-only');
  } else {
    await expect(nearTab).toBeVisible();
    await expect(nearTab).toBeEnabled();
    await expect(tempoTab).toBeVisible();
    await expect(tempoTab).toBeEnabled();
    await expect(arcTab).toBeVisible();
    await expect(arcTab).toBeEnabled();
  }
}

async function openOwnerScanner(page: Page, qrDataUrl: string): Promise<void> {
  await installQrCamera(page, qrDataUrl);
  const menu = await openProfileMenu(page);
  await menu.getByRole('button', { name: /^Scan and Link Device/ }).click();
  await page.locator('.qr-scanner-video').waitFor({ state: 'visible', timeout: 30_000 });
}

async function assertOwnerScannerClosedAfterScan(page: Page): Promise<void> {
  await expect(page.locator('.qr-scanner-modal')).toBeHidden({ timeout: 5_000 });
}

function recordRequestPath(paths: string[], request: Request): void {
  paths.push(new URL(request.url()).pathname);
}

function trackRequestPaths(page: Page, paths: string[]): void {
  page.on('request', recordRequestPath.bind(null, paths));
}

function assertNoUnlockOrNearFundingAfterLink(paths: readonly string[]): void {
  expect(
    paths.filter(
      (pathname) =>
        pathname === '/wallet/unlock/challenge' ||
        pathname === '/wallet/unlock/verify' ||
        pathname.endsWith('/near/implicit-account/fund'),
    ),
  ).toEqual([]);
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
  readonly challengeSubjectId?: string;
  readonly routerOrigin: string;
}): Promise<string> {
  const deadline = Date.now() + 30_000;
  let lastFailure = 'outbox entry was unavailable';
  while (Date.now() < deadline) {
    const response = await input.context.request.post(
      new URL('/wallet/email-otp/dev/otp-outbox', input.routerOrigin).href,
      {
        data: {
          idToken: requireGoogleIdToken(),
          walletId: input.walletId,
          ...(input.challengeId ? { challengeId: input.challengeId } : {}),
          ...(input.challengeId && input.challengeSubjectId
            ? { challengeSubjectId: input.challengeSubjectId }
            : {}),
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

async function completeVisibleEmailOtpPrompt(
  input: {
    readonly page: Page;
  } & EmailOtpPromptContext,
): Promise<boolean> {
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
      routerOrigin: input.routerOrigin,
      ...(challengeId ? { challengeId } : {}),
      ...(challengeId && input.challengeSubjectId
        ? { challengeSubjectId: input.challengeSubjectId }
        : {}),
    });
    await otpInput.fill(otpCode, { timeout: 10_000 });
    /* Raced prompt attempts are abandoned by completeEmailOtpPromptsUntil, so
       every click here is scoped to the OTP surface and bounded: a bare
       [data-auth-menu-primary] with no timeout matches the main-view passkey
       button and can fire minutes later into an unrelated menu. */
    const submit = wallet
      .locator(
        '.w3a-otp-prompt [data-auth-menu-primary], #w3a-confirm-portal button.btn-confirm, #w3a-confirm-portal button.confirm',
      )
      .first();
    if (await submit.isEnabled().catch(() => false)) {
      await submit.click({ timeout: 10_000 }).catch(() => undefined);
    }
    return true;
  }
  const emailView = wallet.locator('.w3a-otp-prompt');
  const startSelector = (await emailView.isVisible().catch(() => false))
    ? '.w3a-otp-prompt [data-auth-menu-primary]'
    : '[data-seams-registration-activation-start="true"], #w3a-confirm-portal button.btn-confirm, #w3a-confirm-portal button.confirm';
  const start = wallet.locator(startSelector).first();
  if (!(await start.isVisible().catch(() => false))) return false;
  if (!(await start.isEnabled().catch(() => false))) return false;
  await start.click({ timeout: 10_000 }).catch(() => undefined);
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

async function completeEmailOtpPromptsUntil<T>(
  input: {
    readonly page: Page;
    readonly task: Promise<T>;
  } & EmailOtpPromptContext,
): Promise<T> {
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

async function authenticateEmailOtpInHostedMenu(
  input: {
    readonly page: Page;
    readonly mode: 'register' | 'login';
    readonly profile: SignerProfile;
  } & EmailOtpPromptContext,
): Promise<void> {
  const wallet = await walletFrame(input.page);
  const google = wallet.locator('[data-auth-menu-provider="google"]');
  const switchMode = wallet.locator(`button[data-auth-menu-mode="${input.mode}"]`);
  /* The intent switch advertises the mode it would switch TO, so the menu is in
     the requested mode exactly when the opposite switch is rendered. The menu
     also flips itself once wallet state settles, detaching the switch button
     mid-click; keep the decision-and-click atomic and bounded instead of
     branching on a stale visibility read. */
  const inRequestedMode = wallet.locator(
    `button[data-auth-menu-mode="${input.mode === 'login' ? 'register' : 'login'}"]`,
  );
  await google.or(switchMode).first().waitFor({ state: 'visible', timeout: 30_000 });
  const modeDeadline = Date.now() + 30_000;
  while (!(await inRequestedMode.isVisible().catch(() => false))) {
    if (Date.now() >= modeDeadline) {
      throw new Error(`Auth menu did not reach ${input.mode} mode`);
    }
    if (await switchMode.isVisible().catch(() => false)) {
      await switchMode.click({ timeout: 2_000 }).catch(() => undefined);
    }
    await input.page.waitForTimeout(100);
  }
  await google.waitFor({ state: 'visible', timeout: 30_000 });
  const authenticated = input.page
    .getByRole('tab', { name: input.profile === 'ed25519' ? 'NEAR' : 'Tempo', exact: true })
    .waitFor({ state: 'visible', timeout: 180_000 });
  await google.click();
  await completeEmailOtpPromptsUntil({
    page: input.page,
    context: input.context,
    walletId: input.walletId,
    routerOrigin: input.routerOrigin,
    task: authenticated,
  });
}

async function unlockEmailOtpWallet(
  page: Page,
  context: BrowserContext,
  walletId: string,
  profile: SignerProfile,
  routerOrigin: string,
): Promise<void> {
  await authenticateEmailOtpInHostedMenu({
    page,
    context,
    mode: 'login',
    walletId,
    profile,
    routerOrigin,
  });
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
  const registrationConfig = directRegistrationConfig();
  const routerOrigin = new URL(registrationConfig.relayerUrl).origin;
  const activated = page.waitForResponse(isRegistrationActivateResponse, { timeout: 120_000 });
  const nearProvisioned = page.waitForResponse(isRegistrationNearProvisioningResponse, {
    timeout: 120_000,
  });
  await authenticateEmailOtpInHostedMenu({
    page,
    context,
    mode: 'register',
    walletId: '',
    profile: 'combined',
    routerOrigin,
  });
  const [activateResponse, nearResponse] = await Promise.all([activated, nearProvisioned]);
  if (!activateResponse.ok() || !nearResponse.ok()) {
    throw new Error(
      `Email owner registration identity responses failed (${activateResponse.status()}, ${nearResponse.status()})`,
    );
  }
  const identity = parseRegisteredWalletPublicIdentity(
    await activateResponse.json(),
    await nearResponse.json(),
    'combined',
  );
  if ((await readActiveWalletId(page)) !== identity.walletId) {
    throw new Error('Email owner registration activated a different wallet');
  }
  emailLinkedDeviceStage('owner registered');
  return identity;
}

type GoogleEmailRegistrationPlan = {
  readonly walletId: string;
  readonly authMethod: Extract<DirectRegistrationAuthMethod, { kind: 'email_otp' }>;
};

async function resolveGoogleEmailRegistrationPlan(
  context: BrowserContext,
  config: Pick<DirectRegistrationInput, 'relayerUrl' | 'projectEnvironmentId' | 'publishableKey'>,
): Promise<GoogleEmailRegistrationPlan> {
  const response = await context.request.post(
    `${config.relayerUrl.replace(/\/+$/, '')}/auth/google/verify`,
    {
      headers: {
        Authorization: `Bearer ${config.publishableKey}`,
        Origin: appOrigin,
      },
      data: {
        id_token: requireGoogleIdToken(),
        account_mode: 'register',
        project_environment_id: config.projectEnvironmentId,
        restart_registration_offer: true,
      },
    },
  );
  const body = requireRecord(await response.json(), 'Google Email OTP verification response');
  if (!response.ok() || body.mode !== 'register_started') {
    throw new Error(
      `Google Email OTP registration verification failed (${response.status()}): ${JSON.stringify(body)}`,
    );
  }
  const offer = requireRecord(body.offer, 'Google Email OTP registration offer');
  const candidates = Array.isArray(offer.candidates)
    ? offer.candidates.map((candidate, index) =>
        requireRecord(candidate, `Google Email OTP registration candidate ${index}`),
      )
    : [];
  const selectedCandidateId = requireStringField(
    offer,
    'selectedCandidateId',
    'Google Email OTP registration offer',
  );
  const selectedCandidateIndex = candidates.findIndex(
    (candidate) => String(candidate.candidateId || '').trim() === selectedCandidateId,
  );
  if (selectedCandidateIndex < 0 || candidates.length === 0) {
    throw new Error('Google Email OTP registration offer selected candidate is missing');
  }
  const registrationCandidate =
    candidates[(selectedCandidateIndex + 1) % candidates.length] ||
    candidates[selectedCandidateIndex];
  if (!registrationCandidate) {
    throw new Error('Google Email OTP registration offer has no registration candidate');
  }
  const registrationCandidateId = requireStringField(
    registrationCandidate,
    'candidateId',
    'Google Email OTP registration candidate',
  );
  return {
    walletId: requireStringField(
      registrationCandidate,
      'walletId',
      'Google Email OTP registration candidate',
    ),
    authMethod: {
      kind: 'email_otp',
      proofKind: 'google_sso_registration',
      email: requireStringField(body, 'email', 'Google Email OTP verification response'),
      providerSubject: requireStringField(
        body,
        'providerSubject',
        'Google Email OTP verification response',
      ),
      googleEmailOtpRegistrationAttemptId: requireStringField(
        body,
        'registrationAttemptId',
        'Google Email OTP verification response',
      ),
      googleEmailOtpRegistrationOfferId: requireStringField(
        offer,
        'offerId',
        'Google Email OTP registration offer',
      ),
      googleEmailOtpRegistrationCandidateId: registrationCandidateId,
    },
  };
}

async function registerEmailOwnerForProfile(
  page: Page,
  context: BrowserContext,
  profile: SignerProfile,
): Promise<RegisteredEmailOwnerIdentity> {
  emailLinkedDeviceStage(`registering ${profile} Email OTP owner`);
  await page.goto(appOrigin, { waitUntil: 'domcontentloaded' });
  const config = directRegistrationConfig();
  const plan = await resolveGoogleEmailRegistrationPlan(context, config);
  const activated = page.waitForResponse(isRegistrationActivateResponse, { timeout: 120_000 });
  const nearProvisioned =
    profile === 'ecdsa'
      ? null
      : page.waitForResponse(isRegistrationNearProvisioningResponse, { timeout: 120_000 });
  await registerWalletWithSignerProfileInBrowser(page, {
    profile,
    authMethod: plan.authMethod,
    wallet: { kind: 'provided', walletId: plan.walletId },
    ...config,
  });
  const activateResponse = await activated;
  if (!activateResponse.ok()) {
    throw new Error(`Profile Email OTP registration failed (${activateResponse.status()})`);
  }
  const nearResponse = nearProvisioned ? await nearProvisioned : null;
  if (nearResponse && !nearResponse.ok()) {
    throw new Error(`Profile Email OTP NEAR provisioning failed (${nearResponse.status()})`);
  }
  const identity = parseRegisteredWalletPublicIdentity(
    await activateResponse.json(),
    nearResponse ? await nearResponse.json() : null,
    profile,
  );
  if (identity.walletId !== plan.walletId) {
    throw new Error('Profile Email OTP registration activated a different wallet');
  }
  await openWallet(page);
  await page.locator('.w3a-profile-button-morphable').waitFor({
    state: 'visible',
    timeout: 120_000,
  });
  if ((await readActiveWalletId(page)) !== identity.walletId) {
    throw new Error('Profile Email OTP registration activated a different wallet in the app');
  }
  await lockActiveWallet(page);
  await unlockEmailOtpWallet(
    page,
    context,
    identity.walletId,
    profile,
    new URL(config.relayerUrl).origin,
  );
  emailLinkedDeviceStage(`${profile} Email OTP owner registered`);
  return { ...identity, emailAddress: plan.authMethod.email.trim().toLowerCase() };
}

async function unlockLinkedPasskeyWallet(
  page: Page,
  diagnostics: readonly string[],
  profile: SignerProfile = 'combined',
): Promise<void> {
  const wallet = await walletFrame(page);
  const unlock = wallet.getByRole('button', { name: 'Sign in with Passkey', exact: true });
  const switchToLogin = wallet.locator('button[data-auth-menu-mode="login"]');
  await unlock.or(switchToLogin).first().waitFor({ state: 'visible', timeout: 30_000 });
  if (await switchToLogin.isVisible()) await switchToLogin.click();
  await unlock.waitFor({ state: 'visible', timeout: 30_000 });
  await unlock.click();
  try {
    await page
      .getByRole('tab', { name: profile === 'ed25519' ? 'NEAR' : 'Tempo', exact: true })
      .waitFor({
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
  profile: SignerProfile,
): Promise<void> {
  const activeTab = profile === 'ed25519' ? 'NEAR' : 'Tempo';
  try {
    await expect
      .poll(
        () => diagnostics.some((entry) => entry.includes('post_link_runtime_ready')),
        {
          message: 'Linked-device signer runtimes did not become ready',
          timeout: linkedDeviceTransitionTimeoutMs,
        },
      )
      .toBe(true);
    await page.getByRole('tab', { name: activeTab, exact: true }).waitFor({
      state: 'visible',
      timeout: linkedDeviceTransitionTimeoutMs,
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

async function walletSigningFrameDiagnostics(page: Page): Promise<string> {
  const diagnostics: string[] = [];
  for (const frame of page.frames()) {
    const body = await frame
      .locator('body')
      .innerText()
      .then(conciseLinkedDeviceFailureText)
      .catch(() => '<unavailable>');
    diagnostics.push(`${frame.url() || '<no-url>'}: ${body}`);
  }
  return diagnostics.join('\n');
}

function walletSigningConfirmButton(page: Page): Locator {
  const iframe = page.locator('iframe[allow*="publickey-credentials-get"]').last();
  return iframe
    .contentFrame()
    .locator('#w3a-confirm-portal button.btn-confirm, #w3a-confirm-portal button.confirm')
    .first();
}

async function confirmWalletSigning(page: Page, diagnostics: readonly string[]): Promise<void> {
  const iframe = page.locator('iframe[allow*="publickey-credentials-get"]').last();
  await iframe.waitFor({ state: 'attached', timeout: 60_000 });
  const confirm = walletSigningConfirmButton(page);
  try {
    await confirm.waitFor({ state: 'visible', timeout: linkedDeviceTransitionTimeoutMs });
  } catch (error: unknown) {
    const visibleFailure = await readVisibleHostedAuthFailure(page);
    throw new Error(
      `Wallet signing confirmation did not appear.\nVisible failure: ${visibleFailure ?? '<none>'}\n${diagnostics.join('\n')}\nFrames:\n${await walletSigningFrameDiagnostics(page)}`,
      { cause: error },
    );
  }
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

async function clickAndConfirmPasskeySigning(input: {
  readonly page: Page;
  readonly trigger: Locator;
  readonly diagnostics: readonly string[];
}): Promise<void> {
  await input.trigger.click();
  await confirmWalletSigning(input.page, input.diagnostics);
}

async function completePasskeySigning(input: {
  readonly page: Page;
  readonly trigger: Locator;
  readonly response: Promise<Response>;
  readonly diagnostics: readonly string[];
}): Promise<void> {
  const responseTask = requireSuccessfulRouterResponse(input.response, input.diagnostics);
  void responseTask.catch(ignoreSigningResponseFailure);
  await clickAndConfirmPasskeySigning(input);
  await responseTask;
}

function ignoreSigningResponseFailure(): undefined {
  return undefined;
}

function clickEnabledTempoFundingButton(element: Element): boolean {
  if (!(element instanceof HTMLButtonElement)) return false;
  if (element.disabled || element.textContent?.trim() !== 'Fund Tempo Account') return false;
  element.click();
  return true;
}

async function clickAndCompleteEmailOtpSigning(input: {
  readonly page: Page;
  readonly trigger: Locator;
  readonly emailOtp: EmailOtpPromptContext;
  readonly task: Promise<void>;
}): Promise<void> {
  await input.trigger.click();
  await completeEmailOtpPromptsUntil({
    page: input.page,
    ...input.emailOtp,
    task: input.task,
  });
}

async function completeEmailOtpSigning(input: {
  readonly page: Page;
  readonly trigger: Locator;
  readonly response: Promise<Response>;
  readonly diagnostics: readonly string[];
  readonly emailOtp: EmailOtpPromptContext;
}): Promise<void> {
  const task = requireSuccessfulRouterResponse(input.response, input.diagnostics);
  await Promise.all([
    task,
    clickAndCompleteEmailOtpSigning({
      page: input.page,
      trigger: input.trigger,
      emailOtp: input.emailOtp,
      task,
    }),
  ]);
}

async function linkedSigning(
  page: Page,
  diagnostics: readonly string[],
  emailOtp?: EmailOtpPromptContext,
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
    const fundingClicked = await tempoFunding.evaluate(clickEnabledTempoFundingButton);
    if (fundingClicked) {
      const fundingSigned = waitForEcdsaSigningOutcome(page);
      const fundingReady = expect(tempoFunding)
        .toHaveText('Tempo Account Funded', { timeout: 180_000 })
        .then(() => ({ kind: 'ready_without_signing' as const }));
      if (emailOtp) {
        const responseTask = requireSuccessfulRouterResponse(fundingSigned, diagnostics).then(
          () => ({ kind: 'signed' as const }),
        );
        void responseTask.catch(ignoreSigningResponseFailure);
        await completeEmailOtpPromptsUntil({
          page,
          ...emailOtp,
          task: Promise.race([responseTask, fundingReady]),
        });
      } else {
        const confirm = walletSigningConfirmButton(page);
        const interaction = await Promise.race([
          confirm
            .waitFor({ state: 'visible', timeout: linkedDeviceTransitionTimeoutMs })
            .then(() => ({ kind: 'confirmation' as const })),
          fundingReady,
        ]);
        if (interaction.kind === 'confirmation') {
          const responseTask = requireSuccessfulRouterResponse(fundingSigned, diagnostics);
          void responseTask.catch(ignoreSigningResponseFailure);
          await confirm.click();
          await responseTask;
        }
      }
      await expect(tempoFunding).toHaveText('Tempo Account Funded', { timeout: 180_000 });
      await expect(tempoFunding).toBeDisabled();
    }
  }
  const tempoSign = page.getByRole('button', { name: 'Sign on Tempo', exact: true });
  await tempoSign.waitFor({ state: 'visible', timeout: 60_000 });
  await expect(tempoSign).toBeEnabled({ timeout: 120_000 });
  const tempoSigned = waitForEcdsaSigningOutcome(page);
  if (emailOtp) {
    await completeEmailOtpSigning({
      page,
      trigger: tempoSign,
      response: tempoSigned,
      diagnostics,
      emailOtp,
    });
  } else {
    await completePasskeySigning({
      page,
      trigger: tempoSign,
      response: tempoSigned,
      diagnostics,
    });
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

function isSigningFailureResponse(response: Response): boolean {
  if (response.ok() || response.request().method() !== 'POST') return false;
  const pathname = new URL(response.url()).pathname;
  return (
    pathname.startsWith('/router-ab/ed25519/') ||
    pathname.startsWith('/router-ab/ecdsa-derivation/')
  );
}

function waitForEcdsaSigningOutcome(page: Page): Promise<Response> {
  return page.waitForResponse(
    (response) => isEcdsaFinalSignResponse(response) || isSigningFailureResponse(response),
    { timeout: 180_000 },
  );
}

function isSigningOutcomeForChain(chain: 'Arc' | 'NEAR', response: Response): boolean {
  const isFinalResponse =
    chain === 'Arc' ? isEcdsaFinalSignResponse(response) : isNearFinalSignResponse(response);
  return isFinalResponse || isSigningFailureResponse(response);
}

/** One greeting transaction on the Arc (EVM) or NEAR tab of the active demo. */
async function greetingSigning(
  page: Page,
  chain: 'Arc' | 'NEAR',
  diagnostics: readonly string[],
  emailOtp?: EmailOtpPromptContext,
): Promise<void> {
  if (!emailOtp) passkeyLinkedDeviceStage(`waiting for ${chain} signing controls`);
  const tab = page.getByRole('tab', { name: chain, exact: true });
  await tab.waitFor({ state: 'visible', timeout: linkedDeviceTransitionTimeoutMs });
  if (!emailOtp) passkeyLinkedDeviceStage(`${chain} tab visible`);
  await tab.click({ timeout: 10_000 });
  const sign = page.getByRole('button', { name: `Sign on ${chain}`, exact: true });
  await sign.waitFor({ state: 'visible', timeout: linkedDeviceTransitionTimeoutMs });
  if (!emailOtp) passkeyLinkedDeviceStage(`${chain} sign button visible`);
  await expect(sign).toBeEnabled({ timeout: linkedDeviceTransitionTimeoutMs });
  if (!emailOtp) passkeyLinkedDeviceStage(`${chain} signing controls enabled`);
  const signed = page.waitForResponse(isSigningOutcomeForChain.bind(null, chain), {
    timeout: 180_000,
  });
  if (emailOtp) {
    await completeEmailOtpSigning({
      page,
      trigger: sign,
      response: signed,
      diagnostics,
      emailOtp,
    });
  } else {
    await completePasskeySigning({ page, trigger: sign, response: signed, diagnostics });
    passkeyLinkedDeviceStage(`${chain} signing confirmed`);
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
  readonly device2CredentialAssertedEvents: readonly unknown[];
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
  readonly routerOrigin: string;
  readonly activation: LinkedActivationSnapshot;
};

type PasskeyOwnerEmailTargetPair = EmailLinkedOwnerPair & {
  readonly source: {
    readonly kind: 'passkey';
    readonly owner: AuthenticatedOwnerSnapshot;
  };
};

type EmailOwnerPasskeyTargetPair = Omit<LinkedOwnerPair, 'owner'> & {
  readonly source: {
    readonly kind: 'email_otp';
    readonly publicIdentity: WalletPublicIdentity;
    readonly routerOrigin: string;
  };
};

type BrowserPasskeyRevocationInput = {
  readonly actorCredentialIdB64u: string;
  readonly endpoint: string;
  readonly operationFingerprintDigestB64u: string;
  readonly rpId: string;
  readonly request: {
    readonly requestedAtMs: number;
    readonly walletAuthMethodId: unknown;
    readonly walletId: string;
  };
};

type BrowserPasskeyRevocationResult = {
  readonly body: unknown;
  readonly status: number;
};

type LinkedActivationSnapshot = {
  readonly linkSessionId: string;
  readonly enrollmentId: string;
  readonly authorityId: string;
  readonly authMethodId: string;
  readonly deviceId: string;
  readonly packageSetDigestB64u: string;
  readonly authorizationId: string;
  readonly revocationEpoch: number;
};

type LinkedInventorySnapshot = {
  readonly deviceId: string;
  readonly enrollmentId: string;
  readonly authMethodId: string;
  readonly keyManifestDigestB64u: string;
  readonly state: string;
  readonly revocationEpoch: number;
};

type LocalAuthoritySnapshot = {
  readonly authorityId: string;
  readonly authorityState: string;
  readonly authMethodId: string;
  readonly authMethodKind: string;
  readonly authMethodStatus: string;
  readonly signerActivationSetDigestB64u: string;
  readonly authorityDigestB64u: string;
  readonly revocationEpoch: number;
  readonly signerActivations: unknown;
  readonly localInstallPackageSetDigestB64u: string | null;
  readonly installedRecordSetDigestB64u: string | null;
  readonly session: {
    readonly authorizationId: string;
    readonly authorityDigestB64u: string;
    readonly authorityRevocationEpoch: number;
  } | null;
};

async function readWalletAuthoritySnapshotInBrowser(walletId: string): Promise<unknown> {
  const database = await new Promise<IDBDatabase | null>((resolve) => {
    const request = indexedDB.open('seams_wallet');
    request.onerror = () => resolve(null);
    request.onsuccess = () => resolve(request.result);
  });
  if (!database) return null;
  const stores = [
    'wallet_authorities',
    'wallet_auth_methods',
    'wallet_authority_installation_receipts',
    'wallet_session_authorizations',
  ] as const;
  if (stores.some((store) => !database.objectStoreNames.contains(store))) {
    database.close();
    return null;
  }
  try {
    const transaction = database.transaction(stores, 'readonly');
    const rows = await Promise.all(
      stores.map(
        (storeName) =>
          new Promise<unknown[]>((resolve, reject) => {
            const request = transaction.objectStore(storeName).getAll();
            request.onerror = () =>
              reject(request.error || new Error(`Failed to read ${storeName}`));
            request.onsuccess = () => resolve(Array.isArray(request.result) ? request.result : []);
          }),
      ),
    );
    const [authorityRows, authMethodRows, receiptRows, sessionRows] = rows;
    const authorityRow = authorityRows.find((value) => {
      if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
      const row = value as Record<string, unknown>;
      const record = row.record;
      if (!record || typeof record !== 'object' || Array.isArray(record)) return false;
      const authority = record as Record<string, unknown>;
      const provenance = authority.provenance;
      return (
        row.wallet_id === walletId &&
        authority.walletId === walletId &&
        authority.state === 'active' &&
        provenance !== null &&
        typeof provenance === 'object' &&
        !Array.isArray(provenance) &&
        (provenance as Record<string, unknown>).kind === 'wallet_registration'
      );
    });
    if (!authorityRow || typeof authorityRow !== 'object' || Array.isArray(authorityRow))
      return null;
    const authority = (authorityRow as Record<string, unknown>).record;
    if (!authority || typeof authority !== 'object' || Array.isArray(authority)) return null;
    const authorityRecord = authority as Record<string, unknown>;
    const authorityId = String(authorityRecord.authorityId || '').trim();
    if (!authorityId) return null;
    const authMethodRow = authMethodRows.find((value) => {
      if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
      const row = value as Record<string, unknown>;
      const record = row.record;
      if (!record || typeof record !== 'object' || Array.isArray(record)) return false;
      const authMethod = record as Record<string, unknown>;
      return (
        row.wallet_id === walletId &&
        authMethod.walletId === walletId &&
        authMethod.walletAuthorityId === authorityId &&
        authMethod.status === 'active'
      );
    });
    if (!authMethodRow || typeof authMethodRow !== 'object' || Array.isArray(authMethodRow)) {
      return null;
    }
    const authMethod = (authMethodRow as Record<string, unknown>).record;
    if (!authMethod || typeof authMethod !== 'object' || Array.isArray(authMethod)) return null;
    const authMethodRecord = authMethod as Record<string, unknown>;
    const authMethodId = String(authMethodRecord.walletAuthMethodId || '').trim();
    const signerActivations = authorityRecord.signerActivations;
    const activationSet =
      signerActivations &&
      typeof signerActivations === 'object' &&
      !Array.isArray(signerActivations)
        ? (signerActivations as Record<string, unknown>)
        : null;
    const activationSummary = {
      ecdsa:
        activationSet?.ecdsa && typeof activationSet.ecdsa === 'object'
          ? String(
              (
                (activationSet.ecdsa as Record<string, unknown>).materialActivation as Record<
                  string,
                  unknown
                >
              )?.activationId || '',
            )
          : null,
      ed25519:
        activationSet?.ed25519 && typeof activationSet.ed25519 === 'object'
          ? String(
              (
                (activationSet.ed25519 as Record<string, unknown>).materialActivation as Record<
                  string,
                  unknown
                >
              )?.activationId || '',
            )
          : null,
      keyFamilies: Array.isArray(activationSet?.keyFamilies) ? activationSet.keyFamilies : [],
      kind: String(activationSet?.kind || ''),
    };
    const receipt = receiptRows.find((value) => {
      if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
      const row = value as Record<string, unknown>;
      return (
        row.wallet_id === walletId &&
        row.authority_id === authorityId &&
        row.wallet_auth_method_id === authMethodId
      );
    });
    const receiptRecord =
      receipt && typeof receipt === 'object' && !Array.isArray(receipt)
        ? (receipt as Record<string, unknown>).record
        : null;
    const sessionRow = sessionRows.find((value) => {
      if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
      const row = value as Record<string, unknown>;
      return (
        row.wallet_id === walletId &&
        row.wallet_authority_id === authorityId &&
        row.wallet_auth_method_id === authMethodId &&
        row.status === 'active'
      );
    });
    const sessionRecord =
      sessionRow && typeof sessionRow === 'object' && !Array.isArray(sessionRow)
        ? (sessionRow as Record<string, unknown>).record
        : null;
    const session =
      sessionRecord && typeof sessionRecord === 'object' && !Array.isArray(sessionRecord)
        ? (sessionRecord as Record<string, unknown>)
        : null;
    return {
      authorityId,
      authorityState: String(authorityRecord.state || ''),
      authMethodId,
      authMethodKind: String(authMethodRecord.kind || ''),
      authMethodStatus: String(authMethodRecord.status || ''),
      authorityDigestB64u: String(authorityRecord.authorityDigestB64u || ''),
      localInstallPackageSetDigestB64u:
        String(authorityRecord.localInstallPackageSetDigestB64u || '') || null,
      revocationEpoch: Number(authorityRecord.revocationEpoch),
      signerActivationSetDigestB64u: String(authorityRecord.signerActivationSetDigestB64u || ''),
      signerActivations: activationSummary,
      installedRecordSetDigestB64u:
        receiptRecord && typeof receiptRecord === 'object' && !Array.isArray(receiptRecord)
          ? String((receiptRecord as Record<string, unknown>).installedRecordSetDigestB64u || '') ||
            null
          : null,
      session:
        session &&
        String(session.authorizationId || '').trim() &&
        String(session.authorityDigestB64u || '').trim()
          ? {
              authorizationId: String(session.authorizationId),
              authorityDigestB64u: String(session.authorityDigestB64u),
              authorityRevocationEpoch: Number(session.authorityRevocationEpoch),
            }
          : null,
    };
  } catch {
    return null;
  } finally {
    database.close();
  }
}

function parseLocalAuthoritySnapshot(raw: unknown): LocalAuthoritySnapshot | null {
  if (raw === null) return null;
  const record = requireRecord(raw, 'local authority snapshot');
  const authorityId = requireStringField(record, 'authorityId', 'local authority snapshot');
  const authorityState = requireStringField(record, 'authorityState', 'local authority snapshot');
  const authMethodId = requireStringField(record, 'authMethodId', 'local authority snapshot');
  const authMethodKind = requireStringField(record, 'authMethodKind', 'local authority snapshot');
  const authMethodStatus = requireStringField(
    record,
    'authMethodStatus',
    'local authority snapshot',
  );
  const authorityDigestB64u = requireStringField(
    record,
    'authorityDigestB64u',
    'local authority snapshot',
  );
  const signerActivationSetDigestB64u = requireStringField(
    record,
    'signerActivationSetDigestB64u',
    'local authority snapshot',
  );
  const revocationEpoch = Number(record.revocationEpoch);
  if (!Number.isSafeInteger(revocationEpoch) || revocationEpoch < 0) {
    throw new Error('local authority snapshot.revocationEpoch is invalid');
  }
  const sessionRecord = record.session;
  let session: LocalAuthoritySnapshot['session'] = null;
  if (sessionRecord !== null) {
    const sessionValue = requireRecord(sessionRecord, 'local authority snapshot.session');
    const authorizationId = requireStringField(
      sessionValue,
      'authorizationId',
      'local authority snapshot.session',
    );
    const sessionDigest = requireStringField(
      sessionValue,
      'authorityDigestB64u',
      'local authority snapshot.session',
    );
    const sessionEpoch = Number(sessionValue.authorityRevocationEpoch);
    if (!Number.isSafeInteger(sessionEpoch) || sessionEpoch < 0) {
      throw new Error('local authority snapshot.session.authorityRevocationEpoch is invalid');
    }
    session = {
      authorizationId,
      authorityDigestB64u: sessionDigest,
      authorityRevocationEpoch: sessionEpoch,
    };
  }
  const localInstallPackageSetDigestB64u =
    record.localInstallPackageSetDigestB64u === null
      ? null
      : requireStringField(record, 'localInstallPackageSetDigestB64u', 'local authority snapshot');
  const installedRecordSetDigestB64u =
    record.installedRecordSetDigestB64u === null
      ? null
      : requireStringField(record, 'installedRecordSetDigestB64u', 'local authority snapshot');
  return {
    authorityId,
    authorityState,
    authMethodId,
    authMethodKind,
    authMethodStatus,
    authorityDigestB64u,
    localInstallPackageSetDigestB64u,
    installedRecordSetDigestB64u,
    revocationEpoch,
    signerActivationSetDigestB64u,
    signerActivations: record.signerActivations,
    session,
  };
}

async function readLocalAuthoritySnapshot(
  page: Page,
  walletId: string,
): Promise<LocalAuthoritySnapshot | null> {
  const frame = page.frames().find((candidate) => candidate.url().includes('/wallet-service'));
  if (!frame) return null;
  return parseLocalAuthoritySnapshot(
    await frame.evaluate(readWalletAuthoritySnapshotInBrowser, walletId),
  );
}

function assertLocalAuthoritySnapshotStable(
  before: LocalAuthoritySnapshot | null,
  after: LocalAuthoritySnapshot | null,
): void {
  if (!before || !after) {
    console.info('[linked-device] Device 1 local authority snapshot unavailable');
    return;
  }
  expect(after).toEqual(before);
}

function isRevokedWalletUnlockResponse(response: Response): boolean {
  const pathname = new URL(response.url()).pathname;
  return (
    response.request().method() === 'POST' &&
    (pathname === '/wallet/unlock/challenge' || pathname === '/wallet/unlock/verify') &&
    !response.ok()
  );
}

function isEcdsaExportResponse(response: Response): boolean {
  return (
    response.request().method() === 'POST' &&
    new URL(response.url()).pathname === '/router-ab/ecdsa-derivation/export'
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

function isEd25519ExportAdmitResponse(response: Response): boolean {
  return (
    response.request().method() === 'POST' &&
    new URL(response.url()).pathname === '/router-ab/ed25519/yao/export/admit'
  );
}

/** The export-scoped challenge id an Ed25519 export presents when it admits. */
function ed25519ExportAdmitChallengeId(response: Response): string {
  const body = response.request().postDataJSON();
  const authorization = requireRecord(
    (body as Record<string, unknown>).authorization,
    'Ed25519 export admit authorization',
  );
  return String(authorization.challengeId || '').trim();
}

function isEcdsaExportOperationStepUpResponse(response: Response): boolean {
  return (
    response.request().method() === 'POST' &&
    new URL(response.url()).pathname === '/router-ab/ecdsa-derivation/operation-step-up'
  );
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

async function requireEmailOtpExportAuthorization(
  page: Page,
  chain: 'near' | 'evm',
): Promise<void> {
  let challenge: Response;
  let stepUp: Response;
  try {
    [challenge, stepUp] = await Promise.all([
      page.waitForResponse(isEmailOtpExportChallengeResponse, {
        timeout: keyExportWaitTimeoutMs,
      }),
      /* The invariant is that a FRESH export-scoped OTP authorizes this export,
         not that one particular route carries the operation tag. An Ed25519
         export presents its export_key challenge and code to export/admit, and
         the factor release then consumes the grant that admit minted — so the
         release itself carries a verified grant rather than an operation. */
      page.waitForResponse(
        chain === 'near' ? isEd25519ExportAdmitResponse : isEcdsaExportOperationStepUpResponse,
        {
          timeout: keyExportWaitTimeoutMs,
        },
      ),
    ]);
  } catch (error: unknown) {
    throw new Error('Email OTP key export did not perform its fresh export_key authorization', {
      cause: error,
    });
  }
  expect(challenge.ok(), 'Email OTP export challenge failed').toBe(true);
  expect(stepUp.ok(), 'Email OTP export step-up failed').toBe(true);
  if (chain === 'near') {
    const challengeBody = requireRecord(
      await challenge.json(),
      'Email OTP export challenge response',
    );
    const issued = requireRecord(
      challengeBody.challenge,
      'Email OTP export challenge response.challenge',
    );
    expect(
      ed25519ExportAdmitChallengeId(stepUp),
      'Ed25519 export admitted a different challenge than the fresh export_key one',
    ).toBe(String(issued.challengeId || '').trim());
  }
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
  emailOtp?: EmailOtpPromptContext,
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
  const exportAuthorization = emailOtp ? requireEmailOtpExportAuthorization(page, chain) : null;
  const exportChallenge = emailOtp
    ? page.waitForResponse(isEmailOtpExportChallengeResponse, {
        timeout: keyExportWaitTimeoutMs,
      })
    : null;
  await exportRow.click();
  if (emailOtp && exportChallenge) {
    const challengeResponse = await exportChallenge;
    const challengeBody = requireRecord(
      await challengeResponse.json(),
      'Email OTP export challenge response',
    );
    const challenge = requireRecord(
      challengeBody.challenge,
      'Email OTP export challenge response.challenge',
    );
    const challengeId = requireStringField(
      challenge,
      'challengeId',
      'Email OTP export challenge response.challenge',
    );
    await Promise.all([
      completeEmailOtpPromptsUntil({ page, ...emailOtp, challengeId, task: finishExport }),
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
  await closeProfileMenu(page);
  await expect(menu).toBeHidden();
  return { accountId: identity.accountId, entries: identity.entries };
}

async function exportPasskeyOwnerKey(
  pair: Pick<
    LinkedOwnerPair,
    'device2CredentialAssertedEvents' | 'device2Diagnostics' | 'device2Page'
  >,
  chain: 'near' | 'evm',
): Promise<ExportedPublicIdentity> {
  const assertionsBeforeExport = pair.device2CredentialAssertedEvents.length;
  const exported = await exportOwnerKey(pair.device2Page, chain, pair.device2Diagnostics);
  await expect
    .poll(() => pair.device2CredentialAssertedEvents.length, {
      message: `Passkey ${chain} export did not perform a fresh WebAuthn assertion`,
      timeout: 30_000,
    })
    .toBeGreaterThan(assertionsBeforeExport);
  return exported;
}

async function assertImmediateLinkedWalletOperations(input: {
  readonly page: Page;
  readonly diagnostics: readonly string[];
  readonly publicIdentity: WalletPublicIdentity;
  readonly profile: SignerProfile;
  readonly emailOtp?: EmailOtpPromptContext;
}): Promise<void> {
  await assertSignerProfileActions(input.page, input.profile);
  if (input.profile !== 'ecdsa') {
    const near = requireNearIdentity(input.publicIdentity);
    await greetingSigning(input.page, 'NEAR', input.diagnostics, input.emailOtp);
    const exported = await exportOwnerKey(
      input.page,
      'near',
      input.diagnostics,
      input.emailOtp,
    );
    expect(exported.accountId).toBe(near.accountId);
    expect(exported.entries.map((entry) => entry.publicKey)).toEqual([near.publicKey]);
  }
  if (input.profile !== 'ed25519') {
    await linkedSigning(input.page, input.diagnostics, input.emailOtp);
    const exported = await exportOwnerKey(
      input.page,
      'evm',
      input.diagnostics,
      input.emailOtp,
    );
    expect(
      exported.entries
        .map((entry) => `${entry.publicKey.toLowerCase()}:${entry.address.toLowerCase()}`)
        .sort(),
    ).toEqual(input.publicIdentity.ecdsaKeys);
  }
}

async function revokeWalletAuthMethodInBrowser(
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

  const normalizedDigest = input.operationFingerprintDigestB64u
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  const paddedDigest = normalizedDigest.padEnd(
    normalizedDigest.length + ((4 - (normalizedDigest.length % 4)) % 4),
    '=',
  );
  const decodedDigest = globalThis.atob(paddedDigest);
  const challenge = new Uint8Array(decodedDigest.length);
  for (let index = 0; index < decodedDigest.length; index += 1) {
    challenge[index] = decodedDigest.charCodeAt(index);
  }
  const rawCredential = await navigator.credentials.get({
    publicKey: {
      allowCredentials: [{ id: allowCredentialId, type: 'public-key' }],
      challenge,
      rpId: input.rpId,
      userVerification: 'required',
      timeout: 60_000,
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
      requestedAtMs: input.request.requestedAtMs,
      sourceProof: {
        kind: 'webauthn_assertion',
        rpId: input.rpId,
        credential: serializableCredential.toJSON(),
        expectedChallengeDigestB64u: input.operationFingerprintDigestB64u,
      },
      walletAuthMethodId: input.request.walletAuthMethodId,
      walletId: input.request.walletId,
    }),
    headers: { 'content-type': 'application/json' },
    method: 'POST',
  });
  return { body: await response.json(), status: response.status };
}

async function revokeOwner(
  page: Page,
  actor: OwnerCredentialSnapshot,
  target: WalletAuthMethodRevocationTarget,
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
  target: WalletAuthMethodRevocationTarget,
): Promise<BrowserPasskeyRevocationResult> {
  if (
    actor.walletId !== target.walletId ||
    actor.rpId !== target.rpId ||
    actor.routerOrigin !== target.routerOrigin
  ) {
    throw new Error('Owner revocation identities do not describe the same wallet deployment');
  }
  const walletId = parseWalletId(actor.walletId);
  const walletAuthMethodId = parseWalletAuthMethodId(target.walletAuthMethodId);
  if (!walletId.ok) throw new Error(walletId.error.message);
  if (!walletAuthMethodId.ok) throw new Error(walletAuthMethodId.error.message);
  const requestedAtMs = Date.now();
  const operationFingerprintDigestB64u = await computeWalletAuthMethodRevokeOperationFingerprintV1({
    walletId: walletId.value,
    targetWalletAuthMethodId: walletAuthMethodId.value,
    requestedAtMs,
  });
  const endpoint = `${actor.routerOrigin}/wallets/${encodeURIComponent(actor.walletId)}/auth-methods/${encodeURIComponent(target.walletAuthMethodId)}/revoke`;
  const result = await page.evaluate(revokeWalletAuthMethodInBrowser, {
    actorCredentialIdB64u: actor.credentialIdB64u,
    endpoint,
    operationFingerprintDigestB64u,
    rpId: actor.rpId,
    request: {
      requestedAtMs,
      walletAuthMethodId: target.walletAuthMethodId,
      walletId: actor.walletId,
    },
  });
  return result;
}

async function attemptRejectedRevocationTarget(
  page: Page,
  actor: OwnerCredentialSnapshot,
  validTargetWalletAuthMethodId: string,
  malformedTarget: unknown,
): Promise<BrowserPasskeyRevocationResult> {
  const walletId = parseWalletId(actor.walletId);
  const walletAuthMethodId = parseWalletAuthMethodId(validTargetWalletAuthMethodId);
  if (!walletId.ok) throw new Error(walletId.error.message);
  if (!walletAuthMethodId.ok) throw new Error(walletAuthMethodId.error.message);
  const requestedAtMs = Date.now();
  const operationFingerprintDigestB64u = await computeWalletAuthMethodRevokeOperationFingerprintV1({
    walletId: walletId.value,
    targetWalletAuthMethodId: walletAuthMethodId.value,
    requestedAtMs,
  });
  const endpoint = `${actor.routerOrigin}/wallets/${encodeURIComponent(actor.walletId)}/auth-methods/${encodeURIComponent(validTargetWalletAuthMethodId)}/revoke`;
  return await page.evaluate(revokeWalletAuthMethodInBrowser, {
    actorCredentialIdB64u: actor.credentialIdB64u,
    endpoint,
    operationFingerprintDigestB64u,
    rpId: actor.rpId,
    request: {
      requestedAtMs,
      walletAuthMethodId: malformedTarget,
      walletId: actor.walletId,
    },
  });
}

function assertRejectedRevocationTarget(result: BrowserPasskeyRevocationResult): void {
  const body = requireRecord(result.body, 'rejected auth-method target response');
  expect(result.status).toBeGreaterThanOrEqual(400);
  expect(body.ok).toBe(false);
  expect(body.code).toBe('invalid_body');
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
    walletAuthMethodId: owner.walletAuthMethodId,
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
  const rejected = page.waitForResponse(isRevokedWalletUnlockResponse, { timeout: 30_000 });
  await unlock.click();
  const response = await rejected;
  const failure = requireRecord(await response.json(), 'revoked owner wallet unlock response');
  const pathname = new URL(response.url()).pathname;
  if (pathname === '/wallet/unlock/challenge') {
    expect(failure).toMatchObject({
      ok: false,
      code: 'unknown_credential',
      message: 'Wallet has no registered passkey credential',
      unlockBackend: 'passkey',
    });
  } else {
    expect(failure).toMatchObject({
      ok: false,
      verified: false,
      code: 'unknown_credential',
      message: 'Credential is not active for this wallet',
      unlockBackend: 'passkey',
    });
  }
  await expect(page.locator('.w3a-profile-button-morphable')).toBeHidden();
  await expect(unlock).toBeVisible();
}

function isLinkedDeviceRevokeResponse(response: Response): boolean {
  const pathname = new URL(response.url()).pathname;
  return (
    response.request().method() === 'POST' &&
    pathname.startsWith('/wallet/device-linking/v1/devices/') &&
    pathname.endsWith('/revoke')
  );
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
  const parsed = await readLinkedDeviceInventory(page);
  const activeDevices = parsed.devices.filter(isActiveLinkedDevice);
  if (activeDevices.length !== 1) {
    throw new Error(`Expected one active linked device, received ${activeDevices.length}`);
  }
  const device = activeDevices[0];
  return {
    authMethodId: String(device.credential.walletAuthMethodId),
    deviceId: String(device.deviceId),
    enrollmentId: String(device.enrollmentId),
    keyManifestDigestB64u: String(device.keyManifestDigestB64u),
    revocationEpoch: device.revocationEpoch,
    state: device.state,
  };
}

async function readLinkedDeviceInventory(
  page: Page,
): Promise<ReturnType<typeof parseLinkedDeviceListResultV1>> {
  const menu = await openProfileMenu(page);
  const inventoryResponse = page.waitForResponse(isLinkedDeviceInventoryResponse, {
    timeout: 60_000,
  });
  await menu.getByRole('button', { name: /^Linked Devices\b/ }).click();
  const inventory = await inventoryResponse;
  const body = requireRecord(await inventory.json(), 'linked-device inventory response');
  expect(body.ok, `Linked-device inventory failed: ${JSON.stringify(body)}`).toBe(true);
  const parsed = parseLinkedDeviceListResultV1({
    devices: body.devices,
    ownerDevices: body.ownerDevices,
    nextCursor: body.nextCursor,
  });
  const dialog = page.getByRole('dialog', { name: 'Your devices', exact: true });
  await dialog.waitFor({ state: 'visible', timeout: 30_000 });
  await dialog.locator('.w3a-linked-devices-modal-close').click();
  await expect(dialog).toBeHidden({ timeout: 10_000 });
  await closeProfileMenu(page);
  return parsed;
}

async function assertLinkedDeviceRetired(
  page: Page,
  activation: LinkedActivationSnapshot,
): Promise<void> {
  const inventory = await readLinkedDeviceInventory(page);
  const matches = inventory.devices.filter(
    (device) =>
      String(device.deviceId) === activation.deviceId ||
      String(device.credential.walletAuthMethodId) === activation.authMethodId,
  );
  if (matches.length === 0) return;
  expect(matches).toHaveLength(1);
  const [target] = matches;
  expect(String(target.deviceId)).toBe(activation.deviceId);
  expect(String(target.credential.walletAuthMethodId)).toBe(activation.authMethodId);
  expect(target.state).toBe('revoked');
  expect(target.revocationEpoch).toBeGreaterThan(activation.revocationEpoch);
}

async function assertRevokedActiveSessionCannotOperate(input: {
  readonly page: Page;
  readonly diagnostics: readonly string[];
  readonly profile: SignerProfile;
  readonly emailOtp?: EmailOtpPromptContext;
}): Promise<void> {
  if (
    input.profile === 'ed25519' &&
    (await input.page.getByRole('button', { name: 'Sign on NEAR', exact: true }).isDisabled())
  ) {
    return;
  }
  let failure: unknown = null;
  try {
    if (input.profile === 'ed25519') {
      await greetingSigning(input.page, 'NEAR', input.diagnostics, input.emailOtp);
    } else {
      await linkedSigning(input.page, input.diagnostics, input.emailOtp);
    }
  } catch (error: unknown) {
    failure = error;
  }
  if (!failure) {
    throw new Error('A revoked linked-device session still completed a signing operation');
  }
  const failureText = [
    failure instanceof Error ? failure.message : String(failure),
    ...input.diagnostics,
  ].join('\n');
  expect(failureText).toMatch(
    /wallet[_ ]session.*(?:invalid|revok(?:ed|ation)|expired|ended|unavailable)|session.*(?:invalid|expired|ended)|(?:authority|auth(?:entication|orization)? method).*(?:invalid|inactive|revok(?:ed|ation)|unavailable)|no longer.*use|revok(?:ed|ation)/i,
  );
}

async function assertRevokedEmailOtpCannotUnlock(input: {
  readonly page: Page;
  readonly context: BrowserContext;
  readonly walletId: string;
  readonly profile: SignerProfile;
  readonly routerOrigin: string;
}): Promise<void> {
  let failure: unknown = null;
  try {
    await unlockEmailOtpWallet(
      input.page,
      input.context,
      input.walletId,
      input.profile,
      input.routerOrigin,
    );
  } catch (error: unknown) {
    failure = error;
  }
  if (!failure) throw new Error('A revoked Email OTP method unlocked the linked device');
  const failureText = [
    failure instanceof Error ? failure.message : String(failure),
    await readVisibleHostedAuthFailure(input.page),
  ]
    .filter(Boolean)
    .join('\n');
  expect(failureText).toMatch(
    /revok(?:ed|ation)|auth(?:entication|orization)? method.*(?:inactive|unavailable|not found)|active wallet auth(?:entication|orization)? method|(?:wallet )?session.*(?:invalid|unavailable|not found)|no active auth(?:entication|orization)? method|no longer.*use/i,
  );
}

function isActiveLinkedDevice(device: { readonly state: string }): boolean {
  return device.state === 'active';
}

async function assertLinkedDeviceInventoryLoaded(page: Page): Promise<void> {
  const dialog = await openLinkedDevicesDialog(page);
  const cards = dialog.locator('.w3a-linked-devices-modal-item');
  await expect(cards).toHaveCount(2, { timeout: 60_000 });
  await expect(cards.filter({ hasText: 'Email OTP' })).toHaveCount(2);
  await expect(cards.filter({ hasText: 'Original device' })).toHaveCount(1);
  await expect(cards.filter({ hasText: 'Can use this wallet' })).toHaveCount(1);
  await dialog.locator('.w3a-linked-devices-modal-close').click();
  await expect(dialog).toBeHidden({ timeout: 10_000 });
  await closeProfileMenu(page);
}

async function assertPasskeyInventoryLoaded(page: Page, expectedCardCount: number): Promise<void> {
  const dialog = await openLinkedDevicesDialog(page);
  const cards = dialog.locator('.w3a-linked-devices-modal-item');
  await expect(cards).toHaveCount(expectedCardCount, { timeout: 60_000 });
  await expect(dialog.getByText('Original device', { exact: true })).toHaveCount(1);
  await expect(dialog.getByText('Can use this wallet', { exact: true })).toHaveCount(
    expectedCardCount - 1,
  );
  await dialog.locator('.w3a-linked-devices-modal-close').click();
  await expect(dialog).toBeHidden({ timeout: 10_000 });
  await closeProfileMenu(page);
}

async function revokeLinkedEmailDeviceFromUi(
  input: { readonly page: Page } & EmailOtpPromptContext & {
      readonly activation: LinkedActivationSnapshot;
      readonly targetFactor: 'email_otp' | 'passkey_prf';
    },
): Promise<void> {
  const { page } = input;
  const dialog = await openLinkedDevicesDialog(page);
  const cards = dialog.locator('.w3a-linked-devices-modal-item');
  await expect(cards).toHaveCount(2, { timeout: 60_000 });
  await expect(cards.filter({ hasText: 'Email OTP' })).toHaveCount(
    input.targetFactor === 'email_otp' ? 2 : 1,
  );
  await expect(cards.filter({ hasText: 'Original device' })).toHaveCount(1);
  await expect(cards.filter({ hasText: 'Can use this wallet' })).toHaveCount(1);
  const remove = cards.getByRole('button', { name: /^Remove Device 2\b/ });
  await expect(remove).toHaveCount(1, { timeout: 30_000 });
  await remove.click();
  const challengeResponsePromise = page.waitForResponse(isLinkedDeviceEmailOtpChallengeResponse, {
    timeout: 60_000,
  });
  await dialog.getByRole('button', { name: 'Yes, remove', exact: true }).click();
  const challengeResponse = await challengeResponsePromise;
  expect(challengeResponse.ok()).toBe(true);
  const challengeBody = requireRecord(
    await challengeResponse.json(),
    'Email OTP linked-device revoke challenge response',
  );
  const challenge = requireRecord(
    challengeBody.challenge,
    'Email OTP linked-device revoke challenge response.challenge',
  );
  const challengeId = requireStringField(
    challenge,
    'challengeId',
    'Email OTP linked-device revoke challenge response.challenge',
  );
  const otpInput = dialog.getByRole('textbox', { name: 'Verification code', exact: true });
  await otpInput.waitFor({ state: 'visible', timeout: 30_000 });
  const otpCode = await readEmailOtpOutboxCode({
    context: input.context,
    walletId: input.walletId,
    routerOrigin: input.routerOrigin,
    challengeId,
  });
  await otpInput.fill(otpCode);
  const revokeResponsePromise = page.waitForResponse(isLinkedDeviceRevokeResponse, {
    timeout: 60_000,
  });
  const verify = dialog.getByRole('button', { name: 'Verify and remove', exact: true });
  await expect(verify).toBeEnabled();
  await verify.click();
  const revokeResponse = await revokeResponsePromise;
  expect(revokeResponse.ok()).toBe(true);
  const revoked = requireRecord(
    await revokeResponse.json(),
    'Email OTP linked-device revoke response',
  );
  expect(revoked).toMatchObject({ kind: 'revoked' });
  expect(String(revoked.walletAuthMethodId)).toBe(input.activation.authMethodId);
  expect(String(revoked.authorityId)).toBe(input.activation.authorityId);
  expect(Number(revoked.revocationEpoch)).toBeGreaterThan(input.activation.revocationEpoch);
  await expect(dialog.getByRole('status')).toContainText('can no longer use this wallet', {
    timeout: 60_000,
  });
  await expect(cards).toHaveCount(1, { timeout: 60_000 });
  await expect(cards.filter({ hasText: 'Email OTP' })).toHaveCount(1);
  await expect(cards.filter({ hasText: 'Original device' })).toHaveCount(1);
  await expect(cards.filter({ hasText: 'Can use this wallet' })).toHaveCount(0);
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

async function setupEmailLinkedOwnerPair(
  browser: Browser,
  profile?: SignerProfile,
): Promise<EmailLinkedOwnerPair>;
async function setupEmailLinkedOwnerPair(
  browser: Browser,
  profile: SignerProfile,
  sourceFactor: 'passkey',
): Promise<PasskeyOwnerEmailTargetPair>;
async function setupEmailLinkedOwnerPair(
  browser: Browser,
  profile: SignerProfile = 'combined',
  sourceFactor: 'email_otp' | 'passkey' = 'email_otp',
): Promise<EmailLinkedOwnerPair | PasskeyOwnerEmailTargetPair> {
  emailLinkedDeviceStage('creating browser contexts');
  const ownerContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const device2Context = await browser.newContext({ ignoreHTTPSErrors: true });
  await ownerContext.route(/https:\/\/[^/]*(?:near\.org|fastnear\.com)\//, fulfillNearRpc);
  await ownerContext.route(/https:\/\/[^/]*arc\.network\//, fulfillArcRpc);
  await device2Context.route(/https:\/\/[^/]*(?:near\.org|fastnear\.com)\//, fulfillNearRpc);
  await device2Context.route(/https:\/\/[^/]*arc\.network\//, fulfillArcRpc);
  await ownerContext.addInitScript(enableSigningSessionDiagnostics);
  await device2Context.addInitScript(enableSigningSessionDiagnostics);
  if (sourceFactor === 'email_otp') {
    await ownerContext.addInitScript(installGoogleIdentityStub, requireGoogleIdToken());
  }
  await device2Context.addInitScript(installGoogleIdentityStub, requireGoogleIdToken());
  const ownerPage = await ownerContext.newPage();
  const device2Page = await device2Context.newPage();
  const device2RequestPaths: string[] = [];
  trackRequestPaths(device2Page, device2RequestPaths);
  device2Page.on('framenavigated', (frame) => {
    if (frame === device2Page.mainFrame()) {
      console.log(`[email-linked-device] Device 2 navigated to ${frame.url()}`);
    }
  });
  /* Virtual authenticators also prove that linking itself performs no source
     WebAuthn operation. A Passkey source may already own one credential. */
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
  let linkedDeviceFailureMonitor: LinkedDeviceFailureMonitor | null = null;
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
    const passkeyOwner =
      sourceFactor === 'passkey'
        ? profile === 'combined'
          ? await registerOwner(ownerPage, ownerDiagnostics)
          : await registerPasskeyOwnerForProfile(ownerPage, profile)
        : null;
    const routerOrigin = passkeyOwner
      ? passkeyOwner.routerOrigin
      : new URL(directRegistrationConfig().relayerUrl).origin;
    let publicIdentity: WalletPublicIdentity;
    let sourceEmailAddress: string | null = null;
    if (passkeyOwner) {
      publicIdentity = passkeyOwner.publicIdentity;
    } else {
      const emailOwner = await registerEmailOwnerForProfile(ownerPage, ownerContext, profile);
      publicIdentity = emailOwner;
      sourceEmailAddress = emailOwner.emailAddress;
    }
    await assertSignerProfileActions(ownerPage, profile);
    if (passkeyOwner) {
      const ownerInventory = await readLinkedDeviceInventory(ownerPage);
      expect(ownerInventory.ownerDevices.map((device) => device.credential.kind)).toEqual([
        'passkey',
      ]);
    }
    const webauthnOperationsBeforeLink = webauthnOperations.length;
    const ownerLocalAuthorityBeforeLink = await readLocalAuthoritySnapshot(
      ownerPage,
      publicIdentity.walletId,
    );
    emailLinkedDeviceStage('opening Device 2 QR');
    linkedDeviceFailureMonitor = new LinkedDeviceFailureMonitor([
      { diagnostics: ownerDiagnostics, label: 'owner', page: ownerPage },
      { diagnostics: device2Diagnostics, label: 'device2', page: device2Page },
    ]);
    await linkedDeviceFailureMonitor.race(
      ownerPage.locator('.w3a-profile-button-morphable .w3a-user-account-button-trigger').click(),
    );

    const created = device2Page.waitForResponse(
      (response) =>
        new URL(response.url()).pathname.endsWith('/wallet/device-linking/v1/sessions') &&
        response.request().method() === 'POST' &&
        response.status() === 200,
      { timeout: linkedDeviceTransitionTimeoutMs },
    );
    const targetEmail = passkeyOwner
      ? linkedTargetEmailAddress(publicIdentity.walletId)
      : sourceEmailAddress;
    if (!targetEmail) throw new Error('Email linked-device source email is unavailable');
    const qrDataUrl = await linkedDeviceFailureMonitor.race(
      openDevice2Qr(device2Page, 'Email code', ` ${targetEmail.toUpperCase()} `),
    );
    const createdResponse = await linkedDeviceFailureMonitor
      .race(created)
      .catch((error: unknown) => {
        throw new Error(
          `Device 2 did not create an email-factor link session.\n${device2Diagnostics.join('\n')}`,
          { cause: error },
        );
      });
    /* The email factor was chosen before the QR existed: the session-create
       request itself carries the discriminator. */
    expect(findTargetFactorKind(createdResponse.request().postDataJSON())).toBe('email_otp');
    const createdRequest = requireRecord(
      createdResponse.request().postDataJSON(),
      'Email linked-device session-create request',
    );
    const createdPayload = requireRecord(
      createdRequest.payload,
      'Email linked-device session-create request.payload',
    );
    expect(createdPayload.targetEmail).toBe(targetEmail);
    const ownerApproval = ownerPage.waitForResponse(isLinkedDeviceOwnerApprovalResponse, {
      timeout: linkedDeviceTransitionTimeoutMs,
    });
    const targetPreparation = device2Page.waitForResponse(isLinkedDeviceTargetPreparationResponse, {
      timeout: linkedDeviceTransitionTimeoutMs,
    });
    const emailOtpVerification = device2Page.waitForResponse(
      isLinkedDeviceEmailOtpVerificationResponse,
      { timeout: linkedDeviceTransitionTimeoutMs },
    );
    const committedPackages = device2Page.waitForResponse(isCommittedAuthorityPackagesResponse, {
      timeout: linkedDeviceTransitionTimeoutMs,
    });
    const authorityActivation = device2Page.waitForResponse(isAuthorityActivationResponse, {
      timeout: linkedDeviceTransitionTimeoutMs,
    });
    const activationAcknowledgement = device2Page.waitForResponse(
      isAuthorityActivationAcknowledgementResponse,
      { timeout: linkedDeviceTransitionTimeoutMs },
    );
    const claimed = ownerPage.waitForResponse(
      (response) =>
        response.request().method() === 'POST' &&
        new URL(response.url()).pathname.endsWith('/claim'),
      { timeout: linkedDeviceTransitionTimeoutMs },
    );
    const emailChallenge = device2Page.waitForResponse(isLinkedDeviceEmailOtpChallengeResponse, {
      timeout: linkedDeviceTransitionTimeoutMs,
    });
    const targetCredentialCommit = device2Page.waitForResponse(
      (response) =>
        response.status() === 200 &&
        response.request().method() === 'POST' &&
        new URL(response.url()).pathname.endsWith('/credential'),
      { timeout: linkedDeviceTransitionTimeoutMs },
    );
    await linkedDeviceFailureMonitor.race(openOwnerScanner(ownerPage, qrDataUrl));
    await linkedDeviceFailureMonitor.race(assertOwnerScannerClosedAfterScan(ownerPage));
    emailLinkedDeviceStage('owner scanned Device 2 QR');
    const claimResponse = await linkedDeviceFailureMonitor
      .race(
        sourceFactor === 'email_otp'
          ? completeEmailOtpPromptsUntil({
              page: ownerPage,
              context: ownerContext,
              walletId: publicIdentity.walletId,
              routerOrigin,
              task: claimed,
            })
          : claimed,
      )
      .catch((error: unknown) => {
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
    const approvalResponse = await linkedDeviceFailureMonitor.race(ownerApproval);
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

    const challengeResponse = await linkedDeviceFailureMonitor.race(emailChallenge);
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
    const preparationResponse = await linkedDeviceFailureMonitor.race(targetPreparation);
    const preparation = parseLinkedDeviceTargetPreparationV1(await preparationResponse.json());
    expect(preparation.walletId).toBe(publicIdentity.walletId);
    expect(preparation.targetFactor.kind).toBe('email_otp');
    if (!preparation.targetEmail || !preparation.enrollment) {
      throw new Error('Email linked-device target preparation omitted its enrollment identity');
    }
    expect(preparation.targetEmail).toBe(targetEmail);
    const preparationEnrollment = preparation.enrollment;
    expect(preparation.ordinarySignerMaterialRecipientRequirements.length).toBeGreaterThan(0);
    const device2Wallet = await linkedDeviceFailureMonitor.race(walletFrame(device2Page));
    const otpInput = device2Wallet.getByRole('textbox', { name: 'Email verification code' });
    await linkedDeviceFailureMonitor.race(
      otpInput.waitFor({ state: 'visible', timeout: linkedDeviceTransitionTimeoutMs }),
    );
    const otpCode = await linkedDeviceFailureMonitor.race(
      readEmailOtpOutboxCode({
        context: device2Context,
        walletId: publicIdentity.walletId,
        routerOrigin,
        challengeId,
        ...(passkeyOwner ? { challengeSubjectId: targetEmail } : {}),
      }),
    );
    await linkedDeviceFailureMonitor.race(otpInput.fill(otpCode));
    const verificationResponse = await linkedDeviceFailureMonitor.race(emailOtpVerification);
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
    expect(verification.verificationGrant.targetEmail).toBe(targetEmail);
    if (passkeyOwner) {
      expect(preparationEnrollment.kind).toBe('new_enrollment');
      expect(verification.verificationGrant.enrollment.kind).toBe('new_enrollment');
      expect(verification.factorRelease).toBeNull();
    } else {
      expect(preparationEnrollment.kind).toBe('existing_enrollment');
      expect(verification.verificationGrant.enrollment.kind).toBe('existing_enrollment');
      expect(verification.factorRelease?.challengeId).toBe(challengeId);
    }
    const credentialCommitted = await linkedDeviceFailureMonitor.race(targetCredentialCommit);
    emailLinkedDeviceStage('Device 2 submitted Email OTP');
    if (!credentialCommitted.ok()) {
      throw new Error(
        `Email linked-device credential commit failed (${credentialCommitted.status()}): ${await credentialCommitted.text()}`,
      );
    }
    const registrationRequest = requireRecord(
      credentialCommitted.request().postDataJSON(),
      'Email linked-device credential registration request',
    );
    if (passkeyOwner) {
      expect(registrationRequest.emailOtpEnrollment).toBeDefined();
    } else {
      expect(registrationRequest.emailOtpEnrollment).toBeUndefined();
    }
    const credentialResponse = requireRecord(
      await credentialCommitted.json(),
      'Email linked-device credential response',
    );
    const targetCredential = parseLinkedDeviceTargetCredentialRegistrationResultV1(
      credentialResponse.targetCredential,
    );
    expect(targetCredential.walletId).toBe(publicIdentity.walletId);
    expect(targetCredential.linkSessionId).toBe(preparation.linkSessionId);
    expect(targetCredential.enrollmentId).toBe(preparation.enrollmentId);
    expect(targetCredential.deviceId).toBe(preparation.deviceId);
    expect(String(targetCredential.walletAuthMethodId)).toBe(
      String(preparation.walletAuthMethodId),
    );
    expect(targetCredential.targetFactor.kind).toBe('verified_email_otp_target_v1');
    expect(targetCredential.ordinarySignerMaterialPreparations.length).toBeGreaterThan(0);
    expect(targetCredential.ordinarySignerMaterialRecipientRequests.length).toBe(
      preparation.ordinarySignerMaterialRecipientRequirements.length,
    );
    /* The emailed code is the only target-factor proof: linking sent exactly
       one challenge, never a resend, and neither device touched WebAuthn. */
    expect(emailChallengeStarts).toBe(1);
    expect(emailChallengeResends).toBe(0);
    expect(webauthnOperations.slice(webauthnOperationsBeforeLink)).toEqual([]);
    const committedResponse = await linkedDeviceFailureMonitor.race(committedPackages);
    const committed = parseCommittedAuthorityPackagesV1(await committedResponse.json());
    expect(committed.authority.walletId).toBe(publicIdentity.walletId);
    expect(String(committed.authority.principal.deviceId)).toBe(String(preparation.deviceId));
    expect(String(committed.authMethod.walletAuthMethodId)).toBe(
      String(preparation.walletAuthMethodId),
    );
    expect(committed.authority.provenance).toMatchObject({
      enrollmentId: preparation.enrollmentId,
      kind: 'device_link',
      linkSessionId: preparation.linkSessionId,
    });
    if (ownerLocalAuthorityBeforeLink) {
      expect(committed.authority.provenance).toMatchObject({
        sourceAuthorityId: ownerLocalAuthorityBeforeLink.authorityId,
      });
    }
    const activationResponse = await linkedDeviceFailureMonitor.race(authorityActivation);
    const activated = parseActivateInstalledAuthorityResultV1(await activationResponse.json());
    expect(activated.kind).toBe('active');
    expect(activated.walletSession.walletId).toBe(publicIdentity.walletId);
    expect(String(activated.authority.authorityId)).toBe(String(committed.authority.authorityId));
    expect(String(activated.authMethod.walletAuthMethodId)).toBe(
      String(committed.authMethod.walletAuthMethodId),
    );
    expect(activated.authority.signerActivations).toEqual(committed.authority.signerActivations);
    expect(activated.authority.signerActivationSetDigestB64u).toBe(
      committed.authority.signerActivationSetDigestB64u,
    );
    expect(activated.authority.revocationEpoch).toBe(committed.authority.revocationEpoch);
    expect(committed.authority.localInstallPackageSetDigestB64u).toBe(
      committed.packageSetDigestB64u,
    );
    expect(activated.walletSession.authorityDigestB64u).toBe(
      activated.authority.authorityDigestB64u,
    );
    expect(activated.walletSession.authorityRevocationEpoch).toBe(
      activated.authority.revocationEpoch,
    );
    expect(activated.walletSession.authMethodId).toBe(activated.authMethod.walletAuthMethodId);
    const acknowledgementResponse =
      await linkedDeviceFailureMonitor.race(activationAcknowledgement);
    expect(acknowledgementResponse.status()).toBe(204);
    const acknowledgement = parseLocalAuthorityActivationFinalAckV1(
      acknowledgementResponse.request().postDataJSON(),
    );
    expect(acknowledgement.linkSessionId).toBe(preparation.linkSessionId);
    expect(acknowledgement.authorityId).toBe(activated.walletSession.authorityId);
    expect(acknowledgement.packageSetDigestB64u).toBe(committed.packageSetDigestB64u);
    expect(acknowledgement.authorizationId).toBe(activated.walletSession.authorizationId);
    await linkedDeviceFailureMonitor.race(
      waitForLinkedDeviceActive(device2Page, device2Diagnostics, ownerDiagnostics, profile),
    );
    assertSelectedWalletAuthorityResolved(
      await readSelectedWalletAuthorityResolution(device2Page, publicIdentity.walletId),
      'Device 2 selected authority before reload',
    );
    await linkedDeviceFailureMonitor.race(
      assertImmediateLinkedWalletOperations({
        page: device2Page,
        diagnostics: device2Diagnostics,
        publicIdentity,
        profile,
        emailOtp: {
          context: device2Context,
          walletId: publicIdentity.walletId,
          routerOrigin,
          challengeSubjectId: targetEmail,
        },
      }),
    );
    assertNoUnlockOrNearFundingAfterLink(device2RequestPaths);
    emailLinkedDeviceStage('Device 2 immediate signing and export complete');
    linkedDeviceFailureMonitor.stop();
    const inventoryBeforeReload = await readActiveLinkedDeviceInventory(ownerPage);
    expect(inventoryBeforeReload.deviceId).toBe(String(targetCredential.deviceId));
    expect(inventoryBeforeReload.enrollmentId).toBe(String(targetCredential.enrollmentId));
    expect(inventoryBeforeReload.authMethodId).toBe(String(targetCredential.walletAuthMethodId));
    expect(inventoryBeforeReload.keyManifestDigestB64u).toBe(
      String(activated.authority.signerActivationSetDigestB64u),
    );
    expect(inventoryBeforeReload.revocationEpoch).toBe(activated.authority.revocationEpoch);
    await ownerPage.reload({ waitUntil: 'domcontentloaded' });
    await ownerPage
      .locator('.w3a-profile-button-morphable')
      .waitFor({ state: 'visible', timeout: 120_000 });
    assertSelectedWalletAuthorityResolved(
      await readSelectedWalletAuthorityResolution(ownerPage, publicIdentity.walletId),
      'Device 1 selected authority after reload',
    );
    await lockActiveWallet(ownerPage);
    if (sourceFactor === 'email_otp') {
      await unlockEmailOtpWallet(
        ownerPage,
        ownerContext,
        publicIdentity.walletId,
        profile,
        routerOrigin,
      );
    } else {
      await unlockLinkedPasskeyWallet(ownerPage, ownerDiagnostics, profile);
    }
    await assertSignerProfileActions(ownerPage, profile);
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
    if (passkeyOwner) {
      await unlockAddressEmailOtpWallet({
        page: device2Page,
        context: device2Context,
        walletId: publicIdentity.walletId,
        walletAuthMethodId: String(targetCredential.walletAuthMethodId),
        routerOrigin,
      });
    } else {
      await unlockEmailOtpWallet(
        device2Page,
        device2Context,
        publicIdentity.walletId,
        profile,
        routerOrigin,
      );
    }
    emailLinkedDeviceStage('Device 2 unlock complete');
    await assertSignerProfileActions(device2Page, profile);
    emailLinkedDeviceStage('Device 2 owner controls enabled');
    expect(await readActiveWalletId(device2Page)).toBe(publicIdentity.walletId);
    const ownerLocalAuthorityAfterLink = await readLocalAuthoritySnapshot(
      ownerPage,
      publicIdentity.walletId,
    );
    assertLocalAuthoritySnapshotStable(ownerLocalAuthorityBeforeLink, ownerLocalAuthorityAfterLink);
    const inventoryAfterReload = await readActiveLinkedDeviceInventory(ownerPage);
    expect(inventoryAfterReload).toEqual(inventoryBeforeReload);
    const activation: LinkedActivationSnapshot = {
      authMethodId: String(committed.authMethod.walletAuthMethodId),
      authorizationId: String(activated.walletSession.authorizationId),
      authorityId: String(activated.authority.authorityId),
      deviceId: String(committed.authority.principal.deviceId),
      enrollmentId: String(preparation.enrollmentId),
      linkSessionId: String(preparation.linkSessionId),
      packageSetDigestB64u: String(committed.packageSetDigestB64u),
      revocationEpoch: committed.authority.revocationEpoch,
    };
    const pair: EmailLinkedOwnerPair = {
      ownerContext,
      device2Context,
      ownerPage,
      device2Page,
      ownerDiagnostics,
      device2Diagnostics,
      publicIdentity,
      routerOrigin,
      activation,
    };
    if (passkeyOwner) {
      return { ...pair, source: { kind: 'passkey', owner: passkeyOwner } };
    }
    return pair;
  } catch (error) {
    linkedDeviceFailureMonitor?.stop();
    await closeBrowserContexts(ownerContext, device2Context);
    throw error;
  }
}

async function setupLinkedOwnerPair(
  browser: Browser,
  profile?: SignerProfile,
): Promise<LinkedOwnerPair>;
async function setupLinkedOwnerPair(
  browser: Browser,
  profile: SignerProfile,
  sourceFactor: 'email_otp',
): Promise<EmailOwnerPasskeyTargetPair>;
async function setupLinkedOwnerPair(
  browser: Browser,
  profile: SignerProfile = 'combined',
  sourceFactor: 'email_otp' | 'passkey' = 'passkey',
): Promise<LinkedOwnerPair | EmailOwnerPasskeyTargetPair> {
  passkeyLinkedDeviceStage(`creating ${profile} browser contexts`);
  const ownerContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const device2Context = await browser.newContext({ ignoreHTTPSErrors: true });
  await ownerContext.route(/https:\/\/[^/]*(?:near\.org|fastnear\.com)\//, fulfillNearRpc);
  await ownerContext.route(/https:\/\/[^/]*arc\.network\//, fulfillArcRpc);
  await device2Context.route(/https:\/\/[^/]*(?:near\.org|fastnear\.com)\//, fulfillNearRpc);
  await device2Context.route(/https:\/\/[^/]*arc\.network\//, fulfillArcRpc);
  await ownerContext.addInitScript(enableSigningSessionDiagnostics);
  await device2Context.addInitScript(enableSigningSessionDiagnostics);
  if (sourceFactor === 'email_otp') {
    await ownerContext.addInitScript(installGoogleIdentityStub, requireGoogleIdToken());
  }
  const ownerPage = await ownerContext.newPage();
  const device2Page = await device2Context.newPage();
  const device2RequestPaths: string[] = [];
  trackRequestPaths(device2Page, device2RequestPaths);
  const ownerAuthenticator = await addVirtualAuthenticator(ownerPage);
  const device2Authenticator = await addVirtualAuthenticator(device2Page);
  const ownerCredentialAddedEvents: unknown[] = [];
  const ownerCredentialAssertedEvents: unknown[] = [];
  const device2CredentialAddedEvents: unknown[] = [];
  const device2CredentialAssertedEvents: unknown[] = [];
  ownerAuthenticator.on('WebAuthn.credentialAdded', (event) => {
    ownerCredentialAddedEvents.push(event);
  });
  ownerAuthenticator.on('WebAuthn.credentialAsserted', (event) => {
    ownerCredentialAssertedEvents.push(event);
  });
  device2Authenticator.on('WebAuthn.credentialAdded', (event) => {
    device2CredentialAddedEvents.push(event);
  });
  device2Authenticator.on('WebAuthn.credentialAsserted', (event) => {
    device2CredentialAssertedEvents.push(event);
  });
  const ownerDiagnostics: string[] = [];
  const device2Diagnostics: string[] = [];
  let linkedDeviceFailureMonitor: LinkedDeviceFailureMonitor | null = null;
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
        /Device2Linking|linked-device|WalletSession|WebAuthn|bridge|passkey/i.test(text)
      ) {
        device2Diagnostics.push(`[device2:${message.type()}] ${text}`);
      }
    });
    passkeyLinkedDeviceStage(`registering ${profile} owner`);
    const passkeyOwner =
      sourceFactor === 'passkey'
        ? profile === 'combined'
          ? await registerOwner(ownerPage, ownerDiagnostics)
          : await registerPasskeyOwnerForProfile(ownerPage, profile)
        : null;
    const config = directRegistrationConfig();
    const publicIdentity =
      passkeyOwner?.publicIdentity ??
      (profile === 'combined'
        ? await registerEmailOwner(ownerPage, ownerContext)
        : await registerEmailOwnerForProfile(ownerPage, ownerContext, profile));
    const routerOrigin = passkeyOwner
      ? passkeyOwner.routerOrigin
      : new URL(config.relayerUrl).origin;
    passkeyLinkedDeviceStage(`${profile} owner registered`);
    await assertSignerProfileActions(ownerPage, profile);
    const ownerLocalAuthorityBeforeLink = await readLocalAuthoritySnapshot(
      ownerPage,
      publicIdentity.walletId,
    );
    linkedDeviceFailureMonitor = new LinkedDeviceFailureMonitor([
      { diagnostics: ownerDiagnostics, label: 'owner', page: ownerPage },
      { diagnostics: device2Diagnostics, label: 'device2', page: device2Page },
    ]);
    await linkedDeviceFailureMonitor.race(
      ownerPage.locator('.w3a-profile-button-morphable .w3a-user-account-button-trigger').click(),
    );

    passkeyLinkedDeviceStage('opening Device 2 QR');
    const created = device2Page.waitForResponse(
      (response) =>
        new URL(response.url()).pathname.endsWith('/wallet/device-linking/v1/sessions') &&
        response.request().method() === 'POST' &&
        response.status() === 200,
      { timeout: linkedDeviceTransitionTimeoutMs },
    );
    const qrDataUrl = await linkedDeviceFailureMonitor.race(openDevice2Qr(device2Page, 'Passkey'));
    await linkedDeviceFailureMonitor.race(created);
    const targetPreparation = device2Page.waitForResponse(isLinkedDeviceTargetPreparationResponse, {
      timeout: linkedDeviceTransitionTimeoutMs,
    });
    const targetCredentialCommit = device2Page.waitForResponse(
      (response) =>
        response.status() === 200 &&
        response.request().method() === 'POST' &&
        new URL(response.url()).pathname.endsWith('/credential'),
      { timeout: linkedDeviceTransitionTimeoutMs },
    );
    const committedPackages = device2Page.waitForResponse(isCommittedAuthorityPackagesResponse, {
      timeout: linkedDeviceTransitionTimeoutMs,
    });
    const authorityActivation = device2Page.waitForResponse(isAuthorityActivationResponse, {
      timeout: linkedDeviceTransitionTimeoutMs,
    });
    const activationAcknowledgement = device2Page.waitForResponse(
      isAuthorityActivationAcknowledgementResponse,
      { timeout: linkedDeviceTransitionTimeoutMs },
    );
    const sourceContributionExecution =
      profile === 'ecdsa'
        ? null
        : ownerPage.waitForResponse(
            (response) =>
              response.request().method() === 'POST' &&
              new URL(response.url()).pathname.endsWith('/source-contribution/execute'),
            { timeout: linkedDeviceTransitionTimeoutMs },
          );
    const claimed = ownerPage
      .waitForResponse(
        (response) =>
          response.url().includes('/wallet/device-linking/v1/sessions/') &&
          response.url().endsWith('/claim') &&
          response.request().method() === 'POST',
        { timeout: linkedDeviceTransitionTimeoutMs },
      )
      .then(
        (response) => ({ kind: 'claimed' as const, response }),
        (error: unknown) => ({ error, kind: 'timeout' as const }),
      );
    const ownerCredentialAssertionsBeforeLinking = ownerCredentialAssertedEvents.length;
    const ownerCredentialCreationsBeforeLinking = ownerCredentialAddedEvents.length;
    await linkedDeviceFailureMonitor.race(openOwnerScanner(ownerPage, qrDataUrl));
    await linkedDeviceFailureMonitor.race(assertOwnerScannerClosedAfterScan(ownerPage));
    passkeyLinkedDeviceStage('Device 1 scanned Device 2 QR');
    const claimResult = await linkedDeviceFailureMonitor.race(claimed);
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
    const device2Wallet = await linkedDeviceFailureMonitor.race(walletFrame(device2Page));
    const createTargetPasskey = device2Wallet.locator('[data-link-device-passkey-action]');
    await linkedDeviceFailureMonitor.race(
      createTargetPasskey.waitFor({
        state: 'visible',
        timeout: linkedDeviceTransitionTimeoutMs,
      }),
    );
    await linkedDeviceFailureMonitor.race(createTargetPasskey.focus());
    await linkedDeviceFailureMonitor.race(createTargetPasskey.press('Enter'));
    const preparationResponse = await linkedDeviceFailureMonitor.race(targetPreparation);
    const preparation = parseLinkedDeviceTargetPreparationV1(await preparationResponse.json());
    expect(preparation.walletId).toBe(publicIdentity.walletId);
    expect(preparation.targetFactor.kind).toBe('passkey_prf');
    expect(preparation.passkeyCreationOptions.walletAuthMethodId).toBe(
      preparation.walletAuthMethodId,
    );
    expect(preparation.ordinarySignerMaterialRecipientRequirements.length).toBeGreaterThan(0);
    const credentialCommitted = await linkedDeviceFailureMonitor.race(targetCredentialCommit);
    if (!credentialCommitted.ok()) {
      throw new Error(
        `Passkey linked-device credential commit failed (${credentialCommitted.status()}): ${await credentialCommitted.text()}`,
      );
    }
    const credentialResponse = requireRecord(
      await credentialCommitted.json(),
      'Passkey linked-device credential response',
    );
    if (sourceContributionExecution) {
      const sourceContributionResponse = await linkedDeviceFailureMonitor.race(
        sourceContributionExecution,
      );
      if (!sourceContributionResponse.ok()) {
        throw new Error(
          `Linked-device source contribution failed (${sourceContributionResponse.status()}): ${await sourceContributionResponse.text()}`,
        );
      }
    }
    const targetCredential = parseLinkedDeviceTargetCredentialRegistrationResultV1(
      credentialResponse.targetCredential,
    );
    expect(targetCredential.walletId).toBe(publicIdentity.walletId);
    expect(targetCredential.linkSessionId).toBe(preparation.linkSessionId);
    expect(targetCredential.enrollmentId).toBe(preparation.enrollmentId);
    expect(targetCredential.deviceId).toBe(preparation.deviceId);
    expect(String(targetCredential.walletAuthMethodId)).toBe(
      String(preparation.walletAuthMethodId),
    );
    expect(targetCredential.targetFactor.kind).toBe('verified_passkey_target_v1');
    expect(targetCredential.ordinarySignerMaterialPreparations.length).toBeGreaterThan(0);
    expect(targetCredential.ordinarySignerMaterialRecipientRequests.length).toBe(
      preparation.ordinarySignerMaterialRecipientRequirements.length,
    );
    await linkedDeviceFailureMonitor.race(
      expect(device2Wallet.getByText('Generating QR code', { exact: false })).toBeHidden(),
    );
    /* The owner scanner is the sole approval action. Device 2 creates exactly
       one target passkey, and Device 1 performs no WebAuthn operation. */
    expect(
      ownerCredentialAssertedEvents.slice(ownerCredentialAssertionsBeforeLinking),
    ).toHaveLength(0);
    expect(ownerCredentialAddedEvents.slice(ownerCredentialCreationsBeforeLinking)).toHaveLength(0);
    expect(device2CredentialAddedEvents).toHaveLength(1);
    const committedResponse = await linkedDeviceFailureMonitor.race(committedPackages);
    const committed = parseCommittedAuthorityPackagesV1(await committedResponse.json());
    expect(committed.authority.walletId).toBe(publicIdentity.walletId);
    expect(String(committed.authority.principal.deviceId)).toBe(String(preparation.deviceId));
    expect(String(committed.authMethod.walletAuthMethodId)).toBe(
      String(preparation.walletAuthMethodId),
    );
    expect(committed.authority.provenance).toMatchObject({
      enrollmentId: preparation.enrollmentId,
      kind: 'device_link',
      linkSessionId: preparation.linkSessionId,
    });
    if (ownerLocalAuthorityBeforeLink) {
      expect(committed.authority.provenance).toMatchObject({
        sourceAuthorityId: ownerLocalAuthorityBeforeLink.authorityId,
      });
    }
    const activationResponse = await linkedDeviceFailureMonitor.race(authorityActivation);
    const activated = parseActivateInstalledAuthorityResultV1(await activationResponse.json());
    expect(activated.kind).toBe('active');
    expect(activated.walletSession.walletId).toBe(publicIdentity.walletId);
    expect(String(activated.authority.authorityId)).toBe(String(committed.authority.authorityId));
    expect(String(activated.authMethod.walletAuthMethodId)).toBe(
      String(committed.authMethod.walletAuthMethodId),
    );
    expect(activated.authority.signerActivations).toEqual(committed.authority.signerActivations);
    expect(activated.authority.signerActivationSetDigestB64u).toBe(
      committed.authority.signerActivationSetDigestB64u,
    );
    expect(activated.authority.revocationEpoch).toBe(committed.authority.revocationEpoch);
    expect(committed.authority.localInstallPackageSetDigestB64u).toBe(
      committed.packageSetDigestB64u,
    );
    expect(activated.walletSession.authorityDigestB64u).toBe(
      activated.authority.authorityDigestB64u,
    );
    expect(activated.walletSession.authorityRevocationEpoch).toBe(
      activated.authority.revocationEpoch,
    );
    expect(activated.walletSession.authMethodId).toBe(activated.authMethod.walletAuthMethodId);
    const acknowledgementResponse =
      await linkedDeviceFailureMonitor.race(activationAcknowledgement);
    expect(acknowledgementResponse.status()).toBe(204);
    const acknowledgement = parseLocalAuthorityActivationFinalAckV1(
      acknowledgementResponse.request().postDataJSON(),
    );
    expect(acknowledgement.linkSessionId).toBe(preparation.linkSessionId);
    expect(acknowledgement.authorityId).toBe(activated.walletSession.authorityId);
    expect(acknowledgement.packageSetDigestB64u).toBe(committed.packageSetDigestB64u);
    expect(acknowledgement.authorizationId).toBe(activated.walletSession.authorizationId);
    await linkedDeviceFailureMonitor.race(
      waitForLinkedDeviceActive(device2Page, device2Diagnostics, ownerDiagnostics, profile),
    );
    passkeyLinkedDeviceStage('Device 2 authority active');
    assertSelectedWalletAuthorityResolved(
      await readSelectedWalletAuthorityResolution(device2Page, publicIdentity.walletId),
      'Device 2 selected authority before reload',
    );
    await linkedDeviceFailureMonitor.race(
      assertImmediateLinkedWalletOperations({
        page: device2Page,
        diagnostics: device2Diagnostics,
        publicIdentity,
        profile,
      }),
    );
    assertNoUnlockOrNearFundingAfterLink(device2RequestPaths);
    passkeyLinkedDeviceStage('Device 2 immediate signing and export complete');
    const activation: LinkedActivationSnapshot = {
      authMethodId: String(committed.authMethod.walletAuthMethodId),
      authorizationId: String(activated.walletSession.authorizationId),
      authorityId: String(activated.authority.authorityId),
      deviceId: String(committed.authority.principal.deviceId),
      enrollmentId: String(preparation.enrollmentId),
      linkSessionId: String(preparation.linkSessionId),
      packageSetDigestB64u: String(committed.packageSetDigestB64u),
      revocationEpoch: committed.authority.revocationEpoch,
    };
    expect(activation.authorityId).toBe(String(acknowledgement.authorityId));
    expect(activation.packageSetDigestB64u).toBe(String(acknowledgement.packageSetDigestB64u));
    const inventoryBeforeReload = await readActiveLinkedDeviceInventory(ownerPage);
    expect(inventoryBeforeReload.deviceId).toBe(activation.deviceId);
    expect(inventoryBeforeReload.authMethodId).toBe(activation.authMethodId);
    expect(inventoryBeforeReload.enrollmentId).toBe(activation.enrollmentId);
    expect(inventoryBeforeReload.revocationEpoch).toBe(activation.revocationEpoch);
    await ownerPage.reload({ waitUntil: 'domcontentloaded' });
    await lockWallet(ownerPage);
    if (sourceFactor === 'passkey') {
      await unlockLinkedPasskeyWallet(ownerPage, ownerDiagnostics, profile);
    } else {
      await unlockEmailOtpWallet(
        ownerPage,
        ownerContext,
        publicIdentity.walletId,
        profile,
        routerOrigin,
      );
    }
    passkeyLinkedDeviceStage('Device 1 reload unlock complete');
    await assertSignerProfileActions(ownerPage, profile);
    const ownerLocalAuthorityAfterLink = await readLocalAuthoritySnapshot(
      ownerPage,
      publicIdentity.walletId,
    );
    assertLocalAuthoritySnapshotStable(ownerLocalAuthorityBeforeLink, ownerLocalAuthorityAfterLink);
    const expectedDevice2: AuthenticatedOwnerSnapshot = {
      credentialIdB64u: credentialIdB64uFromAddedEvent(device2CredentialAddedEvents[0]),
      walletAuthMethodId: activation.authMethodId,
      publicIdentity,
      routerOrigin,
      rpId: config.rpId,
    };
    await device2Page.reload({ waitUntil: 'domcontentloaded' });
    assertSelectedWalletAuthorityResolved(
      await readSelectedWalletAuthorityResolution(device2Page, publicIdentity.walletId),
      'Device 2 selected authority after reload',
    );
    await lockWallet(device2Page);
    await linkedDeviceFailureMonitor.race(
      unlockLinkedPasskeyWallet(device2Page, device2Diagnostics, profile),
    );
    await lockWallet(device2Page);
    await linkedDeviceFailureMonitor.race(
      unlockLinkedPasskeyWallet(device2Page, device2Diagnostics, profile),
    );
    passkeyLinkedDeviceStage('Device 2 double reload unlock complete');
    linkedDeviceFailureMonitor.stop();
    await assertSignerProfileActions(device2Page, profile);
    const device2WalletId = await readActiveWalletId(device2Page);
    expect(device2WalletId).toBe(publicIdentity.walletId);
    const inventoryAfterReload = await readActiveLinkedDeviceInventory(ownerPage);
    expect(inventoryAfterReload).toEqual(inventoryBeforeReload);
    expect(inventoryAfterReload.deviceId).toBe(activation.deviceId);
    expect(inventoryAfterReload.authMethodId).toBe(activation.authMethodId);
    expect(inventoryAfterReload.keyManifestDigestB64u).toBe(
      inventoryBeforeReload.keyManifestDigestB64u,
    );
    const device2 = ownerCredentialSnapshot(expectedDevice2);
    const common = {
      ownerContext,
      device2Context,
      ownerPage,
      device2Page,
      ownerDiagnostics,
      device2Diagnostics,
      device2CredentialAssertedEvents,
      device2,
      activation,
    };
    if (passkeyOwner) return { ...common, owner: passkeyOwner };
    return {
      ...common,
      source: { kind: 'email_otp', publicIdentity, routerOrigin },
    };
  } catch (error) {
    linkedDeviceFailureMonitor?.stop();
    await closeBrowserContexts(ownerContext, device2Context);
    throw error;
  }
}

async function assertPasskeySignerProfilePath(
  pair: LinkedOwnerPair,
  profile: SignerProfile,
): Promise<void> {
  passkeyLinkedDeviceStage(`${profile} linked pair ready`);
  await assertSignerProfileActions(pair.device2Page, profile);
  await assertPasskeyInventoryLoaded(pair.ownerPage, 2);
  if (profile !== 'ecdsa') {
    const near = requireNearIdentity(pair.owner.publicIdentity);
    const exported = await exportPasskeyOwnerKey(pair, 'near');
    passkeyLinkedDeviceStage('Device 2 NEAR export complete');
    expect(exported.accountId).toBe(near.accountId);
    expect(exported.entries.map((entry) => entry.publicKey)).toEqual([near.publicKey]);
    await greetingSigning(pair.device2Page, 'NEAR', pair.device2Diagnostics);
    passkeyLinkedDeviceStage('Device 2 NEAR signing complete');
  }
  if (profile !== 'ed25519') {
    const exported = await exportPasskeyOwnerKey(pair, 'evm');
    expect(
      exported.entries
        .map((entry) => `${entry.publicKey.toLowerCase()}:${entry.address.toLowerCase()}`)
        .sort(),
    ).toEqual(pair.owner.publicIdentity.ecdsaKeys);
    await linkedSigning(pair.device2Page, pair.device2Diagnostics);
    await greetingSigning(pair.device2Page, 'Arc', pair.device2Diagnostics);
  }

  await lockWallet(pair.device2Page);
  await unlockLinkedPasskeyWallet(pair.device2Page, pair.device2Diagnostics, profile);
  await assertSignerProfileActions(pair.device2Page, profile);

  await revokeOwner(pair.ownerPage, ownerCredentialSnapshot(pair.owner), pair.device2);
  passkeyLinkedDeviceStage('Device 1 revoked Device 2');
  await assertPasskeyInventoryLoaded(pair.ownerPage, 1);
  await assertLinkedDeviceRetired(pair.ownerPage, pair.activation);
  await assertRevokedActiveSessionCannotOperate({
    page: pair.device2Page,
    diagnostics: pair.device2Diagnostics,
    profile,
  });
  await lockWallet(pair.device2Page);
  await assertRevokedOwnerCannotUnlock(pair.device2Page);
  if (profile !== 'ed25519') {
    await linkedSigning(pair.ownerPage, pair.ownerDiagnostics);
  } else {
    await greetingSigning(pair.ownerPage, 'NEAR', pair.ownerDiagnostics);
  }
  expect(pair.owner.publicIdentity.profile).toBe(profile);
}

async function assertEmailSignerProfilePath(
  pair: EmailLinkedOwnerPair,
  profile: SignerProfile,
): Promise<void> {
  const emailOtp = {
    context: pair.device2Context,
    walletId: pair.publicIdentity.walletId,
    routerOrigin: pair.routerOrigin,
  } as const;
  await assertSignerProfileActions(pair.device2Page, profile);
  await assertLinkedDeviceInventoryLoaded(pair.ownerPage);
  if (profile !== 'ecdsa') {
    const near = requireNearIdentity(pair.publicIdentity);
    const exported = await exportOwnerKey(
      pair.device2Page,
      'near',
      pair.device2Diagnostics,
      emailOtp,
    );
    expect(exported.accountId).toBe(near.accountId);
    expect(exported.entries.map((entry) => entry.publicKey)).toEqual([near.publicKey]);
    await greetingSigning(pair.device2Page, 'NEAR', pair.device2Diagnostics, emailOtp);
  }
  if (profile !== 'ed25519') {
    const exported = await exportOwnerKey(
      pair.device2Page,
      'evm',
      pair.device2Diagnostics,
      emailOtp,
    );
    expect(
      exported.entries
        .map((entry) => `${entry.publicKey.toLowerCase()}:${entry.address.toLowerCase()}`)
        .sort(),
    ).toEqual(pair.publicIdentity.ecdsaKeys);
    await linkedSigning(pair.device2Page, pair.device2Diagnostics, emailOtp);
    await greetingSigning(pair.device2Page, 'Arc', pair.device2Diagnostics, emailOtp);
  }

  await revokeLinkedEmailDeviceFromUi({
    page: pair.ownerPage,
    context: pair.ownerContext,
    walletId: pair.publicIdentity.walletId,
    routerOrigin: pair.routerOrigin,
    activation: pair.activation,
    targetFactor: 'email_otp',
  });
  await assertLinkedDeviceRetired(pair.ownerPage, pair.activation);
  await assertRevokedActiveSessionCannotOperate({
    page: pair.device2Page,
    diagnostics: pair.device2Diagnostics,
    emailOtp,
    profile,
  });
  await lockActiveWallet(pair.device2Page);
  await assertRevokedEmailOtpCannotUnlock({
    page: pair.device2Page,
    context: pair.device2Context,
    walletId: pair.publicIdentity.walletId,
    profile,
    routerOrigin: pair.routerOrigin,
  });
  if (profile !== 'ecdsa') {
    await greetingSigning(pair.ownerPage, 'NEAR', pair.ownerDiagnostics, {
      context: pair.ownerContext,
      walletId: pair.publicIdentity.walletId,
      routerOrigin: pair.routerOrigin,
    });
  } else {
    await linkedSigning(pair.ownerPage, pair.ownerDiagnostics, {
      context: pair.ownerContext,
      walletId: pair.publicIdentity.walletId,
      routerOrigin: pair.routerOrigin,
    });
  }
  expect(pair.publicIdentity.profile).toBe(profile);
}

async function assertPasskeyOwnerEmailTargetPath(
  pair: PasskeyOwnerEmailTargetPair,
  profile: SignerProfile,
): Promise<void> {
  const emailOtp = {
    context: pair.device2Context,
    walletId: pair.publicIdentity.walletId,
    routerOrigin: pair.routerOrigin,
    challengeSubjectId: linkedTargetEmailAddress(pair.publicIdentity.walletId),
  } as const;
  await assertSignerProfileActions(pair.device2Page, profile);
  const inventory = await readActiveLinkedDeviceInventory(pair.ownerPage);
  expect(inventory.authMethodId).toBe(pair.activation.authMethodId);

  if (profile !== 'ecdsa') {
    const near = requireNearIdentity(pair.publicIdentity);
    const exported = await exportOwnerKey(
      pair.device2Page,
      'near',
      pair.device2Diagnostics,
      emailOtp,
    );
    expect(exported.accountId).toBe(near.accountId);
    expect(exported.entries.map((entry) => entry.publicKey)).toEqual([near.publicKey]);
    await greetingSigning(pair.device2Page, 'NEAR', pair.device2Diagnostics, emailOtp);
  }
  if (profile !== 'ed25519') {
    const exported = await exportOwnerKey(
      pair.device2Page,
      'evm',
      pair.device2Diagnostics,
      emailOtp,
    );
    expect(
      exported.entries
        .map((entry) => `${entry.publicKey.toLowerCase()}:${entry.address.toLowerCase()}`)
        .sort(),
    ).toEqual(pair.publicIdentity.ecdsaKeys);
    await linkedSigning(pair.device2Page, pair.device2Diagnostics, emailOtp);
  }

  const actor = ownerCredentialSnapshot(pair.source.owner);
  await revokeOwner(pair.ownerPage, actor, {
    walletId: pair.publicIdentity.walletId,
    walletAuthMethodId: pair.activation.authMethodId,
    routerOrigin: actor.routerOrigin,
    rpId: actor.rpId,
  });
  await assertLinkedDeviceRetired(pair.ownerPage, pair.activation);
  await assertRevokedActiveSessionCannotOperate({
    page: pair.device2Page,
    diagnostics: pair.device2Diagnostics,
    emailOtp,
    profile,
  });
  await lockActiveWallet(pair.device2Page);
  await assertRevokedEmailOtpCannotUnlock({
    page: pair.device2Page,
    context: pair.device2Context,
    walletId: pair.publicIdentity.walletId,
    profile,
    routerOrigin: pair.routerOrigin,
  });
  if (profile === 'ed25519') {
    await greetingSigning(pair.ownerPage, 'NEAR', pair.ownerDiagnostics);
  } else {
    await linkedSigning(pair.ownerPage, pair.ownerDiagnostics);
  }
}

async function assertEmailOwnerPasskeyTargetPath(
  pair: EmailOwnerPasskeyTargetPair,
  profile: SignerProfile,
): Promise<void> {
  await assertSignerProfileActions(pair.device2Page, profile);
  const inventory = await readActiveLinkedDeviceInventory(pair.ownerPage);
  expect(inventory.authMethodId).toBe(pair.activation.authMethodId);

  if (profile !== 'ecdsa') {
    const near = requireNearIdentity(pair.source.publicIdentity);
    const exported = await exportPasskeyOwnerKey(pair, 'near');
    expect(exported.accountId).toBe(near.accountId);
    expect(exported.entries.map((entry) => entry.publicKey)).toEqual([near.publicKey]);
    await greetingSigning(pair.device2Page, 'NEAR', pair.device2Diagnostics);
  }
  if (profile !== 'ed25519') {
    const exported = await exportPasskeyOwnerKey(pair, 'evm');
    expect(
      exported.entries
        .map((entry) => `${entry.publicKey.toLowerCase()}:${entry.address.toLowerCase()}`)
        .sort(),
    ).toEqual(pair.source.publicIdentity.ecdsaKeys);
    await linkedSigning(pair.device2Page, pair.device2Diagnostics);
  }

  await revokeLinkedEmailDeviceFromUi({
    page: pair.ownerPage,
    context: pair.ownerContext,
    walletId: pair.source.publicIdentity.walletId,
    routerOrigin: pair.source.routerOrigin,
    activation: pair.activation,
    targetFactor: 'passkey_prf',
  });
  await assertLinkedDeviceRetired(pair.ownerPage, pair.activation);
  await assertRevokedActiveSessionCannotOperate({
    page: pair.device2Page,
    diagnostics: pair.device2Diagnostics,
    profile,
  });
  await lockWallet(pair.device2Page);
  await assertRevokedOwnerCannotUnlock(pair.device2Page);
  const ownerEmailOtp = {
    context: pair.ownerContext,
    walletId: pair.source.publicIdentity.walletId,
    routerOrigin: pair.source.routerOrigin,
  } as const;
  if (profile === 'ed25519') {
    await greetingSigning(pair.ownerPage, 'NEAR', pair.ownerDiagnostics, ownerEmailOtp);
  } else {
    await linkedSigning(pair.ownerPage, pair.ownerDiagnostics, ownerEmailOtp);
  }
}

for (const profile of SIGNER_PROFILES) {
  test(`Passkey→Passkey supports the ${profile} signer profile`, async ({ browser }) => {
    const pair = await setupLinkedOwnerPair(browser, profile);
    try {
      await assertPasskeySignerProfilePath(pair, profile);
    } finally {
      await closeBrowserContexts(pair.ownerContext, pair.device2Context);
    }
  });

  test(`Email OTP→Email OTP supports the ${profile} signer profile`, async ({ browser }) => {
    const pair = await setupEmailLinkedOwnerPair(browser, profile);
    try {
      await assertEmailSignerProfilePath(pair, profile);
    } finally {
      await closeBrowserContexts(pair.ownerContext, pair.device2Context);
    }
  });

  test(`Passkey→Email OTP supports the ${profile} signer profile`, async ({ browser }) => {
    const pair = await setupEmailLinkedOwnerPair(browser, profile, 'passkey');
    try {
      await assertPasskeyOwnerEmailTargetPath(pair, profile);
    } finally {
      await closeBrowserContexts(pair.ownerContext, pair.device2Context);
    }
  });

  test(`Email OTP→Passkey supports the ${profile} signer profile`, async ({ browser }) => {
    const pair = await setupLinkedOwnerPair(browser, profile, 'email_otp');
    try {
      await assertEmailOwnerPasskeyTargetPath(pair, profile);
    } finally {
      await closeBrowserContexts(pair.ownerContext, pair.device2Context);
    }
  });
}

test('Device 1 revokes Device 2 while preserving wallet identity and owner operation', async ({
  browser,
}) => {
  const pair = await setupLinkedOwnerPair(browser);
  try {
    const ownerNear = requireNearIdentity(pair.owner.publicIdentity);
    const device2Near = await exportPasskeyOwnerKey(pair, 'near');
    expect(device2Near.accountId).toBe(ownerNear.accountId);
    expect(device2Near.entries.map((entry) => entry.publicKey)).toEqual([ownerNear.publicKey]);
    const device2Evm = await exportPasskeyOwnerKey(pair, 'evm');
    const device2EcdsaKeys = device2Evm.entries
      .map((entry) => `${entry.publicKey.toLowerCase()}:${entry.address.toLowerCase()}`)
      .sort();
    expect(device2EcdsaKeys).toEqual(pair.owner.publicIdentity.ecdsaKeys);
    const actor = ownerCredentialSnapshot(pair.owner);
    assertRejectedRevocationTarget(
      await attemptRejectedRevocationTarget(pair.ownerPage, actor, pair.activation.authMethodId, {
        kind: 'authority_id',
        authorityId: pair.activation.authorityId,
      }),
    );
    assertRejectedRevocationTarget(
      await attemptRejectedRevocationTarget(pair.ownerPage, actor, pair.activation.authMethodId, [
        {
          kind: 'passkey',
          rpId: pair.device2.rpId,
          credentialIdB64u: pair.device2.credentialIdB64u,
        },
      ]),
    );
    await assertPasskeyInventoryLoaded(pair.ownerPage, 2);
    await revokeOwner(pair.ownerPage, actor, pair.device2);
    await assertLinkedDeviceRetired(pair.ownerPage, pair.activation);
    await assertRevokedActiveSessionCannotOperate({
      page: pair.device2Page,
      diagnostics: pair.device2Diagnostics,
      profile: 'combined',
    });
    await lockWallet(pair.device2Page);
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
    routerOrigin: pair.routerOrigin,
  } as const;
  try {
    const ownerNear = requireNearIdentity(pair.publicIdentity);
    await assertLinkedDeviceInventoryLoaded(pair.ownerPage);
    const device2Near = await exportOwnerKey(
      pair.device2Page,
      'near',
      pair.device2Diagnostics,
      emailOtp,
    );
    emailLinkedDeviceStage('Device 2 NEAR export complete');
    expect(device2Near.accountId).toBe(ownerNear.accountId);
    expect(device2Near.entries.map((entry) => entry.publicKey)).toEqual([ownerNear.publicKey]);
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
    await revokeLinkedEmailDeviceFromUi({
      page: pair.ownerPage,
      context: pair.ownerContext,
      walletId: pair.publicIdentity.walletId,
      routerOrigin: pair.routerOrigin,
      activation: pair.activation,
      targetFactor: 'email_otp',
    });
    emailLinkedDeviceStage('Device 1 revoked Device 2');
    await assertLinkedDeviceRetired(pair.ownerPage, pair.activation);
    await assertRevokedActiveSessionCannotOperate({
      page: pair.device2Page,
      diagnostics: pair.device2Diagnostics,
      emailOtp,
      profile: 'combined',
    });
    await lockActiveWallet(pair.device2Page);
    await assertRevokedEmailOtpCannotUnlock({
      page: pair.device2Page,
      context: pair.device2Context,
      walletId: pair.publicIdentity.walletId,
      profile: 'combined',
      routerOrigin: pair.routerOrigin,
    });
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
      routerOrigin: pair.routerOrigin,
    });
  } finally {
    await closeBrowserContexts(pair.ownerContext, pair.device2Context);
  }
});
