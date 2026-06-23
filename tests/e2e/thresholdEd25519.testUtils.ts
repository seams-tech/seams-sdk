import type { Page, Route } from '@playwright/test';
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import bs58 from 'bs58';
import { setupBasicPasskeyTest, SDK_ESM_PATHS } from '../setup';
import { DEFAULT_TEST_CONFIG } from '../setup/config';
import { AuthService } from '@server/core/AuthService';
import { createThresholdSigningService } from '@server/core/ThresholdService';
import type {
  AccountCreationRequest,
  AccountCreationResult,
  ThresholdStoreConfigInput,
} from '@server/core/types';
import { THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID } from '@server/core/ThresholdService/schemes/schemeIds';
import { signSecp256k1Recoverable } from '@server/core/ThresholdService/ethSignerWasm';
import {
  ROUTER_AB_ECDSA_HSS_PRIVATE_SIGNING_PATHS,
  ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS,
} from '@server/router/routerAbPrivateSigningWorker';
import {
  CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH_V1,
  ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
} from '@server/core/ThresholdService/routerAb/ecdsaHssPresignBridge';
import { makeSessionAdapter, startExpressRouter } from '../relayer/helpers';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  createInMemoryConsoleApiKeyService,
  createInMemoryConsoleBootstrapTokenService,
  createInMemoryConsoleOrgProjectEnvService,
  createRelayBootstrapGrantBroker,
  createRelayPublishableKeyAuthAdapter,
  createRelayRouter,
} from '@server/router/express-adaptor';
import { createFixtureSigningRootShareResolverForUnitTests } from '../helpers/thresholdEd25519TestUtils';
import type { SigningSessionSealRoutesOptions } from '@server/threshold/session/signingSessionSeal';
import type { RouterAbPublicKeysetV2 } from '@shared/utils/routerAbPublicKeyset';
import {
  parseCloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1,
  parseRouterAbEcdsaHssEvmDigestSigningRequestV1,
  ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1,
  routerAbEcdsaHssActiveStateSessionId,
  routerAbEcdsaHssEvmDigestSigningRequestDigestV1,
  type CloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1Wire,
} from '@shared/utils/routerAbEcdsaHss';

const SESSION_COOKIE_NAME =
  String(process.env.SESSION_COOKIE_NAME || 'seams-jwt').trim() || 'seams-jwt';

type RouterAbEcdsaHssPrivateFinalizeFixtureRequest = {
  scope: unknown;
  request_id: string;
  expires_at_ms: number;
  signing_digest_b64u: string;
  server_presignature_id: string;
  client_signature_share32_b64u: string;
};

type RouterAbEcdsaHssTrustedAdmissionFixture = {
  request_digest: unknown;
};

function requireFixtureRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireFixtureExactKeys(
  record: Record<string, unknown>,
  label: string,
  keys: readonly string[],
): void {
  const expected = new Set(keys);
  const extra = Object.keys(record).filter((key) => !expected.has(key));
  const missing = keys.filter((key) => !(key in record));
  if (extra.length || missing.length) {
    throw new Error(
      `${label} keys mismatch; missing=${missing.join(',') || 'none'} extra=${extra.join(',') || 'none'}`,
    );
  }
}

function requireFixtureString(value: unknown, label: string): string {
  const text = typeof value === 'string' ? value.trim() : '';
  if (!text) throw new Error(`${label} must be a string`);
  return text;
}

function requireFixtureNumber(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new Error(`${label} must be a positive number`);
  }
  return value;
}

function parseRouterAbEcdsaHssPrivateFinalizeFixtureRequest(
  value: unknown,
): RouterAbEcdsaHssPrivateFinalizeFixtureRequest {
  const record = requireFixtureRecord(value, 'private ecdsa finalize request');
  requireFixtureExactKeys(record, 'private ecdsa finalize request', [
    'scope',
    'request_id',
    'expires_at_ms',
    'signing_digest_b64u',
    'server_presignature_id',
    'client_signature_share32_b64u',
  ]);
  return {
    scope: record.scope,
    request_id: requireFixtureString(record.request_id, 'private ecdsa finalize request_id'),
    expires_at_ms: requireFixtureNumber(
      record.expires_at_ms,
      'private ecdsa finalize expires_at_ms',
    ),
    signing_digest_b64u: requireFixtureString(
      record.signing_digest_b64u,
      'private ecdsa finalize signing_digest_b64u',
    ),
    server_presignature_id: requireFixtureString(
      record.server_presignature_id,
      'private ecdsa finalize server_presignature_id',
    ),
    client_signature_share32_b64u: requireFixtureString(
      record.client_signature_share32_b64u,
      'private ecdsa finalize client_signature_share32_b64u',
    ),
  };
}

function parseRouterAbEcdsaHssTrustedAdmissionFixture(
  value: unknown,
): RouterAbEcdsaHssTrustedAdmissionFixture {
  const record = requireFixtureRecord(value, 'private ecdsa trusted admission');
  if (!record.request_digest) {
    throw new Error('private ecdsa trusted admission request_digest is required');
  }
  return {
    request_digest: record.request_digest,
  };
}

export async function setupThresholdE2ePage(
  page: Page,
  options: { injectWalletServiceImportMap?: boolean } = {},
): Promise<void> {
  const blankPageUrl = new URL('/__test_blank.html', DEFAULT_TEST_CONFIG.frontendUrl).toString();
  await setupBasicPasskeyTest(page, {
    frontendUrl: blankPageUrl,
    skipSeamsWebInit: true,
    injectWalletServiceImportMap: options.injectWalletServiceImportMap,
  });

  await page.evaluate(async (base64Path) => {
    const { base64UrlEncode, base64UrlDecode } = await import(base64Path);
    (window as any).base64UrlEncode = base64UrlEncode;
    (window as any).base64UrlDecode = base64UrlDecode;
  }, SDK_ESM_PATHS.base64);
}

const DEFAULT_ACCOUNTS_ON_CHAIN = new Set<string>(
  [DEFAULT_TEST_CONFIG.relayerAccount].filter((id): id is string => !!id),
);
const THRESHOLD_ED25519_KEY_VERSION_V1 = 'threshold-ed25519-hss-v1';
export const TEST_RELAYER_ACCOUNT_ID = 'relayer.testnet';
export const TEST_RELAYER_PUBLIC_KEY = 'ed25519:GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB';
export const TEST_RELAYER_PRIVATE_KEY =
  'ed25519:99eUso3aSbE9tqGSTXzo3TLfKb9RkMTURrHKQ1K7Zh3StnzFNUx8FKCPPPPpR479qsw5zv2WNBKmgiz7WqgAJfM';
export const TEST_ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET =
  'test-router-ab-internal-service-auth';
const TEST_ROUTER_AB_ECDSA_HSS_SIGNING_WORKER_PRIVATE_KEY_32 = new Uint8Array(32).fill(0x41);
const TEST_ROUTER_AB_ECDSA_HSS_RERANDOMIZATION_ENTROPY_32 = new Uint8Array(32).fill(0x29);
const TEST_ROUTER_AB_SIGNING_WORKER_ID = 'local-signing-worker';
const TEST_ROUTER_AB_SIGNING_WORKER_KEY_EPOCH = 'epoch-1';
const TEST_ROUTER_AB_SIGNING_WORKER_HPKE_PUBLIC_KEY =
  'x25519:3333333333333333333333333333333333333333333333333333333333333333';
const TEST_ROUTER_AB_SIGNING_WORKER_HPKE_PRIVATE_KEY =
  'dev-only-signing-worker-server-output-hpke-private-key';
const ROUTER_AB_DEV_MANIFEST = 'crates/router-ab-dev/Cargo.toml';
const ROUTER_AB_LOCAL_WORKER_BIN = path.join(
  'crates',
  'router-ab-dev',
  'target',
  'debug',
  process.platform === 'win32' ? 'router_ab_local_worker.exe' : 'router_ab_local_worker',
);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
let routerAbLocalWorkerBuildPromise: Promise<void> | null = null;

type ThresholdEcdsaRegistrationBootstrapResult =
  | {
      ok: true;
      relayerKeyId?: string;
      thresholdEcdsaPublicKeyB64u?: string;
      relayerVerifyingShareB64u?: string;
      ethereumAddress?: string;
      ecdsaThresholdKeyId?: string;
      clientVerifyingShareB64u?: string;
    }
  | {
      ok: false;
      code?: string;
      message?: string;
    };

type JsonResponseLike = {
  status: (statusCode: number) => JsonResponseLike;
  json: (body: unknown) => unknown;
};

type LocalRouterAbSigningWorker = {
  baseUrl: string;
  close: () => Promise<void>;
};

function execFileAsync(
  command: string,
  args: string[],
  options: { cwd: string },
): Promise<void> {
  return new Promise((resolve, reject) => {
    execFile(command, args, options, (error, _stdout, stderr) => {
      if (!error) {
        resolve();
        return;
      }
      reject(
        new Error(
          `${command} ${args.join(' ')} failed: ${String(stderr || error.message || error)}`,
        ),
      );
    });
  });
}

function buildRouterAbLocalWorker(): Promise<void> {
  if (!routerAbLocalWorkerBuildPromise) {
    routerAbLocalWorkerBuildPromise = execFileAsync(
      'cargo',
      ['build', '--manifest-path', ROUTER_AB_DEV_MANIFEST, '--bin', 'router_ab_local_worker'],
      { cwd: repoRoot },
    );
  }
  return routerAbLocalWorkerBuildPromise;
}

function reserveLoopbackPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        if (!Number.isSafeInteger(port) || port <= 0) {
          reject(new Error('failed to reserve a Router A/B SigningWorker port'));
          return;
        }
        resolve(port);
      });
    });
  });
}

function waitForLocalWorkerReady(input: {
  child: ReturnType<typeof import('node:child_process').spawn>;
  expectedBindAddr: string;
  stderrLines: string[];
}): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      input.child.off('error', onError);
      input.child.off('exit', onExit);
      input.child.stderr?.off('data', onStderr);
      if (error) reject(error);
      else resolve();
    };
    const onError = (error: Error) => {
      finish(error);
    };
    const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
      finish(
        new Error(
          `Router A/B local SigningWorker exited before ready (${signal || (code ?? 'unknown')}): ${input.stderrLines.join(
            '\n',
          )}`,
        ),
      );
    };
    const onStderr = (chunk: Buffer | string) => {
      const text = String(chunk || '');
      for (const rawLine of text.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line) continue;
        input.stderrLines.push(line);
        try {
          const parsed = JSON.parse(line) as { bind_addr?: unknown; role_label?: unknown };
          if (
            String(parsed.bind_addr || '') === input.expectedBindAddr &&
            String(parsed.role_label || '') === 'signing_worker'
          ) {
            finish();
            return;
          }
        } catch {
          // Cargo and Rust startup diagnostics are plain text until the worker summary.
        }
      }
    };
    const timer = setTimeout(() => {
      finish(
        new Error(
          `Router A/B local SigningWorker did not become ready at ${input.expectedBindAddr}: ${input.stderrLines.join(
            '\n',
          )}`,
        ),
      );
    }, 20_000);
    input.child.once('error', onError);
    input.child.once('exit', onExit);
    input.child.stderr?.on('data', onStderr);
  });
}

async function startLocalRouterAbEd25519SigningWorker(): Promise<LocalRouterAbSigningWorker> {
  await buildRouterAbLocalWorker();
  const [{ spawn }, port, tmpRoot] = await Promise.all([
    import('node:child_process'),
    reserveLoopbackPort(),
    mkdtemp(path.join(tmpdir(), 'seams-router-ab-signing-worker-')),
  ]);
  const bindAddr = `127.0.0.1:${port}`;
  const baseUrl = `http://${bindAddr}`;
  const envPath = path.join(tmpRoot, 'signing-worker.local');
  await writeFile(
    envPath,
    [
      'ROUTER_AB_LOCAL_WORKER_ROLE=signing-worker',
      `SIGNING_WORKER_URL=${baseUrl}`,
      `SIGNING_WORKER_ID=${TEST_ROUTER_AB_SIGNING_WORKER_ID}`,
      `SIGNING_WORKER_KEY_EPOCH=${TEST_ROUTER_AB_SIGNING_WORKER_KEY_EPOCH}`,
      `SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY=${TEST_ROUTER_AB_SIGNING_WORKER_HPKE_PUBLIC_KEY}`,
      `SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY=${TEST_ROUTER_AB_SIGNING_WORKER_HPKE_PRIVATE_KEY}`,
      `SIGNING_WORKER_SERVER_OUTPUT_STORAGE_PATH=${path.join(tmpRoot, 'server-output.sqlite')}`,
      `ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET=${TEST_ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET}`,
      '',
    ].join('\n'),
    'utf8',
  );

  const child = spawn(
    path.join(repoRoot, ROUTER_AB_LOCAL_WORKER_BIN),
    ['--role', 'signing-worker', '--env', envPath],
    {
      cwd: repoRoot,
      env: {
        ...process.env,
        ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: TEST_ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET,
      },
      stdio: ['ignore', 'ignore', 'pipe'],
    },
  );
  const stderrLines: string[] = [];
  try {
    await waitForLocalWorkerReady({ child, expectedBindAddr: bindAddr, stderrLines });
  } catch (error) {
    if (child.exitCode === null && !child.killed) child.kill('SIGTERM');
    await rm(tmpRoot, { recursive: true, force: true }).catch(() => undefined);
    throw error;
  }

  return {
    baseUrl,
    close: async () => {
      if (child.exitCode === null && !child.killed) {
        child.kill('SIGTERM');
        await new Promise<void>((resolve) => {
          const timeout = setTimeout(() => {
            if (child.exitCode === null && !child.killed) child.kill('SIGKILL');
            resolve();
          }, 1_000);
          child.once('exit', () => {
            clearTimeout(timeout);
            resolve();
          });
        });
      }
      await rm(tmpRoot, { recursive: true, force: true }).catch(() => undefined);
    },
  };
}

async function proxyEd25519PrivateSigningWorkerJson(input: {
  workerBaseUrl: string;
  path: string;
  body: unknown;
  res: JsonResponseLike;
}): Promise<void> {
  const response = await fetch(`${input.workerBaseUrl}${input.path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      [ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1]: TEST_ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET,
    },
    body: JSON.stringify(input.body),
  });
  const text = await response.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = {
      ok: false,
      code: 'invalid_signing_worker_response',
      message: text || 'Router A/B local SigningWorker returned a non-JSON response',
    };
  }
  input.res.status(response.status).json(body);
}

function readHeaderValue(
  headers: Record<string, string | string[] | undefined> | undefined,
  name: string,
): string {
  const value = headers?.[name] ?? headers?.[name.toLowerCase()] ?? headers?.[name.toUpperCase()];
  return Array.isArray(value) ? String(value[0] || '').trim() : String(value || '').trim();
}

function publicDigest(bytes: Uint8Array): { bytes: number[] } {
  return { bytes: Array.from(bytes) };
}

function makeRouterAbEcdsaHssPoolFillReceipt(
  request: CloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1Wire,
  stored: boolean,
) {
  return {
    active_signing_worker_state: {
      account_id: request.scope.context.wallet_id,
      session_id: routerAbEcdsaHssActiveStateSessionId({
        kind: ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1,
        scope: request.scope,
      }),
      account_public_key: request.scope.public_identity.threshold_public_key33_b64u,
      signing_worker: request.scope.signing_worker,
      activation_transcript_digest: publicDigest(new Uint8Array(32).fill(0x51)),
      activation_digest: publicDigest(new Uint8Array(32).fill(0x52)),
      signing_worker_material_handle: `fixture-${request.scope.signing_worker.server_id}`,
      activated_at_ms: Math.max(1, Date.now()),
    },
    server_presignature_id: request.server_presignature_id,
    server_big_r33_b64u: request.server_big_r33_b64u,
    stored,
  };
}

function isEd25519PrivateSigningWorkerPath(path: string): boolean {
  return (
    path === ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.prepare ||
    path === ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.presignPoolPrepare ||
    path === ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.presignPoolFinalize ||
    path === ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.finalize
  );
}

export async function setupRouterAbEcdsaHssPrivateSigningWorker(): Promise<{
  baseUrl: string;
  close: () => Promise<void>;
}> {
  const ed25519SigningWorker = await startLocalRouterAbEd25519SigningWorker();
  const presignatures = new Map<
    string,
    CloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1Wire
  >();
  const router = async (
    req: {
      method?: string;
      path?: string;
      url?: string;
      headers?: Record<string, string | string[] | undefined>;
      body?: unknown;
    },
    res: JsonResponseLike,
    next: (err?: unknown) => void,
  ) => {
    try {
      const method = String(req.method || '').toUpperCase();
      const path = String(req.path || req.url || '').split('?')[0] || '';
      if (!path.startsWith('/router-ab/v1/signing-worker/')) {
        next();
        return;
      }
      if (method !== 'POST') {
        res.status(405).json({ ok: false, code: 'method_not_allowed', message: 'POST required' });
        return;
      }
      const authHeader = readHeaderValue(req.headers, ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1);
      if (authHeader !== TEST_ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET) {
        res.status(401).json({
          ok: false,
          code: 'unauthorized',
          message: 'invalid Router A/B internal service auth',
        });
        return;
      }

      if (isEd25519PrivateSigningWorkerPath(path)) {
        await proxyEd25519PrivateSigningWorkerJson({
          workerBaseUrl: ed25519SigningWorker.baseUrl,
          path,
          body: req.body,
          res,
        });
        return;
      }

      if (path === CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH_V1) {
        const request = parseCloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1(req.body);
        const stored = !presignatures.has(request.server_presignature_id);
        if (stored) presignatures.set(request.server_presignature_id, request);
        res.status(200).json(makeRouterAbEcdsaHssPoolFillReceipt(request, stored));
        return;
      }

      if (path === ROUTER_AB_ECDSA_HSS_PRIVATE_SIGNING_PATHS.prepare) {
        const body = req.body && typeof req.body === 'object' ? (req.body as any).request : req.body;
        const request = parseRouterAbEcdsaHssEvmDigestSigningRequestV1(body);
        const presignature = presignatures.get(request.client_presignature_id);
        if (!presignature) {
          res.status(404).json({
            ok: false,
            code: 'presignature_not_found',
            message: 'Router A/B ECDSA-HSS presignature is not available',
          });
          return;
        }
        res.status(200).json({
          scope: request.scope,
          request_id: request.request_id,
          request_digest: await routerAbEcdsaHssEvmDigestSigningRequestDigestV1(request),
          signing_digest: publicDigest(base64UrlDecode(request.signing_digest_b64u)),
          server_presignature_id: request.client_presignature_id,
          server_big_r33_b64u: presignature.server_big_r33_b64u,
          rerandomization_entropy32_b64u: base64UrlEncode(
            TEST_ROUTER_AB_ECDSA_HSS_RERANDOMIZATION_ENTROPY_32,
          ),
          signature_scheme: 'ecdsa_secp256k1_recoverable_v1',
          prepared_at_ms: Math.max(1, Date.now()),
          expires_at_ms: request.expires_at_ms,
        });
        return;
      }

      if (path === ROUTER_AB_ECDSA_HSS_PRIVATE_SIGNING_PATHS.finalize) {
        const envelope = req.body && typeof req.body === 'object' ? (req.body as any) : {};
        const request = parseRouterAbEcdsaHssPrivateFinalizeFixtureRequest(envelope.request);
        const trustedAdmission = parseRouterAbEcdsaHssTrustedAdmissionFixture(
          envelope.trusted_admission,
        );
        const signature65 = await signSecp256k1Recoverable(
          base64UrlDecode(request.signing_digest_b64u),
          TEST_ROUTER_AB_ECDSA_HSS_SIGNING_WORKER_PRIVATE_KEY_32,
        );
        res.status(200).json({
          scope: request.scope,
          request_id: request.request_id,
          request_digest: trustedAdmission.request_digest,
          signing_digest: publicDigest(base64UrlDecode(request.signing_digest_b64u)),
          signature_scheme: 'ecdsa_secp256k1_recoverable_v1',
          signature65_b64u: base64UrlEncode(signature65),
        });
        return;
      }

      res.status(404).json({
        ok: false,
        code: 'not_found',
        message: `unexpected private SigningWorker route: ${path}`,
      });
    } catch (error: unknown) {
      res.status(500).json({
        ok: false,
        code: 'internal',
        message:
          error && typeof error === 'object' && 'message' in error
            ? String((error as { message?: unknown }).message || '')
            : String(error || 'private SigningWorker fixture failed'),
      });
    }
  };
  const expressWorker = await startExpressRouter(router);
  return {
    baseUrl: expressWorker.baseUrl,
    close: async () => {
      const results = await Promise.allSettled([
        expressWorker.close(),
        ed25519SigningWorker.close(),
      ]);
      const failed = results.find(
        (result): result is PromiseRejectedResult => result.status === 'rejected',
      );
      if (failed) throw failed.reason;
    },
  };
}

export function makeAuthServiceForThreshold(
  keysOnChain: Set<string>,
  thresholdStore?: ThresholdStoreConfigInput | null,
): {
  service: AuthService;
  threshold: ReturnType<typeof createThresholdSigningService>;
} {
  const providedConfig = (thresholdStore || {}) as Partial<ThresholdStoreConfigInput>;
  const needsFixtureSigningRootResolver = !(
    providedConfig.signingRootShareResolver ||
    providedConfig.signingRootShareResolverAdapters ||
    providedConfig.signingRootSharePolicy ||
    providedConfig.signingRootShareStore ||
    providedConfig.signingRootShareDecryptAdapter
  );
  const thresholdConfig: ThresholdStoreConfigInput = {
    THRESHOLD_NODE_ROLE: 'coordinator',
    ROUTER_AB_NORMAL_SIGNING_WORKER_ID: TEST_ROUTER_AB_SIGNING_WORKER_ID,
    ...providedConfig,
    ...(needsFixtureSigningRootResolver
      ? { signingRootShareResolver: createFixtureSigningRootShareResolverForUnitTests() }
      : {}),
  };

  const svc = new AuthService({
    relayerAccount: TEST_RELAYER_ACCOUNT_ID,
    relayerPrivateKey: TEST_RELAYER_PRIVATE_KEY,
    nearRpcUrl: DEFAULT_TEST_CONFIG.nearRpcUrl,
    networkId: DEFAULT_TEST_CONFIG.nearNetwork,
    accountInitialBalance: '1',
    createAccountAndRegisterGas: '1',
    thresholdStore: thresholdConfig,
    logger: null,
  });

  // For lite threshold flows, we also stub the standard WebAuthn verifier (contract-backed by default).
  (
    svc as unknown as {
      verifyWebAuthnAuthenticationLite: (
        req: unknown,
      ) => Promise<{ success: boolean; verified: boolean }>;
    }
  ).verifyWebAuthnAuthenticationLite = async (_req: unknown) => ({ success: true, verified: true });
  (
    svc as unknown as {
      createAccount: (request: AccountCreationRequest) => Promise<AccountCreationResult>;
    }
  ).createAccount = async (request: AccountCreationRequest) => {
    const publicKey = String(request.publicKey || '').trim();
    const recoveryPublicKey = String(request.recoveryPublicKey || '').trim();
    if (publicKey) keysOnChain.add(publicKey);
    if (recoveryPublicKey) keysOnChain.add(recoveryPublicKey);
    return {
      success: true,
      transactionHash: `mock-create-account-${Date.now()}`,
      accountId: request.accountId,
      message: `Mock account ${request.accountId} created`,
    };
  };

  keysOnChain.add(TEST_RELAYER_PUBLIC_KEY);
  const blockHash = bs58.encode(Buffer.alloc(32, 7));
  const nearClient = (
    svc as unknown as {
      nearClient: {
        viewAccessKey: (accountId: string, publicKey: string) => Promise<unknown>;
        viewAccessKeyList: (accountId: string) => Promise<unknown>;
        viewBlock: () => Promise<unknown>;
        sendTransaction: () => Promise<unknown>;
        txStatus: () => Promise<unknown>;
      };
    }
  ).nearClient;
  nearClient.viewAccessKey = async (_accountId: string, publicKey: string) => ({
    block_hash: blockHash,
    block_height: 424242,
    nonce: keysOnChain.has(publicKey) ? 1 : 0,
    permission: 'FullAccess' as const,
  });
  nearClient.viewAccessKeyList = async (_accountId: string) => {
    const keys = Array.from(keysOnChain).map((publicKey) => ({
      public_key: publicKey,
      access_key: { nonce: 0, permission: 'FullAccess' as const },
    }));
    return { keys };
  };
  nearClient.viewBlock = async () => ({
    header: {
      hash: blockHash,
      height: 424242,
    },
  });
  nearClient.sendTransaction = async () => ({
    status: { SuccessValue: '' },
    transaction: { hash: `mock-server-tx-${Date.now()}` },
    transaction_outcome: { id: `mock-server-tx-outcome-${Date.now()}` },
    receipts_outcome: [],
  });
  nearClient.txStatus = async () => ({
    status: { SuccessValue: '' },
    transaction: { hash: `mock-server-tx-status-${Date.now()}` },
    transaction_outcome: { id: `mock-server-tx-status-outcome-${Date.now()}` },
    receipts_outcome: [],
  });
  const threshold = createThresholdSigningService({
    authService: svc,
    thresholdStore: thresholdConfig,
    logger: null,
  });
  svc.setThresholdSigningService(threshold);

  return { service: svc, threshold };
}

export async function persistThresholdEd25519RegistrationMaterial(input: {
  threshold: ReturnType<typeof createThresholdSigningService>;
  nearAccountId: string;
  rpId: string;
  publicKey: string;
  keyVersion: string;
  relayerKeyId?: string;
}): Promise<void> {
  const relayerKeyId = String(input.relayerKeyId || input.publicKey).trim();
  const existing = await (
    input.threshold as unknown as {
      keyStore?: {
        get: (relayerKeyId: string) => Promise<{
          nearAccountId: string;
          rpId: string;
          publicKey: string;
          keyVersion: string;
          recoveryExportCapable: true;
        } | null>;
      };
    }
  ).keyStore?.get(relayerKeyId);
  if (
    existing?.nearAccountId === input.nearAccountId &&
    existing?.rpId === input.rpId &&
    existing?.publicKey === input.publicKey &&
    existing?.keyVersion === input.keyVersion &&
    existing?.recoveryExportCapable === true
  ) {
    return;
  }

  const schemeAny = input.threshold.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
  if (!schemeAny || schemeAny.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
    throw new Error(
      `threshold scheme ${THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID} is not enabled on this server`,
    );
  }
	  const keygen = await schemeAny.registration.keygenFromRegistrationMaterial({
	    walletId: input.nearAccountId,
	    nearAccountId: input.nearAccountId,
	    ed25519KeyScopeId: input.nearAccountId,
	    rpId: input.rpId,
    keyVersion: input.keyVersion,
    recoveryExportCapable: true,
    publicKey: input.publicKey,
    relayerKeyId,
  });
  if (!keygen.ok) {
    throw new Error(keygen.message || 'threshold-ed25519 registration material keygen failed');
  }
}

export function createInMemoryJwtSessionAdapter(): ReturnType<typeof makeSessionAdapter> {
  const issuedTokens = new Map<string, Record<string, unknown>>();
  const makeTestJwt = (claims: Record<string, unknown>): string => {
    const header = base64UrlEncode(Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })));
    const payload = base64UrlEncode(
      Buffer.from(
        JSON.stringify({
          ...claims,
          exp: Math.floor(Date.now() / 1000) + 3600,
        }),
      ),
    );
    const signature =
      typeof globalThis.crypto?.randomUUID === 'function'
        ? globalThis.crypto.randomUUID().replace(/-/g, '')
        : `${Date.now()}${Math.random().toString(16).slice(2)}`;
    return `${header}.${payload}.${signature}`;
  };
  const extractCookieToken = (cookieHeader: string | undefined): string => {
    const raw = String(cookieHeader || '').trim();
    if (!raw) return '';
    const parts = raw.split(';');
    for (const part of parts) {
      const [nameRaw, valueRaw] = part.split('=');
      if (String(nameRaw || '').trim() !== SESSION_COOKIE_NAME) continue;
      return String(valueRaw || '').trim();
    }
    return '';
  };
  return makeSessionAdapter({
    signJwt: async (sub: string, extra?: Record<string, unknown>) => {
      const extraRecord = { ...(extra || {}) };
      const claims = { sub, ...extraRecord };
      const token = makeTestJwt(claims);
      issuedTokens.set(token, claims);
      return token;
    },
    parse: async (headers: Record<string, string | string[] | undefined>) => {
      const authHeaderRaw = headers['authorization'] ?? headers['Authorization'];
      const authHeader = Array.isArray(authHeaderRaw) ? authHeaderRaw[0] : authHeaderRaw;
      const cookieHeaderRaw = headers['cookie'] ?? headers['Cookie'];
      const cookieHeader = Array.isArray(cookieHeaderRaw) ? cookieHeaderRaw[0] : cookieHeaderRaw;
      const tokenFromAuthorization =
        typeof authHeader === 'string' ? authHeader.replace(/^Bearer\s+/i, '').trim() : '';
      const token = tokenFromAuthorization || extractCookieToken(cookieHeader);
      const claims = token ? issuedTokens.get(token) : undefined;
      return claims ? { ok: true as const, claims } : { ok: false as const };
    },
    refresh: async (headers: Record<string, string | string[] | undefined>) => {
      const authHeaderRaw = headers['authorization'] ?? headers['Authorization'];
      const authHeader = Array.isArray(authHeaderRaw) ? authHeaderRaw[0] : authHeaderRaw;
      const cookieHeaderRaw = headers['cookie'] ?? headers['Cookie'];
      const cookieHeader = Array.isArray(cookieHeaderRaw) ? cookieHeaderRaw[0] : cookieHeaderRaw;
      const tokenFromAuthorization =
        typeof authHeader === 'string' ? authHeader.replace(/^Bearer\s+/i, '').trim() : '';
      const token = tokenFromAuthorization || extractCookieToken(cookieHeader);
      const claims = token ? issuedTokens.get(token) : undefined;
      if (!claims) return { ok: false as const, code: 'unauthorized', message: 'No valid session' };
      const sub = String(claims.sub || '').trim();
      if (!sub) return { ok: false as const, code: 'unauthorized', message: 'Invalid session' };
      const nextClaims = { ...claims };
      const nextToken = makeTestJwt(nextClaims);
      issuedTokens.set(nextToken, nextClaims);
      return { ok: true as const, jwt: nextToken };
    },
  });
}

export async function setupManagedThresholdRegistrationHarness(args: {
  page: Page;
  service: AuthService;
  threshold: ReturnType<typeof createThresholdSigningService>;
  session?: ReturnType<typeof makeSessionAdapter>;
  keyName?: string;
  orgId?: string;
  orgSlug?: string;
  orgName?: string;
  projectId?: string;
  projectName?: string;
  allowedOrigins?: string[];
  signingSessionSeal?: SigningSessionSealRoutesOptions | null;
  routerAbPublicKeyset?: RouterAbPublicKeysetV2 | null;
}): Promise<{
  baseUrl: string;
  session: ReturnType<typeof makeSessionAdapter>;
  managedRegistration: {
    environmentId: string;
    publishableKey: string;
  };
  runtimePolicyScope: {
    orgId: string;
    projectId: string;
    envId: string;
    signingRootVersion: string;
  };
  close: () => Promise<void>;
}> {
  const session = args.session || createInMemoryJwtSessionAdapter();
  const bootstrapTokenStore = createInMemoryConsoleBootstrapTokenService();
  const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
  const apiKeys = createInMemoryConsoleApiKeyService();
  const frontendOrigin = new URL(DEFAULT_TEST_CONFIG.frontendUrl).origin;
  const allowedOrigins = Array.from(
    new Set(
      (
        args.allowedOrigins || [
          frontendOrigin,
          'https://example.localhost',
          'https://wallet.example.localhost',
        ]
      ).filter((origin): origin is string => !!String(origin || '').trim()),
    ),
  );
  const orgId = String(args.orgId || 'org_threshold_wallet_iframe').trim();
  const projectId = String(args.projectId || 'proj_threshold_wallet_iframe').trim();
  const envId = 'dev';
  const environmentId = `${projectId}:${envId}`;
  const bootstrapAdminCtx = {
    orgId,
    actorUserId: `user_${projectId}`,
    roles: ['admin'],
  } as const;

  await orgProjectEnv.upsertOrganization(bootstrapAdminCtx, {
    name: String(args.orgName || 'Threshold Wallet Iframe Org').trim(),
    slug: String(args.orgSlug || 'threshold-wallet-iframe-org').trim(),
  });
  await orgProjectEnv.createProject(bootstrapAdminCtx, {
    id: projectId,
    name: String(args.projectName || 'Threshold Wallet Iframe Project').trim(),
    liveEnvironmentsEnabled: true,
  });

  const createdPublishableKey = await apiKeys.createApiKey(bootstrapAdminCtx, {
    kind: 'publishable_key',
    name: String(args.keyName || `${projectId}-browser`).trim(),
    environmentId,
    allowedOrigins,
    rateLimitBucket: 'default_web_v1',
    quotaBucket: 'free_registrations_v1',
  });
  const managedRegistration = {
    environmentId,
    publishableKey: createdPublishableKey.secret,
  } as const;

  const router = createRelayRouter(args.service, {
    corsOrigins: allowedOrigins,
    threshold: args.threshold,
    session,
    publishableKeyAuth: createRelayPublishableKeyAuthAdapter(apiKeys),
    bootstrapGrantBroker: createRelayBootstrapGrantBroker({
      apiKeys,
      tokenStore: bootstrapTokenStore,
      orgProjectEnv,
      rateLimitsByBucket: {
        default_web_v1: { windowMs: 60_000, maxIssued: 100 },
      },
      quotasByBucket: {
        free_registrations_v1: { maxIssued: 100 },
      },
    }),
    bootstrapTokenStore,
    orgProjectEnv,
    signingSessionSeal: args.signingSessionSeal || undefined,
    routerAbPublicKeyset: args.routerAbPublicKeyset || undefined,
  });
  const server = await startExpressRouter(router);

  await args.page.addInitScript((config) => {
    (window as any).__w3aManagedRegistration = config;
  }, managedRegistration);
  await args.page.evaluate((config) => {
    (window as any).__w3aManagedRegistration = config;
  }, managedRegistration);

  return {
    baseUrl: server.baseUrl,
    session,
    managedRegistration,
    runtimePolicyScope: {
      orgId,
      projectId,
      envId,
      signingRootVersion: 'default',
    },
    close: server.close,
  };
}

export function corsHeadersForRoute(route: Route): Record<string, string> {
  const req = route.request();
  const origin = req.headers()['origin'] || req.headers()['Origin'] || '';
  return {
    ...(origin
      ? { 'Access-Control-Allow-Origin': origin }
      : { 'Access-Control-Allow-Origin': '*' }),
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Seams-Benchmark-Diagnostics',
  };
}

export async function installRegistrationBootstrapMock(
  page: Page,
  input: {
    relayerBaseUrl: string;
    onNewPublicKey: (publicKey: string) => void;
    accountsOnChain?: Set<string>;
    keysOnChain?: Set<string>;
    nonceByPublicKey?: Map<string, number>;
    onNewAccountId?: (accountId: string) => void;
    session?: {
      signJwt: (sub: string, extra?: Record<string, unknown>) => Promise<string>;
    };
    runtimePolicyScope?: {
      orgId: string;
      projectId: string;
      envId: string;
      signingRootVersion: string;
    };
    threshold?: unknown;
  },
): Promise<void> {
  await page.route(`${input.relayerBaseUrl}/registration/bootstrap`, async (route) => {
    const req = route.request();
    const method = req.method().toUpperCase();
    if (method === 'OPTIONS') {
      await route.fallback();
      return;
    }

    const corsHeaders = corsHeadersForRoute(route);
    const payload = JSON.parse(req.postData() || '{}');
    const thresholdEd25519 = payload?.threshold_ed25519 || {};
    const thresholdEcdsaClientRootShare32B64u = String(
      payload?.threshold_ecdsa?.client_root_share32_b64u || '',
    ).trim();
    const thresholdPublicKey = String(thresholdEd25519?.public_key || '').trim();
    const thresholdMode = !!thresholdPublicKey;
    const thresholdEcdsaMode = !!thresholdEcdsaClientRootShare32B64u;
    // HSS registration finalize binds the relayer key record to the derived public key.
    // Mirror that current seam here instead of echoing any stale request-time relayer_key_id.
    const relayerKeyId = thresholdPublicKey;
    const registeredPublicKey = thresholdMode ? thresholdPublicKey : '';
    const accountId = String(payload?.new_account_id || '');
    const nowMs = Date.now();
    const nowSec = Math.floor(nowMs / 1000);
    const edSessionPolicy = payload?.threshold_ed25519?.session_policy || null;
    const ecdsaSessionPolicy = payload?.threshold_ecdsa?.session_policy || null;
    const coercePositive = (value: unknown, fallback: number): number => {
      const n = Number(value);
      return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
    };
    const signWalletSessionJwt = async (args: {
      kind: 'threshold_ed25519_session_v1' | 'threshold_ecdsa_session_v1';
      sessionId: string;
      relayerKeyId: string;
      participantIds: number[];
      expiresAtMs: number;
    }): Promise<string> => {
      if (!input.session?.signJwt) {
        return args.kind === 'threshold_ed25519_session_v1'
          ? 'mock-threshold-ed25519-jwt'
          : 'mock-threshold-ecdsa-jwt';
      }
      const expSec = Math.floor(args.expiresAtMs / 1000);
      return await input.session.signJwt(accountId, {
        kind: args.kind,
        walletId: accountId,
        sessionId: args.sessionId,
        relayerKeyId: args.relayerKeyId,
        rpId: String(payload?.rp_id || '').trim() || 'example.localhost',
        participantIds: args.participantIds,
        thresholdExpiresAtMs: args.expiresAtMs,
        ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
        iat: nowSec,
        exp: expSec,
      });
    };
    const edSession =
      thresholdMode && edSessionPolicy
        ? await (async () => {
            const sessionKind =
              String(payload?.threshold_ed25519?.session_kind || 'jwt').toLowerCase() === 'cookie'
                ? ('cookie' as const)
                : ('jwt' as const);
            const sessionId = String(
              edSessionPolicy?.sessionId || edSessionPolicy?.session_id || `ed-session-${nowMs}`,
            );
            const expiresAtMs =
              nowMs + coercePositive(edSessionPolicy?.ttlMs || edSessionPolicy?.ttl_ms, 60_000);
            const participantIds = [1, 2];
            const remainingUses = coercePositive(
              edSessionPolicy?.remainingUses || edSessionPolicy?.remaining_uses,
              10_000,
            );
            return {
              sessionKind,
              sessionId,
              expiresAtMs,
              participantIds,
              remainingUses,
              jwt: await signWalletSessionJwt({
                kind: 'threshold_ed25519_session_v1',
                sessionId,
                relayerKeyId,
                participantIds,
                expiresAtMs,
              }),
              ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
            };
          })()
        : undefined;
    const thresholdEcdsaBootstrap = (
      input.threshold as
        | {
            bootstrapEcdsaFromRegistrationMaterial?: (request: {
              walletSessionUserId: string;
              rpId: string;
              clientRootShare32B64u: string;
              sessionPolicy: Record<string, unknown>;
            }) => Promise<ThresholdEcdsaRegistrationBootstrapResult>;
          }
        | undefined
    )?.bootstrapEcdsaFromRegistrationMaterial;
    const ecdsaBootstrap =
      thresholdEcdsaMode && thresholdEcdsaBootstrap && ecdsaSessionPolicy
        ? await thresholdEcdsaBootstrap({
            walletSessionUserId: accountId,
            rpId: String(payload?.rp_id || '').trim() || 'example.localhost',
            clientRootShare32B64u: thresholdEcdsaClientRootShare32B64u,
            sessionPolicy: {
              version: 'threshold_session_v1',
              walletSessionUserId: accountId,
              rpId: String(payload?.rp_id || '').trim() || 'example.localhost',
              sessionId: String(
                ecdsaSessionPolicy?.sessionId ||
                  ecdsaSessionPolicy?.session_id ||
                  `ecdsa-session-${nowMs}`,
              ),
              participantIds: [1, 2],
              ttlMs: coercePositive(
                ecdsaSessionPolicy?.ttlMs || ecdsaSessionPolicy?.ttl_ms,
                60_000,
              ),
              remainingUses: coercePositive(
                ecdsaSessionPolicy?.remainingUses || ecdsaSessionPolicy?.remaining_uses,
                10_000,
              ),
              ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
            },
          })
        : null;
    if (ecdsaBootstrap && ecdsaBootstrap.ok !== true) {
      await route.fulfill({
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          success: false,
          error: String(ecdsaBootstrap.message || 'threshold-ecdsa registration bootstrap'),
        }),
      });
      return;
    }
    const thresholdEcdsaRelayerKeyId =
      String(
        ecdsaBootstrap && ecdsaBootstrap.ok === true ? ecdsaBootstrap.relayerKeyId || '' : '',
      ).trim() || 'secp256k1:mock-relayer-key-id';
    const thresholdEcdsaPublicKeyB64u =
      String(
        ecdsaBootstrap && ecdsaBootstrap.ok === true
          ? ecdsaBootstrap.thresholdEcdsaPublicKeyB64u || ''
          : '',
      ).trim() || base64UrlEncode(new Uint8Array(33).fill(61));
    const thresholdEcdsaRelayerVerifyingShareB64u =
      String(
        ecdsaBootstrap && ecdsaBootstrap.ok === true
          ? ecdsaBootstrap.relayerVerifyingShareB64u || ''
          : '',
      ).trim() || base64UrlEncode(new Uint8Array(33).fill(31));
    const thresholdEcdsaEthereumAddress =
      String(
        ecdsaBootstrap && ecdsaBootstrap.ok === true ? ecdsaBootstrap.ethereumAddress || '' : '',
      ).trim() || `0x${'12'.repeat(20)}`;
    const thresholdEcdsaThresholdKeyId = String(
      ecdsaBootstrap && ecdsaBootstrap.ok === true ? ecdsaBootstrap.ecdsaThresholdKeyId || '' : '',
    ).trim();
    const thresholdEcdsaClientVerifyingShareB64u = String(
      ecdsaBootstrap && ecdsaBootstrap.ok === true
        ? ecdsaBootstrap.clientVerifyingShareB64u || ''
        : '',
    ).trim();
    const ecdsaSession =
      thresholdEcdsaMode && ecdsaSessionPolicy
        ? await (async () => {
            const sessionKind =
              String(payload?.threshold_ecdsa?.session_kind || 'jwt').toLowerCase() === 'cookie'
                ? ('cookie' as const)
                : ('jwt' as const);
            const sessionId = String(
              ecdsaSessionPolicy?.sessionId ||
                ecdsaSessionPolicy?.session_id ||
                `ecdsa-session-${nowMs}`,
            );
            const expiresAtMs =
              nowMs +
              coercePositive(ecdsaSessionPolicy?.ttlMs || ecdsaSessionPolicy?.ttl_ms, 60_000);
            const participantIds = [1, 2];
            const remainingUses = coercePositive(
              ecdsaSessionPolicy?.remainingUses || ecdsaSessionPolicy?.remaining_uses,
              10_000,
            );
            return {
              sessionKind,
              sessionId,
              expiresAtMs,
              participantIds,
              remainingUses,
              jwt: await signWalletSessionJwt({
                kind: 'threshold_ecdsa_session_v1',
                sessionId,
                relayerKeyId: thresholdEcdsaRelayerKeyId,
                participantIds,
                expiresAtMs,
              }),
            };
          })()
        : undefined;

    if (registeredPublicKey) input.onNewPublicKey(registeredPublicKey);
    if (accountId) {
      input.onNewAccountId?.(accountId);
      const accountsOnChain = input.accountsOnChain ?? DEFAULT_ACCOUNTS_ON_CHAIN;
      accountsOnChain.add(accountId);
    }

    await route.fulfill({
      status: 200,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
      body: JSON.stringify({
        success: true,
        transactionHash: `mock_atomic_tx_${Date.now()}`,
        ...(thresholdMode
          ? {
              thresholdEd25519: {
                keyVersion: THRESHOLD_ED25519_KEY_VERSION_V1,
                recoveryExportCapable: true,
                publicKey: thresholdPublicKey,
                relayerKeyId,
                clientParticipantId: 1,
                relayerParticipantId: 2,
                participantIds: [1, 2],
                ...(edSession ? { session: edSession } : {}),
              },
            }
          : {}),
        ...(thresholdEcdsaMode
          ? {
              thresholdEcdsa: {
                ...(thresholdEcdsaThresholdKeyId
                  ? { ecdsaThresholdKeyId: thresholdEcdsaThresholdKeyId }
                  : {}),
                relayerKeyId: thresholdEcdsaRelayerKeyId,
                ...(thresholdEcdsaClientVerifyingShareB64u
                  ? { clientVerifyingShareB64u: thresholdEcdsaClientVerifyingShareB64u }
                  : {}),
                thresholdEcdsaPublicKeyB64u: thresholdEcdsaPublicKeyB64u,
                ethereumAddress: thresholdEcdsaEthereumAddress,
                relayerVerifyingShareB64u: thresholdEcdsaRelayerVerifyingShareB64u,
                participantIds: [1, 2],
                ...(ecdsaSession ? { session: ecdsaSession } : {}),
              },
            }
          : {}),
      }),
    });
  });
}

export async function installFastNearRpcMock(
  page: Page,
  input: {
    keysOnChain: Set<string>;
    nonceByPublicKey: Map<string, number>;
    onSendTx?: () => void;
    strictAccessKeyLookup?: boolean;
    accountsOnChain?: Set<string>;
  },
): Promise<void> {
  const strictAccessKeyLookup = input.strictAccessKeyLookup ?? true;
  const accountsOnChain = input.accountsOnChain ?? DEFAULT_ACCOUNTS_ON_CHAIN;
  const isKnownAccount = (accountId: string) =>
    (accountId && accountsOnChain.has(accountId)) || DEFAULT_ACCOUNTS_ON_CHAIN.has(accountId);

  await page.route('**://test.rpc.fastnear.com/**', async (route) => {
    const req = route.request();
    const method = req.method().toUpperCase();

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (method === 'OPTIONS') {
      await route.fulfill({ status: 204, headers: corsHeaders, body: '' });
      return;
    }
    if (method !== 'POST') {
      await route.fallback();
      return;
    }

    let body: any = {};
    try {
      body = JSON.parse(req.postData() || '{}');
    } catch {}

    const rpcMethod = body?.method;
    const params = body?.params || {};
    const id = body?.id ?? '1';

    const blockHash = bs58.encode(Buffer.alloc(32, 7));
    const blockHeight = 424242;

    if (rpcMethod === 'block') {
      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id,
          result: { header: { hash: blockHash, height: blockHeight } },
        }),
      });
      return;
    }

    if (rpcMethod === 'query' && params?.request_type === 'call_function') {
      const resultBytes = Array.from(Buffer.from(JSON.stringify({ verified: true }), 'utf8'));
      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({ jsonrpc: '2.0', id, result: { result: resultBytes, logs: [] } }),
      });
      return;
    }

    const requestType = typeof params?.request_type === 'string' ? params.request_type : '';
    const isViewAccount =
      rpcMethod === 'query' &&
      (requestType === 'view_account' || (!!params?.account_id && !requestType));

    if (isViewAccount) {
      const accountId = String(params?.account_id || '');
      if (!isKnownAccount(accountId)) {
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            error: {
              code: -32000,
              message: 'UNKNOWN_ACCOUNT',
              data: 'UNKNOWN_ACCOUNT',
            },
          }),
        });
        return;
      }
      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id,
          result: {
            amount: '0',
            locked: '0',
            code_hash: '11111111111111111111111111111111',
            storage_usage: 0,
            storage_paid_at: 0,
            block_height: blockHeight,
            block_hash: blockHash,
          },
        }),
      });
      return;
    }

    if (rpcMethod === 'query' && params?.request_type === 'view_access_key') {
      const publicKey = String(params?.public_key || '');
      if (strictAccessKeyLookup && publicKey && !input.keysOnChain.has(publicKey)) {
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            error: {
              code: -32000,
              message: 'Unknown access key',
              data: { public_key: publicKey },
            },
          }),
        });
        return;
      }

      const nonce = input.nonceByPublicKey.get(publicKey) ?? 0;
      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id,
          result: {
            block_hash: blockHash,
            block_height: blockHeight,
            nonce,
            permission: 'FullAccess',
          },
        }),
      });
      return;
    }

    if (rpcMethod === 'query' && params?.request_type === 'view_access_key_list') {
      const keys: any[] = Array.from(input.keysOnChain).map((pk) => ({
        public_key: pk,
        access_key: { nonce: input.nonceByPublicKey.get(pk) ?? 0, permission: 'FullAccess' },
      }));
      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({ jsonrpc: '2.0', id, result: { keys } }),
      });
      return;
    }

    if (rpcMethod === 'send_tx') {
      input.onSendTx?.();
      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id,
          result: {
            status: { SuccessValue: '' },
            transaction: { hash: `mock-tx-${Date.now()}` },
            transaction_outcome: { id: `mock-tx-outcome-${Date.now()}` },
            receipts_outcome: [],
          },
        }),
      });
      return;
    }

    await route.fulfill({
      status: 200,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
      body: JSON.stringify({ jsonrpc: '2.0', id, result: {} }),
    });
  });
}

export async function installThresholdEd25519RegistrationMocks(
  page: Page,
  input: {
    relayerBaseUrl: string;
    keysOnChain: Set<string>;
    nonceByPublicKey: Map<string, number>;
    accountsOnChain?: Set<string>;
    onBootstrap?: (input: {
      nearAccountId: string;
      rpId: string;
      relayerKeyId: string;
      publicKey: string;
      keyVersion: string;
    }) => void | Promise<void>;
    session?: {
      signJwt: (sub: string, extra?: Record<string, unknown>) => Promise<string>;
    };
    threshold?: ReturnType<typeof createThresholdSigningService>;
    runtimePolicyScope?: {
      orgId: string;
      projectId: string;
      envId: string;
      signingRootVersion: string;
    };
    mutateThresholdEd25519Response?: (
      thresholdEd25519: Record<string, unknown>,
    ) => Record<string, unknown>;
  },
): Promise<void> {
  const accountsOnChain = input.accountsOnChain ?? DEFAULT_ACCOUNTS_ON_CHAIN;
  const coercePositive = (value: unknown, fallback: number): number => {
    const n = Number(value);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
  };

  await page.route(`${input.relayerBaseUrl}/registration/bootstrap`, async (route) => {
    const req = route.request();
    const method = req.method().toUpperCase();
    const corsHeaders = corsHeadersForRoute(route);
    if (method === 'OPTIONS') {
      await route.fulfill({ status: 204, headers: corsHeaders, body: '' });
      return;
    }
    if (method !== 'POST') {
      await route.fallback();
      return;
    }

    const payload = JSON.parse(req.postData() || '{}');
    const accountId = String(payload?.new_account_id || '').trim();
    const rpId = String(payload?.rp_id || '').trim();
    const thresholdEd25519 = payload?.threshold_ed25519 || {};
    const publicKey = String(thresholdEd25519?.public_key || '').trim();
    const relayerKeyId = publicKey || 'ed25519:mock-relayer-key-id';
    const keyVersion =
      String(thresholdEd25519?.key_version || '').trim() || THRESHOLD_ED25519_KEY_VERSION_V1;
    const sessionPolicy = thresholdEd25519?.session_policy || null;
    const sessionId = String(sessionPolicy?.sessionId || sessionPolicy?.session_id || '').trim();
    const ttlMs = coercePositive(sessionPolicy?.ttlMs || sessionPolicy?.ttl_ms, 60_000);
    const remainingUses = coercePositive(
      sessionPolicy?.remainingUses || sessionPolicy?.remaining_uses,
      10_000,
    );
    const expiresAtMs = Date.now() + ttlMs;
    const effectiveExpiresAtMs = expiresAtMs;
    const effectiveRemainingUses = remainingUses;
    const effectiveParticipantIds = [1, 2];
    const thresholdWalletSessionStore = (
      input.threshold as unknown as {
        walletSessionStore?: {
          putSession: (
            sessionId: string,
            record: unknown,
            opts: { ttlMs: number; remainingUses: number },
          ) => Promise<void>;
        };
      }
    )?.walletSessionStore;
    if (sessionId && thresholdWalletSessionStore?.putSession) {
      await thresholdWalletSessionStore.putSession(
        sessionId,
        {
          expiresAtMs: effectiveExpiresAtMs,
          relayerKeyId,
          userId: accountId,
          rpId,
          participantIds: effectiveParticipantIds,
        },
        {
          ttlMs,
          remainingUses: effectiveRemainingUses,
        },
      );
    }
    const nowSec = Math.floor(Date.now() / 1000);
    const walletSessionJwt =
      sessionId && input.session?.signJwt
        ? await input.session.signJwt(accountId, {
            kind: 'threshold_ed25519_session_v1',
            walletId: accountId,
            sessionId,
            relayerKeyId,
            rpId,
            participantIds: effectiveParticipantIds,
            thresholdExpiresAtMs: effectiveExpiresAtMs,
            ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
            iat: nowSec,
            exp: Math.floor(effectiveExpiresAtMs / 1000),
          })
        : 'mock-threshold-ed25519-registration-jwt';

    if (accountId) {
      accountsOnChain.add(accountId);
    }
    if (publicKey) {
      input.keysOnChain.add(publicKey);
      input.nonceByPublicKey.set(publicKey, input.nonceByPublicKey.get(publicKey) ?? 0);
    }

    await input.onBootstrap?.({
      nearAccountId: accountId,
      rpId,
      relayerKeyId,
      publicKey,
      keyVersion,
    });

    const responseThresholdEd25519Base: Record<string, unknown> = {
      relayerKeyId,
      publicKey,
      keyVersion,
      recoveryExportCapable: true,
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: [1, 2],
      ...(sessionId
        ? {
            session: {
              sessionKind: 'jwt',
              sessionId,
              expiresAtMs: effectiveExpiresAtMs,
              participantIds: effectiveParticipantIds,
              remainingUses: effectiveRemainingUses,
              jwt: walletSessionJwt,
              ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
            },
          }
        : {}),
    };

    const responseThresholdEd25519 = input.mutateThresholdEd25519Response
      ? input.mutateThresholdEd25519Response(responseThresholdEd25519Base)
      : responseThresholdEd25519Base;

    await route.fulfill({
      status: 200,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
      body: JSON.stringify({
        success: true,
        transactionHash: `mock_atomic_tx_${Date.now()}`,
        thresholdEd25519: responseThresholdEd25519,
      }),
    });
  });
}

export function flipFirstByteB64u(b64u: string): string {
  const bytes = base64UrlDecode(b64u);
  if (!bytes.length) return b64u;
  bytes[0] ^= 1;
  return base64UrlEncode(bytes);
}

export async function proxyPostJsonAndMutate(
  route: Route,
  mutate: (json: any) => any,
): Promise<void> {
  const req = route.request();
  const method = req.method().toUpperCase();
  if (method !== 'POST') {
    await route.fallback();
    return;
  }

  const origin = req.headers()['origin'] || req.headers()['Origin'] || '';
  const contentType =
    req.headers()['content-type'] || req.headers()['Content-Type'] || 'application/json';
  const body = req.postData() || '';

  const res = await fetch(req.url(), {
    method: 'POST',
    headers: {
      'Content-Type': contentType,
      ...(origin ? { Origin: origin } : {}),
    },
    body,
  });
  const text = await res.text();
  let outText = text;
  try {
    const json = JSON.parse(text || '{}');
    outText = JSON.stringify(mutate(json));
  } catch {}

  const headers = Object.fromEntries(res.headers.entries());
  delete (headers as Record<string, string>)['content-length'];
  delete (headers as Record<string, string>)['Content-Length'];

  await route.fulfill({
    status: res.status,
    headers,
    body: outText,
  });
}
