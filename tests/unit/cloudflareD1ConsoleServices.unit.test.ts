import { expect, test } from '@playwright/test';
import type { RouterAbNormalSigningAdmissionInput } from '../../packages/sdk-server-ts/src/router/domains/signingOperations/routerAbPrivateSigningWorker';
import {
  createCloudflareD1ConsoleOnlyServiceBundle,
  createCloudflareD1ConsoleServiceBundle,
} from '../../packages/console-server-ts/src/router/cloudflare/d1ConsoleServices';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import type { CfExecutionContext } from '../../packages/sdk-server-ts/src/router/cloudflare/runtime/cloudflare.types';
import localD1DevWorker, {
  buildLocalRouterRequest,
} from '../../packages/console-server-ts/src/router/cloudflare/d1LocalDevWorker';
import type { SponsoredEvmCallExecutorConfig } from '../../packages/console-server-ts/src/sponsorship/evmExecutorTypes';
import { resolveStaticSponsoredExecutionPricingFromEnv } from '../../packages/console-server-ts/src/sponsorship/pricing';
import { getNearSpendCapChainId } from '../../packages/console-shared-ts/src/gasSponsorshipSpendCapTargets';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';

type LocalD1WorkflowEnv = Parameters<typeof localD1DevWorker.fetch>[1];
type JsonRecord = Record<string, unknown>;

const LOCAL_D1_WORKFLOW_ORG_ID = 'org_abcdefgh1234';
const LOCAL_D1_WORKFLOW_SIGNING_WORKER_ID = 'signing-worker.local';

test('local Router binding rewrites the origin and preserves authenticated POST requests', async () => {
  const request = buildLocalRouterRequest(
    'http://127.0.0.1:9090',
    new Request('https://router.router-ab.internal/router-ab/ecdsa-derivation/register?attempt=1', {
      method: 'POST',
      headers: {
        authorization: 'Bearer ceremony-token',
        'content-type': 'application/json',
      },
      body: '{"registration":"payload"}',
    }),
  );

  expect(request.url).toBe('http://127.0.0.1:9090/router-ab/ecdsa-derivation/register?attempt=1');
  expect(request.method).toBe('POST');
  expect(request.headers.get('authorization')).toBe('Bearer ceremony-token');
  expect(request.headers.get('content-type')).toBe('application/json');
  expect(await request.text()).toBe('{"registration":"payload"}');
});

class FakeD1PreparedStatement implements D1PreparedStatementLike {
  constructor(private readonly query: string) {}

  bind(): D1PreparedStatementLike {
    return this;
  }

  async first<T = unknown>(): Promise<T | null> {
    return firstFakeD1Row<T>(this.query);
  }

  async all<T = unknown>(): Promise<D1ResultLike<T>> {
    return {
      success: true,
      results: [] as readonly T[],
    };
  }

  async run<T = unknown>(): Promise<D1ResultLike<T>> {
    return {
      success: true,
      results: [] as readonly T[],
      meta: { changes: 0, rows_written: 0 },
    };
  }
}

class FakeD1Database implements D1DatabaseLike {
  readonly queries: string[] = [];

  prepare(query: string): D1PreparedStatementLike {
    this.queries.push(query);
    return new FakeD1PreparedStatement(query);
  }

  async batch<T = unknown>(): Promise<readonly T[]> {
    return [];
  }

  async exec(): Promise<unknown> {
    return null;
  }
}

function createSponsoredEvmCallExecutorConfig(): SponsoredEvmCallExecutorConfig {
  return {
    executorsByChain: new Map([
      [
        42_431,
        {
          chainId: 42_431,
          rpcUrl: 'https://rpc.example.test',
          sponsorAddress: '0x2222222222222222222222222222222222222222',
          sponsorPrivateKeyHex:
            '0x1111111111111111111111111111111111111111111111111111111111111111',
          maxPriorityFeePerGasFloor: 2_000_000_000n,
          maxFeePerGasFloor: 40_000_000_000n,
        },
      ],
    ]),
  };
}

function createLocalSponsoredEvmExecutorsJson(): string {
  return JSON.stringify({
    '42431': {
      sponsorPrivateKeyHex: '0x1111111111111111111111111111111111111111111111111111111111111111',
      rpcUrl: 'https://rpc.example.test',
    },
  });
}

function firstFakeD1Row<T>(query: string): T | null {
  /* Counts must match the Worker's CONSOLE_READY_TABLES / SIGNER_READY_TABLES
     lengths; readiness fails closed when a migration adds a required table. */
  if (query.includes('sqlite_master') && query.includes('runtime_snapshot_outbox')) {
    return { table_count: 44 } as T;
  }
  if (query.includes('sqlite_master') && query.includes('email_otp_registration_attempts')) {
    return { table_count: 47 } as T;
  }
  return null;
}

function createFakeExecutionContext(): CfExecutionContext {
  return {
    waitUntil,
    passThroughOnException,
  };
}

function waitUntil(_promise: Promise<unknown>): void {}

function passThroughOnException(): void {}

function webAuthnRpId(value: string) {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) {
    throw new Error(parsed.error.message);
  }
  return parsed.value;
}

function createAdmissionInput(): RouterAbNormalSigningAdmissionInput {
  return {
    curve: 'ed25519',
    phase: 'prepare',
    walletId: 'alice.testnet',
    authorityScope: {
      kind: 'passkey_rp',
      rpId: webAuthnRpId('example.localhost'),
    },
    thresholdSessionId: 'threshold-session-1',
    walletSessionId: 'wallet-session-1',
    quotaId: 'wallet-session-quota-1',
    requestId: 'request-1',
    expiresAtMs: Date.now() + 60_000,
    signingWorkerId: 'signing-worker-a',
    runtimePolicyScope: {
      orgId: 'org_1',
      projectId: 'project_1',
      envId: 'env_1',
      signingRootVersion: 'root-v1',
    },
  };
}

/**
 * The Router A/B material the local dev Worker requires to stand up at all,
 * independent of what any one test exercises. Kept in one place because the
 * Worker's required set grows: a test that spreads this keeps booting, a test
 * that hand-lists a few keys silently stops.
 */
const LOCAL_D1_DEV_ROUTER_AB_ENV = {
  ROUTER_AB_NORMAL_SIGNING_WORKER_ID: LOCAL_D1_WORKFLOW_SIGNING_WORKER_ID,
  DERIVER_A_ENVELOPE_HPKE_KEY_EPOCH: 'epoch-1',
  DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY: `x25519:${'11'.repeat(32)}`,
  DERIVER_B_ENVELOPE_HPKE_KEY_EPOCH: 'epoch-1',
  DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY: `x25519:${'22'.repeat(32)}`,
  DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY: `x25519:${'33'.repeat(32)}`,
  DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY: `x25519:${'44'.repeat(32)}`,
  DERIVER_A_PEER_VERIFYING_KEY_HEX:
    '5afa80b305e72e02615ed1f580144a40a42a71dfcac175809ceb5d79e740d015',
  DERIVER_B_PEER_VERIFYING_KEY_HEX:
    '0c700dd63695221e508f3164b528f190bed63a4437d38e882308f9a57acc1bc3',
  SIGNING_WORKER_SERVER_OUTPUT_HPKE_KEY_EPOCH: 'epoch-1',
  SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY: `x25519:${'55'.repeat(32)}`,
  ACCOUNT_ID_DERIVATION_SECRET: 'local-workflow-account-id-derivation-secret',
  SEAMS_LOCAL_CONSOLE_ORG_ID: LOCAL_D1_WORKFLOW_ORG_ID,
  ROUTER_AB_ECDSA_REGISTRATION_TOPOLOGY_JSON: JSON.stringify({
    routerId: 'local-router',
    signerSet: {
      signer_set_id: 'signer-set-v1',
      policy: 'all_2',
      signer_a: { role: 'signer_a', signer_id: 'signer-a', key_epoch: 'epoch-1' },
      signer_b: { role: 'signer_b', signer_id: 'signer-b', key_epoch: 'epoch-1' },
      selected_server: {
        server_id: LOCAL_D1_WORKFLOW_SIGNING_WORKER_ID,
        key_epoch: 'epoch-1',
        recipient_encryption_key: `x25519:${'66'.repeat(32)}`,
      },
    },
    deriverRecipientKeys: {
      deriver_a: {
        role: 'signer_a',
        key_epoch: 'epoch-1',
        public_key: `x25519:${'11'.repeat(32)}`,
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: 'epoch-1',
        public_key: `x25519:${'22'.repeat(32)}`,
      },
    },
  }),
  /* The Worker mints ceremony JWTs, so it needs a signing key exactly as the
     deployed Worker does. A throwaway pair, but a real one — WebCrypto
     rejects a placeholder that is not a curve point. */
  ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK: JSON.stringify({
    kty: 'OKP',
    crv: 'Ed25519',
    x: 'dZBo_spdvrGU19BMbbgt3_4I4QlqHoNzfr1zH3QqFyI',
    d: 'iUlWL9uMjgvXkHHq9q0y-jfVnOEQ3nZLCObiP3tatqE',
  }),
} as const;

function createLocalD1WorkflowEnv(input: {
  readonly consoleDatabase: D1DatabaseLike;
  readonly signerDatabase: D1DatabaseLike;
}): LocalD1WorkflowEnv {
  return {
    ...LOCAL_D1_DEV_ROUTER_AB_ENV,
    CONSOLE_DB: input.consoleDatabase,
    SIGNER_DB: input.signerDatabase,
    SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-workflow-smoke',
    SEAMS_LOCAL_CONSOLE_USER_ID: 'local-workflow-user',
    SEAMS_LOCAL_CONSOLE_PROJECT_ID: 'project-local-workflow',
    SEAMS_LOCAL_CONSOLE_ENVIRONMENT_ID: 'env-local-workflow',
    SEAMS_LOCAL_CONSOLE_ROLES:
      'owner,admin,platform_admin,billing_admin,ops,developer,security_admin',
  };
}

function createLocalWorkflowRequest(input: {
  readonly method: 'GET' | 'POST';
  readonly path: string;
  readonly body?: JsonRecord;
  readonly headers?: HeadersInit;
}): Request {
  const headers = new Headers(input.headers);
  if (input.path.startsWith('/console/') && !input.path.startsWith('/console/auth/')) {
    headers.set('x-console-user-id', 'local-workflow-user');
  }
  let body: string | undefined;
  if (input.body) {
    body = JSON.stringify(input.body);
    if (!headers.has('content-type')) headers.set('content-type', 'application/json');
  }
  return new Request(`http://127.0.0.1:8787${input.path}`, {
    method: input.method,
    headers,
    body,
  });
}

test('local Console sign-out clears the session and refresh stays unauthorized', async () => {
  const database = new FakeD1Database();
  const env = createLocalD1WorkflowEnv({
    consoleDatabase: database,
    signerDatabase: database,
  });
  const ctx = createFakeExecutionContext();

  const missingSession = await localD1DevWorker.fetch(
    new Request('https://localhost:9444/console/session'),
    env,
    ctx,
  );
  expect(missingSession.status).toBe(401);

  const invalidGoogleLogin = await localD1DevWorker.fetch(
    new Request('https://localhost:9444/console/auth/google', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    }),
    env,
    ctx,
  );
  expect(invalidGoogleLogin.status).toBe(400);
  await expect(readJsonRecord(invalidGoogleLogin)).resolves.toMatchObject({
    ok: false,
    code: 'invalid_body',
  });

  const revoke = await localD1DevWorker.fetch(
    new Request('https://localhost:9444/console/auth/revoke', { method: 'POST' }),
    env,
    ctx,
  );
  expect(revoke.status).toBe(200);
  expect(revoke.headers.get('set-cookie')).toContain('seams-console-jwt=');
  expect(revoke.headers.get('set-cookie')).toContain('Max-Age=0');

  const refreshed = await localD1DevWorker.fetch(
    new Request('https://localhost:9444/console/session'),
    env,
    ctx,
  );
  expect(refreshed.status).toBe(401);
});

async function callLocalWorkflowWorker(
  env: LocalD1WorkflowEnv,
  input: {
    readonly method: 'GET' | 'POST';
    readonly path: string;
    readonly body?: JsonRecord;
    readonly headers?: HeadersInit;
  },
): Promise<Response> {
  return await localD1DevWorker.fetch(
    createLocalWorkflowRequest(input),
    env,
    createFakeExecutionContext(),
  );
}

async function readJsonRecord(response: Response): Promise<JsonRecord> {
  const parsed: unknown = await response.json();
  if (!isJsonRecord(parsed)) {
    throw new Error(`Expected JSON object response, got ${typeof parsed}`);
  }
  return parsed;
}

function jsonRecordField(record: JsonRecord, key: string): JsonRecord {
  const value = record[key];
  if (!isJsonRecord(value)) {
    throw new Error(`Expected JSON object field ${key}`);
  }
  return value;
}

function jsonArrayField(record: JsonRecord, key: string): readonly unknown[] {
  const value = record[key];
  if (!Array.isArray(value)) {
    throw new Error(`Expected JSON array field ${key}`);
  }
  return value;
}

function jsonRecordAt(items: readonly unknown[], index: number): JsonRecord {
  const value = items[index];
  if (!isJsonRecord(value)) {
    throw new Error(`Expected JSON object at array index ${index}`);
  }
  return value;
}

function booleanField(record: JsonRecord, key: string): boolean {
  const value = record[key];
  if (typeof value !== 'boolean') {
    throw new Error(`Expected boolean field ${key}`);
  }
  return value;
}

function numberField(record: JsonRecord, key: string): number {
  const value = Number(record[key]);
  if (!Number.isFinite(value)) {
    throw new Error(`Expected finite numeric field ${key}`);
  }
  return value;
}

function stringField(record: JsonRecord, key: string): string {
  const value = record[key];
  if (typeof value !== 'string') {
    throw new Error(`Expected string field ${key}`);
  }
  return value;
}

function isJsonRecord(value: unknown): value is JsonRecord {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

test('Cloudflare D1 service bundle wires signer-D1 normal-signing admission into relay options', async () => {
  const database = new FakeD1Database();
  const signer = createTemporaryD1Database();
  await applyD1MigrationFiles(signer.database, listD1MigrationFiles('d1-signer'));
  const sponsorshipPricing = {
    async estimateSponsoredExecutionSpend() {
      return {
        spendMinor: 1,
        pricingVersion: 'test-pricing-v1',
      };
    },
    async finalizeSponsoredExecutionSpend() {
      return {
        spendMinor: 1,
        pricingVersion: 'test-pricing-v1',
      };
    },
  };
  try {
    const bundle = await createCloudflareD1ConsoleServiceBundle({
      bindings: {
        consoleDatabase: database,
        signerMetadataDatabase: signer.database,
      },
      route: {
        namespace: 'seams',
      },
      adapters: {
        ensureSchema: false,
        sponsorshipPricing,
      },
    });

    const admission = bundle.routerApiRouterOptions.routerAbNormalSigningAdmission;
    const input = createAdmissionInput();

    await expect(admission.evaluatePolicy(input)).resolves.toEqual({ ok: true });
    await expect(admission.evaluatePolicy(input)).resolves.toEqual({ ok: true });
    expect(bundle.sponsorshipPricing).toBe(sponsorshipPricing);
    expect(bundle.routerApiRouterOptions).not.toHaveProperty('signedDelegate');
    expect(bundle.routerApiRouterOptions).not.toHaveProperty('sponsorship');
    expect(bundle.routerApiRouterOptions).not.toHaveProperty('sponsoredEvmCall');
    expect(bundle.routerApiRouterOptions.orgProjectEnv).toBe(bundle.orgProjectEnv);
    expect(bundle.routerApiRouterOptions).not.toHaveProperty('observabilityIngestion');
    expect(typeof bundle.routerApiRouterOptions.apiKeyAuth.authenticate).toBe('function');
    expect(typeof bundle.routerApiRouterOptions.publishableKeyAuth.authenticate).toBe('function');
    expect(typeof bundle.routerApiRouterOptions.apiKeyUsageMeter.recordEvent).toBe('function');
    expect(bundle.routerApiRouterOptions).not.toHaveProperty('wallets');
    expect(bundle.routerApiRouterOptions.routeExtensions.length).toBeGreaterThan(0);
    expect(
      bundle.routerApiRouterOptions.routeExtensions
        .flatMap((extension) => extension.routes)
        .some((route) => route.id === 'sponsored_evm_call'),
    ).toBe(false);
  } finally {
    cleanupTemporaryD1Database(signer.tempDir);
  }
});

test('Cloudflare D1 console-only bundle omits signer custody bindings', async () => {
  const database = new FakeD1Database();
  const bundle = await createCloudflareD1ConsoleOnlyServiceBundle({
    bindings: {
      consoleDatabase: database,
    },
    route: {
      namespace: 'seams',
    },
    adapters: {
      ensureSchema: false,
    },
  });

  expect(bundle).not.toHaveProperty('tenantStorageRouteResolver');
  expect(bundle).not.toHaveProperty('routerApiRouterOptions');
  expect(bundle).not.toHaveProperty('spendCaps');
  expect(bundle.consoleRouterOptions).not.toHaveProperty('tenantStorageRouteResolver');
  expect(bundle.consoleRouterOptions).not.toHaveProperty('tenantStorageNamespace');
  expect(bundle.consoleRouterOptions.keyExports).toBe(bundle.keyExports);
  expect(bundle.consoleRouterOptions.billing).toBe(bundle.billing);
  expect(bundle.consoleRouterOptions.sponsoredCalls).toBe(bundle.sponsoredCalls);
});

test('D1 Router API storage options attach sponsored EVM route extension with executor config', async () => {
  const database = new FakeD1Database();
  const sponsoredEvmCallConfig = createSponsoredEvmCallExecutorConfig();
  const bundle = await createCloudflareD1ConsoleServiceBundle({
    bindings: {
      consoleDatabase: database,
      signerMetadataDatabase: database,
    },
    route: {
      namespace: 'seams',
    },
    adapters: {
      ensureSchema: false,
      sponsoredEvmCallConfig,
    },
  });

  const extensionRoutes = bundle.routerApiRouterOptions.routeExtensions.flatMap(
    (extension) => extension.routes,
  );
  const sponsoredRoute = extensionRoutes.find((route) => route.id === 'sponsored_evm_call');
  expect(bundle.routerApiRouterOptions).not.toHaveProperty('sponsoredEvmCall');
  expect(sponsoredRoute).toMatchObject({
    method: 'POST',
    path: '/sponsorships/evm/call',
    metering: { kind: 'gas', ledger: 'evm' },
    requiredServices: ['routerApiSponsoredEvmCall'],
  });
  expect(sponsoredEvmCallConfig.executorsByChain.size).toBe(1);
});

test('D1 Router API routes NEAR pricing around the EVM-only D1 pricing adapter', async () => {
  const database = new FakeD1Database();
  const nearPricing = resolveStaticSponsoredExecutionPricingFromEnv({
    SPONSORED_EXECUTION_STATIC_PRICING_JSON: JSON.stringify({
      near: {
        TESTNET: {
          estimateFeeAmountYocto: '1000',
          minorPerFeeUnitNumerator: '1',
          minorPerFeeUnitDenominator: '1000',
          pricingVersion: 'static-near-testnet-v1',
        },
      },
    }),
  });
  expect(nearPricing).not.toBeNull();
  const bundle = await createCloudflareD1ConsoleServiceBundle({
    bindings: {
      consoleDatabase: database,
      signerMetadataDatabase: database,
    },
    route: {
      namespace: 'seams',
    },
    adapters: {
      ensureSchema: false,
      sponsoredEvmCallConfig: createSponsoredEvmCallExecutorConfig(),
      sponsorshipPricing: nearPricing,
    },
  });

  const quote = await bundle.sponsorshipPricing!.estimateSponsoredExecutionSpend({
    chainFamily: 'near',
    intentKind: 'near_delegate',
    executorKind: 'near_delegate',
    environmentId: 'env-local',
    policyId: 'policy-near',
    accountRef: 'near:sender.testnet',
    targetRef: 'near:guest-book.testnet',
    chainId: getNearSpendCapChainId('TESTNET'),
    requestDetails: {
      receiverId: 'guest-book.testnet',
    },
  });

  expect(quote).toEqual({
    spendMinor: 1,
    pricingVersion: 'static-near-testnet-v1',
  });
});

test('local D1 Worker ready smoke validates D1 tables and signer-D1 admission', async () => {
  const database = new FakeD1Database();
  const response = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/readyz'),
    {
      ...LOCAL_D1_DEV_ROUTER_AB_ENV,
      CONSOLE_DB: database,
      SIGNER_DB: database,
      SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-test',
    },
    createFakeExecutionContext(),
  );

  expect(response.status).toBe(200);
  await expect(response.json()).resolves.toMatchObject({
    ok: true,
    backend: 'cloudflare_d1_do',
    namespace: 'seams-local-test',
    schemas: {
      consoleTables: 44,
      signerTables: 47,
    },
    admission: {
      database: 'SIGNER_DB',
      policy: 'allowed',
    },
  });
});

test('local D1 Worker routes smoke requests through the Router API handler', async () => {
  const database = new FakeD1Database();
  const env = {
    ...LOCAL_D1_DEV_ROUTER_AB_ENV,
    CONSOLE_DB: database,
    SIGNER_DB: database,
    SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-test',
  };
  const ctx = createFakeExecutionContext();

  const health = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/relay/healthz'),
    env,
    ctx,
  );
  expect(health.status).toBe(200);
  await expect(health.json()).resolves.toMatchObject({
    ok: true,
    thresholdEd25519: { configured: true },
    cors: {
      allowedOrigins: [
        'https://localhost',
        'https://localhost:8443',
        'https://localhost:9444',
        'http://127.0.0.1:9090',
        'http://localhost:9090',
        'http://127.0.0.1:8787',
        'http://localhost:8787',
      ],
    },
  });

  const sponsored = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/relay/sponsorships/evm/call', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: 'http://127.0.0.1:8787',
      },
      body: JSON.stringify({
        environmentId: 'project_local:local',
        walletId: 'wallet_local_1',
        walletAddress: '0x1111111111111111111111111111111111111111',
        chainId: 1,
        call: {
          to: '0x2222222222222222222222222222222222222222',
          data: '0x12345678',
          gasLimit: '21000',
          value: '0',
        },
        idempotencyKey: 'intent_local_1',
      }),
    }),
    env,
    ctx,
  );
  expect(sponsored.status).toBe(404);
  expect(sponsored.headers.get('Access-Control-Allow-Origin')).toBe('http://127.0.0.1:8787');

  const signedDelegate = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/relay/signed-delegate', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: 'http://127.0.0.1:8787',
      },
      body: '{}',
    }),
    env,
    ctx,
  );
  expect(signedDelegate.status).not.toBe(404);
  expect(signedDelegate.headers.get('Access-Control-Allow-Origin')).toBe('http://127.0.0.1:8787');

  const apiWallets = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/v1/wallets', {
      method: 'GET',
    }),
    env,
    ctx,
  );
  expect(apiWallets.status).toBe(401);
  await expect(apiWallets.json()).resolves.toMatchObject({
    ok: false,
    code: 'secret_key_missing',
  });
});

test('local D1 Worker routes internal Gateway requests through the Router API handler', async () => {
  const database = new FakeD1Database();
  const response = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/internal/gateway/device-linking/v1/lanes/prepare', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    }),
    {
      ...LOCAL_D1_DEV_ROUTER_AB_ENV,
      CONSOLE_DB: database,
      SIGNER_DB: database,
      SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-test',
    },
    createFakeExecutionContext(),
  );

  expect(response.status).toBe(400);
  await expect(response.json()).resolves.toMatchObject({
    ok: false,
    code: 'invalid_body',
  });
});

test('local D1 Worker mounts direct sponsored EVM Router API route when local executor config is present', async () => {
  const database = new FakeD1Database();
  const response = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/sponsorships/evm/call', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: 'http://127.0.0.1:8787',
      },
      body: JSON.stringify({
        environmentId: 'local',
        walletId: 'local.sponsored.testnet',
        walletAddress: '0x1111111111111111111111111111111111111111',
        chainId: 42_431,
        call: {
          to: '0x2222222222222222222222222222222222222222',
          data: '0x12345678',
          gasLimit: '21000',
          value: '0',
        },
        idempotencyKey: 'local-sponsored-route-mounted',
      }),
    }),
    {
      ...LOCAL_D1_DEV_ROUTER_AB_ENV,
      CONSOLE_DB: database,
      SIGNER_DB: database,
      SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-test',
      SPONSORED_EVM_EXECUTORS_JSON: createLocalSponsoredEvmExecutorsJson(),
      /* An executor alone does not make the route serviceable: its handler
         refuses with 503 when spend pricing is unconfigured, and does so
         before authenticating. Without pricing this test would assert that
         gate rather than the publishable-key requirement it is named for. */
      SPONSORED_EXECUTION_STATIC_PRICING_JSON: JSON.stringify({
        evm: {
          '42431': {
            estimateFeePerGas: '1000000000',
            minorPerFeeUnitNumerator: '1',
            minorPerFeeUnitDenominator: '1000000000000',
            pricingVersion: 'static-evm-42431-v1',
          },
        },
      }),
    },
    createFakeExecutionContext(),
  );

  expect(response.status).toBe(401);
  await expect(response.json()).resolves.toMatchObject({
    ok: false,
    code: 'publishable_key_missing',
  });
});

test('local D1 Worker serves Router A/B public keyset from local Worker env', async () => {
  const database = new FakeD1Database();
  const env = createLocalD1WorkflowEnv({
    consoleDatabase: database,
    signerDatabase: database,
  });
  const response = await callLocalWorkflowWorker(env, {
    method: 'GET',
    path: '/router-ab/keyset',
  });

  expect(response.status).toBe(200);
  await expect(readJsonRecord(response)).resolves.toMatchObject({
    keyset_version: 'router_ab_keyset_v2',
    signer_envelope_hpke: {
      current: {
        deriver_a: {
          role: 'signer_a',
          key_epoch: 'epoch-1',
        },
        deriver_b: {
          role: 'signer_b',
          key_epoch: 'epoch-1',
        },
      },
    },
    signing_worker_server_output_hpke: {
      key_epoch: 'epoch-1',
    },
  });
});

test('local D1 Worker runs a representative signer smoke through relay prefix', async () => {
  const database = new FakeD1Database();
  const response = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/relay/auth/passkey/options', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: 'http://127.0.0.1:8787',
      },
      body: JSON.stringify({
        user_id: 'alice.testnet',
        rp_id: 'localhost',
      }),
    }),
    {
      ...LOCAL_D1_DEV_ROUTER_AB_ENV,
      CONSOLE_DB: database,
      SIGNER_DB: database,
      SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-test',
    },
    createFakeExecutionContext(),
  );

  expect(response.status).toBe(200);
  await expect(response.json()).resolves.toMatchObject({
    ok: true,
  });
  expect(database.queries.some((query) => query.includes('INSERT INTO webauthn_challenges'))).toBe(
    true,
  );
});

test('local D1 Worker serves console routes through D1 console services', async () => {
  const database = new FakeD1Database();
  const response = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/console/readyz', {
      headers: {
        'x-console-user-id': 'local-user',
        'x-console-org-id': 'local-org',
        'x-console-roles': 'owner,admin',
      },
    }),
    {
      ...LOCAL_D1_DEV_ROUTER_AB_ENV,
      CONSOLE_DB: database,
      SIGNER_DB: database,
      SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-test',
    },
    createFakeExecutionContext(),
  );

  expect(response.status).toBe(200);
  await expect(response.json()).resolves.toMatchObject({
    ok: true,
    service: 'console',
  });
});

test('local D1 Worker serves dashboard Google options at the root auth path', async () => {
  const database = new FakeD1Database();
  const response = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:9090/auth/google/options', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    }),
    {
      ...LOCAL_D1_DEV_ROUTER_AB_ENV,
      CONSOLE_DB: database,
      SIGNER_DB: database,
      SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-test',
      GOOGLE_OIDC_CLIENT_ID: 'local-google-client.apps.googleusercontent.com',
    },
    createFakeExecutionContext(),
  );

  expect(response.status).toBe(200);
  await expect(response.json()).resolves.toMatchObject({
    ok: true,
    configured: true,
    clientId: 'local-google-client.apps.googleusercontent.com',
  });
});

test('local D1 Worker routes dashboard session exchange and state at root paths', async () => {
  const database = new FakeD1Database();
  const env = {
    ...LOCAL_D1_DEV_ROUTER_AB_ENV,
    CONSOLE_DB: database,
    SIGNER_DB: database,
    SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-test',
    GOOGLE_OIDC_CLIENT_ID: 'local-google-client.apps.googleusercontent.com',
  };
  const ctx = createFakeExecutionContext();

  const exchange = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:9090/session/exchange', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        session_kind: 'cookie',
        exchange: {
          type: 'oidc_jwt',
          provider: 'google',
          token: 'not-a-jwt',
        },
      }),
    }),
    env,
    ctx,
  );
  expect(exchange.status).toBe(400);
  await expect(exchange.json()).resolves.toMatchObject({
    ok: false,
    code: 'invalid_body',
    message: 'id_token must be a JWT (3 segments)',
  });

  const state = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:9090/session/state'),
    env,
    ctx,
  );
  expect(state.status).toBe(200);
  await expect(state.json()).resolves.toMatchObject({
    authenticated: false,
    code: 'unauthorized',
  });
});

test('local D1 Worker serves dashboard onboarding state through D1 services', async () => {
  const consoleTemp = createTemporaryD1Database();
  const signerTemp = createTemporaryD1Database();

  try {
    await applyD1MigrationFiles(consoleTemp.database, listD1MigrationFiles('d1-console'));
    await applyD1MigrationFiles(signerTemp.database, listD1MigrationFiles('d1-signer'));
    const env = createLocalD1WorkflowEnv({
      consoleDatabase: consoleTemp.database,
      signerDatabase: signerTemp.database,
    });

    const response = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: '/console/onboarding/state',
    });

    expect(response.status).toBe(200);
    await expect(readJsonRecord(response)).resolves.toMatchObject({
      ok: true,
      state: {
        orgId: LOCAL_D1_WORKFLOW_ORG_ID,
        hasOrganization: false,
        hasProject: false,
        hasEnvironment: false,
        onboardingComplete: false,
        currentStep: 'organization',
      },
    });

    const approvalsResponse = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: '/console/approvals',
    });
    expect(approvalsResponse.status).toBe(200);
    await expect(readJsonRecord(approvalsResponse)).resolves.toMatchObject({
      ok: true,
      approvals: [],
    });
  } finally {
    cleanupTemporaryD1Database(consoleTemp.tempDir);
    cleanupTemporaryD1Database(signerTemp.tempDir);
  }
});

test('local D1 publishable key creation publishes Tempo sponsorship runtime snapshot', async () => {
  test.setTimeout(60_000);
  const consoleTemp = createTemporaryD1Database();
  const signerTemp = createTemporaryD1Database();

  try {
    await applyD1MigrationFiles(consoleTemp.database, listD1MigrationFiles('d1-console'));
    await applyD1MigrationFiles(signerTemp.database, listD1MigrationFiles('d1-signer'));
    const env = {
      ...createLocalD1WorkflowEnv({
        consoleDatabase: consoleTemp.database,
        signerDatabase: signerTemp.database,
      }),
      SPONSORED_EVM_EXECUTORS_JSON: createLocalSponsoredEvmExecutorsJson(),
    };

    const organizationResponse = await callLocalWorkflowWorker(env, {
      method: 'POST',
      path: '/console/onboarding/organization',
      body: {
        org: { name: 'Tempo Snapshot Org', slug: 'tempo-snapshot-org' },
      },
    });
    expect(organizationResponse.status).toBe(201);

    const projectResponse = await callLocalWorkflowWorker(env, {
      method: 'POST',
      path: '/console/onboarding/project',
      body: {
        project: { id: 'proj_tempo_snapshot', name: 'Tempo Snapshot Project' },
        environment: { id: 'proj_tempo_snapshot-dev', name: 'Development' },
      },
    });
    expect(projectResponse.status).toBe(201);
    const projectResult = jsonRecordField(await readJsonRecord(projectResponse), 'result');
    const projectId = stringField(jsonRecordField(projectResult, 'project'), 'id');
    const environmentId = stringField(jsonRecordField(projectResult, 'environment'), 'id');

    const apiKeyResponse = await callLocalWorkflowWorker(env, {
      method: 'POST',
      path: '/console/api-keys',
      body: {
        kind: 'publishable_key',
        name: 'tempo-snapshot-browser',
        environmentId,
        allowedOrigins: ['https://localhost:8443'],
        rateLimitBucket: 'default_web_v1',
        quotaBucket: 'free_registrations_v1',
      },
    });
    expect(apiKeyResponse.status).toBe(201);

    const snapshotResponse = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: `/console/runtime-snapshots/latest?environmentId=${encodeURIComponent(
        environmentId,
      )}&projectId=${encodeURIComponent(projectId)}`,
    });
    expect(snapshotResponse.status).toBe(200);
    const snapshot = jsonRecordField(await readJsonRecord(snapshotResponse), 'snapshot');
    expect(stringField(snapshot, 'environmentId')).toBe(environmentId);
    expect(numberField(snapshot, 'version')).toBeGreaterThanOrEqual(1);
    const gasSponsorship = jsonRecordField(jsonRecordField(snapshot, 'payload'), 'gasSponsorship');
    expect(stringField(gasSponsorship, 'status')).toBe('resolved');
    const resolvedPolicies = jsonArrayField(gasSponsorship, 'resolvedPolicies');
    expect(resolvedPolicies).toHaveLength(1);
    const policy = jsonRecordAt(resolvedPolicies, 0);
    const pricingRow = await consoleTemp.database
      .prepare(
        `SELECT pricing_version
           FROM sponsorship_pricing_rules
          WHERE namespace = ?
            AND environment_id = ?
            AND policy_id = ?
            AND chain_id = ?
            AND status = 'active'`,
      )
      .bind('seams-local-workflow-smoke', environmentId, stringField(policy, 'policyId'), 42_431)
      .first<{ pricing_version?: string }>();
    expect(pricingRow?.pricing_version).toBe(
      `tempo-testnet-static-v1:${stringField(policy, 'policyId')}`,
    );
  } finally {
    cleanupTemporaryD1Database(consoleTemp.tempDir);
    cleanupTemporaryD1Database(signerTemp.tempDir);
  }
});

test('local D1 Worker runs dashboard, signer, billing, and reconciliation smoke on real D1', async () => {
  test.setTimeout(60_000);
  const consoleTemp = createTemporaryD1Database();
  const signerTemp = createTemporaryD1Database();

  try {
    await applyD1MigrationFiles(consoleTemp.database, listD1MigrationFiles('d1-console'));
    await applyD1MigrationFiles(signerTemp.database, listD1MigrationFiles('d1-signer'));
    const env = createLocalD1WorkflowEnv({
      consoleDatabase: consoleTemp.database,
      signerDatabase: signerTemp.database,
    });

    const readyResponse = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: '/readyz',
    });
    expect(readyResponse.status).toBe(200);
    await expect(readJsonRecord(readyResponse)).resolves.toMatchObject({
      ok: true,
      backend: 'cloudflare_d1_do',
      namespace: 'seams-local-workflow-smoke',
      schemas: {
        consoleTables: 44,
        signerTables: 47,
      },
      /* Admission moved to private D1, so readiness names the database it
         proved the policy against rather than a Durable Object binding. */
      admission: {
        database: 'SIGNER_DB',
        policy: 'allowed',
      },
    });

    const consoleReadyResponse = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: '/console/readyz',
    });
    expect(consoleReadyResponse.status).toBe(200);
    await expect(readJsonRecord(consoleReadyResponse)).resolves.toMatchObject({
      ok: true,
      service: 'console',
    });

    const supportCreditResponse = await callLocalWorkflowWorker(env, {
      method: 'POST',
      path: '/console/billing/adjustments/support-credit',
      body: {
        amountMinor: 5000,
        reasonCode: 'local_workflow_smoke_credit',
        note: 'Seed local D1 workflow smoke prepaid balance',
        idempotencyKey: 'local-workflow-smoke-credit',
      },
    });
    expect(supportCreditResponse.status).toBe(201);
    const supportCredit = jsonRecordField(await readJsonRecord(supportCreditResponse), 'result');
    expect(booleanField(supportCredit, 'created')).toBe(true);
    expect(numberField(jsonRecordField(supportCredit, 'adjustment'), 'amountMinor')).toBe(5000);

    const duplicateCreditResponse = await callLocalWorkflowWorker(env, {
      method: 'POST',
      path: '/console/billing/adjustments/support-credit',
      body: {
        amountMinor: 5000,
        reasonCode: 'local_workflow_smoke_credit',
        note: 'Seed local D1 workflow smoke prepaid balance',
        idempotencyKey: 'local-workflow-smoke-credit',
      },
    });
    expect(duplicateCreditResponse.status).toBe(200);
    const duplicateCredit = jsonRecordField(
      await readJsonRecord(duplicateCreditResponse),
      'result',
    );
    expect(booleanField(duplicateCredit, 'created')).toBe(false);

    const overviewResponse = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: '/console/billing/overview',
    });
    expect(overviewResponse.status).toBe(200);
    const overview = jsonRecordField(await readJsonRecord(overviewResponse), 'overview');
    expect(numberField(overview, 'creditBalanceMinor')).toBe(5000);

    const activityResponse = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: '/console/billing/account/activity?limit=5',
    });
    expect(activityResponse.status).toBe(200);
    const activity = jsonRecordField(await readJsonRecord(activityResponse), 'activity');
    const entries = jsonArrayField(activity, 'entries');
    expect(entries).toHaveLength(1);
    expect(numberField(jsonRecordAt(entries, 0), 'amountMinor')).toBe(5000);

    const signerResponse = await callLocalWorkflowWorker(env, {
      method: 'POST',
      path: '/relay/auth/passkey/options',
      headers: {
        origin: 'http://127.0.0.1:8787',
      },
      body: {
        user_id: 'local.workflow.testnet',
        rp_id: 'localhost',
      },
    });
    expect(signerResponse.status).toBe(200);
    await expect(readJsonRecord(signerResponse)).resolves.toMatchObject({
      ok: true,
    });

    const sponsoredHistoryResponse = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: '/console/billing/sponsored-executions',
    });
    expect(sponsoredHistoryResponse.status).toBe(200);
    const sponsoredHistoryPage = jsonRecordField(
      await readJsonRecord(sponsoredHistoryResponse),
      'page',
    );
    expect(jsonArrayField(sponsoredHistoryPage, 'items')).toHaveLength(0);

    const reconciliationResponse = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: '/console/billing/sponsored-executions/reconciliation',
    });
    expect(reconciliationResponse.status).toBe(200);
    const reconciliationPage = jsonRecordField(
      await readJsonRecord(reconciliationResponse),
      'page',
    );
    expect(jsonArrayField(reconciliationPage, 'items')).toHaveLength(0);
    expect(jsonRecordField(reconciliationPage, 'summary')).toMatchObject({
      matchedCount: 0,
      missingBillingDebitCount: 0,
      amountMismatchCount: 0,
      unexpectedBillingDebitCount: 0,
    });
  } finally {
    cleanupTemporaryD1Database(consoleTemp.tempDir);
    cleanupTemporaryD1Database(signerTemp.tempDir);
  }
});
