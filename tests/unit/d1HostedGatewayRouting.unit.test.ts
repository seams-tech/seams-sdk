import { expect, test } from '@playwright/test';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
} from '../../packages/sdk-server-ts/src/core/types';
import type {
  CfExecutionContext,
  FetchHandler,
} from '../../packages/sdk-server-ts/src/router/cloudflare/cloudflare.types';
import type { RouterAbEd25519YaoGatewayCutoverStateV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/routerAbEd25519YaoGatewayCutover';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
} from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import d1RouterApiStagingWorker, {
  dispatchHostedGatewayRequest,
  resolveRouterApiYaoGatewayRequestRouteV1,
} from '../../packages/console-server-ts/src/router/cloudflare/d1RouterApiStagingWorker';
import {
  ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1,
} from '../../packages/shared-ts/src/utils/routerAbEd25519Yao';
import { ROUTER_AB_ED25519_WALLET_SESSION_PATH } from '../../packages/shared-ts/src/utils/signingSessionSeal';

function markerHandler(marker: string): FetchHandler {
  return buildMarkerResponse.bind(null, marker);
}

async function buildMarkerResponse(marker: string): Promise<Response> {
  return new Response(marker);
}

async function routePath(pathname: string): Promise<string> {
  const response = await dispatchHostedGatewayRequest(
    markerHandler('console'),
    markerHandler('router-api'),
    new Request(`https://gateway.example.test${pathname}`),
  );
  return await response.text();
}

function resolveYaoRoute(
  pathname: string,
  nowMs: number,
  cutover: RouterAbEd25519YaoGatewayCutoverStateV1,
) {
  return resolveRouterApiYaoGatewayRequestRouteV1({
    request: new Request(`https://gateway.example.test${pathname}`, { method: 'POST' }),
    nowMs,
    cutover,
  });
}

const ALL_FAMILIES_WINDOW = {
  registration: { admissionCutoffMs: 1_000, drainUntilMs: 2_000 },
  recovery: { admissionCutoffMs: 1_000, drainUntilMs: 2_000 },
  export: { admissionCutoffMs: 1_000, drainUntilMs: 2_000 },
} as const;

const FULL_GATEWAY_REGISTRATION_PATHS = [
  '/wallets/register/start',
  '/wallets/register/finalize',
  '/wallets/wallet-1/signers/start',
  '/wallets/wallet-1/signers/finalize',
] as const;

const FULL_GATEWAY_RECOVERY_PATHS = [
  ROUTER_AB_ED25519_WALLET_SESSION_PATH,
  '/wallet/unlock/verify',
  '/sync-account/verify',
] as const;

const DIRECT_CONTINUATION_PATHS = [
  ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
  ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1,
] as const;

const ALL_YAO_PATHS = [
  ...FULL_GATEWAY_REGISTRATION_PATHS,
  ...FULL_GATEWAY_RECOVERY_PATHS,
  ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1,
  ...DIRECT_CONTINUATION_PATHS,
] as const;

const POST_DRAIN_WINDOW_ENV = {
  ROUTER_AB_YAO_GATEWAY_REGISTRATION_ADMISSION_CUTOFF_MS: '0',
  ROUTER_AB_YAO_GATEWAY_REGISTRATION_DRAIN_UNTIL_MS: '0',
  ROUTER_AB_YAO_GATEWAY_RECOVERY_ADMISSION_CUTOFF_MS: '0',
  ROUTER_AB_YAO_GATEWAY_RECOVERY_DRAIN_UNTIL_MS: '0',
  ROUTER_AB_YAO_GATEWAY_EXPORT_ADMISSION_CUTOFF_MS: '0',
  ROUTER_AB_YAO_GATEWAY_EXPORT_DRAIN_UNTIL_MS: '0',
} as const;

const PRE_CUTOFF_TIMESTAMP = String(Number.MAX_SAFE_INTEGER);
const PRE_CUTOFF_WINDOW_ENV = {
  ROUTER_AB_YAO_GATEWAY_REGISTRATION_ADMISSION_CUTOFF_MS: PRE_CUTOFF_TIMESTAMP,
  ROUTER_AB_YAO_GATEWAY_REGISTRATION_DRAIN_UNTIL_MS: PRE_CUTOFF_TIMESTAMP,
  ROUTER_AB_YAO_GATEWAY_RECOVERY_ADMISSION_CUTOFF_MS: PRE_CUTOFF_TIMESTAMP,
  ROUTER_AB_YAO_GATEWAY_RECOVERY_DRAIN_UNTIL_MS: PRE_CUTOFF_TIMESTAMP,
  ROUTER_AB_YAO_GATEWAY_EXPORT_ADMISSION_CUTOFF_MS: PRE_CUTOFF_TIMESTAMP,
  ROUTER_AB_YAO_GATEWAY_EXPORT_DRAIN_UNTIL_MS: PRE_CUTOFF_TIMESTAMP,
} as const;

class RecordingRuntimeNamespace
  implements CloudflareDurableObjectNamespaceLike, CloudflareDurableObjectStubLike
{
  idFromNameCalls = 0;
  getCalls = 0;
  fetchCalls = 0;

  idFromName(name: string): unknown {
    this.idFromNameCalls += 1;
    return name;
  }

  get(): CloudflareDurableObjectStubLike {
    this.getCalls += 1;
    return this;
  }

  async fetch(): Promise<Response> {
    this.fetchCalls += 1;
    return new Response('legacy-runtime');
  }
}

class RejectingD1Database implements D1DatabaseLike {
  prepare(): D1PreparedStatementLike {
    throw new Error('D1 execution is outside the tenant-runtime boundary assertion');
  }

  async batch<T>(): Promise<readonly T[]> {
    throw new Error('D1 execution is outside the tenant-runtime boundary assertion');
  }

  async exec(): Promise<unknown> {
    throw new Error('D1 execution is outside the tenant-runtime boundary assertion');
  }
}

class RejectingServiceBinding {
  async fetch(): Promise<Response> {
    throw new Error('service execution is outside the tenant-runtime boundary assertion');
  }
}

const FETCH_BOUNDARY_CONTEXT: CfExecutionContext = {
  waitUntil: ignorePromise,
  passThroughOnException: ignore,
};

function ignore(): void {}

function ignorePromise(_promise: Promise<unknown>): void {}

function createFetchBoundaryEnv(
  runtime: RecordingRuntimeNamespace,
  window: typeof PRE_CUTOFF_WINDOW_ENV | typeof POST_DRAIN_WINDOW_ENV,
): Parameters<typeof d1RouterApiStagingWorker.fetch>[1] {
  const database = new RejectingD1Database();
  const thresholdStore = new RecordingRuntimeNamespace();
  const service = new RejectingServiceBinding();
  return {
    CONSOLE_DB: database,
    SIGNER_DB: database,
    THRESHOLD_STORE: thresholdStore,
    ROUTER_API_RUNTIME: runtime,
    MPC_ROUTER: service,
    DERIVER_A: service,
    DERIVER_B: service,
    SIGNING_WORKER: service,
    SEAMS_TENANT_STORAGE_NAMESPACE: 'test',
    SEAMS_STAGING_ORG_ID: 'org-test',
    SEAMS_STAGING_PROJECT_ID: 'project-test',
    SEAMS_STAGING_ENV_ID: 'env-test',
    ...window,
  };
}

function yaoRequest(pathname: string): Request {
  return new Request(`https://gateway.example.test${pathname}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}',
  });
}

async function settleWorkerRequest(request: Promise<Response>): Promise<void> {
  try {
    await request;
  } catch {
    // The partitioned handler can reject on deliberately absent non-routing fixtures.
  }
}

test('hosted gateway dispatches console routes to the console router', async () => {
  await expect(routePath('/console/session')).resolves.toBe('console');
  await expect(routePath('/console/billing/account')).resolves.toBe('console');
});

test('hosted gateway keeps Router API routes on the Router API router', async () => {
  await expect(routePath('/session/exchange')).resolves.toBe('router-api');
  await expect(routePath('/consolex')).resolves.toBe('router-api');
});

test('Yao runtime consumers stay on the tenant runtime with no cutover window', () => {
  for (const pathname of ALL_YAO_PATHS) {
    expect(resolveYaoRoute(pathname, 10_000, {}).kind).toBe('legacy_runtime');
  }
});

test('every Yao runtime consumer stays legacy before its family cutoff', () => {
  for (const pathname of ALL_YAO_PATHS) {
    expect(resolveYaoRoute(pathname, 999, ALL_FAMILIES_WINDOW).kind).toBe('legacy_runtime');
  }
});

test('the Worker fetch boundary bypasses ROUTER_API_RUNTIME for every post-drain Yao route', async () => {
  for (const pathname of ALL_YAO_PATHS) {
    const runtime = new RecordingRuntimeNamespace();
    await settleWorkerRequest(
      d1RouterApiStagingWorker.fetch(
        yaoRequest(pathname),
        createFetchBoundaryEnv(runtime, POST_DRAIN_WINDOW_ENV),
        FETCH_BOUNDARY_CONTEXT,
      ),
    );
    expect(
      [runtime.idFromNameCalls, runtime.getCalls, runtime.fetchCalls],
      `unexpected tenant-runtime access for ${pathname}`,
    ).toEqual([0, 0, 0]);
  }
});

test('the Worker fetch boundary reaches ROUTER_API_RUNTIME for every pre-cutoff Yao route', async () => {
  for (const pathname of ALL_YAO_PATHS) {
    const runtime = new RecordingRuntimeNamespace();
    const response = await d1RouterApiStagingWorker.fetch(
      yaoRequest(pathname),
      createFetchBoundaryEnv(runtime, PRE_CUTOFF_WINDOW_ENV),
      FETCH_BOUNDARY_CONTEXT,
    );
    expect(await response.text(), `unexpected legacy response for ${pathname}`).toBe(
      'legacy-runtime',
    );
    expect(
      [runtime.idFromNameCalls, runtime.getCalls, runtime.fetchCalls],
      `missing tenant-runtime access for ${pathname}`,
    ).toEqual([1, 1, 1]);
  }
});

test('the drain blocks public and internal admissions', () => {
  const expected = [
    ['/wallets/register/start', 'registration_start', 'registration'],
    ['/wallets/wallet-1/signers/start', 'registration_add_signer_start', 'registration'],
    [
      ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
      'registration_admission',
      'registration',
    ],
    [ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1, 'recovery_admission', 'recovery'],
    [ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1, 'export_admission', 'export'],
  ] as const;
  for (const [pathname, operation, family] of expected) {
    expect(resolveYaoRoute(pathname, 1_500, ALL_FAMILIES_WINDOW)).toEqual({
      kind: 'admission_blocked',
      operation,
      family,
    });
  }
});

test('the drain keeps every continuation on the tenant runtime', () => {
  const paths = [
    '/wallets/register/finalize',
    '/wallets/wallet-1/signers/finalize',
    ...FULL_GATEWAY_RECOVERY_PATHS,
    ...DIRECT_CONTINUATION_PATHS,
  ];
  for (const pathname of paths) {
    expect(resolveYaoRoute(pathname, 1_500, ALL_FAMILIES_WINDOW).kind).toBe('legacy_runtime');
  }
});

test('post-drain public consumers use the full D1 Gateway and internal operations use family handlers', () => {
  for (const pathname of [...FULL_GATEWAY_REGISTRATION_PATHS, ...FULL_GATEWAY_RECOVERY_PATHS]) {
    expect(resolveYaoRoute(pathname, 2_000, ALL_FAMILIES_WINDOW).kind).toBe('partitioned_gateway');
  }
  for (const pathname of [
    ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
    ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
    ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1,
    ...DIRECT_CONTINUATION_PATHS,
  ]) {
    expect(resolveYaoRoute(pathname, 2_000, ALL_FAMILIES_WINDOW).kind).toBe(
      'partitioned_operation',
    );
  }
});

test('registration, recovery, and export follow independent schedules', () => {
  const cutover = {
    registration: { admissionCutoffMs: 1_000, drainUntilMs: 2_000 },
    recovery: { admissionCutoffMs: 4_000, drainUntilMs: 5_000 },
  } as const;

  expect(resolveYaoRoute('/wallets/register/finalize', 4_500, cutover).kind).toBe(
    'partitioned_gateway',
  );
  expect(resolveYaoRoute('/wallets/wallet-1/signers/start', 4_500, cutover).kind).toBe(
    'partitioned_gateway',
  );
  expect(
    resolveYaoRoute(ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1, 4_500, cutover).kind,
  ).toBe('admission_blocked');
  for (const pathname of FULL_GATEWAY_RECOVERY_PATHS) {
    expect(resolveYaoRoute(pathname, 4_500, cutover).kind).toBe('partitioned_gateway');
    expect(resolveYaoRoute(pathname, 5_000, cutover).kind).toBe('partitioned_gateway');
  }
  expect(resolveYaoRoute(ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1, 6_000, cutover).kind).toBe(
    'legacy_runtime',
  );
  expect(resolveYaoRoute('/session/exchange', 6_000, cutover).kind).toBe('legacy_runtime');
});

test('capability consumers follow registration into D1 while recovery remains unset', () => {
  const cutover = {
    registration: { admissionCutoffMs: 1_000, drainUntilMs: 2_000 },
  } as const;

  for (const pathname of FULL_GATEWAY_RECOVERY_PATHS) {
    expect(resolveYaoRoute(pathname, 2_000, cutover)).toEqual({
      kind: 'partitioned_gateway',
      operation:
        pathname === ROUTER_AB_ED25519_WALLET_SESSION_PATH
          ? 'recovery_wallet_session'
          : pathname === '/wallet/unlock/verify'
            ? 'recovery_unlock'
            : 'recovery_sync_account',
    });
  }
});
