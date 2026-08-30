import { createHash } from 'node:crypto';
import { rmSync } from 'node:fs';
import {
  expect,
  test,
  type APIRequestContext,
  type BrowserContext,
  type Page,
  type Route,
} from '@playwright/test';
import {
  ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  parseRegistrationEstablishedSessionResultV2,
  type RegistrationEstablishedSessionProjectionV2,
} from '@shared/utils/registrationEstablishedSession';
import { projectRegistrationEstablishedSessionV2 } from '../../../packages/wallet-server/src/router/cloudflare/d1/registration/walletRegistrationSessionCommitReceipt';
import {
  parseRefactor93StagingConfig,
  REFACTOR93_STAGING_CONFIG,
  REFACTOR93_STAGING_RUNTIME_PATHS,
} from '../../playwright.refactor93-staging.config';
import { IntendedBehaviourHarness } from './harness';

const OBSERVED_PATHS = [
  ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1,
  '/wallets/register/near-provisioning',
] as const;

type ObservedPath = (typeof OBSERVED_PATHS)[number];

test.afterAll(cleanStagingRuntimeArtifacts);

test('staging cohort configuration is pinned to the checked-in staging origins', () => {
  const parsed = parseRefactor93StagingConfig({ SEAMS_REF93_STAGING_MODE: 'check' });
  expect(parsed).toEqual({
    mode: 'check',
    origins: {
      gateway: 'https://staging.api.seams.sh',
      site: 'https://staging.seams.sh',
      wallet: 'https://staging.sign.seams.sh',
    },
    localSiteOrigin: 'http://127.0.0.1:37994',
  });
});

test('staging cohort rejects private Router service-auth material', () => {
  expect(() =>
    parseRefactor93StagingConfig({
      SEAMS_REF93_STAGING_MODE: 'check',
      ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: 'must-not-enter-browser-tooling',
    }),
  ).toThrow(/refuses private Router service-auth material/u);
});

test('live staging cohort requires a frozen full commit SHA', () => {
  expect(() =>
    parseRefactor93StagingConfig({
      SEAMS_REF93_STAGING_MODE: 'live',
      SEAMS_REF93_EXPECTED_SHA: 'not-a-commit',
    }),
  ).toThrow(/full 40-character commit SHA/u);
});

if (REFACTOR93_STAGING_CONFIG.mode === 'live') {
  // Narrowing the imported union does not survive into the test callbacks below.
  const liveConfig = REFACTOR93_STAGING_CONFIG;
  test('live staging cohort binds the intended harness to staging', () => {
    expect(process.env.SEAMS_INTENDED_APP_URL).toBe(liveConfig.origins.site);
    expect(process.env.SEAMS_INTENDED_ROUTER_URL).toBe(liveConfig.origins.gateway);
    expect(process.env.SEAMS_INTENDED_WALLET_ORIGIN).toBe(liveConfig.origins.wallet);
    expect(process.env.SEAMS_INTENDED_PROJECT_ENVIRONMENT_ID).toBe(liveConfig.projectEnvironmentId);
    expect(process.env.SEAMS_INTENDED_PUBLISHABLE_KEY).toBe(liveConfig.publishableKey);
  });
  test(
    'staging registration replay returns the same credential-free committed identity',
    runLiveStagingCohort,
  );
}

async function runLiveStagingCohort({ context, page, request }: LiveTestFixtures): Promise<void> {
  if (REFACTOR93_STAGING_CONFIG.mode !== 'live') {
    throw new Error('Live staging cohort was registered outside live mode');
  }
  await context.route(
    `${REFACTOR93_STAGING_CONFIG.origins.site}/**`,
    proxyLocalSiteRequest.bind(null, REFACTOR93_STAGING_CONFIG.localSiteOrigin),
  );
  const pathCounter = new OperationPathCounter(REFACTOR93_STAGING_CONFIG.origins.gateway);
  context.on('request', pathCounter.observe.bind(pathCounter));
  const replayCapture = new RegistrationTerminalReplayCapture();
  await context.route(
    `${REFACTOR93_STAGING_CONFIG.origins.gateway}/wallets/register/near-provisioning`,
    replayCapture.handle.bind(replayCapture),
  );

  const harness = new IntendedBehaviourHarness({
    context,
    flow: 'passkey.registration',
    networkMode: 'external_staging',
    page,
    request,
  });
  try {
    await harness.initialize();
    await harness.registerPasskeyEd25519YaoWallet();
    replayCapture.assertSingleExecutionCapture();
    const replay = await replayCapture.replayTerminalConcurrently(request);
    await harness.exportEd25519Key();
    pathCounter.assertRequiredPaths();
    harness.assertNoLifecycleViolations();
    harness.assertNoWrongAuthPath();
    printSafeEvidence({
      expectedSha: REFACTOR93_STAGING_CONFIG.expectedSha,
      pathCounts: pathCounter.snapshot(),
      requestBodySha256: replay.requestBodySha256,
      committedProjectionSha256: replay.committedProjectionSha256,
    });
  } finally {
    replayCapture.clear();
  }
}

class RegistrationTerminalReplayCapture {
  private replayRequest: ReplayRequest | null = null;

  private issuedProjection: RegistrationEstablishedSessionProjectionV2 | null = null;

  private readonly observedRequestDigests: string[] = [];

  async handle(route: Route): Promise<void> {
    const request = route.request();
    const body = request.postData();
    if (!body) throw new Error('Registration execute request body is missing');
    this.observedRequestDigests.push(sha256(body));
    if (this.replayRequest) {
      await route.continue();
      return;
    }
    this.replayRequest = captureReplayRequest(request.url(), request.headers(), body);
    const upstream = await route.fetch();
    const responseBody = await upstream.body();
    if (!upstream.ok()) {
      throw new Error(
        `Staging registration execute returned HTTP ${upstream.status()}: ${safeFailureSummary(responseBody)}`,
      );
    }
    this.issuedProjection = requireIssuedRegistrationProjection(responseBody);
    await route.fulfill({ response: upstream, body: responseBody });
  }

  assertSingleExecutionCapture(): void {
    expect(this.observedRequestDigests).toHaveLength(1);
  }

  async replayTerminalConcurrently(request: APIRequestContext): Promise<ReplayEvidence> {
    const replayRequest = this.replayRequest;
    const issuedProjection = this.issuedProjection;
    if (!replayRequest || !issuedProjection) {
      throw new Error('Registration response-loss capture did not complete');
    }
    const responses = await Promise.all([
      sendReplayRequest(request, replayRequest),
      sendReplayRequest(request, replayRequest),
    ]);
    const committedProjectionDigests: string[] = [];
    for (const response of responses) {
      expect(response.status).toBe(200);
      const committedProjection = requireCommittedRegistrationProjection(response.body);
      expect(committedProjection).toEqual(issuedProjection);
      committedProjectionDigests.push(sha256(JSON.stringify(committedProjection)));
    }
    expect(new Set(committedProjectionDigests).size).toBe(1);
    return {
      requestBodySha256: sha256(replayRequest.body),
      committedProjectionSha256: committedProjectionDigests[0]!,
    };
  }

  clear(): void {
    this.replayRequest = null;
    this.issuedProjection = null;
    this.observedRequestDigests.length = 0;
  }
}

class OperationPathCounter {
  private readonly counts = new Map<ObservedPath, number>();

  constructor(private readonly gatewayOrigin: string) {}

  observe(request: { url(): string }): void {
    const url = new URL(request.url());
    if (url.origin !== this.gatewayOrigin || !isObservedPath(url.pathname)) return;
    this.counts.set(url.pathname, (this.counts.get(url.pathname) || 0) + 1);
  }

  assertRequiredPaths(): void {
    for (const path of OBSERVED_PATHS) {
      expect(this.counts.get(path) || 0).toBeGreaterThan(0);
    }
  }

  snapshot(): Record<ObservedPath, number> {
    return Object.fromEntries(
      OBSERVED_PATHS.map((path) => [path, this.counts.get(path) || 0]),
    ) as Record<ObservedPath, number>;
  }
}

type ReplayRequest = {
  url: string;
  contentType: string;
  traceId: string | null;
  body: string;
};

type ReplayEvidence = {
  requestBodySha256: string;
  committedProjectionSha256: string;
};

type LiveTestFixtures = {
  context: BrowserContext;
  page: Page;
  request: APIRequestContext;
};

function captureReplayRequest(
  url: string,
  headers: Record<string, string>,
  body: string,
): ReplayRequest {
  return {
    url,
    contentType: requireHeader(headers, 'content-type'),
    traceId: optionalHeader(headers, 'x-seams-trace-id'),
    body,
  };
}

async function sendReplayRequest(
  request: APIRequestContext,
  replay: ReplayRequest,
): Promise<{ status: number; body: Buffer }> {
  const response = await request.fetch(replay.url, {
    method: 'POST',
    headers: {
      'content-type': replay.contentType,
      ...(replay.traceId ? { 'x-seams-trace-id': replay.traceId } : {}),
    },
    data: replay.body,
  });
  return { status: response.status(), body: await response.body() };
}

function requireIssuedRegistrationProjection(
  body: Buffer,
): RegistrationEstablishedSessionProjectionV2 {
  const result = parseRegistrationEstablishedSessionResultV2(
    requireRegistrationEstablishedSession(body),
  );
  if (result?.kind !== 'issued') {
    throw new Error('Initial registration terminal did not issue an exact Wallet Session');
  }
  return projectRegistrationEstablishedSessionV2(result.session);
}

function requireCommittedRegistrationProjection(
  body: Buffer,
): RegistrationEstablishedSessionProjectionV2 {
  const result = parseRegistrationEstablishedSessionResultV2(
    requireRegistrationEstablishedSession(body),
  );
  if (result?.kind !== 'already_committed' || result.next !== 'unlock_exact_method') {
    throw new Error('Registration retry did not return an exact-method committed projection');
  }
  return result.session;
}

function requireRegistrationEstablishedSession(body: Buffer): unknown {
  const parsed: unknown = JSON.parse(body.toString('utf8'));
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    !Object.prototype.hasOwnProperty.call(parsed, 'registrationEstablishedSession')
  ) {
    throw new Error('Registration terminal response is missing its session result');
  }
  return (parsed as { readonly registrationEstablishedSession: unknown })
    .registrationEstablishedSession;
}

async function proxyLocalSiteRequest(localSiteOrigin: string, route: Route): Promise<void> {
  const request = route.request();
  if (request.method() !== 'GET' && request.method() !== 'HEAD') {
    await route.abort('blockedbyclient');
    return;
  }
  const requestedUrl = new URL(request.url());
  const localUrl = new URL(`${requestedUrl.pathname}${requestedUrl.search}`, localSiteOrigin);
  const response = await fetch(localUrl);
  const headers = safeProxyHeaders(response.headers);
  const body = request.method() === 'HEAD' ? undefined : Buffer.from(await response.arrayBuffer());
  await route.fulfill({ status: response.status, headers, body });
}

function safeProxyHeaders(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [name, value] of headers.entries()) {
    if (name === 'content-length' || name === 'content-encoding' || name === 'transfer-encoding') {
      continue;
    }
    result[name] = value;
  }
  result['cache-control'] = 'no-store';
  return result;
}

function requireHeader(headers: Record<string, string>, name: string): string {
  const value = String(headers[name] || '').trim();
  if (value) return value;
  throw new Error(`Captured staging request is missing ${name}`);
}

function optionalHeader(headers: Record<string, string>, name: string): string | null {
  const value = String(headers[name] || '').trim();
  return value || null;
}

function isObservedPath(value: string): value is ObservedPath {
  return (OBSERVED_PATHS as readonly string[]).includes(value);
}

function sha256(value: string | Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

function safeFailureSummary(body: Buffer): string {
  try {
    const parsed = JSON.parse(body.toString('utf8')) as unknown;
    if (!isRecord(parsed)) return 'non-object JSON error';
    return JSON.stringify({
      code: String(parsed.code || ''),
      message: String(parsed.message || ''),
    });
  } catch {
    return 'non-JSON error body';
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function printSafeEvidence(input: {
  expectedSha: string;
  pathCounts: Record<ObservedPath, number>;
  requestBodySha256: string;
  committedProjectionSha256: string;
}): void {
  process.stdout.write(
    `${JSON.stringify({ version: 'refactor93_staging_browser_cohort_v1', ...input })}\n`,
  );
}

function cleanStagingRuntimeArtifacts(): void {
  rmSync(REFACTOR93_STAGING_RUNTIME_PATHS.viteCache, { recursive: true, force: true });
}
