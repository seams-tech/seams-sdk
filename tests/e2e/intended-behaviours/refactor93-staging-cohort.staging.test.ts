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
] as const;

type ObservedPath = (typeof OBSERVED_PATHS)[number];

test.afterAll(cleanStagingRuntimeArtifacts);

test('staging cohort configuration is pinned to the checked-in staging origins', () => {
  const parsed = parseRefactor93StagingConfig({ SEAMS_REF93_STAGING_MODE: 'check' });
  expect(parsed).toEqual({
    mode: 'check',
    origins: {
      gateway: 'https://seams-sdk-d1-gateway-staging.n6378056.workers.dev',
      site: 'https://staging.seams.sh',
      wallet: 'https://sign-staging.seams.sh',
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
    'staging registration redelivers exact terminal output for byte-identical replay',
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
  const replayCapture = new RegistrationExecuteReplayCapture();
  await context.route(
    `${REFACTOR93_STAGING_CONFIG.origins.gateway}${ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1}`,
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
      terminalResponseSha256: replay.terminalResponseSha256,
    });
  } finally {
    replayCapture.clear();
  }
}

class RegistrationExecuteReplayCapture {
  private replayRequest: ReplayRequest | null = null;

  private terminalResponseSha256: string | null = null;

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
    this.terminalResponseSha256 = sha256(responseBody);
    await route.fulfill({ response: upstream, body: responseBody });
  }

  assertSingleExecutionCapture(): void {
    expect(this.observedRequestDigests).toHaveLength(1);
  }

  async replayTerminalConcurrently(request: APIRequestContext): Promise<ReplayEvidence> {
    const replayRequest = this.replayRequest;
    const expectedResponseDigest = this.terminalResponseSha256;
    if (!replayRequest || !expectedResponseDigest) {
      throw new Error('Registration response-loss capture did not complete');
    }
    const responses = await Promise.all([
      sendReplayRequest(request, replayRequest),
      sendReplayRequest(request, replayRequest),
    ]);
    for (const response of responses) {
      expect(response.status).toBe(200);
      expect(response.bodySha256).toBe(expectedResponseDigest);
    }
    return {
      requestBodySha256: sha256(replayRequest.body),
      terminalResponseSha256: expectedResponseDigest,
    };
  }

  clear(): void {
    this.replayRequest = null;
    this.terminalResponseSha256 = null;
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
  authorization: string;
  contentType: string;
  traceId: string;
  body: string;
};

type ReplayEvidence = {
  requestBodySha256: string;
  terminalResponseSha256: string;
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
    authorization: requireHeader(headers, 'authorization'),
    contentType: requireHeader(headers, 'content-type'),
    traceId: requireHeader(headers, 'x-seams-trace-id'),
    body,
  };
}

async function sendReplayRequest(
  request: APIRequestContext,
  replay: ReplayRequest,
): Promise<{ status: number; bodySha256: string }> {
  const response = await request.fetch(replay.url, {
    method: 'POST',
    headers: {
      authorization: replay.authorization,
      'content-type': replay.contentType,
      'x-seams-trace-id': replay.traceId,
    },
    data: replay.body,
  });
  return { status: response.status(), bodySha256: sha256(await response.body()) };
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
  terminalResponseSha256: string;
}): void {
  process.stdout.write(
    `${JSON.stringify({ version: 'refactor93_staging_browser_cohort_v1', ...input })}\n`,
  );
}

function cleanStagingRuntimeArtifacts(): void {
  rmSync(REFACTOR93_STAGING_RUNTIME_PATHS.viteCache, { recursive: true, force: true });
}
