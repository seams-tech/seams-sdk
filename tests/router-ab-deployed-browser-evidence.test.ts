import { expect, test, type Browser } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const PREPARE_PATH = '/v2/hss/sign/prepare';
const FINALIZE_PATH = '/v2/hss/sign';
const CORS_HEADER_NAMES = [
  'access-control-allow-origin',
  'access-control-allow-methods',
  'access-control-allow-headers',
  'access-control-allow-credentials',
  'access-control-max-age',
  'vary',
] as const;

type EvidenceBaseConfig = {
  baseUrl: string;
  allowedOrigin: string;
  rejectedOrigin: string;
  walletSessionJwt: string | null;
  evidenceOut: string | null;
};

type JsonFixtureConfig = EvidenceBaseConfig & {
  kind: 'json_fixtures';
  prepareBodyFile: string;
  finalizeBodyFile: string;
};

type FlowModuleConfig = EvidenceBaseConfig & {
  kind: 'flow_module';
  flowModulePath: string;
};

type EvidenceConfig = JsonFixtureConfig | FlowModuleConfig;

type EvidenceRequestInput = {
  body: unknown;
  walletSessionJwt: string | null;
};

type ObservedBrowserRequest = {
  method: string;
  url: string;
};

type ObservedBrowserResponse = {
  method: string;
  url: string;
  status: number;
  corsHeaders: Record<string, string>;
};

type BrowserPostEvidence =
  | {
      kind: 'response';
      status: number;
      ok: boolean;
      elapsedMs: number;
      corsHeaders: Record<string, string>;
      responseJson: unknown;
      responseText: string | null;
      observedRequests: readonly ObservedBrowserRequest[];
      observedResponses: readonly ObservedBrowserResponse[];
      preflightObserved: boolean;
    }
  | {
      kind: 'error';
      name: string;
      message: string;
      elapsedMs: number;
      observedRequests: readonly ObservedBrowserRequest[];
      observedResponses: readonly ObservedBrowserResponse[];
      preflightObserved: boolean;
    };

type PreflightEvidence = {
  origin: string;
  path: typeof PREPARE_PATH | typeof FINALIZE_PATH;
  status: number;
  elapsedMs: number;
  corsHeaders: Record<string, string>;
};

type FlowModule = {
  buildPrepareRequest(input: {
    baseUrl: string;
    allowedOrigin: string;
    rejectedOrigin: string;
    walletSessionJwt: string | null;
    nowMs: number;
  }): Promise<unknown> | unknown;
  buildFinalizeRequest(input: {
    baseUrl: string;
    allowedOrigin: string;
    rejectedOrigin: string;
    walletSessionJwt: string | null;
    nowMs: number;
    prepareRequest: unknown;
    prepareResponse: unknown;
  }): Promise<unknown> | unknown;
};

test.describe.configure({ mode: 'serial' });

test('strict Cloudflare Router normal-signing deployed browser evidence', async ({
  browser,
}, testInfo) => {
  const config = readEvidenceConfig(process.env);
  const evidence: Record<string, unknown> = {
    generatedAt: new Date().toISOString(),
    baseUrl: config.baseUrl,
    allowedOrigin: config.allowedOrigin,
    rejectedOrigin: config.rejectedOrigin,
  };

  const prepareInput = await buildPrepareInput(config);
  const prepareToken = resolveWalletSessionJwt(config, prepareInput, 'prepare');

  const preflight = {
    allowedPrepare: await runPreflight(config, config.allowedOrigin, PREPARE_PATH),
    rejectedPrepare: await runPreflight(config, config.rejectedOrigin, PREPARE_PATH),
    allowedFinalize: await runPreflight(config, config.allowedOrigin, FINALIZE_PATH),
    rejectedFinalize: await runPreflight(config, config.rejectedOrigin, FINALIZE_PATH),
  };
  evidence.preflight = preflight;
  expectAllowedPreflight(preflight.allowedPrepare, config.allowedOrigin, PREPARE_PATH);
  expectAllowedPreflight(preflight.allowedFinalize, config.allowedOrigin, FINALIZE_PATH);
  expectRejectedPreflight(preflight.rejectedPrepare, config.rejectedOrigin);
  expectRejectedPreflight(preflight.rejectedFinalize, config.rejectedOrigin);

  const rejectedPrepare = await runBrowserPost({
    browser,
    origin: config.rejectedOrigin,
    baseUrl: config.baseUrl,
    path: PREPARE_PATH,
    walletSessionJwt: prepareToken,
    body: prepareInput.body,
  });
  evidence.rejectedPrepare = rejectedPrepare;
  expectRejectedBrowserPost(rejectedPrepare);

  const allowedPrepare = await runBrowserPost({
    browser,
    origin: config.allowedOrigin,
    baseUrl: config.baseUrl,
    path: PREPARE_PATH,
    walletSessionJwt: prepareToken,
    body: prepareInput.body,
  });
  evidence.allowedPrepare = allowedPrepare;
  expectAllowedBrowserPost(allowedPrepare, config.allowedOrigin);

  const finalizeInput = await buildFinalizeInput(config, prepareInput, allowedPrepare.responseJson);
  const finalizeToken = resolveWalletSessionJwt(config, finalizeInput, 'finalize');

  const rejectedFinalize = await runBrowserPost({
    browser,
    origin: config.rejectedOrigin,
    baseUrl: config.baseUrl,
    path: FINALIZE_PATH,
    walletSessionJwt: finalizeToken,
    body: finalizeInput.body,
  });
  evidence.rejectedFinalize = rejectedFinalize;
  expectRejectedBrowserPost(rejectedFinalize);

  const allowedFinalize = await runBrowserPost({
    browser,
    origin: config.allowedOrigin,
    baseUrl: config.baseUrl,
    path: FINALIZE_PATH,
    walletSessionJwt: finalizeToken,
    body: finalizeInput.body,
  });
  evidence.allowedFinalize = allowedFinalize;
  expectAllowedBrowserPost(allowedFinalize, config.allowedOrigin);

  const evidencePath = config.evidenceOut ?? testInfo.outputPath('router-ab-deployed-browser-evidence.json');
  mkdirSync(path.dirname(evidencePath), { recursive: true });
  writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);
  console.log(`Router A/B deployed browser evidence written to ${evidencePath}`);
});

function readEvidenceConfig(env: NodeJS.ProcessEnv): EvidenceConfig {
  const base: EvidenceBaseConfig = {
    baseUrl: normalizeBaseUrl(readRequiredEnv(env, 'ROUTER_AB_DEPLOYED_BASE_URL')),
    allowedOrigin: normalizeOrigin(readRequiredEnv(env, 'ROUTER_AB_DEPLOYED_ALLOWED_ORIGIN')),
    rejectedOrigin: normalizeOrigin(readRequiredEnv(env, 'ROUTER_AB_DEPLOYED_REJECTED_ORIGIN')),
    walletSessionJwt: readOptionalEnv(env, 'ROUTER_AB_DEPLOYED_WALLET_SESSION_JWT'),
    evidenceOut: readOptionalEnv(env, 'ROUTER_AB_DEPLOYED_EVIDENCE_OUT'),
  };

  const flowModulePath = readOptionalEnv(env, 'ROUTER_AB_DEPLOYED_FLOW_MODULE');
  if (flowModulePath) {
    return { ...base, kind: 'flow_module', flowModulePath };
  }

  return {
    ...base,
    kind: 'json_fixtures',
    prepareBodyFile: readRequiredEnv(env, 'ROUTER_AB_DEPLOYED_PREPARE_BODY_FILE'),
    finalizeBodyFile: readRequiredEnv(env, 'ROUTER_AB_DEPLOYED_FINALIZE_BODY_FILE'),
  };
}

async function buildPrepareInput(config: EvidenceConfig): Promise<EvidenceRequestInput> {
  switch (config.kind) {
    case 'json_fixtures':
      return { body: readJsonFile(config.prepareBodyFile), walletSessionJwt: null };
    case 'flow_module': {
      const module = await loadFlowModule(config.flowModulePath);
      return normalizeEvidenceRequestInput(
        await module.buildPrepareRequest({
          baseUrl: config.baseUrl,
          allowedOrigin: config.allowedOrigin,
          rejectedOrigin: config.rejectedOrigin,
          walletSessionJwt: config.walletSessionJwt,
          nowMs: Date.now(),
        }),
        'prepare flow output',
      );
    }
  }
}

async function buildFinalizeInput(
  config: EvidenceConfig,
  prepareInput: EvidenceRequestInput,
  prepareResponse: unknown,
): Promise<EvidenceRequestInput> {
  switch (config.kind) {
    case 'json_fixtures':
      return { body: readJsonFile(config.finalizeBodyFile), walletSessionJwt: null };
    case 'flow_module': {
      const module = await loadFlowModule(config.flowModulePath);
      return normalizeEvidenceRequestInput(
        await module.buildFinalizeRequest({
          baseUrl: config.baseUrl,
          allowedOrigin: config.allowedOrigin,
          rejectedOrigin: config.rejectedOrigin,
          walletSessionJwt: config.walletSessionJwt,
          nowMs: Date.now(),
          prepareRequest: prepareInput.body,
          prepareResponse,
        }),
        'finalize flow output',
      );
    }
  }
}

async function loadFlowModule(modulePath: string): Promise<FlowModule> {
  const imported = await import(resolveModuleUrl(modulePath));
  const record = readRecord(imported, 'Router A/B deployed flow module');
  const buildPrepareRequest = record.buildPrepareRequest;
  const buildFinalizeRequest = record.buildFinalizeRequest;
  if (typeof buildPrepareRequest !== 'function') {
    throw new Error('ROUTER_AB_DEPLOYED_FLOW_MODULE must export buildPrepareRequest');
  }
  if (typeof buildFinalizeRequest !== 'function') {
    throw new Error('ROUTER_AB_DEPLOYED_FLOW_MODULE must export buildFinalizeRequest');
  }
  return {
    buildPrepareRequest: (input) => buildPrepareRequest(input),
    buildFinalizeRequest: (input) => buildFinalizeRequest(input),
  };
}

function normalizeEvidenceRequestInput(value: unknown, label: string): EvidenceRequestInput {
  const record = readRecord(value, label);
  return {
    body: record.body,
    walletSessionJwt:
      typeof record.walletSessionJwt === 'string' && record.walletSessionJwt.trim()
        ? record.walletSessionJwt.trim()
        : null,
  };
}

function resolveWalletSessionJwt(
  config: EvidenceConfig,
  input: EvidenceRequestInput,
  label: string,
): string {
  const token = input.walletSessionJwt ?? config.walletSessionJwt;
  if (!token) {
    throw new Error(
      `${label} requires ROUTER_AB_DEPLOYED_WALLET_SESSION_JWT or walletSessionJwt from the flow module`,
    );
  }
  return token;
}

async function runPreflight(
  config: EvidenceConfig,
  origin: string,
  routePath: typeof PREPARE_PATH | typeof FINALIZE_PATH,
): Promise<PreflightEvidence> {
  const started = performance.now();
  const response = await fetch(`${config.baseUrl}${routePath}`, {
    method: 'OPTIONS',
    headers: {
      Origin: origin,
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'authorization,content-type',
    },
  });
  return {
    origin,
    path: routePath,
    status: response.status,
    elapsedMs: performance.now() - started,
    corsHeaders: selectCorsHeaders(response.headers),
  };
}

async function runBrowserPost(args: {
  browser: Browser;
  origin: string;
  baseUrl: string;
  path: typeof PREPARE_PATH | typeof FINALIZE_PATH;
  walletSessionJwt: string;
  body: unknown;
}): Promise<BrowserPostEvidence> {
  const context = await args.browser.newContext({ ignoreHTTPSErrors: true });
  const pageUrl = syntheticEvidencePageUrl(args.origin);
  await context.route(pageUrl, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: '<!doctype html><meta charset="utf-8"><title>Router A/B evidence</title>',
    });
  });

  const page = await context.newPage();
  const observedRequests: ObservedBrowserRequest[] = [];
  const observedResponses: ObservedBrowserResponse[] = [];

  page.on('request', (request) => {
    if (!isRouterRequest(request.url(), args.baseUrl, args.path)) return;
    observedRequests.push({ method: request.method(), url: request.url() });
  });
  page.on('response', (response) => {
    const request = response.request();
    if (!isRouterRequest(request.url(), args.baseUrl, args.path)) return;
    observedResponses.push({
      method: request.method(),
      url: request.url(),
      status: response.status(),
      corsHeaders: selectHeaderRecord(response.headers()),
    });
  });

  await page.goto(pageUrl, { waitUntil: 'domcontentloaded' });
  const result = await page.evaluate(
    async ({ url, token, body }) => {
      const started = performance.now();
      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          credentials: 'omit',
          cache: 'no-store',
          body: JSON.stringify(body),
        });
        const responseText = await response.text();
        let responseJson: unknown = null;
        try {
          responseJson = responseText ? JSON.parse(responseText) : null;
        } catch {
          responseJson = null;
        }
        const headers: Record<string, string> = {};
        for (const [name, value] of response.headers.entries()) {
          headers[name.toLowerCase()] = value;
        }
        return {
          kind: 'response' as const,
          status: response.status,
          ok: response.ok,
          elapsedMs: performance.now() - started,
          corsHeaders: headers,
          responseJson,
          responseText: responseJson === null ? responseText.slice(0, 4096) : null,
        };
      } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error));
        return {
          kind: 'error' as const,
          name: err.name,
          message: err.message,
          elapsedMs: performance.now() - started,
        };
      }
    },
    {
      url: `${args.baseUrl}${args.path}`,
      token: args.walletSessionJwt,
      body: args.body,
    },
  );

  await context.close();

  return {
    ...result,
    observedRequests,
    observedResponses,
    preflightObserved: observedRequests.some((request) => request.method === 'OPTIONS'),
  };
}

function expectAllowedPreflight(
  evidence: PreflightEvidence,
  allowedOrigin: string,
  routePath: typeof PREPARE_PATH | typeof FINALIZE_PATH,
): void {
  expect(evidence.path).toBe(routePath);
  expect(evidence.status).toBe(204);
  expect(evidence.corsHeaders['access-control-allow-origin']).toBe(allowedOrigin);
  expect(evidence.corsHeaders['access-control-allow-credentials']).toBeUndefined();
  expectHeaderListIncludes(evidence.corsHeaders['access-control-allow-methods'], [
    'POST',
    'OPTIONS',
  ]);
  expectHeaderListIncludes(evidence.corsHeaders['access-control-allow-headers'], [
    'Authorization',
    'Content-Type',
  ]);
  expect(evidence.corsHeaders['access-control-max-age']).toBeTruthy();
}

function expectRejectedPreflight(evidence: PreflightEvidence, rejectedOrigin: string): void {
  expect(evidence.status).toBe(204);
  expect(evidence.corsHeaders['access-control-allow-origin']).not.toBe(rejectedOrigin);
  expect(evidence.corsHeaders['access-control-allow-credentials']).toBeUndefined();
}

function expectAllowedBrowserPost(
  evidence: BrowserPostEvidence,
  allowedOrigin: string,
): asserts evidence is Extract<BrowserPostEvidence, { kind: 'response' }> {
  expect(evidence.kind).toBe('response');
  if (evidence.kind !== 'response') throw new Error(evidence.message);
  expect(evidence.ok).toBe(true);
  expect(evidence.preflightObserved).toBe(true);
  expect(evidence.observedRequests.some((request) => request.method === 'POST')).toBe(true);
  const postResponse = evidence.observedResponses.find((response) => response.method === 'POST');
  expect(postResponse?.corsHeaders['access-control-allow-origin']).toBe(allowedOrigin);
  expect(postResponse?.corsHeaders['access-control-allow-credentials']).toBeUndefined();
}

function expectRejectedBrowserPost(
  evidence: BrowserPostEvidence,
): asserts evidence is Extract<BrowserPostEvidence, { kind: 'error' }> {
  expect(evidence.kind).toBe('error');
  expect(evidence.preflightObserved).toBe(true);
  expect(evidence.observedRequests.some((request) => request.method === 'POST')).toBe(false);
}

function expectHeaderListIncludes(value: string | undefined, expectedItems: readonly string[]): void {
  expect(value).toBeTruthy();
  const normalized = new Set(
    String(value || '')
      .split(',')
      .map((item) => item.trim().toLowerCase())
      .filter(Boolean),
  );
  for (const item of expectedItems) {
    expect(normalized.has(item.toLowerCase())).toBe(true);
  }
}

function selectCorsHeaders(headers: Headers): Record<string, string> {
  const selected: Record<string, string> = {};
  for (const name of CORS_HEADER_NAMES) {
    const value = headers.get(name);
    if (value !== null) selected[name] = value;
  }
  return selected;
}

function selectHeaderRecord(headers: Record<string, string>): Record<string, string> {
  const selected: Record<string, string> = {};
  for (const name of CORS_HEADER_NAMES) {
    const value = headers[name];
    if (value) selected[name] = value;
  }
  return selected;
}

function syntheticEvidencePageUrl(origin: string): string {
  const url = new URL('/__router_ab_deployed_evidence.html', origin);
  url.searchParams.set('t', `${Date.now()}`);
  return url.toString();
}

function isRouterRequest(
  value: string,
  baseUrl: string,
  routePath: typeof PREPARE_PATH | typeof FINALIZE_PATH,
): boolean {
  try {
    const url = new URL(value);
    return `${url.origin}${url.pathname}` === `${baseUrl}${routePath}`;
  } catch {
    return false;
  }
}

function readJsonFile(filePath: string): unknown {
  return JSON.parse(readFileSync(path.resolve(filePath), 'utf8'));
}

function readRecord(value: unknown, label: string): Record<string, unknown> {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  throw new Error(`${label} must be an object`);
}

function readRequiredEnv(env: NodeJS.ProcessEnv, name: string): string {
  const value = readOptionalEnv(env, name);
  if (!value) throw new Error(`${name} is required for deployed Router A/B browser evidence`);
  return value;
}

function readOptionalEnv(env: NodeJS.ProcessEnv, name: string): string | null {
  const value = env[name];
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  return normalized ? normalized : null;
}

function normalizeBaseUrl(value: string): string {
  const url = new URL(value);
  url.hash = '';
  url.search = '';
  return `${url.origin}${url.pathname.replace(/\/+$/, '')}`;
}

function normalizeOrigin(value: string): string {
  return new URL(value).origin;
}

function resolveModuleUrl(modulePath: string): string {
  if (modulePath.startsWith('file://')) return modulePath;
  return pathToFileURL(path.resolve(modulePath)).toString();
}
