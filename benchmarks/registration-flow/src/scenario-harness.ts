import { expect, test, type ConsoleMessage, type Page } from '@playwright/test';
import { setupBasicPasskeyTest, handleInfrastructureErrors } from '../../../tests/setup';
import { DEFAULT_TEST_CONFIG } from '../../../tests/setup/config';
import { autoConfirmWalletIframeUntil } from '../../../tests/setup/flows';
import { installRelayServerProxyShim } from '../../../tests/setup/cross-origin-headers';
import {
  installCreateAccountAndRegisterUserMock,
  installFastNearRpcMock,
  makeAuthServiceForThreshold,
  setupManagedThresholdRegistrationHarness,
} from '../../../tests/e2e/thresholdEd25519.testUtils';

const SUMMARY_MARKER = '@@REGISTRATION_FLOW_SUMMARY@@';
const REGISTRATION_TIMING_LABEL = '[Registration] wallet timing summary';
const HSS_WORKER_DIAGNOSTICS_LABEL =
  '[threshold-ed25519][client-worker] hss command diagnostics';
const HSS_CLIENT_TIMING_PREFIX = '[threshold-ed25519][client] hss ';
const HSS_CLIENT_TIMING_NUMERIC_FIELDS = [
  'serializeMs',
  'fetchMs',
  'parseMs',
  'requestBytes',
  'responseBytes',
  'totalMs',
] as const;

type ScenarioId =
  | 'passkey_ed25519_only_wallet_iframe'
  | 'passkey_ed25519_and_ecdsa_wallet_iframe'
  | 'passkey_ed25519_only_host_origin'
  | 'passkey_ed25519_and_ecdsa_host_origin';

type SignerMode = 'ed25519_only' | 'ed25519_and_ecdsa';
type WalletIframeMode = 'host_origin' | 'wallet_iframe';

type BrowserConsoleCapture = {
  registrationSummaries: unknown[];
  hssWorkerDiagnostics: unknown[];
  hssClientTimings: unknown[];
};

type BenchmarkRunResult = {
  runIndex: number;
  ok: boolean;
  accountId: string;
  durationMs: number;
  registrationSummary: unknown | null;
  hssWorkerDiagnostics: unknown[];
  hssClientTimings: unknown[];
  error?: string;
};

function parseScenarioId(raw: string | undefined): ScenarioId {
  const scenarioId = String(raw || 'passkey_ed25519_only_wallet_iframe').trim();
  switch (scenarioId) {
    case 'passkey_ed25519_only_wallet_iframe':
    case 'passkey_ed25519_and_ecdsa_wallet_iframe':
    case 'passkey_ed25519_only_host_origin':
    case 'passkey_ed25519_and_ecdsa_host_origin':
      return scenarioId;
  }
  throw new Error(`Unknown registration benchmark scenario: ${scenarioId}`);
}

function signerModeForScenario(scenarioId: ScenarioId): SignerMode {
  return scenarioId.includes('ed25519_and_ecdsa') ? 'ed25519_and_ecdsa' : 'ed25519_only';
}

function walletIframeModeForScenario(scenarioId: ScenarioId): WalletIframeMode {
  return scenarioId.endsWith('wallet_iframe') ? 'wallet_iframe' : 'host_origin';
}

function readRuns(): number {
  const parsed = Number(String(process.env.BENCH_REGISTRATION_RUNS || '5').trim());
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : 5;
}

function summarizeNumbers(values: number[]) {
  const sorted = values.filter((value) => Number.isFinite(value)).sort((a, b) => a - b);
  if (!sorted.length) {
    return {
      count: 0,
      min: null,
      mean: null,
      p50: null,
      p95: null,
      p99: null,
      max: null,
    };
  }
  const percentile = (p: number): number => {
    const index = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
    return sorted[Math.max(0, index)]!;
  };
  const total = sorted.reduce((acc, value) => acc + value, 0);
  return {
    count: sorted.length,
    min: sorted[0]!,
    mean: total / sorted.length,
    p50: percentile(50),
    p95: percentile(95),
    p99: percentile(99),
    max: sorted[sorted.length - 1]!,
  };
}

function numericField(record: unknown, key: string): number | null {
  if (!record || typeof record !== 'object' || Array.isArray(record)) return null;
  const value = (record as Record<string, unknown>)[key];
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function sanitizeNumberRecord(record: unknown): Record<string, number> {
  if (!record || typeof record !== 'object' || Array.isArray(record)) return {};
  const out: Record<string, number> = {};
  for (const [key, value] of Object.entries(record)) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) out[key] = parsed;
  }
  return out;
}

function sanitizeHssClientTimingPayload(payload: unknown): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of HSS_CLIENT_TIMING_NUMERIC_FIELDS) {
    const value = numericField(payload, key);
    if (value !== null) out[key] = value;
  }
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
    const requestSizeBreakdown = sanitizeNumberRecord(
      (payload as { requestSizeBreakdown?: unknown }).requestSizeBreakdown,
    );
    if (Object.keys(requestSizeBreakdown).length) out.requestSizeBreakdown = requestSizeBreakdown;
    const responseSizeBreakdown = sanitizeNumberRecord(
      (payload as { responseSizeBreakdown?: unknown }).responseSizeBreakdown,
    );
    if (Object.keys(responseSizeBreakdown).length) {
      out.responseSizeBreakdown = responseSizeBreakdown;
    }
  }
  return out;
}

function collectTimingStats(runs: BenchmarkRunResult[]) {
  const valuesByBucket = new Map<string, number[]>();
  for (const run of runs) {
    if (run.ok) {
      valuesByBucket.set('totalMs', [...(valuesByBucket.get('totalMs') || []), run.durationMs]);
      valuesByBucket.set('browserRunDurationMs', [
        ...(valuesByBucket.get('browserRunDurationMs') || []),
        run.durationMs,
      ]);
    }
    const summary = run.registrationSummary;
    if (!summary || typeof summary !== 'object' || Array.isArray(summary)) continue;
    const totalMs = numericField(summary, 'totalMs');
    if (totalMs !== null) {
      valuesByBucket.set('sdkTotalMs', [...(valuesByBucket.get('sdkTotalMs') || []), totalMs]);
    }
    const timings = (summary as { timings?: unknown }).timings;
    if (!timings || typeof timings !== 'object' || Array.isArray(timings)) continue;
    for (const [key, value] of Object.entries(timings)) {
      if (typeof value !== 'number' || !Number.isFinite(value)) continue;
      valuesByBucket.set(key, [...(valuesByBucket.get(key) || []), value]);
    }
  }
  const out: Record<string, ReturnType<typeof summarizeNumbers>> = {};
  for (const [key, values] of valuesByBucket.entries()) {
    out[key] = summarizeNumbers(values);
  }
  return out;
}

function collectRelayRouteStats(runs: BenchmarkRunResult[]) {
  const grouped = new Map<string, Map<string, number[]>>();
  for (const run of runs) {
    const summary = run.registrationSummary;
    if (!summary || typeof summary !== 'object' || Array.isArray(summary)) continue;
    const relayDiagnostics = (summary as { relayDiagnostics?: unknown }).relayDiagnostics;
    if (!Array.isArray(relayDiagnostics)) continue;
    for (const diagnostic of relayDiagnostics) {
      if (!diagnostic || typeof diagnostic !== 'object' || Array.isArray(diagnostic)) continue;
      const route = String((diagnostic as { route?: unknown }).route || '').trim();
      const entries = (diagnostic as { entries?: unknown }).entries;
      if (!route || !Array.isArray(entries)) continue;
      const routeBucket = grouped.get(route) || new Map<string, number[]>();
      for (const entry of entries) {
        if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
        const name = String((entry as { name?: unknown }).name || '').trim();
        const durationMs = numericField(entry, 'durationMs');
        if (!name || durationMs === null) continue;
        routeBucket.set(name, [...(routeBucket.get(name) || []), durationMs]);
      }
      grouped.set(route, routeBucket);
    }
  }
  const out: Record<string, Record<string, ReturnType<typeof summarizeNumbers>>> = {};
  for (const [route, routeBucket] of grouped.entries()) {
    out[route] = {};
    for (const [name, values] of routeBucket.entries()) {
      out[route]![name] = summarizeNumbers(values);
    }
  }
  return out;
}

function collectHssWorkerStats(runs: BenchmarkRunResult[]) {
  const grouped = new Map<
    string,
    {
      totalMs: number[];
      wasmCallMs: number[];
      queueWaitMs: number[];
      wasmInitWaitMs: number[];
      requestPayloadBytes: number[];
      responsePayloadBytes: number[];
      wasmOperationTimings: Map<string, number[]>;
    }
  >();
  for (const run of runs) {
    for (const entry of run.hssWorkerDiagnostics) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
      const operation = String((entry as { operation?: unknown }).operation || '').trim();
      const diagnostics = (entry as { diagnostics?: unknown }).diagnostics;
      if (!operation || !diagnostics || typeof diagnostics !== 'object') continue;
      const bucket =
        grouped.get(operation) ||
        {
          totalMs: [],
          wasmCallMs: [],
          queueWaitMs: [],
          wasmInitWaitMs: [],
          requestPayloadBytes: [],
          responsePayloadBytes: [],
          wasmOperationTimings: new Map<string, number[]>(),
        };
      const numericBucketKeys = [
        'totalMs',
        'wasmCallMs',
        'queueWaitMs',
        'wasmInitWaitMs',
        'requestPayloadBytes',
        'responsePayloadBytes',
      ] as const;
      for (const key of numericBucketKeys) {
        const value = numericField(diagnostics, key);
        if (value !== null) bucket[key].push(value);
      }
      const wasmOperationTimings = sanitizeNumberRecord(
        (diagnostics as { wasmOperationTimings?: unknown }).wasmOperationTimings,
      );
      for (const [key, value] of Object.entries(wasmOperationTimings)) {
        bucket.wasmOperationTimings.set(key, [
          ...(bucket.wasmOperationTimings.get(key) || []),
          value,
        ]);
      }
      grouped.set(operation, bucket);
    }
  }
  const out: Record<string, Record<string, ReturnType<typeof summarizeNumbers>>> = {};
  for (const [operation, values] of grouped.entries()) {
    out[operation] = {
      totalMs: summarizeNumbers(values.totalMs),
      wasmCallMs: summarizeNumbers(values.wasmCallMs),
      queueWaitMs: summarizeNumbers(values.queueWaitMs),
      wasmInitWaitMs: summarizeNumbers(values.wasmInitWaitMs),
      requestPayloadBytes: summarizeNumbers(values.requestPayloadBytes),
      responsePayloadBytes: summarizeNumbers(values.responsePayloadBytes),
    };
    for (const [key, timings] of values.wasmOperationTimings.entries()) {
      out[operation]![`wasm.${key}`] = summarizeNumbers(timings);
    }
  }
  return out;
}

function collectHssClientStats(runs: BenchmarkRunResult[]) {
  const grouped = new Map<
    string,
    {
      totalMs: number[];
      serializeMs: number[];
      fetchMs: number[];
      parseMs: number[];
      requestBytes: number[];
      responseBytes: number[];
    }
  >();
  for (const run of runs) {
    for (const entry of run.hssClientTimings) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
      const label = String((entry as { label?: unknown }).label || '').trim();
      const operation = label
        .replace(HSS_CLIENT_TIMING_PREFIX, '')
        .replace(/\s+timings$/, '')
        .trim();
      const payload = (entry as { payload?: unknown }).payload;
      if (!operation || !payload || typeof payload !== 'object' || Array.isArray(payload)) {
        continue;
      }
      const bucket =
        grouped.get(operation) ||
        {
          totalMs: [],
          serializeMs: [],
          fetchMs: [],
          parseMs: [],
          requestBytes: [],
          responseBytes: [],
        };
      for (const key of Object.keys(bucket) as Array<keyof typeof bucket>) {
        const value = numericField(payload, key);
        if (value !== null) bucket[key].push(value);
      }
      grouped.set(operation, bucket);
    }
  }
  const out: Record<string, Record<string, ReturnType<typeof summarizeNumbers>>> = {};
  for (const [operation, values] of grouped.entries()) {
    out[operation] = {
      totalMs: summarizeNumbers(values.totalMs),
      serializeMs: summarizeNumbers(values.serializeMs),
      fetchMs: summarizeNumbers(values.fetchMs),
      parseMs: summarizeNumbers(values.parseMs),
      requestBytes: summarizeNumbers(values.requestBytes),
      responseBytes: summarizeNumbers(values.responseBytes),
    };
  }
  return out;
}

async function consoleArgs(message: ConsoleMessage): Promise<unknown[]> {
  const values: unknown[] = [];
  for (const arg of message.args()) {
    try {
      values.push(await arg.jsonValue());
    } catch {
      values.push(String(message.text() || ''));
    }
  }
  return values.length ? values : [message.text()];
}

function installBenchmarkConsoleCapture(page: Page): BrowserConsoleCapture {
  const capture: BrowserConsoleCapture = {
    registrationSummaries: [],
    hssWorkerDiagnostics: [],
    hssClientTimings: [],
  };

  page.on('console', (message) => {
    void (async () => {
      const args = await consoleArgs(message);
      const label = String(args[0] || '').trim();
      if (label === REGISTRATION_TIMING_LABEL) {
        capture.registrationSummaries.push(args[1] ?? null);
        return;
      }
      if (label === HSS_WORKER_DIAGNOSTICS_LABEL) {
        capture.hssWorkerDiagnostics.push(args[1] ?? null);
        return;
      }
      if (label.startsWith(HSS_CLIENT_TIMING_PREFIX)) {
        capture.hssClientTimings.push({
          label,
          payload: sanitizeHssClientTimingPayload(args[1] ?? null),
        });
      }
    })().catch(() => undefined);
  });

  return capture;
}

function consumeNewEntries<T>(entries: T[], cursor: { index: number }): T[] {
  const out = entries.slice(cursor.index);
  cursor.index = entries.length;
  return out;
}

function accountIdForRun(runIndex: number): string {
  const suffix = `${Date.now()}-${runIndex}-${Math.random().toString(16).slice(2, 10)}`;
  return `bench${runIndex}-${suffix}.w3a-v1.testnet`;
}

function registrationOptionsForSignerMode(signerMode: SignerMode) {
  const confirmationConfig = {
    uiMode: 'none',
    behavior: 'skipClick',
    autoProceedDelay: 0,
  } as const;
  if (signerMode === 'ed25519_only') {
    return {
      confirmationConfig,
      signerOptions: {
        tempo: {
          enabled: false,
          participantIds: [1, 2],
          signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
        },
        evm: {
          enabled: false,
          participantIds: [1, 2],
          signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
        },
      },
    };
  }
  return { confirmationConfig };
}

test.describe('registration flow benchmark scenario', () => {
  test.setTimeout(300_000);

  test('captures registration timing and HSS worker diagnostics', async ({ page }) => {
    const scenarioId = parseScenarioId(process.env.BENCH_REGISTRATION_SCENARIO);
    const signerMode = signerModeForScenario(scenarioId);
    const walletIframeMode = walletIframeModeForScenario(scenarioId);
    const runsRequested = readRuns();
    await page.addInitScript(() => {
      (globalThis as { __SEAMS_REGISTRATION_BENCHMARK_DIAGNOSTICS?: boolean })
        .__SEAMS_REGISTRATION_BENCHMARK_DIAGNOSTICS = true;
    });
    const capture = installBenchmarkConsoleCapture(page);

    await setupBasicPasskeyTest(page);
    await page.waitForTimeout(300);

    const keysOnChain = new Set<string>();
    const nonceByPublicKey = new Map<string, number>();
    const accountsOnChain = new Set<string>();
    const { service, threshold } = makeAuthServiceForThreshold(keysOnChain);
    const managedRegistrationHarness = await setupManagedThresholdRegistrationHarness({
      page,
      service,
      threshold,
      keyName: `benchmark-registration-${scenarioId}`,
      orgId: `org_benchmark_${scenarioId}`,
      orgSlug: `benchmark-${scenarioId}`,
      orgName: `Benchmark ${scenarioId}`,
      projectId: `proj_benchmark_${scenarioId}`,
      projectName: `Benchmark ${scenarioId}`,
    });

    const relayerUrl =
      walletIframeMode === 'wallet_iframe'
        ? (DEFAULT_TEST_CONFIG.relayer?.url ?? 'https://relay-server.localhost')
        : managedRegistrationHarness.baseUrl;

    try {
      if (walletIframeMode === 'wallet_iframe') {
        await installRelayServerProxyShim(page, {
          relayOrigin: relayerUrl,
          relayUpstream: managedRegistrationHarness.baseUrl,
          logStyle: 'silent',
        });
      }

      await installCreateAccountAndRegisterUserMock(page, {
        relayerBaseUrl: relayerUrl,
        keysOnChain,
        nonceByPublicKey,
        accountsOnChain,
        session: managedRegistrationHarness.session,
        runtimePolicyScope: managedRegistrationHarness.runtimePolicyScope,
        threshold,
        onNewPublicKey: (publicKey) => {
          keysOnChain.add(publicKey);
          nonceByPublicKey.set(publicKey, nonceByPublicKey.get(publicKey) ?? 0);
        },
        onNewAccountId: (accountId) => {
          accountsOnChain.add(accountId);
        },
      });

      await installFastNearRpcMock(page, {
        keysOnChain,
        nonceByPublicKey,
        accountsOnChain,
        strictAccessKeyLookup: true,
      });

      const summaryCursor = { index: 0 };
      const hssWorkerCursor = { index: 0 };
      const hssClientCursor = { index: 0 };
      const runs: BenchmarkRunResult[] = [];

      for (let runIndex = 1; runIndex <= runsRequested; runIndex += 1) {
        const accountId = accountIdForRun(runIndex);
        const registrationOptions = registrationOptionsForSignerMode(signerMode);
        const startedAt = performance.now();
        const resultPromise = page.evaluate(
          async ({
            accountId: browserAccountId,
            relayerUrl: browserRelayerUrl,
            signerMode: browserSignerMode,
            walletIframeMode: browserWalletIframeMode,
            registrationOptions: browserRegistrationOptions,
          }) => {
            try {
              const { SeamsWeb } = await import('/sdk/esm/SeamsWeb/index.js');
              const managedRegistration = (globalThis as any).__w3aManagedRegistration || null;
              const seams = new SeamsWeb({
                nearNetwork: 'testnet',
                nearRpcUrl: 'https://test.rpc.fastnear.com',
                relayer: { url: browserRelayerUrl },
                ...(managedRegistration
                  ? {
                      registration: {
                        mode: 'managed' as const,
                        environmentId: String(managedRegistration.environmentId || ''),
                        publishableKey: String(managedRegistration.publishableKey || ''),
                      },
                    }
                  : {}),
                iframeWallet:
                  browserWalletIframeMode === 'wallet_iframe'
                    ? {
                        walletOrigin: 'https://wallet.example.localhost',
                        servicePath: '/wallet-service',
                        sdkBasePath: '/sdk',
                        rpIdOverride: 'example.localhost',
                      }
                    : { walletOrigin: '' },
              });
              const registration = await seams.registration.registerPasskey(
                browserAccountId,
                browserRegistrationOptions as any,
              );
              if (!registration?.success) {
                return {
                  ok: false as const,
                  error: String(
                    registration?.error ||
                      `registration failed for signer mode ${browserSignerMode}`,
                  ),
                };
              }
              return { ok: true as const };
            } catch (error: any) {
              return { ok: false as const, error: String(error?.message || error) };
            }
          },
          {
            accountId,
            relayerUrl,
            signerMode,
            walletIframeMode,
            registrationOptions,
          },
        );
        const result = await autoConfirmWalletIframeUntil(page, resultPromise, {
          timeoutMs: 120_000,
          intervalMs: 250,
        });
        await page.waitForTimeout(250);
        const durationMs = Math.max(0, Math.round(performance.now() - startedAt));
        const registrationSummaries = consumeNewEntries(capture.registrationSummaries, summaryCursor);
        const hssWorkerDiagnostics = consumeNewEntries(
          capture.hssWorkerDiagnostics,
          hssWorkerCursor,
        );
        const hssClientTimings = consumeNewEntries(capture.hssClientTimings, hssClientCursor);

        runs.push({
          runIndex,
          ok: !!result.ok,
          accountId,
          durationMs,
          registrationSummary: registrationSummaries.at(-1) ?? null,
          hssWorkerDiagnostics,
          hssClientTimings,
          ...(!result.ok ? { error: String(result.error || 'registration failed') } : {}),
        });
      }

      const failed = runs.find((run) => !run.ok);
      if (failed && handleInfrastructureErrors({ success: false, error: failed.error || '' })) {
        return;
      }

      const successfulRuns = runs.filter((run) => run.ok).length;
      const summary = {
        reportVersion: 'registration_flow_scenario_v1',
        scenarioId,
        signerMode,
        walletIframeMode,
        runsRequested,
        successfulRuns,
        failedRuns: runsRequested - successfulRuns,
        hssWorkerDiagnosticsCount: runs.reduce(
          (acc, run) => acc + run.hssWorkerDiagnostics.length,
          0,
        ),
        hssClientTimingCount: runs.reduce((acc, run) => acc + run.hssClientTimings.length, 0),
        relayDiagnosticsCount: runs.reduce((acc, run) => {
          const summary = run.registrationSummary;
          if (!summary || typeof summary !== 'object' || Array.isArray(summary)) return acc;
          const relayDiagnostics = (summary as { relayDiagnostics?: unknown }).relayDiagnostics;
          return acc + (Array.isArray(relayDiagnostics) ? relayDiagnostics.length : 0);
        }, 0),
        timingStats: collectTimingStats(runs),
        relayStatsByRoute: collectRelayRouteStats(runs),
        hssWorkerStatsByOperation: collectHssWorkerStats(runs),
        hssClientStatsByOperation: collectHssClientStats(runs),
        runs,
      };

      console.log(`${SUMMARY_MARKER}${JSON.stringify(summary)}`);
      expect(failed, failed?.error || 'registration benchmark run failed').toBeUndefined();
      expect(successfulRuns).toBe(runsRequested);
      expect(summary.timingStats.totalMs?.count || 0).toBe(runsRequested);
    } finally {
      await managedRegistrationHarness.close().catch(() => undefined);
    }
  });
});
