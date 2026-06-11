import { expect, test, type ConsoleMessage, type Page } from '@playwright/test';
import { setupBasicPasskeyTest, handleInfrastructureErrors } from '../../../tests/setup';
import { DEFAULT_TEST_CONFIG } from '../../../tests/setup/config';
import {
  autoConfirmWalletIframeUntil,
  type WalletIframeAutoConfirmDiagnostics,
} from '../../../tests/setup/flows';
import { installRelayServerProxyShim } from '../../../tests/setup/cross-origin-headers';
import {
  installCreateAccountAndRegisterUserMock,
  installFastNearRpcMock,
  makeAuthServiceForThreshold,
  setupManagedThresholdRegistrationHarness,
} from '../../../tests/e2e/thresholdEd25519.testUtils';

const SUMMARY_MARKER = '@@REGISTRATION_FLOW_SUMMARY@@';
const REGISTRATION_TIMING_LABEL = '[Registration] wallet timing summary';
const WALLET_IFRAME_TRANSPORT_TIMING_LABEL =
  '[Registration] wallet iframe transport timing summary';
const HSS_WORKER_DIAGNOSTICS_LABEL =
  '[threshold-ed25519][client-worker] hss command diagnostics';
const HSS_CLIENT_TIMING_PREFIX = '[threshold-ed25519][client] hss ';
const REGISTRATION_ROUTE_PAYLOAD_DIAGNOSTICS_LABEL =
  '[Registration] wallet route payload summary';
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
  | 'passkey_ed25519_only_wallet_iframe_activation'
  | 'passkey_ed25519_and_ecdsa_wallet_iframe'
  | 'passkey_ed25519_and_ecdsa_wallet_iframe_activation'
  | 'passkey_ed25519_only_host_origin'
  | 'passkey_ed25519_and_ecdsa_host_origin';

type SignerMode = 'ed25519_only' | 'ed25519_and_ecdsa';
type WalletIframeMode = 'host_origin' | 'wallet_iframe';

type BrowserConsoleCapture = {
  registrationSummaries: unknown[];
  walletIframeTransportDiagnostics: unknown[];
  hssWorkerDiagnostics: unknown[];
  hssClientTimings: unknown[];
  registrationRoutePayloadDiagnostics: unknown[];
};

type BrowserMemoryDiagnostics = {
  supported: boolean;
  sampleCount: number;
  usedJSHeapSizeBeforeBytes?: number;
  usedJSHeapSizeAfterBytes?: number;
  usedJSHeapSizePeakBytes?: number;
  usedJSHeapSizeDeltaBytes?: number;
  usedJSHeapSizePeakDeltaBytes?: number;
  totalJSHeapSizePeakBytes?: number;
  jsHeapSizeLimitBytes?: number;
};

type BenchmarkRunResult = {
  runIndex: number;
  ok: boolean;
  accountId: string;
  durationMs: number;
  registrationSummary: unknown | null;
  walletIframeTransportDiagnostics: unknown[];
  hssWorkerDiagnostics: unknown[];
  hssClientTimings: unknown[];
  registrationRoutePayloadDiagnostics: unknown[];
  browserMemoryDiagnostics?: BrowserMemoryDiagnostics;
  walletIframeAutoConfirmDiagnostics?: WalletIframeAutoConfirmDiagnostics;
  error?: string;
};

function parseScenarioId(raw: string | undefined): ScenarioId {
  const scenarioId = String(raw || 'passkey_ed25519_only_wallet_iframe').trim();
  switch (scenarioId) {
    case 'passkey_ed25519_only_wallet_iframe':
    case 'passkey_ed25519_only_wallet_iframe_activation':
    case 'passkey_ed25519_and_ecdsa_wallet_iframe':
    case 'passkey_ed25519_and_ecdsa_wallet_iframe_activation':
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
  return scenarioId.includes('_wallet_iframe') ? 'wallet_iframe' : 'host_origin';
}

function usesRegistrationActivationSurface(scenarioId: ScenarioId): boolean {
  return scenarioId.endsWith('_activation');
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

function appendTimingBucket(valuesByBucket: Map<string, number[]>, key: string, value: number) {
  if (!Number.isFinite(value)) return;
  valuesByBucket.set(key, [...(valuesByBucket.get(key) || []), value]);
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
      appendTimingBucket(valuesByBucket, 'totalMs', run.durationMs);
      appendTimingBucket(valuesByBucket, 'browserRunDurationMs', run.durationMs);
    }
    if (run.ok && run.walletIframeAutoConfirmDiagnostics) {
      for (const [key, value] of Object.entries(run.walletIframeAutoConfirmDiagnostics)) {
        if (typeof value !== 'number' || !Number.isFinite(value)) continue;
        const bucket = `walletIframeAutoConfirm${key[0]!.toUpperCase()}${key.slice(1)}`;
        appendTimingBucket(valuesByBucket, bucket, value);
      }
    }
    if (run.ok) {
      for (const diagnostics of run.walletIframeTransportDiagnostics) {
        if (!diagnostics || typeof diagnostics !== 'object' || Array.isArray(diagnostics)) {
          continue;
        }
        for (const [key, value] of Object.entries(diagnostics)) {
          if (typeof value !== 'number' || !Number.isFinite(value)) continue;
          const bucket = `walletIframeTransport${key[0]!.toUpperCase()}${key.slice(1)}`;
          appendTimingBucket(valuesByBucket, bucket, value);
        }
      }
    }
    const summary = run.registrationSummary;
    if (!summary || typeof summary !== 'object' || Array.isArray(summary)) continue;
    const totalMs = numericField(summary, 'totalMs');
    if (totalMs !== null) {
      appendTimingBucket(valuesByBucket, 'sdkTotalMs', totalMs);
    }
    const timings = (summary as { timings?: unknown }).timings;
    if (!timings || typeof timings !== 'object' || Array.isArray(timings)) continue;
    for (const [key, value] of Object.entries(timings)) {
      if (typeof value !== 'number' || !Number.isFinite(value)) continue;
      appendTimingBucket(valuesByBucket, key, value);
    }
    const promptDecisionWaitMs = numericField(timings, 'passkeyAuthPromptDecisionWaitMs');
    const authProofMs = numericField(timings, 'authProofMs');
    if (promptDecisionWaitMs !== null && totalMs !== null && totalMs >= promptDecisionWaitMs) {
      appendTimingBucket(
        valuesByBucket,
        'sdkMinusPasskeyPromptDecisionWaitMs',
        totalMs - promptDecisionWaitMs,
      );
    }
    if (
      promptDecisionWaitMs !== null &&
      authProofMs !== null &&
      authProofMs >= promptDecisionWaitMs
    ) {
      appendTimingBucket(
        valuesByBucket,
        'authProofMinusPasskeyPromptDecisionWaitMs',
        authProofMs - promptDecisionWaitMs,
      );
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

function collectRegistrationRoutePayloadStats(runs: BenchmarkRunResult[]) {
  const grouped = new Map<
    string,
    {
      totalMs: number[];
      requestBytes: number[];
      responseBytes: number[];
    }
  >();
  for (const run of runs) {
    for (const diagnostic of run.registrationRoutePayloadDiagnostics) {
      if (!diagnostic || typeof diagnostic !== 'object' || Array.isArray(diagnostic)) continue;
      const path = String((diagnostic as { path?: unknown }).path || '').trim();
      if (!path) continue;
      const bucket =
        grouped.get(path) ||
        {
          totalMs: [],
          requestBytes: [],
          responseBytes: [],
        };
      for (const key of Object.keys(bucket) as Array<keyof typeof bucket>) {
        const value = numericField(diagnostic, key);
        if (value !== null) bucket[key].push(value);
      }
      grouped.set(path, bucket);
    }
  }
  const out: Record<string, Record<string, ReturnType<typeof summarizeNumbers>>> = {};
  for (const [path, values] of grouped.entries()) {
    out[path] = {
      totalMs: summarizeNumbers(values.totalMs),
      requestBytes: summarizeNumbers(values.requestBytes),
      responseBytes: summarizeNumbers(values.responseBytes),
    };
  }
  return out;
}

function collectBrowserMemoryStats(runs: BenchmarkRunResult[]) {
  const grouped = new Map<string, number[]>();
  for (const run of runs) {
    const diagnostics = run.browserMemoryDiagnostics;
    if (!diagnostics || !diagnostics.supported || diagnostics.sampleCount <= 0) continue;
    for (const [key, value] of Object.entries(diagnostics)) {
      if (key === 'supported') continue;
      const numberValue = Number(value);
      if (!Number.isFinite(numberValue)) continue;
      grouped.set(key, [...(grouped.get(key) || []), numberValue]);
    }
  }
  const out: Record<string, ReturnType<typeof summarizeNumbers>> = {};
  for (const [key, values] of grouped.entries()) {
    out[key] = summarizeNumbers(values);
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
    walletIframeTransportDiagnostics: [],
    hssWorkerDiagnostics: [],
    hssClientTimings: [],
    registrationRoutePayloadDiagnostics: [],
  };

  page.on('console', (message) => {
    void (async () => {
      const args = await consoleArgs(message);
      const label = String(args[0] || '').trim();
      if (label === REGISTRATION_TIMING_LABEL) {
        capture.registrationSummaries.push(args[1] ?? null);
        return;
      }
      if (label === WALLET_IFRAME_TRANSPORT_TIMING_LABEL) {
        capture.walletIframeTransportDiagnostics.push(args[1] ?? null);
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
        return;
      }
      if (label === REGISTRATION_ROUTE_PAYLOAD_DIAGNOSTICS_LABEL) {
        capture.registrationRoutePayloadDiagnostics.push(args[1] ?? null);
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
    const activationSurface = usesRegistrationActivationSurface(scenarioId);
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
      const walletIframeTransportCursor = { index: 0 };
      const hssWorkerCursor = { index: 0 };
      const hssClientCursor = { index: 0 };
      const registrationRoutePayloadCursor = { index: 0 };
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
            activationSurface: browserActivationSurface,
            registrationOptions: browserRegistrationOptions,
          }) => {
            type MemorySample = {
              usedJSHeapSize?: number;
              totalJSHeapSize?: number;
              jsHeapSizeLimit?: number;
            };
            const memorySamples: MemorySample[] = [];
            const readMemorySample = (): MemorySample | null => {
              const memory = (performance as { memory?: unknown }).memory;
              if (!memory || typeof memory !== 'object') return null;
              const record = memory as Record<string, unknown>;
              const sample: MemorySample = {};
              for (const key of [
                'usedJSHeapSize',
                'totalJSHeapSize',
                'jsHeapSizeLimit',
              ] as const) {
                const value = Number(record[key]);
                if (Number.isFinite(value) && value >= 0) sample[key] = value;
              }
              return Object.keys(sample).length ? sample : null;
            };
            const sampleMemory = (): void => {
              const sample = readMemorySample();
              if (sample) memorySamples.push(sample);
            };
            const peak = (values: number[]): number | undefined => {
              const finite = values.filter((value) => Number.isFinite(value));
              return finite.length ? Math.max(...finite) : undefined;
            };
            const summarizeMemory = (): BrowserMemoryDiagnostics => {
              const used = memorySamples
                .map((sample) => sample.usedJSHeapSize)
                .filter((value): value is number => Number.isFinite(value));
              const total = memorySamples
                .map((sample) => sample.totalJSHeapSize)
                .filter((value): value is number => Number.isFinite(value));
              const limits = memorySamples
                .map((sample) => sample.jsHeapSizeLimit)
                .filter((value): value is number => Number.isFinite(value));
              if (!used.length && !total.length && !limits.length) {
                return { supported: false, sampleCount: 0 };
              }
              const usedBefore = used[0];
              const usedAfter = used[used.length - 1];
              const usedPeak = peak(used);
              return {
                supported: true,
                sampleCount: memorySamples.length,
                ...(usedBefore !== undefined ? { usedJSHeapSizeBeforeBytes: usedBefore } : {}),
                ...(usedAfter !== undefined ? { usedJSHeapSizeAfterBytes: usedAfter } : {}),
                ...(usedPeak !== undefined ? { usedJSHeapSizePeakBytes: usedPeak } : {}),
                ...(usedBefore !== undefined && usedAfter !== undefined
                  ? { usedJSHeapSizeDeltaBytes: usedAfter - usedBefore }
                  : {}),
                ...(usedBefore !== undefined && usedPeak !== undefined
                  ? { usedJSHeapSizePeakDeltaBytes: usedPeak - usedBefore }
                  : {}),
                ...(peak(total) !== undefined ? { totalJSHeapSizePeakBytes: peak(total) } : {}),
                ...(peak(limits) !== undefined ? { jsHeapSizeLimitBytes: peak(limits) } : {}),
              };
            };
            sampleMemory();
            const memoryTimer = window.setInterval(sampleMemory, 25);
            const finish = (result: { ok: true } | { ok: false; error: string }) => {
              sampleMemory();
              window.clearInterval(memoryTimer);
              return {
                ...result,
                browserMemoryDiagnostics: summarizeMemory(),
              };
            };
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
              if (browserActivationSurface) {
                const container = document.createElement('div');
                container.setAttribute('data-benchmark-registration-activation-mount', 'true');
                document.body.appendChild(container);
                const surface = seams.registration.createPasskeyRegistrationActivationSurface({
                  nearAccountId: browserAccountId,
                  options: browserRegistrationOptions as any,
                  button: {
                    label: 'Create passkey',
                    busyLabel: 'Creating passkey...',
                  },
                });
                try {
                  const activationResult = await new Promise<
                    { ok: true } | { ok: false; error: string }
                  >(
                    (resolve) => {
                      let settled = false;
                      let unsubscribe = (): void => {};
                      let timeout = 0;
                      const finish = (result: { ok: true } | { ok: false; error: string }) => {
                        if (settled) return;
                        settled = true;
                        window.clearTimeout(timeout);
                        unsubscribe();
                        resolve(result);
                      };
                      timeout = window.setTimeout(() => {
                        finish({
                          ok: false,
                          error: 'registration activation surface timed out',
                        });
                      }, 120_000);
                      unsubscribe = surface.onStateChange((state: any) => {
                        if (state.kind === 'completed') {
                          finish({ ok: true });
                          return;
                        }
                        if (state.kind === 'failed') {
                          finish({
                            ok: false,
                            error: String(state.error || 'registration activation failed'),
                          });
                          return;
                        }
                        if (state.kind === 'cancelled') {
                          finish({
                            ok: false,
                            error: `registration activation cancelled: ${String(state.reason || '')}`,
                          });
                        }
                      });
                      surface.mount(container);
                    },
                  );
                  return finish(activationResult);
                } finally {
                  try {
                    surface.dispose();
                  } catch {}
                  try {
                    container.remove();
                  } catch {}
                }
              }
              const registration = await seams.registration.registerPasskey(
                browserAccountId,
                browserRegistrationOptions as any,
              );
              if (!registration?.success) {
                return finish({
                  ok: false as const,
                  error: String(
                    registration?.error ||
                      `registration failed for signer mode ${browserSignerMode}`,
                  ),
                });
              }
              return finish({ ok: true as const });
            } catch (error: any) {
              return finish({ ok: false as const, error: String(error?.message || error) });
            }
          },
          {
            accountId,
            relayerUrl,
            signerMode,
            walletIframeMode,
            activationSurface,
            registrationOptions,
          },
        );
        const walletIframeAutoConfirmDiagnostics =
          walletIframeMode === 'wallet_iframe'
            ? ({
                attempts: 0,
                clicked: false,
              } satisfies WalletIframeAutoConfirmDiagnostics)
            : undefined;
        const result = await autoConfirmWalletIframeUntil(page, resultPromise, {
          timeoutMs: 120_000,
          intervalMs: 50,
          retryDelayMs: 0,
          stopAfterClick: true,
          ...(walletIframeAutoConfirmDiagnostics
            ? { diagnostics: walletIframeAutoConfirmDiagnostics }
            : {}),
        });
        const durationMs = Math.max(0, Math.round(performance.now() - startedAt));
        await page.waitForTimeout(250);
        const registrationSummaries = consumeNewEntries(capture.registrationSummaries, summaryCursor);
        const walletIframeTransportDiagnostics = consumeNewEntries(
          capture.walletIframeTransportDiagnostics,
          walletIframeTransportCursor,
        );
        const hssWorkerDiagnostics = consumeNewEntries(
          capture.hssWorkerDiagnostics,
          hssWorkerCursor,
        );
        const hssClientTimings = consumeNewEntries(capture.hssClientTimings, hssClientCursor);
        const registrationRoutePayloadDiagnostics = consumeNewEntries(
          capture.registrationRoutePayloadDiagnostics,
          registrationRoutePayloadCursor,
        );

        runs.push({
          runIndex,
          ok: !!result.ok,
          accountId,
          durationMs,
          registrationSummary: registrationSummaries.at(-1) ?? null,
          walletIframeTransportDiagnostics,
          hssWorkerDiagnostics,
          hssClientTimings,
          registrationRoutePayloadDiagnostics,
          ...(result.browserMemoryDiagnostics
            ? { browserMemoryDiagnostics: result.browserMemoryDiagnostics }
            : {}),
          ...(walletIframeAutoConfirmDiagnostics
            ? { walletIframeAutoConfirmDiagnostics }
            : {}),
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
        activationSurface,
        runsRequested,
        successfulRuns,
        failedRuns: runsRequested - successfulRuns,
        hssWorkerDiagnosticsCount: runs.reduce(
          (acc, run) => acc + run.hssWorkerDiagnostics.length,
          0,
        ),
        hssClientTimingCount: runs.reduce((acc, run) => acc + run.hssClientTimings.length, 0),
        walletIframeTransportDiagnosticsCount: runs.reduce(
          (acc, run) => acc + run.walletIframeTransportDiagnostics.length,
          0,
        ),
        registrationRoutePayloadDiagnosticsCount: runs.reduce(
          (acc, run) => acc + run.registrationRoutePayloadDiagnostics.length,
          0,
        ),
        browserMemoryDiagnosticsCount: runs.reduce(
          (acc, run) =>
            acc +
            (run.browserMemoryDiagnostics?.supported &&
            run.browserMemoryDiagnostics.sampleCount > 0
              ? 1
              : 0),
          0,
        ),
        relayDiagnosticsCount: runs.reduce((acc, run) => {
          const summary = run.registrationSummary;
          if (!summary || typeof summary !== 'object' || Array.isArray(summary)) return acc;
          const relayDiagnostics = (summary as { relayDiagnostics?: unknown }).relayDiagnostics;
          return acc + (Array.isArray(relayDiagnostics) ? relayDiagnostics.length : 0);
        }, 0),
        timingStats: collectTimingStats(runs),
        relayStatsByRoute: collectRelayRouteStats(runs),
        registrationRoutePayloadStatsByPath: collectRegistrationRoutePayloadStats(runs),
        hssWorkerStatsByOperation: collectHssWorkerStats(runs),
        hssClientStatsByOperation: collectHssClientStats(runs),
        browserMemoryStats: collectBrowserMemoryStats(runs),
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
