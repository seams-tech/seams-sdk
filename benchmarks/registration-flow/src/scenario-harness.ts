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
import {
  createSigningSessionSealPolicyFromWalletSessionStores,
  createSigningSessionSealRoutesOptions,
  createSigningSessionSealShamir3PassCipherAdapter,
} from '@server/threshold/session/signingSessionSeal';
import {
  parseRouterAbPublicKeysetV2,
  ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
} from '@shared/utils/routerAbPublicKeyset';

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
const BENCHMARK_SIGNING_SESSION_SEAL_KEY_VERSION = 'kek-s-registration-benchmark';
const BENCHMARK_SHAMIR_PRIME_B64U = '_____________________________________v___C8';
const BENCHMARK_SHAMIR_SERVER_ENCRYPT_EXPONENT_B64U = 'AQAB';
const BENCHMARK_SHAMIR_SERVER_DECRYPT_EXPONENT_B64U =
  '6LQXS-i0F0votBdL6LQXS-i0F0votBdL6LQXSv___Ic';
const BENCHMARK_ROUTER_AB_PUBLIC_KEYSET = parseRouterAbPublicKeysetV2({
  keyset_version: ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
  signer_envelope_hpke: {
    current: {
      deriver_a: {
        role: 'signer_a',
        key_epoch: 'epoch-a',
        public_key: 'x25519:1111111111111111111111111111111111111111111111111111111111111111',
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: 'epoch-b',
        public_key: 'x25519:2222222222222222222222222222222222222222222222222222222222222222',
      },
    },
  },
  signer_peer_verifying_keys: {
    deriver_a: {
      role: 'signer_a',
      verifying_key_hex: '5afa80b305e72e02615ed1f580144a40a42a71dfcac175809ceb5d79e740d015',
    },
    deriver_b: {
      role: 'signer_b',
      verifying_key_hex: '0c700dd63695221e508f3164b528f190bed63a4437d38e882308f9a57acc1bc3',
    },
  },
  signing_worker_server_output_hpke: {
    key_epoch: 'epoch-server',
    public_key: 'x25519:3333333333333333333333333333333333333333333333333333333333333333',
  },
});

type ScenarioId =
  | 'passkey_ed25519_only_wallet_iframe'
  | 'passkey_ed25519_only_wallet_iframe_activation'
  | 'passkey_ed25519_and_ecdsa_wallet_iframe'
  | 'passkey_ed25519_and_ecdsa_wallet_iframe_activation'
  | 'passkey_ed25519_only_host_origin'
  | 'passkey_ed25519_and_ecdsa_host_origin'
  | 'email_otp_ed25519_only_wallet_iframe'
  | 'email_otp_ed25519_and_ecdsa_wallet_iframe'
  | 'email_otp_ed25519_only_host_origin'
  | 'email_otp_ed25519_and_ecdsa_host_origin';

type AuthMode = 'passkey' | 'email_otp';
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
    case 'email_otp_ed25519_only_wallet_iframe':
    case 'email_otp_ed25519_and_ecdsa_wallet_iframe':
    case 'email_otp_ed25519_only_host_origin':
    case 'email_otp_ed25519_and_ecdsa_host_origin':
      return scenarioId;
  }
  throw new Error(`Unknown registration benchmark scenario: ${scenarioId}`);
}

function authModeForScenario(scenarioId: ScenarioId): AuthMode {
  return scenarioId.startsWith('email_otp_') ? 'email_otp' : 'passkey';
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

function installBenchmarkGoogleLoginVerifier(service: {
  verifyGoogleLogin(request: { idToken?: unknown; id_token?: unknown }): Promise<{
    ok: boolean;
    verified?: boolean;
    userId?: string;
    providerSubject?: string;
    sub?: string;
    email?: string;
    name?: string;
    emailVerified?: boolean;
    code?: string;
    message?: string;
  }>;
}): void {
  service.verifyGoogleLogin = async (request) => {
    const token = String(request.idToken ?? request.id_token ?? '').trim();
    const seed = token.replace(/[^a-zA-Z0-9-]/g, '-').slice(0, 72);
    if (!seed) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_body',
        message: 'benchmark Google id token is required',
      };
    }
    const sub = `benchmark-${seed}`;
    const providerSubject = `google:${sub}`;
    return {
      ok: true,
      verified: true,
      userId: providerSubject,
      providerSubject,
      sub,
      email: `${seed.toLowerCase()}@registration-benchmark.example`,
      name: `Benchmark ${seed}`,
      emailVerified: true,
    };
  };
}

function createBenchmarkSigningSessionSealOptions(threshold: unknown) {
  const thresholdAuthStores = threshold as {
    authSessionStore?: unknown;
    ecdsaAuthSessionStore?: unknown;
  };
  if (!thresholdAuthStores.authSessionStore || !thresholdAuthStores.ecdsaAuthSessionStore) {
    throw new Error('Missing threshold auth session stores for registration benchmark seal policy');
  }
  return createSigningSessionSealRoutesOptions({
    sessionPolicy: createSigningSessionSealPolicyFromWalletSessionStores({
      ed25519Stores: [thresholdAuthStores.authSessionStore as any],
      ecdsaStores: [thresholdAuthStores.ecdsaAuthSessionStore as any],
      walletBudgetStores: [thresholdAuthStores.authSessionStore as any],
    }),
    cipher: createSigningSessionSealShamir3PassCipherAdapter({
      currentKeyVersion: BENCHMARK_SIGNING_SESSION_SEAL_KEY_VERSION,
      keys: [
        {
          keyVersion: BENCHMARK_SIGNING_SESSION_SEAL_KEY_VERSION,
          shamirPrimeB64u: BENCHMARK_SHAMIR_PRIME_B64U,
          serverEncryptExponentB64u: BENCHMARK_SHAMIR_SERVER_ENCRYPT_EXPONENT_B64U,
          serverDecryptExponentB64u: BENCHMARK_SHAMIR_SERVER_DECRYPT_EXPONENT_B64U,
        },
      ],
    }),
    capabilities: {
      mode: 'sealed_refresh_v1',
      keyVersion: BENCHMARK_SIGNING_SESSION_SEAL_KEY_VERSION,
      shamirPrimeB64u: BENCHMARK_SHAMIR_PRIME_B64U,
    },
  });
}

test.describe('registration flow benchmark scenario', () => {
  test.setTimeout(300_000);

  test('captures registration timing and HSS worker diagnostics', async ({ page }) => {
    const scenarioId = parseScenarioId(process.env.BENCH_REGISTRATION_SCENARIO);
    const authMode = authModeForScenario(scenarioId);
    const signerMode = signerModeForScenario(scenarioId);
    const walletIframeMode = walletIframeModeForScenario(scenarioId);
    const activationSurface = usesRegistrationActivationSurface(scenarioId);
    if (authMode === 'email_otp' && activationSurface) {
      throw new Error('Email OTP registration benchmark scenarios do not support activation surface');
    }
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
    const previousAccountIdDerivationSecret = process.env.ACCOUNT_ID_DERIVATION_SECRET;
    process.env.ACCOUNT_ID_DERIVATION_SECRET =
      previousAccountIdDerivationSecret || 'registration-benchmark-account-id-derivation-secret';
    const { service, threshold } = makeAuthServiceForThreshold(
      keysOnChain,
      authMode === 'email_otp'
        ? {
            THRESHOLD_NODE_ROLE: 'coordinator',
            SIGNING_SESSION_SEAL_KEY_VERSION: BENCHMARK_SIGNING_SESSION_SEAL_KEY_VERSION,
            SIGNING_SESSION_SHAMIR_P_B64U: BENCHMARK_SHAMIR_PRIME_B64U,
            SIGNING_SESSION_SEAL_E_S_B64U: BENCHMARK_SHAMIR_SERVER_ENCRYPT_EXPONENT_B64U,
            SIGNING_SESSION_SEAL_D_S_B64U: BENCHMARK_SHAMIR_SERVER_DECRYPT_EXPONENT_B64U,
          }
        : undefined,
    );
    installBenchmarkGoogleLoginVerifier(service);
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
      routerAbPublicKeyset: BENCHMARK_ROUTER_AB_PUBLIC_KEYSET,
      ...(authMode === 'email_otp'
        ? { signingSessionSeal: createBenchmarkSigningSessionSealOptions(threshold) }
        : {}),
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
            scenarioId: browserScenarioId,
            authMode: browserAuthMode,
            signerMode: browserSignerMode,
            walletIframeMode: browserWalletIframeMode,
            activationSurface: browserActivationSurface,
            signingSessionSeal: browserSigningSessionSeal,
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
                ...(browserSigningSessionSeal
                  ? {
                      signingSessionPersistenceMode: 'sealed_refresh_v1' as const,
                      signingSessionSeal: browserSigningSessionSeal,
                    }
                  : {}),
                ...(managedRegistration
                  ? {
                      registration: {
                        mode: 'managed' as const,
                        environmentId: String(managedRegistration.environmentId || ''),
                        publishableKey: String(managedRegistration.publishableKey || ''),
                      },
                    }
                  : {}),
                routerAb: {
                  normalSigning: {
                    mode: 'enabled' as const,
                    signingWorkerId: 'local-signing-worker',
                  },
                },
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
              if (browserAuthMode === 'email_otp') {
                const started = await seams.auth.beginGoogleEmailOtpWalletAuth({
                  idToken: `registration-benchmark-${browserScenarioId}-${browserAccountId}`,
                  mode: 'register',
                  relayUrl: browserRelayerUrl,
                  sessionKind: 'jwt',
                  ecdsaTargets:
                    browserSignerMode === 'ed25519_and_ecdsa'
                      ? ({ kind: 'configured' } as const)
                      : ({ kind: 'none' } as const),
                });
                if (!started.ok) {
                  return finish({
                    ok: false as const,
                    error: `email otp start failed: ${started.error.message}`,
                  });
                }
                if (started.value.mode !== 'register') {
                  return finish({
                    ok: false as const,
                    error: `email otp start resolved ${started.value.mode}, expected register`,
                  });
                }
                const completed = await started.value.completeRegistration();
                if (!completed.ok) {
                  return finish({
                    ok: false as const,
                    error: `email otp registration failed: ${completed.error.message}`,
                  });
                }
                return finish({ ok: true as const });
              }
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
            scenarioId,
            authMode,
            signerMode,
            walletIframeMode,
            activationSurface,
            signingSessionSeal:
              authMode === 'email_otp'
                ? {
                    keyVersion: BENCHMARK_SIGNING_SESSION_SEAL_KEY_VERSION,
                    shamirPrimeB64u: BENCHMARK_SHAMIR_PRIME_B64U,
                  }
                : null,
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
        authMode,
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
      if (previousAccountIdDerivationSecret === undefined) {
        delete process.env.ACCOUNT_ID_DERIVATION_SECRET;
      } else {
        process.env.ACCOUNT_ID_DERIVATION_SECRET = previousAccountIdDerivationSecret;
      }
    }
  });
});
