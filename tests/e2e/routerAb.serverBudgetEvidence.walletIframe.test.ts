import {
  expect,
  test,
  type ConsoleMessage,
  type Frame,
  type Page,
  type Request,
  type TestInfo,
} from '@playwright/test';
import {
  readWebAuthnGetCallCount,
  setupThresholdEcdsaSealedRefreshHarness,
  TEST_KEY_VERSION,
  TEST_SHAMIR_PRIME_B64U,
  type SealedRefreshHarness,
} from '../helpers/thresholdEcdsaSealedRefreshHarness';
import { autoConfirmWalletIframeUntil } from '../setup/flows';

type BudgetEvidenceStage = {
  label: string;
  ok: boolean;
  chain?: string;
  kind?: string;
  sessionStatus?: string;
  remainingUses?: number | null;
  signingGrantId?: string;
  thresholdSessionId?: string;
  ed25519State?: string;
  ed25519Reason?: string;
  hasMaterialHandle?: boolean;
  hasMaterialBindingDigest?: boolean;
  hasClientVerifier?: boolean;
  ed25519VisibleRecordCount?: number;
  ed25519VisibleRecordAccounts?: string[];
  ed25519VisibleRecordSessions?: string[];
  hasSealedWorkerMaterial?: boolean;
  ed25519BudgetStatus?: string;
  ed25519BudgetError?: string;
  ed25519RemainingUses?: number | null;
  ed25519SigningGrantId?: string;
  ed25519ThresholdSessionId?: string;
  ed25519RestoreWorkerMaterialCalls?: number;
  ed25519HssRouteCalls?: number;
  ed25519WorkerRequestTypes?: Record<string, number>;
  ed25519WorkerTraceInstall?: string;
  error?: string;
};

type BudgetEvidenceResult = {
  ok: boolean;
  accountId: string;
  consoleMessages?: string[];
  stages: BudgetEvidenceStage[];
  webauthnGetCounts: {
    before: number;
    afterUnlock: number;
    afterFirstThreeSigns: number;
    afterFourthSign: number;
  };
  error?: string;
};

type Ed25519WorkerOperationTraceSnapshot = {
  restoreWorkerMaterialCalls: number;
  workerRequestTypes: Record<string, number>;
};

type Ed25519NoHssTraceBaseline = {
  workerTrace: Ed25519WorkerOperationTraceSnapshot;
  ed25519HssRouteCalls: number;
};

function installEd25519WorkerOperationTraceInRealm(): void {
  const global = window as typeof window & {
    __w3aEd25519WorkerTrace?: {
      record: (requestType: string) => void;
      snapshot: () => Ed25519WorkerOperationTraceSnapshot;
    };
    __w3aResetNearSignerWorkers?: () => void;
  };
  if (global.__w3aEd25519WorkerTrace) return;

  const requestTypes: Record<string, number> = {};
  const nearSignerWorkers = new Set<Worker>();
  const recordRequestType = (requestTypeRaw: string): void => {
    const requestType = String(requestTypeRaw || '').trim();
    if (!requestType) return;
    requestTypes[requestType] = (requestTypes[requestType] || 0) + 1;
  };
  const isNearSignerWorker = (url: unknown, options: unknown): boolean => {
    const workerUrl = String(url || '').toLowerCase();
    const workerName =
      options && typeof options === 'object'
        ? String((options as { name?: unknown }).name || '').toLowerCase()
        : '';
    return workerUrl.includes('near-signer.worker') || workerName.includes('signer-worker');
  };
  const OriginalWorker = window.Worker;
  const patchNearSignerPostMessage = (worker: Worker): void => {
    const originalPostMessage = worker.postMessage.bind(worker);
    worker.postMessage = ((message: unknown, transfer?: Transferable[]) => {
      if (message && typeof message === 'object') {
        recordRequestType(String((message as { type?: unknown }).type || ''));
      }
      if (transfer) {
        originalPostMessage(message, transfer);
        return;
      }
      originalPostMessage(message);
    }) as Worker['postMessage'];
  };
  const TracedWorker = function tracedWorker(
    this: Worker,
    url: string | URL,
    options?: WorkerOptions,
  ): Worker {
    const worker = new OriginalWorker(url, options);
    if (isNearSignerWorker(url, options)) {
      nearSignerWorkers.add(worker);
      patchNearSignerPostMessage(worker);
    }
    return worker;
  } as unknown as typeof Worker;
  TracedWorker.prototype = OriginalWorker.prototype;
  Object.defineProperty(window, 'Worker', { value: TracedWorker, configurable: true });

  global.__w3aEd25519WorkerTrace = {
    record: recordRequestType,
    snapshot: () => ({
      restoreWorkerMaterialCalls:
        requestTypes.thresholdEd25519RestoreWorkerMaterial || 0,
      workerRequestTypes: { ...requestTypes },
    }),
  };
  global.__w3aResetNearSignerWorkers = () => {
    for (const worker of nearSignerWorkers) {
      try {
        worker.terminate();
      } catch {}
    }
    nearSignerWorkers.clear();
  };
}

async function installEd25519WorkerOperationTrace(page: Page): Promise<void> {
  await page.addInitScript(installEd25519WorkerOperationTraceInRealm);
  await page.evaluate(installEd25519WorkerOperationTraceInRealm);
}

async function resetNearSignerWorkerForColdEd25519Material(page: Page): Promise<void> {
  await page.evaluate(async () => {
    const harness = (globalThis as any).__routerAbBudgetEvidence;
    let resetByHarness = false;
    if (typeof harness?.resetNearSignerWorker === 'function') {
      harness.resetNearSignerWorker();
      resetByHarness = true;
    }
    if (!resetByHarness) {
      const workerTransportMod = await import(
        '/sdk/esm/core/signingEngine/workerManager/workerTransport.js'
      );
      const workerTransport = workerTransportMod.getWorkerTransport?.();
      if (typeof workerTransport?.resetWorker === 'function') {
        workerTransport.resetWorker('nearSigner');
      }
    }
  });
}

async function readEd25519WorkerOperationTrace(
  page: Page,
): Promise<Ed25519WorkerOperationTraceSnapshot> {
  const snapshots = await Promise.all(
    page.frames().map((frame) =>
      frame
        .evaluate(() => {
          const trace = (window as any).__w3aEd25519WorkerTrace;
          return typeof trace?.snapshot === 'function'
            ? trace.snapshot()
            : { restoreWorkerMaterialCalls: 0, workerRequestTypes: {} };
        })
        .catch(() => ({ restoreWorkerMaterialCalls: 0, workerRequestTypes: {} })),
    ),
  );
  const workerRequestTypes: Record<string, number> = {};
  let restoreWorkerMaterialCalls = 0;
  for (const snapshot of snapshots) {
    restoreWorkerMaterialCalls += Number(snapshot.restoreWorkerMaterialCalls || 0);
    for (const [requestType, count] of Object.entries(snapshot.workerRequestTypes || {})) {
      workerRequestTypes[requestType] = (workerRequestTypes[requestType] || 0) + Number(count || 0);
    }
  }
  return { restoreWorkerMaterialCalls, workerRequestTypes };
}

function isEd25519HssRouteUrl(urlRaw: string): boolean {
  const url = String(urlRaw || '').toLowerCase();
  return (
    url.includes('/v2/router-ab/ed25519/hss/') ||
    url.includes('/registration/threshold-ed25519/hss/') ||
    (url.includes('threshold-ed25519') && url.includes('/hss/'))
  );
}

test.describe('Router A/B shared server-budget local evidence', () => {
  test.describe.configure({ timeout: 180_000 });

  test.skip(
    process.env.RUN_ROUTER_AB_BUDGET_EVIDENCE !== '1',
    'Set RUN_ROUTER_AB_BUDGET_EVIDENCE=1 to run local browser budget evidence.',
  );

  test('one unlock provisions three shared uses across NEAR, Tempo, and EVM, then step-up resets budget', async (
    { page },
    testInfo,
  ) => {
    const harness = await setupThresholdEcdsaSealedRefreshHarness(page, {
      injectWalletServiceImportMap: true,
    });
    try {
      const result = await runSharedBudgetEvidence(page, harness, {
        accountId: `budget-evidence-${Date.now()}.w3a-v1.testnet`,
        captureEd25519LaneEvidence: true,
      });

      await attachBudgetEvidenceTrace(testInfo, result);
      const signingStages = result.stages.filter((stage) => stage.chain);
      const budgetEvidence = validateSharedBudgetEvidenceResult(result);
      expect(result.ok, result.error || JSON.stringify(result, null, 2)).toBe(true);
      expect(
        budgetEvidence.ok,
        budgetEvidence.ok ? JSON.stringify(result, null, 2) : budgetEvidence.error,
      ).toBe(true);
      expect(signingStages.slice(0, 3).map((stage) => stage.chain)).toEqual([
        'near',
        'tempo',
        'evm',
      ]);
      expect(signingStages.slice(0, 3).every((stage) => stage.ok)).toBe(true);
      expect(result.webauthnGetCounts.afterFirstThreeSigns).toBe(
        result.webauthnGetCounts.afterUnlock,
      );
      expect(signingStages[3]?.ok, JSON.stringify(signingStages[3])).toBe(true);
      expect(result.webauthnGetCounts.afterFourthSign).toBe(
        result.webauthnGetCounts.afterFirstThreeSigns + 1,
      );
    } finally {
      await harness.close();
    }
  });

  test('one unlock lazily restores Ed25519 material across NEAR tx, NEP-413, and delegate signing', async (
    { page },
    testInfo,
  ) => {
    const harness = await setupThresholdEcdsaSealedRefreshHarness(page, {
      injectWalletServiceImportMap: true,
    });
    try {
      const result = await runSharedBudgetEvidence(page, harness, {
        accountId: `ed25519-evidence-${Date.now()}.w3a-v1.testnet`,
        firstLabels: ['near-1', 'nep413-1', 'delegate-1'],
        fourthLabels: ['near-2'],
        captureEd25519LaneEvidence: true,
        forceColdEd25519MaterialBeforeFirstSign: true,
        validateSharedBudget: false,
      });

      await attachBudgetEvidenceTrace(testInfo, result);
      const signingStages = result.stages.filter((stage) => stage.chain);
      const ed25519Evidence = validateEd25519RestoreEvidenceResult(result);
      expect(result.ok, result.error || JSON.stringify(result, null, 2)).toBe(true);
      expect(
        ed25519Evidence.ok,
        ed25519Evidence.ok ? JSON.stringify(result, null, 2) : ed25519Evidence.error,
      ).toBe(true);
      expect(signingStages.slice(0, 3).map((stage) => stage.chain)).toEqual([
        'near',
        'near-nep413',
        'near-delegate',
      ]);
      expect(signingStages.slice(0, 3).every((stage) => stage.ok)).toBe(true);
      expect(result.webauthnGetCounts.afterFirstThreeSigns).toBe(
        result.webauthnGetCounts.afterUnlock + 1,
      );
      expect(signingStages[3]?.ok, JSON.stringify(signingStages[3])).toBe(true);
      expect(result.webauthnGetCounts.afterFourthSign).toBe(
        result.webauthnGetCounts.afterFirstThreeSigns + 1,
      );
    } finally {
      await harness.close();
    }
  });
});

async function attachBudgetEvidenceTrace(
  testInfo: TestInfo,
  result: BudgetEvidenceResult,
): Promise<void> {
  await testInfo.attach('router-ab-server-budget-evidence.json', {
    body: JSON.stringify(result, null, 2),
    contentType: 'application/json',
  });
}

async function runEvidenceSignsWithEd25519LaneEvidence(
  page: Page,
  args: {
    accountId: string;
    labels: string[];
    budgetStatusBaseUrl: string;
    traceBaseline?: Ed25519NoHssTraceBaseline;
    readEd25519HssRouteCalls?: () => number;
  },
): Promise<{ ok: boolean; stages: BudgetEvidenceStage[]; error?: string }> {
  const stages: BudgetEvidenceStage[] = [];
  for (const label of args.labels) {
    const result = await runEvidenceSigns(page, {
      accountId: args.accountId,
      labels: [label],
    });
    const decoratedStages = await decorateStagesWithEd25519LaneEvidence(page, {
      stages: result.stages,
      accountId: args.accountId,
      budgetStatusBaseUrl: args.budgetStatusBaseUrl,
      traceBaseline: args.traceBaseline,
      readEd25519HssRouteCalls: args.readEd25519HssRouteCalls,
    });
    stages.push(...decoratedStages);
    if (!result.ok) {
      return { ok: false, stages, error: result.error };
    }
  }
  return { ok: true, stages };
}

async function decorateStagesWithEd25519LaneEvidence(
  page: Page,
  args: {
    stages: BudgetEvidenceStage[];
    accountId: string;
    budgetStatusBaseUrl: string;
    traceBaseline?: Ed25519NoHssTraceBaseline;
    readEd25519HssRouteCalls?: () => number;
  },
): Promise<BudgetEvidenceStage[]> {
  const evidence = await readWalletIframeEd25519LaneEvidence(page, {
    accountId: args.accountId,
    budgetStatusBaseUrl: args.budgetStatusBaseUrl,
  });
  const traceEvidence = args.traceBaseline
    ? await readEd25519NoHssTraceEvidence(page, {
        baseline: args.traceBaseline,
        ed25519HssRouteCalls: args.readEd25519HssRouteCalls?.() || 0,
      })
    : {};
  return args.stages.map((stage) => ({ ...stage, ...evidence, ...traceEvidence }));
}

async function readEd25519NoHssTraceEvidence(
  page: Page,
  args: {
    baseline: Ed25519NoHssTraceBaseline;
    ed25519HssRouteCalls: number;
  },
): Promise<Partial<BudgetEvidenceStage>> {
  const current = await readEd25519WorkerOperationTrace(page);
  const installDiagnostic = await readEd25519WorkerTraceInstallDiagnostic(page);
  const workerRequestTypes = diffRequestTypeCounts({
    baseline: args.baseline.workerTrace.workerRequestTypes,
    current: current.workerRequestTypes,
  });
  return {
    ed25519RestoreWorkerMaterialCalls:
      current.restoreWorkerMaterialCalls - args.baseline.workerTrace.restoreWorkerMaterialCalls,
    ed25519HssRouteCalls: args.ed25519HssRouteCalls - args.baseline.ed25519HssRouteCalls,
    ed25519WorkerRequestTypes: workerRequestTypes,
    ed25519WorkerTraceInstall: installDiagnostic,
  };
}

async function readEd25519WorkerTraceInstallDiagnostic(page: Page): Promise<string> {
  const diagnostics = await Promise.all(
    page.frames().map((frame) =>
      frame
        .evaluate(() => String((globalThis as any).__w3aEd25519WorkerTraceInstall || ''))
        .catch(() => ''),
    ),
  );
  return diagnostics.filter(Boolean).join(' | ');
}

function diffRequestTypeCounts(args: {
  baseline: Record<string, number>;
  current: Record<string, number>;
}): Record<string, number> {
  const requestTypes = new Set([...Object.keys(args.baseline), ...Object.keys(args.current)]);
  const diff: Record<string, number> = {};
  for (const requestType of requestTypes) {
    const delta = Number(args.current[requestType] || 0) - Number(args.baseline[requestType] || 0);
    if (delta) diff[requestType] = delta;
  }
  return diff;
}

type WalletIframeEd25519RecordEvidence = Partial<BudgetEvidenceStage> & {
  walletSessionJwt?: string;
};

const WALLET_IFRAME_ED25519_EVIDENCE_MODULE_URL =
  'https://wallet.example.localhost/__w3a-ed25519-evidence.js';

async function readWalletIframeEd25519LaneEvidence(
  page: Page,
  args: {
    accountId: string;
    budgetStatusBaseUrl: string;
  },
): Promise<Partial<BudgetEvidenceStage>> {
  const frame = findWalletIframeFrame(page);
  if (!frame) {
    return {
      ed25519State: 'diagnostic_error',
      ed25519Reason: 'wallet iframe was not available',
      ed25519BudgetStatus: 'missing_wallet_iframe',
    };
  }
  await ensureWalletIframeEd25519EvidenceModule(page, frame);
  const recordEvidence = await frame
    .evaluate(readWalletIframeEd25519RecordEvidenceFromGlobal, {
      accountId: args.accountId,
    })
    .catch(async (error: unknown) => {
      const diagnostics = await frame
        .evaluate(readWalletIframeImportMapDiagnostics)
        .catch(() => 'import-map diagnostics unavailable');
      return {
        ed25519State: 'diagnostic_error',
        ed25519Reason:
          error && typeof error === 'object' && 'message' in error
            ? String((error as { message?: unknown }).message || '')
            : String(error || 'wallet iframe record diagnostic failed'),
        ed25519BudgetStatus: 'diagnostic_error',
        ed25519BudgetError: diagnostics,
      } satisfies WalletIframeEd25519RecordEvidence;
    });
  if (recordEvidence.ed25519BudgetStatus === 'diagnostic_error') {
    return stripPrivateEd25519Evidence(recordEvidence);
  }
  const budgetEvidence = await readEd25519ServerBudgetEvidence({
    budgetStatusBaseUrl: args.budgetStatusBaseUrl,
    recordEvidence,
  });
  return stripPrivateEd25519Evidence({
    ...recordEvidence,
    ...budgetEvidence,
  });
}

async function ensureWalletIframeEd25519EvidenceModule(page: Page, frame: Frame): Promise<void> {
  await installWalletIframeEd25519EvidenceModuleRoute(page);
  const isInstalled = await frame.evaluate(hasWalletIframeEd25519EvidenceReader).catch(() => false);
  if (isInstalled) return;
  await frame.addScriptTag({
    url: WALLET_IFRAME_ED25519_EVIDENCE_MODULE_URL,
  });
  await frame
    .waitForFunction(hasWalletIframeEd25519EvidenceReaderOrInstallError, undefined, {
      timeout: 5_000,
    })
    .catch(() => undefined);
}

async function installWalletIframeEd25519EvidenceModuleRoute(page: Page): Promise<void> {
  const context = page.context();
  await context.unroute(WALLET_IFRAME_ED25519_EVIDENCE_MODULE_URL).catch(() => undefined);
  await context.route(WALLET_IFRAME_ED25519_EVIDENCE_MODULE_URL, async (route) => {
    await route.fulfill({
      status: 200,
      headers: {
        'content-type': 'application/javascript; charset=utf-8',
        'cross-origin-resource-policy': 'same-origin',
      },
      body: WALLET_IFRAME_ED25519_EVIDENCE_MODULE_SOURCE,
    });
  });
}

function hasWalletIframeEd25519EvidenceReader(): boolean {
  return typeof (window as any).__w3aReadEd25519Evidence === 'function';
}

function hasWalletIframeEd25519EvidenceReaderOrInstallError(): boolean {
  return (
    typeof (window as any).__w3aReadEd25519Evidence === 'function' ||
    Boolean((window as any).__w3aReadEd25519EvidenceInstallError)
  );
}

function findWalletIframeFrame(page: Page): Frame | null {
  for (const frame of page.frames()) {
    if (isWalletIframeFrame(frame)) return frame;
  }
  return null;
}

function isWalletIframeFrame(frame: Frame): boolean {
  return frame.url().startsWith('https://wallet.example.localhost/');
}

async function readEd25519ServerBudgetEvidence(args: {
  budgetStatusBaseUrl: string;
  recordEvidence: WalletIframeEd25519RecordEvidence;
}): Promise<Partial<BudgetEvidenceStage>> {
  const walletSessionJwt = String(args.recordEvidence.walletSessionJwt || '').trim();
  const signingGrantId = String(args.recordEvidence.ed25519SigningGrantId || '').trim();
  const thresholdSessionId = String(args.recordEvidence.ed25519ThresholdSessionId || '').trim();
  if (!walletSessionJwt || !signingGrantId || !thresholdSessionId) {
    return {
      ed25519BudgetStatus: 'missing_budget_status_identity',
      ed25519BudgetError: 'Ed25519 budget status requires JWT, signing grant, and session id',
    };
  }

  try {
    const response = await fetch(`${args.budgetStatusBaseUrl}/session/signing-budget/status`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${walletSessionJwt}`,
      },
      body: JSON.stringify({
        signingGrantId,
        thresholdSessionId,
      }),
    });
    const json = await response.json().catch(() => null);
    if (!response.ok || json?.ok !== true) {
      return {
        ed25519BudgetStatus: 'rejected',
        ed25519BudgetError: String(
          json?.message || json?.code || json?.status || `HTTP ${response.status}`,
        ),
      };
    }
    return parseEd25519BudgetStatusJson(json, {
      signingGrantId,
      thresholdSessionId,
    });
  } catch (error: unknown) {
    return {
      ed25519BudgetStatus: 'fetch_error',
      ed25519BudgetError:
        error && typeof error === 'object' && 'message' in error
          ? String((error as { message?: unknown }).message || '')
          : String(error || 'budget status fetch failed'),
    };
  }
}

function parseEd25519BudgetStatusJson(
  json: Record<string, unknown>,
  expected: {
    signingGrantId: string;
    thresholdSessionId: string;
  },
): Partial<BudgetEvidenceStage> {
  const remainingUses = Number(json.remainingUses);
  const responseSigningGrantId = String(json.signingGrantId || '').trim();
  const responseThresholdSessionId = String(json.thresholdSessionId || '').trim();
  if (
    !Number.isFinite(remainingUses) ||
    responseSigningGrantId !== expected.signingGrantId ||
    responseThresholdSessionId !== expected.thresholdSessionId
  ) {
    return {
      ed25519BudgetStatus: 'malformed_budget_status',
      ed25519BudgetError: 'Budget status response did not match Ed25519 record identity',
    };
  }
  return {
    ed25519BudgetStatus: String(json.status || ''),
    ed25519RemainingUses: Math.floor(remainingUses),
    ed25519SigningGrantId: responseSigningGrantId,
    ed25519ThresholdSessionId: responseThresholdSessionId,
  };
}

function stripPrivateEd25519Evidence(
  evidence: WalletIframeEd25519RecordEvidence,
): Partial<BudgetEvidenceStage> {
  const { walletSessionJwt: _walletSessionJwt, ...publicEvidence } = evidence;
  return publicEvidence;
}

const WALLET_IFRAME_ED25519_EVIDENCE_MODULE_SOURCE = `
(() => {
  if (
    globalThis.__w3aReadEd25519EvidenceInstalling ||
    (globalThis.__w3aReadEd25519Evidence && globalThis.__w3aForceColdEd25519Material)
  ) {
    return;
  }
  globalThis.__w3aReadEd25519EvidenceInstalling = true;
  (async () => {
    const storeMod = await import('/sdk/esm/core/signingEngine/session/persistence/sealedSessionStore.js');
    const workerTransportMod = await import('/sdk/esm/core/signingEngine/workerManager/workerTransport.js').catch(() => null);
    const latestEd25519Record = async (input) => {
      const visibleRecords = await storeMod.listExactSealedSessionsForWallet({
        walletId: input.accountId,
        filter: { authMethod: 'passkey', curve: 'ed25519' },
      });
      const records = Array.isArray(visibleRecords) ? visibleRecords : [];
      const record = records
        .slice()
        .sort((left, right) => Number(right.updatedAtMs || 0) - Number(left.updatedAtMs || 0))[0] || null;
      return { record, records };
    };
    globalThis.__w3aReadEd25519Evidence = async (input) => {
      const { record, records } = await latestEd25519Record(input);
      const restore = record?.ed25519Restore || {};
      const recordSigningGrantId = String(record?.signingGrantId || '').trim();
      const recordThresholdSessionId = String(
        record?.thresholdSessionIds?.ed25519 || record?.thresholdSessionId || '',
      ).trim();
      const materialHandle = String(restore.ed25519WorkerMaterialHandle || '').trim();
      const materialBindingDigest = String(restore.ed25519WorkerMaterialBindingDigest || '').trim();
      const sealedMaterial = String(
        restore.sealedWorkerMaterialRef || restore.sealedWorkerMaterialB64u || '',
      ).trim();
      const verifier = String(restore.clientVerifyingShareB64u || '').trim();
      return {
        thresholdSessionId: recordThresholdSessionId,
        ed25519ThresholdSessionId: recordThresholdSessionId,
        ed25519SigningGrantId: recordSigningGrantId,
        walletSessionJwt: String(restore.walletSessionJwt || record?.walletSessionJwt || '').trim(),
        ed25519State: record
          ? materialHandle
            ? 'material_handle_hint'
            : sealedMaterial
              ? 'material_pending'
              : 'invalid'
          : 'invalid',
        ed25519Reason: record ? '' : 'missing_record',
        hasMaterialHandle: Boolean(materialHandle),
        hasMaterialBindingDigest: Boolean(materialBindingDigest),
        hasSealedWorkerMaterial: Boolean(sealedMaterial),
        hasClientVerifier: Boolean(verifier),
        ed25519VisibleRecordCount: records.length,
        ed25519VisibleRecordAccounts: records.map((visibleRecord) =>
          String(visibleRecord.walletId || ''),
        ),
        ed25519VisibleRecordSessions: records.map((visibleRecord) =>
          String(visibleRecord.thresholdSessionIds?.ed25519 || visibleRecord.thresholdSessionId || ''),
        ),
      };
    };
    globalThis.__w3aForceColdEd25519Material = async (input) => {
      const { record } = await latestEd25519Record(input);
      if (!record) {
        return {
          ok: false,
          reason: 'missing_record',
          evidence: await globalThis.__w3aReadEd25519Evidence(input),
        };
      }
      const restore = record.ed25519Restore || {};
      const sealedMaterial = String(
        restore.sealedWorkerMaterialRef || restore.sealedWorkerMaterialB64u || '',
      ).trim();
      const materialBindingDigest = String(
        restore.ed25519WorkerMaterialBindingDigest || '',
      ).trim();
      const verifier = String(restore.clientVerifyingShareB64u || '').trim();
      if (!sealedMaterial || !materialBindingDigest || !verifier) {
        return {
          ok: false,
          reason: 'missing_sealed_material',
          evidence: await globalThis.__w3aReadEd25519Evidence(input),
        };
      }
      const {
        ed25519WorkerMaterialHandle: _ed25519WorkerMaterialHandle,
        ...coldRestore
      } = restore;
      await storeMod.writeExactSealedSession({
        ...record,
        updatedAtMs: Date.now(),
        ed25519Restore: coldRestore,
      });
      try {
        globalThis.__w3aResetNearSignerWorkers?.();
      } catch {}
      try {
        const workerTransport = workerTransportMod?.getWorkerTransport?.();
        if (typeof workerTransport?.resetWorker === 'function') {
          workerTransport.resetWorker('nearSigner');
        }
      } catch {}
      return {
        ok: true,
        reason: 'material_handle_hint_removed',
        evidence: await globalThis.__w3aReadEd25519Evidence(input),
      };
    };
    globalThis.__w3aReadEd25519EvidenceInstalling = false;
  })().catch((error) => {
    globalThis.__w3aReadEd25519EvidenceInstallError =
      error && typeof error === 'object' && 'message' in error
        ? String(error.message || '')
        : String(error || 'wallet iframe evidence install failed');
  });
})();
`;

async function readWalletIframeEd25519RecordEvidenceFromGlobal(input: {
  accountId: string;
}): Promise<WalletIframeEd25519RecordEvidence> {
  const readEvidence = (window as any).__w3aReadEd25519Evidence;
  if (typeof readEvidence !== 'function') {
    const installError = String((window as any).__w3aReadEd25519EvidenceInstallError || '');
    if (installError) {
      throw new Error(`wallet iframe Ed25519 evidence module failed: ${installError}`);
    }
    throw new Error('wallet iframe Ed25519 evidence module was not installed');
  }
  return await readEvidence(input);
}

async function forceColdWalletIframeEd25519MaterialFromGlobal(input: {
  accountId: string;
}): Promise<{ ok: boolean; reason: string; evidence: WalletIframeEd25519RecordEvidence }> {
  const forceColdMaterial = (window as any).__w3aForceColdEd25519Material;
  if (typeof forceColdMaterial !== 'function') {
    const installError = String((window as any).__w3aReadEd25519EvidenceInstallError || '');
    if (installError) {
      throw new Error(`wallet iframe Ed25519 evidence module failed: ${installError}`);
    }
    throw new Error('wallet iframe cold Ed25519 material helper was not installed');
  }
  return await forceColdMaterial(input);
}

async function forceColdWalletIframeEd25519Material(
  page: Page,
  args: {
    accountId: string;
    budgetStatusBaseUrl: string;
  },
): Promise<Partial<BudgetEvidenceStage>> {
  const frame = findWalletIframeFrame(page);
  if (!frame) {
    return {
      ed25519State: 'diagnostic_error',
      ed25519Reason: 'wallet iframe was not available',
      ed25519BudgetStatus: 'missing_wallet_iframe',
    };
  }
  await ensureWalletIframeEd25519EvidenceModule(page, frame);
  const result = await frame.evaluate(forceColdWalletIframeEd25519MaterialFromGlobal, {
    accountId: args.accountId,
  });
  const budgetEvidence = await readEd25519ServerBudgetEvidence({
    budgetStatusBaseUrl: args.budgetStatusBaseUrl,
    recordEvidence: result.evidence,
  });
  return stripPrivateEd25519Evidence({
    ...result.evidence,
    ...budgetEvidence,
    ...(!result.ok ? { ed25519Reason: result.reason } : {}),
  });
}

function readWalletIframeImportMapDiagnostics(): string {
  const importMapCount = document.querySelectorAll('script[type="importmap"]').length;
  const hasW3aImportMap = Boolean(
    document.querySelector('script[type="importmap"][data-w3a-importmap="1"]'),
  );
  return JSON.stringify({
    href: window.location.href,
    importMapCount,
    hasW3aImportMap,
    headPrefix: document.head?.innerHTML?.slice(0, 500) || '',
  });
}

async function runSharedBudgetEvidence(
  page: Page,
  harness: SealedRefreshHarness,
  args: {
    accountId: string;
    firstLabels?: string[];
    fourthLabels?: string[];
    captureEd25519LaneEvidence?: boolean;
    forceColdEd25519MaterialBeforeFirstSign?: boolean;
    validateSharedBudget?: boolean;
  },
): Promise<BudgetEvidenceResult> {
  const before = await readWebAuthnGetCallCount(page);
  await installEd25519WorkerOperationTrace(page);
  const consoleMessages: string[] = [];
  let ed25519HssRouteCalls = 0;
  const onConsole = (message: ConsoleMessage): void => {
    if (message.type() !== 'error' && message.type() !== 'warning') return;
    consoleMessages.push(`[${message.type()}] ${message.text()}`);
  };
  const onRequest = (request: Request): void => {
    if (isEd25519HssRouteUrl(request.url())) {
      ed25519HssRouteCalls += 1;
    }
  };
  page.on('console', onConsole);
  page.on('request', onRequest);
  const setupResult = await autoConfirmWalletIframeUntil(
    page,
    runSharedBudgetSetup(page, harness, args),
    {
      timeoutMs: 180_000,
      intervalMs: 250,
    },
  );
  if (!setupResult.ok) {
    return {
      ok: false,
      accountId: args.accountId,
      consoleMessages,
      stages: setupResult.stages,
      webauthnGetCounts: {
        before,
        afterUnlock: await readWebAuthnGetCallCount(page),
        afterFirstThreeSigns: await readWebAuthnGetCallCount(page),
        afterFourthSign: await readWebAuthnGetCallCount(page),
      },
      error: setupResult.error,
    };
  }
  let setupStages = setupResult.stages;
  let traceBaseline: Ed25519NoHssTraceBaseline | undefined;
  if (args.forceColdEd25519MaterialBeforeFirstSign) {
    const coldEvidence = await forceColdWalletIframeEd25519Material(page, {
      accountId: args.accountId,
      budgetStatusBaseUrl: harness.baseUrl,
    });
    setupStages = setupResult.stages.map((stage) => ({ ...stage, ...coldEvidence }));
    await resetNearSignerWorkerForColdEd25519Material(page);
    traceBaseline = {
      workerTrace: await readEd25519WorkerOperationTrace(page),
      ed25519HssRouteCalls,
    };
  } else if (args.captureEd25519LaneEvidence) {
    setupStages = await decorateStagesWithEd25519LaneEvidence(page, {
      stages: setupResult.stages,
      accountId: args.accountId,
      budgetStatusBaseUrl: harness.baseUrl,
    });
  }
  const afterUnlock = await readWebAuthnGetCallCount(page);

  const firstThreeLabels = args.firstLabels || ['near-1', 'tempo-1', 'evm-1'];
  const runFirstThreeSigns = (): Promise<{
    ok: boolean;
    stages: BudgetEvidenceStage[];
    error?: string;
  }> =>
    args.captureEd25519LaneEvidence
      ? runEvidenceSignsWithEd25519LaneEvidence(page, {
          accountId: args.accountId,
          labels: firstThreeLabels,
          budgetStatusBaseUrl: harness.baseUrl,
          traceBaseline,
          readEd25519HssRouteCalls: () => ed25519HssRouteCalls,
        })
      : runEvidenceSigns(page, {
          accountId: args.accountId,
          labels: firstThreeLabels,
        });
  const firstThree = args.forceColdEd25519MaterialBeforeFirstSign
    ? await autoConfirmWalletIframeUntil(page, runFirstThreeSigns(), {
        timeoutMs: 180_000,
        intervalMs: 250,
      })
    : await runFirstThreeSigns();
  const afterFirstThreeSigns = await readWebAuthnGetCallCount(page);

  const fourthLabels = args.fourthLabels || ['near-2'];
  const fourth = await autoConfirmWalletIframeUntil(
    page,
    args.captureEd25519LaneEvidence
      ? runEvidenceSignsWithEd25519LaneEvidence(page, {
          accountId: args.accountId,
          labels: fourthLabels,
          budgetStatusBaseUrl: harness.baseUrl,
          traceBaseline,
          readEd25519HssRouteCalls: () => ed25519HssRouteCalls,
        })
      : runEvidenceSigns(page, {
          accountId: args.accountId,
          labels: fourthLabels,
        }),
    {
      timeoutMs: 180_000,
      intervalMs: 250,
    },
  );
  const afterFourthSign = await readWebAuthnGetCallCount(page);
  const stages = [...setupStages, ...firstThree.stages, ...fourth.stages];
  const expectedAfterFirstThreeSigns =
    afterUnlock + (args.forceColdEd25519MaterialBeforeFirstSign ? 1 : 0);
  const baseOk =
    setupResult.ok &&
    firstThree.ok &&
    fourth.ok &&
    afterFirstThreeSigns === expectedAfterFirstThreeSigns &&
    afterFourthSign === afterFirstThreeSigns + 1;
  const baseResult: BudgetEvidenceResult = {
    ok: baseOk,
    accountId: args.accountId,
    consoleMessages,
    stages,
    webauthnGetCounts: {
      before,
      afterUnlock,
      afterFirstThreeSigns,
      afterFourthSign,
    },
  };
  const shouldValidateSharedBudget = args.validateSharedBudget ?? true;
  const evidenceValidation = shouldValidateSharedBudget
    ? validateSharedBudgetEvidenceResult(baseResult)
    : { ok: true as const };
  const ok = baseOk && evidenceValidation.ok;

  return {
    ok,
    accountId: args.accountId,
    consoleMessages,
    stages,
    webauthnGetCounts: {
      before,
      afterUnlock,
      afterFirstThreeSigns,
      afterFourthSign,
    },
    ...(!ok
      ? {
          error: `Budget evidence failed: ${JSON.stringify({
            setupResult,
            firstThree,
            fourth,
            consoleMessages,
            before,
            afterUnlock,
            afterFirstThreeSigns,
            afterFourthSign,
            evidenceError: evidenceValidation.ok ? '' : evidenceValidation.error,
          })}`,
        }
      : {}),
  };
}

function findEvidenceStage(
  stages: BudgetEvidenceResult['stages'],
  label: string,
): BudgetEvidenceResult['stages'][number] | null {
  return stages.find((stage) => stage.label === label) || null;
}

function requireStageEd25519RemainingUses(
  stage: BudgetEvidenceResult['stages'][number] | null,
  label: string,
  expected: number,
): string | null {
  if (!stage) return `Missing evidence stage ${label}`;
  if (stage.ed25519RemainingUses !== expected) {
    return `Expected ${label} ed25519RemainingUses=${expected}, got ${String(
      stage.ed25519RemainingUses,
    )}`;
  }
  return null;
}

function validateSharedBudgetEvidenceResult(
  result: BudgetEvidenceResult,
): { ok: true } | { ok: false; error: string } {
  const setup = findEvidenceStage(result.stages, 'evm_bootstrapped');
  const near1 = findEvidenceStage(result.stages, 'near-1');
  const tempo1 = findEvidenceStage(result.stages, 'tempo-1');
  const evm1 = findEvidenceStage(result.stages, 'evm-1');
  const near2 = findEvidenceStage(result.stages, 'near-2');
  const failures = [
    requireStageEd25519RemainingUses(setup, 'evm_bootstrapped', 3),
    requireStageEd25519RemainingUses(near1, 'near-1', 2),
    requireStageEd25519RemainingUses(tempo1, 'tempo-1', 1),
    requireStageEd25519RemainingUses(evm1, 'evm-1', 0),
  ].filter(Boolean);
  if (!evm1?.ed25519SigningGrantId || !near2?.ed25519ThresholdSessionId) {
    failures.push('Budget evidence is missing Ed25519 grant/session values');
  } else if (evm1.ed25519ThresholdSessionId === near2.ed25519ThresholdSessionId) {
    failures.push('Fourth sign did not mint a fresh threshold session after exhaustion');
  }
  if (failures.length) {
    return { ok: false, error: failures.join('; ') };
  }
  return { ok: true };
}

function validateEd25519RestoreEvidenceResult(
  result: BudgetEvidenceResult,
): { ok: true } | { ok: false; error: string } {
  const setup = findEvidenceStage(result.stages, 'evm_bootstrapped');
  const near1 = findEvidenceStage(result.stages, 'near-1');
  const nep4131 = findEvidenceStage(result.stages, 'nep413-1');
  const delegate1 = findEvidenceStage(result.stages, 'delegate-1');
  const near2 = findEvidenceStage(result.stages, 'near-2');
  const failures = [
    requireStageEd25519RemainingUses(setup, 'evm_bootstrapped', 3),
    requireStageEd25519RemainingUses(near1, 'near-1', 2),
    requireStageEd25519RemainingUses(nep4131, 'nep413-1', 1),
    requireStageEd25519RemainingUses(delegate1, 'delegate-1', 0),
  ].filter(Boolean);
  if (
    !setup?.hasSealedWorkerMaterial ||
    !setup?.hasMaterialBindingDigest ||
    !setup?.hasClientVerifier
  ) {
    failures.push('Ed25519 durable sealed material is missing before lazy restore');
  }
  if (setup?.ed25519State !== 'material_pending' || setup?.hasMaterialHandle) {
    failures.push('Ed25519 setup evidence did not start from cold material_pending state');
  }
  if (
    !near1?.hasSealedWorkerMaterial ||
    !near1?.hasMaterialBindingDigest ||
    !near1?.hasClientVerifier
  ) {
    failures.push('First Ed25519 sign did not preserve durable sealed worker-material evidence');
  }
  if (near1?.ed25519RestoreWorkerMaterialCalls !== 1) {
    failures.push(
      `First Ed25519 sign did not run exactly one RestoreThresholdEd25519WorkerMaterial command; got ${String(
        near1?.ed25519RestoreWorkerMaterialCalls,
      )}; worker requests=${JSON.stringify(
        near1?.ed25519WorkerRequestTypes || {},
      )}; install=${String(near1?.ed25519WorkerTraceInstall || '')}`,
    );
  }
  for (const stage of [near1, nep4131, delegate1]) {
    if (!stage) continue;
    if (stage.ed25519RestoreWorkerMaterialCalls !== 1) {
      failures.push(
        `${stage.label} restore command count drifted from one; got ${String(
          stage.ed25519RestoreWorkerMaterialCalls,
        )}`,
      );
    }
    if (stage.ed25519HssRouteCalls !== 0) {
      failures.push(
        `${stage.label} invoked Ed25519 HSS routes during normal signing; got ${String(
          stage.ed25519HssRouteCalls,
        )}`,
      );
    }
  }
  if (!delegate1?.ed25519SigningGrantId || !near2?.ed25519ThresholdSessionId) {
    failures.push('Ed25519 evidence is missing signing grant or threshold session values');
  } else if (delegate1.ed25519ThresholdSessionId === near2.ed25519ThresholdSessionId) {
    failures.push('Fourth Ed25519 sign did not mint a fresh threshold session after exhaustion');
  }
  if (failures.length) {
    return { ok: false, error: failures.join('; ') };
  }
  return { ok: true };
}

function runSharedBudgetSetup(
  page: Page,
  harness: SealedRefreshHarness,
  args: {
    accountId: string;
  },
): Promise<{ ok: boolean; stages: BudgetEvidenceResult['stages']; error?: string }> {
  return page.evaluate(
    async ({ accountId, keyVersion, relayerUrl, shamirPrimeB64u }) => {
      const stages: BudgetEvidenceResult['stages'] = [];
      const formatEvidenceError = (error: unknown, fallback: string): string => {
        if (error instanceof Error) return error.stack || error.message;
        if (error && typeof error === 'object' && 'message' in error) {
          return String((error as { message?: unknown }).message || fallback);
        }
        return String(error || fallback);
      };
      try {
        const sdkMod = await import('/sdk/esm/SeamsWeb/index.js');
        const { SeamsWeb } = sdkMod as any;
        const confirmationConfig = (): Record<string, unknown> => ({
          uiMode: 'none',
          behavior: 'skipClick',
          autoProceedDelay: 0,
        });
        const labelHex = (label: string): string => {
          const hex = Array.from(new TextEncoder().encode(label))
            .map((byte) => byte.toString(16).padStart(2, '0'))
            .join('');
          return `0x${hex || '00'}`;
        };
        const sessionStage = async (
          seamsForStage: any,
          stageAccountId: string,
          label: string,
          chain?: string,
          kind?: string,
        ): Promise<BudgetEvidenceResult['stages'][number]> => {
          const session = await seamsForStage.auth.getWalletSession(stageAccountId).catch(() => null);
          const remainingUses = Number(session?.signingSession?.remainingUses);
          return {
            label,
            ok: true,
            ...(chain ? { chain } : {}),
            ...(kind ? { kind } : {}),
            sessionStatus: String(session?.signingSession?.status || ''),
            remainingUses: Number.isFinite(remainingUses) ? Math.floor(remainingUses) : null,
            signingGrantId: String(
              (session?.signingSession as Record<string, unknown> | null | undefined)
                ?.signingGrantId || '',
            ),
          };
        };
        let operationalPublicKey = '';
        const signNear = async (seamsForSign: any, label: string): Promise<void> => {
          const signed = await seamsForSign.near.executeAction({
            nearAccount: { accountId },
            receiverId: 'w3a-v1.testnet',
            actionArgs: {
              type: 'FunctionCall',
              methodName: 'set_greeting',
              args: { greeting: `budget-evidence-${label}-${Date.now()}` },
              gas: '30000000000000',
              deposit: '0',
            },
            options: {
              waitUntil: 'EXECUTED_OPTIMISTIC',
              confirmationConfig: confirmationConfig(),
            },
          });
          if (!signed?.success) throw new Error(String(signed?.error || 'NEAR sign failed'));
        };
        const signNep413 = async (seamsForSign: any, label: string): Promise<void> => {
          const signed = await seamsForSign.near.signNEP413Message({
            nearAccount: { accountId },
            params: {
              message: `budget-evidence-${label}-${Date.now()}`,
              recipient: 'example.localhost',
              state: label,
            },
            options: {
              confirmationConfig: confirmationConfig(),
            },
          });
          if (!signed?.success) throw new Error(String(signed?.error || 'NEP-413 sign failed'));
        };
        const signDelegate = async (seamsForSign: any, label: string): Promise<void> => {
          const delegatePublicKey = operationalPublicKey;
          if (!delegatePublicKey) throw new Error('missing operational public key for delegate');
          const delegate = {
            senderId: accountId,
            receiverId: 'w3a-v1.testnet',
            actions: [{ type: 'Transfer', amount: '1' }],
            nonce: Math.floor(Date.now() / 1000),
            maxBlockHeight: 999_999,
            publicKey: delegatePublicKey,
          };
          const signed = await seamsForSign.near.signDelegateAction({
            nearAccount: { accountId },
            delegate,
            options: {
              confirmationConfig: confirmationConfig(),
            },
          });
          if (!signed?.signedDelegate || !signed?.hash) {
            throw new Error(String(signed?.error || 'delegate sign failed'));
          }
        };
        const signTempo = async (seamsForSign: any, label: string): Promise<void> => {
          const signed = await seamsForSign.tempo.signTempo({
            walletSession: {
              walletId: accountId,
              walletSessionUserId: accountId,
            },
            chainTarget: {
              kind: 'tempo',
              chainId: 42431,
              networkSlug: 'tempo-moderato',
            },
            request: {
              chain: 'tempo',
              kind: 'tempoTransaction',
              senderSignatureAlgorithm: 'secp256k1',
              tx: {
                chainId: 42431,
                maxPriorityFeePerGas: 1n,
                maxFeePerGas: 2n,
                gasLimit: 21_000n,
                calls: [{ to: `0x${'11'.repeat(20)}`, value: 0n, input: labelHex(label) }],
                accessList: [],
                nonceKey: 0n,
                validBefore: null,
                validAfter: null,
                feePayerSignature: { kind: 'none' },
                aaAuthorizationList: [],
              },
            },
            options: { confirmationConfig: confirmationConfig() },
          });
          if (!signed || signed.kind !== 'tempoTransaction') {
            throw new Error('Tempo sign failed');
          }
        };
        const signEvm = async (seamsForSign: any, label: string): Promise<void> => {
          const signed = await seamsForSign.tempo.signTempo({
            walletSession: {
              walletId: accountId,
              walletSessionUserId: accountId,
            },
            chainTarget: {
              kind: 'evm',
              namespace: 'eip155',
              chainId: 11155111,
              networkSlug: 'ethereum-sepolia',
            },
            request: {
              chain: 'evm',
              kind: 'eip1559',
              senderSignatureAlgorithm: 'secp256k1',
              tx: {
                chainId: 11155111,
                maxPriorityFeePerGas: 1_500_000_000n,
                maxFeePerGas: 3_000_000_000n,
                gasLimit: 21_000n,
                to: `0x${'22'.repeat(20)}`,
                value: 0n,
                data: labelHex(label),
                accessList: [],
              },
            },
            options: { confirmationConfig: confirmationConfig() },
          });
          if (!signed || signed.kind !== 'eip1559' || signed.chain !== 'evm') {
            throw new Error('EVM sign failed');
          }
        };
        const seams = new SeamsWeb({
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayerAccount: 'web3-authn-v4.testnet',
          relayer: { url: relayerUrl },
          registration: {
            mode: 'managed',
            environmentId: String(
              (globalThis as any).__w3aManagedRegistration?.environmentId || '',
            ),
            publishableKey: String(
              (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
            ),
          },
          signingSessionDefaults: {
            ttlMs: 120_000,
            remainingUses: 3,
          },
          routerAb: {
            normalSigning: {
              mode: 'enabled',
              signingWorkerId: 'local-signing-worker',
            },
          },
          signingSessionPersistenceMode: 'sealed_refresh_v1',
          signingSessionSeal: {
            keyVersion,
            shamirPrimeB64u,
          },
          iframeWallet: {
            walletOrigin: 'https://wallet.example.localhost',
            servicePath: '/wallet-service',
            sdkBasePath: '/sdk',
            rpIdOverride: 'example.localhost',
          },
        });
        seams.preferences.setConfirmationConfig(confirmationConfig());
        const evidenceWorkerTransport = (seams as any).signingEngine?.signerWorkerManager?.workerTransport;
        (globalThis as any).__w3aEd25519WorkerTraceInstall = JSON.stringify({
          hasSigningEngine: Boolean((seams as any).signingEngine),
          hasSignerWorkerManager: Boolean((seams as any).signingEngine?.signerWorkerManager),
          hasWorkerTransport: Boolean(evidenceWorkerTransport),
          hasRequestOperation: typeof evidenceWorkerTransport?.requestOperation === 'function',
          hasResetWorker: typeof evidenceWorkerTransport?.resetWorker === 'function',
          installed: true,
        });
        (globalThis as any).__routerAbBudgetEvidence = {
          resetNearSignerWorker: (): void => {
            const workerTransport = (seams as any).signingEngine?.signerWorkerManager?.workerTransport;
            if (typeof workerTransport?.resetWorker === 'function') {
              workerTransport.resetWorker('nearSigner');
            }
          },
          sign: async (labels: string[]): Promise<{ ok: boolean; stages: BudgetEvidenceResult['stages']; error?: string }> => {
            const signStages: BudgetEvidenceResult['stages'] = [];
            try {
              for (const label of labels) {
                if (label.startsWith('near')) {
                  await signNear(seams, label);
                  signStages.push(await sessionStage(seams, accountId, label, 'near', 'nearAction'));
                  continue;
                }
                if (label.startsWith('nep413')) {
                  await signNep413(seams, label);
                  signStages.push(
                    await sessionStage(seams, accountId, label, 'near-nep413', 'nep413'),
                  );
                  continue;
                }
                if (label.startsWith('delegate')) {
                  await signDelegate(seams, label);
                  signStages.push(
                    await sessionStage(
                      seams,
                      accountId,
                      label,
                      'near-delegate',
                      'nearDelegate',
                    ),
                  );
                  continue;
                }
                if (label.startsWith('tempo')) {
                  await signTempo(seams, label);
                  signStages.push(
                    await sessionStage(seams, accountId, label, 'tempo', 'tempoTransaction'),
                  );
                  continue;
                }
                if (label.startsWith('evm')) {
                  await signEvm(seams, label);
                  signStages.push(await sessionStage(seams, accountId, label, 'evm', 'eip1559'));
                  continue;
                }
                throw new Error(`unknown evidence sign label: ${label}`);
              }
              return { ok: true, stages: signStages };
            } catch (error: unknown) {
              signStages.push(
                await sessionStage(seams, accountId, 'sign_failure_diagnostic').catch(
                  (diagnosticError: unknown) => ({
                    label: 'sign_failure_diagnostic',
                    ok: false,
                    error:
                      diagnosticError &&
                      typeof diagnosticError === 'object' &&
                      'message' in diagnosticError
                        ? String((diagnosticError as { message?: unknown }).message || '')
                        : String(diagnosticError || 'diagnostic failed'),
                  }),
                ),
              );
              return {
                ok: false,
                stages: signStages,
                error: formatEvidenceError(error, 'budget evidence sign failed'),
              };
            }
          },
        };

        const registration = await seams.registration.registerPasskey(accountId, {
          signerOptions: {
            tempo: {
              enabled: false,
              signingSession: { kind: 'jwt', ttlMs: 120_000, remainingUses: 3 },
            },
            evm: {
              enabled: false,
              signingSession: { kind: 'jwt', ttlMs: 120_000, remainingUses: 3 },
            },
          },
          confirmationConfig: confirmationConfig(),
        });
        if (!registration?.success) {
          throw new Error(String(registration?.error || 'registration failed'));
        }
        operationalPublicKey = String(registration.operationalPublicKey || '');
        stages.push(await sessionStage(seams, accountId, 'registered'));

        const login = await seams.auth.unlock(accountId, {
          unlockSelection: { mode: 'ed25519_and_ecdsa', ed25519: true, ecdsa: true },
          session: {
            kind: 'jwt',
            relayUrl: relayerUrl,
            exchange: { type: 'passkey_assertion' },
          },
          signingSession: { ttlMs: 120_000, remainingUses: 3 },
        });
        if (!login?.success) {
          throw new Error(String(login?.error || 'unlock failed'));
        }
        stages.push(await sessionStage(seams, accountId, 'unlocked'));

        const tempoBootstrap = await seams.tempo.bootstrapEcdsaSession({
          kind: 'reuse_warm_ecdsa_bootstrap',
          walletSession: {
            walletId: accountId,
            walletSessionUserId: accountId,
          },
          chainTarget: {
            kind: 'tempo',
            chainId: 42431,
            networkSlug: 'tempo-moderato',
          },
          relayerUrl,
          ttlMs: 120_000,
          remainingUses: 3,
        });
        if (!tempoBootstrap?.thresholdEcdsaKeyRef?.ecdsaThresholdKeyId) {
          throw new Error('Tempo threshold ECDSA bootstrap did not return ecdsaThresholdKeyId');
        }

        const evmBootstrap = await seams.evm.bootstrapEcdsaSession({
          kind: 'reuse_warm_ecdsa_bootstrap',
          walletSession: {
            walletId: accountId,
            walletSessionUserId: accountId,
          },
          chainTarget: {
            kind: 'evm',
            namespace: 'eip155',
            chainId: 11155111,
            networkSlug: 'ethereum-sepolia',
          },
          relayerUrl,
          ttlMs: 120_000,
          remainingUses: 3,
        });
        if (!evmBootstrap?.thresholdEcdsaKeyRef?.ecdsaThresholdKeyId) {
          throw new Error('EVM threshold ECDSA bootstrap did not return ecdsaThresholdKeyId');
        }
        stages.push(await sessionStage(seams, accountId, 'evm_bootstrapped'));

        return { ok: true, stages };
      } catch (error: unknown) {
        return {
          ok: false,
          stages,
          error: formatEvidenceError(error, 'budget evidence setup failed'),
        };
      }
    },
    {
      accountId: args.accountId,
      keyVersion: TEST_KEY_VERSION,
      relayerUrl: harness.relayerUrl,
      shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
    },
  );
}

function runEvidenceSigns(
  page: Page,
  args: {
    accountId: string;
    labels: string[];
  },
): Promise<{ ok: boolean; stages: BudgetEvidenceResult['stages']; error?: string }> {
  return page.evaluate(async ({ accountId, labels }) => {
    const harness = (globalThis as any).__routerAbBudgetEvidence;
    if (!harness || typeof harness.sign !== 'function') {
      return {
        ok: false,
        stages: [],
        error: `missing budget evidence SeamsWeb instance for ${accountId}`,
      };
    }
    return await harness.sign(labels);
  }, args);
}
