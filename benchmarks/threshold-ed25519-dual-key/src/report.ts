import fs from 'node:fs/promises';
import path from 'node:path';

export type Stats = {
  count: number;
  minMs: number;
  maxMs: number;
  meanMs: number;
  p50Ms: number;
  p95Ms: number;
};

export type RegistrationBenchmarkSummary = {
  operationalEnrollment: {
    clientShareMs: Stats;
    relayKeygenMs: Stats;
    totalMs: Stats;
  };
  dualKeyBootstrap: {
    recoveryPreflightMs: Stats;
    bootstrapPackageMs: Stats;
    totalMs: Stats;
  };
  delta: {
    meanMs: number;
    meanPercent: number;
  };
};

export type ExportFlowBenchmarkSummary = {
  paillier: {
    keygenMs: Stats;
    encryptMs: Stats;
    addConstMs: Stats;
    decryptMs: Stats;
  };
  payloadSizes: {
    publicKeyRawBytes: number;
    publicKeyB64uChars: number;
    clientCiphertextRawBytes: number;
    clientCiphertextB64uChars: number;
    serverCiphertextRawBytes: number;
    serverCiphertextB64uChars: number;
    requestCryptoRawBytes: number;
    responseCryptoRawBytes: number;
    requestJsonBytes: number;
    responseJsonBytes: number;
    roundTrips: number;
  };
};

export type NodeBenchmarkSummary = {
  generatedAt: string;
  runtime: {
    node: string;
    platform: NodeJS.Platform;
    arch: string;
  };
  config: {
    registrationIterations: number;
    paillierIterations: number;
    paillierBits: number;
  };
  registration: RegistrationBenchmarkSummary;
  exportFlow: ExportFlowBenchmarkSummary;
};

export type BrowserBenchmarkRun = {
  browserName: string;
  browserVersion: string;
  userAgent: string;
  platform: string;
  config: {
    registrationIterations: number;
    paillierIterations: number;
    paillierBits: number;
  };
  registration: RegistrationBenchmarkSummary;
  exportFlow: ExportFlowBenchmarkSummary;
};

export type BrowserBenchmarkSummary = {
  generatedAt: string;
  runs: BrowserBenchmarkRun[];
};

export function percentile(values: number[], q: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * q) - 1));
  return sorted[idx] || 0;
}

export function roundMs(value: number): number {
  return Math.round(value * 1000) / 1000;
}

export function buildStats(values: number[]): Stats {
  if (values.length === 0) {
    return { count: 0, minMs: 0, maxMs: 0, meanMs: 0, p50Ms: 0, p95Ms: 0 };
  }
  const sum = values.reduce((acc, value) => acc + value, 0);
  return {
    count: values.length,
    minMs: roundMs(Math.min(...values)),
    maxMs: roundMs(Math.max(...values)),
    meanMs: roundMs(sum / values.length),
    p50Ms: roundMs(percentile(values, 0.5)),
    p95Ms: roundMs(percentile(values, 0.95)),
  };
}

export function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).length;
}

export function tsRunId(): string {
  const d = new Date();
  const yyyy = d.getUTCFullYear();
  const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(d.getUTCDate()).padStart(2, '0');
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const min = String(d.getUTCMinutes()).padStart(2, '0');
  const ss = String(d.getUTCSeconds()).padStart(2, '0');
  return `${yyyy}${mm}${dd}-${hh}${min}${ss}Z`;
}

export async function ensureDir(dir: string): Promise<void> {
  await fs.mkdir(dir, { recursive: true });
}

export async function loadJsonFile<T>(filePath: string): Promise<T | null> {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export async function findLatestRunArtifact(
  outDir: string,
  fileName: string,
): Promise<string | null> {
  const entries = await fs.readdir(outDir, { withFileTypes: true }).catch(() => []);
  const runDirs = entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort()
    .reverse();
  for (const runDir of runDirs) {
    const candidate = path.join(outDir, runDir, fileName);
    try {
      await fs.access(candidate);
      return candidate;
    } catch {}
  }
  return null;
}

function renderRegistrationSection(summary: RegistrationBenchmarkSummary): string {
  return `Operational enrollment baseline:
- client verifying-share derive mean/p95: ${summary.operationalEnrollment.clientShareMs.meanMs} ms / ${summary.operationalEnrollment.clientShareMs.p95Ms} ms
- relay keygen mean/p95: ${summary.operationalEnrollment.relayKeygenMs.meanMs} ms / ${summary.operationalEnrollment.relayKeygenMs.p95Ms} ms
- total mean/p95: ${summary.operationalEnrollment.totalMs.meanMs} ms / ${summary.operationalEnrollment.totalMs.p95Ms} ms

Dual-key bootstrap:
- recovery-share preflight mean/p95: ${summary.dualKeyBootstrap.recoveryPreflightMs.meanMs} ms / ${summary.dualKeyBootstrap.recoveryPreflightMs.p95Ms} ms
- bootstrap package derive mean/p95: ${summary.dualKeyBootstrap.bootstrapPackageMs.meanMs} ms / ${summary.dualKeyBootstrap.bootstrapPackageMs.p95Ms} ms
- total mean/p95: ${summary.dualKeyBootstrap.totalMs.meanMs} ms / ${summary.dualKeyBootstrap.totalMs.p95Ms} ms

Delta versus operational enrollment:
- mean delta: ${summary.delta.meanMs} ms (${summary.delta.meanPercent}%)`;
}

function renderExportSection(summary: ExportFlowBenchmarkSummary): string {
  return `Paillier latency:
- keygen mean/p95: ${summary.paillier.keygenMs.meanMs} ms / ${summary.paillier.keygenMs.p95Ms} ms
- encrypt mean/p95: ${summary.paillier.encryptMs.meanMs} ms / ${summary.paillier.encryptMs.p95Ms} ms
- add-constant mean/p95: ${summary.paillier.addConstMs.meanMs} ms / ${summary.paillier.addConstMs.p95Ms} ms
- decrypt mean/p95: ${summary.paillier.decryptMs.meanMs} ms / ${summary.paillier.decryptMs.p95Ms} ms

Payload sizes:
- public key raw / b64u: ${summary.payloadSizes.publicKeyRawBytes} bytes / ${summary.payloadSizes.publicKeyB64uChars} chars
- request ciphertext raw / b64u: ${summary.payloadSizes.clientCiphertextRawBytes} bytes / ${summary.payloadSizes.clientCiphertextB64uChars} chars
- response ciphertext raw / b64u: ${summary.payloadSizes.serverCiphertextRawBytes} bytes / ${summary.payloadSizes.serverCiphertextB64uChars} chars
- request crypto payload raw: ${summary.payloadSizes.requestCryptoRawBytes} bytes
- response crypto payload raw: ${summary.payloadSizes.responseCryptoRawBytes} bytes
- request JSON payload: ${summary.payloadSizes.requestJsonBytes} bytes
- response JSON payload: ${summary.payloadSizes.responseJsonBytes} bytes
- round trips: ${summary.payloadSizes.roundTrips}`;
}

function renderBrowserRuns(browserSummary: BrowserBenchmarkSummary): string {
  if (!browserSummary.runs.length) return '';
  return browserSummary.runs
    .map((run) => {
      return `### ${run.browserName}

Runtime:
- version: ${run.browserVersion}
- platform: ${run.platform}
- user agent: ${run.userAgent}

Config:
- registration iterations: ${run.config.registrationIterations}
- Paillier iterations: ${run.config.paillierIterations}
- Paillier modulus bits: ${run.config.paillierBits}

Registration

${renderRegistrationSection(run.registration)}

Recovery Export

${renderExportSection(run.exportFlow)}`;
    })
    .join('\n\n');
}

export function buildMarkdown(
  nodeSummary: NodeBenchmarkSummary,
  browserSummary?: BrowserBenchmarkSummary | null,
): string {
  const browserSection =
    browserSummary && browserSummary.runs.length > 0
      ? `
## Browser Runtime

Generated: ${browserSummary.generatedAt}

${renderBrowserRuns(browserSummary)}
`
      : '';

  return `# Threshold Ed25519 Dual-Key Benchmark

Generated: ${nodeSummary.generatedAt}

Runtime:
- node: ${nodeSummary.runtime.node}
- platform: ${nodeSummary.runtime.platform}
- arch: ${nodeSummary.runtime.arch}

Config:
- registration iterations: ${nodeSummary.config.registrationIterations}
- Paillier iterations: ${nodeSummary.config.paillierIterations}
- Paillier modulus bits: ${nodeSummary.config.paillierBits}

## Registration

${renderRegistrationSection(nodeSummary.registration)}

## Recovery Export

${renderExportSection(nodeSummary.exportFlow)}${browserSection}
`;
}
