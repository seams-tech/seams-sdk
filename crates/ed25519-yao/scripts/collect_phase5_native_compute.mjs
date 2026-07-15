import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

const SAMPLE_COUNT = 21;
const SOCKET_TIMEOUT_MS = 15_000;
const CEREMONY_P95_LIMIT_MS = 250;
const COMBINED_CPU_P95_LIMIT_MS = 150;
const MEMORY_LIMIT_BYTES = 96 * 1024 * 1024;
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const ROLE_BINARY = resolve(ROOT, "crates/ed25519-yao/target/release/benchmark_phase5_role");
const CASES = Object.freeze([
  Object.freeze({ family: "activation", profile: "128k" }),
  Object.freeze({ family: "export", profile: "128k" }),
]);

function compareNumbers(left, right) {
  return left - right;
}

function percentile(values, numerator, denominator) {
  const sorted = [...values].sort(compareNumbers);
  const rank = Math.max(0, Math.ceil((numerator * sorted.length) / denominator) - 1);
  return sorted[rank];
}

function summarize(values) {
  return Object.freeze({
    min: Math.min(...values),
    p50: percentile(values, 50, 100),
    p95: percentile(values, 95, 100),
    p99: percentile(values, 99, 100),
    max: Math.max(...values),
  });
}

async function readStream(stream) {
  let text = "";
  for await (const chunk of stream) {
    text += chunk.toString("utf8");
  }
  return text;
}

function spawnRole(definition, role, controlSocket, tableSocket, session) {
  const child = spawn(
    "/usr/bin/time",
    [
      "-lp",
      ROLE_BINARY,
      definition.family,
      definition.profile,
      role,
      controlSocket,
      tableSocket,
      session,
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  return Object.freeze({
    child,
    exit: once(child, "exit"),
    stdout: readStream(child.stdout),
    stderr: readStream(child.stderr),
  });
}

async function pathExists(path) {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

async function waitForSockets(processRecord, controlSocket, tableSocket) {
  const deadline = performance.now() + SOCKET_TIMEOUT_MS;
  while (!(await pathExists(controlSocket)) || !(await pathExists(tableSocket))) {
    if (processRecord.child.exitCode !== null) {
      throw new Error("Deriver B exited before binding native benchmark sockets");
    }
    if (performance.now() >= deadline) {
      processRecord.child.kill();
      throw new Error("Deriver B socket setup timed out");
    }
    await delay(5);
  }
}

function requiredMatch(text, expression, field) {
  const match = expression.exec(text);
  if (match === null) {
    throw new Error(`missing /usr/bin/time field: ${field}`);
  }
  return Number(match[1]);
}

function parseResourceUsage(stderr) {
  const userSeconds = requiredMatch(stderr, /^user ([0-9.]+)$/m, "user");
  const systemSeconds = requiredMatch(stderr, /^sys ([0-9.]+)$/m, "sys");
  const maximumResidentBytes = requiredMatch(
    stderr,
    /^\s*([0-9]+)\s+maximum resident set size$/m,
    "maximum resident set size",
  );
  return Object.freeze({
    user_ms: userSeconds * 1_000,
    system_ms: systemSeconds * 1_000,
    cpu_ms: (userSeconds + systemSeconds) * 1_000,
    maximum_resident_bytes: maximumResidentBytes,
  });
}

async function finishRole(role, processRecord) {
  const [code, signal] = await processRecord.exit;
  const stdout = await processRecord.stdout;
  const stderr = await processRecord.stderr;
  if (code !== 0 || signal !== null) {
    throw new Error(`Deriver ${role} failed: ${stderr}`);
  }
  if (!stdout.includes("|")) {
    throw new Error(`Deriver ${role} emitted malformed benchmark evidence`);
  }
  return parseResourceUsage(stderr);
}

async function runCeremony(definition) {
  const directory = await mkdtemp(join(tmpdir(), "eyac-"));
  const controlSocket = join(directory, "c.sock");
  const tableSocket = join(directory, "t.sock");
  const session = randomBytes(32).toString("hex");
  const started = performance.now();
  try {
    const b = spawnRole(definition, "b", controlSocket, tableSocket, session);
    await waitForSockets(b, controlSocket, tableSocket);
    const a = spawnRole(definition, "a", controlSocket, tableSocket, session);
    const aUsage = await finishRole("A", a);
    const bUsage = await finishRole("B", b);
    return Object.freeze({
      wall_ms: performance.now() - started,
      deriver_a: aUsage,
      deriver_b: bUsage,
      combined_cpu_ms: aUsage.cpu_ms + bUsage.cpu_ms,
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function select(samples, selector) {
  const values = [];
  for (const sample of samples) {
    values.push(selector(sample));
  }
  return values;
}

function selectWall(sample) {
  return sample.wall_ms;
}

function selectACpu(sample) {
  return sample.deriver_a.cpu_ms;
}

function selectBCpu(sample) {
  return sample.deriver_b.cpu_ms;
}

function selectCombinedCpu(sample) {
  return sample.combined_cpu_ms;
}

function selectARss(sample) {
  return sample.deriver_a.maximum_resident_bytes;
}

function selectBRss(sample) {
  return sample.deriver_b.maximum_resident_bytes;
}

function buildCaseReport(definition, samples) {
  const warm = samples.slice(1);
  return Object.freeze({
    family: definition.family,
    profile: definition.profile,
    sample_count: samples.length,
    warm_sample_count: warm.length,
    wall_ms: summarize(select(warm, selectWall)),
    deriver_a_cpu_ms: summarize(select(warm, selectACpu)),
    deriver_b_cpu_ms: summarize(select(warm, selectBCpu)),
    combined_cpu_ms: summarize(select(warm, selectCombinedCpu)),
    deriver_a_maximum_resident_bytes: summarize(select(samples, selectARss)),
    deriver_b_maximum_resident_bytes: summarize(select(samples, selectBRss)),
  });
}

async function collectCase(definition) {
  const samples = [];
  for (let index = 0; index < SAMPLE_COUNT; index += 1) {
    samples.push(await runCeremony(definition));
  }
  return buildCaseReport(definition, samples);
}

function validateActivationBudget(report) {
  if (
    report.wall_ms.p95 > CEREMONY_P95_LIMIT_MS ||
    report.combined_cpu_ms.p95 > COMBINED_CPU_P95_LIMIT_MS ||
    report.deriver_a_maximum_resident_bytes.max >= MEMORY_LIMIT_BYTES ||
    report.deriver_b_maximum_resident_bytes.max >= MEMORY_LIMIT_BYTES
  ) {
    throw new Error("local native activation compute budget exceeded");
  }
}

async function main() {
  const cases = [];
  for (const definition of CASES) {
    cases.push(await collectCase(definition));
  }
  validateActivationBudget(cases[0]);
  const report = Object.freeze({
    schema: "ed25519_yao_phase5_local_native_compute_v1",
    recorded_at: new Date().toISOString(),
    host: `${process.platform}-${process.arch}`,
    sample_policy: "one warmup followed by twenty measured sequential ceremonies",
    cpu_scope: "/usr/bin/time user plus system time per independent role process",
    memory_scope: "/usr/bin/time maximum resident set size per independent role process",
    cases,
  });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

function handleFatal(error) {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exitCode = 1;
}

main().catch(handleFatal);
