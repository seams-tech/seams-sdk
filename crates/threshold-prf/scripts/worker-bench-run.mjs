import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const crateDir = join(scriptDir, "..");
const defaultOutDir = join(crateDir, "target", "worker-bench");

const args = parseArgs(process.argv.slice(2));
if (args.url === undefined) {
  console.error(
    "usage: node crates/threshold-prf/scripts/worker-bench-run.mjs <worker-url> [--samples 5] [--iterations 1000] [--warmup 20] [--out path]",
  );
  process.exit(2);
}

const samples = boundedInteger(args.samples, 5, 1, 1_000);
const iterations = boundedInteger(args.iterations, 1_000, 1, 100_000);
const warmup = boundedInteger(args.warmup, 20, 0, 100_000);
const workerUrl = normalizeUrl(args.url);
const outPath =
  args.out ??
  join(defaultOutDir, `results-${new Date().toISOString().replaceAll(":", "-")}.json`);

const responses = [];
for (let index = 0; index < samples; index += 1) {
  responses.push(await fetchJson(new URL("/noop", workerUrl)));
  responses.push(
    await fetchJson(
      new URL(`/bench?iterations=${iterations}&warmup=${warmup}`, workerUrl),
    ),
  );
}

const payload = {
  date: new Date().toISOString(),
  runtime: `node ${process.version}`,
  workerUrl,
  samples,
  iterations,
  warmup,
  responses,
};

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, `${JSON.stringify(payload, null, 2)}\n`);
console.log(`wrote ${outPath}`);
printSummary(responses);

async function fetchJson(url) {
  const startedAt = performance.now();
  const response = await fetch(url);
  const elapsedMs = performance.now() - startedAt;
  if (!response.ok) {
    throw new Error(`${url} returned HTTP ${response.status}`);
  }
  return {
    url: String(url),
    clientElapsedMs: elapsedMs,
    body: await response.json(),
  };
}

function printSummary(responses) {
  const benchRows = [];
  for (const response of responses) {
    if (response.body.route !== "bench") {
      continue;
    }
    for (const result of response.body.results) {
      benchRows.push({
        benchmark: result.name,
        "worker us/op": result.usPerOp.toFixed(3),
        "client ms": response.clientElapsedMs.toFixed(3),
        first: response.body.firstRequestInIsolate,
        wasmReady: response.body.wasmWasReadyBeforeRequest,
      });
    }
  }
  console.table(benchRows);
}

function parseArgs(rawArgs) {
  const parsed = {};
  for (let index = 0; index < rawArgs.length; index += 1) {
    const arg = rawArgs[index];
    if (!arg.startsWith("--")) {
      parsed.url = arg;
      continue;
    }
    const key = arg.slice(2);
    const value = rawArgs[index + 1];
    index += 1;
    parsed[key] = value;
  }
  return parsed;
}

function boundedInteger(raw, fallback, min, max) {
  if (raw === undefined) {
    return fallback;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`expected integer in [${min}, ${max}], got ${raw}`);
  }
  return parsed;
}

function normalizeUrl(raw) {
  const url = new URL(raw);
  url.pathname = "/";
  url.search = "";
  url.hash = "";
  return String(url);
}
