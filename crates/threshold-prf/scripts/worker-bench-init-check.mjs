import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(scriptDir, "..", "..", "..");
const workerBenchDir = join(repoRoot, "crates", "threshold-prf", "worker-bench");
const vendorWasmPath = join(
  workerBenchDir,
  "vendor",
  "threshold_prf",
  "threshold_prf_bg.wasm",
);

if (!existsSync(vendorWasmPath)) {
  throw new Error(
    `missing Worker benchmark WASM package at ${vendorWasmPath}; run just threshold-prf-worker-bench-build first`,
  );
}

const port = await reserveLocalPort();
const baseUrl = `http://127.0.0.1:${port}`;
const wrangler = spawn(
  "pnpm",
  [
    "exec",
    "wrangler",
    "dev",
    "--ip",
    "127.0.0.1",
    "--port",
    String(port),
    "--local-protocol",
    "http",
    "--log-level",
    "error",
    "--show-interactive-dev-session=false",
  ],
  {
    cwd: workerBenchDir,
    env: {
      ...process.env,
      CI: "1",
      NO_COLOR: "1",
      WRANGLER_SEND_METRICS: "false",
    },
    stdio: ["ignore", "pipe", "pipe"],
  },
);

const logs = [];
let wranglerExitCode;
let wranglerExitSignal;
const wranglerExited = new Promise((resolve) => {
  wrangler.on("exit", (code, signal) => {
    wranglerExitCode = code;
    wranglerExitSignal = signal;
    resolve();
  });
});

wrangler.stdout.on("data", (chunk) => appendLog(chunk));
wrangler.stderr.on("data", (chunk) => appendLog(chunk));

try {
  await waitForWorker(baseUrl);

  const first = await fetchBench(baseUrl);
  const second = await fetchBench(baseUrl);

  requireBenchResponse("first bench response", first);
  requireBenchResponse("second bench response", second);

  if (first.body.wasmWasReadyBeforeRequest !== false) {
    throw new Error(
      `expected first /bench request to initialize WASM, got wasmWasReadyBeforeRequest=${String(
        first.body.wasmWasReadyBeforeRequest,
      )}`,
    );
  }

  if (second.body.wasmWasReadyBeforeRequest !== true) {
    throw new Error(
      `expected second /bench request to reuse initialized WASM, got wasmWasReadyBeforeRequest=${String(
        second.body.wasmWasReadyBeforeRequest,
      )}`,
    );
  }

  console.log(`Worker WASM init guard passed at ${baseUrl}`);
  console.log(
    `first wasmReady=${String(
      first.body.wasmWasReadyBeforeRequest,
    )}, second wasmReady=${String(second.body.wasmWasReadyBeforeRequest)}`,
  );
} finally {
  await stopWrangler();
}

async function fetchBench(baseUrl) {
  const url = new URL("/bench?iterations=3&warmup=0", baseUrl);
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${url} returned HTTP ${response.status}`);
  }
  return {
    url: String(url),
    body: await response.json(),
  };
}

function requireBenchResponse(label, response) {
  const body = response.body;
  if (body.route !== "bench" || body.ok !== true) {
    throw new Error(`${label} was not a successful bench payload`);
  }
  if (!Array.isArray(body.results) || body.results.length === 0) {
    throw new Error(`${label} did not include benchmark results`);
  }
}

async function waitForWorker(baseUrl) {
  const deadline = Date.now() + 30_000;
  const url = new URL("/", baseUrl);
  while (Date.now() < deadline) {
    if (wranglerExitCode !== undefined || wranglerExitSignal !== undefined) {
      throw new Error(`wrangler exited before readiness\n${recentLogs()}`);
    }
    try {
      const response = await fetch(url);
      if (response.ok) {
        await response.arrayBuffer();
        return;
      }
    } catch {
      // Retry until local Wrangler finishes startup.
    }
    await sleep(250);
  }
  throw new Error(`timed out waiting for local Wrangler at ${baseUrl}\n${recentLogs()}`);
}

async function stopWrangler() {
  if (wranglerExitCode !== undefined || wranglerExitSignal !== undefined) {
    return;
  }
  wrangler.kill("SIGTERM");
  await Promise.race([wranglerExited, sleep(5_000)]);
  if (wranglerExitCode === undefined && wranglerExitSignal === undefined) {
    wrangler.kill("SIGKILL");
    await wranglerExited;
  }
}

function appendLog(chunk) {
  for (const line of String(chunk).split(/\r?\n/)) {
    if (line.trim().length === 0) {
      continue;
    }
    logs.push(line);
    if (logs.length > 80) {
      logs.shift();
    }
  }
}

function recentLogs() {
  return logs.join("\n");
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function reserveLocalPort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        server.close();
        reject(new Error("failed to reserve a local TCP port"));
        return;
      }
      const { port } = address;
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(port);
      });
    });
  });
}
