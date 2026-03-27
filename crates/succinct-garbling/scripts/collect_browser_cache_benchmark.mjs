#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";

const DEFAULT_DEBUG_PORT = 9222;
const DEFAULT_SERVER_ORIGIN = "http://127.0.0.1:8765";
const DEFAULT_PAGE_PATH = "/indexeddb_cache_benchmark.html";
const DEFAULT_BUNDLE_PATH = "generated/bundle.json";
const DEFAULT_TIMEOUT_MS = 120_000;

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const debugPort = args.debugPort ?? DEFAULT_DEBUG_PORT;
  const serverOrigin = args.serverOrigin ?? DEFAULT_SERVER_ORIGIN;
  const pagePath = args.pagePath ?? DEFAULT_PAGE_PATH;
  const bundlePath = args.bundlePath ?? DEFAULT_BUNDLE_PATH;
  const timeoutMs = args.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const pageUrl = new URL(pagePath, ensureTrailingSlash(serverOrigin));
  const chromeOrigin = new URL(`http://127.0.0.1:${debugPort}`);

  const newPageResponse = await fetchText(
    new URL(`/json/new?${encodeURIComponent(pageUrl.href)}`, chromeOrigin),
    { method: "PUT" },
  );
  if (!newPageResponse.ok) {
    throw new Error(
      `failed to create Chrome page via remote debugging port ${debugPort}: ${newPageResponse.status} ${newPageResponse.text}`,
    );
  }

  const pageInfo = JSON.parse(newPageResponse.text);
  const cdp = await connectCdp(pageInfo.webSocketDebuggerUrl);

  try {
    await cdp.send("Page.enable");
    await cdp.send("Runtime.enable");
    await cdp.send("Network.enable");
    await cdp.send("Page.navigate", { url: pageUrl.href });

    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const readyState = await evalExpr(cdp, "document.readyState");
      if (readyState === "complete") {
        break;
      }
      await sleep(250);
    }

    await evalExpr(
      cdp,
      `(async () => {
        document.getElementById("bundle-path").value = ${JSON.stringify(bundlePath)};
        document.getElementById("run-button").click();
        return true;
      })()`,
    );

    let status = "";
    let reportText = "";
    while (Date.now() < deadline) {
      status = await evalExpr(cdp, `document.getElementById("status").textContent`);
      reportText = await evalExpr(cdp, `document.getElementById("json-output").textContent`);

      if (status === "Benchmark complete." && reportText && reportText !== "No report yet.") {
        break;
      }
      if (String(status).startsWith("Benchmark failed:")) {
        throw new Error(status);
      }
      await sleep(500);
    }

    if (!reportText || reportText === "No report yet.") {
      throw new Error(`benchmark did not complete within ${timeoutMs}ms`);
    }

    const report = JSON.parse(reportText);
    if (args.outputPath) {
      await fs.mkdir(path.dirname(args.outputPath), { recursive: true });
      await fs.writeFile(args.outputPath, `${JSON.stringify(report, null, 2)}\n`);
    }

    const consoleMessages = cdp.getConsoleMessages();
    const browserExecutor = report.browser_cpu_executor ?? null;
    const browserDdhHiddenEval = report.browser_ddh_hidden_eval ?? null;
    const browserWebGpuProbe = report.browser_webgpu_probe ?? null;
    const summary = {
      status,
      page_url: pageUrl.href,
      bundle_path: bundlePath,
      output_path: args.outputPath ?? null,
      browser_cpu_available: Boolean(browserExecutor?.available),
      browser_cpu_mean_ns:
        browserExecutor?.execution_latency_ns?.mean ?? null,
      browser_cpu_ns_per_curve_cost_unit:
        browserExecutor?.latency_ns_per_curve_cost_unit?.mean ?? null,
      browser_cpu_checksum: browserExecutor?.output_checksum_hex ?? null,
      browser_ddh_available: Boolean(browserDdhHiddenEval?.available),
      browser_ddh_mean_ns:
        browserDdhHiddenEval?.execution_latency_ns?.mean ?? null,
      browser_ddh_ns_per_curve_cost_unit:
        browserDdhHiddenEval?.latency_ns_per_curve_cost_unit?.mean ?? null,
      browser_ddh_round_mean_ns:
        browserDdhHiddenEval?.stage_timings_ns?.round_core?.mean ?? null,
      browser_ddh_schedule_mean_ns:
        browserDdhHiddenEval?.stage_timings_ns?.message_schedule?.mean ?? null,
      browser_ddh_schedule_accumulation_mean_ns:
        browserDdhHiddenEval?.substage_timings_ns?.message_schedule_accumulation?.mean ?? null,
      browser_ddh_probe_total_hidden_eval_ns:
        browserDdhHiddenEval?.probe_total_hidden_eval_ns ?? null,
      browser_ddh_estimated_js_wasm_gap_mean_ns:
        browserDdhHiddenEval?.estimated_js_wasm_gap_ns?.mean ?? null,
      browser_ddh_detailed_result_duration_ns:
        browserDdhHiddenEval?.detailed_result_duration_ns ?? null,
      browser_ddh_evaluate_duration_ns:
        browserDdhHiddenEval?.evaluate_duration_ns ?? null,
      browser_ddh_ot_open_join_duration_ns:
        browserDdhHiddenEval?.ot_open_join_duration_ns ?? null,
      browser_ddh_ot_branch_key_derivation_duration_ns:
        browserDdhHiddenEval?.ot_branch_key_derivation_duration_ns ?? null,
      browser_ddh_ot_branch_decrypt_duration_ns:
        browserDdhHiddenEval?.ot_branch_decrypt_duration_ns ?? null,
      browser_ddh_ot_point_scalar_reconstruction_duration_ns:
        browserDdhHiddenEval?.ot_point_scalar_reconstruction_duration_ns ?? null,
      browser_ddh_ot_commitment_verification_duration_ns:
        browserDdhHiddenEval?.ot_commitment_verification_duration_ns ?? null,
      browser_ddh_server_input_open_duration_ns:
        browserDdhHiddenEval?.server_input_open_duration_ns ?? null,
      browser_ddh_server_input_share_duration_ns:
        browserDdhHiddenEval?.server_input_share_duration_ns ?? null,
      browser_ddh_server_input_commitment_duration_ns:
        browserDdhHiddenEval?.server_input_commitment_duration_ns ?? null,
      browser_ddh_server_input_transcript_duration_ns:
        browserDdhHiddenEval?.server_input_transcript_duration_ns ?? null,
      browser_ddh_server_input_seal_duration_ns:
        browserDdhHiddenEval?.server_input_seal_duration_ns ?? null,
      browser_ddh_output_sealing_finalization_duration_ns:
        browserDdhHiddenEval?.output_sealing_finalization_duration_ns ?? null,
      browser_ddh_result_assembly_duration_ns:
        browserDdhHiddenEval?.result_assembly_duration_ns ?? null,
      browser_ddh_output_open_duration_ns:
        browserDdhHiddenEval?.output_open_duration_ns ?? null,
      browser_ddh_public_key_duration_ns:
        browserDdhHiddenEval?.public_key_duration_ns ?? null,
      browser_ddh_detailed_total_duration_ns:
        browserDdhHiddenEval?.detailed_total_duration_ns ?? null,
      browser_ddh_reference_match:
        browserDdhHiddenEval?.reference_match ?? null,
      browser_ddh_round_temp1_mean_ns:
        browserDdhHiddenEval?.substage_timings_ns?.round_temp1?.mean ?? null,
      browser_ddh_round_temp2_mean_ns:
        browserDdhHiddenEval?.substage_timings_ns?.round_temp2?.mean ?? null,
      browser_ddh_probe_results:
        browserDdhHiddenEval?.probe_results ?? null,
      browser_ddh_public_key:
        browserDdhHiddenEval?.output_public_key_hex ?? null,
      browser_console_messages: consoleMessages,
      browser_webgpu_available: Boolean(browserWebGpuProbe?.available),
      browser_webgpu_recode_mean_ns:
        browserWebGpuProbe?.subkernel_timings_ns?.digit_recode_v0?.mean ?? null,
      browser_webgpu_window_mean_ns:
        browserWebGpuProbe?.subkernel_timings_ns?.window_bucket_accumulate_v0?.mean ?? null,
      browser_webgpu_reduce_mean_ns:
        browserWebGpuProbe?.subkernel_timings_ns?.bucket_reduce_v0?.mean ?? null,
      browser_webgpu_bucket_mean_ns:
        browserWebGpuProbe?.bucket_pipeline_timings_ns?.mean ?? null,
      browser_webgpu_dependency_mean_ns:
        browserWebGpuProbe?.subkernel_timings_ns?.dependency_merge_normalize_v0?.mean ?? null,
      browser_webgpu_mean_ns:
        browserWebGpuProbe?.execution_latency_ns?.mean ?? null,
      browser_webgpu_ns_per_proxy_unit:
        browserWebGpuProbe?.proxy_latency_ns_per_curve_cost_unit?.mean ?? null,
      browser_webgpu_dominant_subkernel:
        browserWebGpuProbe?.dominant_subkernel_kind ?? null,
      browser_webgpu_checksum: browserWebGpuProbe?.output_checksum_hex ?? null,
    };

    console.log(JSON.stringify(summary, null, 2));
  } finally {
    try {
      await cdp.send("Page.close");
    } catch {
      // Ignore tab-close failures during teardown.
    }
    cdp.close();
  }
}

function parseArgs(argv) {
  const parsed = {
    debugPort: null,
    serverOrigin: null,
    pagePath: null,
    bundlePath: null,
    outputPath: null,
    timeoutMs: null,
  };

  for (let idx = 0; idx < argv.length; ) {
    const arg = argv[idx];
    switch (arg) {
      case "--debug-port":
        parsed.debugPort = parseInteger(readValue(argv, idx, "--debug-port"), "--debug-port");
        idx += 2;
        break;
      case "--server-origin":
        parsed.serverOrigin = readValue(argv, idx, "--server-origin");
        idx += 2;
        break;
      case "--page-path":
        parsed.pagePath = readValue(argv, idx, "--page-path");
        idx += 2;
        break;
      case "--bundle-path":
        parsed.bundlePath = readValue(argv, idx, "--bundle-path");
        idx += 2;
        break;
      case "--output":
        parsed.outputPath = readValue(argv, idx, "--output");
        idx += 2;
        break;
      case "--timeout-ms":
        parsed.timeoutMs = parseInteger(readValue(argv, idx, "--timeout-ms"), "--timeout-ms");
        idx += 2;
        break;
      case "--help":
      case "-h":
        printUsageAndExit(0);
        break;
      default:
        throw new Error(`unknown argument: ${arg}\n\n${usage()}`);
    }
  }

  return parsed;
}

function readValue(argv, idx, flag) {
  const value = argv[idx + 1];
  if (!value) {
    throw new Error(`missing value for ${flag}\n\n${usage()}`);
  }
  return value;
}

function parseInteger(value, flag) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) {
    throw new Error(`invalid ${flag} value: ${value}`);
  }
  return parsed;
}

function usage() {
  return [
    "Usage: collect_browser_cache_benchmark.mjs [options]",
    "",
    "Options:",
    "  --debug-port <n>       Chrome remote debugging port (default: 9222)",
    "  --server-origin <url>  Local benchmark server origin (default: http://127.0.0.1:8765)",
    "  --page-path <path>     Benchmark page path (default: /indexeddb_cache_benchmark.html)",
    "  --bundle-path <path>   Bundle path relative to the page (default: generated/bundle.json)",
    "  --output <path>        Write the full benchmark JSON report to disk",
    "  --timeout-ms <n>       Timeout for the browser run (default: 120000)",
  ].join("\n");
}

function printUsageAndExit(code) {
  process.stdout.write(`${usage()}\n`);
  process.exit(code);
}

async function connectCdp(webSocketUrl) {
  const socket = new WebSocket(webSocketUrl);
  const pending = new Map();
  const consoleMessages = [];
  let nextId = 1;

  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });

  socket.addEventListener("message", (event) => {
    const message = JSON.parse(String(event.data));
    if (!message.id) {
      if (message.method === "Runtime.consoleAPICalled") {
        consoleMessages.push({
          type: message.params?.type ?? "log",
          args: (message.params?.args ?? []).map((arg) =>
            arg.value ?? arg.description ?? arg.unserializableValue ?? "<unavailable>",
          ),
        });
      }
      return;
    }
    const handler = pending.get(message.id);
    if (!handler) {
      return;
    }
    pending.delete(message.id);
    if (message.error) {
      handler.reject(new Error(message.error.message));
    } else {
      handler.resolve(message.result);
    }
  });

  socket.addEventListener("close", () => {
    for (const handler of pending.values()) {
      handler.reject(new Error("CDP socket closed"));
    }
    pending.clear();
  });

  return {
    async send(method, params = {}) {
      const id = nextId;
      nextId += 1;
      socket.send(JSON.stringify({ id, method, params }));
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
      });
    },
    close() {
      socket.close();
    },
    getConsoleMessages() {
      return [...consoleMessages];
    },
  };
}

async function evalExpr(cdp, expression) {
  const result = await cdp.send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  if (result.exceptionDetails) {
    throw new Error(`page evaluation failed: ${JSON.stringify(result.exceptionDetails)}`);
  }
  return result.result?.value;
}

async function fetchText(url, init) {
  const response = await fetch(url, init);
  const text = await response.text();
  return { ok: response.ok, status: response.status, text };
}

function ensureTrailingSlash(url) {
  return url.endsWith("/") ? url : `${url}/`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exit(1);
});
