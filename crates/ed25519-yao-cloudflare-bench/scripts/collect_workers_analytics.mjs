import { pathToFileURL } from "node:url";

import {
  BoundaryError,
  parseAnalyticsWindow,
  parseDeploymentEnvironment,
  requireAnalyticsToken,
} from "./deployment_boundary.mjs";
import {
  deploymentReceiptEvidence,
  deploymentReceiptPath,
  readDeploymentReceipt,
} from "./deployment_receipt.mjs";

const GRAPHQL_ENDPOINT = "https://api.cloudflare.com/client/v4/graphql";
const GRAPHQL_TIMEOUT_MS = 30_000;
const MAX_GRAPHQL_RESPONSE_BYTES = 1_048_576;
export const SAMPLED_MEMORY_GATE_BYTES = 96 * 1024 * 1024;
export const MEMORY_EVIDENCE_CLASSIFICATION =
  "cloudflare-reservoir-sampled-shared-isolate-operational-proxy";
export const PLATFORM_COPY_ACCOUNTING = "unavailable";

export const WORKERS_CORE_QUERY = `
query YaosAbWorkersCore(
  $accountTag: string!
  $scriptName: string!
  $datetimeStart: string!
  $datetimeEnd: string!
) {
  viewer {
    accounts(filter: { accountTag: $accountTag }) {
      aggregate: workersInvocationsAdaptive(
        limit: 1
        filter: {
          scriptName: $scriptName
          datetime_geq: $datetimeStart
          datetime_leq: $datetimeEnd
        }
      ) {
        sum {
          requests
          errors
          subrequests
          clientDisconnects
          cpuTimeUs
          requestDuration
          wallTime
          responseBodySize
        }
        quantiles {
          cpuTimeP50
          cpuTimeP90
          cpuTimeP95
          cpuTimeP99
          cpuTimeP999
          requestDurationP50
          requestDurationP90
          requestDurationP95
          requestDurationP99
          requestDurationP999
          wallTimeP50
          wallTimeP90
          wallTimeP95
          wallTimeP99
          wallTimeP999
        }
      }
      byColo: workersInvocationsAdaptive(
        limit: 1000
        filter: {
          scriptName: $scriptName
          datetime_geq: $datetimeStart
          datetime_leq: $datetimeEnd
        }
      ) {
        sum {
          requests
          errors
        }
        dimensions {
          scriptName
          coloCode
          status
        }
      }
    }
  }
}`;

export const WORKERS_MEMORY_QUERY = `
query YaosAbWorkersMemory(
  $accountTag: string!
  $scriptName: string!
  $datetimeStart: string!
  $datetimeEnd: string!
) {
  viewer {
    accounts(filter: { accountTag: $accountTag }) {
      workersInvocationsAdaptive(
        limit: 1
        filter: {
          scriptName: $scriptName
          datetime_geq: $datetimeStart
          datetime_leq: $datetimeEnd
        }
      ) {
        quantiles {
          memoryUsageBytesP50
          memoryUsageBytesP90
          memoryUsageBytesP99
          memoryUsageBytesP999
        }
      }
    }
  }
}`;

function graphqlVariables(accountId, scriptName, window) {
  return Object.freeze({
    accountTag: accountId,
    scriptName,
    datetimeStart: window.start,
    datetimeEnd: window.end,
  });
}

function graphqlErrorDescriptor(error) {
  const code = error?.extensions?.code;
  const path = Array.isArray(error?.path) ? error.path.join(".") : null;
  return Object.freeze({
    code: typeof code === "string" ? code : "GRAPHQL_ERROR",
    path,
  });
}

function graphqlErrorDescriptors(errors) {
  const output = [];
  for (const error of errors) {
    output.push(graphqlErrorDescriptor(error));
  }
  return output;
}

async function readBoundedJson(response) {
  if (response.body === null) {
    throw new BoundaryError("GraphQL response has no body");
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const next = await reader.read();
    if (next.done) {
      break;
    }
    total += next.value.byteLength;
    if (total > MAX_GRAPHQL_RESPONSE_BYTES) {
      await reader.cancel("bounded GraphQL response exceeded");
      throw new BoundaryError("GraphQL response exceeds the bounded JSON limit");
    }
    chunks.push(next.value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder().decode(merged));
  } catch {
    throw new BoundaryError("GraphQL response is not valid JSON");
  }
}

function transportFailure(kind, httpStatus = null) {
  return Object.freeze({
    available: false,
    failure: Object.freeze({ kind, http_status: httpStatus, errors: [] }),
  });
}

function graphqlFailure(httpStatus, errors) {
  return Object.freeze({
    available: false,
    failure: Object.freeze({
      kind: "graphql-schema-or-plan",
      http_status: httpStatus,
      errors: graphqlErrorDescriptors(errors),
    }),
  });
}

async function queryGraphql(accountId, token, query, scriptName, window, fetchImplementation) {
  let response;
  try {
    response = await fetchImplementation(GRAPHQL_ENDPOINT, {
      method: "POST",
      headers: Object.freeze({
        accept: "application/json",
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      }),
      body: JSON.stringify({ query, variables: graphqlVariables(accountId, scriptName, window) }),
      redirect: "error",
      signal: AbortSignal.timeout(GRAPHQL_TIMEOUT_MS),
    });
  } catch {
    return transportFailure("fetch");
  }
  let payload;
  try {
    payload = await readBoundedJson(response);
  } catch {
    return transportFailure("invalid-response", response.status);
  }
  if (!response.ok) {
    return transportFailure("http", response.status);
  }
  if (Array.isArray(payload.errors) && payload.errors.length > 0) {
    return graphqlFailure(response.status, payload.errors);
  }
  const accounts = payload?.data?.viewer?.accounts;
  if (!Array.isArray(accounts) || accounts.length !== 1) {
    return transportFailure("unexpected-account-scope", response.status);
  }
  return Object.freeze({ available: true, account: accounts[0] });
}

function normalizeQuantileMicroseconds(quantiles) {
  if (quantiles === null || typeof quantiles !== "object") {
    return null;
  }
  const milliseconds = {};
  for (const [name, value] of Object.entries(quantiles)) {
    milliseconds[name] = typeof value === "number" ? value / 1_000 : null;
  }
  return Object.freeze({ microseconds: quantiles, milliseconds: Object.freeze(milliseconds) });
}

function normalizeCore(queryResult) {
  if (!queryResult.available) {
    return queryResult;
  }
  const aggregateRows = queryResult.account.aggregate;
  const byColoRows = queryResult.account.byColo;
  if (!Array.isArray(aggregateRows) || !Array.isArray(byColoRows)) {
    return transportFailure("unexpected-core-shape");
  }
  const aggregate = aggregateRows[0] ?? null;
  return Object.freeze({
    available: true,
    sum: aggregate?.sum ?? null,
    quantiles: normalizeQuantileMicroseconds(aggregate?.quantiles ?? null),
    by_colo: byColoRows,
  });
}

function normalizeMemory(queryResult) {
  if (!queryResult.available) {
    return queryResult;
  }
  const rows = queryResult.account.workersInvocationsAdaptive;
  if (!Array.isArray(rows)) {
    return transportFailure("unexpected-memory-shape");
  }
  const aggregate = rows[0] ?? null;
  return Object.freeze({
    available: true,
    quantiles_bytes: aggregate?.quantiles ?? null,
    gate_evidence:
      "P999 is the strongest supported sampled isolate-memory percentile; it is not an exact maximum.",
  });
}

function exceededMemoryCount(core) {
  if (!core.available || !Array.isArray(core.by_colo)) {
    return null;
  }
  let count = 0;
  for (const row of core.by_colo) {
    const status = row?.dimensions?.status;
    const requests = row?.sum?.requests;
    if (
      typeof status !== "string" ||
      status.length === 0 ||
      !Number.isSafeInteger(requests) ||
      requests < 0
    ) {
      return null;
    }
    if (status === "exceededMemory") {
      count += requests;
    }
  }
  return count;
}

function sampledP999(memory) {
  if (!memory.available) {
    return null;
  }
  const value = memory.quantiles_bytes?.memoryUsageBytesP999;
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

export function buildSampledMemoryGate(core, memory) {
  const exceededCount = exceededMemoryCount(core);
  const p999 = sampledP999(memory);
  let result;
  if (exceededCount !== null && exceededCount > 0) {
    result = "fail";
  } else if (exceededCount === null || p999 === null) {
    result = "unavailable";
  } else {
    result = p999 < SAMPLED_MEMORY_GATE_BYTES ? "pass" : "fail";
  }
  return Object.freeze({
    threshold_bytes: SAMPLED_MEMORY_GATE_BYTES,
    comparison: "memoryUsageBytesP999 < threshold_bytes",
    memory_usage_bytes_p999: p999,
    exceeded_memory_status_count: exceededCount,
    exceeded_memory_status_observed: exceededCount === null ? null : exceededCount > 0,
    result,
    limitation:
      "P999 is adaptively sampled and cannot prove an exact maximum; any exceededMemory status forces failure.",
  });
}

export async function collectRoleAnalytics(
  role,
  accountId,
  scriptName,
  token,
  window,
  fetchImplementation = fetch,
) {
  const coreRaw = await queryGraphql(
    accountId,
    token,
    WORKERS_CORE_QUERY,
    scriptName,
    window,
    fetchImplementation,
  );
  const memoryRaw = await queryGraphql(
    accountId,
    token,
    WORKERS_MEMORY_QUERY,
    scriptName,
    window,
    fetchImplementation,
  );
  const core = normalizeCore(coreRaw);
  const memory = normalizeMemory(memoryRaw);
  return Object.freeze({
    role,
    script_name: scriptName,
    core,
    memory,
    sampled_memory_gate: buildSampledMemoryGate(core, memory),
  });
}

export async function collectWorkersAnalytics(
  configuration,
  receipt,
  window,
  tokens,
  fetchImplementation = fetch,
) {
  const a = await collectRoleAnalytics(
    "deriver-a",
    configuration.a.accountId,
    configuration.a.scriptName,
    tokens.a,
    window,
    fetchImplementation,
  );
  const b = await collectRoleAnalytics(
    "deriver-b",
    configuration.b.accountId,
    configuration.b.scriptName,
    tokens.b,
    window,
    fetchImplementation,
  );
  return Object.freeze({
    benchmark: "phase9b-cloudflare-workers-analytics",
    benchmark_only: true,
    security_claim: "none",
    topology: configuration.expectedTopologyLabel,
    region_label: configuration.regionLabel,
    deployment: deploymentReceiptEvidence(receipt),
    generated_at: new Date().toISOString(),
    window,
    dataset: "workersInvocationsAdaptive",
    adaptive_sampling: true,
    memory_evidence_classification: MEMORY_EVIDENCE_CLASSIFICATION,
    exact_peak_proven: false,
    platform_copy_accounting: PLATFORM_COPY_ACCOUNTING,
    units: Object.freeze({
      cpu_time: "microseconds (plus derived milliseconds)",
      wall_time: "microseconds (plus derived milliseconds)",
      request_duration: "microseconds (plus derived milliseconds)",
      memory: "bytes",
    }),
    a,
    b,
  });
}

function isMainModule() {
  return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
}

async function main() {
  const configuration = parseDeploymentEnvironment(process.env);
  const receipt = readDeploymentReceipt(
    deploymentReceiptPath(process.env),
    configuration,
    true,
  );
  const window = parseAnalyticsWindow(process.env);
  const tokens = Object.freeze({
    a: requireAnalyticsToken(process.env, "a", false),
    b: requireAnalyticsToken(process.env, "b", configuration.topology === "one-account"),
  });
  const report = await collectWorkersAnalytics(configuration, receipt, window, tokens);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

function handleFatal(error) {
  const message = error instanceof BoundaryError ? error.message : "Workers analytics collection failed";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
}

if (isMainModule()) {
  main().catch(handleFatal);
}
