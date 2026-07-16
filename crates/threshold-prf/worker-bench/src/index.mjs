import initThresholdPrfWasm, {
  init_threshold_prf,
  threshold_prf_derive_router_ab_ecdsa_derivation_y_relayer,
} from "../vendor/threshold_prf/threshold_prf.js";
import thresholdPrfWasmModule from "../vendor/threshold_prf/threshold_prf_bg.wasm";

const DEFAULT_ITERATIONS = 1_000;
const DEFAULT_WARMUP = 20;
const MAX_ITERATIONS = 100_000;
const ISOLATE_STARTED_AT_MS = Date.now();
const ISOLATE_STARTED_AT_ISO = new Date(ISOLATE_STARTED_AT_MS).toISOString();

const THRESHOLD_PRF_THRESHOLD = 2;
const THRESHOLD_PRF_SHARE_COUNT = 3;
const SHARE_WIRE_1 = hexToBytes(
  "0001d73847ea1a0888265782eb6998f3d905b8275fa4e5fda6556ddacc3b28741702",
);
const SHARE_WIRE_2 = hexToBytes(
  "0002b3ee4da8422ffeebb66bd0b55afb5d072f55aa324698a89c0a8b234042fd6c0f",
);

const APPLICATION_BINDING_DIGEST = hexToBytes(
  "7f6ec48989273bf014547956927059547a8d659391735b7a6c1958bc6f0cf8f4",
);

let firstRequestInIsolate = true;
let wasmReadyPromise;
let wasmInitResult;

export default {
  async fetch(request) {
    const requestStartedAt = performance.now();
    const url = new URL(request.url);
    const isFirstRequestInIsolate = firstRequestInIsolate;
    firstRequestInIsolate = false;

    if (url.pathname === "/noop") {
      return jsonResponse({
        ok: true,
        route: "noop",
        isolateStartedAtIso: ISOLATE_STARTED_AT_ISO,
        firstRequestInIsolate: isFirstRequestInIsolate,
        requestElapsedMs: performance.now() - requestStartedAt,
      });
    }

    if (url.pathname === "/bench") {
      const wasmWasReadyBeforeRequest = wasmReadyPromise !== undefined;
      const initResult = await ensureWasmInitialized();
      const iterations = parseBoundedInteger(
        url.searchParams.get("iterations"),
        DEFAULT_ITERATIONS,
        1,
        MAX_ITERATIONS,
      );
      const warmup = parseBoundedInteger(
        url.searchParams.get("warmup"),
        DEFAULT_WARMUP,
        0,
        MAX_ITERATIONS,
      );

      const results = [
        measureSync("dispatch_loop_noop", iterations, warmup, benchmarkNoop),
        measureSync(
          "threshold_prf_derive_router_ab_ecdsa_derivation_y_relayer",
          iterations,
          warmup,
          benchmarkEcdsaYServer,
        ),
      ];

      return jsonResponse({
        ok: true,
        route: "bench",
        isolateStartedAtIso: ISOLATE_STARTED_AT_ISO,
        firstRequestInIsolate: isFirstRequestInIsolate,
        wasmWasReadyBeforeRequest,
        wasmInitElapsedMs: initResult.elapsedMs,
        iterations,
        warmup,
        results,
        requestElapsedMs: performance.now() - requestStartedAt,
      });
    }

    return jsonResponse({
      ok: true,
      route: "index",
      endpoints: ["/noop", "/bench?iterations=1000&warmup=20"],
      isolateStartedAtIso: ISOLATE_STARTED_AT_ISO,
      firstRequestInIsolate: isFirstRequestInIsolate,
      requestElapsedMs: performance.now() - requestStartedAt,
    });
  },
};

async function ensureWasmInitialized() {
  if (wasmReadyPromise === undefined) {
    wasmReadyPromise = (async () => {
      const startedAt = performance.now();
      await initThresholdPrfWasm(thresholdPrfWasmModule);
      init_threshold_prf();
      wasmInitResult = {
        elapsedMs: performance.now() - startedAt,
      };
      return wasmInitResult;
    })();
  }
  return wasmReadyPromise;
}

function measureSync(name, iterations, warmup, fn) {
  let checksum = 0;
  for (let index = 0; index < warmup; index += 1) {
    checksum ^= fn(index);
  }

  const startedAt = performance.now();
  for (let index = 0; index < iterations; index += 1) {
    checksum ^= fn(index);
  }
  const elapsedMs = performance.now() - startedAt;

  return {
    name,
    iterations,
    elapsedMs,
    msPerOp: elapsedMs / iterations,
    usPerOp: (elapsedMs * 1_000) / iterations,
    checksum,
  };
}

function benchmarkNoop(index) {
  return index & 0xff;
}

function benchmarkEcdsaYServer() {
  const output = threshold_prf_derive_router_ab_ecdsa_derivation_y_relayer(
    THRESHOLD_PRF_THRESHOLD,
    THRESHOLD_PRF_SHARE_COUNT,
    shareWires(),
    APPLICATION_BINDING_DIGEST,
  );
  return output[0];
}

function shareWires() {
  const out = new Uint8Array(SHARE_WIRE_1.length + SHARE_WIRE_2.length);
  out.set(SHARE_WIRE_1, 0);
  out.set(SHARE_WIRE_2, SHARE_WIRE_1.length);
  return out;
}

function parseBoundedInteger(raw, fallback, min, max) {
  if (raw === null || raw === "") {
    return fallback;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    return fallback;
  }
  return parsed;
}

function hexToBytes(hex) {
  if (hex.length % 2 !== 0) {
    throw new Error("hex fixture must have even length");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let offset = 0; offset < hex.length; offset += 2) {
    bytes[offset / 2] = Number.parseInt(hex.slice(offset, offset + 2), 16);
  }
  return bytes;
}

function jsonResponse(payload) {
  return new Response(`${JSON.stringify(payload, null, 2)}\n`, {
    headers: {
      "content-type": "application/json; charset=utf-8",
    },
  });
}
