import initThresholdPrfWasm, {
  init_threshold_prf,
  threshold_prf_derive_ecdsa_hss_y_relayer,
  threshold_prf_derive_ed25519_hss_server_inputs,
} from "../vendor/threshold_prf/threshold_prf.js";
import thresholdPrfWasmModule from "../vendor/threshold_prf/threshold_prf_bg.wasm";

const DEFAULT_ITERATIONS = 1_000;
const DEFAULT_WARMUP = 20;
const MAX_ITERATIONS = 100_000;
const ISOLATE_STARTED_AT_MS = Date.now();
const ISOLATE_STARTED_AT_ISO = new Date(ISOLATE_STARTED_AT_MS).toISOString();

const SHARE_WIRE_1 = hexToBytes(
  "011ba5f9c2f4003d409a9358a20b40b37eb32a28daacc5676a468b64a203c1e303",
);
const SHARE_WIRE_3 = hexToBytes(
  "032ef917611df8a3dae0fa9bd6545044d7a43843ed8dda35ce0fb4646ea093f707",
);

const ECDSA_CONTEXT = Object.freeze({
  walletId: "alice.near",
  rpId: "wallet.example.test",
  ecdsaThresholdKeyId: "ecdsa-alpha",
  signingRootId: "project-alpha:dev",
  signingRootVersion: "root-v1",
  keyPurpose: "wallet",
  keyVersion: "v1",
});

const ED25519_CONTEXT = Object.freeze({
  signingRootId: "project-alpha:dev",
  accountId: "alice.near",
  keyPurpose: "wallet",
  keyVersion: "v1",
  participantIds: Object.freeze([1, 2]),
  derivationVersion: 1,
});

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
          "threshold_prf_derive_ecdsa_hss_y_relayer",
          iterations,
          warmup,
          benchmarkEcdsaYRelayer,
        ),
        measureSync(
          "threshold_prf_derive_ed25519_hss_server_inputs",
          iterations,
          warmup,
          benchmarkEd25519ServerInputs,
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

function benchmarkEcdsaYRelayer() {
  const output = threshold_prf_derive_ecdsa_hss_y_relayer(
    shareWire1(),
    shareWire3(),
    ECDSA_CONTEXT.walletId,
    ECDSA_CONTEXT.rpId,
    ECDSA_CONTEXT.ecdsaThresholdKeyId,
    ECDSA_CONTEXT.signingRootId,
    ECDSA_CONTEXT.signingRootVersion,
    ECDSA_CONTEXT.keyPurpose,
    ECDSA_CONTEXT.keyVersion,
  );
  return output[0];
}

function benchmarkEd25519ServerInputs() {
  const output = threshold_prf_derive_ed25519_hss_server_inputs(
    shareWire1(),
    shareWire3(),
    ED25519_CONTEXT.signingRootId,
    ED25519_CONTEXT.accountId,
    ED25519_CONTEXT.keyPurpose,
    ED25519_CONTEXT.keyVersion,
    new Uint32Array(ED25519_CONTEXT.participantIds),
    ED25519_CONTEXT.derivationVersion,
  );
  return output.yRelayerB64u.charCodeAt(0) ^ output.tauRelayerB64u.charCodeAt(0);
}

function shareWire1() {
  return new Uint8Array(SHARE_WIRE_1);
}

function shareWire3() {
  return new Uint8Array(SHARE_WIRE_3);
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
