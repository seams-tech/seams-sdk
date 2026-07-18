import { WorkerEntrypoint } from "cloudflare:workers";

import RustDeriverB from "../build/deriver-b-rpc/index.js";

const BENCHMARK_URL = "https://ed25519-yao-b.internal/benchmark/activation";
const DEPLOYMENT_ID_HEADER = "x-ed25519-yao-deployment-id";
const DERIVER_A_COLO_HEADER = "x-ed25519-yao-a-colo";
const SESSION_HEADER = "x-ed25519-yao-session";

function requireReadableByteStream(value) {
  if (!(value instanceof ReadableStream)) {
    throw new TypeError("Deriver B RPC requires an A-to-B ReadableStream");
  }
  return value;
}

function requireWritableStream(value) {
  if (!(value instanceof WritableStream)) {
    throw new TypeError("Deriver B RPC requires a B-to-A WritableStream");
  }
  return value;
}

function requireWireString(value, label, pattern) {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new TypeError(`Deriver B RPC ${label} is invalid`);
  }
  return value;
}

function optionalColo(value) {
  if (value === null) {
    return null;
  }
  return requireWireString(value, "Deriver A colo", /^[A-Z]{3}$/);
}

function buildDeriverBRequest(aToB, deploymentId, session, deriverAColo) {
  const headers = new Headers({
    "cache-control": "no-store",
    "content-type": "application/octet-stream",
    [DEPLOYMENT_ID_HEADER]: deploymentId,
    [SESSION_HEADER]: session,
  });
  if (deriverAColo !== null) {
    headers.set(DERIVER_A_COLO_HEADER, deriverAColo);
  }
  return new Request(BENCHMARK_URL, {
    method: "POST",
    headers,
    body: aToB,
    duplex: "half",
  });
}

async function abortWritable(writable, error) {
  try {
    await writable.abort(error);
  } catch {
    // The stream may already be errored by the RPC transport.
  }
}

async function requireSuccessfulResponse(response, writable) {
  if (response.ok && response.body !== null) {
    return response.body;
  }
  const message = `Deriver B Rust role rejected the RPC ceremony with HTTP ${response.status}`;
  const error = new Error(message);
  await abortWritable(writable, error);
  throw error;
}

function describeUnknownError(error) {
  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      stack: error.stack,
    };
  }
  return { value: String(error) };
}

async function pipeRpcResponse(responseBody, writable) {
  try {
    await responseBody.pipeTo(writable);
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "ed25519_yao_rpc_response_pipe_failed",
        error: describeUnknownError(error),
      }),
    );
    throw error;
  }
}

export default class DeriverBRpcEntrypoint extends WorkerEntrypoint {
  fetch() {
    return Response.json(
      {
        benchmark_only: true,
        error_code: "YAOS_AB_ENDPOINT_NOT_FOUND",
        ok: false,
        topology: "same-account-service-binding-rpc-streams",
      },
      { status: 404 },
    );
  }

  async runCeremony(aToB, bToA, deploymentId, session, deriverAColo) {
    const readable = requireReadableByteStream(aToB);
    const writable = requireWritableStream(bToA);
    const bindingDeploymentId = requireWireString(
      deploymentId,
      "deployment ID",
      /^[0-9a-f]{32}$/,
    );
    const bindingSession = requireWireString(session, "session", /^[0-9a-f]{64}$/);
    const bindingDeriverAColo = optionalColo(deriverAColo);
    const request = buildDeriverBRequest(
      readable,
      bindingDeploymentId,
      bindingSession,
      bindingDeriverAColo,
    );
    const response = await RustDeriverB.prototype.fetch.call(this, request);
    const responseBody = await requireSuccessfulResponse(response, writable);
    await pipeRpcResponse(responseBody, writable);
    return "ok";
  }
}
