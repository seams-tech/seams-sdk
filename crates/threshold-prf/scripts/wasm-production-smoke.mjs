import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(scriptDir, "..", "..", "..");
const crateDir = join(scriptDir, "..");
const packageDir = join(crateDir, "worker-bench", "vendor", "threshold_prf");

run("node", [join(scriptDir, "worker-bench-build.mjs")]);

const wasm = await import(pathToFileURL(join(packageDir, "threshold_prf.js")));
await wasm.default({
  module_or_path: readFileSync(join(packageDir, "threshold_prf_bg.wasm")),
});

const protocolCorpus = JSON.parse(
  readFileSync(join(crateDir, "fixtures", "protocol-t-of-n.json"), "utf8"),
);
const wireCorpus = JSON.parse(
  readFileSync(join(crateDir, "fixtures", "protocol-wire.json"), "utf8"),
);

let checkedOutputs = 0;
let checkedRejections = 0;

if ("threshold_prf_combine_partials" in wasm) {
  throw new Error("unverified partial combine must not be exported by production WASM");
}

const hssVector = protocolCorpus.vectors.find(
  (vector) => vector.purpose === "ecdsa-hss/y_server" && vector.policy.threshold === 2,
);
if (!hssVector) {
  throw new Error("missing ecdsa-hss threshold-prf smoke vector");
}
const hssShareWiresById = new Map(hssVector.shares.map((share) => [share.id, share]));
const hssIds = hssVector.threshold_outputs[0].ids;
const hssShareWires = shareWiresForIds(hssShareWiresById, hssIds);
const reversedHssShareWires = shareWiresForIds(hssShareWiresById, hssIds.toReversed());

const ecdsaOutput = wasm.threshold_prf_derive_ecdsa_hss_y_server(
  hssVector.policy.threshold,
  hssVector.policy.share_count,
  hssShareWires,
  "alice.near",
  "wallet.example.test",
  "ecdsa-alpha",
  "project-alpha",
  "root-v1",
  "wallet",
  "v1",
);
assertByteLength(ecdsaOutput, 32, "ecdsa-hss y_server");
assertSameBytes(
  ecdsaOutput,
  wasm.threshold_prf_derive_ecdsa_hss_y_server(
    hssVector.policy.threshold,
    hssVector.policy.share_count,
    reversedHssShareWires,
    "alice.near",
    "wallet.example.test",
    "ecdsa-alpha",
    "project-alpha",
    "root-v1",
    "wallet",
    "v1",
  ),
  "ecdsa-hss y_server is stable under share order",
);
checkedOutputs += 2;

const ed25519Output = wasm.threshold_prf_derive_ed25519_hss_server_inputs(
  hssVector.policy.threshold,
  hssVector.policy.share_count,
  hssShareWires,
  "project-alpha",
  "alice.near",
  "wallet",
  "v1",
  1,
);
assertByteLength(ed25519Output.contextBinding, 32, "ed25519 context binding");
assertByteLength(ed25519Output.yServer, 32, "ed25519 y_server");
assertByteLength(ed25519Output.tauServer, 32, "ed25519 tau_server");
checkedOutputs += 3;

for (const vector of wireCorpus.vectors) {
  const proofBundle = concatBytes([
    hexToBytes(vector.partial.wire_hex),
    hexToBytes(vector.share_commitment_wire_hex),
    hexToBytes(vector.dleq_proof_wire_hex),
  ]);
  assertThrows(
    () =>
      wasm.threshold_prf_combine_verified_partials(
        vector.policy.threshold,
        vector.policy.share_count,
        proofBundle.slice(0, proofBundle.length - 1),
        "ecdsa-hss/y_server",
        new Uint8Array([1, 2, 3]),
      ),
    "malformed proof bundle rejects at production WASM boundary",
  );
  checkedRejections += 1;
}

console.log(
  `ok: production WASM smoke checked ${checkedOutputs} outputs and ${checkedRejections} rejection cases`,
);

function shareWiresForIds(sharesById, ids) {
  return concatBytes(
    ids.map((id) => {
      const share = sharesById.get(id);
      if (!share) {
        throw new Error(`missing share id ${id}`);
      }
      return hexToBytes(share.wire_hex);
    }),
  );
}

function assertByteLength(actual, expectedLength, label) {
  if (actual.length !== expectedLength) {
    throw new Error(`${label}: expected ${expectedLength} bytes, got ${actual.length}`);
  }
}

function assertSameBytes(left, right, label) {
  if (bytesToHex(left) !== bytesToHex(right)) {
    throw new Error(`${label}: byte mismatch`);
  }
}

function assertThrows(fn, label) {
  try {
    fn();
  } catch {
    return;
  }
  throw new Error(`${label}: expected throw`);
}

function concatBytes(chunks) {
  const out = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function hexToBytes(hex) {
  if (hex.length % 2 !== 0) {
    throw new Error("hex input must have even length");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    stdio: "inherit",
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}
