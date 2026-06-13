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

for (const vector of protocolCorpus.vectors) {
  const partialsById = new Map(vector.partials.map((partial) => [partial.id, partial]));
  for (const thresholdOutput of vector.threshold_outputs) {
    const partialWires = partialWiresForIds(partialsById, thresholdOutput.ids);
    assertHexOutput(
      wasm.threshold_prf_combine_partials(
        vector.policy.threshold,
        vector.policy.share_count,
        partialWires,
        vector.purpose,
        hexToBytes(vector.context_hex),
      ),
      thresholdOutput.output_hex,
      `partial combine ${vector.policy.threshold}-of-${vector.policy.share_count} ids ${thresholdOutput.ids.join(",")}`,
    );
    checkedOutputs += 1;

    assertHexOutput(
      wasm.threshold_prf_combine_partials(
        vector.policy.threshold,
        vector.policy.share_count,
        partialWiresForIds(partialsById, thresholdOutput.ids.toReversed()),
        vector.purpose,
        hexToBytes(vector.context_hex),
      ),
      thresholdOutput.output_hex,
      `partial combine reversed ${vector.policy.threshold}-of-${vector.policy.share_count} ids ${thresholdOutput.ids.join(",")}`,
    );
    checkedOutputs += 1;
  }

  assertThrows(
    () =>
      wasm.threshold_prf_combine_partials(
        vector.policy.threshold,
        vector.policy.share_count,
        partialWiresForIds(
          partialsById,
          Array.from({ length: vector.policy.threshold }, () => vector.partials[0].id),
        ),
        vector.purpose,
        hexToBytes(vector.context_hex),
      ),
    "duplicate partial ids reject at production WASM boundary",
  );
  checkedRejections += 1;

  assertThrows(
    () =>
      wasm.threshold_prf_combine_partials(
        vector.policy.threshold,
        vector.policy.share_count,
        partialWiresForIds(
          partialsById,
          vector.threshold_outputs[0].ids,
        ),
        vector.purpose,
        mutateContext(hexToBytes(vector.context_hex)),
      ),
    "wrong partial context rejects at production WASM boundary",
  );
  checkedRejections += 1;
}

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
        "ecdsa-hss/y_relayer",
        new Uint8Array([1, 2, 3]),
      ),
    "malformed proof bundle rejects at production WASM boundary",
  );
  checkedRejections += 1;
}

console.log(
  `ok: production WASM smoke checked ${checkedOutputs} outputs and ${checkedRejections} rejection cases`,
);

function partialWiresForIds(partialsById, ids) {
  return concatBytes(
    ids.map((id) => {
      const partial = partialsById.get(id);
      if (!partial) {
        throw new Error(`missing partial id ${id}`);
      }
      return hexToBytes(partial.wire_hex);
    }),
  );
}

function mutateContext(bytes) {
  const out = new Uint8Array(bytes);
  out[out.length - 1] ^= 0x01;
  return out;
}

function assertHexOutput(actual, expectedHex, label) {
  const actualHex = bytesToHex(actual);
  if (actualHex !== expectedHex) {
    throw new Error(`${label}: expected ${expectedHex}, got ${actualHex}`);
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
