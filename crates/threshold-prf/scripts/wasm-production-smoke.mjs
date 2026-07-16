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

const derivationVector = protocolCorpus.vectors.find(
  (vector) => vector.purpose === "router-ab-ecdsa-derivation/y-server/v1" && vector.policy.threshold === 2,
);
if (!derivationVector) {
  throw new Error("missing Router A/B ECDSA derivation threshold-prf smoke vector");
}
const derivationShareWiresById = new Map(derivationVector.shares.map((share) => [share.id, share]));
const derivationIds = derivationVector.threshold_outputs[0].ids;
const derivationShareWires = shareWiresForIds(derivationShareWiresById, derivationIds);
const reversedDerivationShareWires = shareWiresForIds(derivationShareWiresById, derivationIds.toReversed());
const applicationBindingDigest = hexToBytes(
  "7f6ec48989273bf014547956927059547a8d659391735b7a6c1958bc6f0cf8f4",
);

const ecdsaOutput = wasm.threshold_prf_derive_router_ab_ecdsa_derivation_y_relayer(
  derivationVector.policy.threshold,
  derivationVector.policy.share_count,
  derivationShareWires,
  applicationBindingDigest,
);
assertByteLength(ecdsaOutput, 32, "Router A/B ECDSA derivation y_server");
assertSameBytes(
  ecdsaOutput,
  wasm.threshold_prf_derive_router_ab_ecdsa_derivation_y_relayer(
    derivationVector.policy.threshold,
    derivationVector.policy.share_count,
    reversedDerivationShareWires,
    applicationBindingDigest,
  ),
  "Router A/B ECDSA derivation y_server is stable under share order",
);
checkedOutputs += 2;

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
        "router-ab-ecdsa-derivation/y-server/v1",
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
