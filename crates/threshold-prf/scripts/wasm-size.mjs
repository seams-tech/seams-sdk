import { spawnSync } from "node:child_process";
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, relative } from "node:path";
import { brotliCompressSync, gzipSync } from "node:zlib";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(scriptDir, "..", "..", "..");
const crateDir = join(scriptDir, "..");
const packageDir = join(crateDir, "worker-bench", "vendor", "threshold_prf");
const resultsDir = join(crateDir, "target", "wasm-size");
const resultsPath = join(resultsDir, "results.json");

run("node", [join(scriptDir, "worker-bench-build.mjs")]);

const files = listFiles(packageDir).map((path) => measureFile(path));
const totals = files.reduce(
  (acc, file) => ({
    raw_bytes: acc.raw_bytes + file.raw_bytes,
    gzip_bytes: acc.gzip_bytes + file.gzip_bytes,
    brotli_bytes: acc.brotli_bytes + file.brotli_bytes,
  }),
  { raw_bytes: 0, gzip_bytes: 0, brotli_bytes: 0 },
);

const payload = {
  date: new Date().toISOString(),
  command: "just threshold-prf-wasm-size",
  package_dir: packageDir,
  git: {
    revision: commandOutput("git", ["rev-parse", "HEAD"]),
    dirty_status: commandOutput("git", ["status", "--short"]),
  },
  totals,
  files,
};

mkdirSync(resultsDir, { recursive: true });
writeFileSync(resultsPath, `${JSON.stringify(payload, null, 2)}\n`);

console.table(
  files
    .filter((file) => file.name.endsWith(".wasm") || file.name.endsWith(".js"))
    .map((file) => ({
      file: file.name,
      raw: formatBytes(file.raw_bytes),
      gzip: formatBytes(file.gzip_bytes),
      brotli: formatBytes(file.brotli_bytes),
    })),
);
console.table([
  {
    file: "package total",
    raw: formatBytes(totals.raw_bytes),
    gzip: formatBytes(totals.gzip_bytes),
    brotli: formatBytes(totals.brotli_bytes),
  },
]);
console.log(`wrote ${resultsPath}`);

function listFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...listFiles(path));
    } else if (entry.isFile()) {
      out.push(path);
    }
  }
  return out.sort();
}

function measureFile(path) {
  const bytes = readFileSync(path);
  return {
    name: relative(packageDir, path),
    basename: basename(path),
    raw_bytes: statSync(path).size,
    gzip_bytes: gzipSync(bytes).byteLength,
    brotli_bytes: brotliCompressSync(bytes).byteLength,
  };
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

function commandOutput(command, args) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
  });
  if (result.error || result.status !== 0) {
    return null;
  }
  return result.stdout.trim();
}

function formatBytes(bytes) {
  if (bytes >= 1024 * 1024) {
    return `${(bytes / 1024 / 1024).toFixed(2)} MiB`;
  }
  if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(1)} KiB`;
  }
  return `${bytes} B`;
}
