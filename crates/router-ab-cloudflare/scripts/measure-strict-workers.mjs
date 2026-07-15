import { gzipSync } from "node:zlib";
import { mkdirSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const roles = [
  {
    label: "router",
    feature: "strict-worker-router-entrypoint",
    outDir: "build/router",
  },
  {
    label: "deriver-a",
    feature: "strict-worker-deriver-a-entrypoint",
    outDir: "build/deriver-a",
  },
  {
    label: "deriver-b",
    feature: "strict-worker-deriver-b-entrypoint",
    outDir: "build/deriver-b",
  },
  {
    label: "signing-worker",
    feature: "strict-worker-signing-worker-entrypoint",
    outDir: "build/signing-worker",
  },
];

function run(command, args) {
  const child = spawnSync(command, args, {
    stdio: "inherit",
    env: process.env,
  });
  if (child.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed with status ${child.status}`);
  }
}

function measureFile(path) {
  const bytes = readFileSync(path);
  return {
    raw: bytes.byteLength,
    gzip: gzipSync(bytes, { level: 9 }).byteLength,
  };
}

function collectFiles(dir) {
  const entries = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    const stat = statSync(path);
    if (stat.isDirectory()) {
      entries.push(...collectFiles(path));
    } else {
      entries.push(path);
    }
  }
  return entries;
}

for (const role of roles) {
  mkdirSync(role.outDir, { recursive: true });
  run("worker-build", [
    "--release",
    "--out-dir",
    role.outDir,
    "--features",
    role.feature,
  ]);
}

const measurements = roles.map((role) => {
  const wasm = measureFile(join(role.outDir, "index_bg.wasm"));
  const js = measureFile(join(role.outDir, "index.js"));
  const shim = measureFile(join(role.outDir, "worker", "shim.mjs"));
  const files = collectFiles(role.outDir).map((path) => measureFile(path));
  const total = files.reduce(
    (acc, file) => ({
      raw: acc.raw + file.raw,
      gzip: acc.gzip + file.gzip,
    }),
    { raw: 0, gzip: 0 },
  );
  return {
    role: role.label,
    feature: role.feature,
    wasm,
    js,
    shim,
    total,
  };
});

console.log(JSON.stringify({ generatedAt: new Date().toISOString(), measurements }, null, 2));
