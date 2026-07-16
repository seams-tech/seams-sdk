#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const BUDGET_FIELDS = {
  historicalMixedEthSigner: 'historicalMixedEthSignerGzip9HardCeilingBytes',
  historicalRoleLocalClient: 'historicalRoleLocalClientGzip9HardCeilingBytes',
  purposeBuiltOnlineClient: 'purposeBuiltOnlineClientGzip9HardCeilingBytes',
};

function fail(message) {
  throw new Error(message);
}

function compress(command, arguments_) {
  const result = spawnSync(command, arguments_, {
    encoding: null,
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.status !== 0) {
    fail(`${command} failed: ${result.stderr?.toString('utf8') ?? 'unknown error'}`);
  }
  return result.stdout.length;
}

function main(arguments_) {
  const [evidencePath, budgetName, wasmPath] = arguments_;
  if (evidencePath === undefined || budgetName === undefined || wasmPath === undefined) {
    fail('usage: check-wasm-budget.mjs <evidence-json> <budget-name> <wasm>');
  }
  const budgetField = BUDGET_FIELDS[budgetName];
  if (budgetField === undefined) {
    fail(`unknown budget ${budgetName}`);
  }
  const evidence = JSON.parse(readFileSync(evidencePath, 'utf8'));
  const ceiling = evidence.budgets[budgetField];
  if (!Number.isSafeInteger(ceiling) || ceiling <= 0) {
    fail(`invalid budget field ${budgetField}`);
  }
  const raw = readFileSync(wasmPath).length;
  const gzip9 = compress('gzip', ['-9', '-c', wasmPath]);
  const brotli11 = compress('brotli', ['-q', '11', '-c', wasmPath]);
  const passed = gzip9 <= ceiling;
  process.stdout.write(
    `${JSON.stringify(
      {
        schema: 'seams.refactor89.wasm-budget-result.v1',
        budgetName,
        ceilingGzip9Bytes: ceiling,
        actual: { rawBytes: raw, gzip9Bytes: gzip9, brotli11Bytes: brotli11 },
        passed,
      },
      null,
      2,
    )}\n`,
  );
  if (!passed) {
    process.exitCode = 1;
  }
}

main(process.argv.slice(2));
