import { expect, test } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  collectRuntimeEntryGraphOffenders,
  collectWalletIframeHostGraphOffenders,
} from '../../packages/wallet/scripts/checks/assert-runtime-entry-bundles.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

test('runtime entry bundle avoids browser implementation modules', () => {
  const output = execFileSync(
    'node',
    ['packages/wallet/scripts/checks/assert-runtime-entry-bundles.mjs'],
    {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );

  expect(output).toContain('runtime entry avoids browser bundles');
  expect(output).toContain('wallet iframe host graphs are React-free');
});

test('wallet host guard ignores prose and rejects a React package import', () => {
  const fixtureRoot = mkdtempSync(path.join(tmpdir(), 'seams-runtime-entry-bundle-'));
  const entry = 'sdk/wallet-iframe-host-runtime.js';

  try {
    mkdirSync(path.join(fixtureRoot, 'sdk'), { recursive: true });
    writeFileSync(
      path.join(fixtureRoot, entry),
      '// React-free wallet-host copy with no framework import\n',
    );
    expect(collectWalletIframeHostGraphOffenders([entry], fixtureRoot)).toEqual([]);

    writeFileSync(path.join(fixtureRoot, entry), 'import { createElement } from "react";\n');
    expect(collectWalletIframeHostGraphOffenders([entry], fixtureRoot)).toEqual([
      expect.stringContaining('forbidden package react'),
    ]);
  } finally {
    rmSync(fixtureRoot, { recursive: true, force: true });
  }
});

test('runtime guard ignores lazy browser chunks while retaining static graph checks', () => {
  const fixtureRoot = mkdtempSync(path.join(tmpdir(), 'seams-runtime-entry-bundle-'));
  const entry = 'runtime.js';

  try {
    writeFileSync(path.join(fixtureRoot, entry), 'void import("./lazy.js");\n');
    writeFileSync(path.join(fixtureRoot, 'lazy.js'), 'export const browser = window;\n');
    expect(collectRuntimeEntryGraphOffenders([entry], fixtureRoot)).toEqual([]);

    writeFileSync(path.join(fixtureRoot, entry), 'import "./lazy.js";\n');
    expect(collectRuntimeEntryGraphOffenders([entry], fixtureRoot)).toEqual([
      expect.stringContaining('forbidden source'),
    ]);
  } finally {
    rmSync(fixtureRoot, { recursive: true, force: true });
  }
});

test('wallet host guard rejects dynamic framework imports and fully inlined React markers', () => {
  const fixtureRoot = mkdtempSync(path.join(tmpdir(), 'seams-runtime-entry-bundle-'));
  const entry = 'sdk/wallet-iframe-host-runtime.js';

  try {
    mkdirSync(path.join(fixtureRoot, 'sdk'), { recursive: true });
    writeFileSync(path.join(fixtureRoot, entry), 'void import("react-dom/client");\n');
    expect(collectWalletIframeHostGraphOffenders([entry], fixtureRoot)).toEqual([
      expect.stringContaining('forbidden package react-dom/client'),
    ]);

    writeFileSync(path.join(fixtureRoot, entry), 'void import("./lazy.js");\n');
    writeFileSync(
      path.join(fixtureRoot, 'sdk/lazy.js'),
      'export const framework = import(/* split point */ "react");\n',
    );
    expect(collectWalletIframeHostGraphOffenders([entry], fixtureRoot)).toEqual([
      expect.stringContaining('forbidden package react'),
    ]);

    writeFileSync(
      path.join(fixtureRoot, entry),
      [
        'const elementType = Symbol.for("react.element");',
        'const fragmentType = Symbol.for("react.fragment");',
        'const ReactCurrentDispatcher = { current: null };',
      ].join('\n'),
    );
    expect(collectWalletIframeHostGraphOffenders([entry], fixtureRoot)).toEqual([
      expect.stringContaining('forbidden source'),
    ]);

    writeFileSync(
      path.join(fixtureRoot, entry),
      '// Documentation mentions React and react.element without bundling the runtime.\n',
    );
    expect(collectWalletIframeHostGraphOffenders([entry], fixtureRoot)).toEqual([]);

    writeFileSync(
      path.join(fixtureRoot, entry),
      ['const criticalDirs = ["src/react"];', '//#region src/react/deviceDetection.ts'].join('\n'),
    );
    expect(collectWalletIframeHostGraphOffenders([entry], fixtureRoot)).toEqual([
      expect.stringContaining('forbidden source'),
    ]);

    writeFileSync(path.join(fixtureRoot, entry), 'const criticalDirs = ["src/react"];\n');
    expect(collectWalletIframeHostGraphOffenders([entry], fixtureRoot)).toEqual([]);
  } finally {
    rmSync(fixtureRoot, { recursive: true, force: true });
  }
});
