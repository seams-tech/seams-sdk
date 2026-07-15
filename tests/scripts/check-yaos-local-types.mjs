#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as ts from 'typescript';

const testRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const configPath = path.join(testRoot, 'tsconfig.playwright.json');
const localManifest = {
  path: path.join(testRoot, 'yaos-local-test-slice.json'),
  schema: 'seams-yaos-ab-local-test-slice-v1',
};
const productManifest = {
  path: path.join(testRoot, 'yaos-local-product-test-slice.json'),
  schema: 'seams-yaos-ab-local-product-test-slice-v1',
};
const playwrightConfigPaths = [
  path.join(testRoot, 'playwright.yaos-local.config.ts'),
  path.join(testRoot, 'playwright.yaos-local-product.config.ts'),
];

function fail(message) {
  throw new Error(`Yao local type gate: ${message}`);
}

function requireObject(value, field) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail(`${field} must be an object`);
  }
  return value;
}

function requireString(value, field) {
  if (typeof value !== 'string' || value.length === 0) {
    fail(`${field} must be a nonempty string`);
  }
  return value;
}

function normalizeTestFile(value, index) {
  const testFile = requireString(value, `test_files[${String(index)}]`);
  if (
    path.isAbsolute(testFile) ||
    testFile.includes('\\') ||
    testFile.includes('\0') ||
    testFile.startsWith('../') ||
    path.posix.normalize(testFile) !== testFile ||
    !testFile.endsWith('.test.ts')
  ) {
    fail(`invalid test path ${JSON.stringify(testFile)}`);
  }
  return testFile;
}

function loadManifest(definition) {
  const manifest = requireObject(
    JSON.parse(fs.readFileSync(definition.path, 'utf8')),
    'manifest',
  );
  if (manifest.schema !== definition.schema) {
    fail(`schema must equal ${definition.schema}`);
  }
  if (!Array.isArray(manifest.test_files) || manifest.test_files.length === 0) {
    fail('test_files must be a nonempty array');
  }
  const testFiles = manifest.test_files.map(normalizeTestFile);
  if (new Set(testFiles).size !== testFiles.length) {
    fail('test_files contains a duplicate');
  }
  for (const testFile of testFiles) {
    if (!fs.statSync(path.join(testRoot, testFile)).isFile()) {
      fail(`test file is unavailable: ${testFile}`);
    }
  }
  return testFiles;
}

function listTestFiles(directory, prefix) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const relativePath = path.posix.join(prefix, entry.name);
    const absolutePath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...listTestFiles(absolutePath, relativePath));
    } else if (entry.isFile() && entry.name.endsWith('.test.ts')) {
      files.push(relativePath);
    }
  }
  return files.sort();
}

function requireCompleteLocalInventory(testFiles) {
  const expected = listTestFiles(path.join(testRoot, 'yaos-local'), 'yaos-local');
  const observed = testFiles.filter((testFile) => testFile.startsWith('yaos-local/')).sort();
  if (JSON.stringify(observed) !== JSON.stringify(expected)) {
    fail('manifest does not contain the complete tests/yaos-local inventory');
  }
}

function parseCompilerOptions() {
  const config = ts.readConfigFile(configPath, ts.sys.readFile);
  if (config.error !== undefined) {
    printDiagnostics([config.error]);
    fail('could not read tsconfig.playwright.json');
  }
  const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, testRoot, {}, configPath);
  if (parsed.errors.length > 0) {
    printDiagnostics(parsed.errors);
    fail('could not parse tsconfig.playwright.json');
  }
  return { ...parsed.options, incremental: false, noEmit: true };
}

function printDiagnostics(diagnostics) {
  const formatted = ts.formatDiagnosticsWithColorAndContext(diagnostics, {
    getCanonicalFileName: (fileName) => fileName,
    getCurrentDirectory: () => testRoot,
    getNewLine: () => '\n',
  });
  process.stderr.write(formatted);
}

function typeCheck(testFiles) {
  const rootNames = [
    ...playwrightConfigPaths,
    ...testFiles.map((testFile) => path.join(testRoot, testFile)),
  ];
  const program = ts.createProgram({ rootNames, options: parseCompilerOptions() });
  const diagnostics = ts.getPreEmitDiagnostics(program);
  if (diagnostics.length > 0) {
    printDiagnostics(diagnostics);
    fail(`${String(diagnostics.length)} TypeScript diagnostics found`);
  }
}

const localTestFiles = loadManifest(localManifest);
const productTestFiles = loadManifest(productManifest);
requireCompleteLocalInventory(localTestFiles);
typeCheck([...new Set([...localTestFiles, ...productTestFiles])]);
console.log(
  `Yao local TypeScript gate passed for ${String(localTestFiles.length)} focused files and ${String(productTestFiles.length)} managed product files`,
);
