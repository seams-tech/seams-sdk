#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../..');
const ignoredDirectories = new Set(['.vite', 'dist', 'node_modules']);

const requiredWorkspacePackages = [
  'packages/console-shared-ts',
  'packages/sdk-web',
  'packages/sdk-server-ts',
  'packages/shared-ts',
  'apps/seams-site',
  'apps/web-server',
  'apps/docs',
];

const removedWorkspacePackages = [
  'sdk',
  'packages/sdk-runtime-ts',
  'apps/web-client',
];

const deletedImplementationRoots = ['client', 'sdk', 'server', 'shared'];
const deployableAppRoots = ['apps/seams-site', 'apps/web-server'];
const nativeRoots = ['clients/ios', 'crates/seams-embedded'];

function absolutePath(relativePath) {
  return path.join(repoRoot, relativePath);
}

function readText(relativePath) {
  return fs.readFileSync(absolutePath(relativePath), 'utf8');
}

function readJson(relativePath) {
  return JSON.parse(readText(relativePath));
}

function isSourceFileName(fileName) {
  return /\.(ts|tsx|mjs|js|json|yaml|yml)$/.test(fileName);
}

function listSourceFiles(relativeDir) {
  const absoluteDir = absolutePath(relativeDir);
  if (!fs.existsSync(absoluteDir)) return [];
  const entries = fs.readdirSync(absoluteDir, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const relativePath = path.join(relativeDir, entry.name).split(path.sep).join('/');
    if (entry.isDirectory()) {
      if (ignoredDirectories.has(entry.name)) continue;
      files.push(...listSourceFiles(relativePath));
      continue;
    }
    if (entry.isFile() && isSourceFileName(entry.name)) {
      files.push(relativePath);
    }
  }

  return files;
}

function jsonContains(value, needle) {
  return JSON.stringify(value).includes(needle);
}

function collectDeletedRootViolations() {
  const violations = [];
  for (const relativePath of deletedImplementationRoots) {
    if (fs.existsSync(absolutePath(relativePath))) {
      violations.push(`${relativePath}: deleted implementation root exists`);
    }
  }
  return violations;
}

function collectWorkspaceManifestViolations() {
  const violations = [];
  const workspace = readText('pnpm-workspace.yaml');

  for (const required of requiredWorkspacePackages) {
    if (!workspace.includes(required)) {
      violations.push(`pnpm-workspace.yaml: missing ${required}`);
    }
  }

  for (const removed of removedWorkspacePackages) {
    const pattern = new RegExp(`^\\s*-\\s*${escapeRegExp(removed)}\\s*$`, 'm');
    if (pattern.test(workspace) || workspace.includes(`${removed}/`)) {
      violations.push(`pnpm-workspace.yaml: removed workspace package ${removed} is present`);
    }
  }

  return violations;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function collectPackageTypePathViolations() {
  const violations = [];
  const webPackageJson = readJson('packages/sdk-web/package.json');
  const serverPackageJson = readJson('packages/sdk-server-ts/package.json');

  for (const forbidden of [
    'dist/types/client/src',
    'dist/types/server/src',
    'dist/types/sdk-server-ts/src',
  ]) {
    if (jsonContains(webPackageJson, forbidden)) {
      violations.push(`packages/sdk-web/package.json: forbidden type path ${forbidden}`);
    }
  }

  if (!jsonContains(webPackageJson, 'dist/types/sdk-web/src')) {
    violations.push('packages/sdk-web/package.json: missing dist/types/sdk-web/src type path');
  }

  for (const forbidden of ['dist/types/client/src', 'dist/types/server/src']) {
    if (jsonContains(serverPackageJson, forbidden)) {
      violations.push(`packages/sdk-server-ts/package.json: forbidden type path ${forbidden}`);
    }
  }

  if (!jsonContains(serverPackageJson, 'dist/types/sdk-server-ts/src')) {
    violations.push('packages/sdk-server-ts/package.json: missing dist/types/sdk-server-ts/src type path');
  }

  return violations;
}

function collectDeployableImportViolations() {
  const violations = [];
  for (const file of sourceFilesInRoots(deployableAppRoots)) {
    const source = readText(file);
    if (/\.\.\/(?:\.\.\/)*packages\/(?:sdk-web|sdk-server-ts|shared-ts)\/src/.test(source)) {
      violations.push(`${file}: imports package implementation source`);
    }
    if (/\.\.\/(?:\.\.\/)*(?:client|server|shared)\/src/.test(source)) {
      violations.push(`${file}: imports deleted implementation source root`);
    }
  }
  return violations;
}

function collectNativeImportViolations() {
  const violations = [];
  for (const file of sourceFilesInRoots(nativeRoots)) {
    const source = readText(file);
    if (/packages\/(?:sdk-web|sdk-server-ts|shared-ts)\/src/.test(source)) {
      violations.push(`${file}: imports package implementation source`);
    }
    if (/(?:client|server|shared)\/src/.test(source)) {
      violations.push(`${file}: imports deleted implementation source root`);
    }
  }
  return violations;
}

function sourceFilesInRoots(roots) {
  const files = [];
  for (const root of roots) {
    files.push(...listSourceFiles(root));
  }
  return files;
}

function main() {
  const violations = [
    ...collectDeletedRootViolations(),
    ...collectWorkspaceManifestViolations(),
    ...collectPackageTypePathViolations(),
    ...collectDeployableImportViolations(),
    ...collectNativeImportViolations(),
  ];

  if (violations.length > 0) {
    console.error(`[workspace-package-boundaries] failed with ${violations.length} violation(s):`);
    for (const violation of violations) {
      console.error(`- ${violation}`);
    }
    process.exit(1);
  }

  console.log('[workspace-package-boundaries] ok');
}

main();
