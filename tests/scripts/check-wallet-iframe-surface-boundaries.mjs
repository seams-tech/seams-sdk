#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../..');
const clientRoot = path.join(
  repoRoot,
  'packages/sdk-web/src/SeamsWeb/walletIframe/client',
);
const routerPath = path.join(clientRoot, 'router.ts');
const rendererPath = path.join(clientRoot, 'surface/renderer.ts');
const legacyRouterCallLimits = new Map([
  ['controller.showFullscreen(', 7],
  ['controller.showAnchored(', 1],
  ['controller.setSticky(', 4],
  ['forceFullscreen = true', 3],
  ['forceFullscreen = false', 2],
]);

function listTypeScriptFiles(root) {
  return fs.readdirSync(root).flatMap((entryName) => {
    const absolutePath = path.join(root, entryName);
    const entry = fs.statSync(absolutePath);
    if (entry.isDirectory()) return listTypeScriptFiles(absolutePath);
    return entryName.endsWith('.ts') ? [absolutePath] : [];
  });
}

function countOccurrences(source, needle) {
  return source.split(needle).length - 1;
}

function relativePath(absolutePath) {
  return path.relative(repoRoot, absolutePath).split(path.sep).join('/');
}

function collectViolations() {
  const violations = [];
  const directMutationPattern =
    /\.controller\.(?:applyHidden|applyAnchored|applyAnchoredSuspended|applyViewportModal|showFullscreen|showAnchored|setSticky|hide|forceHide|setAnchoredRect|suspendAnchored|clearAnchoredRect)\s*\(/;
  for (const filePath of listTypeScriptFiles(clientRoot)) {
    if (
      filePath === routerPath ||
      filePath === rendererPath ||
      filePath.includes(`${path.sep}overlay${path.sep}`)
    ) {
      continue;
    }
    if (directMutationPattern.test(fs.readFileSync(filePath, 'utf8'))) {
      violations.push(`${relativePath(filePath)}: direct overlay mutation outside the renderer`);
    }
  }

  const routerSource = fs.readFileSync(routerPath, 'utf8');
  for (const [needle, limit] of legacyRouterCallLimits) {
    const count = countOccurrences(routerSource, needle);
    if (count > limit) {
      violations.push(
        `${relativePath(routerPath)}: ${needle} count ${count} exceeds legacy limit ${limit}`,
      );
    }
  }

  const registrationSource = routerSource.slice(
    routerSource.indexOf('createPasskeyRegistrationActivationSurface('),
    routerSource.indexOf('\n  async registerWallet('),
  );
  if (directMutationPattern.test(registrationSource) || /forceFullscreen/.test(registrationSource)) {
    violations.push(
      `${relativePath(routerPath)}: registration activation must transition surface state`,
    );
  }
  return violations;
}

const violations = collectViolations();
if (violations.length > 0) {
  console.error(`[wallet-iframe-surface-boundaries] failed with ${violations.length} violation(s):`);
  for (const violation of violations) console.error(`- ${violation}`);
  process.exit(1);
}
console.log('[wallet-iframe-surface-boundaries] ok');
