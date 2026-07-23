#!/usr/bin/env node

import { readFile } from 'node:fs/promises';

const options = parseOptions(process.argv.slice(2));
const ROUTER_COMPONENTS = ['router', 'deriver-a', 'deriver-b', 'signing-worker'];

await main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});

async function main() {
  const manifestPath = requireOption('manifest');
  const expectedReleaseSetId = requireOption('release-set-id');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  if (!isRecord(manifest) || manifest.releaseSetId !== expectedReleaseSetId) {
    throw new Error('final smoke release-set identity mismatch');
  }
  const selectedComponents = parseSelectedComponents(requireOption('selected-components'));
  const manifestSelectedComponents = manifest.buildIdentity?.selectedComponents;
  if (
    Array.isArray(manifestSelectedComponents) &&
    stableComponents(manifestSelectedComponents) !== stableComponents(selectedComponents)
  ) {
    throw new Error('final smoke selected-component identity mismatch');
  }

  const checks = [];
  if (selectedComponents.includes('gateway')) {
    checks.push(
      ...buildChecks(requireOption('gateway-origin'), [
        '/readyz',
        '/healthz',
        '/.well-known/router-ab-ceremony-jwks.json',
        '/router-ab/ed25519/healthz',
        '/router-ab/ecdsa-derivation/healthz',
      ]),
    );
  } else if (selectedComponents.some((component) => ROUTER_COMPONENTS.includes(component))) {
    checks.push(
      ...buildChecks(requireOption('gateway-origin'), [
        '/router-ab/ed25519/healthz',
        '/router-ab/ecdsa-derivation/healthz',
      ]),
    );
  }
  if (selectedComponents.includes('site') || selectedComponents.includes('signer-iframe')) {
    checks.push(...buildChecks(requireOption('site-origin'), ['/', '/sdk/']));
    checks.push(...buildChecks(requireOption('wallet-origin'), ['/', '/wallet-service/']));
  }
  if (checks.length === 0) {
    throw new Error('final smoke has no runtime checks for the selected components');
  }
  const results = await Promise.all(checks.map(runCheck));
  const failed = results.filter((result) => !result.ok);
  process.stdout.write(`${JSON.stringify({ releaseSetId: expectedReleaseSetId, results })}\n`);
  if (failed.length > 0) {
    throw new Error(
      `final deployment smoke failed for ${failed.map((result) => result.name).join(', ')}`,
    );
  }
}

function buildChecks(origin, paths) {
  const base = new URL(origin);
  return paths.map((path) => ({
    name: `${base.origin}${path}`,
    url: new URL(path, base).toString(),
  }));
}

async function runCheck(check) {
  try {
    const response = await fetch(check.url, { signal: AbortSignal.timeout(5000) });
    return {
      name: check.name,
      ok: response.status >= 200 && response.status < 400,
      status: response.status,
    };
  } catch (error) {
    return {
      name: check.name,
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function parseOptions(args) {
  const options = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (!name?.startsWith('--') || value === undefined || value.startsWith('--')) {
      throw new Error(`invalid argument: ${name ?? '<missing>'}`);
    }
    options.set(name.slice(2), value);
  }
  return options;
}

function requireOption(name) {
  const value = options.get(name);
  if (!value) throw new Error(`--${name} is required`);
  return value;
}

function parseSelectedComponents(value) {
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch (error) {
    throw new Error(`--selected-components must contain a JSON array: ${error.message}`);
  }
  if (
    !Array.isArray(parsed) ||
    parsed.some((component) => typeof component !== 'string' || component.length === 0)
  ) {
    throw new Error('--selected-components must contain a JSON array of component names');
  }
  return [...new Set(parsed)];
}

function stableComponents(components) {
  return JSON.stringify([...new Set(components)].sort());
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
