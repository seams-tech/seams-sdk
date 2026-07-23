#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const ROUTER_COMPONENTS = Object.freeze(['router', 'deriver-a', 'deriver-b', 'signing-worker']);
const PAGES_COMPONENTS = Object.freeze(['site', 'signer-iframe']);

export const COMPONENT_NAMES = Object.freeze(
  [...ROUTER_COMPONENTS, 'gateway', ...PAGES_COMPONENTS].sort(compareStrings),
);

const ALL_COMPONENTS = COMPONENT_NAMES;

const componentInputMap = {
  router: [
    inputRule({
      exact: [
        'crates/router-ab-cloudflare/wrangler.router.toml',
        'crates/router-ab-cloudflare/src/strict_worker/router.rs',
      ],
      prefixes: ['crates/router-ab-cloudflare/src/router/'],
    }),
    inputRule({ prefixes: ['.github/workflows/validate-cloudflare-router-ab.yml'] }),
  ],
  'deriver-a': [
    inputRule({
      exact: [
        'crates/router-ab-cloudflare/wrangler.deriver-a.toml',
        'crates/router-ab-cloudflare/src/strict_worker/deriver.rs',
      ],
    }),
  ],
  'deriver-b': [
    inputRule({
      exact: [
        'crates/router-ab-cloudflare/wrangler.deriver-b.toml',
        'crates/router-ab-cloudflare/src/strict_worker/deriver.rs',
      ],
    }),
  ],
  'signing-worker': [
    inputRule({
      exact: [
        'crates/router-ab-cloudflare/wrangler.signing-worker.toml',
        'crates/router-ab-cloudflare/src/strict_worker/signing_worker.rs',
      ],
      prefixes: ['crates/router-ab-cloudflare/src/signing_worker/'],
    }),
  ],
  gateway: [
    inputRule({
      prefixes: [
        'packages/console-server-ts/',
        'packages/sdk-server-ts/',
        'packages/console-shared-ts/',
      ],
    }),
    inputRule({
      exact: [
        '.github/workflows/deploy-staging-cloudflare-stack.yml',
        '.github/workflows/deploy-production-cloudflare-stack.yml',
        'packages/console-server-ts/wrangler.d1-local.toml',
        'packages/console-server-ts/wrangler.d1-staging-gateway.toml',
        'packages/console-server-ts/wrangler.d1-staging-gateway.toml.example',
      ],
    }),
  ],
  site: [
    inputRule({ prefixes: ['apps/seams-site/'] }),
    inputRule({
      exact: [
        '.github/workflows/deploy-staging-cloudflare-stack.yml',
        '.github/workflows/deploy-production-cloudflare-stack.yml',
      ],
      prefixes: [
        'packages/sdk-web/src/SeamsWeb/operations/',
        'packages/sdk-web/src/SeamsWeb/publicApi/',
        'packages/sdk-web/src/SeamsWeb/signingSurface/',
        'packages/sdk-web/src/core/',
        'packages/sdk-web/src/plugins/',
        'packages/sdk-web/src/react/',
        'packages/sdk-web/src/theme/',
        'packages/sdk-web/src/utils/',
      ],
    }),
  ],
  'signer-iframe': [
    inputRule({
      exact: [
        '.github/workflows/deploy-staging-cloudflare-stack.yml',
        '.github/workflows/deploy-production-cloudflare-stack.yml',
      ],
      prefixes: [
        'packages/sdk-web/src/SeamsWeb/walletIframe/',
        'packages/sdk-web/src/core/signingEngine/uiConfirm/ui/',
        'packages/sdk-web/src/static/',
      ],
    }),
  ],
};

/**
 * Shared inputs are intentionally explicit. A new path falls through to every
 * component, which keeps the release set complete until this table is reviewed.
 */
const sharedInputRules = [
  sharedInputRule(ALL_COMPONENTS, {
    exact: [
      '.cargo/config.toml',
      '.github/workflows/validate-repository.yml',
      '.github/workflows/deploy-production-cloudflare-stack.yml',
      '.github/workflows/deploy-staging-cloudflare-stack.yml',
      '.github/dependabot.yml',
      '.npmrc',
      'package.json',
      'pnpm-lock.yaml',
      'pnpm-workspace.yaml',
      'rust-toolchain.toml',
      'rustfmt.toml',
    ],
    prefixes: ['.github/actions/', '.cargo/', 'scripts/'],
    suffixes: ['Cargo.lock'],
  }),
  sharedInputRule(ROUTER_COMPONENTS, {
    exact: ['crates/router-ab-cloudflare/Cargo.toml', 'crates/router-ab-cloudflare/package.json'],
    prefixes: [
      'crates/router-ab-cloudflare/env/',
      'crates/router-ab-cloudflare/scripts/',
      'crates/router-ab-core/',
      'crates/router-ab-ecdsa-client-protocol/',
      'crates/router-ab-ecdsa-derivation/',
      'crates/router-ab-ecdsa-online/',
      'crates/router-ab-ecdsa-pool/',
      'crates/router-ab-ecdsa-presign/',
      'crates/router-ab-ecdsa-wire/',
      'crates/router-ab-ed25519-yao/',
      'crates/router-ab-ed25519-yao-protocol/',
      'crates/router-ab-ecdsa-near-oracle-tests/',
      'crates/router-ab-dev/',
      'crates/router-ab-cloudflare/src/durable_object/',
    ],
  }),
  sharedInputRule(ROUTER_COMPONENTS, {
    exact: [
      'crates/router-ab-cloudflare/src/auth.rs',
      'crates/router-ab-cloudflare/src/ecdsa_normal_signing_transport.rs',
      'crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs',
      'crates/router-ab-cloudflare/src/ed25519_yao_lifecycle.rs',
      'crates/router-ab-cloudflare/src/ed25519_yao_signing_worker.rs',
      'crates/router-ab-cloudflare/src/ed25519_yao_websocket.rs',
      'crates/router-ab-cloudflare/src/encoding.rs',
      'crates/router-ab-cloudflare/src/env.rs',
      'crates/router-ab-cloudflare/src/hpke.rs',
      'crates/router-ab-cloudflare/src/lib.rs',
      'crates/router-ab-cloudflare/src/paths.rs',
      'crates/router-ab-cloudflare/src/strict_worker/cors.rs',
      'crates/router-ab-cloudflare/src/strict_worker/mod.rs',
    ],
  }),
  sharedInputRule(ALL_COMPONENTS, {
    prefixes: ['crates/signer-core/', 'crates/ed25519-yao/'],
  }),
  sharedInputRule([...PAGES_COMPONENTS, 'gateway'], {
    exact: [
      'packages/sdk-web/package.json',
      'packages/sdk-web/scripts/build/build-paths.sh',
      'packages/sdk-web/scripts/build/build-wasm.sh',
      'packages/sdk-web/scripts/build/install-ci-wasm-tooling.sh',
      'packages/sdk-web/scripts/build/wasm-toolchain.sh',
    ],
    prefixes: ['wasm/'],
  }),
  sharedInputRule(PAGES_COMPONENTS, {
    exact: [
      'packages/sdk-web/scripts/build/build-full.sh',
      'packages/sdk-web/scripts/build/build-prod.sh',
      'packages/sdk-web/scripts/build/build-sdk.sh',
      'packages/sdk-web/scripts/build/emit-static-wallet-assets.mjs',
      'packages/sdk-web/scripts/codegen/generate-w3a-components-css.mjs',
      'packages/sdk-web/tsconfig.build.json',
      'packages/sdk-web/rolldown.config.ts',
    ],
    prefixes: ['packages/sdk-web/src/core/platform/generated/'],
  }),
  sharedInputRule(PAGES_COMPONENTS, {
    prefixes: ['crates/router-ab-ed25519-yao-client/'],
  }),
  sharedInputRule(['gateway'], {
    exact: ['packages/sdk-server-ts/src/wasm-modules.d.ts'],
  }),
  sharedInputRule(['gateway', ...PAGES_COMPONENTS], {
    prefixes: ['packages/shared-ts/'],
  }),
  sharedInputRule(ROUTER_COMPONENTS, {
    exact: ['.github/workflows/validate-cloudflare-router-ab.yml'],
  }),
  sharedInputRule(PAGES_COMPONENTS, {
    exact: [
      '.github/workflows/deploy-staging-cloudflare-stack.yml',
      '.github/workflows/deploy-production-cloudflare-stack.yml',
    ],
  }),
];

const nonDeploymentInputRule = inputRule({
  prefixes: ['apps/docs/', 'docs/', 'tests/'],
  suffixes: ['.md'],
});

export const COMPONENT_INPUT_MAP = freezeInputMap(componentInputMap);
export const SHARED_INPUT_RULES = Object.freeze(
  sharedInputRules.map((rule) => freezeSharedInputRule(rule)),
);

export function selectComponents(changedFiles) {
  if (!Array.isArray(changedFiles)) {
    throw new TypeError('changedFiles must be an array of repository-relative paths');
  }

  const normalizedFiles = deduplicateSorted(changedFiles.map(normalizeChangedFile));
  const selected = new Set();

  for (const file of normalizedFiles) {
    if (matchesInputRule(nonDeploymentInputRule, file)) continue;

    const matchedComponents = componentsForFile(file);
    if (matchedComponents.length === 0) return [...ALL_COMPONENTS];
    for (const component of matchedComponents) selected.add(component);
  }

  if (selected.has('router')) {
    for (const component of ROUTER_COMPONENTS) selected.add(component);
  }
  if (selected.has('signer-iframe')) selected.add('site');
  return [...selected].sort(compareStrings);
}

export async function readChangedFilesFromFile(filePath) {
  const value = await readFile(filePath, 'utf8');
  return value
    .split('\n')
    .map((line) => line.replace(/\r$/u, ''))
    .filter((line) => line.length > 0);
}

export async function runCli(args) {
  const options = parseCliOptions(args);
  const changedFiles = [...options.files];

  if (options.filesJson !== undefined) {
    changedFiles.push(...parseFilesJson(options.filesJson));
  }
  if (options.filesFile !== undefined) {
    changedFiles.push(...(await readChangedFilesFromFile(options.filesFile)));
  }

  const components = selectComponents(changedFiles);
  if (options.format === 'lines') {
    process.stdout.write(components.length === 0 ? '' : `${components.join('\n')}\n`);
    return components;
  }
  process.stdout.write(`${JSON.stringify(components)}\n`);
  return components;
}

function componentsForFile(file) {
  const selected = new Set();

  for (const [component, rules] of Object.entries(COMPONENT_INPUT_MAP)) {
    if (rules.some((rule) => matchesInputRule(rule, file))) selected.add(component);
  }
  for (const rule of SHARED_INPUT_RULES) {
    if (!matchesInputRule(rule, file)) continue;
    for (const component of rule.components) selected.add(component);
  }

  return [...selected].sort(compareStrings);
}

function normalizeChangedFile(value) {
  if (typeof value !== 'string') throw new TypeError('changed file paths must be strings');
  const normalized = value.replaceAll('\\', '/').replace(/^\.\//u, '');
  if (
    normalized.length === 0 ||
    normalized.startsWith('/') ||
    normalized.split('/').some((segment) => segment === '..')
  ) {
    throw new Error(`changed file path must be repository-relative: ${value}`);
  }
  return normalized;
}

function parseCliOptions(args) {
  const options = { files: [], filesFile: undefined, filesJson: undefined, format: 'json' };

  for (let index = 0; index < args.length; index += 1) {
    const token = args[index];
    if (token === '--file') {
      options.files.push(requireCliValue(args, ++index, '--file'));
      continue;
    }
    if (token === '--files-file') {
      options.filesFile = requireCliValue(args, ++index, '--files-file');
      continue;
    }
    if (token === '--files-json') {
      options.filesJson = requireCliValue(args, ++index, '--files-json');
      continue;
    }
    if (token === '--format') {
      options.format = requireCliValue(args, ++index, '--format');
      if (options.format !== 'json' && options.format !== 'lines') {
        throw new Error('--format must be json or lines');
      }
      continue;
    }
    if (token.startsWith('--')) throw new Error(`unknown option: ${token}`);
    options.files.push(token);
  }

  return options;
}

function parseFilesJson(value) {
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch (error) {
    throw new Error(`--files-json must contain a JSON array: ${error.message}`);
  }
  if (!Array.isArray(parsed)) throw new Error('--files-json must contain a JSON array');
  return parsed;
}

function requireCliValue(args, index, optionName) {
  const value = args[index];
  if (value === undefined || value.startsWith('--')) {
    throw new Error(`${optionName} requires a value`);
  }
  return value;
}

function inputRule({ exact = [], prefixes = [], suffixes = [] } = {}) {
  return {
    exact: Object.freeze([...exact]),
    prefixes: Object.freeze([...prefixes]),
    suffixes: Object.freeze([...suffixes]),
  };
}

function sharedInputRule(components, rule) {
  return { ...inputRule(rule), components: Object.freeze([...components].sort(compareStrings)) };
}

function matchesInputRule(rule, file) {
  return (
    rule.exact.includes(file) ||
    rule.prefixes.some((prefix) => file.startsWith(prefix)) ||
    rule.suffixes.some((suffix) => file.endsWith(suffix))
  );
}

function deduplicateSorted(values) {
  return [...new Set(values)].sort(compareStrings);
}

function compareStrings(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function freezeInputMap(map) {
  return Object.freeze(
    Object.fromEntries(
      Object.entries(map).map(([component, rules]) => [
        component,
        Object.freeze(rules.map((rule) => inputRule(rule))),
      ]),
    ),
  );
}

function freezeSharedInputRule(rule) {
  return Object.freeze({
    exact: Object.freeze([...rule.exact]),
    prefixes: Object.freeze([...rule.prefixes]),
    suffixes: Object.freeze([...rule.suffixes]),
    components: Object.freeze([...rule.components]),
  });
}

function isMainModule() {
  return (
    process.argv[1] !== undefined && fileURLToPath(import.meta.url) === resolve(process.argv[1])
  );
}

if (isMainModule()) {
  const [command, ...args] = process.argv.slice(2);
  if (command !== 'select') {
    throw new Error(
      'usage: deployment-components.mjs select [--file <path> ...] [--files-file <file>] [--files-json <json>] [--format json|lines]',
    );
  }
  await runCli(args);
}
