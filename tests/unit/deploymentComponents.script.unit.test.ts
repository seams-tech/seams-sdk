import { expect, test } from '@playwright/test';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

type DeploymentComponentsModule = {
  readonly COMPONENT_NAMES: readonly string[];
  readonly selectComponents: (changedFiles: readonly string[]) => readonly string[];
};

const deploymentComponentsModule = loadDeploymentComponentsModule();

function repoRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
}

function runSelectorCli(args: readonly string[]) {
  return spawnSync(
    process.execPath,
    [path.join(repoRoot(), 'scripts/deployment-components.mjs'), ...args],
    {
      cwd: repoRoot(),
      encoding: 'utf8',
    },
  );
}

async function loadDeploymentComponentsModule(): Promise<DeploymentComponentsModule> {
  const modulePath = path.join(repoRoot(), 'scripts/deployment-components.mjs');
  return (await import(pathToFileURL(modulePath).href)) as DeploymentComponentsModule;
}

test('deployment component names are stable and sorted for release manifests', async () => {
  const module = await deploymentComponentsModule;

  expect(module.COMPONENT_NAMES).toEqual([
    'deriver-a',
    'deriver-b',
    'gateway',
    'router',
    'signer-iframe',
    'signing-worker',
    'site',
  ]);
});

test('selects the site for an app-only change', async () => {
  const module = await deploymentComponentsModule;

  expect(module.selectComponents(['apps/seams-site/src/main.ts'])).toEqual(['site']);
});

test('selects the coupled Pages artifact for wallet iframe source changes', async () => {
  const module = await deploymentComponentsModule;

  expect(
    module.selectComponents([
      'packages/sdk-web/src/SeamsWeb/walletIframe/host/lit-ui/iframe-lit-element-registry.ts',
    ]),
  ).toEqual(['signer-iframe', 'site']);
});

test('selects Gateway for either Gateway migration family', async () => {
  const module = await deploymentComponentsModule;

  expect(
    module.selectComponents(['packages/console-server-ts/migrations/d1-console/0020_new.sql']),
  ).toEqual(['gateway']);
  expect(
    module.selectComponents(['packages/sdk-server-ts/migrations/d1-signer/0013_new.sql']),
  ).toEqual(['gateway']);
});

test('expands Router changes to the complete topology while keeping role changes narrow', async () => {
  const module = await deploymentComponentsModule;

  expect(module.selectComponents(['crates/router-ab-cloudflare/src/router/mod.rs'])).toEqual([
    'deriver-a',
    'deriver-b',
    'router',
    'signing-worker',
  ]);
  expect(
    module.selectComponents(['crates/router-ab-cloudflare/src/strict_worker/router.rs']),
  ).toEqual(['deriver-a', 'deriver-b', 'router', 'signing-worker']);
  expect(module.selectComponents(['crates/router-ab-cloudflare/wrangler.deriver-a.toml'])).toEqual([
    'deriver-a',
  ]);
  expect(
    module.selectComponents(['crates/router-ab-cloudflare/src/strict_worker/deriver.rs']),
  ).toEqual(['deriver-a', 'deriver-b']);
  expect(
    module.selectComponents(['crates/router-ab-cloudflare/src/strict_worker/signing_worker.rs']),
  ).toEqual(['signing-worker']);
});

test('selects every Router role for shared Router crates', async () => {
  const module = await deploymentComponentsModule;

  expect(module.selectComponents(['crates/router-ab-core/src/lib.rs'])).toEqual([
    'deriver-a',
    'deriver-b',
    'router',
    'signing-worker',
  ]);
});

test('selects all components for shared lockfiles, toolchains, and orchestration scripts', async () => {
  const module = await deploymentComponentsModule;
  const allComponents = [...module.COMPONENT_NAMES];

  expect(module.selectComponents(['pnpm-lock.yaml'])).toEqual(allComponents);
  expect(module.selectComponents(['wasm/near_signer/Cargo.lock'])).toEqual(allComponents);
  expect(module.selectComponents(['scripts/deployment-release.mjs'])).toEqual(allComponents);
  expect(module.selectComponents(['rust-toolchain.toml'])).toEqual(allComponents);
});

test('selects Pages components for generated SDK bindings', async () => {
  const module = await deploymentComponentsModule;

  expect(
    module.selectComponents(['packages/sdk-web/src/core/platform/generated/signerCoreCommands.ts']),
  ).toEqual(['signer-iframe', 'site']);
});

test('ignores known documentation and test-only inputs', async () => {
  const module = await deploymentComponentsModule;

  expect(module.selectComponents(['docs/deployment/README.md'])).toEqual([]);
  expect(module.selectComponents(['tests/unit/deploymentComponents.script.unit.test.ts'])).toEqual(
    [],
  );
  expect(module.selectComponents(['README.md'])).toEqual([]);
});

test('fails closed to every component for unknown inputs and mixed known inputs', async () => {
  const module = await deploymentComponentsModule;
  const allComponents = [...module.COMPONENT_NAMES];

  expect(module.selectComponents(['packages/new-deployment-input.txt'])).toEqual(allComponents);
  expect(
    module.selectComponents(['apps/seams-site/src/main.ts', 'packages/new-deployment-input.txt']),
  ).toEqual(allComponents);
  expect(module.selectComponents(['crates/router-ab-cloudflare/src/routerish/mod.rs'])).toEqual(
    allComponents,
  );
});

test('deduplicates exact changed-file input and keeps output stable regardless of input order', async () => {
  const module = await deploymentComponentsModule;

  expect(
    module.selectComponents([
      'packages/console-server-ts/migrations/d1-console/0020_new.sql',
      'apps/seams-site/src/main.ts',
      'packages/console-server-ts/migrations/d1-console/0020_new.sql',
    ]),
  ).toEqual(['gateway', 'site']);
  expect(
    module.selectComponents([
      'apps/seams-site/src/main.ts',
      'packages/console-server-ts/migrations/d1-console/0020_new.sql',
    ]),
  ).toEqual(['gateway', 'site']);
});

test('CLI accepts exact files as repeated arguments and emits JSON or lines', () => {
  const scriptPath = path.join(repoRoot(), 'scripts/deployment-components.mjs');
  const json = execFileSync(
    process.execPath,
    [scriptPath, 'select', '--file', 'apps/seams-site/src/main.ts'],
    { encoding: 'utf8' },
  );
  expect(json).toBe('["site"]\n');

  const lines = execFileSync(
    process.execPath,
    [
      scriptPath,
      'select',
      '--format',
      'lines',
      '--files-json',
      JSON.stringify(['apps/seams-site/src/main.ts', 'packages/console-server-ts/src/index.ts']),
    ],
    { encoding: 'utf8' },
  );
  expect(lines).toBe('gateway\nsite\n');
});

test('CLI requires the select subcommand at the process boundary', () => {
  const result = runSelectorCli(['--file', 'apps/seams-site/src/main.ts']);

  expect(result.status).not.toBe(0);
  expect(`${result.stdout}\n${result.stderr}`).toContain('usage: deployment-components.mjs select');
});

test('release workflow invokes the selector through its required CLI command', () => {
  const workflowSource = readFileSync(
    path.join(repoRoot(), 'scripts/deployment-workflow-templates/release-cloudflare-stack.yml'),
    'utf8',
  );

  expect(workflowSource).toContain(
    'node scripts/deployment-components.mjs select --files-file "$RUNNER_TEMP/changed-files.txt"',
  );
  expect(workflowSource).toContain('name: template / release / cloudflare-stack');
  expect(workflowSource).toContain('name: release-change-set');
  expect(workflowSource).not.toContain('workflow_run:');
});

test('CLI unions component selection across files accumulated from multiple commits', () => {
  const tempRoot = mkdtempSync(path.join(os.tmpdir(), 'seams-deployment-components-'));
  const changedFilesPath = path.join(tempRoot, 'changed-files.txt');

  try {
    writeFileSync(
      changedFilesPath,
      [
        'apps/seams-site/src/main.ts',
        'packages/console-server-ts/src/index.ts',
        'crates/router-ab-cloudflare/src/router/mod.rs',
        '',
      ].join('\n'),
      'utf8',
    );

    const result = runSelectorCli(['select', '--files-file', changedFilesPath]);

    expect(result.status).toBe(0);
    expect(result.stdout).toBe(
      '["deriver-a","deriver-b","gateway","router","signing-worker","site"]\n',
    );
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('rejects absolute and parent-traversal changed-file inputs', async () => {
  const module = await deploymentComponentsModule;

  expect(() => module.selectComponents(['/tmp/changed.ts'])).toThrow(
    'changed file path must be repository-relative',
  );
  expect(() => module.selectComponents(['../changed.ts'])).toThrow(
    'changed file path must be repository-relative',
  );
});
