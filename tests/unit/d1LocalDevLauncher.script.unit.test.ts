import { expect, test } from '@playwright/test';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

type D1LocalDevLauncherModule = {
  readonly buildD1LocalDevWranglerArgs: (input: {
    readonly repoRoot: string;
    readonly packageRoot: string;
    readonly env?: Record<string, string | undefined>;
  }) => {
    readonly args: readonly string[];
    readonly envFiles: readonly string[];
  };
};

const launcherModulePromise = loadD1LocalDevLauncherModule();

function repoRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
}

async function loadD1LocalDevLauncherModule(): Promise<D1LocalDevLauncherModule> {
  const modulePath = path.join(
    repoRoot(),
    'packages/console-server-ts/scripts/d1-local-dev.mjs',
  );
  return (await import(pathToFileURL(modulePath).href)) as D1LocalDevLauncherModule;
}

function createTempLocalDevTree(): { readonly root: string; readonly consolePackageRoot: string } {
  const root = mkdtempSync(path.join(tmpdir(), 'seams-d1-local-dev-'));
  const consolePackageRoot = path.join(root, 'packages/console-server-ts');
  mkdirSync(path.join(root, 'packages/sdk-server-ts'), { recursive: true });
  mkdirSync(consolePackageRoot, { recursive: true });
  return { root, consolePackageRoot };
}

function writeSdkDevVars(root: string): string {
  const filePath = path.join(root, 'packages/sdk-server-ts/.dev.vars');
  writeFileSync(filePath, 'RELAYER_PRIVATE_KEY=ed25519:sdk\n');
  return filePath;
}

function writeConsoleDevVars(consolePackageRoot: string): string {
  const filePath = path.join(consolePackageRoot, '.dev.vars');
  writeFileSync(filePath, 'RELAYER_PRIVATE_KEY=ed25519:console\n');
  return filePath;
}

function envFilesFromArgs(args: readonly string[]): string[] {
  const envFiles: string[] = [];
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === '--env-file') envFiles.push(args[i + 1]);
  }
  return envFiles;
}

test('D1 local dev launcher omits env-file args when no real secret file exists', async () => {
  const module = await launcherModulePromise;
  const tree = createTempLocalDevTree();

  const command = module.buildD1LocalDevWranglerArgs({
    repoRoot: tree.root,
    packageRoot: tree.consolePackageRoot,
    env: {},
  });

  expect(command.envFiles).toEqual([]);
  expect(envFilesFromArgs(command.args)).toEqual([]);
  expect(command.args).toEqual([
    'dev',
    '--config',
    'wrangler.d1-local.toml',
    '--persist-to',
    '.wrangler/state/seams-d1',
    '--port',
    '9090',
  ]);
});

test('D1 local dev launcher loads sdk-server-ts and console .dev.vars in override order', async () => {
  const module = await launcherModulePromise;
  const tree = createTempLocalDevTree();
  const sdkDevVars = writeSdkDevVars(tree.root);
  const consoleDevVars = writeConsoleDevVars(tree.consolePackageRoot);

  const command = module.buildD1LocalDevWranglerArgs({
    repoRoot: tree.root,
    packageRoot: tree.consolePackageRoot,
    env: {
      SEAMS_D1_LOCAL_WRANGLER_CONFIG: 'custom-wrangler.toml',
      SEAMS_D1_LOCAL_PERSIST_TO: '.runtime/d1',
      SEAMS_D1_LOCAL_PORT: '9191',
    },
  });

  expect(command.envFiles).toEqual([sdkDevVars, consoleDevVars]);
  expect(envFilesFromArgs(command.args)).toEqual([sdkDevVars, consoleDevVars]);
  expect(command.args.slice(0, 7)).toEqual([
    'dev',
    '--config',
    'custom-wrangler.toml',
    '--persist-to',
    '.runtime/d1',
    '--port',
    '9191',
  ]);
});
