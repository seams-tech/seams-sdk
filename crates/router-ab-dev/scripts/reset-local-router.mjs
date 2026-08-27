import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, renameSync } from 'node:fs';
import net from 'node:net';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../..', import.meta.url));
const manifestPath = 'crates/router-ab-dev/Cargo.toml';
const protectedPorts = Object.freeze([4100, 4101, 4102, 4103, 4104, 4105]);
const portCheckTimeoutMs = 500;
const stateDirectoryNames = Object.freeze(['gateway', 'router-ab']);

try {
  await resetLocalRouter(process.argv.slice(2));
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}

async function resetLocalRouter(argv) {
  const root = parseRoot(argv);
  const listeningPorts = await findListeningPorts(protectedPorts);
  if (listeningPorts.length > 0) {
    throw new Error(
      `refusing Router A/B reset while TCP port(s) ${listeningPorts.join(', ')} are listening; ` +
        'stop the local Router topology first',
    );
  }

  const backupPaths = moveLocalState(root);
  if (backupPaths.length > 0) {
    console.log('Backed up existing Router A/B local state:');
    for (const { sourcePath, backupPath } of backupPaths) {
      console.log(`  ${sourcePath} -> ${backupPath}`);
    }
  } else {
    console.log('No existing Router A/B local state found to back up.');
  }

  runLocalInitializer(root);
  console.log('Router A/B local state reset. Start the local topology with: pnpm router');
}

function parseRoot(argv) {
  let root = repoRoot;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--') continue;
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    }
    if (arg === '--root' || arg.startsWith('--root=')) {
      const value = arg === '--root' ? argv[++index] : arg.slice('--root='.length);
      if (!value || value.startsWith('--')) {
        throw new Error(`${arg === '--root' ? '--root' : '--root='} requires a path\n${usage()}`);
      }
      root = value;
      continue;
    }
    throw new Error(`unknown argument ${arg}\n${usage()}`);
  }
  return resolve(repoRoot, root);
}

function usage() {
  return 'usage: pnpm router:reset [-- --root <path>]';
}

async function findListeningPorts(ports) {
  const results = await Promise.all(ports.map((port) => inspectPort(port)));
  return results.filter((result) => result.listening).map((result) => result.port);
}

function inspectPort(port) {
  return new Promise((resolveResult, rejectResult) => {
    let settled = false;
    let socket;
    const finish = (result, error = null) => {
      if (settled) return;
      settled = true;
      socket?.destroy();
      if (error) {
        rejectResult(error);
      } else {
        resolveResult(result);
      }
    };

    try {
      socket = net.createConnection({ host: '127.0.0.1', port });
      socket.once('connect', () => finish({ port, listening: true }));
      socket.once('error', (error) => {
        if (error.code === 'ECONNREFUSED') {
          finish({ port, listening: false });
          return;
        }
        finish(null, new Error(`could not inspect TCP port ${port}: ${error.message}`));
      });
      socket.setTimeout(portCheckTimeoutMs, () => {
        finish(null, new Error(`timed out inspecting TCP port ${port}`));
      });
    } catch (error) {
      finish(
        null,
        new Error(
          `could not inspect TCP port ${port}: ${error instanceof Error ? error.message : String(error)}`,
        ),
      );
    }
  });
}

function moveLocalState(root) {
  const cloudflareStateRoot = join(root, '.local', 'cloudflare-state');
  const existingState = stateDirectoryNames
    .map((name) => ({ name, sourcePath: join(cloudflareStateRoot, name) }))
    .filter(({ sourcePath }) => existsSync(sourcePath));
  if (existingState.length === 0) return [];

  mkdirSync(cloudflareStateRoot, { recursive: true });
  const timestamp = backupTimestamp();
  return existingState.map(({ name, sourcePath }) => {
    const backupPath = collisionSafeBackupPath(cloudflareStateRoot, name, timestamp);
    renameSync(sourcePath, backupPath);
    return { sourcePath, backupPath };
  });
}

function backupTimestamp() {
  const iso = new Date().toISOString();
  return `${iso.slice(0, 10).replaceAll('-', '')}-${iso.slice(11, 19).replaceAll(':', '')}-${iso.slice(20, 23)}Z`;
}

function collisionSafeBackupPath(stateRoot, stateName, timestamp) {
  const basePath = join(stateRoot, `${basename(stateName)}.backup-${timestamp}`);
  let candidate = basePath;
  let suffix = 1;
  while (existsSync(candidate)) {
    candidate = `${basePath}-${suffix}`;
    suffix += 1;
  }
  return candidate;
}

function runLocalInitializer(root) {
  const result = spawnSync(
    'cargo',
    [
      'run',
      '--manifest-path',
      manifestPath,
      '--bin',
      'router_ab_local_init',
      '--',
      '--root',
      root,
      '--force',
    ],
    { cwd: repoRoot, env: process.env, stdio: 'inherit' },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`router_ab_local_init failed${result.signal ? ` (${result.signal})` : ''}`);
  }
}
