import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../..', import.meta.url));
const manifestPath = 'crates/router-ab-dev/Cargo.toml';
const [command, ...rawArgs] = process.argv.slice(2);
const args = rawArgs[0] === '--' ? rawArgs.slice(1) : rawArgs;

switch (command) {
  case 'init':
    cargoRun('router_ab_local_init', args);
    break;
  case 'up':
    cargoBuild('router_ab_local_worker', 'router_ab_local_up');
    cargoRun('router_ab_local_up', args);
    break;
  case 'down':
    cargoRun('router_ab_local_down', args);
    break;
  case 'check':
    cargoBuild('router_ab_local_smoke');
    cargoRun('router_ab_local_smoke', args);
    break;
  case 'smoke':
    cargoBuild('router_ab_local_worker', 'router_ab_local_smoke');
    cargoRun('router_ab_local_smoke', ['--ephemeral', ...args]);
    break;
  case 'smoke-bundled':
    cargoBuild('router_ab_local_bundled', 'router_ab_local_smoke');
    cargoRun('router_ab_local_smoke', ['--ephemeral', '--topology', 'bundled', ...args]);
    break;
  case 'bundled':
    cargoBuild('router_ab_local_bundled');
    cargoRun('router_ab_local_bundled', args);
    break;
  case 'dev-signer':
    cargoRunWithManifest('crates/router-ab-core/Cargo.toml', 'dev_router_ab_signer', args);
    break;
  case 'seed-sqlite':
    cargoRun('dev_seed_router_ab_sqlite', args);
    break;
  case '--help':
  case '-h':
  case undefined:
    printUsage();
    process.exit(command ? 0 : 1);
    break;
  default:
    console.error(`unknown Router A/B local command: ${command}`);
    printUsage();
    process.exit(1);
}

function cargoBuild(...bins) {
  run('cargo', [
    'build',
    '--manifest-path',
    manifestPath,
    ...bins.flatMap((bin) => ['--bin', bin]),
  ]);
}

function cargoRun(bin, binArgs) {
  cargoRunWithManifest(manifestPath, bin, binArgs);
}

function cargoRunWithManifest(manifest, bin, binArgs) {
  run('cargo', ['run', '--manifest-path', manifest, '--bin', bin, '--', ...binArgs]);
}

function run(commandName, commandArgs) {
  const child = spawnSync(commandName, commandArgs, {
    cwd: repoRoot,
    stdio: 'inherit',
    env: process.env,
  });
  if (child.status !== 0) {
    process.exit(child.status ?? 1);
  }
}

function printUsage() {
  console.log(`usage: pnpm router:<command> [-- args]

Commands:
  router:init             materialize local env and seed data
  router:up               start detached four-worker local topology
  router:check            smoke-test already running local topology
  router:down             stop detached local workers
  router:smoke            run ephemeral four-worker smoke
  router:smoke:bundled    run ephemeral bundled smoke
  router:bundled          start bundled single-server topology
  router:dev:signer       run the core dev signer smoke
  router:seed:sqlite      seed local SQLite state`);
}
