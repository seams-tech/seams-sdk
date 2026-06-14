import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import http from 'node:http';
import { dirname, isAbsolute, join, relative } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../..', import.meta.url));
const workerBinary = join(
  repoRoot,
  'crates',
  'router-ab-dev',
  'target',
  'debug',
  process.platform === 'win32' ? 'router_ab_local_worker.exe' : 'router_ab_local_worker',
);

const roles = [
  {
    title: 'Router',
    role: 'router',
    envFile: '.env.router-ab.router.local',
    urlKey: 'ROUTER_PUBLIC_URL',
  },
  {
    title: 'Deriver A',
    role: 'deriver-a',
    envFile: '.env.router-ab.deriver-a.local',
    urlKey: 'DERIVER_A_URL',
  },
  {
    title: 'Deriver B',
    role: 'deriver-b',
    envFile: '.env.router-ab.deriver-b.local',
    urlKey: 'DERIVER_B_URL',
  },
  {
    title: 'SigningWorker',
    role: 'signing-worker',
    envFile: '.env.router-ab.signing-worker.local',
    urlKey: 'SIGNING_WORKER_URL',
  },
];

const argv = process.argv.slice(2);
const options = parseArgs(argv);
const root = resolvePath(options.root);
const displayMode = options.mode === 'multiplex' && process.stdout.isTTY ? 'multiplex' : 'logs';
const labelWidth = Math.max(...roles.map((role) => role.role.length));
const panes = roles.map((role) => ({
  ...role,
  status: 'pending',
  pid: null,
  url: null,
  lines: [],
  child: null,
  exitPromise: null,
}));

let screenActive = false;
let renderTimer = null;
let shutdownStarted = false;
let rawModeEnabled = false;

const labelColors = {
  router: '\x1b[36m',
  'deriver-a': '\x1b[32m',
  'deriver-b': '\x1b[33m',
  'signing-worker': '\x1b[35m',
};
const resetColor = '\x1b[0m';

try {
  if (options.help) {
    printUsage();
    process.exit(0);
  }

  ensureLocalEnv();
  buildWorkerBinary();
  if (options.mode === 'multiplex' && displayMode === 'logs') {
    console.log('Multiplex mode requires a TTY; using interleaved logs.');
  }
  startWorkers();
  if (displayMode === 'multiplex') {
    enterDashboard();
    captureInput();
    process.stdout.on('resize', scheduleRender);
  }
  process.once('SIGINT', () => shutdown(130));
  process.once('SIGTERM', () => shutdown(143));
  scheduleRender();
} catch (error) {
  restoreTerminal();
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}

function ensureLocalEnv() {
  const missing = roles.filter((role) => !existsSync(join(root, role.envFile)));
  if (options.noInit && missing.length > 0) {
    throw new Error(
      `missing Router A/B local env files: ${missing.map((role) => role.envFile).join(', ')}`,
    );
  }
  if (!options.fresh && missing.length === 0) {
    return;
  }

  mkdirSync(root, { recursive: true });
  const args = [
    'run',
    '--manifest-path',
    'crates/router-ab-dev/Cargo.toml',
    '--bin',
    'router_ab_local_init',
    '--',
    '--root',
    root,
    '--force',
  ];
  if (!options.defaultPorts) {
    args.push('--ephemeral-ports');
  }
  run('cargo', args);
}

function buildWorkerBinary() {
  run('cargo', [
    'build',
    '--manifest-path',
    'crates/router-ab-dev/Cargo.toml',
    '--bin',
    'router_ab_local_worker',
  ]);
}

function startWorkers() {
  for (const pane of panes) {
    pane.url = readEnvValue(join(root, pane.envFile), pane.urlKey);
    appendLine(pane, `env ${relative(repoRoot, join(root, pane.envFile))}`);
    appendLine(pane, `url ${pane.url}`);
    appendLine(pane, 'starting worker...');
    pane.status = 'starting';

    const child = spawn(workerBinary, ['--role', pane.role, '--env', join(root, pane.envFile)], {
      cwd: root,
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    pane.child = child;
    pane.pid = child.pid ?? null;
    pane.exitPromise = new Promise((resolve) => child.once('exit', resolve));

    child.stdout.on('data', (chunk) => appendChunk(pane, chunk));
    child.stderr.on('data', (chunk) => appendChunk(pane, chunk, 'stderr: '));
    child.once('spawn', () => {
      appendLine(pane, `pid ${child.pid}`);
      appendProcessStatus(pane, child.pid);
      pollReady(pane);
    });
    child.once('exit', (code, signal) => {
      pane.status = signal ? `signal ${signal}` : `exit ${code ?? 'unknown'}`;
      appendLine(pane, `worker stopped: ${pane.status}`);
      scheduleRender();
      if (!shutdownStarted) {
        shutdown(code === 0 ? 0 : 1);
      }
    });
    child.once('error', (error) => {
      pane.status = 'spawn error';
      appendLine(pane, `spawn error: ${error.message}`);
      scheduleRender();
    });
  }
}

function pollReady(pane, attempts = 0) {
  if (shutdownStarted || pane.status.startsWith('exit') || pane.status.startsWith('signal')) {
    return;
  }
  healthCheck(pane.url)
    .then(() => {
      pane.status = 'ready';
      appendLine(pane, 'health ready');
    })
    .catch(() => {
      if (attempts < 100) {
        setTimeout(() => pollReady(pane, attempts + 1), 50);
      } else {
        pane.status = 'not ready';
        appendLine(pane, 'health check timed out');
      }
    })
    .finally(scheduleRender);
}

function healthCheck(baseUrl) {
  return new Promise((resolve, reject) => {
    const url = new URL('/healthz', baseUrl);
    const request = http.get(url, { timeout: 500 }, (response) => {
      response.resume();
      response.statusCode === 200 ? resolve() : reject(new Error(`status ${response.statusCode}`));
    });
    request.on('timeout', () => request.destroy(new Error('timeout')));
    request.on('error', reject);
  });
}

async function shutdown(exitCode) {
  if (shutdownStarted) {
    return;
  }
  shutdownStarted = true;
  for (const pane of panes) {
    if (pane.child && pane.child.exitCode === null && !pane.child.killed) {
      pane.status = 'stopping';
      appendLine(pane, 'stopping worker...');
      pane.child.kill('SIGTERM');
    }
  }
  scheduleRender();

  await Promise.race([
    Promise.all(panes.map((pane) => pane.exitPromise).filter(Boolean)),
    sleep(1200),
  ]);

  for (const pane of panes) {
    if (pane.child && pane.child.exitCode === null && !pane.child.killed) {
      pane.child.kill('SIGKILL');
    }
  }
  restoreTerminal();
  console.log('Stopped Router A/B local dev workers.');
  process.exit(exitCode);
}

function enterDashboard() {
  if (displayMode !== 'multiplex' || !process.stdout.isTTY) {
    return;
  }
  screenActive = true;
  process.stdout.write(
    [
      '\x1b[?1049h',
      '\x1b[?25l',
      '\x1b[?7l',
      '\x1b[?1000h',
      '\x1b[?1002h',
      '\x1b[?1006h',
      '\x1b[?1007h',
      '\x1b[2J',
      '\x1b[H',
    ].join(''),
  );
}

function restoreTerminal() {
  releaseInput();
  if (!screenActive) {
    return;
  }
  screenActive = false;
  process.stdout.write(
    [
      '\x1b[?1007l',
      '\x1b[?1006l',
      '\x1b[?1002l',
      '\x1b[?1000l',
      '\x1b[?7h',
      '\x1b[?25h',
      '\x1b[?1049l',
    ].join(''),
  );
}

function captureInput() {
  if (displayMode !== 'multiplex' || !process.stdin.isTTY) {
    return;
  }
  process.stdin.resume();
  process.stdin.on('data', handleInput);
  if (typeof process.stdin.setRawMode === 'function') {
    process.stdin.setRawMode(true);
    rawModeEnabled = true;
  }
}

function releaseInput() {
  process.stdin.off('data', handleInput);
  if (rawModeEnabled && typeof process.stdin.setRawMode === 'function') {
    process.stdin.setRawMode(false);
    rawModeEnabled = false;
  }
}

function handleInput(chunk) {
  for (const byte of chunk) {
    if (byte === 0x03) {
      shutdown(130);
      return;
    }
  }
}

function scheduleRender() {
  if (displayMode !== 'multiplex' || !process.stdout.isTTY) {
    return;
  }
  if (renderTimer) {
    return;
  }
  renderTimer = setTimeout(() => {
    renderTimer = null;
    renderDashboard();
  }, 40);
}

function renderDashboard() {
  if (!screenActive) {
    return;
  }
  const width = Math.max(process.stdout.columns ?? 120, 60);
  const height = Math.max(process.stdout.rows ?? 32, 16);
  const grid = Array.from({ length: height }, () => Array(width).fill(' '));
  const centerX = Math.floor(width / 2);
  const splitY = Math.floor(height / 2);
  drawDashboardBorders(grid, width, height, centerX, splitY);
  const layouts = [
    { x: 1, y: 1, w: centerX - 1, h: splitY - 1, headerX: 2, headerY: 0 },
    {
      x: centerX + 1,
      y: 1,
      w: width - centerX - 2,
      h: splitY - 1,
      headerX: centerX + 2,
      headerY: 0,
    },
    {
      x: 1,
      y: splitY + 1,
      w: centerX - 1,
      h: height - splitY - 2,
      headerX: 2,
      headerY: splitY,
    },
    {
      x: centerX + 1,
      y: splitY + 1,
      w: width - centerX - 2,
      h: height - splitY - 2,
      headerX: centerX + 2,
      headerY: splitY,
    },
  ];

  panes.forEach((pane, index) => drawPane(grid, layouts[index], pane));
  process.stdout.write(`\x1b[H${grid.map((row) => row.join('')).join('\n')}`);
}

function drawDashboardBorders(grid, width, height, centerX, splitY) {
  for (let col = 0; col < width; col += 1) {
    grid[0][col] = '─';
    grid[splitY][col] = '─';
    grid[height - 1][col] = '─';
  }
  for (let row = 0; row < height; row += 1) {
    grid[row][0] = '│';
    grid[row][centerX] = '│';
    grid[row][width - 1] = '│';
  }

  grid[0][0] = '┌';
  grid[0][centerX] = '┬';
  grid[0][width - 1] = '┐';
  grid[splitY][0] = '├';
  grid[splitY][centerX] = '┼';
  grid[splitY][width - 1] = '┤';
  grid[height - 1][0] = '└';
  grid[height - 1][centerX] = '┴';
  grid[height - 1][width - 1] = '┘';
}

function drawPane(grid, layout, pane) {
  const { x, y, w, h, headerX, headerY } = layout;
  if (w < 8 || h < 2) {
    return;
  }

  const header = ` ${pane.title} | ${pane.status}${pane.pid ? ` | pid ${pane.pid}` : ''} `;
  drawText(grid, headerX, headerY, clip(header, w - 2), w - 2);

  const visibleLines = pane.lines.slice(-h);
  for (let index = 0; index < visibleLines.length; index += 1) {
    drawText(grid, x, y + index, clip(visibleLines[index], w), w);
  }
}

function drawText(grid, x, y, text, maxWidth) {
  if (y < 0 || y >= grid.length) {
    return;
  }
  const clean = stripAnsi(text).slice(0, maxWidth);
  for (let i = 0; i < clean.length && x + i < grid[y].length; i += 1) {
    if (x + i >= 0) {
      grid[y][x + i] = clean[i];
    }
  }
}

function appendChunk(pane, chunk, prefix = '') {
  const text = stripAnsi(String(chunk));
  for (const rawLine of text.split(/\r?\n/)) {
    if (rawLine.length === 0) {
      continue;
    }
    appendLine(pane, `${prefix}${rawLine}`);
  }
}

function appendLine(pane, line) {
  const wrapped = wrap(stripAnsi(line), 180);
  pane.lines.push(...wrapped);
  if (pane.lines.length > 500) {
    pane.lines.splice(0, pane.lines.length - 500);
  }
  if (displayMode === 'logs') {
    for (const wrappedLine of wrapped) {
      process.stdout.write(`${formatLogLine(pane, wrappedLine)}\n`);
    }
  }
  scheduleRender();
}

function formatLogLine(pane, line) {
  const label = pane.role.padEnd(labelWidth, ' ');
  if (!process.stdout.isTTY || process.env.NO_COLOR) {
    return `${label} | ${line}`;
  }
  const color = labelColors[pane.role] ?? '';
  return `${color}${label}${resetColor} | ${line}`;
}

function appendProcessStatus(pane, pid) {
  if (!pid || process.platform === 'win32') {
    return;
  }
  const child = spawnSync('ps', ['-p', String(pid), '-o', 'pid=,ppid=,stat=,command='], {
    encoding: 'utf8',
  });
  const line = child.stdout?.trim().split(/\r?\n/)[0];
  if (line) {
    appendLine(pane, `ps ${line}`);
  }
}

function wrap(line, width) {
  if (line.length <= width) {
    return [line];
  }
  const lines = [];
  for (let i = 0; i < line.length; i += width) {
    lines.push(line.slice(i, i + width));
  }
  return lines;
}

function clip(value, width) {
  if (value.length <= width) {
    return value;
  }
  if (width <= 3) {
    return value.slice(0, width);
  }
  return `${value.slice(0, width - 3)}...`;
}

function stripAnsi(value) {
  return value.replace(/\x1b\[[0-9;]*m/g, '');
}

function readEnvValue(path, key) {
  const contents = readFileSync(path, 'utf8');
  for (const line of contents.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    const index = trimmed.indexOf('=');
    if (index === -1) {
      continue;
    }
    if (trimmed.slice(0, index) === key) {
      return trimmed.slice(index + 1);
    }
  }
  throw new Error(`${path} is missing ${key}`);
}

function run(command, args) {
  const child = spawnSync(command, args, {
    cwd: repoRoot,
    stdio: 'inherit',
    env: process.env,
  });
  if (child.status !== 0) {
    process.exit(child.status ?? 1);
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseArgs(args) {
  const parsed = {
    root: '.',
    mode: 'logs',
    fresh: false,
    defaultPorts: false,
    noInit: false,
    help: false,
  };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case '--':
        break;
      case '--root':
        parsed.root = readArgValue(args, ++index, '--root');
        break;
      case '--mode': {
        const mode = readArgValue(args, ++index, '--mode');
        if (mode !== 'logs' && mode !== 'multiplex') {
          throw new Error(`--mode must be logs or multiplex\n${usage()}`);
        }
        parsed.mode = mode;
        break;
      }
      case '--fresh':
        parsed.fresh = true;
        break;
      case '--default-ports':
        parsed.defaultPorts = true;
        break;
      case '--no-init':
        parsed.noInit = true;
        break;
      case '--help':
      case '-h':
        parsed.help = true;
        break;
      default:
        throw new Error(`unknown argument ${arg}\n${usage()}`);
    }
  }
  return parsed;
}

function readArgValue(args, index, name) {
  const value = args[index];
  if (!value || value.startsWith('--')) {
    throw new Error(`${name} requires a value`);
  }
  return value;
}

function resolvePath(path) {
  return isAbsolute(path) ? path : join(repoRoot, path);
}

function printUsage() {
  console.log(usage());
}

function usage() {
  return `usage: pnpm router [-- --root <path>] [--fresh] [--default-ports] [--no-init]
       pnpm router:multiplex [-- --root <path>] [--fresh] [--default-ports] [--no-init]

Runs Router, Deriver A, Deriver B, and SigningWorker in one terminal.

Options:
  --root <path>      Local root containing generated env files. Defaults to repo root.
  --mode <mode>      Display mode: logs or multiplex. Defaults to logs.
  --fresh           Regenerate env files before launch.
  --default-ports   Use 8787-8790 when generating env files. Fresh init defaults to free ports.
  --no-init         Require env files to already exist.

Press Ctrl-C to stop all four workers and restore the terminal.`;
}
