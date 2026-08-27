#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const LOCAL_SITE_PORTS = Object.freeze([4001, 4002, 4003, 4004, 4005, 4006, 4101]);
const TERMINATION_TIMEOUT_MS = 2_000;
const POLL_INTERVAL_MS = 50;
const SLEEP_STATE = new Int32Array(new SharedArrayBuffer(4));

const listeners = collectListeners();
assertRepositoryOwnership(listeners);
stopListeners(listeners);

function collectListeners() {
  const listenersByPid = new Map();
  for (const port of LOCAL_SITE_PORTS) {
    const pids = listeningPidsForPort(port);
    for (const pid of pids) {
      const existing = listenersByPid.get(pid);
      if (existing) {
        existing.ports.push(port);
        continue;
      }
      listenersByPid.set(pid, {
        command: processCommand(pid),
        pid,
        ports: [port],
        workingDirectory: processWorkingDirectory(pid),
      });
    }
  }
  return [...listenersByPid.values()];
}

function processCommand(pid) {
  const result = run('ps', ['-p', String(pid), '-o', 'comm=']);
  requireSuccessfulCommand(result, `inspect process ${pid}`);
  return result.stdout.trim();
}

function listeningPidsForPort(port) {
  const result = run('lsof', ['-nP', '-t', `-iTCP:${port}`, '-sTCP:LISTEN']);
  if (result.status === 1) return [];
  requireSuccessfulCommand(result, `inspect port ${port}`);
  const pids = [];
  for (const line of result.stdout.split('\n')) {
    const pid = Number.parseInt(line.trim(), 10);
    if (Number.isInteger(pid) && pid > 0) pids.push(pid);
  }
  return pids;
}

function processWorkingDirectory(pid) {
  const result = run('lsof', ['-a', '-p', String(pid), '-d', 'cwd', '-Fn']);
  if (result.status === 1) return '';
  requireSuccessfulCommand(result, `inspect process ${pid}`);
  for (const line of result.stdout.split('\n')) {
    if (line.startsWith('n')) return line.slice(1);
  }
  return '';
}

function assertRepositoryOwnership(listeners) {
  for (const listener of listeners) {
    if (isInsideRepository(listener.workingDirectory)) continue;
    if (path.basename(listener.command) === 'caddy') continue;
    const ports = listener.ports.join(', ');
    const owner = listener.workingDirectory || 'unknown working directory';
    throw new Error(
      `[local-site] ports ${ports} are used by non-Caddy process ${listener.pid} outside this repository (${owner})`,
    );
  }
}

function isInsideRepository(directory) {
  if (!directory) return false;
  const relative = path.relative(REPOSITORY_ROOT, directory);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function stopListeners(listeners) {
  if (listeners.length === 0) return;
  for (const listener of listeners) signalProcess(listener.pid, 'SIGTERM');
  waitForExit(listeners, TERMINATION_TIMEOUT_MS);
  const survivors = runningListeners(listeners);
  for (const listener of survivors) signalProcess(listener.pid, 'SIGKILL');
  waitForExit(survivors, TERMINATION_TIMEOUT_MS);
  const remaining = runningListeners(survivors);
  if (remaining.length > 0) {
    const pids = [];
    for (const listener of remaining) pids.push(String(listener.pid));
    throw new Error(`[local-site] failed to stop repository processes: ${pids.join(', ')}`);
  }
  for (const listener of listeners) {
    console.log(
      `[local-site] stopped process ${listener.pid} on ports ${listener.ports.join(', ')}`,
    );
  }
}

function signalProcess(pid, signal) {
  try {
    process.kill(pid, signal);
  } catch (error) {
    if (error?.code === 'ESRCH') return;
    throw error;
  }
}

function waitForExit(listeners, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline && runningListeners(listeners).length > 0) {
    Atomics.wait(SLEEP_STATE, 0, 0, POLL_INTERVAL_MS);
  }
}

function runningListeners(listeners) {
  const running = [];
  for (const listener of listeners) {
    if (processIsRunning(listener.pid)) running.push(listener);
  }
  return running;
}

function processIsRunning(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error?.code === 'ESRCH') return false;
    throw error;
  }
}

function run(command, args) {
  return spawnSync(command, args, { encoding: 'utf8' });
}

function requireSuccessfulCommand(result, action) {
  if (result.error) throw result.error;
  if (result.status === 0) return;
  const details = String(result.stderr || '').trim();
  throw new Error(`[local-site] failed to ${action}${details ? `: ${details}` : ''}`);
}
