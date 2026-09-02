import { expect, test } from '@playwright/test';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

type IntendedServicesModule = {
  readonly killChild: (
    child: { readonly pid: number; readonly kill: (signal: NodeJS.Signals) => boolean },
    signal: NodeJS.Signals,
    killAsGroup: boolean,
  ) => void;
  readonly terminateProcesses: (pids: readonly number[], signal: NodeJS.Signals) => void;
};

const intendedServicesModulePromise = loadIntendedServicesModule();

function repoRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
}

async function loadIntendedServicesModule(): Promise<IntendedServicesModule> {
  const modulePath = path.join(repoRoot(), 'tests/scripts/start-intended-services.mjs');
  return (await import(pathToFileURL(modulePath).href)) as IntendedServicesModule;
}

test('intended-services teardown falls back to the managed process after group EPERM', async () => {
  const module = await intendedServicesModulePromise;
  const originalKill = process.kill;
  const groupSignals: Array<{ readonly pid: number; readonly signal: NodeJS.Signals }> = [];
  const directSignals: NodeJS.Signals[] = [];

  process.kill = ((pid: number, signal: NodeJS.Signals) => {
    groupSignals.push({ pid, signal });
    throw Object.assign(new Error('operation not permitted'), { code: 'EPERM' });
  }) as typeof process.kill;

  try {
    module.killChild(
      {
        pid: 44,
        kill(signal) {
          directSignals.push(signal);
          return true;
        },
      },
      'SIGTERM',
      true,
    );
  } finally {
    process.kill = originalKill;
  }

  expect(groupSignals).toEqual([{ pid: -44, signal: 'SIGTERM' }]);
  expect(directSignals).toEqual(['SIGTERM']);
});

test('intended-services teardown continues after a descendant signal is denied', async () => {
  const module = await intendedServicesModulePromise;
  const originalKill = process.kill;
  const originalConsoleError = console.error;
  const signals: Array<{ readonly pid: number; readonly signal: NodeJS.Signals }> = [];
  const warnings: string[] = [];

  process.kill = ((pid: number, signal: NodeJS.Signals) => {
    signals.push({ pid, signal });
    if (pid === 22) {
      throw Object.assign(new Error('operation not permitted'), { code: 'EPERM' });
    }
    return true;
  }) as typeof process.kill;
  console.error = (message?: unknown) => {
    warnings.push(String(message));
  };

  try {
    module.terminateProcesses([11, 22, 33], 'SIGTERM');
  } finally {
    process.kill = originalKill;
    console.error = originalConsoleError;
  }

  expect(signals).toEqual([
    { pid: 11, signal: 'SIGTERM' },
    { pid: 22, signal: 'SIGTERM' },
    { pid: 33, signal: 'SIGTERM' },
  ]);
  expect(warnings).toEqual([
    '[intended-services] teardown warning: could not send SIGTERM to descendant 22: operation not permitted',
  ]);
});
