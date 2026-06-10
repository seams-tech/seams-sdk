import { test, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

function runNodeScript(scriptPath: string, env: NodeJS.ProcessEnv): Promise<{
  code: number | null;
  stdout: string;
  stderr: string;
}> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [scriptPath], {
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += String(chunk || '');
    });
    child.stderr.on('data', (chunk) => {
      stderr += String(chunk || '');
    });
    child.on('error', reject);
    child.on('exit', (code) => resolve({ code, stdout, stderr }));
  });
}

test.describe('postgres-verify-split-domains script', () => {
  test('fails fast on invalid SQL identifier overrides', async () => {
    const scriptPath = fileURLToPath(
      new URL('../../apps/web-server/scripts/postgres-verify-split-domains.mjs', import.meta.url),
    );
    const result = await runNodeScript(scriptPath, {
      ...process.env,
      SIGNER_RUNTIME_USER: 'invalid-user-name',
    });

    expect(result.code).not.toBe(0);
    expect(`${result.stdout}\n${result.stderr}`).toContain(
      'Invalid SQL identifier "invalid-user-name"',
    );
  });

  test('validates console role overrides before any docker/sql execution', async () => {
    const scriptPath = fileURLToPath(
      new URL('../../apps/web-server/scripts/postgres-verify-split-domains.mjs', import.meta.url),
    );
    const result = await runNodeScript(scriptPath, {
      ...process.env,
      CONSOLE_MIGRATOR_USER: 'invalid-console-migrator',
    });

    expect(result.code).not.toBe(0);
    expect(`${result.stdout}\n${result.stderr}`).toContain(
      'Invalid SQL identifier "invalid-console-migrator"',
    );
  });
});
