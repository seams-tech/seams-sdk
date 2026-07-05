import { expect, test } from '@playwright/test';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');
const testsRoot = path.join(repoRoot, 'tests');
const pnpmCommand = process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm';

function runCommand(
  args: string[],
  cwd: string,
  env?: NodeJS.ProcessEnv,
): Promise<{
  code: number | null;
  stdout: string;
  stderr: string;
}> {
  return new Promise((resolve, reject) => {
    const child = spawn(pnpmCommand, args, {
      cwd,
      env: {
        ...process.env,
        ...env,
      },
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

function extractTaggedJson(output: string, tag: string): unknown {
  const line = output
    .split(/\r?\n/)
    .map((entry) => entry.trim())
    .find((entry) => entry.startsWith(`${tag}:`));
  if (!line) {
    throw new Error(`Missing ${tag} output in:\n${output}`);
  }
  return JSON.parse(line.slice(tag.length + 1));
}

test.describe('source-backed recovery domain typing', () => {
  test('shared multichain recovery domain types align across shared, server, and client surfaces', async () => {
    const scriptPath = path.join(repoRoot, 'tests/unit/recoveryDomain.source.script.ts');
    const result = await runCommand(['exec', 'tsx', scriptPath], testsRoot, {
      TSX_TSCONFIG_PATH: path.join(repoRoot, 'tests/tsconfig.playwright.json'),
    });

    expect(result.code, `${result.stdout}\n${result.stderr}`).toBe(0);
    const parsed = extractTaggedJson(`${result.stdout}\n${result.stderr}`, 'RESULT') as {
      payloadVersion: string;
      accountId: string;
      recoverySessionId: string;
      deadlineEpochSeconds: number;
      derivedEvmOwnerAddress: string;
      bodyPrefix: string;
    };

    expect(parsed.payloadVersion).toBe('recovery_email_payload_v1');
    expect(parsed.accountId).toBe('alice.testnet');
    expect(parsed.recoverySessionId).toBe('ABC123');
    expect(parsed.deadlineEpochSeconds).toBe(1_893_456_000);
    expect(parsed.derivedEvmOwnerAddress).toBe(`0x${'11'.repeat(20)}`);
    expect(parsed.bodyPrefix).toBe('seams-recovery-v1');
  });
});
