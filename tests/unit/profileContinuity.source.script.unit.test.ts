import { expect, test } from '@playwright/test';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');
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

test.describe('source-backed profile continuity snapshot', () => {
  test('reads canonical profile plus signer-set continuity from one snapshot', async () => {
    const scriptPath = path.join(repoRoot, 'tests/unit/profileContinuity.source.script.ts');
    const result = await runCommand(['exec', 'node', '--import', 'tsx', scriptPath], repoRoot, {
      TSX_TSCONFIG_PATH: path.join(repoRoot, 'sdk/tsconfig.json'),
    });

    expect(result.code, `${result.stdout}\n${result.stderr}`).toBe(0);
    const parsed = extractTaggedJson(`${result.stdout}\n${result.stderr}`, 'RESULT') as {
      profileId: string | null;
      nearAccountId: string | null;
      resolvedProfileId: string | null;
      chainAccounts: Array<{
        chainIdKey: string;
        accountAddress: string;
        accountModel: string;
        isPrimary: boolean;
      }>;
      accountSigners: Array<{
        chainIdKey: string;
        signerId: string;
        signerSlot: number;
        status: string;
      }>;
      activeSignerIds: string[];
    };

    expect(parsed.profileId).toBe('profile-alice');
    expect(parsed.nearAccountId).toBe('alice.testnet');
    expect(parsed.resolvedProfileId).toBe('profile-alice');
    expect(parsed.chainAccounts).toEqual([
      {
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
        accountModel: 'near-native',
        isPrimary: true,
      },
      {
        chainIdKey: 'evm:11155111',
        accountAddress: `0x${'11'.repeat(20)}`,
        accountModel: 'threshold-ecdsa',
        isPrimary: true,
      },
    ]);
    expect(parsed.accountSigners).toEqual([
      {
        chainIdKey: 'near:testnet',
        signerId: 'near-passkey-1',
        signerSlot: 1,
        status: 'active',
      },
      {
        chainIdKey: 'evm:11155111',
        signerId: `0x${'aa'.repeat(20)}`,
        signerSlot: 1,
        status: 'active',
      },
      {
        chainIdKey: 'evm:11155111',
        signerId: `0x${'bb'.repeat(20)}`,
        signerSlot: 2,
        status: 'pending',
      },
    ]);
    expect(parsed.activeSignerIds).toEqual(['near-passkey-1', `0x${'aa'.repeat(20)}`]);
  });
});
