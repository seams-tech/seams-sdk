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

test.describe('source-backed verified email recovery request', () => {
  test('derives NEAR EmailRecoverer args from the canonical verified recovery request', async () => {
    const scriptPath = path.join(
      repoRoot,
      'tests/unit/emailRecoveryVerifiedRequest.source.script.ts',
    );
    const result = await runCommand(['exec', 'tsx', scriptPath], testsRoot, {
      TSX_TSCONFIG_PATH: path.join(repoRoot, 'tests/tsconfig.playwright.json'),
    });

    expect(result.code, `${result.stdout}\n${result.stderr}`).toBe(0);
    const parsed = extractTaggedJson(`${result.stdout}\n${result.stderr}`, 'RESULT') as {
      verifiedRecoveryRequest: {
        version: string;
        nearAccountId: string;
        recoverySessionId: string;
        newNearPublicKey: string;
        newEvmOwnerAddress: string;
        deadlineEpochSeconds: number;
        scope?: string;
      };
      verifiedRecoveryRequestKeys: string[];
      parsedArgs: {
        expected_new_public_key: string;
        request_id: string;
      };
    };

    expect(parsed.verifiedRecoveryRequest).toEqual({
      version: 'verified_email_recovery_request_v1',
      nearAccountId: 'alice.testnet',
      recoverySessionId: 'ABC123',
      newNearPublicKey: 'ed25519:recovery-key',
      newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
      deadlineEpochSeconds: 1_893_456_000,
      scope: 'all-linked-evm-accounts',
    });
    expect(parsed.verifiedRecoveryRequestKeys).toEqual([
      'deadlineEpochSeconds',
      'nearAccountId',
      'newEvmOwnerAddress',
      'newNearPublicKey',
      'recoverySessionId',
      'scope',
      'version',
    ]);
    expect(parsed.parsedArgs.expected_new_public_key).toBe(
      parsed.verifiedRecoveryRequest.newNearPublicKey,
    );
    expect(parsed.parsedArgs.request_id).toBe(parsed.verifiedRecoveryRequest.recoverySessionId);
  });
});
