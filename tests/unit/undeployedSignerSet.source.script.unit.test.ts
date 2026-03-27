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

test.describe('source-backed undeployed signer-set representation', () => {
  test('server manifest and client bootstrap share the same undeployed signer-set shape', async () => {
    const scriptPath = path.join(repoRoot, 'tests/unit/undeployedSignerSet.source.script.ts');
    const result = await runCommand(['exec', 'node', '--import', 'tsx', scriptPath], repoRoot, {
      TSX_TSCONFIG_PATH: path.join(repoRoot, 'sdk/tsconfig.json'),
    });

    expect(result.code, `${result.stdout}\n${result.stderr}`).toBe(0);
    const parsed = extractTaggedJson(`${result.stdout}\n${result.stderr}`, 'RESULT') as {
      manifestUndeployedSignerSet: {
        version: string;
        ownerAddresses: string[];
        activeOwnerAddresses: string[];
        pendingOwnerAddresses: string[];
        owners: Array<Record<string, unknown>>;
      };
      clientUndeployedSignerSet: {
        version: string;
        ownerAddresses: string[];
        activeOwnerAddresses: string[];
        pendingOwnerAddresses: string[];
        owners: Array<Record<string, unknown>>;
      };
      syncedMetadataUndeployedSignerSet: {
        version: string;
        ownerAddresses: string[];
        activeOwnerAddresses: string[];
        pendingOwnerAddresses: string[];
        owners: Array<Record<string, unknown>>;
      };
    };

    expect(parsed.manifestUndeployedSignerSet.version).toBe(
      'undeployed_smart_account_signer_set_v1',
    );
    expect(parsed.clientUndeployedSignerSet.version).toBe('undeployed_smart_account_signer_set_v1');
    expect(parsed.manifestUndeployedSignerSet.ownerAddresses).toEqual(
      parsed.clientUndeployedSignerSet.ownerAddresses,
    );
    expect(parsed.manifestUndeployedSignerSet.activeOwnerAddresses).toEqual(
      parsed.clientUndeployedSignerSet.activeOwnerAddresses,
    );
    expect(parsed.manifestUndeployedSignerSet.pendingOwnerAddresses).toEqual(
      parsed.clientUndeployedSignerSet.pendingOwnerAddresses,
    );
    expect(parsed.manifestUndeployedSignerSet.owners).toEqual(
      parsed.clientUndeployedSignerSet.owners,
    );
    expect(parsed.syncedMetadataUndeployedSignerSet).toEqual(parsed.manifestUndeployedSignerSet);
  });
});
