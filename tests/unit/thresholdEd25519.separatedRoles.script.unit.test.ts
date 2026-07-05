import { expect, test } from '@playwright/test';
import { execFile } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const EXAMPLE_MANIFEST_PATH = path.join(repoRoot, 'crates/ed25519-hss/Cargo.toml');

const REQUIRED_CHECKLIST_LABELS = [
  'separation_of_shares',
  'wire_messages_do_not_embed_raw_secret_inputs',
  'client_never_gets_server_recovery_material',
  'server_never_gets_client_recovery_material',
  'split_role_e2e_matches_reference_output',
] as const;

test.describe('threshold Ed25519 separated-role verification', () => {
  test('reuses the separated-role HSS example as a keep-gate', async () => {
    test.setTimeout(60_000);

    const { stdout, stderr } = await execFileAsync(
      'cargo',
      [
        'run',
        '--manifest-path',
        EXAMPLE_MANIFEST_PATH,
        '--example',
        'prime_order_separated_roles_e2e',
      ],
      {
        cwd: repoRoot,
        env: { ...process.env, NO_COLOR: '1', CARGO_TERM_COLOR: 'never' },
        maxBuffer: 1024 * 1024 * 4,
      },
    );

    const combined = `${stdout}\n${stderr}`;
    expect(combined).toContain('Separated prime-order succinct HSS end-to-end example');
    expect(combined).toContain('segregation_audit: passed');

    for (const label of REQUIRED_CHECKLIST_LABELS) {
      expect(combined).toContain(`[x] ${label}:`);
    }
  });
});
