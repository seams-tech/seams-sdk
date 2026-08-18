#!/usr/bin/env node
/**
 * Proves the emitted declarations resolve the way an outside consumer sees
 * them — without this repository's source path aliases.
 *
 * Inside the repo everything resolves, because tsconfig maps `@/*` and
 * `@shared/*` to source. A published consumer has neither. When a declaration
 * leaks such a specifier the failure is silent rather than loud: a consumer
 * that happens to define its own `@/` resolves it against their own tree and
 * TypeScript degrades the type to `any`, so a green consumer typecheck can
 * mean nothing was checked at all.
 *
 * So this typechecks a small program against the built package with no `paths`
 * configured, and asserts the public types survive as real types. It is a
 * check, not a framework: one temp directory, one `tsc` invocation.
 */

import { mkdtemp, rm, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const repoRoot = resolve(packageRoot, '../..');

/* `never` forces tsc to name each type; a degraded one reports `any`, which is
   the failure this exists to catch. */
const CONSUMER_SOURCE = `
import type { SeamsWeb, NearProvisioningState } from '@seams/wallet';
type ProvisioningStatus = NearProvisioningState['status'];
type LaneRegistration = SeamsWeb['registration'];
declare const status: ProvisioningStatus;
declare const registration: LaneRegistration;
declare const provisioning: Awaited<ReturnType<LaneRegistration['getNearProvisioningState']>>;
export const a: never = status;
export const b: never = registration;
export const c: never = provisioning;
`;

const workspace = await mkdtemp(join(tmpdir(), 'seams-decl-check-'));
try {
  await mkdir(join(workspace, 'node_modules/@seams'), { recursive: true });
  const { symlink } = await import('node:fs/promises');
  await symlink(packageRoot, join(workspace, 'node_modules/@seams/wallet'), 'dir');
  /* React types are a peer dependency of the declarations. */
  await symlink(
    join(repoRoot, 'node_modules/@types'),
    join(workspace, 'node_modules/@types'),
    'dir',
  );

  await writeFile(join(workspace, 'consumer.ts'), CONSUMER_SOURCE, 'utf8');
  await writeFile(
    join(workspace, 'tsconfig.json'),
    JSON.stringify(
      {
        compilerOptions: {
          /* Deliberately no `paths`: that is the whole point. */
          module: 'esnext',
          moduleResolution: 'bundler',
          target: 'es2022',
          strict: true,
          noEmit: true,
          skipLibCheck: false,
          types: [],
        },
        files: ['consumer.ts'],
      },
      null,
      2,
    ),
    'utf8',
  );

  const result = spawnSync(
    'npx',
    ['tsc', '--noEmit', '-p', join(workspace, 'tsconfig.json')],
    { cwd: repoRoot, encoding: 'utf8' },
  );
  const output = `${result.stdout || ''}${result.stderr || ''}`;

  /* Each probe must fail as its real type. `any` means the declaration did not
     resolve, and an unresolved-module error means a specifier leaked. */
  const degraded = output.match(/Type 'any' is not assignable to type 'never'/g) || [];
  const unresolved = output.match(/Cannot find module '([^']+)'/g) || [];
  if (unresolved.length > 0) {
    console.error('[declarations] emitted declarations reference unresolvable modules:');
    console.error([...new Set(unresolved)].join('\n'));
    process.exit(1);
  }
  if (degraded.length > 0) {
    console.error(
      `[declarations] ${degraded.length} public type(s) degraded to 'any' for an external consumer.`,
    );
    console.error(output.split('\n').slice(0, 20).join('\n'));
    process.exit(1);
  }
  console.log('[declarations] public types resolve for an external consumer');
} finally {
  await rm(workspace, { recursive: true, force: true });
}
