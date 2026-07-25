import { rmSync } from 'node:fs';

import { resolveD1LocalPersistRoot } from './d1-local-friendly-paths.mjs';

const persistRoot = resolveD1LocalPersistRoot();

function main() {
  requireConfirmation(process.argv.slice(2));
  removePersistRoot();
  console.log(`[d1-local] Removed local D1 and Durable Object state: ${persistRoot}`);
  console.log(
    '[d1-local] Friendly SQLite symlinks were preserved; run `pnpm run d1:local:prepare` to repoint them and recreate the empty schemas.',
  );
}

function requireConfirmation(args) {
  if (args.includes('--yes')) return;
  throw new Error(
    'This deletes local console and signer D1 data. Stop the local Worker and rerun with --yes.',
  );
}

function removePersistRoot() {
  rmSync(persistRoot, { recursive: true, force: true });
}

main();
