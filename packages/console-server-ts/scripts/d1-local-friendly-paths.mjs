import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  realpathSync,
  symlinkSync,
  unlinkSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { runCommandArgs } from './d1-staging-config.mjs';

const packageRoot = fileURLToPath(new URL('../', import.meta.url));
const repoRoot = fileURLToPath(new URL('../../..', import.meta.url));

export const localD1DatabaseDefinitions = Object.freeze([
  Object.freeze({
    logicalName: 'console',
    databaseName: 'seams-console',
    markerTable: 'organizations',
    fileName: 'seams_console.sqlite',
  }),
  Object.freeze({
    logicalName: 'signer',
    databaseName: 'seams-signer',
    markerTable: 'wallets',
    fileName: 'seams_signer.sqlite',
  }),
]);

export function resolveD1LocalPersistRoot(input = {}) {
  const resolvedPackageRoot = input.packageRoot || packageRoot;
  const env = input.env || process.env;
  const configuredPath = env.SEAMS_D1_LOCAL_PERSIST_TO || '.wrangler/state/seams-d1';
  return path.resolve(resolvedPackageRoot, configuredPath);
}

export function resolveD1LocalFriendlyRoot(input = {}) {
  const resolvedRepoRoot = input.repoRoot || repoRoot;
  const env = input.env || process.env;
  const configuredPath = env.SEAMS_D1_LOCAL_SQLITE_DIR || 'sqlite';
  return path.resolve(resolvedRepoRoot, configuredPath);
}

export function ensureFriendlyD1DatabasePaths(input = {}) {
  const persistRoot = input.persistRoot || resolveD1LocalPersistRoot(input);
  const friendlyRoot = input.friendlyRoot || resolveD1LocalFriendlyRoot(input);
  const d1ObjectRoot = path.join(persistRoot, 'v3/d1/miniflare-D1DatabaseObject');

  if (!existsSync(d1ObjectRoot)) return [];

  mkdirSync(friendlyRoot, { recursive: true });
  const linkedDatabases = [];
  for (const database of localD1DatabaseDefinitions) {
    const sourcePath = findLocalD1Database(d1ObjectRoot, database);
    if (!sourcePath) continue;
    const friendlyPath = path.join(friendlyRoot, database.fileName);
    ensureFriendlySymlink({ database, friendlyPath, sourcePath });
    linkedDatabases.push({ ...database, sourcePath, friendlyPath });
  }
  return linkedDatabases;
}

function findLocalD1Database(d1ObjectRoot, database) {
  const matches = [];
  for (const fileName of readdirSync(d1ObjectRoot)) {
    if (!fileName.endsWith('.sqlite') || fileName === 'metadata.sqlite') continue;
    const candidate = path.join(d1ObjectRoot, fileName);
    if (sqliteTableExists(candidate, database.markerTable)) matches.push(candidate);
  }
  if (matches.length > 1) {
    throw new Error(
      `Expected one local ${database.databaseName} database with ${database.markerTable}; found ${matches.length}`,
    );
  }
  return matches[0] || '';
}

function ensureFriendlySymlink(input) {
  const { database, friendlyPath, sourcePath } = input;
  const friendlyIsDangling = isDanglingSymlink(friendlyPath);
  if (existsSync(friendlyPath) || friendlyIsDangling) {
    const friendlyStats = lstatSync(friendlyPath);
    if (!friendlyStats.isSymbolicLink()) {
      throw new Error(
        `Friendly local ${database.databaseName} path already exists as a regular file: ${friendlyPath}`,
      );
    }
    if (!friendlyIsDangling && sameResolvedPath(friendlyPath, sourcePath)) return;
    unlinkSync(friendlyPath);
  }

  // The symlink keeps Wrangler's hashed path and its WAL/SHM sidecars authoritative.
  const relativeSourcePath = path.relative(path.dirname(friendlyPath), sourcePath);
  symlinkSync(relativeSourcePath, friendlyPath);
}

function isDanglingSymlink(filePath) {
  try {
    return lstatSync(filePath).isSymbolicLink() && !existsSync(filePath);
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

function sameResolvedPath(leftPath, rightPath) {
  return realpathSync(leftPath) === realpathSync(rightPath);
}

function sqliteTableExists(databasePath, tableName) {
  const result = runCommandArgs(
    'sqlite3',
    [databasePath, `SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '${tableName}';`],
    { cwd: packageRoot },
  );
  return result.stdout.trim() === '1';
}

function printLinkedDatabases(linkedDatabases) {
  if (linkedDatabases.length === 0) {
    console.log('[d1-local] No initialized local D1 databases found to link.');
    return;
  }
  for (const database of linkedDatabases) {
    console.log(`[d1-local] ${database.databaseName}: ${database.friendlyPath}`);
  }
}

function isMainModule() {
  return process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
}

if (isMainModule()) printLinkedDatabases(ensureFriendlyD1DatabasePaths());
