#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const migrationNamePattern = /^[0-9]{4}_[a-z0-9_]+\.sql$/u;

export function readMigrationFiles(migrationsDir) {
  const directory = resolve(migrationsDir);
  const migrations = [];
  for (const name of readdirSync(directory).filter(isMigrationName).sort()) {
    migrations.push(readMigrationFile(directory, name));
  }
  return migrations;
}

export function digestMigrations(migrations) {
  const hash = createHash('sha256');
  for (const migration of migrations) {
    hash.update(migration.name);
    hash.update('\0');
    hash.update(migration.source);
    hash.update('\0');
  }
  return hash.digest('hex');
}

export function readMigrationSet(migrationsDir) {
  const migrations = readMigrationFiles(migrationsDir);
  const names = [];
  for (const migration of migrations) {
    names.push(migration.name);
  }
  return {
    fingerprint: digestMigrations(migrations),
    migrations: names,
  };
}

function isMigrationName(name) {
  return migrationNamePattern.test(name);
}

function readMigrationFile(directory, name) {
  return {
    name,
    source: readFileSync(join(directory, name), 'utf8'),
  };
}

function main(args) {
  const options = parseArgs(args);
  const database = requireOption(options, 'database');
  const migrationSet = readMigrationSet(requireOption(options, 'migrations-dir'));
  if (options.get('format') === 'json') {
    process.stdout.write(`${JSON.stringify({ database, ...migrationSet })}\n`);
    return;
  }
  process.stdout.write(`${migrationSet.fingerprint}\n`);
}

function parseArgs(args) {
  const options = new Map();
  for (let index = 0; index < args.length; index += 1) {
    const token = args[index];
    if (!token.startsWith('--')) throw new Error(`unexpected argument: ${token}`);
    const name = token.slice(2);
    const value = args[index + 1];
    if (value === undefined || value.startsWith('--'))
      throw new Error(`--${name} requires a value`);
    options.set(name, value);
    index += 1;
  }
  return options;
}

function requireOption(options, name) {
  const value = options.get(name);
  if (value === undefined || value.length === 0) throw new Error(`--${name} is required`);
  return value;
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
