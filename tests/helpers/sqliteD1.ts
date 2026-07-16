import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../packages/sdk-server-ts/src/storage/tenantRoute';

type SqliteJsonRow = Record<string, unknown>;

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

export class SqliteCliD1Database implements D1DatabaseLike {
  constructor(readonly databasePath: string) {}

  prepare(query: string): D1PreparedStatementLike {
    return new SqliteCliD1PreparedStatement(this.databasePath, query, []);
  }

  async batch<T = unknown>(
    statements: readonly D1PreparedStatementLike[],
  ): Promise<readonly T[]> {
    const sqlStatements = statements.map(sqlFromD1PreparedStatement);
    const sql = `BEGIN IMMEDIATE; ${sqlStatements
      .map(sqlStatementWithChangesReadback)
      .join(' ')} COMMIT;`;
    const rows = runSqliteJson(this.databasePath, sql);
    return rows.map(buildD1BatchResult) as unknown as readonly T[];
  }

  async exec(query: string): Promise<unknown> {
    runSqlite(this.databasePath, query);
    return null;
  }
}

export class SqliteCliD1PreparedStatement implements D1PreparedStatementLike {
  constructor(
    private readonly databasePath: string,
    private readonly query: string,
    private readonly values: readonly unknown[],
  ) {}

  bind(...values: readonly unknown[]): D1PreparedStatementLike {
    return new SqliteCliD1PreparedStatement(this.databasePath, this.query, values);
  }

  async first<T = unknown>(columnName?: string): Promise<T | null> {
    const result = await this.all<SqliteJsonRow>();
    const row = result.results?.[0] || null;
    if (!row) return null;
    if (!columnName) return row as T;
    const value = row[columnName];
    return value === undefined ? null : (value as T);
  }

  async all<T = unknown>(): Promise<D1ResultLike<T>> {
    const results = runSqliteJson(this.databasePath, this.toSql());
    return {
      success: true,
      results: results as readonly T[],
      meta: {
        rows_read: results.length,
        rows_written: 0,
      },
    };
  }

  async run<T = unknown>(): Promise<D1ResultLike<T>> {
    const sql = `${this.toSql()} SELECT changes() AS changes, last_insert_rowid() AS last_row_id;`;
    const results = runSqliteJson(this.databasePath, sql);
    const metaRow = results.at(-1) || {};
    return {
      success: true,
      results: [] as readonly T[],
      meta: {
        changes: toInteger(metaRow.changes),
        last_row_id: toInteger(metaRow.last_row_id),
        rows_written: toInteger(metaRow.changes),
      },
    };
  }

  toSql(): string {
    return interpolateSql(this.query, this.values);
  }
}

export type TemporaryD1Database = {
  readonly database: D1DatabaseLike;
  readonly tempDir: string;
};

export function createTemporaryD1Database(): TemporaryD1Database {
  const tempDir = mkdtempSync(path.join(tmpdir(), 'seams-d1-adapter-test-'));
  return {
    database: new SqliteCliD1Database(path.join(tempDir, 'test.sqlite')),
    tempDir,
  };
}

export function cleanupTemporaryD1Database(tempDir: string): void {
  rmSync(tempDir, { recursive: true, force: true });
}

export type D1MigrationDirectoryName = 'd1-console' | 'd1-signer';

export function listD1MigrationFiles(directoryName: D1MigrationDirectoryName): readonly string[] {
  const packageRoot =
    directoryName === 'd1-console' ? 'packages/console-server-ts' : 'packages/sdk-server-ts';
  const migrationsDir = path.join(repoRoot, packageRoot, 'migrations', directoryName);
  const files: string[] = [];
  for (const fileName of readdirSync(migrationsDir)) {
    if (isD1SqlMigrationFile(fileName)) files.push(path.join(migrationsDir, fileName));
  }
  files.sort();
  if (files.length === 0) {
    throw new Error(`No D1 migrations found in ${migrationsDir}`);
  }
  return files;
}

export function d1MigrationFileBasenames(files: readonly string[]): readonly string[] {
  const names: string[] = [];
  for (const file of files) {
    names.push(path.basename(file));
  }
  return names;
}

export async function applyD1MigrationFiles(
  database: D1DatabaseLike,
  files: readonly string[],
): Promise<void> {
  for (const file of files) {
    await database.exec(readFileSync(file, 'utf8'));
  }
}

export async function readUserTableCount(database: D1DatabaseLike): Promise<number> {
  const row = await database
    .prepare(
      "SELECT COUNT(*) AS table_count FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
    )
    .first<{ table_count?: unknown }>();
  return toInteger(row?.table_count);
}

export async function readTableColumnNames(
  database: D1DatabaseLike,
  tableName: string,
): Promise<readonly string[]> {
  const rows = await database
    .prepare(`PRAGMA table_info(${quoteSqlIdentifier(tableName)})`)
    .all<{ name?: unknown }>();
  const names: string[] = [];
  for (const row of rows.results || []) {
    const name = typeof row.name === 'string' ? row.name.trim() : '';
    if (name) names.push(name);
  }
  return names;
}

function sqlFromD1PreparedStatement(statement: D1PreparedStatementLike): string {
  if (!(statement instanceof SqliteCliD1PreparedStatement)) {
    throw new Error('SQLite D1 test batch only accepts SQLite-backed statements');
  }
  return statement.toSql();
}

function sqlStatementWithChangesReadback(statement: string): string {
  return `${statement} SELECT changes() AS changes, last_insert_rowid() AS last_row_id;`;
}

function buildD1BatchResult(row: SqliteJsonRow): D1ResultLike {
  const changes = toInteger(row.changes);
  return {
    success: true,
    results: [],
    meta: {
      changes,
      last_row_id: toInteger(row.last_row_id),
      rows_written: changes,
    },
  };
}

function isD1SqlMigrationFile(fileName: string): boolean {
  return /^\d+_.*\.sql$/.test(fileName);
}

function runSqlite(databasePath: string, sql: string): void {
  const result = spawnSync('sqlite3', [databasePath], {
    encoding: 'utf8',
    input: sql,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status === 0) return;
  throw new Error(formatSqliteError(result.stderr, sql));
}

function runSqliteJson(databasePath: string, sql: string): readonly SqliteJsonRow[] {
  const result = spawnSync('sqlite3', ['-json', databasePath], {
    encoding: 'utf8',
    input: sql,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(formatSqliteError(result.stderr, sql));
  }
  const stdout = result.stdout.trim();
  if (!stdout) return [];
  return parseSqliteJsonRows(stdout);
}

function parseSqliteJsonRows(stdout: string): readonly SqliteJsonRow[] {
  const parsed = parseSqliteJsonValue(stdout);
  if (!Array.isArray(parsed)) {
    throw new Error(`sqlite3 JSON output was not an array: ${stdout}`);
  }
  return parsed.filter(isSqliteJsonRow);
}

function parseSqliteJsonValue(stdout: string): unknown[] {
  try {
    const parsed: unknown = JSON.parse(stdout);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    const rows: SqliteJsonRow[] = [];
    for (const line of stdout.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const parsedLine: unknown = JSON.parse(trimmed);
      if (Array.isArray(parsedLine)) {
        rows.push(...parsedLine.filter(isSqliteJsonRow));
      }
    }
    return rows;
  }
}

function formatSqliteError(stderr: string, sql: string): string {
  return `sqlite3 failed: ${stderr.trim() || 'unknown error'}\nSQL: ${sql}`;
}

function isSqliteJsonRow(input: unknown): input is SqliteJsonRow {
  return Boolean(input && typeof input === 'object' && !Array.isArray(input));
}

function interpolateSql(query: string, values: readonly unknown[]): string {
  const segments = splitSqlByPlaceholders(query);
  if (segments.length - 1 !== values.length) {
    throw new Error(
      `SQL placeholder count ${segments.length - 1} did not match bound value count ${values.length}`,
    );
  }
  let sql = segments[0] || '';
  for (let i = 0; i < values.length; i += 1) {
    sql += `${sqlLiteral(values[i])}${segments[i + 1] || ''}`;
  }
  return ensureSqlStatementTerminator(sql);
}

function splitSqlByPlaceholders(query: string): readonly string[] {
  const segments: string[] = [];
  let current = '';
  let inSingleQuote = false;
  for (let i = 0; i < query.length; i += 1) {
    const char = query[i] || '';
    const next = query[i + 1] || '';
    if (char === "'" && inSingleQuote && next === "'") {
      current += "''";
      i += 1;
      continue;
    }
    if (char === "'") {
      inSingleQuote = !inSingleQuote;
      current += char;
      continue;
    }
    if (char === '?' && !inSingleQuote) {
      segments.push(current);
      current = '';
      continue;
    }
    current += char;
  }
  segments.push(current);
  return segments;
}

function ensureSqlStatementTerminator(sql: string): string {
  const trimmed = sql.trim();
  return trimmed.endsWith(';') ? trimmed : `${trimmed};`;
}

function sqlLiteral(value: unknown): string {
  if (value === null || value === undefined) return 'NULL';
  if (typeof value === 'boolean') return value ? '1' : '0';
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof Uint8Array) return `X'${Buffer.from(value).toString('hex')}'`;
  if (value instanceof Date) return quoteSqlString(value.toISOString());
  return quoteSqlString(String(value));
}

function quoteSqlString(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function quoteSqlIdentifier(value: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) {
    throw new Error(`Invalid SQL identifier: ${value}`);
  }
  return `"${value}"`;
}

function toInteger(value: unknown): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : 0;
}
