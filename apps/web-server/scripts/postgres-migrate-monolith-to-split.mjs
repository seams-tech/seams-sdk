#!/usr/bin/env node
import dotenv from 'dotenv';
import {
  ensurePostgresSchema,
  getPostgresPool,
} from '../../../packages/sdk-web/dist/esm/server/storage/postgres.js';
import {
  ensureConsoleApiKeysPostgresSchema,
  ensureConsoleApprovalsPostgresSchema,
  ensureConsoleAuditPostgresSchema,
  ensureConsoleBillingPostgresSchema,
  ensureConsoleKeyExportsPostgresSchema,
  ensureConsoleObservabilityPostgresSchema,
  ensureConsoleOrgProjectEnvPostgresSchema,
  ensureConsolePoliciesPostgresSchema,
  ensureConsoleRuntimeSnapshotsPostgresSchema,
  ensureConsoleSettingsPostgresSchema,
  ensureConsoleTeamRbacPostgresSchema,
  ensureConsoleWalletsPostgresSchema,
  ensureConsoleWebhooksPostgresSchema,
} from '@seams/sdk/server/router/express';

dotenv.config({ path: '.env' });

const DEFAULT_BATCH_SIZE = 500;

function readEnv(name, fallback = '') {
  const value = process.env[name];
  if (typeof value !== 'string') return fallback;
  const trimmed = value.trim();
  return trimmed || fallback;
}

function readBoolEnv(name, fallback) {
  const raw = readEnv(name, '');
  if (!raw) return fallback;
  const normalized = raw.toLowerCase();
  if (normalized === '1' || normalized === 'true' || normalized === 'yes') return true;
  if (normalized === '0' || normalized === 'false' || normalized === 'no') return false;
  return fallback;
}

function normalizePositiveInt(raw, fallback) {
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) return fallback;
  return Math.floor(value);
}

function quoteIdent(value) {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error('Cannot quote empty SQL identifier');
  }
  return `"${normalized.replace(/"/g, '""')}"`;
}

function parsePostgresUrl(raw, label) {
  const value = String(raw || '').trim();
  if (!value) {
    throw new Error(`Missing ${label}`);
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch (err) {
    throw new Error(`Invalid ${label}: ${String(err?.message || err)}`);
  }
  if (parsed.protocol !== 'postgres:' && parsed.protocol !== 'postgresql:') {
    throw new Error(`Invalid ${label}: expected postgres:// or postgresql://`);
  }
  const database = decodeURIComponent(parsed.pathname.replace(/^\//, '').trim());
  if (!database) {
    throw new Error(`Invalid ${label}: missing database name`);
  }
  return parsed;
}

function withDatabase(url, database) {
  const next = new URL(url.toString());
  next.pathname = `/${encodeURIComponent(database)}`;
  return next;
}

function connectionIdentity(url) {
  const protocol = url.protocol.toLowerCase();
  const user = decodeURIComponent(url.username || '');
  const host = (url.hostname || '').toLowerCase();
  const port =
    url.port ||
    (protocol === 'postgresql:' || protocol === 'postgres:'
      ? '5432'
      : '');
  const db = decodeURIComponent(url.pathname.replace(/^\//, ''));
  return `${protocol}//${user}@${host}:${port}/${db}`;
}

function databaseIdentity(url) {
  const host = (url.hostname || '').toLowerCase();
  const port = url.port || '5432';
  const db = decodeURIComponent(url.pathname.replace(/^\//, ''));
  return `${host}:${port}/${db}`;
}

async function ensureDatabaseExists(adminPool, targetDb, logger) {
  const exists = await adminPool.query(
    'SELECT 1 FROM pg_database WHERE datname = $1 LIMIT 1',
    [targetDb],
  );
  if ((exists.rowCount || 0) > 0) {
    logger.info(`[postgres-migrate-split] database exists: ${targetDb}`);
    return;
  }
  await adminPool.query(`CREATE DATABASE ${quoteIdent(targetDb)}`);
  logger.info(`[postgres-migrate-split] created database: ${targetDb}`);
}

async function ensureSplitSchemas(input) {
  const { signerUrl, consoleUrl, logger } = input;

  await ensurePostgresSchema({ postgresUrl: signerUrl, logger });

  await ensureConsoleOrgProjectEnvPostgresSchema({ postgresUrl: consoleUrl, logger });
  await ensureConsoleTeamRbacPostgresSchema({ postgresUrl: consoleUrl, logger });
  await ensureConsoleApprovalsPostgresSchema({ postgresUrl: consoleUrl, logger });
  await ensureConsoleAuditPostgresSchema({ postgresUrl: consoleUrl, logger });
  await ensureConsoleWalletsPostgresSchema({ postgresUrl: consoleUrl, logger });
  await ensureConsolePoliciesPostgresSchema({ postgresUrl: consoleUrl, logger });
  await ensureConsoleApiKeysPostgresSchema({ postgresUrl: consoleUrl, logger });
  await ensureConsoleBillingPostgresSchema({ postgresUrl: consoleUrl, logger });
  await ensureConsoleWebhooksPostgresSchema({ postgresUrl: consoleUrl, logger });
  await ensureConsoleSettingsPostgresSchema({ postgresUrl: consoleUrl, logger });
  await ensureConsoleKeyExportsPostgresSchema({ postgresUrl: consoleUrl, logger });
  await ensureConsoleRuntimeSnapshotsPostgresSchema({ postgresUrl: consoleUrl, logger });
  await ensureConsoleObservabilityPostgresSchema({ postgresUrl: consoleUrl, logger });
}

async function listPublicTables(pool) {
  const out = await pool.query(`
    SELECT c.relname AS table_name
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind IN ('r', 'p')
       AND NOT c.relispartition
     ORDER BY c.relname ASC
  `);
  return out.rows.map((row) => String(row.table_name));
}

async function listForeignKeyEdges(pool, tableNames) {
  if (!tableNames.length) return [];
  const out = await pool.query(
    `
    SELECT child.relname AS child_table, parent.relname AS parent_table
      FROM pg_constraint con
      JOIN pg_class child ON child.oid = con.conrelid
      JOIN pg_namespace child_ns ON child_ns.oid = child.relnamespace
      JOIN pg_class parent ON parent.oid = con.confrelid
      JOIN pg_namespace parent_ns ON parent_ns.oid = parent.relnamespace
     WHERE con.contype = 'f'
       AND child_ns.nspname = 'public'
       AND parent_ns.nspname = 'public'
       AND child.relname = ANY($1::text[])
       AND parent.relname = ANY($1::text[])
    `,
    [tableNames],
  );
  return out.rows.map((row) => ({
    child: String(row.child_table),
    parent: String(row.parent_table),
  }));
}

function topologicalTableOrder(tableNames, edges) {
  const nodes = new Set(tableNames);
  const inbound = new Map();
  const outbound = new Map();

  for (const tableName of nodes) {
    inbound.set(tableName, new Set());
    outbound.set(tableName, new Set());
  }

  for (const edge of edges) {
    if (!nodes.has(edge.child) || !nodes.has(edge.parent)) continue;
    inbound.get(edge.child).add(edge.parent);
    outbound.get(edge.parent).add(edge.child);
  }

  const queue = Array.from(nodes).filter((name) => inbound.get(name).size === 0);
  queue.sort();

  const ordered = [];
  while (queue.length > 0) {
    const current = queue.shift();
    ordered.push(current);
    const dependents = Array.from(outbound.get(current) || []).sort();
    for (const dependent of dependents) {
      const incoming = inbound.get(dependent);
      incoming.delete(current);
      if (incoming.size === 0) queue.push(dependent);
    }
    queue.sort();
  }

  if (ordered.length === nodes.size) return ordered;

  const missing = Array.from(nodes).filter((name) => !ordered.includes(name)).sort();
  return [...ordered, ...missing];
}

async function listTableColumns(pool, tableName) {
  const out = await pool.query(
    `
    SELECT column_name, udt_name, is_nullable
      FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name = $1
     ORDER BY ordinal_position ASC
    `,
    [tableName],
  );
  return out.rows.map((row) => ({
    name: String(row.column_name),
    udtName: String(row.udt_name || ''),
    nullable: String(row.is_nullable || 'YES') === 'YES',
  }));
}

function isJsonUdt(udtName) {
  return udtName === 'json' || udtName === 'jsonb';
}

function parsePgArrayLiteral(input) {
  const value = String(input || '').trim();
  if (!value.startsWith('{') || !value.endsWith('}')) return null;
  if (value === '{}') return [];

  const result = [];
  let current = '';
  let inQuotes = false;
  let escaping = false;

  for (let i = 1; i < value.length - 1; i += 1) {
    const ch = value[i];
    if (escaping) {
      current += ch;
      escaping = false;
      continue;
    }
    if (ch === '\\') {
      escaping = true;
      continue;
    }
    if (ch === '"') {
      inQuotes = !inQuotes;
      continue;
    }
    if (ch === ',' && !inQuotes) {
      const token = current.trim();
      result.push(token === 'NULL' && !inQuotes ? null : token);
      current = '';
      continue;
    }
    current += ch;
  }

  const token = current.trim();
  result.push(token === 'NULL' && !inQuotes ? null : token);
  return result;
}

function normalizeJsonParameter(value) {
  if (value === null || typeof value === 'undefined') return null;
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return JSON.stringify('');
    try {
      return JSON.stringify(JSON.parse(trimmed));
    } catch {
      const parsedArray = parsePgArrayLiteral(trimmed);
      if (parsedArray !== null) return JSON.stringify(parsedArray);
      return JSON.stringify(value);
    }
  }
  return JSON.stringify(value);
}

function buildInsertSql(tableName, columns, rowCount) {
  const columnSql = columns.map((column) => quoteIdent(column.name)).join(', ');
  const valuesSql = [];
  let parameterIndex = 1;

  for (let rowIdx = 0; rowIdx < rowCount; rowIdx += 1) {
    const placeholders = [];
    for (const column of columns) {
      const castSql = isJsonUdt(column.udtName) ? `::${column.udtName}` : '';
      placeholders.push(`$${parameterIndex}${castSql}`);
      parameterIndex += 1;
    }
    valuesSql.push(`(${placeholders.join(', ')})`);
  }

  return `INSERT INTO public.${quoteIdent(tableName)} (${columnSql}) VALUES ${valuesSql.join(
    ', ',
  )} ON CONFLICT DO NOTHING`;
}

function buildCopySelectSql(tableName, columns) {
  const columnSql = columns.map((column) => quoteIdent(column.name)).join(', ');
  return `SELECT ${columnSql} FROM public.${quoteIdent(tableName)}`;
}

function isForeignKeyViolation(error) {
  return String(error?.code || '') === '23503';
}

async function copySingleTable(input) {
  const { sourcePool, targetPool, tableName, batchSize, logger } = input;

  const [sourceColumns, targetColumns] = await Promise.all([
    listTableColumns(sourcePool, tableName),
    listTableColumns(targetPool, tableName),
  ]);
  if (!sourceColumns.length || !targetColumns.length) {
    logger.warn(
      `[postgres-migrate-split] skipping ${tableName}: source or target columns missing`,
    );
    return { tableName, scanned: 0, inserted: 0 };
  }

  const sourceColumnSet = new Set(sourceColumns.map((column) => column.name));
  const commonColumns = targetColumns.filter((column) => sourceColumnSet.has(column.name));
  if (!commonColumns.length) {
    logger.warn(`[postgres-migrate-split] skipping ${tableName}: no common columns`);
    return { tableName, scanned: 0, inserted: 0 };
  }

  const maxParams = 65_000;
  const perTableBatchSize = Math.max(
    1,
    Math.min(batchSize, Math.floor(maxParams / commonColumns.length)),
  );

  const sourceClient = await sourcePool.connect();
  const cursorName = `c_${tableName}_${Date.now()}_${Math.floor(Math.random() * 10_000)}`;
  const selectSql = buildCopySelectSql(tableName, commonColumns);
  let scanned = 0;
  let inserted = 0;
  let skippedMissingRequired = 0;

  try {
    await sourceClient.query('BEGIN READ ONLY');
    await sourceClient.query(`DECLARE ${quoteIdent(cursorName)} NO SCROLL CURSOR FOR ${selectSql}`);

    while (true) {
      const fetch = await sourceClient.query(
        `FETCH FORWARD ${perTableBatchSize} FROM ${quoteIdent(cursorName)}`,
      );
      const rows = fetch.rows || [];
      if (!rows.length) break;
      scanned += rows.length;

      const filteredRows = [];
      for (const row of rows) {
        let missingRequired = false;
        for (const column of commonColumns) {
          if (column.nullable) continue;
          if (row[column.name] === null || typeof row[column.name] === 'undefined') {
            missingRequired = true;
            break;
          }
        }
        if (missingRequired) {
          skippedMissingRequired += 1;
          continue;
        }
        filteredRows.push(row);
      }

      if (!filteredRows.length) {
        continue;
      }

      const values = [];
      for (const row of filteredRows) {
        for (const column of commonColumns) {
          const rawValue = row[column.name];
          values.push(isJsonUdt(column.udtName) ? normalizeJsonParameter(rawValue) : rawValue);
        }
      }

      const insertSql = buildInsertSql(tableName, commonColumns, filteredRows.length);
      const write = await targetPool.query(insertSql, values);
      inserted += Number(write.rowCount || 0);
    }

    await sourceClient.query(`CLOSE ${quoteIdent(cursorName)}`);
    await sourceClient.query('COMMIT');
  } catch (err) {
    try {
      await sourceClient.query('ROLLBACK');
    } catch {
      // no-op
    }
    throw err;
  } finally {
    sourceClient.release();
  }

  logger.info(
    `[postgres-migrate-split] copied ${tableName}: scanned=${scanned} inserted=${inserted} skipped_missing_required=${skippedMissingRequired}`,
  );
  return { tableName, scanned, inserted, skippedMissingRequired };
}

async function copyDomainTables(input) {
  const { domain, sourcePool, targetPool, tableNames, batchSize, logger } = input;
  if (!tableNames.length) {
    logger.info(`[postgres-migrate-split] ${domain}: no tables to migrate`);
    return [];
  }

  const edges = await listForeignKeyEdges(sourcePool, tableNames);
  const ordered = topologicalTableOrder(tableNames, edges);

  logger.info(
    `[postgres-migrate-split] ${domain}: table order -> ${ordered.join(', ')}`,
  );

  const pending = [...ordered];
  const results = [];
  let pass = 1;
  while (pending.length > 0) {
    const next = [];
    let progressed = 0;
    logger.info(`[postgres-migrate-split] ${domain}: pass ${pass}, pending=${pending.length}`);
    for (const tableName of pending) {
      try {
        const result = await copySingleTable({
          sourcePool,
          targetPool,
          tableName,
          batchSize,
          logger,
        });
        results.push(result);
        progressed += 1;
      } catch (err) {
        if (isForeignKeyViolation(err)) {
          logger.warn(
            `[postgres-migrate-split] ${domain}: deferred ${tableName} due to FK ordering`,
          );
          next.push(tableName);
          continue;
        }
        throw err;
      }
    }
    if (!next.length) break;
    if (progressed === 0) {
      throw new Error(
        `[postgres-migrate-split] ${domain}: unable to resolve FK order for tables: ${next.join(
          ', ',
        )}`,
      );
    }
    pending.splice(0, pending.length, ...next);
    pass += 1;
  }

  return results;
}

function monthStartUtcMs(inputMs) {
  const d = new Date(inputMs);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1, 0, 0, 0, 0);
}

function addUtcMonths(monthStartMs, deltaMonths) {
  const d = new Date(monthStartMs);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + deltaMonths, 1, 0, 0, 0, 0);
}

function buildEventsPartitionTableName(monthStartMsValue) {
  const d = new Date(monthStartMsValue);
  const year = d.getUTCFullYear();
  const month = String(d.getUTCMonth() + 1).padStart(2, '0');
  return `console_observability_events_p_${year}${month}`;
}

async function ensureEventsPartition(q, monthStartMsValue) {
  const rangeStartMs = monthStartUtcMs(monthStartMsValue);
  const rangeEndMs = addUtcMonths(rangeStartMs, 1);
  const tableName = buildEventsPartitionTableName(rangeStartMs);
  await q.query(`
    CREATE TABLE IF NOT EXISTS ${quoteIdent(tableName)}
    PARTITION OF console_observability_events
    FOR VALUES FROM (${rangeStartMs}) TO (${rangeEndMs})
  `);
}

async function ensureEventsPartitionsForRange(q, rangeStartMs, rangeEndMs) {
  let monthStart = monthStartUtcMs(rangeStartMs);
  const endMonthStart = monthStartUtcMs(rangeEndMs);
  while (monthStart <= endMonthStart) {
    await ensureEventsPartition(q, monthStart);
    monthStart = addUtcMonths(monthStart, 1);
  }
}

async function prepareObservabilityPartitionRange(sourcePool, consolePool, logger) {
  const sourceExists = await sourcePool.query(
    `SELECT to_regclass('public.console_observability_events') IS NOT NULL AS exists`,
  );
  if (!Boolean(sourceExists.rows?.[0]?.exists)) return;

  const minMax = await sourcePool.query(`
    SELECT MIN(created_at_ms) AS min_created_at_ms, MAX(created_at_ms) AS max_created_at_ms
      FROM public.console_observability_events
  `);
  const minCreatedAtMs = Number(minMax.rows?.[0]?.min_created_at_ms || 0);
  const maxCreatedAtMs = Number(minMax.rows?.[0]?.max_created_at_ms || 0);
  if (!Number.isFinite(minCreatedAtMs) || !Number.isFinite(maxCreatedAtMs) || maxCreatedAtMs <= 0) {
    return;
  }

  await ensureEventsPartitionsForRange(consolePool, minCreatedAtMs, maxCreatedAtMs);
  logger.info(
    `[postgres-migrate-split] ensured observability partitions for ${new Date(
      minCreatedAtMs,
    ).toISOString()} .. ${new Date(maxCreatedAtMs).toISOString()}`,
  );
}

async function backfillObservabilityDedup(consolePool, logger) {
  const dedupExists = await consolePool.query(
    `SELECT to_regclass('public.console_observability_event_dedup') IS NOT NULL AS exists`,
  );
  const eventsExists = await consolePool.query(
    `SELECT to_regclass('public.console_observability_events') IS NOT NULL AS exists`,
  );
  if (!Boolean(dedupExists.rows?.[0]?.exists) || !Boolean(eventsExists.rows?.[0]?.exists)) return;

  const out = await consolePool.query(`
    INSERT INTO console_observability_event_dedup (namespace, org_id, event_id, created_at_ms)
    SELECT namespace, org_id, event_id, created_at_ms
      FROM console_observability_events
    ON CONFLICT (namespace, org_id, event_id) DO NOTHING
  `);
  logger.info(
    `[postgres-migrate-split] observability dedup synchronized: inserted=${Number(
      out.rowCount || 0,
    )}`,
  );
}

async function resetOwnedSequences(pool, domainTables, logger) {
  if (!domainTables.length) return;
  const out = await pool.query(
    `
    SELECT
      s.relname AS sequence_name,
      t.relname AS table_name,
      a.attname AS column_name
    FROM pg_class s
    JOIN pg_namespace sn ON sn.oid = s.relnamespace
    JOIN pg_depend d ON d.objid = s.oid AND d.deptype IN ('a', 'i')
    JOIN pg_class t ON t.oid = d.refobjid
    JOIN pg_namespace tn ON tn.oid = t.relnamespace
    JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = d.refobjsubid
    WHERE s.relkind = 'S'
      AND sn.nspname = 'public'
      AND tn.nspname = 'public'
      AND t.relname = ANY($1::text[])
    ORDER BY t.relname ASC, a.attname ASC
  `,
    [domainTables],
  );
  for (const row of out.rows) {
    const sequenceName = String(row.sequence_name);
    const tableName = String(row.table_name);
    const columnName = String(row.column_name);
    await pool.query(
      `
      SELECT setval(
        $1::regclass,
        COALESCE((SELECT MAX(${quoteIdent(columnName)}) FROM public.${quoteIdent(tableName)}), 0) + 1,
        false
      )
      `,
      [`public.${sequenceName}`],
    );
    logger.info(
      `[postgres-migrate-split] reset sequence public.${sequenceName} from ${tableName}.${columnName}`,
    );
  }
}

function summarizeResults(results) {
  return results.reduce(
    (acc, entry) => {
      acc.tables += 1;
      acc.scanned += Number(entry.scanned || 0);
      acc.inserted += Number(entry.inserted || 0);
      acc.skippedMissingRequired += Number(entry.skippedMissingRequired || 0);
      return acc;
    },
    { tables: 0, scanned: 0, inserted: 0, skippedMissingRequired: 0 },
  );
}

async function main() {
  const logger = console;

  const sourceRaw = readEnv('MONOLITH_POSTGRES_URL', readEnv('LEGACY_POSTGRES_URL', ''));
  const signerRaw = readEnv(
    'POSTGRES_MIGRATION_URL',
    readEnv('POSTGRES_URL', ''),
  );
  const consoleRaw = readEnv(
    'CONSOLE_POSTGRES_MIGRATION_URL',
    readEnv('CONSOLE_POSTGRES_URL', ''),
  );

  const sourceUrl = parsePostgresUrl(
    sourceRaw,
    'MONOLITH_POSTGRES_URL (or LEGACY_POSTGRES_URL)',
  );
  const signerUrl = parsePostgresUrl(
    signerRaw,
    'POSTGRES_MIGRATION_URL (or POSTGRES_URL)',
  );
  const consoleUrl = parsePostgresUrl(
    consoleRaw,
    'CONSOLE_POSTGRES_MIGRATION_URL (or CONSOLE_POSTGRES_URL)',
  );

  const sourceIdentity = connectionIdentity(sourceUrl);
  const signerIdentity = connectionIdentity(signerUrl);
  const consoleIdentity = connectionIdentity(consoleUrl);
  const sourceDbIdentity = databaseIdentity(sourceUrl);
  const signerDbIdentity = databaseIdentity(signerUrl);
  const consoleDbIdentity = databaseIdentity(consoleUrl);
  if (sourceDbIdentity === signerDbIdentity || sourceDbIdentity === consoleDbIdentity) {
    throw new Error(
      'Source DB must be different from signer/console target DBs. Use MONOLITH_POSTGRES_URL for source and split POSTGRES_URL + CONSOLE_POSTGRES_URL for targets.',
    );
  }
  if (signerDbIdentity === consoleDbIdentity) {
    throw new Error('Signer and console target DB URLs resolve to the same database');
  }

  const createDatabases = readBoolEnv('SPLIT_MIGRATION_CREATE_DATABASES', true);
  const batchSize = normalizePositiveInt(readEnv('SPLIT_MIGRATION_BATCH_SIZE', ''), DEFAULT_BATCH_SIZE);

  logger.info(`[postgres-migrate-split] source: ${sourceIdentity}`);
  logger.info(`[postgres-migrate-split] signer target: ${signerIdentity}`);
  logger.info(`[postgres-migrate-split] console target: ${consoleIdentity}`);
  logger.info(
    `[postgres-migrate-split] options: createDatabases=${String(
      createDatabases,
    )} batchSize=${batchSize}`,
  );

  const adminUrl = withDatabase(sourceUrl, 'postgres');
  let adminPool = null;
  if (createDatabases) {
    adminPool = await getPostgresPool(adminUrl.toString());
    await ensureDatabaseExists(
      adminPool,
      decodeURIComponent(signerUrl.pathname.replace(/^\//, '')),
      logger,
    );
    await ensureDatabaseExists(
      adminPool,
      decodeURIComponent(consoleUrl.pathname.replace(/^\//, '')),
      logger,
    );
  }

  await ensureSplitSchemas({
    signerUrl: signerUrl.toString(),
    consoleUrl: consoleUrl.toString(),
    logger,
  });

  const sourcePool = await getPostgresPool(sourceUrl.toString());
  const signerPool = await getPostgresPool(signerUrl.toString());
  const consolePool = await getPostgresPool(consoleUrl.toString());

  try {
    const [sourceTables, signerTables, consoleTables] = await Promise.all([
      listPublicTables(sourcePool),
      listPublicTables(signerPool),
      listPublicTables(consolePool),
    ]);

    const signerTableSet = new Set(signerTables);
    const consoleTableSet = new Set(consoleTables);

    const signerSelected = sourceTables
      .filter((name) => !name.startsWith('console_'))
      .filter((name) => name !== 'seams_sdk_migrations')
      .filter((name) => signerTableSet.has(name));

    const consoleSelected = sourceTables
      .filter((name) => name.startsWith('console_'))
      .filter((name) => consoleTableSet.has(name));

    await prepareObservabilityPartitionRange(sourcePool, consolePool, logger);

    const signerResults = await copyDomainTables({
      domain: 'signer',
      sourcePool,
      targetPool: signerPool,
      tableNames: signerSelected,
      batchSize,
      logger,
    });
    const consoleResults = await copyDomainTables({
      domain: 'console',
      sourcePool,
      targetPool: consolePool,
      tableNames: consoleSelected,
      batchSize,
      logger,
    });

    await backfillObservabilityDedup(consolePool, logger);
    await resetOwnedSequences(signerPool, signerSelected, logger);
    await resetOwnedSequences(consolePool, consoleSelected, logger);

    const signerSummary = summarizeResults(signerResults);
    const consoleSummary = summarizeResults(consoleResults);

    logger.info(
      `[postgres-migrate-split] signer summary: tables=${signerSummary.tables} scanned=${signerSummary.scanned} inserted=${signerSummary.inserted} skipped_missing_required=${signerSummary.skippedMissingRequired}`,
    );
    logger.info(
      `[postgres-migrate-split] console summary: tables=${consoleSummary.tables} scanned=${consoleSummary.scanned} inserted=${consoleSummary.inserted} skipped_missing_required=${consoleSummary.skippedMissingRequired}`,
    );
    logger.info('[postgres-migrate-split] complete');
  } finally {
    const poolsToClose = new Set([sourcePool, signerPool, consolePool]);
    if (adminPool) poolsToClose.add(adminPool);
    for (const pool of poolsToClose) {
      try {
        await pool.end();
      } catch {
        // no-op
      }
    }
  }
}

main().catch((err) => {
  console.error('[postgres-migrate-split] fatal:', err);
  process.exit(1);
});
