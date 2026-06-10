#!/usr/bin/env node
import dotenv from 'dotenv';
import pg from 'pg';

const LEGACY_EVENT_TYPE = 'router.request.completed';
const LEGACY_SOURCE = 'ROUTER';
const REQUIRED_SOURCES = ['WEBHOOK', 'BILLING', 'APPROVAL', 'SYSTEM'];

function normalize(value) {
  return String(value || '').trim();
}

function resolvePostgresUrl() {
  dotenv.config({ path: '.env' });
  return (
    normalize(process.env.CONSOLE_POSTGRES_MIGRATION_URL) ||
    normalize(process.env.CONSOLE_POSTGRES_URL) ||
    ''
  );
}

function assertStrictSourceConstraint(definition) {
  const normalized = normalize(definition);
  if (!normalized) return false;
  for (const source of REQUIRED_SOURCES) {
    if (!normalized.includes(source)) return false;
  }
  if (normalized.includes(LEGACY_SOURCE)) return false;
  return true;
}

async function main() {
  const postgresUrl = resolvePostgresUrl();
  if (!postgresUrl) {
    throw new Error(
      'Missing console Postgres URL. Set CONSOLE_POSTGRES_MIGRATION_URL (preferred) or CONSOLE_POSTGRES_URL.',
    );
  }

  const pool = new pg.Pool({ connectionString: postgresUrl });
  const client = await pool.connect();
  try {
    const legacyRows = await client.query(
      `SELECT COUNT(*)::int AS count
         FROM console_observability_events
        WHERE event_type = $1
           OR source = $2`,
      [LEGACY_EVENT_TYPE, LEGACY_SOURCE],
    );

    const sourceConstraint = await client.query(
      `SELECT pg_get_constraintdef(oid) AS definition
         FROM pg_constraint
        WHERE conrelid = 'console_observability_events'::regclass
          AND conname = 'console_observability_events_source_check'`,
    );

    const legacyRowCount = Number(legacyRows.rows?.[0]?.count || 0);
    const sourceConstraintDef = normalize(sourceConstraint.rows?.[0]?.definition);
    const strictConstraint = assertStrictSourceConstraint(sourceConstraintDef);

    const output = {
      legacyRowCount,
      strictSourceConstraint: strictConstraint,
      sourceConstraint: sourceConstraintDef || 'missing',
      requiredSources: REQUIRED_SOURCES,
    };
    console.log(JSON.stringify(output, null, 2));

    if (legacyRowCount > 0) {
      throw new Error(
        `Found ${legacyRowCount} legacy observability rows (event_type=${LEGACY_EVENT_TYPE} or source=${LEGACY_SOURCE})`,
      );
    }
    if (!strictConstraint) {
      throw new Error(
        'console_observability_events_source_check is missing or does not enforce WEBHOOK/BILLING/APPROVAL/SYSTEM only',
      );
    }

    console.log('[postgres-verify-observability-cleanup] success');
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((error) => {
  console.error(
    `[postgres-verify-observability-cleanup] fatal: ${
      error instanceof Error ? error.message : String(error)
    }`,
  );
  process.exit(1);
});
