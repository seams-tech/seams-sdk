#!/usr/bin/env node
import dotenv from 'dotenv';
import { ensurePostgresSchema } from '../../../sdk/dist/esm/server/storage/postgres.js';

dotenv.config({ path: '.env' });

const postgresUrl = String(
  process.env.POSTGRES_MIGRATION_URL || process.env.POSTGRES_URL || '',
).trim();

if (!postgresUrl) {
  throw new Error(
    'Missing signer Postgres URL. Set POSTGRES_MIGRATION_URL (preferred) or POSTGRES_URL.',
  );
}

await ensurePostgresSchema({ postgresUrl, logger: console });
console.log('[postgres-migrate-signer] signer schema ready');
