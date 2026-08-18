import { test, expect } from '@playwright/test';
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const CONSOLE_CORE_SCHEMA = path.join(
  repoRoot,
  'packages/console-server-ts/migrations/d1-console-core/0001_console_core_initial.sql',
);
const COMPOSED_SCHEMA = path.join(
  repoRoot,
  'packages/wallet-console-server-ts/migrations/d1-console/0001_wallet_console_initial.sql',
);

// The R105 ownership inventory (docs/refactor-105-ownership-inventory.md).
// Every Console table has exactly one owner; the composed schema is the union
// and nothing else.
const CONSOLE_CORE_TABLES = [
  'api_keys',
  'audit_events',
  'audit_evidence',
  'billing_accounts',
  'billing_credit_purchases',
  'billing_disputes',
  'billing_ledger_entries',
  'billing_ledger_postings',
  'billing_monthly_active_resources',
  'billing_refunds',
  'billing_stripe_post_processing_outbox',
  'console_email_deliveries',
  'console_email_outbox',
  'environments',
  'invoice_line_items',
  'invoices',
  'observability_event_dedup',
  'observability_events',
  'observability_ingest_windows',
  'observability_request_rollups_minute',
  'organization_admin_permissions',
  'organization_invitations',
  'organization_memberships',
  'organization_owner_events',
  'organizations',
  'project_member_access',
  'projects',
  'stripe_webhook_events',
  'user_backup_emails',
  'user_profiles',
  'webhook_attempts',
  'webhook_dead_letters',
  'webhook_deliveries',
  'webhook_endpoint_categories',
  'webhook_endpoints',
] as const;

const WALLET_CONSOLE_TABLES = [
  'approvals',
  'billing_prepaid_reservation_summaries',
  'billing_prepaid_reservations',
  'key_exports',
  'policies',
  'policy_assignments',
  'policy_versions',
  'runtime_snapshot_outbox',
  'runtime_snapshots',
  'sponsored_call_records',
  'sponsorship_pricing_rules',
  'sponsorship_spend_cap_reservations',
  'sponsorship_spend_cap_windows',
  'wallet_index',
] as const;

function applyFreshSchema(schemaPath: string): Set<string> {
  const database = new DatabaseSync(':memory:');
  database.exec(fs.readFileSync(schemaPath, 'utf8'));
  const rows = database
    .prepare(
      `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`,
    )
    .all() as Array<{ name: string }>;
  database.close();
  return new Set(rows.map((row) => row.name));
}

test('fresh Console-core schema creates exactly the core-owned tables', () => {
  const created = applyFreshSchema(CONSOLE_CORE_SCHEMA);
  expect([...created].sort()).toEqual([...CONSOLE_CORE_TABLES]);
});

test('fresh composed Wallet Console schema creates exactly core plus wallet tables', () => {
  const created = applyFreshSchema(COMPOSED_SCHEMA);
  const expected = [...CONSOLE_CORE_TABLES, ...WALLET_CONSOLE_TABLES].sort();
  expect([...created].sort()).toEqual(expected);
  expect(created.size).toBe(49);
});

test('core and wallet ownership sets are disjoint', () => {
  const overlap = CONSOLE_CORE_TABLES.filter((name) =>
    (WALLET_CONSOLE_TABLES as readonly string[]).includes(name),
  );
  expect(overlap).toEqual([]);
});

test('composed schema embeds the core section verbatim before the wallet section', () => {
  const core = fs.readFileSync(CONSOLE_CORE_SCHEMA, 'utf8');
  const composed = fs.readFileSync(COMPOSED_SCHEMA, 'utf8');
  const marker = '-- ===== Wallet Console section (owner: wallet-console) =====';
  expect(composed).toContain(marker);
  const [coreSection, walletSection] = composed.split(marker);
  const canonicalMarker = '-- Canonical D1 schema.';
  expect(coreSection.slice(coreSection.indexOf(canonicalMarker)).trim()).toBe(
    core.slice(core.indexOf(canonicalMarker)).trim(),
  );
  for (const table of WALLET_CONSOLE_TABLES) {
    expect(coreSection).not.toContain(`CREATE TABLE "${table}"`);
    expect(coreSection).not.toContain(`CREATE TABLE ${table} `);
  }
  for (const table of ['organizations', 'billing_accounts', 'webhook_endpoints']) {
    expect(walletSection).not.toContain(`CREATE TABLE "${table}"`);
  }
});

test('Console-core schema contains no Wallet product vocabulary', () => {
  const core = fs.readFileSync(CONSOLE_CORE_SCHEMA, 'utf8');
  for (const forbidden of [
    'wallet',
    'signing_root',
    'sponsored_execution',
    'maw_',
    'key_export',
    'runtime_snapshot',
  ]) {
    expect(core.toLowerCase()).not.toContain(forbidden);
  }
});
