type Queryable = {
  query: (
    text: string,
    values?: unknown[],
  ) => Promise<{ rows: Record<string, unknown>[]; rowCount?: number }>;
};

type QueryClient = Queryable & {
  release: () => void;
};

type ConnectablePool = Queryable & {
  connect?: () => Promise<QueryClient>;
};

export interface ConsoleTenantContext {
  namespace: string;
  orgId: string;
}

const CONSOLE_NAMESPACE_GUC = 'app.console_namespace';
const CONSOLE_ORG_ID_GUC = 'app.console_org_id';

function assertNonEmptyString(input: string, label: string): string {
  const value = String(input || '').trim();
  if (!value) {
    throw new Error(`${label} is required`);
  }
  return value;
}

function assertSimpleIdentifier(input: string): string {
  const value = String(input || '').trim();
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(value)) {
    throw new Error(`Invalid SQL identifier: ${input}`);
  }
  return value;
}

export async function setConsoleTenantContext(
  q: Queryable,
  context: ConsoleTenantContext,
): Promise<void> {
  const namespace = assertNonEmptyString(context.namespace, 'namespace');
  const orgId = assertNonEmptyString(context.orgId, 'orgId');
  await q.query(
    `SELECT set_config($1, $2, true), set_config($3, $4, true)`,
    [CONSOLE_NAMESPACE_GUC, namespace, CONSOLE_ORG_ID_GUC, orgId],
  );
}

export async function withConsoleTenantContextTx<T>(
  pool: ConnectablePool,
  context: ConsoleTenantContext,
  fn: (q: Queryable) => Promise<T>,
): Promise<T> {
  if (typeof pool.connect !== 'function') {
    throw new Error(
      'Postgres pool does not expose connect(); tenant-context transactions require a dedicated client',
    );
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await setConsoleTenantContext(client, context);
    const out = await fn(client);
    await client.query('COMMIT');
    return out;
  } catch (error: unknown) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // no-op
    }
    throw error;
  } finally {
    client.release();
  }
}

export async function ensureConsoleTenantRlsPolicies(input: {
  q: Queryable;
  table: string;
  policyName: string;
  namespaceColumn?: string;
  orgIdColumn?: string;
}): Promise<void> {
  const table = assertSimpleIdentifier(input.table);
  const policyName = assertSimpleIdentifier(input.policyName);
  const namespaceColumn = assertSimpleIdentifier(input.namespaceColumn || 'namespace');
  const orgIdColumn = assertSimpleIdentifier(input.orgIdColumn || 'org_id');

  await input.q.query(`ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY`);
  await input.q.query(`ALTER TABLE ${table} FORCE ROW LEVEL SECURITY`);
  await input.q.query(`DROP POLICY IF EXISTS ${policyName} ON ${table}`);
  await input.q.query(`
    CREATE POLICY ${policyName}
      ON ${table}
      USING (
        ${namespaceColumn} = current_setting('${CONSOLE_NAMESPACE_GUC}', true)
        AND ${orgIdColumn} = current_setting('${CONSOLE_ORG_ID_GUC}', true)
      )
      WITH CHECK (
        ${namespaceColumn} = current_setting('${CONSOLE_NAMESPACE_GUC}', true)
        AND ${orgIdColumn} = current_setting('${CONSOLE_ORG_ID_GUC}', true)
      )
  `);
}
