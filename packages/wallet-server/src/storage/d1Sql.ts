import type { D1DatabaseLike, D1ResultLike } from './tenantRoute';

export type D1Row = Record<string, unknown>;
type D1DatabaseProbe = {
  readonly prepare?: unknown;
  readonly batch?: unknown;
  readonly exec?: unknown;
};

function d1DatabaseProbe(value: unknown): D1DatabaseProbe | null {
  if (!value || typeof value !== 'object') return null;
  return value as D1DatabaseProbe;
}

function collapseD1SchemaWhitespace(statement: string): string {
  let output = '';
  let inSingleQuote = false;
  let pendingSpace = false;
  for (let index = 0; index < statement.length; index += 1) {
    const char = statement[index];
    if (char === "'") {
      if (pendingSpace && output) output += ' ';
      pendingSpace = false;
      output += char;
      if (inSingleQuote && statement[index + 1] === "'") {
        output += "'";
        index += 1;
      } else {
        inSingleQuote = !inSingleQuote;
      }
      continue;
    }
    if (!inSingleQuote && /\s/.test(char)) {
      pendingSpace = Boolean(output);
      continue;
    }
    if (pendingSpace && output) output += ' ';
    pendingSpace = false;
    output += char;
  }
  return output.trim();
}

export function formatD1ExecStatement(statement: string): string {
  const sql = collapseD1SchemaWhitespace(statement);
  if (!sql) throw new Error('D1 exec statement must be non-empty');
  return sql.endsWith(';') ? sql : `${sql};`;
}

export async function queryD1One(
  database: D1DatabaseLike,
  text: string,
  values: readonly unknown[],
): Promise<D1Row | null> {
  return await database.prepare(text).bind(...values).first<D1Row>();
}

export async function queryD1All(
  database: D1DatabaseLike,
  text: string,
  values: readonly unknown[],
): Promise<readonly D1Row[]> {
  const result = await database.prepare(text).bind(...values).all<D1Row>();
  return result.results || [];
}

export function d1ChangedRows(result: D1ResultLike): number {
  const changes = Number(result.meta?.changes ?? result.meta?.rows_written ?? 0);
  return Number.isFinite(changes) ? Math.max(0, Math.trunc(changes)) : 0;
}

export function d1Number(value: unknown, fallback = 0): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function d1Integer(value: unknown, fallback = 0): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : fallback;
}

export function parseD1JsonColumn(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

export function parseD1JsonArrayColumn(value: unknown): readonly unknown[] {
  const parsed = parseD1JsonColumn(value);
  return Array.isArray(parsed) ? parsed : [];
}

export function parseD1JsonObjectColumn(value: unknown): Record<string, unknown> {
  const parsed = parseD1JsonColumn(value);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
  return { ...(parsed as Record<string, unknown>) };
}

export function isD1DatabaseLike(value: unknown): value is D1DatabaseLike {
  const probe = d1DatabaseProbe(value);
  return Boolean(
    probe &&
      typeof probe.prepare === 'function' &&
      typeof probe.batch === 'function' &&
      typeof probe.exec === 'function',
  );
}

export function resolveD1DatabaseFromConfig(config: Record<string, unknown>): D1DatabaseLike | null {
  if (isD1DatabaseLike(config.database)) return config.database;
  if (isD1DatabaseLike(config.metadataDatabase)) return config.metadataDatabase;
  if (isD1DatabaseLike(config.SIGNER_DB)) return config.SIGNER_DB;
  return null;
}
