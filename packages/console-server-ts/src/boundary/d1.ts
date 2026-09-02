export type D1Row = Record<string, unknown>;

export interface D1ResultLike<T = unknown> {
  readonly results?: readonly T[];
  readonly success: boolean;
  readonly meta?: {
    readonly changes?: number;
    readonly last_row_id?: number | string;
    readonly rows_read?: number;
    readonly rows_written?: number;
  };
}

export interface D1PreparedStatementLike {
  bind(...values: readonly unknown[]): D1PreparedStatementLike;
  first<T = unknown>(columnName?: string): Promise<T | null>;
  all<T = unknown>(): Promise<D1ResultLike<T>>;
  run<T = unknown>(): Promise<D1ResultLike<T>>;
}

export interface D1DatabaseLike {
  prepare(query: string): D1PreparedStatementLike;
  batch<T = unknown>(statements: readonly D1PreparedStatementLike[]): Promise<readonly T[]>;
  exec(query: string): Promise<unknown>;
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
