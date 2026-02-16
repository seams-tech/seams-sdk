import { ensureEd25519Prefix } from '@shared/utils/validation';

export interface ForwardableEmailPayload {
  from: string;
  to: string;
  headers: Record<string, string>;
  raw?: string;
  rawSize?: number;
}

export type NormalizedEmailResult =
  | { ok: true; payload: ForwardableEmailPayload }
  | { ok: false; code: string; message: string };

export function normalizeForwardableEmailPayload(input: unknown): NormalizedEmailResult {
  if (!input || typeof input !== 'object') {
    return { ok: false, code: 'invalid_email', message: 'JSON body required' };
  }

  const body = input as Partial<ForwardableEmailPayload>;
  const { from, to, headers, raw, rawSize } = body;

  if (!from || typeof from !== 'string' || !to || typeof to !== 'string') {
    return { ok: false, code: 'invalid_email', message: 'from and to are required' };
  }

  if (!headers || typeof headers !== 'object') {
    return { ok: false, code: 'invalid_email', message: 'headers object is required' };
  }

  const normalizedHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers as Record<string, unknown>)) {
    normalizedHeaders[String(k).toLowerCase()] = String(v);
  }

  return {
    ok: true,
    payload: {
      from,
      to,
      headers: normalizedHeaders,
      raw: typeof raw === 'string' ? raw : undefined,
      rawSize: typeof rawSize === 'number' ? rawSize : undefined,
    },
  };
}

/**
 * Parse NEAR accountId from the Subject line inside a raw RFC822 email.
 *
 * Expected format (case-insensitive on "Subject" and "recover"):
 *   Subject: recover-123ABC bob.testnet ed25519:<pk>
 *
 * Returns the parsed accountId (e.g. "bob.testnet") or null if not found.
 */
export function parseAccountIdFromSubject(raw: string | undefined | null): string | null {
  if (!raw || typeof raw !== 'string') return null;

  let subjectText = '';
  const lines = raw.split(/\r?\n/);
  const subjectLine = lines.find((line) => /^subject:/i.test(line));
  if (subjectLine) {
    const idx = subjectLine.indexOf(':');
    const restRaw = idx >= 0 ? subjectLine.slice(idx + 1) : '';
    subjectText = restRaw.trim();
  } else {
    subjectText = raw.trim();
  }

  if (!subjectText) return null;

  subjectText = subjectText.replace(/^(re|fwd):\s*/i, '').trim();
  if (!subjectText) return null;

  const match = subjectText.match(
    /^recover-([A-Za-z0-9]{6})\s+([^\s]+)(?:\s+ed25519:[^\s]+)?\s*$/i
  );
  if (match?.[2]) {
    return match[2];
  }

  return null;
}

export type RecoverEmailParseResult =
  | { ok: true; accountId: string; emailBlob: string }
  | { ok: false; status: number; code: string; message: string };

export function parseRecoverEmailRequest(body: unknown): RecoverEmailParseResult {
  const normalized = normalizeForwardableEmailPayload(body);
  if (!normalized.ok) {
    return { ok: false, status: 400, code: normalized.code, message: normalized.message };
  }

  const payload = normalized.payload;
  const emailBlob = payload.raw || '';
  const emailHeaders = payload.headers || {};

  const subjectHeader = emailHeaders['subject'];
  const parsedAccountId = parseAccountIdFromSubject(subjectHeader || emailBlob);
  const headerAccountId = String(emailHeaders['x-near-account-id'] || emailHeaders['x-account-id'] || '').trim();
  const accountId = (parsedAccountId || headerAccountId || '').trim();

  if (!accountId) {
    return { ok: false, status: 400, code: 'missing_account', message: 'x-near-account-id header is required' };
  }
  if (!emailBlob) {
    return { ok: false, status: 400, code: 'missing_email', message: 'raw email blob is required' };
  }

  return { ok: true, accountId, emailBlob };
}

const EMAIL_ADDRESS_REGEX =
  /([a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)/;

export function canonicalizeEmail(input: string): string {
  const raw = String(input || '').trim();
  if (!raw) return '';

  // Handle cases where a full header line is passed in (e.g. "From: ...").
  const withoutHeaderName = raw.replace(/^[a-z0-9-]+\s*:\s*/i, '').trim();

  // Prefer the common "Name <email@domain>" format when present, but still
  // validate/extract the actual address via regex.
  const angleMatch = withoutHeaderName.match(/<([^>]+)>/);
  const candidates = [
    angleMatch?.[1],
    withoutHeaderName,
  ].filter((v): v is string => typeof v === 'string' && v.length > 0);

  for (const candidate of candidates) {
    const cleaned = candidate.replace(/^mailto:\s*/i, '');
    const match = cleaned.match(EMAIL_ADDRESS_REGEX);
    if (match?.[1]) {
      return match[1].trim().toLowerCase();
    }
  }

  return withoutHeaderName.toLowerCase();
}

export function parseHeaderValue(rawEmail: string, name: string): string | undefined {
  try {
    const raw = String(rawEmail || '');
    if (!raw) return undefined;

    const lines = raw.split(/\r?\n/);
    const headerLines: string[] = [];

    // Only consider the header section (until the first blank line).
    for (const line of lines) {
      if (line.trim() === '') break;

      // RFC822 header folding: lines starting with whitespace continue previous header.
      if (/^\s/.test(line) && headerLines.length > 0) {
        headerLines[headerLines.length - 1] += ` ${line.trim()}`;
        continue;
      }

      headerLines.push(line);
    }

    const headerName = name.trim();
    if (!headerName) return undefined;

    const re = new RegExp(`^${headerName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*:`, 'i');
    const found = headerLines.find((l) => re.test(l));
    if (!found) return undefined;

    const idx = found.indexOf(':');
    const value = idx >= 0 ? found.slice(idx + 1).trim() : '';
    return value || undefined;
  } catch {
    return undefined;
  }
}

export function parseRecoverSubjectBindings(
  rawEmail: string
): { requestId: string; accountId: string; newPublicKey: string } | null {
  // Accept either a full RFC822 email or a bare Subject value.
  let subjectText = (parseHeaderValue(rawEmail, 'subject') || String(rawEmail || '')).trim();
  if (!subjectText) return null;

  // Strip common reply/forward prefixes.
  subjectText = subjectText.replace(/^(re|fwd):\s*/i, '').trim();
  if (!subjectText) return null;

  // Strict format:
  //   "recover-<request_id> <accountId> ed25519:<pk>"
  const match = subjectText.match(
    /^recover-([A-Za-z0-9]{6})\s+([^\s]+)\s+ed25519:([^\s]+)\s*$/i
  );
  if (!match) return null;

  const [, requestId, accountId, newPublicKey] = match;
  return { requestId, accountId, newPublicKey: ensureEd25519Prefix(newPublicKey) };
}
