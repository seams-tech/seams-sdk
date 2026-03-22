import { base64UrlDecode, base64UrlEncode } from './encoders';
import { alphabetizeStringify, sha256BytesUtf8 } from './digests';
import { ensureEd25519Prefix, isValidAccountId, toOptionalTrimmedString } from './validation';

export const RECOVERY_EMAIL_SUBJECT_PREFIX = 'recover-v1';
export const RECOVERY_EMAIL_BODY_PREFIX = 'tatchi-recovery-v1:';

export type RecoveryEmailPayload = {
  version: 'recovery_email_payload_v1';
  nearAccountId: string;
  recoverySessionId: string;
  newNearPublicKey: string;
  newEvmOwnerAddress: string;
  deadlineEpochSeconds: number;
  scope?: string;
};

export type ParsedRecoveryEmailArtifact = {
  subject: string;
  payload: RecoveryEmailPayload;
};

function normalizeHexAddress(value: unknown): string {
  const normalized = toOptionalTrimmedString(value)?.toLowerCase() || '';
  return /^0x[0-9a-f]{40}$/.test(normalized) ? normalized : '';
}

function normalizePositiveInteger(value: unknown): number {
  const normalized = Number(value);
  return Number.isFinite(normalized) && normalized > 0 ? Math.floor(normalized) : 0;
}

function normalizeRecoverySessionId(value: unknown): string {
  const normalized = toOptionalTrimmedString(value) || '';
  return /^[A-Za-z0-9_-]{3,64}$/.test(normalized) ? normalized : '';
}

function normalizeRecoveryEmailPayload(
  input: Partial<RecoveryEmailPayload> | null | undefined,
): RecoveryEmailPayload | null {
  if (!input) return null;
  const nearAccountId = toOptionalTrimmedString(input.nearAccountId) || '';
  const recoverySessionId = normalizeRecoverySessionId(input.recoverySessionId);
  const newNearPublicKey = ensureEd25519Prefix(input.newNearPublicKey || '');
  const newEvmOwnerAddress = normalizeHexAddress(input.newEvmOwnerAddress);
  const deadlineEpochSeconds = normalizePositiveInteger(input.deadlineEpochSeconds);
  const scope = toOptionalTrimmedString(input.scope);

  if (!isValidAccountId(nearAccountId)) return null;
  if (!recoverySessionId || !newNearPublicKey || !newEvmOwnerAddress || !deadlineEpochSeconds) {
    return null;
  }

  return {
    version: 'recovery_email_payload_v1',
    nearAccountId,
    recoverySessionId,
    newNearPublicKey,
    newEvmOwnerAddress,
    deadlineEpochSeconds,
    ...(scope ? { scope } : {}),
  };
}

function extractSubjectText(rawEmailOrSubject: string): string {
  const raw = String(rawEmailOrSubject || '');
  if (!raw.trim()) return '';
  const lines = raw.split(/\r?\n/);
  const subjectLine = lines.find((line) => /^subject:/i.test(line));
  const value = subjectLine
    ? subjectLine.slice(subjectLine.indexOf(':') + 1).trim()
    : raw.trim();
  return value.replace(/^(re|fwd):\s*/i, '').trim();
}

export function buildRecoveryEmailPayload(input: {
  nearAccountId: string;
  recoverySessionId: string;
  newNearPublicKey: string;
  newEvmOwnerAddress: string;
  deadlineEpochSeconds: number;
  scope?: string;
}): RecoveryEmailPayload {
  const payload = normalizeRecoveryEmailPayload({
    version: 'recovery_email_payload_v1',
    nearAccountId: input.nearAccountId,
    recoverySessionId: input.recoverySessionId,
    newNearPublicKey: input.newNearPublicKey,
    newEvmOwnerAddress: input.newEvmOwnerAddress,
    deadlineEpochSeconds: input.deadlineEpochSeconds,
    scope: input.scope,
  });
  if (!payload) {
    throw new Error('Invalid recovery email payload');
  }
  return payload;
}

export function serializeRecoveryEmailPayload(payload: RecoveryEmailPayload): string {
  const normalized = normalizeRecoveryEmailPayload(payload);
  if (!normalized) {
    throw new Error('Invalid recovery email payload');
  }
  return alphabetizeStringify(normalized);
}

export function encodeRecoveryEmailPayloadToken(payload: RecoveryEmailPayload): string {
  return base64UrlEncode(new TextEncoder().encode(serializeRecoveryEmailPayload(payload)));
}

export function decodeRecoveryEmailPayloadToken(token: string): RecoveryEmailPayload | null {
  const normalizedToken = toOptionalTrimmedString(token);
  if (!normalizedToken) return null;
  try {
    const bytes = base64UrlDecode(normalizedToken);
    const parsed = JSON.parse(new TextDecoder().decode(bytes)) as Partial<RecoveryEmailPayload>;
    return normalizeRecoveryEmailPayload(parsed);
  } catch {
    return null;
  }
}

export function buildRecoveryEmailSubject(payload: RecoveryEmailPayload): string {
  const normalized = normalizeRecoveryEmailPayload(payload);
  if (!normalized) {
    throw new Error('Invalid recovery email payload');
  }
  return `${RECOVERY_EMAIL_SUBJECT_PREFIX} ${normalized.nearAccountId} ${normalized.recoverySessionId}`;
}

export function buildRecoveryEmailBody(payload: RecoveryEmailPayload): string {
  return ['tee-encrypted', `${RECOVERY_EMAIL_BODY_PREFIX}${encodeRecoveryEmailPayloadToken(payload)}`].join(
    '\n',
  );
}

export function parseRecoveryEmailSubject(
  rawEmailOrSubject: string | undefined | null,
): { nearAccountId: string; recoverySessionId: string } | null {
  const subject = extractSubjectText(rawEmailOrSubject || '');
  if (!subject) return null;
  const match = subject.match(/^recover-v1\s+([^\s]+)\s+([A-Za-z0-9_-]{3,64})\s*$/i);
  if (!match) return null;
  const nearAccountId = toOptionalTrimmedString(match[1]) || '';
  const recoverySessionId = normalizeRecoverySessionId(match[2]);
  if (!isValidAccountId(nearAccountId) || !recoverySessionId) return null;
  return { nearAccountId, recoverySessionId };
}

export function extractRecoveryEmailPayloadToken(rawEmail: string | undefined | null): string | null {
  const raw = String(rawEmail || '');
  if (!raw.trim()) return null;
  const lines = raw.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith(RECOVERY_EMAIL_BODY_PREFIX)) continue;
    const token = trimmed.slice(RECOVERY_EMAIL_BODY_PREFIX.length).trim();
    return token || null;
  }
  return null;
}

export function parseRecoveryEmailArtifact(
  rawEmail: string | undefined | null,
): ParsedRecoveryEmailArtifact | null {
  const subject = extractSubjectText(rawEmail || '');
  const subjectBindings = parseRecoveryEmailSubject(subject);
  if (!subjectBindings) return null;
  const token = extractRecoveryEmailPayloadToken(rawEmail);
  if (!token) return null;
  const payload = decodeRecoveryEmailPayloadToken(token);
  if (!payload) return null;
  if (
    payload.nearAccountId !== subjectBindings.nearAccountId ||
    payload.recoverySessionId !== subjectBindings.recoverySessionId
  ) {
    return null;
  }
  return {
    subject,
    payload,
  };
}

export async function hashRecoveryEmailPayload(payload: RecoveryEmailPayload): Promise<string> {
  const digest = await sha256BytesUtf8(serializeRecoveryEmailPayload(payload));
  return `sha256:${base64UrlEncode(digest)}`;
}

export async function hashRecoveryEmailArtifact(rawEmail: string): Promise<string> {
  const digest = await sha256BytesUtf8(String(rawEmail || ''));
  return `sha256:${base64UrlEncode(digest)}`;
}
