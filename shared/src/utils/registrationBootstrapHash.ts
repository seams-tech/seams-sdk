import { base64UrlEncode } from './encoders';
import { sha256BytesUtf8 } from './digests';

const REGISTRATION_BOOTSTRAP_HASH_FIELDS = [
  'new_account_id',
  'signer_slot',
  'threshold_ed25519',
  'threshold_ecdsa',
  'rp_id',
  'webauthn_registration',
  'authenticator_options',
  'context',
  'preparedSession',
  'clientRequest',
  'evaluationResult',
] as const;

type RegistrationBootstrapHashField = (typeof REGISTRATION_BOOTSTRAP_HASH_FIELDS)[number];

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

const LARGE_STRING_HASH_THRESHOLD = 1024;

async function digestLargeUtf8String(input: string): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(input));
}

async function normalizeRegistrationBootstrapHashValue(value: unknown): Promise<unknown> {
  if (Array.isArray(value)) {
    return await Promise.all(value.map((entry) => normalizeRegistrationBootstrapHashValue(entry)));
  }
  if (isRecord(value)) {
    const sortedKeys = Object.keys(value).sort();
    const normalizedEntries = await Promise.all(
      sortedKeys.map(
        async (key) => [key, await normalizeRegistrationBootstrapHashValue(value[key])] as const,
      ),
    );
    const result: Record<string, unknown> = {};
    for (const [key, normalizedValue] of normalizedEntries) {
      result[key] = normalizedValue;
    }
    return result;
  }
  if (typeof value === 'string' && value.length > LARGE_STRING_HASH_THRESHOLD) {
    return {
      __hash: 'sha256-utf8-b64u',
      length: value.length,
      digest: await digestLargeUtf8String(value),
    };
  }
  return value;
}

export function normalizeRegistrationBootstrapHashInput(
  input: unknown,
): Partial<Record<RegistrationBootstrapHashField, unknown>> {
  if (!isRecord(input)) return {};
  const out: Partial<Record<RegistrationBootstrapHashField, unknown>> = {};
  for (const field of REGISTRATION_BOOTSTRAP_HASH_FIELDS) {
    const value = input[field];
    if (value === undefined) continue;
    out[field] = value;
  }
  return out;
}

export async function serializeRegistrationBootstrapHashInput(input: unknown): Promise<string> {
  const normalized = await normalizeRegistrationBootstrapHashValue(
    normalizeRegistrationBootstrapHashInput(input),
  );
  return JSON.stringify(normalized);
}

export async function computeRegistrationBootstrapRequestHashSha256(
  input: unknown,
): Promise<string> {
  const digest = await sha256BytesUtf8(await serializeRegistrationBootstrapHashInput(input));
  return base64UrlEncode(digest);
}
