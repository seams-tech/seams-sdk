import { base64UrlEncode } from './encoders';
import { alphabetizeStringify, sha256BytesUtf8 } from './digests';

const REGISTRATION_BOOTSTRAP_HASH_FIELDS = [
  'new_account_id',
  'new_public_key',
  'device_number',
  'threshold_ed25519',
  'threshold_ecdsa',
  'rp_id',
  'webauthn_registration',
  'authenticator_options',
] as const;

type RegistrationBootstrapHashField = (typeof REGISTRATION_BOOTSTRAP_HASH_FIELDS)[number];

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
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

export function serializeRegistrationBootstrapHashInput(input: unknown): string {
  return alphabetizeStringify(normalizeRegistrationBootstrapHashInput(input));
}

export async function computeRegistrationBootstrapRequestHashSha256(
  input: unknown,
): Promise<string> {
  const digest = await sha256BytesUtf8(serializeRegistrationBootstrapHashInput(input));
  return base64UrlEncode(digest);
}
