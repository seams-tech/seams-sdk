import { errorMessage } from '@shared/utils/errors';
import { joinNormalizedUrl } from '@shared/utils/normalize';

export type EmailOtpWorkerJson = Record<string, unknown>;

function requireObjectJson(value: unknown, label: string): EmailOtpWorkerJson {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} returned invalid JSON`);
  }
  return value as EmailOtpWorkerJson;
}

function buildSessionHeaders(appSessionJwt?: string): HeadersInit {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const token = String(appSessionJwt || '').trim();
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

export async function postEmailOtpJson(args: {
  relayUrl: string;
  route: string;
  body: EmailOtpWorkerJson;
  appSessionJwt?: string;
}): Promise<EmailOtpWorkerJson> {
  const url = joinNormalizedUrl(args.relayUrl, args.route);
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: buildSessionHeaders(args.appSessionJwt),
      credentials: 'include',
      body: JSON.stringify(args.body),
    });
    const text = await response.text();
    let json: unknown = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      throw new Error(`${url} returned non-JSON response (HTTP ${response.status})`);
    }
    const objectJson = requireObjectJson(json, url);
    if (!response.ok || objectJson.ok === false) {
      const message =
        (typeof objectJson.message === 'string' && objectJson.message.trim()) ||
        `${url} failed (HTTP ${response.status})`;
      throw new Error(message);
    }
    return objectJson;
  } catch (error) {
    throw new Error(errorMessage(error));
  }
}
