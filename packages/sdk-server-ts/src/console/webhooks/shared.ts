import { secureRandomBase36 } from '@shared/utils/secureRandomId';
import type { WebhookDispatchRequest, WebhookDispatchResult } from './service';
import {
  normalizeConsoleWebhookEventCategory,
  type ConsoleWebhookEventCategory,
} from '../../../../console-shared-ts/src/webhookEventCategories';

export const DELIVERY_RESPONSE_BODY_MAX_LEN = 2_048;
const WEBHOOK_DISPATCH_TIMEOUT_MS = 10_000;

export function makeId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = secureRandomBase36(8, 'console IDs');
  return `${prefix}_${ts}_${rand}`;
}

export function coerceIsoDate(input: Date): string {
  return input.toISOString();
}

export function truncateResponseBody(input: string | undefined): string | null {
  if (!input) return null;
  if (input.length <= DELIVERY_RESPONSE_BODY_MAX_LEN) return input;
  return input.slice(0, DELIVERY_RESPONSE_BODY_MAX_LEN);
}

export function makeSecretPreview(secret: string): string {
  return `${secret.slice(0, 10)}...`;
}

export function makeSigningSecret(now: Date): string {
  return `whsec_${makeId('secret', now)}`;
}

export function normalizeEventCategory(eventType: string): ConsoleWebhookEventCategory | null {
  const value = String(eventType || '')
    .trim()
    .toLowerCase();
  if (!value) return null;
  const idx = value.indexOf('.');
  const category = idx === -1 ? value : value.slice(0, idx);
  return normalizeConsoleWebhookEventCategory(category);
}

export async function signPayload(secret: string, message: string): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error('Webhook signing requires WebCrypto (crypto.subtle)');
  }

  const key = await subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await subtle.sign('HMAC', key, new TextEncoder().encode(message));
  const hex = Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `v1=${hex}`;
}

export function toDispatchHeaders(input: {
  endpointId: string;
  eventId: string;
  eventType: string;
  signature: string;
  timestamp: string;
}): Record<string, string> {
  return {
    'Content-Type': 'application/json',
    'X-Console-Webhook-Id': input.endpointId,
    'X-Console-Webhook-Event-Id': input.eventId,
    'X-Console-Webhook-Event-Type': input.eventType,
    'X-Console-Webhook-Timestamp': input.timestamp,
    'X-Console-Webhook-Signature': input.signature,
  };
}

export async function defaultDispatchWebhook(
  input: WebhookDispatchRequest,
): Promise<WebhookDispatchResult> {
  const controller = typeof AbortController === 'function' ? new AbortController() : null;
  const timeout = controller
    ? setTimeout(() => {
        try {
          controller.abort();
        } catch {
          // no-op
        }
      }, WEBHOOK_DISPATCH_TIMEOUT_MS)
    : null;

  try {
    const response = await fetch(input.endpointUrl, {
      method: 'POST',
      headers: input.headers,
      body: input.body,
      signal: controller?.signal,
    });
    const responseBody = truncateResponseBody(await response.text()) || undefined;
    return {
      ok: response.ok,
      statusCode: response.status,
      responseBody,
      errorMessage: response.ok ? undefined : `HTTP ${response.status}`,
    };
  } catch (error: unknown) {
    return {
      ok: false,
      statusCode: 0,
      errorMessage: error instanceof Error ? error.message : String(error),
    };
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}
