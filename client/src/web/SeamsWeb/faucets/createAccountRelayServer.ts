import { SeamsWebContext } from '..';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { RegistrationErrorCode } from '@/core/types/seams';
import { isObject } from '@shared/utils/validation';

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).length;
}

const REGISTRATION_FAILURE_CODES: readonly RegistrationErrorCode[] = [
  'secret_key_missing',
  'secret_key_invalid',
  'secret_key_revoked',
  'secret_key_forbidden_scope',
  'secret_key_ip_blocked',
  'secret_key_environment_mismatch',
  'publishable_key_missing',
  'publishable_key_invalid',
  'publishable_key_revoked',
  'publishable_key_origin_blocked',
  'publishable_key_environment_mismatch',
  'publishable_key_rate_limited',
  'publishable_key_quota_exhausted',
  'invalid_environment',
  'environment_archived',
  'invalid_body',
  'payment_required',
  'payment_invalid',
  'bootstrap_token_missing',
  'bootstrap_token_invalid',
  'bootstrap_token_expired',
  'bootstrap_token_already_used',
  'bootstrap_token_request_mismatch',
  'bootstrap_token_origin_mismatch',
];

function isRegistrationErrorCode(raw: unknown): raw is RegistrationErrorCode {
  const value = String(raw || '').trim();
  return REGISTRATION_FAILURE_CODES.includes(value as RegistrationErrorCode);
}

export class RelayRegistrationError extends Error {
  readonly code: RegistrationErrorCode;
  readonly status: number;

  constructor(input: { code: RegistrationErrorCode; status: number; message: string }) {
    super(input.message);
    this.name = 'RelayRegistrationError';
    this.code = input.code;
    this.status = input.status;
  }
}

const REGISTRATION_NETWORK_TIMEOUT_MS = 30_000;

function createRegistrationTimeoutError(args: {
  operation: string;
  url: string;
  timeoutMs: number;
}): Error {
  const url = String(args.url || '').trim();
  const suffix = url ? ` (${url})` : '';
  return new Error(`${args.operation} timed out after ${args.timeoutMs}ms${suffix}`);
}

async function fetchWithRegistrationTimeout(args: {
  url: string;
  init: RequestInit;
  operation: string;
  timeoutMs?: number;
}): Promise<Response> {
  const timeoutMs = Math.max(
    1_000,
    Math.floor(Number(args.timeoutMs ?? REGISTRATION_NETWORK_TIMEOUT_MS) || 0),
  );
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(args.url, {
      ...args.init,
      signal: controller.signal,
    });
  } catch (error: unknown) {
    if (
      controller.signal.aborted ||
      (error instanceof DOMException && error.name === 'AbortError')
    ) {
      throw createRegistrationTimeoutError({
        operation: args.operation,
        url: args.url,
        timeoutMs,
      });
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

function joinUrlPath(baseUrl: string, path: string): string {
  const base = String(baseUrl || '')
    .trim()
    .replace(/\/+$/, '');
  const suffix = String(path || '').trim();
  if (!base) return '';
  if (!suffix) return base;
  return `${base}${suffix.startsWith('/') ? suffix : `/${suffix}`}`;
}

type ResolvedRegistrationTransport =
  | {
      mode: 'backend_proxy';
    }
  | {
      mode: 'managed';
      relayerUrl: string;
      environmentId: string;
      publishableKey: string;
      paymentMode?: string;
    };

function resolveRegistrationTransport(
  context: SeamsWebContext,
): ResolvedRegistrationTransport {
  const configs = context.configs as SeamsWebContext['configs'] & {
    registration?: unknown;
  };
  const registration = configs.registration;
  if (registration && typeof registration === 'object' && !Array.isArray(registration)) {
    const mode = String((registration as { mode?: unknown }).mode || 'backend_proxy').trim();
    if (mode === 'managed') {
      const relayerUrl = String(context.configs.network.relayer.url || '').trim();
      const environmentId = String(
        (registration as { environmentId?: unknown }).environmentId || '',
      ).trim();
      const publishableKey = String(
        (registration as { publishableKey?: unknown }).publishableKey || '',
      ).trim();
      const paymentMode = String(
        (registration as { paymentMode?: unknown }).paymentMode || '',
      ).trim();
      if (!relayerUrl) throw new Error('Managed registration requires relayer.url');
      if (!environmentId)
        throw new Error('Managed registration requires registration.environmentId');
      if (!publishableKey) {
        throw new Error('Managed registration requires registration.publishableKey');
      }
      return {
        mode: 'managed',
        relayerUrl,
        environmentId,
        publishableKey,
        ...(paymentMode ? { paymentMode } : {}),
      };
    }
  }
  return { mode: 'backend_proxy' };
}

function buildManagedClientContext(): { sdk: string; userAgentHint?: string } {
  const userAgentHint =
    typeof navigator !== 'undefined' ? String(navigator.userAgent || '').trim() : '';
  return {
    sdk: '@seams/sdk',
    ...(userAgentHint ? { userAgentHint } : {}),
  };
}

type ManagedRegistrationFlowGrant = {
  token: string;
  expiresAt: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  origin?: string;
  mode?: string;
};

async function readJsonObject(response: Response): Promise<Record<string, unknown>> {
  const text = await response.text();
  if (!text) return {};
  try {
    const parsed: unknown = JSON.parse(text);
    return isObject(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

async function requestManagedRegistrationFlowGrant(args: {
  relayerUrl: string;
  publishableKey: string;
  environmentId: string;
  nearAccountId?: string;
  walletId?: string;
  rpId: string;
}): Promise<ManagedRegistrationFlowGrant> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const bootstrapGrantUrl = joinUrlPath(args.relayerUrl, '/v1/registration/bootstrap-grants');
  const subjectId = String(args.nearAccountId || args.walletId || '').trim();
  const brokerResponse = await fetchWithRegistrationTimeout({
    url: bootstrapGrantUrl,
    operation: 'Managed registration flow grant',
    init: {
      method: 'POST',
      headers: {
        ...headers,
        Authorization: `Bearer ${args.publishableKey}`,
      },
      body: JSON.stringify({
        environmentId: args.environmentId,
        ...(subjectId ? { newAccountId: subjectId } : {}),
        rpId: args.rpId,
        flow: 'registration_v1',
        clientContext: buildManagedClientContext(),
      }),
    },
  });
  const brokerResult = await readJsonObject(brokerResponse);
  const brokerCode = String(brokerResult.code || '').trim();
  const brokerMessage =
    String(brokerResult.message || '').trim() ||
    `HTTP ${brokerResponse.status}: ${brokerResponse.statusText}`;
  if (!brokerResponse.ok || brokerResult.ok === false) {
    if (isRegistrationErrorCode(brokerCode)) {
      throw new RelayRegistrationError({
        code: brokerCode,
        status: brokerResponse.status,
        message: brokerMessage,
      });
    }
    throw new Error(brokerMessage || 'Managed registration grant failed');
  }

  const grant = isObject(brokerResult.grant)
    ? (brokerResult.grant as Record<string, unknown>)
    : null;
  const token = String((grant?.token as string) || '').trim();
  const orgId = String((grant?.orgId as string) || '').trim();
  const projectId = String((grant?.projectId as string) || '').trim();
  const envId = String((grant?.envId as string) || '').trim();
  const signingRootVersion = String((grant?.signingRootVersion as string) || '').trim();
  if (!token) {
    throw new Error('Managed registration grant response did not include a bootstrap token');
  }
  if (!orgId || !projectId || !envId || !signingRootVersion) {
    throw new Error('Managed registration grant response did not include canonical runtime scope');
  }

  return {
    token,
    expiresAt: String((grant?.expiresAt as string) || '').trim(),
    runtimePolicyScope: {
      orgId,
      projectId,
      envId,
      signingRootVersion,
    },
    ...(String((grant?.origin as string) || '').trim()
      ? { origin: String((grant?.origin as string) || '').trim() }
      : {}),
    ...(String((grant?.mode as string) || '').trim()
      ? { mode: String((grant?.mode as string) || '').trim() }
      : {}),
  };
}

export async function createManagedRegistrationFlowGrant(args: {
  context: SeamsWebContext;
  nearAccountId?: string;
  walletId?: string;
  rpId: string;
}): Promise<ManagedRegistrationFlowGrant> {
  const registrationTransport = resolveRegistrationTransport(args.context);
  if (registrationTransport.mode !== 'managed') {
    throw new Error('Managed registration flow grants require managed registration transport');
  }
  const grantStartedAt = performance.now();
  const grant = await requestManagedRegistrationFlowGrant({
    relayerUrl: registrationTransport.relayerUrl,
    publishableKey: registrationTransport.publishableKey,
    environmentId: registrationTransport.environmentId,
    ...(String(args.nearAccountId || '').trim()
      ? { nearAccountId: String(args.nearAccountId || '').trim() }
      : {}),
    ...(String(args.walletId || '').trim()
      ? { walletId: String(args.walletId || '').trim() }
      : {}),
    rpId: String(args.rpId || '').trim(),
  });
  console.debug('[Registration] managed registration flow grant issued', {
    durationMs: Math.round(performance.now() - grantStartedAt),
    requestBytes: utf8Bytes(args.rpId),
  });
  return grant;
}
