import type {
  CreateRegistrationFlowEventInput,
  RegistrationHooksOptions,
} from '../../types/sdkSentEvents';
import { createRegistrationFlowEvent, RegistrationEventPhase } from '../../types/sdkSentEvents';
import { PasskeyManagerContext } from '..';
import {
  serializeRegistrationCredential,
  normalizeRegistrationCredential,
} from '../../signingEngine/signers/webauthn/credentials/helpers';
import { redactCredentialExtensionOutputs } from '../../signingEngine/signers/webauthn/credentials';
import type { WebAuthnRegistrationCredential } from '../../types/webauthn';
import {
  cloneAuthenticatorOptions,
  type AuthenticatorOptions,
} from '../../types/authenticatorOptions';
import type {
  CreateAccountAndRegisterResult,
  ThresholdEd25519HssCanonicalContext,
  ThresholdEd25519HssClientRequestEnvelope,
  ThresholdEd25519HssPrepareForRegistrationResponse,
  ThresholdEd25519HssPreparedSessionEnvelope,
  ThresholdEd25519HssRespondForRegistrationResponse,
  ThresholdEd25519HssFinalizeForRegistrationResponse,
} from '@server/core/types';
import type { Ed25519SessionPolicy } from '../../signingEngine/threshold/session/sessionPolicy';
import type { ThresholdRuntimePolicyScope } from '../../signingEngine/threshold/session/sessionPolicy';
import { isObject } from '@shared/utils/validation';
import { errorMessage } from '@shared/utils/errors';
import type { RegistrationErrorCode } from '../../types/tatchi';

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).length;
}

function jsonBytes(value: unknown): number {
  return utf8Bytes(JSON.stringify(value));
}

function isSerializedRegistrationCredential(
  credential: WebAuthnRegistrationCredential | PublicKeyCredential,
): credential is WebAuthnRegistrationCredential {
  if (!isObject(credential)) return false;
  const resp = (credential as { response?: unknown }).response;
  if (!isObject(resp)) return false;
  return typeof (resp as { attestationObject?: unknown }).attestationObject === 'string';
}

function improveAtomicRegistrationError(args: {
  raw: string;
  nearAccountId: string;
  relayUrl: string;
}): string {
  const raw = String(args.raw || '').trim();
  const nearAccountId = String(args.nearAccountId || '').trim();
  const relayUrl = String(args.relayUrl || '').trim();

  // Server validation: account creation can only create subaccounts under a specific namespace.
  const mRelayer =
    /new_account_id must be a subaccount of relayer(?:\s+signer\s+)?account\s*\(([^)]+)\)/i.exec(
      raw,
    );

  const expectedRelayer = mRelayer?.[1] ? String(mRelayer[1]).trim() : '';

  if (expectedRelayer) {
    const hint =
      `Registration accountId must be a subaccount of the relay signer account.\n` +
      `Expected: <username>.${expectedRelayer}\n` +
      (nearAccountId ? `Got: ${nearAccountId}\n` : '') +
      `Fix: set client config \`relayerAccount: '${expectedRelayer}'\` (must match relay RELAYER_ACCOUNT_ID)` +
      (relayUrl ? ` for relayer \`${relayUrl}\`` : '') +
      `.`;
    return hint;
  }

  return raw || 'Atomic registration failed';
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

type EmitRelayRegistrationEventInput = Omit<
  CreateRegistrationFlowEventInput,
  'accountId' | 'authMethod' | 'flowId'
>;

function emitRelayRegistrationEvent(
  onEvent: RegistrationHooksOptions['onEvent'] | undefined,
  nearAccountId: string,
  event: EmitRelayRegistrationEventInput,
): void {
  onEvent?.(
    createRegistrationFlowEvent({
      flowId: `registration:passkey:${nearAccountId}`,
      accountId: nearAccountId,
      authMethod: 'passkey',
      ...event,
    }),
  );
}

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

function isRelayRegistrationError(error: unknown): error is RelayRegistrationError {
  return error instanceof RelayRegistrationError;
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

function replaceUrlPathSuffix(url: string, fromPath: string, toPath: string): string {
  const raw = String(url || '').trim();
  if (!raw) return '';
  try {
    const parsed = new URL(raw);
    if (parsed.pathname === fromPath || parsed.pathname === `${fromPath}/`) {
      parsed.pathname = toPath;
      return parsed.toString();
    }
  } catch {}
  if (raw.endsWith(fromPath)) {
    return `${raw.slice(0, raw.length - fromPath.length)}${toPath}`;
  }
  if (raw.endsWith(`${fromPath}/`)) {
    return `${raw.slice(0, raw.length - fromPath.length - 1)}${toPath}`;
  }
  return '';
}

type ResolvedRegistrationTransport =
  | {
      mode: 'backend_proxy';
      bootstrapUrl: string;
      recoveryShareUrl: string;
    }
  | {
      mode: 'managed';
      relayerUrl: string;
      environmentId: string;
      publishableKey: string;
      paymentMode?: string;
    };

function resolveRegistrationTransport(
  context: PasskeyManagerContext,
): ResolvedRegistrationTransport {
  const configs = context.configs as PasskeyManagerContext['configs'] & {
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
    const bootstrapUrl = String(
      (registration as { bootstrapUrl?: unknown; registrationBootstrapUrl?: unknown })
        .bootstrapUrl ??
        (registration as { registrationBootstrapUrl?: unknown }).registrationBootstrapUrl ??
        '',
    ).trim();
    if (bootstrapUrl) {
      const recoveryShareUrl =
        replaceUrlPathSuffix(
          bootstrapUrl,
          '/registration/bootstrap',
          '/registration/recovery-share',
        ) || joinUrlPath(bootstrapUrl, '/registration/recovery-share');
      return { mode: 'backend_proxy', bootstrapUrl, recoveryShareUrl };
    }
  }
  const relayerUrl = String(context.configs.network.relayer.url || '').trim();
  return {
    mode: 'backend_proxy',
    bootstrapUrl: joinUrlPath(relayerUrl, '/registration/bootstrap'),
    recoveryShareUrl: joinUrlPath(relayerUrl, '/registration/recovery-share'),
  };
}

function buildManagedClientContext(): { sdk: string; userAgentHint?: string } {
  const userAgentHint =
    typeof navigator !== 'undefined' ? String(navigator.userAgent || '').trim() : '';
  return {
    sdk: '@tatchi-xyz/sdk',
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

async function requestManagedRegistrationFlowGrant(args: {
  relayerUrl: string;
  publishableKey: string;
  environmentId: string;
  nearAccountId: string;
  rpId: string;
}): Promise<ManagedRegistrationFlowGrant> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const bootstrapGrantUrl = joinUrlPath(args.relayerUrl, '/v1/registration/bootstrap-grants');
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
        newAccountId: args.nearAccountId,
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
    throw new Error(brokerMessage || 'Managed bootstrap grant failed');
  }

  const grant = isObject(brokerResult.grant)
    ? (brokerResult.grant as Record<string, unknown>)
    : null;
  const token = String((grant?.token as string) || '').trim();
  const orgId = String((grant?.orgId as string) || '').trim();
  const projectId = String((grant?.projectId as string) || '').trim();
  const envId = String((grant?.envId as string) || '').trim();
  if (!token) {
    throw new Error('Managed bootstrap grant response did not include a bootstrap token');
  }
  if (!orgId || !projectId || !envId) {
    throw new Error('Managed bootstrap grant response did not include canonical runtime scope');
  }

  return {
    token,
    expiresAt: String((grant?.expiresAt as string) || '').trim(),
    runtimePolicyScope: {
      orgId,
      projectId,
      envId,
    },
    ...(String((grant?.origin as string) || '').trim()
      ? { origin: String((grant?.origin as string) || '').trim() }
      : {}),
    ...(String((grant?.mode as string) || '').trim()
      ? { mode: String((grant?.mode as string) || '').trim() }
      : {}),
  };
}

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
export async function createManagedRegistrationFlowGrant(args: {
  context: PasskeyManagerContext;
  nearAccountId: string;
  rpId: string;
}): Promise<ManagedRegistrationFlowGrant> {
  const registrationTransport = resolveRegistrationTransport(args.context);
  if (registrationTransport.mode !== 'managed') {
    throw new Error(
      'Threshold Ed25519 Option A registration currently requires managed registration transport',
    );
  }
  const grantStartedAt = performance.now();
  const grant = await requestManagedRegistrationFlowGrant({
    relayerUrl: registrationTransport.relayerUrl,
    publishableKey: registrationTransport.publishableKey,
    environmentId: registrationTransport.environmentId,
    nearAccountId: String(args.nearAccountId || '').trim(),
    rpId: String(args.rpId || '').trim(),
  });
  console.debug('[Registration] managed registration flow grant issued', {
    durationMs: Math.round(performance.now() - grantStartedAt),
  });
  return grant;
}

export async function prepareThresholdEd25519HssServerCeremonyWithRelayRegistration(args: {
  context: PasskeyManagerContext;
  nearAccountId: string;
  rpId: string;
  hssContext: ThresholdEd25519HssCanonicalContext;
}): Promise<{
  ceremonyHandle: string;
  preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  clientOtOfferMessageB64u: string;
}> {
  const startedAt = performance.now();
  const registrationTransport = resolveRegistrationTransport(args.context);
  const requestPayload = {
    new_account_id: String(args.nearAccountId || '').trim(),
    rp_id: String(args.rpId || '').trim(),
    context: args.hssContext,
  };
  const requestBody = JSON.stringify(requestPayload);
  const requestBytes = utf8Bytes(requestBody);
  const requestSizeBreakdown = {
    newAccountIdBytes: utf8Bytes(requestPayload.new_account_id),
    rpIdBytes: utf8Bytes(requestPayload.rp_id),
    contextBytes: jsonBytes(requestPayload.context),
  };
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  let response: Response;

  if (registrationTransport.mode === 'managed') {
    const token = (
      await requestManagedRegistrationFlowGrant({
        relayerUrl: registrationTransport.relayerUrl,
        publishableKey: registrationTransport.publishableKey,
        environmentId: registrationTransport.environmentId,
        nearAccountId: requestPayload.new_account_id,
        rpId: requestPayload.rp_id,
      })
    ).token;
    const prepareUrl = joinUrlPath(
      registrationTransport.relayerUrl,
      '/registration/threshold-ed25519/hss/prepare',
    );
    response = await fetchWithRegistrationTimeout({
      url: prepareUrl,
      operation: 'Threshold Ed25519 HSS registration prepare',
      init: {
        method: 'POST',
        headers: {
          ...headers,
          Authorization: `Bearer ${token}`,
        },
        body: requestBody,
      },
    });
  } else {
    const prepareUrl =
      replaceUrlPathSuffix(
        registrationTransport.bootstrapUrl,
        '/registration/bootstrap',
        '/registration/threshold-ed25519/hss/prepare',
      ) ||
      joinUrlPath(
        registrationTransport.bootstrapUrl,
        '/registration/threshold-ed25519/hss/prepare',
      );
    response = await fetchWithRegistrationTimeout({
      url: prepareUrl,
      operation: 'Threshold Ed25519 HSS registration prepare',
      init: {
        method: 'POST',
        headers,
        body: requestBody,
      },
    });
  }

  const result = (await readJsonObject(
    response,
  )) as unknown as ThresholdEd25519HssPrepareForRegistrationResponse;
  const ceremonyHandle = String(result.ok === true ? result.ceremonyHandle || '' : '').trim();
  const preparedSession = result.ok === true ? result.preparedSession : undefined;
  const clientOtOfferMessageB64u = String(
    result.ok === true ? result.clientOtOfferMessageB64u || '' : '',
  ).trim();
  if (
    !response.ok ||
    result.ok !== true ||
    !ceremonyHandle ||
    !preparedSession ||
    !clientOtOfferMessageB64u
  ) {
    const failure = result as Extract<
      ThresholdEd25519HssPrepareForRegistrationResponse,
      { ok: false }
    >;
    throw new Error(String(failure.message || failure.code || `HTTP ${response.status}`).trim());
  }
  const responsePayload = {
    ceremonyHandle,
    preparedSession,
    clientOtOfferMessageB64u,
  };
  const responseBytes = jsonBytes(responsePayload);
  const responseSizeBreakdown = {
    ceremonyHandleBytes: utf8Bytes(ceremonyHandle),
    preparedSessionBytes: jsonBytes(preparedSession),
    clientOtOfferMessageBytes: utf8Bytes(clientOtOfferMessageB64u),
  };
  console.debug('[Registration] threshold-ed25519 HSS prepare response received', {
    durationMs: Math.round(performance.now() - startedAt),
    status: response.status,
    requestBytes,
    requestSizeBreakdown,
    responseBytes,
    responseSizeBreakdown,
  });
  return { ceremonyHandle, preparedSession, clientOtOfferMessageB64u };
}

export async function respondThresholdEd25519HssServerCeremonyWithRelayRegistration(args: {
  context: PasskeyManagerContext;
  nearAccountId: string;
  rpId: string;
  ceremonyHandle: string;
  clientRequest: ThresholdEd25519HssClientRequestEnvelope;
}): Promise<{
}> {
  const startedAt = performance.now();
  const registrationTransport = resolveRegistrationTransport(args.context);
  const requestPayload = {
    new_account_id: String(args.nearAccountId || '').trim(),
    rp_id: String(args.rpId || '').trim(),
    ceremonyHandle: String(args.ceremonyHandle || '').trim(),
    clientRequest: args.clientRequest,
  };
  const requestBody = JSON.stringify(requestPayload);
  const requestBytes = utf8Bytes(requestBody);
  const requestSizeBreakdown = {
    newAccountIdBytes: utf8Bytes(requestPayload.new_account_id),
    rpIdBytes: utf8Bytes(requestPayload.rp_id),
    ceremonyHandleBytes: utf8Bytes(requestPayload.ceremonyHandle),
    clientRequestBytes: jsonBytes(requestPayload.clientRequest),
  };
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  let response: Response;

  if (registrationTransport.mode === 'managed') {
    const token = (
      await requestManagedRegistrationFlowGrant({
        relayerUrl: registrationTransport.relayerUrl,
        publishableKey: registrationTransport.publishableKey,
        environmentId: registrationTransport.environmentId,
        nearAccountId: requestPayload.new_account_id,
        rpId: requestPayload.rp_id,
      })
    ).token;
    const respondUrl = joinUrlPath(
      registrationTransport.relayerUrl,
      '/registration/threshold-ed25519/hss/respond',
    );
    response = await fetchWithRegistrationTimeout({
      url: respondUrl,
      operation: 'Threshold Ed25519 HSS registration respond',
      init: {
        method: 'POST',
        headers: {
          ...headers,
          Authorization: `Bearer ${token}`,
        },
        body: requestBody,
      },
    });
  } else {
    const respondUrl =
      replaceUrlPathSuffix(
        registrationTransport.bootstrapUrl,
        '/registration/bootstrap',
        '/registration/threshold-ed25519/hss/respond',
      ) ||
      joinUrlPath(
        registrationTransport.bootstrapUrl,
        '/registration/threshold-ed25519/hss/respond',
      );
    response = await fetchWithRegistrationTimeout({
      url: respondUrl,
      operation: 'Threshold Ed25519 HSS registration respond',
      init: {
        method: 'POST',
        headers,
        body: requestBody,
      },
    });
  }

  const result = (await readJsonObject(
    response,
  )) as unknown as ThresholdEd25519HssRespondForRegistrationResponse;
  if (!response.ok || result.ok !== true) {
    const failure = result as Extract<
      ThresholdEd25519HssRespondForRegistrationResponse,
      { ok: false }
    >;
    throw new Error(String(failure.message || failure.code || `HTTP ${response.status}`).trim());
  }
  const responsePayload = { ok: true };
  const responseBytes = jsonBytes(responsePayload);
  const responseSizeBreakdown = {};
  console.debug('[Registration] threshold-ed25519 HSS respond response received', {
    durationMs: Math.round(performance.now() - startedAt),
    status: response.status,
    requestBytes,
    requestSizeBreakdown,
    responseBytes,
    responseSizeBreakdown,
  });
  return {};
}

export async function finalizeThresholdEd25519HssServerCeremonyWithRelayRegistration(args: {
  context: PasskeyManagerContext;
  nearAccountId: string;
  rpId: string;
  ceremonyHandle: string;
}): Promise<ThresholdEd25519RegistrationHssFinalizeResult> {
  const finalizeStartedAt = performance.now();
  const registrationTransport = resolveRegistrationTransport(args.context);
  const requestPayload = {
    new_account_id: String(args.nearAccountId || '').trim(),
    rp_id: String(args.rpId || '').trim(),
    ceremonyHandle: String(args.ceremonyHandle || '').trim(),
  };
  const requestBody = JSON.stringify(requestPayload);
  const requestBytes = utf8Bytes(requestBody);
  const requestSizeBreakdown = {
    newAccountIdBytes: utf8Bytes(requestPayload.new_account_id),
    rpIdBytes: utf8Bytes(requestPayload.rp_id),
    ceremonyHandleBytes: utf8Bytes(requestPayload.ceremonyHandle),
  };
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  let response: Response;

  if (registrationTransport.mode === 'managed') {
    const token = (
      await requestManagedRegistrationFlowGrant({
        relayerUrl: registrationTransport.relayerUrl,
        publishableKey: registrationTransport.publishableKey,
        environmentId: registrationTransport.environmentId,
        nearAccountId: requestPayload.new_account_id,
        rpId: requestPayload.rp_id,
      })
    ).token;
    const finalizeUrl = joinUrlPath(
      registrationTransport.relayerUrl,
      '/registration/threshold-ed25519/hss/finalize',
    );
    response = await fetchWithRegistrationTimeout({
      url: finalizeUrl,
      operation: 'Threshold Ed25519 HSS registration finalize',
      init: {
        method: 'POST',
        headers: {
          ...headers,
          Authorization: `Bearer ${token}`,
        },
        body: requestBody,
      },
    });
  } else {
    const finalizeUrl =
      replaceUrlPathSuffix(
        registrationTransport.bootstrapUrl,
        '/registration/bootstrap',
        '/registration/threshold-ed25519/hss/finalize',
      ) ||
      joinUrlPath(
        registrationTransport.bootstrapUrl,
        '/registration/threshold-ed25519/hss/finalize',
      );
    response = await fetchWithRegistrationTimeout({
      url: finalizeUrl,
      operation: 'Threshold Ed25519 HSS registration finalize',
      init: {
        method: 'POST',
        headers,
        body: requestBody,
      },
    });
  }

  const result = (await readJsonObject(
    response,
  )) as unknown as ThresholdEd25519HssFinalizeForRegistrationResponse;
  if (!response.ok || result.ok !== true) {
    const failure = result as Extract<
      ThresholdEd25519HssFinalizeForRegistrationResponse,
      { ok: false }
    >;
    throw new Error(String(failure.message || failure.code || `HTTP ${response.status}`).trim());
  }
  const responsePayload = {
    publicKey: String(result.publicKey || '').trim(),
    relayerKeyId: String(result.relayerKeyId || '').trim(),
  };
  const responseBytes = jsonBytes(responsePayload);
  const responseSizeBreakdown = {
    publicKeyBytes: utf8Bytes(String(result.publicKey || '').trim()),
    relayerKeyIdBytes: utf8Bytes(String(result.relayerKeyId || '').trim()),
  };
  console.debug('[Registration] threshold-ed25519 HSS finalize response received', {
    durationMs: Math.round(performance.now() - finalizeStartedAt),
    status: response.status,
    requestBytes,
    requestSizeBreakdown,
    responseBytes,
    responseSizeBreakdown,
  });
  return {
    publicKey: String(result.publicKey || '').trim(),
    relayerKeyId: String(result.relayerKeyId || '').trim(),
  };
}

/**
 * HTTP Request body for the relay server's /registration/bootstrap endpoint
 */
type ThresholdEd25519RegistrationSessionPolicy = Omit<Ed25519SessionPolicy, 'relayerKeyId'> & {
  relayerKeyId?: string;
};

export interface CreateAccountAndRegisterThresholdEd25519Input {
  keyVersion: string;
  recoveryExportCapable: true;
  publicKey: string;
  relayerKeyId: string;
  sessionPolicy: ThresholdEd25519RegistrationSessionPolicy;
  sessionKind: 'jwt' | 'cookie';
}

export type CreateAccountAndRegisterThresholdEd25519Response = {
  keyVersion: string;
  recoveryExportCapable: true;
  publicKey: string;
  relayerKeyId: string;
  clientParticipantId?: number;
  relayerParticipantId?: number;
  participantIds?: number[];
  session?: {
    sessionKind: 'jwt' | 'cookie';
    sessionId: string;
    expiresAtMs: number;
    expiresAt?: string;
    participantIds?: number[];
    remainingUses?: number;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    jwt?: string;
  };
};

export type ThresholdEd25519RegistrationHssFinalizeResult = {
  publicKey: string;
  relayerKeyId: string;
};

function buildThresholdEd25519RegistrationRequest(
  input?: CreateAccountAndRegisterThresholdEd25519Input,
): CreateAccountAndRegisterUserRequest['threshold_ed25519'] | undefined {
  const thresholdEd25519 = input;
  if (!thresholdEd25519?.relayerKeyId) return undefined;
  return {
    key_version: thresholdEd25519.keyVersion,
    recovery_export_capable: thresholdEd25519.recoveryExportCapable,
    public_key: thresholdEd25519.publicKey,
    relayer_key_id: thresholdEd25519.relayerKeyId,
    session_policy: thresholdEd25519.sessionPolicy,
    session_kind: thresholdEd25519.sessionKind,
  };
}

function normalizeThresholdEd25519RegistrationResult(
  thresholdEd25519: CreateAccountAndRegisterResult['thresholdEd25519'],
): CreateAccountAndRegisterThresholdEd25519Response | undefined {
  if (!thresholdEd25519) return undefined;
  const keyVersion = String(thresholdEd25519.keyVersion || '').trim();
  const publicKey = String(thresholdEd25519.publicKey || '').trim();
  const relayerKeyId = String(thresholdEd25519.relayerKeyId || '').trim();
  if (
    !keyVersion ||
    thresholdEd25519.recoveryExportCapable !== true ||
    !publicKey ||
    !relayerKeyId
  ) {
    throw new Error('Atomic registration returned incomplete threshold-ed25519 key material');
  }
  return {
    keyVersion,
    recoveryExportCapable: true,
    publicKey,
    relayerKeyId,
    clientParticipantId: thresholdEd25519.clientParticipantId,
    relayerParticipantId: thresholdEd25519.relayerParticipantId,
    participantIds: thresholdEd25519.participantIds,
    session: thresholdEd25519.session
      ? {
          sessionKind: thresholdEd25519.session.sessionKind,
          sessionId: thresholdEd25519.session.sessionId,
          expiresAtMs: thresholdEd25519.session.expiresAtMs,
          expiresAt: thresholdEd25519.session.expiresAt,
          participantIds: thresholdEd25519.session.participantIds,
          remainingUses: thresholdEd25519.session.remainingUses,
          runtimePolicyScope: thresholdEd25519.session.runtimePolicyScope,
          jwt: thresholdEd25519.session.jwt,
        }
      : undefined,
  };
}

export interface CreateAccountAndRegisterUserRequest {
  new_account_id: string;
  signer_slot: number;
  threshold_ed25519?: {
    key_version: string;
    recovery_export_capable: boolean;
    public_key: string;
    relayer_key_id: string;
    session_policy: ThresholdEd25519RegistrationSessionPolicy;
    session_kind: 'jwt' | 'cookie';
  };
  rp_id: string;
  webauthn_registration: WebAuthnRegistrationCredential;
  authenticator_options?: AuthenticatorOptions;
}

/**
 * Create account and register user using relay-server atomic endpoint
 * Makes a single call to the relay-server's /registration/bootstrap endpoint
 */
export async function createAccountAndRegisterWithRelayServer(
  context: PasskeyManagerContext,
  nearAccountId: string,
  credential: WebAuthnRegistrationCredential | PublicKeyCredential,
  rpId: string,
  authenticatorOptions?: AuthenticatorOptions,
  onEvent?: RegistrationHooksOptions['onEvent'],
  opts?: {
    thresholdEd25519?: CreateAccountAndRegisterThresholdEd25519Input;
  },
): Promise<{
  success: boolean;
  transactionId?: string;
  thresholdEd25519?: CreateAccountAndRegisterThresholdEd25519Response;
  error?: string;
  errorCode?: RegistrationErrorCode;
}> {
  const { configs } = context;

  if (!configs.network.relayer.url) {
    throw new Error('Relay server URL is required for atomic registration');
  }

  try {
    emitRelayRegistrationEvent(onEvent, nearAccountId, {
      phase: RegistrationEventPhase.STEP_06_RELAY_BOOTSTRAP_STARTED,
      status: 'running',
    });

    // Serialize the WebAuthn credential properly for the contract.
    // Accept both live PublicKeyCredential and already-serialized credentials from secureConfirm.
    const isSerialized = isSerializedRegistrationCredential(credential);

    // Ensure proper serialization + normalization regardless of source
    const serialized: WebAuthnRegistrationCredential = isSerialized
      ? normalizeRegistrationCredential(credential)
      : serializeRegistrationCredential(credential);

    // Strip PRF outputs before sending to relay/contract
    const serializedCredential =
      redactCredentialExtensionOutputs<WebAuthnRegistrationCredential>(serialized);
    // Normalize transports to an array (avoid null)
    if (!Array.isArray(serializedCredential?.response?.transports)) {
      serializedCredential.response.transports = [];
    }

    const thresholdEd25519Request = buildThresholdEd25519RegistrationRequest(
      opts?.thresholdEd25519,
    );

    const requestData: CreateAccountAndRegisterUserRequest = {
      new_account_id: nearAccountId,
      signer_slot: 1,
      ...(thresholdEd25519Request ? { threshold_ed25519: thresholdEd25519Request } : {}),
      rp_id: String(rpId || '').trim(),
      webauthn_registration: serializedCredential,
      authenticator_options: cloneAuthenticatorOptions(
        authenticatorOptions ?? context.configs.webauthn.authenticatorOptions,
      ),
    };

    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const registrationTransport = resolveRegistrationTransport(context);
    let response: Response;
    let result: CreateAccountAndRegisterResult;

    if (registrationTransport.mode === 'managed') {
      const managedToken = (
        await requestManagedRegistrationFlowGrant({
          relayerUrl: registrationTransport.relayerUrl,
          publishableKey: registrationTransport.publishableKey,
          environmentId: registrationTransport.environmentId,
          nearAccountId,
          rpId: requestData.rp_id,
        })
      ).token;
      const registrationBootstrapUrl = joinUrlPath(
        configs.network.relayer.url,
        '/registration/bootstrap',
      );
      if (!registrationBootstrapUrl) {
        throw new Error('Relay server URL is required for managed passkey registration');
      }
      response = await fetchWithRegistrationTimeout({
        url: registrationBootstrapUrl,
        operation: 'Managed passkey registration bootstrap',
        init: {
          method: 'POST',
          headers: {
            ...headers,
            Authorization: `Bearer ${managedToken}`,
          },
          body: JSON.stringify(requestData),
        },
      });
      result = (await readJsonObject(response)) as unknown as CreateAccountAndRegisterResult;
    } else {
      if (!registrationTransport.bootstrapUrl) {
        throw new Error('Registration bootstrap URL is required for passkey registration');
      }
      response = await fetchWithRegistrationTimeout({
        url: registrationTransport.bootstrapUrl,
        operation: 'Passkey registration bootstrap',
        init: {
          method: 'POST',
          headers,
          body: JSON.stringify(requestData),
        },
      });
      result = (await readJsonObject(response)) as unknown as CreateAccountAndRegisterResult;
    }

    const responseCode = String(result.code || '').trim();
    const responseMessage =
      result.error || result.message || `HTTP ${response.status}: ${response.statusText}`;

    if (!response.ok) {
      if (isRegistrationErrorCode(responseCode)) {
        throw new RelayRegistrationError({
          code: responseCode,
          status: response.status,
          message: responseMessage,
        });
      }
      throw new Error(
        improveAtomicRegistrationError({
          raw: responseMessage,
          nearAccountId,
          relayUrl: configs.network.relayer.url,
        }),
      );
    }

    if (!result.success) {
      if (isRegistrationErrorCode(responseCode)) {
        throw new RelayRegistrationError({
          code: responseCode,
          status: response.status,
          message: responseMessage,
        });
      }
      throw new Error(responseMessage || 'Atomic registration failed');
    }

    const normalizedThresholdEd25519 = normalizeThresholdEd25519RegistrationResult(
      result.thresholdEd25519,
    );

    emitRelayRegistrationEvent(onEvent, nearAccountId, {
      phase: RegistrationEventPhase.STEP_06_RELAY_BOOTSTRAP_SUCCEEDED,
      status: 'succeeded',
      data: {
        transactionId: result.transactionHash,
      },
    });

    return {
      success: true,
      transactionId: result.transactionHash,
      thresholdEd25519: normalizedThresholdEd25519,
    };
  } catch (error: unknown) {
    console.error('Atomic registration failed:', error);
    const code = isRelayRegistrationError(error) ? error.code : undefined;

    return {
      success: false,
      error: errorMessage(error),
      ...(code ? { errorCode: code } : {}),
    };
  }
}
