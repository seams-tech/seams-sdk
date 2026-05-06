import { stripTrailingSlashes, toTrimmedString } from '@shared/utils/validation';
import type { ThresholdEcdsaPresignPoolPolicyInput } from '@/core/types/seams';
import { fetchThresholdEcdsaJson } from './httpRequest';

function toDigest32Bytes(input: Uint8Array | number[]): Uint8Array | null {
  if (input instanceof Uint8Array) {
    return input.length === 32 ? input : null;
  }
  if (!Array.isArray(input)) return null;
  const bytes = Uint8Array.from(input.map((v) => Number(v)));
  return bytes.length === 32 ? bytes : null;
}

function parseThresholdEcdsaPresignPoolPolicyHint(
  value: unknown,
): ThresholdEcdsaPresignPoolPolicyInput | undefined {
  if (!value || typeof value !== 'object') return undefined;
  const raw = value as Record<string, unknown>;
  const out: ThresholdEcdsaPresignPoolPolicyInput = {};
  if (typeof raw.enabled === 'boolean') out.enabled = raw.enabled;
  if (typeof raw.targetDepth === 'number' && Number.isFinite(raw.targetDepth))
    out.targetDepth = Math.floor(raw.targetDepth);
  if (typeof raw.lowWatermark === 'number' && Number.isFinite(raw.lowWatermark))
    out.lowWatermark = Math.floor(raw.lowWatermark);
  if (typeof raw.maxRefillInFlight === 'number' && Number.isFinite(raw.maxRefillInFlight)) {
    out.maxRefillInFlight = Math.floor(raw.maxRefillInFlight);
  }
  if (
    typeof raw.refillAttemptTimeoutMs === 'number' &&
    Number.isFinite(raw.refillAttemptTimeoutMs)
  ) {
    out.refillAttemptTimeoutMs = Math.floor(raw.refillAttemptTimeoutMs);
  }
  return Object.keys(out).length ? out : undefined;
}

export async function authorizeEcdsaWithSession(args: {
  relayerUrl: string;
  ecdsaThresholdKeyId: string;
  purpose: string;
  signingDigest32: Uint8Array | number[];
  signingPayload?: unknown;
  sessionKind?: 'jwt' | 'cookie';
  thresholdSessionAuthToken?: string;
  requestTimeoutMs?: number;
}): Promise<{
  ok: boolean;
  mpcSessionId?: string;
  expiresAtMs?: number;
  expiresAt?: string;
  walletSigningSessionId?: string;
  remainingUses?: number;
  presignPoolPolicy?: ThresholdEcdsaPresignPoolPolicyInput;
  code?: string;
  message?: string;
}> {
  const relayerUrl = stripTrailingSlashes(toTrimmedString(args.relayerUrl));
  if (!relayerUrl) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing relayerUrl for threshold-ecdsa authorize',
    };
  }

  if (typeof fetch !== 'function') {
    return {
      ok: false,
      code: 'unsupported',
      message: 'fetch is not available for threshold-ecdsa authorize',
    };
  }

  const ecdsaThresholdKeyId = String(args.ecdsaThresholdKeyId || '').trim();
  if (!ecdsaThresholdKeyId) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing ecdsaThresholdKeyId for threshold-ecdsa authorize',
    };
  }

  const purpose = String(args.purpose || '').trim();
  if (!purpose) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing purpose for threshold-ecdsa authorize',
    };
  }

  const signingDigest32 = toDigest32Bytes(args.signingDigest32);
  if (!signingDigest32) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'signingDigest32 must be 32 bytes for threshold-ecdsa authorize',
    };
  }

  const sessionKind: 'jwt' | 'cookie' = args.sessionKind || 'jwt';
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const jwt = String(args.thresholdSessionAuthToken || '').trim();
  if (sessionKind === 'jwt' && !jwt) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing thresholdSessionAuthToken for threshold-ecdsa authorize (jwt sessionKind)',
    };
  }
  if (jwt) {
    headers.Authorization = `Bearer ${jwt}`;
  }

  type ThresholdEcdsaAuthorizeResponseBody = Partial<{
    ok: boolean;
    mpcSessionId: string;
    expiresAt: string;
    walletSigningSessionId: string;
    remainingUses: number;
    presignPoolPolicy: ThresholdEcdsaPresignPoolPolicyInput;
    code: string;
    message: string;
  }>;

  try {
    const url = `${relayerUrl}/threshold-ecdsa/authorize`;
    const { response, data } = await fetchThresholdEcdsaJson<ThresholdEcdsaAuthorizeResponseBody>({
      url,
      operation: 'authorize',
      timeoutMs: args.requestTimeoutMs,
      init: {
        method: 'POST',
        headers,
        credentials: jwt ? 'omit' : sessionKind === 'cookie' ? 'include' : 'omit',
        body: JSON.stringify({
          ecdsaThresholdKeyId,
          purpose,
          signing_digest_32: Array.from(signingDigest32),
          ...(args.signingPayload !== undefined ? { signingPayload: args.signingPayload } : {}),
        }),
      },
    });
    if (!response.ok) {
      return {
        ok: false,
        code: data.code || 'http_error',
        message: data.message || `HTTP ${response.status}`,
      };
    }

    const expiresAtMs = (() => {
      const raw = typeof data.expiresAt === 'string' ? Date.parse(data.expiresAt) : NaN;
      return Number.isFinite(raw) ? raw : undefined;
    })();
    const presignPoolPolicy = parseThresholdEcdsaPresignPoolPolicyHint(data.presignPoolPolicy);

    return {
      ok: data.ok === true,
      mpcSessionId: data.mpcSessionId,
      ...(data.expiresAt ? { expiresAt: data.expiresAt } : {}),
      ...(expiresAtMs ? { expiresAtMs } : {}),
      ...(String(data.walletSigningSessionId || '').trim()
        ? { walletSigningSessionId: String(data.walletSigningSessionId || '').trim() }
        : {}),
      ...(Number.isFinite(Number(data.remainingUses))
        ? { remainingUses: Math.max(0, Math.floor(Number(data.remainingUses))) }
        : {}),
      ...(presignPoolPolicy ? { presignPoolPolicy } : {}),
      ...(data.code ? { code: data.code } : {}),
      ...(data.message ? { message: data.message } : {}),
    };
  } catch (e: unknown) {
    const msg = String(
      e && typeof e === 'object' && 'message' in e
        ? (e as { message?: unknown }).message
        : e || 'Failed to authorize threshold-ecdsa',
    );
    return { ok: false, code: 'network_error', message: msg };
  }
}
