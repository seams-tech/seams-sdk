import { readJson } from '../../../../router/framework/http';
import type {
  DeviceLinkingAuthDeniedV1,
  DeviceLinkingOperatorAuthenticatedRequestV1,
  DeviceLinkingOperatorRecoveryProviderV1,
  DeviceLinkingOperatorRequestInputV1,
} from '../../../../router/transport/fetch/routes/deviceLinking';
import { sha256BytesUtf8 } from '@shared/utils/digests';

/** Header used by the private operator-recovery route. */
export const LINKED_DEVICE_OPERATOR_SECRET_HEADER_V1 = 'x-seams-linked-device-operator-secret';

const DEFAULT_OPERATOR_RECOVERY_TTL_MS_V1 = 30_000;
const MAX_OPERATOR_RECOVERY_TTL_MS_V1 = 300_000;

export type D1LinkedDeviceOperatorRecoveryProviderOptionsV1 = {
  /** Secret delivered through the private operator control plane. */
  readonly operatorSecret: string;
  /** A short-lived binding prevents a captured operator request from being reused. */
  readonly ttlMs?: number;
};

/**
 * Authenticates the private recovery route before reading its body. The D1
 * route performs the durable recovery mutation after this authority boundary.
 */
export class D1LinkedDeviceOperatorRecoveryProviderV1 implements DeviceLinkingOperatorRecoveryProviderV1 {
  private readonly operatorSecret: string;
  private readonly ttlMs: number;

  constructor(options: D1LinkedDeviceOperatorRecoveryProviderOptionsV1) {
    this.operatorSecret = requireSecret(options.operatorSecret);
    this.ttlMs = requireShortTtl(options.ttlMs ?? DEFAULT_OPERATOR_RECOVERY_TTL_MS_V1);
  }

  async authenticateOperatorRecoveryRequestV1(
    input: DeviceLinkingOperatorRequestInputV1,
  ): Promise<DeviceLinkingOperatorAuthenticatedRequestV1 | DeviceLinkingAuthDeniedV1> {
    const suppliedSecret = input.request.headers.get(LINKED_DEVICE_OPERATOR_SECRET_HEADER_V1);
    if (
      suppliedSecret === null ||
      !(await constantTimeSecretEqualV1(this.operatorSecret, suppliedSecret))
    ) {
      return denied('unauthorized', 'operator recovery authentication failed');
    }
    if (input.method !== 'GET' && input.method !== 'POST') {
      return denied('invalid', 'operator recovery method is invalid');
    }
    if (!isPathname(input.pathname)) {
      return denied('invalid', 'operator recovery pathname is invalid');
    }
    if (!Number.isSafeInteger(input.requestedAtMs) || input.requestedAtMs < 0) {
      return denied('invalid', 'operator recovery request timestamp is invalid');
    }
    const expiresAtMs = input.requestedAtMs + this.ttlMs;
    if (!Number.isSafeInteger(expiresAtMs)) {
      return denied('invalid', 'operator recovery binding expiry is invalid');
    }

    // This is deliberately after the secret check. The route's body digest is
    // computed from the original bytes before authentication and is retained
    // in the returned binding.
    const body = await readJson(input.request.clone());
    return {
      kind: 'authorized',
      body,
      binding: {
        kind: 'linked_device_operator_request_binding_v1',
        method: input.method,
        pathname: input.pathname,
        bodyDigestB64u: input.bodyDigestB64u,
        expiresAtMs,
      },
    };
  }
}

function requireSecret(value: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    throw new Error('operator recovery secret must be nonempty and canonical');
  }
  return value;
}

function requireShortTtl(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0 || value > MAX_OPERATOR_RECOVERY_TTL_MS_V1) {
    throw new Error('operator recovery TTL must be a short positive duration');
  }
  return value;
}

function isPathname(value: string): boolean {
  return (
    typeof value === 'string' && value.length > 0 && value.startsWith('/') && value.trim() === value
  );
}

async function constantTimeSecretEqualV1(left: string, right: string): Promise<boolean> {
  const [leftDigest, rightDigest] = await Promise.all([
    sha256BytesUtf8(left),
    sha256BytesUtf8(right),
  ]);
  let difference = leftDigest.length ^ rightDigest.length;
  const length = Math.max(leftDigest.length, rightDigest.length);
  for (let index = 0; index < length; index += 1) {
    difference |= (leftDigest[index] ?? 0) ^ (rightDigest[index] ?? 0);
  }
  return difference === 0;
}

function denied(
  code: DeviceLinkingAuthDeniedV1['code'],
  message: string,
): DeviceLinkingAuthDeniedV1 {
  return { kind: 'denied', code, message };
}
