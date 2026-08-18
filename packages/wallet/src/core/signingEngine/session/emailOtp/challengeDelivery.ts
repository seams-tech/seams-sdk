import { requireTrimmedString } from '@shared/utils/validation';
import type { EmailOtpChallengeDelivery, EmailOtpChallengeDeliveryStatus } from './publicTypes';

type JsonObject = Record<string, unknown>;

function requireDeliveryObject(value: unknown, label: string): JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as JsonObject;
}

function parseDeliveryStatus(value: unknown, label: string): EmailOtpChallengeDeliveryStatus {
  const status = requireTrimmedString(value, label);
  switch (status) {
    case 'sent':
    case 'reused':
      return status;
    default:
      throw new Error(`${label} must be sent or reused`);
  }
}

function providerDelivery(
  status: EmailOtpChallengeDeliveryStatus,
  emailHint: string,
): EmailOtpChallengeDelivery {
  return { kind: 'provider', status, emailHint };
}

export function parseEmailOtpProviderDelivery(args: {
  status: unknown;
  emailHint: unknown;
  label: string;
}): EmailOtpChallengeDelivery {
  return providerDelivery(
    parseDeliveryStatus(args.status, `${args.label}.status`),
    requireTrimmedString(args.emailHint, `${args.label}.emailHint`),
  );
}

export function parseEmailOtpChallengeDelivery(
  value: unknown,
  label: string,
): EmailOtpChallengeDelivery {
  const delivery = requireDeliveryObject(value, label);
  const kind = requireTrimmedString(delivery.kind, `${label}.kind`);
  const status = parseDeliveryStatus(delivery.status, `${label}.status`);
  const emailHint = requireTrimmedString(delivery.emailHint, `${label}.emailHint`);

  switch (kind) {
    case 'provider':
    case 'development': {
      if (delivery.otpCode !== undefined) {
        throw new Error(`${label}.otpCode is only valid for code-bearing delivery`);
      }
      return providerDelivery(status, emailHint);
    }
    case 'demo_code_response':
    case 'provider_and_demo_code': {
      const otpCode = requireTrimmedString(delivery.otpCode, `${label}.otpCode`);
      if (!/^\d{6}$/.test(otpCode)) {
        throw new Error(`${label}.otpCode must be a 6-digit code`);
      }
      return { kind, status, emailHint, otpCode };
    }
    default:
      throw new Error(`${label}.kind is invalid`);
  }
}

export function demoEmailOtpCodeFromDelivery(delivery: EmailOtpChallengeDelivery): string | null {
  switch (delivery.kind) {
    case 'provider':
      return null;
    case 'demo_code_response':
    case 'provider_and_demo_code':
      return delivery.otpCode;
  }
}
