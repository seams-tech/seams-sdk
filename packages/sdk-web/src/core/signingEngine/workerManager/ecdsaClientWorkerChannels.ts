import { isObject } from '@shared/utils/validation';

export const EcdsaClientWorkerControlKind = {
  AttachDerivationToPresign: 'attach_ecdsa_derivation_to_presign_v1',
  AttachEmailOtpToPresign: 'attach_email_otp_to_ecdsa_presign_v1',
  AttachPresignToOnline: 'attach_ecdsa_presign_to_online_v1',
} as const;

export type AttachEcdsaDerivationToPresignPort = {
  readonly kind: typeof EcdsaClientWorkerControlKind.AttachDerivationToPresign;
  readonly port: MessagePort;
};

export type AttachEcdsaPresignToOnlinePort = {
  readonly kind: typeof EcdsaClientWorkerControlKind.AttachPresignToOnline;
  readonly port: MessagePort;
};

export type AttachEmailOtpToPresignPort = {
  readonly kind: typeof EcdsaClientWorkerControlKind.AttachEmailOtpToPresign;
  readonly port: MessagePort;
};

export type EcdsaDerivationAdditiveShareRequest = {
  readonly kind: 'ecdsa_derivation_additive_share_request_v1';
  readonly requestId: string;
  readonly materialHandle: string;
  readonly expectedBindingDigest: string;
};

export type EcdsaDerivationAdditiveShareResponse =
  | {
      readonly kind: 'ecdsa_derivation_additive_share_result_v1';
      readonly requestId: string;
      readonly ok: true;
      readonly additiveShare32: ArrayBuffer;
      readonly error?: never;
    }
  | {
      readonly kind: 'ecdsa_derivation_additive_share_result_v1';
      readonly requestId: string;
      readonly ok: false;
      readonly additiveShare32?: never;
      readonly error: string;
    };

export type EmailOtpEcdsaSigningShareRequest = {
  readonly kind: 'email_otp_ecdsa_signing_share_request_v1';
  readonly requestId: string;
  readonly sessionId: string;
};

export type EmailOtpEcdsaSigningShareResponse =
  | {
      readonly kind: 'email_otp_ecdsa_signing_share_result_v1';
      readonly requestId: string;
      readonly ok: true;
      readonly additiveShare32: ArrayBuffer;
      readonly remainingUses: number;
      readonly expiresAtMs: number;
      readonly error?: never;
    }
  | {
      readonly kind: 'email_otp_ecdsa_signing_share_result_v1';
      readonly requestId: string;
      readonly ok: false;
      readonly additiveShare32?: never;
      readonly remainingUses?: never;
      readonly expiresAtMs?: never;
      readonly error: string;
    };

export type EcdsaPresignMaterialRequest = {
  readonly kind: 'ecdsa_presign_material_request_v1';
  readonly requestId: string;
  readonly materialHandle: string;
};

export type EcdsaPresignMaterialResponse =
  | {
      readonly kind: 'ecdsa_presign_material_result_v1';
      readonly requestId: string;
      readonly ok: true;
      readonly bigR33: ArrayBuffer;
      readonly kShare32: ArrayBuffer;
      readonly sigmaShare32: ArrayBuffer;
      readonly error?: never;
    }
  | {
      readonly kind: 'ecdsa_presign_material_result_v1';
      readonly requestId: string;
      readonly ok: false;
      readonly bigR33?: never;
      readonly kShare32?: never;
      readonly sigmaShare32?: never;
      readonly error: string;
    };

type ParsedWorkerChannelControl = {
  readonly kind: unknown;
  readonly port: unknown;
};

function parseWorkerChannelControl(value: unknown): ParsedWorkerChannelControl | null {
  if (!isObject(value)) return null;
  return { kind: value.kind, port: value.port };
}

export function isAttachEcdsaDerivationToPresignPort(
  value: unknown,
): value is AttachEcdsaDerivationToPresignPort {
  const parsed = parseWorkerChannelControl(value);
  return (
    parsed?.kind === EcdsaClientWorkerControlKind.AttachDerivationToPresign &&
    parsed.port instanceof MessagePort
  );
}

export function isAttachEcdsaPresignToOnlinePort(
  value: unknown,
): value is AttachEcdsaPresignToOnlinePort {
  const parsed = parseWorkerChannelControl(value);
  return (
    parsed?.kind === EcdsaClientWorkerControlKind.AttachPresignToOnline &&
    parsed.port instanceof MessagePort
  );
}

export function isAttachEmailOtpToPresignPort(
  value: unknown,
): value is AttachEmailOtpToPresignPort {
  const parsed = parseWorkerChannelControl(value);
  return (
    parsed?.kind === EcdsaClientWorkerControlKind.AttachEmailOtpToPresign &&
    parsed.port instanceof MessagePort
  );
}
