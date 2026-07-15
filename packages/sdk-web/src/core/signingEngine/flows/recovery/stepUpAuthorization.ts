import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import {
  SigningAuthPlanKind,
  type EmailOtpConfirmPrompt,
  type EmailOtpStepUpAuthorization,
  type PasskeyStepUpAuthorization,
  type SigningAuthPlan,
  type UserConfirmDecision,
} from '@/core/signingEngine/stepUpConfirmation/types';
import { normalizeAuthenticationCredential } from '@/core/signingEngine/webauthnAuth/credentials/helpers';

type EcdsaExportAuthorizationIdentity = {
  walletSessionUserId: string;
  publicKey: string;
  curve: 'ecdsa';
  intent: 'ecdsa_export';
  chain: ThresholdEcdsaChainTarget['kind'];
};

type Ed25519ExportAuthorizationIdentity = {
  walletSessionUserId: string;
  publicKey: string;
  curve: 'ed25519';
  intent: 'ed25519_export';
  chain: 'near';
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  signerSlot: number;
  thresholdSessionId: string;
  signingGrantId: string;
};

type ExportAuthorizationIdentity =
  | EcdsaExportAuthorizationIdentity
  | Ed25519ExportAuthorizationIdentity;

export type EcdsaExportPasskeyStepUpAuthorization = PasskeyStepUpAuthorization<
  Extract<SigningAuthPlan, { kind: typeof SigningAuthPlanKind.PasskeyReauth }>,
  EcdsaExportAuthorizationIdentity
> &
  EcdsaExportAuthorizationIdentity;

export type Ed25519ExportPasskeyStepUpAuthorization = PasskeyStepUpAuthorization<
  Extract<SigningAuthPlan, { kind: typeof SigningAuthPlanKind.PasskeyReauth }>,
  Ed25519ExportAuthorizationIdentity
> &
  Ed25519ExportAuthorizationIdentity;

export type ExportPasskeyStepUpAuthorization =
  | EcdsaExportPasskeyStepUpAuthorization
  | Ed25519ExportPasskeyStepUpAuthorization;

export type EcdsaExportEmailOtpStepUpAuthorization = EmailOtpStepUpAuthorization<
  Extract<SigningAuthPlan, { kind: typeof SigningAuthPlanKind.EmailOtpReauth }>,
  EcdsaExportAuthorizationIdentity
> &
  EcdsaExportAuthorizationIdentity;

export type Ed25519ExportEmailOtpStepUpAuthorization = EmailOtpStepUpAuthorization<
  Extract<SigningAuthPlan, { kind: typeof SigningAuthPlanKind.EmailOtpReauth }>,
  Ed25519ExportAuthorizationIdentity
> &
  Ed25519ExportAuthorizationIdentity;

export type ExportEmailOtpStepUpAuthorization =
  | EcdsaExportEmailOtpStepUpAuthorization
  | Ed25519ExportEmailOtpStepUpAuthorization;

export type ExportStepUpAuthorization =
  | ExportPasskeyStepUpAuthorization
  | ExportEmailOtpStepUpAuthorization;

type ExportPasskeyStepUpAuthorizationInput = {
  method: 'passkey';
  decision: UserConfirmDecision;
} & ExportAuthorizationIdentity;

type ExportEmailOtpStepUpAuthorizationInput = {
  method: 'email_otp';
  decision: Pick<UserConfirmDecision, 'confirmed' | 'error' | 'otpCode' | 'emailOtpChallengeId'>;
  emailOtpPrompt: EmailOtpConfirmPrompt;
} & ExportAuthorizationIdentity;

function assertNeverExportAuthorizationIdentity(value: never): never {
  throw new Error(`[SigningEngine][export] unsupported authorization identity: ${String(value)}`);
}

function assertNeverExportStepUpMethod(value: never): never {
  throw new Error(`[SigningEngine][export] unsupported step-up method: ${String(value)}`);
}

function normalizeExportAuthorizationIdentity(
  args: ExportAuthorizationIdentity,
): ExportAuthorizationIdentity {
  const walletSessionUserId = String(args.walletSessionUserId || '').trim();
  if (!walletSessionUserId) {
    throw new Error('[SigningEngine][export] missing export step-up authorization identity');
  }
  const publicKey = String(args.publicKey || '').trim();
  if (!publicKey) {
    throw new Error('[SigningEngine][export] missing export step-up authorization public key');
  }
  switch (args.curve) {
    case 'ecdsa':
      return {
        walletSessionUserId,
        publicKey,
        curve: 'ecdsa',
        intent: 'ecdsa_export',
        chain: args.chain,
      };
    case 'ed25519': {
      const identity: Ed25519ExportAuthorizationIdentity = {
        walletSessionUserId,
        publicKey,
        curve: 'ed25519',
        intent: 'ed25519_export',
        chain: 'near',
        nearAccountId: String(args.nearAccountId || '').trim(),
        nearEd25519SigningKeyId: String(args.nearEd25519SigningKeyId || '').trim(),
        signerSlot: Number(args.signerSlot),
        thresholdSessionId: String(args.thresholdSessionId || '').trim(),
        signingGrantId: String(args.signingGrantId || '').trim(),
      };
      if (
        !identity.nearAccountId ||
        !identity.nearEd25519SigningKeyId ||
        !Number.isSafeInteger(identity.signerSlot) ||
        identity.signerSlot < 1 ||
        !identity.thresholdSessionId ||
        !identity.signingGrantId
      ) {
        throw new Error('[SigningEngine][export] Ed25519 export authorization identity is invalid');
      }
      return identity;
    }
    default:
      return assertNeverExportAuthorizationIdentity(args);
  }
}

function buildEmailOtpExportAuthorization(args: {
  identity: ExportAuthorizationIdentity;
  emailOtpPrompt: EmailOtpConfirmPrompt;
  challengeId: string;
  otpCode: string;
}): ExportEmailOtpStepUpAuthorization {
  const signingAuthPlan = {
    kind: SigningAuthPlanKind.EmailOtpReauth,
    method: 'email_otp',
    emailOtpPrompt: args.emailOtpPrompt,
  } as const;
  const emailHint = args.emailOtpPrompt.emailHint;
  switch (args.identity.curve) {
    case 'ecdsa':
      return {
        kind: 'email_otp',
        signingAuthPlan,
        challengeId: args.challengeId,
        otpCode: args.otpCode,
        walletSessionUserId: args.identity.walletSessionUserId,
        publicKey: args.identity.publicKey,
        curve: 'ecdsa',
        intent: 'ecdsa_export',
        chain: args.identity.chain,
        ...(emailHint ? { emailHint } : {}),
      };
    case 'ed25519':
      return {
        kind: 'email_otp',
        signingAuthPlan,
        challengeId: args.challengeId,
        otpCode: args.otpCode,
        walletSessionUserId: args.identity.walletSessionUserId,
        publicKey: args.identity.publicKey,
        curve: 'ed25519',
        intent: 'ed25519_export',
        chain: 'near',
        nearAccountId: args.identity.nearAccountId,
        nearEd25519SigningKeyId: args.identity.nearEd25519SigningKeyId,
        signerSlot: args.identity.signerSlot,
        thresholdSessionId: args.identity.thresholdSessionId,
        signingGrantId: args.identity.signingGrantId,
        ...(emailHint ? { emailHint } : {}),
      };
    default:
      return assertNeverExportAuthorizationIdentity(args.identity);
  }
}

function buildPasskeyExportAuthorization(args: {
  identity: ExportAuthorizationIdentity;
  credential: WebAuthnAuthenticationCredential;
}): ExportPasskeyStepUpAuthorization {
  const signingAuthPlan = {
    kind: SigningAuthPlanKind.PasskeyReauth,
    method: 'passkey',
  } as const;
  switch (args.identity.curve) {
    case 'ecdsa':
      return {
        kind: 'passkey',
        signingAuthPlan,
        credential: args.credential,
        walletSessionUserId: args.identity.walletSessionUserId,
        publicKey: args.identity.publicKey,
        curve: 'ecdsa',
        intent: 'ecdsa_export',
        chain: args.identity.chain,
      };
    case 'ed25519':
      return {
        kind: 'passkey',
        signingAuthPlan,
        credential: args.credential,
        walletSessionUserId: args.identity.walletSessionUserId,
        publicKey: args.identity.publicKey,
        curve: 'ed25519',
        intent: 'ed25519_export',
        chain: 'near',
        nearAccountId: args.identity.nearAccountId,
        nearEd25519SigningKeyId: args.identity.nearEd25519SigningKeyId,
        signerSlot: args.identity.signerSlot,
        thresholdSessionId: args.identity.thresholdSessionId,
        signingGrantId: args.identity.signingGrantId,
      };
    default:
      return assertNeverExportAuthorizationIdentity(args.identity);
  }
}

export function buildExportStepUpAuthorization(
  args: {
    method: 'passkey';
    decision: UserConfirmDecision;
  } & EcdsaExportAuthorizationIdentity,
): EcdsaExportPasskeyStepUpAuthorization;
export function buildExportStepUpAuthorization(
  args: {
    method: 'passkey';
    decision: UserConfirmDecision;
  } & Ed25519ExportAuthorizationIdentity,
): Ed25519ExportPasskeyStepUpAuthorization;
export function buildExportStepUpAuthorization(
  args: {
    method: 'email_otp';
    decision: Pick<UserConfirmDecision, 'confirmed' | 'error' | 'otpCode' | 'emailOtpChallengeId'>;
    emailOtpPrompt: EmailOtpConfirmPrompt;
  } & EcdsaExportAuthorizationIdentity,
): EcdsaExportEmailOtpStepUpAuthorization;
export function buildExportStepUpAuthorization(
  args: {
    method: 'email_otp';
    decision: Pick<UserConfirmDecision, 'confirmed' | 'error' | 'otpCode' | 'emailOtpChallengeId'>;
    emailOtpPrompt: EmailOtpConfirmPrompt;
  } & Ed25519ExportAuthorizationIdentity,
): Ed25519ExportEmailOtpStepUpAuthorization;
export function buildExportStepUpAuthorization(
  args: ExportPasskeyStepUpAuthorizationInput | ExportEmailOtpStepUpAuthorizationInput,
): ExportStepUpAuthorization {
  const identity = normalizeExportAuthorizationIdentity(args);
  switch (args.method) {
    case 'email_otp': {
      if (!args.decision.confirmed) {
        throw new Error(args.decision.error || 'User cancelled Email OTP export request');
      }
      const otpCode = String(args.decision.otpCode || '')
        .replace(/\D/g, '')
        .slice(0, 6);
      if (otpCode.length !== 6) {
        throw new Error('Email OTP export requires a 6-digit code');
      }
      const challengeId = String(
        args.decision.emailOtpChallengeId || args.emailOtpPrompt.challengeId || '',
      ).trim();
      if (!challengeId) {
        throw new Error('Email OTP export challenge response did not include challengeId');
      }
      return buildEmailOtpExportAuthorization({
        identity,
        emailOtpPrompt: args.emailOtpPrompt,
        challengeId,
        otpCode,
      });
    }
    case 'passkey':
      if (!args.decision.confirmed) {
        throw new Error(args.decision.error || 'User cancelled export request');
      }
      if (!args.decision.credential) {
        throw new Error(
          '[SigningEngine][export] missing WebAuthn credential for export authorization',
        );
      }
      return buildPasskeyExportAuthorization({
        identity,
        credential: normalizeAuthenticationCredential(args.decision.credential),
      });
    default:
      return assertNeverExportStepUpMethod(args);
  }
}
