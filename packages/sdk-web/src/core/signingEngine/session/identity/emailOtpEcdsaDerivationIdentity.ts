import type {
  EcdsaThresholdKeyId,
  EvmFamilyEcdsaSessionLanePolicy,
  SessionBootstrapKeyContext,
  SigningRootId,
  SigningRootVersion,
  ThresholdEcdsaSessionId,
  ThresholdOwnerAddress,
  SigningGrantId,
} from './evmFamilyEcdsaIdentity';
import type { EmailOtpAuthSubjectId } from '@/core/platform/types';
import {
  parseSdkEcdsaDerivationSigningRootId,
  parseSdkEcdsaDerivationSigningRootVersion,
  parseSdkEcdsaDerivationThresholdKeyId,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { parseSigningGrantId } from '@shared/utils/domainIds';

export type {
  EcdsaThresholdKeyId,
  EmailOtpAuthSubjectId,
  SigningRootId,
  SigningRootVersion,
  ThresholdEcdsaSessionId,
  ThresholdOwnerAddress,
  SigningGrantId,
};

export type WalletSessionUserId = string & { readonly __brand: 'WalletSessionUserId' };

export type EmailOtpRegistrationBootstrap = {
  operation: 'email_otp_bootstrap';
  ecdsaThresholdKeyId?: never;
  key?: never;
  lanePolicy?: never;
};

export type EmailOtpExistingKeyBootstrap = {
  operation: 'email_otp_bootstrap';
  keyHandle: string;
  ecdsaThresholdKeyId?: never;
  key?: never;
  lanePolicy?: never;
};

export type SessionBootstrap = {
  operation: 'session_bootstrap';
  keyHandle: string;
  keyContext: SessionBootstrapKeyContext;
  lanePolicy: EvmFamilyEcdsaSessionLanePolicy;
  ecdsaThresholdKeyId?: never;
  key?: never;
  walletSessionUserId?: never;
  subjectId?: never;
  rpId?: never;
  chainTarget?: never;
  participantIds?: never;
  sessionKind?: never;
  sessionId?: never;
  signingGrantId?: never;
  runtimePolicyScope?: never;
  ttlMs?: never;
  remainingUses?: never;
};

export type EmailOtpDerivationBootstrapLifecycle =
  | EmailOtpRegistrationBootstrap
  | EmailOtpExistingKeyBootstrap
  | SessionBootstrap;

function requiredEmailOtpDerivationString(value: unknown, field: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) {
    throw new Error(`[email-otp-derivation] ${field} is required`);
  }
  return normalized;
}

function rejectProviderScopedWalletIdentity(value: string, field: string): void {
  if (/^[a-z][a-z0-9+.-]*:/i.test(value)) {
    throw new Error(`[email-otp-derivation] ${field} must be a wallet-scoped identity`);
  }
}

export function toWalletSessionUserId(value: unknown): WalletSessionUserId {
  const normalized = requiredEmailOtpDerivationString(value, 'walletSessionUserId');
  rejectProviderScopedWalletIdentity(normalized, 'walletSessionUserId');
  return normalized as WalletSessionUserId;
}

export function toEmailOtpAuthSubjectId(value: unknown): EmailOtpAuthSubjectId {
  return requiredEmailOtpDerivationString(value, 'authSubjectId') as EmailOtpAuthSubjectId;
}

export function toEcdsaDerivationThresholdKeyId(value: unknown): EcdsaThresholdKeyId {
  return parseSdkEcdsaDerivationThresholdKeyId(value);
}

export function toEcdsaDerivationSigningRootId(value: unknown): SigningRootId {
  return parseSdkEcdsaDerivationSigningRootId(value);
}

export function toEcdsaDerivationSigningRootVersion(value: unknown): SigningRootVersion {
  return parseSdkEcdsaDerivationSigningRootVersion(value);
}

export function toEcdsaDerivationThresholdSessionId(value: unknown): ThresholdEcdsaSessionId {
  return requiredEmailOtpDerivationString(value, 'thresholdSessionId') as ThresholdEcdsaSessionId;
}

export function toEcdsaDerivationSigningGrantId(value: unknown): SigningGrantId {
  const parsed = parseSigningGrantId(
    requiredEmailOtpDerivationString(value, 'signingGrantId'),
  );
  if (!parsed.ok) {
    throw new Error('[email-otp-derivation] signingGrantId is invalid');
  }
  return parsed.value;
}

export function toEcdsaDerivationThresholdOwnerAddress(value: unknown): ThresholdOwnerAddress {
  const normalized = requiredEmailOtpDerivationString(value, 'thresholdOwnerAddress').toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(normalized)) {
    throw new Error('[email-otp-derivation] thresholdOwnerAddress must be an EVM address');
  }
  return normalized as ThresholdOwnerAddress;
}
