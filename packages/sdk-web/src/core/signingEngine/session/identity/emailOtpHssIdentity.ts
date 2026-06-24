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
  parseSdkEcdsaHssSigningRootId,
  parseSdkEcdsaHssSigningRootVersion,
  parseSdkEcdsaHssThresholdKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';

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

export type EmailOtpHssBootstrapLifecycle =
  | EmailOtpRegistrationBootstrap
  | EmailOtpExistingKeyBootstrap
  | SessionBootstrap;

function requiredEmailOtpHssString(value: unknown, field: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) {
    throw new Error(`[email-otp-hss] ${field} is required`);
  }
  return normalized;
}

function rejectProviderScopedWalletIdentity(value: string, field: string): void {
  if (/^[a-z][a-z0-9+.-]*:/i.test(value)) {
    throw new Error(`[email-otp-hss] ${field} must be a wallet-scoped identity`);
  }
}

export function toWalletSessionUserId(value: unknown): WalletSessionUserId {
  const normalized = requiredEmailOtpHssString(value, 'walletSessionUserId');
  rejectProviderScopedWalletIdentity(normalized, 'walletSessionUserId');
  return normalized as WalletSessionUserId;
}

export function toEmailOtpAuthSubjectId(value: unknown): EmailOtpAuthSubjectId {
  return requiredEmailOtpHssString(value, 'authSubjectId') as EmailOtpAuthSubjectId;
}

export function toEcdsaHssThresholdKeyId(value: unknown): EcdsaThresholdKeyId {
  return parseSdkEcdsaHssThresholdKeyId(value);
}

export function toEcdsaHssSigningRootId(value: unknown): SigningRootId {
  return parseSdkEcdsaHssSigningRootId(value);
}

export function toEcdsaHssSigningRootVersion(value: unknown): SigningRootVersion {
  return parseSdkEcdsaHssSigningRootVersion(value);
}

export function toEcdsaHssThresholdSessionId(value: unknown): ThresholdEcdsaSessionId {
  return requiredEmailOtpHssString(value, 'thresholdSessionId') as ThresholdEcdsaSessionId;
}

export function toEcdsaHssSigningGrantId(value: unknown): SigningGrantId {
  return requiredEmailOtpHssString(value, 'signingGrantId') as SigningGrantId;
}

export function toEcdsaHssThresholdOwnerAddress(value: unknown): ThresholdOwnerAddress {
  const normalized = requiredEmailOtpHssString(value, 'thresholdOwnerAddress').toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(normalized)) {
    throw new Error('[email-otp-hss] thresholdOwnerAddress must be an EVM address');
  }
  return normalized as ThresholdOwnerAddress;
}
