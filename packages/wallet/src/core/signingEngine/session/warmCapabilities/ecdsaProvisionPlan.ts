import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import type { WalletSessionRouteAuth } from '@shared/utils/sessionTokens';
import type { EmailOtpWorkerIssuedSessionHandle } from '@/core/platform';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaEmailOtpAuthContext } from '../identity/laneIdentity';
import type { EvmFamilyEcdsaKeyIdentity } from '../identity/evmFamilyEcdsaIdentity';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import {
  SigningSessionIds,
  type ThresholdEcdsaSessionId,
} from '../operationState/types';

export type EcdsaSessionIdentity = {
  thresholdSessionId: ThresholdEcdsaSessionId;
};

export type EcdsaSigningKeyContext = {
  ecdsaThresholdKeyId: string;
  participantIds: readonly number[];
};

export type PasskeyPrfFirstB64u = string & { readonly __brand: 'PasskeyPrfFirstB64u' };

export type PasskeyEcdsaProvisionSecretSource = {
  kind: 'webauthn_prf_first_v1';
  passkeyPrfFirstB64u: PasskeyPrfFirstB64u;
  webauthnAuthentication: WebAuthnAuthenticationCredential;
  emailOtpAuthContext?: never;
};

export type PasskeyEcdsaActivationMaterial = {
  kind: 'session_record';
  relayerUrl?: never;
  walletKey?: never;
};

export type EmailOtpEcdsaProvisionSecretSource = {
  kind: 'email_otp_worker_session_v1';
  workerHandle: Extract<EmailOtpWorkerIssuedSessionHandle, { action: 'threshold_ecdsa_bootstrap' }>;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  webauthnAuthentication?: never;
  passkeyPrfFirstB64u?: never;
};

export type PasskeyEcdsaSessionProvision = {
  kind: 'passkey_ecdsa_session_provision';
  key: EvmFamilyEcdsaKeyIdentity;
  chainTarget: ThresholdEcdsaChainTarget;
  newSessionIdentity: EcdsaSessionIdentity;
  signingKeyContext: EcdsaSigningKeyContext;
  sessionKind: 'opaque';
  sessionBudgetUses: number;
  requestId: string;

  // Branch-specific fields.
  provisionSecretSource: PasskeyEcdsaProvisionSecretSource;
  activationMaterial: PasskeyEcdsaActivationMaterial;
  walletSessionRouteAuth: WalletSessionRouteAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  emailOtpAuthContext?: never;
  passkeyPrfFirstB64u?: never;
  webauthnAuthentication?: never;
};

export type EmailOtpEcdsaSessionProvision = {
  kind: 'email_otp_ecdsa_session_provision';
  key: EvmFamilyEcdsaKeyIdentity;
  chainTarget: ThresholdEcdsaChainTarget;
  newSessionIdentity: EcdsaSessionIdentity;
  signingKeyContext: EcdsaSigningKeyContext;
  sessionKind: 'opaque';
  sessionBudgetUses: number;

  // Branch-specific fields.
  provisionSecretSource: EmailOtpEcdsaProvisionSecretSource;
  walletSessionRouteAuth: WalletSessionRouteAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  emailOtpAuthContext?: never;
  passkeyPrfFirstB64u?: never;
  webauthnAuthentication?: never;
};

export type EcdsaSessionProvisionPlan =
  | PasskeyEcdsaSessionProvision
  | EmailOtpEcdsaSessionProvision;

export type FreshEcdsaSessionProvisionPlan =
  | PasskeyEcdsaSessionProvision
  | EmailOtpEcdsaSessionProvision;

type BuildPasskeyEcdsaSessionProvisionPlanArgs = {
  kind: 'passkey_ecdsa_session_provision';
  key: EvmFamilyEcdsaKeyIdentity;
  chainTarget: ThresholdEcdsaChainTarget;
  sessionIdentity: EcdsaSessionIdentity;
  signingKeyContext: EcdsaSigningKeyContext;
  sessionKind: 'opaque';
  sessionBudgetUses: number;
  requestId: string;
  provisionSecretSource: PasskeyEcdsaProvisionSecretSource;
  activationMaterial: PasskeyEcdsaActivationMaterial;
  walletSessionRouteAuth: WalletSessionRouteAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  emailOtpAuthContext?: never;
  reconnectMaterial?: never;
  passkeyPrfFirstB64u?: never;
  webauthnAuthentication?: never;
};

type BuildEmailOtpEcdsaSessionProvisionPlanArgs = {
  kind: 'email_otp_ecdsa_session_provision';
  key: EvmFamilyEcdsaKeyIdentity;
  chainTarget: ThresholdEcdsaChainTarget;
  sessionIdentity: EcdsaSessionIdentity;
  signingKeyContext: EcdsaSigningKeyContext;
  sessionKind: 'opaque';
  sessionBudgetUses: number;
  provisionSecretSource: EmailOtpEcdsaProvisionSecretSource;
  walletSessionRouteAuth: WalletSessionRouteAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  emailOtpAuthContext?: never;
  passkeyPrfFirstB64u?: never;
  webauthnAuthentication?: never;
  reconnectMaterial?: never;
};

export type BuildEcdsaSessionProvisionPlanArgs =
  | BuildPasskeyEcdsaSessionProvisionPlanArgs
  | BuildEmailOtpEcdsaSessionProvisionPlanArgs;

function assertNeverEcdsaProvisionPlan(plan: never): never {
  throw new Error(`[SigningEngine][ecdsa] unsupported ECDSA provision plan: ${String(plan)}`);
}

function requireNonEmptyString(value: unknown, field: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) {
    throw new Error(`[SigningEngine][ecdsa] ${field} is required`);
  }
  return normalized;
}

function toPasskeyPrfFirstB64u(value: unknown): PasskeyPrfFirstB64u {
  return requireNonEmptyString(value, 'passkeyPrfFirstB64u') as PasskeyPrfFirstB64u;
}

function requirePositiveInteger(value: unknown, field: string): number {
  const normalized = Math.floor(Number(value) || 0);
  if (normalized <= 0) {
    throw new Error(`[SigningEngine][ecdsa] ${field} must be a positive integer`);
  }
  return normalized;
}

function requireParticipantIds(value: unknown, field: string): readonly number[] {
  const normalized = normalizeThresholdEd25519ParticipantIds(value);
  if (!normalized?.length) {
    throw new Error(`[SigningEngine][ecdsa] ${field} is required`);
  }
  return normalized;
}

export function buildPasskeyEcdsaProvisionSecretSource(args: {
  passkeyPrfFirstB64u: string;
  webauthnAuthentication: WebAuthnAuthenticationCredential;
}): PasskeyEcdsaProvisionSecretSource {
  return {
    kind: 'webauthn_prf_first_v1',
    passkeyPrfFirstB64u: toPasskeyPrfFirstB64u(args.passkeyPrfFirstB64u),
    webauthnAuthentication: args.webauthnAuthentication,
  };
}

export function buildEmailOtpEcdsaProvisionSecretSource(args: {
  workerHandle: Extract<EmailOtpWorkerIssuedSessionHandle, { action: 'threshold_ecdsa_bootstrap' }>;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
}): EmailOtpEcdsaProvisionSecretSource {
  return {
    kind: 'email_otp_worker_session_v1',
    workerHandle: args.workerHandle,
    emailOtpAuthContext: args.emailOtpAuthContext,
  };
}

export function buildEcdsaSessionIdentity(args: {
  thresholdSessionId: unknown;
}): EcdsaSessionIdentity {
  return {
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(args.thresholdSessionId),
  };
}

export function buildPasskeyEcdsaSessionProvision(args: {
  key: EvmFamilyEcdsaKeyIdentity;
  chainTarget: ThresholdEcdsaChainTarget;
  newSessionIdentity: EcdsaSessionIdentity;
  signingKeyContext: EcdsaSigningKeyContext;
  sessionKind: 'opaque';
  sessionBudgetUses: number;
  requestId: string;
  provisionSecretSource: PasskeyEcdsaProvisionSecretSource;
  activationMaterial: PasskeyEcdsaActivationMaterial;
  walletSessionRouteAuth: WalletSessionRouteAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
}): PasskeyEcdsaSessionProvision {
  return {
    kind: 'passkey_ecdsa_session_provision',
    key: args.key,
    chainTarget: args.chainTarget,
    newSessionIdentity: args.newSessionIdentity,
    signingKeyContext: args.signingKeyContext,
    sessionKind: args.sessionKind,
    sessionBudgetUses: requirePositiveInteger(args.sessionBudgetUses, 'sessionBudgetUses'),
    requestId: requireNonEmptyString(args.requestId, 'requestId'),

    // Branch-specific fields.
    provisionSecretSource: args.provisionSecretSource,
    activationMaterial: args.activationMaterial,
    walletSessionRouteAuth: args.walletSessionRouteAuth,
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
  } satisfies PasskeyEcdsaSessionProvision;
}

export function buildEmailOtpEcdsaSessionProvision(args: {
  key: EvmFamilyEcdsaKeyIdentity;
  chainTarget: ThresholdEcdsaChainTarget;
  newSessionIdentity: EcdsaSessionIdentity;
  signingKeyContext: EcdsaSigningKeyContext;
  sessionKind: 'opaque';
  sessionBudgetUses: number;
  provisionSecretSource: EmailOtpEcdsaProvisionSecretSource;
  walletSessionRouteAuth: WalletSessionRouteAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
}): EmailOtpEcdsaSessionProvision {
  return {
    kind: 'email_otp_ecdsa_session_provision',
    key: args.key,
    chainTarget: args.chainTarget,
    newSessionIdentity: args.newSessionIdentity,
    signingKeyContext: args.signingKeyContext,
    sessionKind: 'opaque',
    sessionBudgetUses: requirePositiveInteger(args.sessionBudgetUses, 'sessionBudgetUses'),

    // Branch-specific fields.
    provisionSecretSource: args.provisionSecretSource,
    walletSessionRouteAuth: args.walletSessionRouteAuth,
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
  } satisfies EmailOtpEcdsaSessionProvision;
}

export function buildEcdsaSessionProvisionPlan(
  args: BuildEcdsaSessionProvisionPlanArgs,
): EcdsaSessionProvisionPlan {
  switch (args.kind) {
    case 'email_otp_ecdsa_session_provision':
      return buildEmailOtpEcdsaSessionProvision({
        key: args.key,
        chainTarget: args.chainTarget,
        newSessionIdentity: args.sessionIdentity,
        signingKeyContext: args.signingKeyContext,
        sessionKind: args.sessionKind,
        sessionBudgetUses: args.sessionBudgetUses,
        provisionSecretSource: args.provisionSecretSource,
        walletSessionRouteAuth: args.walletSessionRouteAuth,
        ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
      });
    case 'passkey_ecdsa_session_provision':
      return buildPasskeyEcdsaSessionProvision({
        key: args.key,
        chainTarget: args.chainTarget,
        newSessionIdentity: args.sessionIdentity,
        signingKeyContext: args.signingKeyContext,
        sessionKind: args.sessionKind,
        sessionBudgetUses: args.sessionBudgetUses,
        requestId: args.requestId,
        provisionSecretSource: args.provisionSecretSource,
        activationMaterial: args.activationMaterial,
        walletSessionRouteAuth: args.walletSessionRouteAuth,
        ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
      });
  }
  args satisfies never;
  throw new Error('[SigningEngine][ecdsa] unsupported ECDSA provision plan kind');
}
