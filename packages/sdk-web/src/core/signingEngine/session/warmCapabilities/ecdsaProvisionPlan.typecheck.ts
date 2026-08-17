import type { EmailOtpWorkerIssuedSessionHandle } from '@/core/platform';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type {
  EvmFamilyEcdsaKeyIdentity,
} from '../identity/evmFamilyEcdsaIdentity';
import type { ThresholdEcdsaChainTarget } from '../../interfaces/ecdsaChainTarget';
import type { WalletSessionRouteAuth } from '@shared/utils/sessionTokens';
import type { ThresholdEcdsaEmailOtpAuthContext } from '../identity/laneIdentity';
import {
  buildEcdsaSessionIdentity,
  buildEcdsaSessionProvisionPlan,
  buildEmailOtpEcdsaProvisionSecretSource,
  buildPasskeyEcdsaProvisionSecretSource,
  type EcdsaSigningKeyContext,
  type PasskeyEcdsaProvisionSecretSource,
} from './ecdsaProvisionPlan';

declare const key: EvmFamilyEcdsaKeyIdentity;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const webauthnAuthentication: WebAuthnAuthenticationCredential;
declare const emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
declare const walletSessionRouteAuth: WalletSessionRouteAuth;
declare const emailOtpWorkerHandle: Extract<
  EmailOtpWorkerIssuedSessionHandle,
  { action: 'threshold_ecdsa_bootstrap' }
>;

const identity = buildEcdsaSessionIdentity({
  thresholdSessionId: 'threshold-session-1',
});
const signingKeyContext = {
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  participantIds: [1, 2],
} satisfies EcdsaSigningKeyContext;
const passkeySecret = buildPasskeyEcdsaProvisionSecretSource({
  passkeyPrfFirstB64u: 'prf-first',
  webauthnAuthentication,
});
const emailOtpSecret = buildEmailOtpEcdsaProvisionSecretSource({
  workerHandle: emailOtpWorkerHandle,
  emailOtpAuthContext,
});

void buildEcdsaSessionProvisionPlan({
  kind: 'passkey_ecdsa_session_provision',
  key,
  chainTarget,
  sessionIdentity: identity,
  signingKeyContext,
  sessionKind: 'opaque',
  sessionBudgetUses: 1,
  requestId: 'request-1',
  provisionSecretSource: passkeySecret,
  activationMaterial: { kind: 'session_record' },
  walletSessionRouteAuth,
});

void buildEcdsaSessionProvisionPlan({
  kind: 'email_otp_ecdsa_session_provision',
  key,
  chainTarget,
  sessionIdentity: identity,
  signingKeyContext,
  sessionKind: 'opaque',
  sessionBudgetUses: 1,
  provisionSecretSource: emailOtpSecret,
  walletSessionRouteAuth,
});

const invalidUnbrandedPasskeySecret: PasskeyEcdsaProvisionSecretSource = {
  kind: 'webauthn_prf_first_v1',
  // @ts-expect-error PRF.first must be normalized by the branch-specific builder.
  passkeyPrfFirstB64u: 'prf-first',
  webauthnAuthentication,
};
void invalidUnbrandedPasskeySecret;

void buildEcdsaSessionProvisionPlan({
  // @ts-expect-error Record-backed reconnect is a retired lifecycle branch.
  kind: 'ecdsa_session_reconnect',
  chainTarget,
  sessionIdentity: identity,
  sessionBudgetUses: 1,
});

export {};
