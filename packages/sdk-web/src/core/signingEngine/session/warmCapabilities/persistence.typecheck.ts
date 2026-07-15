import { toAccountId } from '@/core/types/accountIds';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '../identity/laneIdentity';
import type { RouterAbEd25519NormalSigningState } from '../../threshold/ed25519/routerAbNormalSigningState';
import {
  persistWarmSessionEd25519Capability,
  type PersistWarmSessionEd25519CapabilityArgs,
} from './persistence';

const routerAbNormalSigning = {
  kind: 'router_ab_ed25519_normal_signing_v1',
  signingWorkerId: 'signing-worker-a',
} satisfies RouterAbEd25519NormalSigningState;

const commonArgs = {
  walletId: 'wallet.testnet',
  nearAccountId: toAccountId('alice.testnet'),
  nearEd25519SigningKeyId: 'near-key-1',
  rpId: 'example.test',
  relayerUrl: 'https://relayer.test',
  relayerKeyId: 'relayer-key-1',
  runtimePolicyScope: {
    orgId: 'org-1',
    projectId: 'project-1',
    envId: 'env-1',
    signingRootVersion: 'root-v1',
  },
  participantIds: [1, 2],
  sessionId: 'threshold-session-1',
  signingGrantId: 'signing-grant-1',
  expiresAtMs: 1_900_000_000_000,
  remainingUses: 2,
  signerSlot: 1,
  routerAbNormalSigning,
  jwt: 'wallet-session-jwt',
} as const;

const emailOtpAuthContext = buildEmailOtpAuthContextForWalletAuthMethod({
  walletId: 'wallet.testnet',
  emailHashHex: 'email-hash',
  policy: 'session',
  retention: 'session',
  reason: 'sign',
  provider: 'google',
  providerUserId: 'google-subject-1',
});

void persistWarmSessionEd25519Capability({
  kind: 'jwt_passkey',
  ...commonArgs,
  passkeyCredentialIdB64u: 'credential-id',
  source: 'login',
});

void persistWarmSessionEd25519Capability({
  kind: 'jwt_email_otp',
  ...commonArgs,
  emailOtpAuthContext,
  source: 'email_otp',
});

const missingRuntimePolicyScope: PersistWarmSessionEd25519CapabilityArgs = {
  kind: 'jwt_passkey',
  walletId: commonArgs.walletId,
  nearAccountId: commonArgs.nearAccountId,
  nearEd25519SigningKeyId: commonArgs.nearEd25519SigningKeyId,
  rpId: commonArgs.rpId,
  relayerUrl: commonArgs.relayerUrl,
  relayerKeyId: commonArgs.relayerKeyId,
  participantIds: commonArgs.participantIds,
  sessionId: commonArgs.sessionId,
  signingGrantId: commonArgs.signingGrantId,
  expiresAtMs: commonArgs.expiresAtMs,
  remainingUses: commonArgs.remainingUses,
  signerSlot: commonArgs.signerSlot,
  routerAbNormalSigning,
  jwt: commonArgs.jwt,
  passkeyCredentialIdB64u: 'credential-id',
  source: 'login',
  // @ts-expect-error public Ed25519 session persistence requires an exact runtime scope.
  runtimePolicyScope: undefined,
};
void missingRuntimePolicyScope;

// @ts-expect-error passkey persistence requires the exact credential binding.
const missingPasskeyCredential: PersistWarmSessionEd25519CapabilityArgs = {
  kind: 'jwt_passkey',
  ...commonArgs,
  source: 'login',
};
void missingPasskeyCredential;

// @ts-expect-error Email OTP persistence requires its auth context.
const missingEmailOtpContext: PersistWarmSessionEd25519CapabilityArgs = {
  kind: 'jwt_email_otp',
  ...commonArgs,
  source: 'email_otp',
};
void missingEmailOtpContext;

// @ts-expect-error passkey persistence rejects Email OTP authority.
const passkeyWithEmailOtpContext: PersistWarmSessionEd25519CapabilityArgs = {
  kind: 'jwt_passkey',
  ...commonArgs,
  passkeyCredentialIdB64u: 'credential-id',
  source: 'login',
  emailOtpAuthContext,
};
void passkeyWithEmailOtpContext;

const obsoleteCookieCapability = {
  kind: 'cookie_passkey',
  ...commonArgs,
  passkeyCredentialIdB64u: 'credential-id',
  source: 'login',
};
// @ts-expect-error cookie sessions are not signing capabilities.
void (obsoleteCookieCapability satisfies PersistWarmSessionEd25519CapabilityArgs);

export {};
