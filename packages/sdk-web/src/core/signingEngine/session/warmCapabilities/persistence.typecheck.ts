import { toAccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaEmailOtpAuthContext } from '../identity/laneIdentity';
import {
  persistWarmSessionEd25519Capability,
  type PersistWarmSessionEd25519CapabilityArgs,
} from './persistence';

const commonArgs = {
  nearAccountId: toAccountId('alice.testnet'),
  rpId: 'example.test',
  relayerUrl: 'https://relayer.test',
  relayerKeyId: 'relayer-key-1',
  participantIds: [1, 2],
  sessionId: 'threshold-session-1',
  walletSigningSessionId: 'wallet-session-1',
  expiresAtMs: 1_900_000_000_000,
  remainingUses: 2,
} as const;

const emailOtpAuthContext = {
  policy: 'session',
  retention: 'session',
  reason: 'sign',
  authMethod: 'email_otp',
} satisfies ThresholdEcdsaEmailOtpAuthContext;

void persistWarmSessionEd25519Capability({
  kind: 'jwt_email_otp',
  ...commonArgs,
  sessionKind: 'jwt',
  jwt: 'jwt-token',
  source: 'email_otp',
  emailOtpAuthContext,
});

void persistWarmSessionEd25519Capability({
  kind: 'jwt_passkey',
  ...commonArgs,
  sessionKind: 'jwt',
  jwt: 'jwt-token',
  source: 'login',
});

void persistWarmSessionEd25519Capability({
  kind: 'jwt_passkey',
  ...commonArgs,
  sessionKind: 'jwt',
  jwt: 'jwt-token',
  source: 'login',
  clientVerifyingShareB64u: 'public-client-verifying-share',
  ed25519HssMaterialHandle: 'ed25519-hss-material-handle',
  ed25519HssMaterialBindingDigest: 'ed25519-hss-material-binding',
});

void persistWarmSessionEd25519Capability({
  kind: 'jwt_passkey',
  ...commonArgs,
  sessionKind: 'jwt',
  jwt: 'jwt-token',
  source: 'login',
  // @ts-expect-error Warm-session persistence must not accept raw Ed25519 client-base material.
  xClientBaseB64u: 'raw-client-base',
});

// @ts-expect-error Email OTP persistence requires Email OTP auth context.
void persistWarmSessionEd25519Capability({
  kind: 'jwt_email_otp',
  ...commonArgs,
  sessionKind: 'jwt',
  jwt: 'jwt-token',
  source: 'email_otp',
});

const cookieBackedCapability = {
  kind: 'cookie_passkey',
  ...commonArgs,
  sessionKind: 'cookie',
  source: 'manual-connect',
};
// @ts-expect-error Cookie-backed signing capabilities are not valid Wallet Session V2 state.
void (cookieBackedCapability satisfies PersistWarmSessionEd25519CapabilityArgs);

// @ts-expect-error JWT passkey persistence must not accept Email OTP auth context.
void persistWarmSessionEd25519Capability({
  kind: 'jwt_passkey',
  ...commonArgs,
  sessionKind: 'jwt',
  jwt: 'jwt-token',
  source: 'login',
  emailOtpAuthContext,
});

export {};
