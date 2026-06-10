import { toAccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaEmailOtpAuthContext } from '../identity/laneIdentity';
import { persistWarmSessionEd25519Capability } from './persistence';

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
  kind: 'cookie_passkey',
  ...commonArgs,
  sessionKind: 'cookie',
  source: 'manual-connect',
});

// @ts-expect-error Email OTP persistence requires Email OTP auth context.
void persistWarmSessionEd25519Capability({
  kind: 'jwt_email_otp',
  ...commonArgs,
  sessionKind: 'jwt',
  jwt: 'jwt-token',
  source: 'email_otp',
});

// @ts-expect-error Cookie persistence must not accept JWT auth material.
void persistWarmSessionEd25519Capability({
  kind: 'cookie_passkey',
  ...commonArgs,
  sessionKind: 'cookie',
  jwt: 'jwt-token',
  source: 'manual-connect',
});

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
