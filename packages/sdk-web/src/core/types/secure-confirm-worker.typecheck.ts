import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WarmSessionSealTransportInput } from './secure-confirm-worker';

declare const chainTarget: ThresholdEcdsaChainTarget;

const validWarmSessionSealTransportWithWalletSessionJwt = {
  curve: 'ecdsa',
  chainTarget,
  relayerUrl: 'https://relay.example',
  walletSessionJwt: 'wallet-session-jwt',
} satisfies WarmSessionSealTransportInput;
void validWarmSessionSealTransportWithWalletSessionJwt;

const validWarmSessionSealTransportWithEmailOtpAuthMethod = {
  curve: 'ed25519',
  authMethod: 'email_otp',
  relayerUrl: 'https://relay.example',
  walletSessionJwt: 'wallet-session-jwt',
} satisfies WarmSessionSealTransportInput;
void validWarmSessionSealTransportWithEmailOtpAuthMethod;

const invalidWarmSessionSealTransportWithEmailOtpRestore = {
  curve: 'ed25519',
  authMethod: 'email_otp',
  relayerUrl: 'https://relay.example',
  walletSessionJwt: 'wallet-session-jwt',
  // @ts-expect-error Email OTP Ed25519 seal transports keep raw restore metadata out of TS.
  emailOtpRestore: {
    xClientBaseB64u: 'x-client-base',
    clientVerifyingShareB64u: 'client-verifying-share',
  },
} satisfies WarmSessionSealTransportInput;
void invalidWarmSessionSealTransportWithEmailOtpRestore;

const invalidWarmSessionSealTransportWithUnknownAuthMethod = {
  curve: 'ed25519',
  // @ts-expect-error warm-session seal auth methods are explicit domain values.
  authMethod: 'cookie',
  relayerUrl: 'https://relay.example',
} satisfies WarmSessionSealTransportInput;
void invalidWarmSessionSealTransportWithUnknownAuthMethod;

const invalidWarmSessionSealTransportWithOldTokenField = {
  curve: 'ed25519',
  relayerUrl: 'https://relay.example',
  // @ts-expect-error warm-session worker transports use walletSessionJwt.
  thresholdSessionAuthToken: 'wallet-session-jwt',
} satisfies WarmSessionSealTransportInput;
void invalidWarmSessionSealTransportWithOldTokenField;
