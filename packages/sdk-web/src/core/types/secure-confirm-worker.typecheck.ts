import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WarmSessionSealTransportInput } from './secure-confirm-worker';
import { parseSigningSessionSealKeyVersion } from '@/core/signingEngine/session/keyMaterialBrands';

declare const chainTarget: ThresholdEcdsaChainTarget;
const signingSessionSealKeyVersion = parseSigningSessionSealKeyVersion(
  'signing-session-seal-kek-test-r1',
);

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

// @ts-expect-error Email OTP seal transports require explicit wallet-session authority.
const invalidWarmSessionSealTransportEmailOtpWithoutWalletSessionJwt: WarmSessionSealTransportInput = {
  curve: 'ed25519',
  authMethod: 'email_otp',
  relayerUrl: 'https://relay.example',
};
void invalidWarmSessionSealTransportEmailOtpWithoutWalletSessionJwt;

// @ts-expect-error Email OTP ECDSA seal transports require explicit wallet-session authority.
const invalidWarmSessionSealTransportEmailOtpEcdsaWithoutWalletSessionJwt: WarmSessionSealTransportInput = {
  curve: 'ecdsa',
  authMethod: 'email_otp',
  chainTarget,
  relayerUrl: 'https://relay.example',
};
void invalidWarmSessionSealTransportEmailOtpEcdsaWithoutWalletSessionJwt;

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

const validWarmSessionSealTransportWithBrandedSealVersion = {
  curve: 'ed25519',
  relayerUrl: 'https://relay.example',
  signingSessionSealKeyVersion,
} satisfies WarmSessionSealTransportInput;
void validWarmSessionSealTransportWithBrandedSealVersion;

const invalidWarmSessionSealTransportWithRawSealVersion = {
  curve: 'ed25519',
  relayerUrl: 'https://relay.example',
  // @ts-expect-error warm-session worker transports require branded seal key versions.
  signingSessionSealKeyVersion: 'signing-session-seal-kek-test-r1',
} satisfies WarmSessionSealTransportInput;
void invalidWarmSessionSealTransportWithRawSealVersion;

const invalidWarmSessionSealTransportWithGenericKeyVersion = {
  curve: 'ed25519',
  relayerUrl: 'https://relay.example',
  // @ts-expect-error warm-session worker transports use signingSessionSealKeyVersion.
  keyVersion: 'signing-session-seal-kek-test-r1',
} satisfies WarmSessionSealTransportInput;
void invalidWarmSessionSealTransportWithGenericKeyVersion;
