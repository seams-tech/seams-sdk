import type { ProvisionEmailOtpThresholdEd25519CapabilityArgs } from './provisioning';

const common = {
  nearAccountId: 'alice.testnet',
  relayUrl: 'https://relay.example',
  rpId: 'localhost',
  prfFirstB64u: 'prf-first-b64u',
  emailOtpAuthContext: {
    policy: 'session',
    retention: 'session',
    reason: 'login',
    authMethod: 'email_otp',
  },
} satisfies Omit<
  ProvisionEmailOtpThresholdEd25519CapabilityArgs,
  'kind' | 'walletSigningSessionId' | 'ecdsaThresholdSessionId'
>;

const validFreshProvisioning = {
  ...common,
  kind: 'fresh_ed25519_provisioning',
} satisfies ProvisionEmailOtpThresholdEd25519CapabilityArgs;

const validCompanionProvisioning = {
  ...common,
  kind: 'companion_to_ecdsa_provisioning',
  walletSigningSessionId: 'wallet-signing-session',
  ecdsaThresholdSessionId: 'ecdsa-threshold-session',
} satisfies ProvisionEmailOtpThresholdEd25519CapabilityArgs;

void validFreshProvisioning;
void validCompanionProvisioning;

// @ts-expect-error fresh provisioning cannot carry companion ECDSA identity
const invalidFreshWithCompanionIds: ProvisionEmailOtpThresholdEd25519CapabilityArgs = {
  ...common,
  kind: 'fresh_ed25519_provisioning',
  walletSigningSessionId: 'wallet-signing-session',
  ecdsaThresholdSessionId: 'ecdsa-threshold-session',
};

// @ts-expect-error companion provisioning requires wallet signing-session identity
const invalidCompanionWithoutWalletId: ProvisionEmailOtpThresholdEd25519CapabilityArgs = {
  ...common,
  kind: 'companion_to_ecdsa_provisioning',
  ecdsaThresholdSessionId: 'ecdsa-threshold-session',
};

// @ts-expect-error companion provisioning requires ECDSA threshold-session identity
const invalidCompanionWithoutThresholdSessionId: ProvisionEmailOtpThresholdEd25519CapabilityArgs =
  {
    ...common,
    kind: 'companion_to_ecdsa_provisioning',
    walletSigningSessionId: 'wallet-signing-session',
  };

void invalidFreshWithCompanionIds;
void invalidCompanionWithoutWalletId;
void invalidCompanionWithoutThresholdSessionId;
