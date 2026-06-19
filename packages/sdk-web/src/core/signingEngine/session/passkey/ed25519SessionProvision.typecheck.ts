import type {
  ExactWarmEd25519CapabilityProvisionArgs,
  FreshWarmEd25519CapabilityProvisionArgs,
} from '../warmCapabilities/types';

declare const freshProvision: FreshWarmEd25519CapabilityProvisionArgs;
declare const exactProvision: ExactWarmEd25519CapabilityProvisionArgs;

const _freshProvisionOk: FreshWarmEd25519CapabilityProvisionArgs = freshProvision;
const _exactProvisionOk: ExactWarmEd25519CapabilityProvisionArgs = exactProvision;

const _freshProvisionWithSessionId: FreshWarmEd25519CapabilityProvisionArgs = {
  kind: 'fresh_ed25519_provisioning',
  nearAccountId: 'alice.testnet',
  relayerKeyId: 'rk-ed25519',
  // @ts-expect-error fresh Ed25519 provisioning cannot carry exact session identity
  sessionId: 'threshold-ed25519-session',
};

const _freshProvisionWithSigningGrantId: FreshWarmEd25519CapabilityProvisionArgs = {
  kind: 'fresh_ed25519_provisioning',
  nearAccountId: 'alice.testnet',
  relayerKeyId: 'rk-ed25519',
  // @ts-expect-error fresh Ed25519 provisioning cannot carry wallet signing-session identity
  signingGrantId: 'signing-grant',
};

// @ts-expect-error exact Ed25519 provisioning requires sessionId
const _exactProvisionMissingSessionId: ExactWarmEd25519CapabilityProvisionArgs = {
  kind: 'exact_ed25519_provisioning',
  nearAccountId: 'alice.testnet',
  relayerKeyId: 'rk-ed25519',
  signingGrantId: 'signing-grant',
};

// @ts-expect-error exact Ed25519 provisioning requires signingGrantId
const _exactProvisionMissingSigningGrantId: ExactWarmEd25519CapabilityProvisionArgs = {
  kind: 'exact_ed25519_provisioning',
  nearAccountId: 'alice.testnet',
  relayerKeyId: 'rk-ed25519',
  sessionId: 'threshold-ed25519-session',
};
