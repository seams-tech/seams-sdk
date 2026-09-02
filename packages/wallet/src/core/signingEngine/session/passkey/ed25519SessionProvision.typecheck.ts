import type {
  ExactWarmEd25519CapabilityProvisionArgs,
  FreshWarmEd25519CapabilityProvisionArgs,
} from '../warmCapabilities/types';
import type { ExactEd25519SigningLaneIdentity } from '../identity/exactSigningLaneIdentity';

declare const freshProvision: FreshWarmEd25519CapabilityProvisionArgs;
declare const exactProvision: ExactWarmEd25519CapabilityProvisionArgs;
declare const exactLaneIdentity: ExactEd25519SigningLaneIdentity;
declare const freshProvisionFields: Omit<
  FreshWarmEd25519CapabilityProvisionArgs,
  'kind' | 'sessionId' | 'laneIdentity'
>;
declare const exactProvisionFields: Omit<
  ExactWarmEd25519CapabilityProvisionArgs,
  | 'kind'
  | 'laneIdentity'
  | 'walletId'
  | 'nearAccountId'
  | 'nearEd25519SigningKeyId'
  | 'signerSlot'
  | 'sessionId'
>;
declare const exactProvisionWithoutCredentialFields: Omit<
  ExactWarmEd25519CapabilityProvisionArgs,
  | 'kind'
  | 'laneIdentity'
  | 'operationCredential'
  | 'walletId'
  | 'nearAccountId'
  | 'nearEd25519SigningKeyId'
  | 'signerSlot'
  | 'sessionId'
>;

const _freshProvisionOk: FreshWarmEd25519CapabilityProvisionArgs = freshProvision;
const _exactProvisionOk: ExactWarmEd25519CapabilityProvisionArgs = exactProvision;

const _freshProvisionWithSessionId: FreshWarmEd25519CapabilityProvisionArgs = {
  kind: 'fresh_ed25519_provisioning',
  ...freshProvisionFields,
  // @ts-expect-error fresh Ed25519 provisioning cannot carry exact session identity
  sessionId: 'threshold-ed25519-session',
};

// @ts-expect-error exact Ed25519 provisioning requires laneIdentity
const _exactProvisionMissingLaneIdentity: ExactWarmEd25519CapabilityProvisionArgs = {
  kind: 'exact_ed25519_provisioning',
  ...exactProvisionFields,
};

// @ts-expect-error exact Ed25519 provisioning requires the complete operation credential
const _exactProvisionMissingCredential: ExactWarmEd25519CapabilityProvisionArgs = {
  kind: 'exact_ed25519_provisioning',
  laneIdentity: exactLaneIdentity,
  ...exactProvisionWithoutCredentialFields,
};

const _exactProvisionWithDetachedToken: ExactWarmEd25519CapabilityProvisionArgs = {
  kind: 'exact_ed25519_provisioning',
  laneIdentity: exactLaneIdentity,
  ...exactProvisionFields,
  // @ts-expect-error exact Ed25519 provisioning cannot carry a detached token
  existingWalletSessionToken: 'wst_detached',
};

const _exactProvisionWithSessionId: ExactWarmEd25519CapabilityProvisionArgs = {
  kind: 'exact_ed25519_provisioning',
  laneIdentity: exactLaneIdentity,
  ...exactProvisionFields,
  // @ts-expect-error exact Ed25519 provisioning derives sessionId from laneIdentity
  sessionId: 'threshold-ed25519-session',
};

const _exactProvisionWithWalletId: ExactWarmEd25519CapabilityProvisionArgs = {
  kind: 'exact_ed25519_provisioning',
  laneIdentity: exactLaneIdentity,
  ...exactProvisionFields,
  // @ts-expect-error exact Ed25519 provisioning derives wallet fields from laneIdentity
  walletId: 'frost-vermillion-k7p9m2',
};
