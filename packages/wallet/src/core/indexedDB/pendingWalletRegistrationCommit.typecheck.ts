import type {
  PendingWalletRegistrationCommitV1,
  PendingWalletRegistrationLocalMaterialV1,
} from './pendingWalletRegistrationCommit';

type NearLocalMaterial = Extract<
  PendingWalletRegistrationLocalMaterialV1,
  { readonly keyFamilies: readonly ['ed25519'] }
>;
type EcdsaLocalMaterial = Extract<
  PendingWalletRegistrationLocalMaterialV1,
  { readonly keyFamilies: readonly ['ecdsa_secp256k1'] }
>;

declare const nearLocalMaterial: NearLocalMaterial;
declare const ecdsaLocalMaterial: EcdsaLocalMaterial;
declare const nearCommit: Extract<
  PendingWalletRegistrationCommitV1,
  { readonly operation: 'near_provisioning' }
>;

const validNearCommit: Extract<
  PendingWalletRegistrationCommitV1,
  { readonly operation: 'near_provisioning' }
> = {
  ...nearCommit,
  localMaterial: nearLocalMaterial,
};
void validNearCommit;

const invalidNearCommit: Extract<
  PendingWalletRegistrationCommitV1,
  { readonly operation: 'near_provisioning' }
> = {
  ...nearCommit,
  // @ts-expect-error Deferred NEAR records cannot carry an ECDSA-only local branch.
  localMaterial: ecdsaLocalMaterial,
};
void invalidNearCommit;
