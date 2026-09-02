import {
  buildActiveCombinedWalletAuthorityV1,
  isActiveEcdsaWalletAuthorityV1,
  isActiveRecoveredWalletAuthorityV1,
  type ActiveCombinedWalletAuthorityV1,
  type ActiveEcdsaWalletAuthorityV1,
  type ActiveEd25519WalletAuthorityV1,
  type ActiveRecoveredWalletAuthorityV1,
  type ActiveWalletAuthorityV1,
  type CombinedWalletSignerActivationSetV1,
  type EcdsaWalletSignerActivationSetV1,
  type Ed25519WalletSignerActivationSetV1,
  type WalletAuthorityProvenanceV1,
  type WalletSignerActivationSetV1,
} from './walletAuthority';
import type { WalletRecoveryOperationId } from '../utils/domainIds';

declare const activeAuthority: ActiveWalletAuthorityV1;
declare const activeEd25519Authority: ActiveEd25519WalletAuthorityV1;
declare const activeEcdsaAuthority: ActiveEcdsaWalletAuthorityV1;
declare const activeCombinedAuthority: ActiveCombinedWalletAuthorityV1;
declare const broadSignerActivations: WalletSignerActivationSetV1;
declare const ed25519Activations: Ed25519WalletSignerActivationSetV1;
declare const ecdsaActivations: EcdsaWalletSignerActivationSetV1;
declare const combinedActivations: CombinedWalletSignerActivationSetV1;
declare const recoveryOperationId: WalletRecoveryOperationId;

const recoveryProvenance: WalletAuthorityProvenanceV1 = {
  kind: 'wallet_recovery',
  recoveryOperationId,
  continuityAuthorityId: activeAuthority.authorityId,
};
void recoveryProvenance;

const invalidRecoveryProvenance: WalletAuthorityProvenanceV1 = {
  kind: 'wallet_recovery',
  recoveryOperationId,
  continuityAuthorityId: activeAuthority.authorityId,
  // @ts-expect-error Recovery provenance cannot carry device-link enrollment.
  enrollmentId: activeAuthority.authorityId,
};
void invalidRecoveryProvenance;

const combinedAuthority = buildActiveCombinedWalletAuthorityV1(activeCombinedAuthority);
void combinedAuthority;

if (isActiveEcdsaWalletAuthorityV1(activeAuthority)) {
  const ecdsaActivation = activeAuthority.signerActivations.ecdsa;
  void ecdsaActivation;
}

if (isActiveRecoveredWalletAuthorityV1(activeAuthority)) {
  const recoveredAuthority: ActiveRecoveredWalletAuthorityV1 = activeAuthority;
  const recoveryOperation = recoveredAuthority.provenance.recoveryOperationId;
  void recoveryOperation;
}

// @ts-expect-error A broad active authority does not prove recovery provenance.
const invalidRecoveredAuthority: ActiveRecoveredWalletAuthorityV1 = activeAuthority;
void invalidRecoveredAuthority;

const invalidCombinedWithoutEcdsa = buildActiveCombinedWalletAuthorityV1({
  ...activeCombinedAuthority,
  // @ts-expect-error A combined authority requires its ECDSA activation.
  signerActivations: ed25519Activations,
});
void invalidCombinedWithoutEcdsa;

const invalidCombinedWithoutEd25519: CombinedWalletSignerActivationSetV1 = {
  ...combinedActivations,
  // @ts-expect-error A combined activation set requires its Ed25519 activation.
  ed25519: undefined,
};
void invalidCombinedWithoutEd25519;

const invalidEd25519WithEcdsa: Ed25519WalletSignerActivationSetV1 = {
  ...ed25519Activations,
  // @ts-expect-error An Ed25519-only activation set cannot carry ECDSA.
  ecdsa: ecdsaActivations.ecdsa,
};
void invalidEd25519WithEcdsa;

// @ts-expect-error A broad active-authority spread cannot enter the combined builder.
const invalidBroadAuthoritySpread = buildActiveCombinedWalletAuthorityV1({
  ...activeAuthority,
});
void invalidBroadAuthoritySpread;

// @ts-expect-error A broad activation spread cannot enter the combined branch.
const invalidBroadActivationSpread: CombinedWalletSignerActivationSetV1 = {
  ...broadSignerActivations,
};
void invalidBroadActivationSpread;

// @ts-expect-error An ECDSA-only authority cannot enter the combined builder.
const invalidEcdsaAuthoritySpread = buildActiveCombinedWalletAuthorityV1({
  ...activeEcdsaAuthority,
});
void invalidEcdsaAuthoritySpread;

// @ts-expect-error An Ed25519-only authority cannot enter the combined builder.
const invalidEd25519AuthoritySpread = buildActiveCombinedWalletAuthorityV1({
  ...activeEd25519Authority,
});
void invalidEd25519AuthoritySpread;

export {};
