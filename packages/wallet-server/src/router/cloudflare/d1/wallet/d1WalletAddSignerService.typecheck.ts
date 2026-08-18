import type { D1WalletAddSignerFinalizePreparedV1 } from './d1WalletAddSignerService';
import type { WalletAddSignerEcdsaActivationRequest } from '../../../../core/registrationContracts';

declare const activationCommit: WalletAddSignerEcdsaActivationRequest;

const activationCommitWithoutCanonicalDigest = {
  addSignerCeremonyId: activationCommit.addSignerCeremonyId,
  // @ts-expect-error Add-signer activation commit requires the canonical command digest.
  ecdsa: {
    kind: activationCommit.ecdsa.kind,
    activationCorrelationId: activationCommit.ecdsa.activationCorrelationId,
    publicFacts: activationCommit.ecdsa.publicFacts,
  },
} satisfies WalletAddSignerEcdsaActivationRequest;

const activationCommitWithBrowserOwnedMaterial = {
  ...activationCommit,
  ecdsa: {
    ...activationCommit.ecdsa,
    // @ts-expect-error The public activation request cannot choose Router-owned material identity.
    materialActivation: {},
  },
} satisfies WalletAddSignerEcdsaActivationRequest;

const validEd25519FinalizePrepared = {
  kind: 'd1_wallet_add_signer_finalize_ed25519_prepared_v1',
  finalizingAtMs: 1,
} satisfies D1WalletAddSignerFinalizePreparedV1;

const validEcdsaFinalizePrepared = {
  kind: 'd1_wallet_add_signer_finalize_ecdsa_prepared_v1',
  signerWriteAtMs: 1,
} satisfies D1WalletAddSignerFinalizePreparedV1;

const ecdsaFinalizeWithSessionTerms = {
  kind: 'd1_wallet_add_signer_finalize_ecdsa_prepared_v1',
  signerWriteAtMs: 1,
} satisfies D1WalletAddSignerFinalizePreparedV1;

const ed25519FinalizeWithSessionTerms = {
  kind: 'd1_wallet_add_signer_finalize_ed25519_prepared_v1',
  finalizingAtMs: 1,
} satisfies D1WalletAddSignerFinalizePreparedV1;

void validEd25519FinalizePrepared;
void validEcdsaFinalizePrepared;
void ecdsaFinalizeWithSessionTerms;
void ed25519FinalizeWithSessionTerms;
void activationCommitWithoutCanonicalDigest;
void activationCommitWithBrowserOwnedMaterial;
