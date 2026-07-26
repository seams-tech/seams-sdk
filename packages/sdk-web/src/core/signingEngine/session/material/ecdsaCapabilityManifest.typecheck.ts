import type {
  CapabilityInstanceRef,
  MpcMaterialActivationId,
  MpcMaterialOwnerRef,
  WalletAuthorityBindingDigest,
  WalletId,
} from '@shared/utils/domainIds';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type {
  SigningRootId,
  SigningRootVersion,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import type { RouterAbEcdsaRegistrationActivationReceiptV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { CorrelationId, DigestB64u, IsoTimestamp } from '@shared/utils/canonicalPrimitives';
import type {
  CanonicalEcdsaServerActivationRequest,
  EcdsaCapabilityManifestId,
  EcdsaCapabilityManifestRevision,
  EcdsaCiphertextB64u,
  EcdsaCiphertextDigest,
  EcdsaIv12B64u,
  EcdsaMaterialSealingKeyId,
  EcdsaPendingCiphertextDigest,
  EcdsaServerGeneration,
  EvmFamilyEcdsaSignerId,
} from '@shared/utils/ecdsaCapabilityActivation';
import type { ThresholdEcdsaChainTarget } from '@/core/platform/types';
import type { ParticipantId, VerifiedEcdsaPublicFacts } from '../identity/evmFamilyEcdsaIdentity';
import type {
  EcdsaClientVerifyingPublicKey33B64u,
  EcdsaKeyHandle,
  EcdsaRelayerKeyId,
  EcdsaRoleLocalBindingDigest,
  EcdsaRoleLocalDurableMaterialRef,
  EcdsaThresholdKeyId,
} from '../keyMaterialBrands';
import {
  buildActiveEcdsaCapabilityManifest,
  buildEcdsaCapabilityScope,
  buildEcdsaManifestIdentity,
  buildEcdsaRoleLocalMaterialBinding,
  buildEncryptedEcdsaPendingCandidate,
  buildExactEcdsaManifestExpectation,
  buildExactEcdsaServerGenerationExpectation,
  buildNoCurrentEcdsaManifestExpectation,
  buildNoCurrentEcdsaServerGenerationExpectation,
  buildPreparedEcdsaActivationCandidate,
  buildPreparedEcdsaActivationJournal,
  buildPreparedEvmFamilySigner,
  buildReplacedEcdsaCapabilityManifest,
  buildServerCommittedEcdsaActivationJournal,
  buildValidatedEncryptedEcdsaReadyMaterial,
  type ActiveEcdsaCapabilityManifest,
  type PreparedEcdsaActivationJournal,
  type ValidatedEncryptedEcdsaReadyMaterial,
} from './ecdsaCapabilityManifest';

declare const capability: CapabilityInstanceRef;
declare const materialOwner: MpcMaterialOwnerRef;
declare const activationId: MpcMaterialActivationId;
declare const walletId: WalletId;
declare const authorityDigest: WalletAuthorityBindingDigest;
declare const signerId: EvmFamilyEcdsaSignerId;
declare const signingRootId: SigningRootId;
declare const signingRootVersion: SigningRootVersion;
declare const keyHandle: EcdsaKeyHandle;
declare const ecdsaThresholdKeyId: EcdsaThresholdKeyId;
declare const clientVerifyingPublicKey33B64u: EcdsaClientVerifyingPublicKey33B64u;
declare const participantId: ParticipantId;
declare const relayerKeyId: EcdsaRelayerKeyId;
declare const bindingDigest: EcdsaRoleLocalBindingDigest;
declare const durableMaterialRef: EcdsaRoleLocalDurableMaterialRef;
declare const manifestId: EcdsaCapabilityManifestId;
declare const manifestRevision: EcdsaCapabilityManifestRevision;
declare const replacementManifestId: EcdsaCapabilityManifestId;
declare const replacementManifestRevision: EcdsaCapabilityManifestRevision;
declare const sealingKeyId: EcdsaMaterialSealingKeyId;
declare const iv12B64u: EcdsaIv12B64u;
declare const ciphertextB64u: EcdsaCiphertextB64u;
declare const pendingCiphertextDigest: EcdsaPendingCiphertextDigest;
declare const ciphertextDigest: EcdsaCiphertextDigest;
declare const journalId: CorrelationId;
declare const requestDigest: DigestB64u;
declare const canonicalRequest: CanonicalEcdsaServerActivationRequest;
declare const createdAt: IsoTimestamp;
declare const committedAt: IsoTimestamp;
declare const serverGeneration: EcdsaServerGeneration;
declare const protocolReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
declare const registeredPublicFacts: VerifiedEcdsaPublicFacts;
declare const replacementActiveManifest: ActiveEcdsaCapabilityManifest;

const authority: WalletAuthAuthorityRef = {
  kind: 'wallet_auth_authority_ref',
  walletId,
  authorityDigest,
};

const chainTarget: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 1,
  networkSlug: 'ethereum',
};

const scope = buildEcdsaCapabilityScope({
  targetMemberships: [chainTarget],
});

const roleLocalBinding = buildEcdsaRoleLocalMaterialBinding({
  keyHandle,
  ecdsaThresholdKeyId,
  clientVerifyingPublicKey33B64u,
  participantIds: [participantId],
  relayerKeyId,
});

const preparedSigner = buildPreparedEvmFamilySigner({
  capability,
  signerId,
  authority,
  scope,
  materialOwner,
  signingRootId,
  signingRootVersion,
});

const encryptedPending = buildEncryptedEcdsaPendingCandidate({
  sealingKeyId,
  iv12B64u,
  ciphertextB64u,
  ciphertextDigest: pendingCiphertextDigest,
});

const targetManifest = buildEcdsaManifestIdentity({
  manifestId,
  manifestRevision,
});

const candidate = buildPreparedEcdsaActivationCandidate({
  targetManifest,
  signer: preparedSigner,
  activationId,
  roleLocalBinding,
  bindingDigest,
  durableMaterialRef,
  encryptedPending,
});

const noCurrentManifest = buildNoCurrentEcdsaManifestExpectation();
const noCurrentGeneration = buildNoCurrentEcdsaServerGenerationExpectation();

const preparedJournal = buildPreparedEcdsaActivationJournal({
  journalId,
  candidate,
  expectedManifest: noCurrentManifest,
  expectedGeneration: noCurrentGeneration,
  requestDigest,
  canonicalRequest,
  createdAt,
});

const committedJournal = buildServerCommittedEcdsaActivationJournal({
  preparedJournal,
  serverCommit: {
    correlationId: journalId,
    activationRequestDigest: requestDigest,
    serverGeneration,
    protocolReceipt,
  },
});

const readyMaterial = buildValidatedEncryptedEcdsaReadyMaterial({
  committedJournal,
  sealingKeyId,
  iv12B64u,
  ciphertextB64u,
  ciphertextDigest,
});

const activeManifest = buildActiveEcdsaCapabilityManifest({
  committedJournal,
  registeredPublicFacts,
  readyMaterial,
  committedAt,
});

buildReplacedEcdsaCapabilityManifest({
  activeManifest,
  replacementManifest: replacementActiveManifest,
});

const exactManifest = buildExactEcdsaManifestExpectation(
  buildEcdsaManifestIdentity({
    manifestId,
    manifestRevision,
  }),
);
const exactGeneration = buildExactEcdsaServerGenerationExpectation(serverGeneration);
const replacementTarget = buildEcdsaManifestIdentity({
  manifestId: replacementManifestId,
  manifestRevision: replacementManifestRevision,
});

buildPreparedEcdsaActivationJournal({
  journalId,
  candidate: buildPreparedEcdsaActivationCandidate({
    targetManifest: replacementTarget,
    signer: preparedSigner,
    activationId,
    roleLocalBinding,
    bindingDigest,
    durableMaterialRef,
    encryptedPending,
  }),
  expectedManifest: exactManifest,
  expectedGeneration: exactGeneration,
  requestDigest,
  canonicalRequest,
  createdAt,
});

// @ts-expect-error Manifest identities require a revision.
buildEcdsaManifestIdentity({ manifestId });

// @ts-expect-error ECDSA capability scope has no exact-target branch.
buildEcdsaCapabilityScope({ exactTarget: chainTarget });

// @ts-expect-error Prepared signers require exact wallet authority.
buildPreparedEvmFamilySigner({
  capability,
  signerId,
  scope,
  materialOwner,
  signingRootId,
  signingRootVersion,
});

buildPreparedEvmFamilySigner({
  capability,
  signerId,
  authority,
  scope,
  materialOwner,
  signingRootId,
  signingRootVersion,
  // @ts-expect-error Wallet identity is derived from authority.
  walletId,
});

buildEcdsaRoleLocalMaterialBinding({
  keyHandle,
  ecdsaThresholdKeyId,
  clientVerifyingPublicKey33B64u,
  participantIds: [participantId],
  relayerKeyId,
  // @ts-expect-error Role-local material cannot carry Wallet Session expiry.
  expiresAtMs: 1,
});

// @ts-expect-error Pending candidates require encrypted ciphertext.
buildEncryptedEcdsaPendingCandidate({
  sealingKeyId,
  iv12B64u,
  ciphertextDigest: pendingCiphertextDigest,
});

// @ts-expect-error Activation candidates require a durable material reference.
buildPreparedEcdsaActivationCandidate({
  targetManifest,
  signer: preparedSigner,
  activationId,
  roleLocalBinding,
  bindingDigest,
  encryptedPending,
});

// @ts-expect-error Activation candidates require an exact role-local binding digest.
buildPreparedEcdsaActivationCandidate({
  targetManifest,
  signer: preparedSigner,
  activationId,
  roleLocalBinding,
  durableMaterialRef,
  encryptedPending,
});

// @ts-expect-error Initial local state must pair with no-current server state.
buildPreparedEcdsaActivationJournal({
  journalId,
  candidate,
  expectedManifest: noCurrentManifest,
  expectedGeneration: exactGeneration,
  requestDigest,
  canonicalRequest,
  createdAt,
});

buildPreparedEcdsaActivationJournal({
  journalId,
  candidate,
  expectedManifest: noCurrentManifest,
  expectedGeneration: noCurrentGeneration,
  requestDigest,
  canonicalRequest,
  createdAt,
  // @ts-expect-error Prepared journals cannot carry a server commit.
  serverActivation: committedJournal.serverActivation,
});

buildServerCommittedEcdsaActivationJournal({
  preparedJournal,
  // @ts-expect-error Server-committed journals require server generation.
  serverCommit: {
    correlationId: journalId,
    activationRequestDigest: requestDigest,
    protocolReceipt,
  },
});

// @ts-expect-error Active manifests require validated encrypted ready material.
buildActiveEcdsaCapabilityManifest({
  committedJournal,
  registeredPublicFacts,
  committedAt,
});

const rawReadyMaterial = {
  ...readyMaterial,
};

// @ts-expect-error Spreading validated material loses its opaque validation proof.
const invalidReadyMaterial: ValidatedEncryptedEcdsaReadyMaterial = rawReadyMaterial;

buildActiveEcdsaCapabilityManifest({
  committedJournal,
  registeredPublicFacts,
  // @ts-expect-error Active construction rejects material without its validation proof.
  readyMaterial: rawReadyMaterial,
  committedAt,
});

const rawPreparedJournal = {
  ...preparedJournal,
};

// @ts-expect-error Prepared journals can only be constructed by their branch builder.
const invalidPreparedJournal: PreparedEcdsaActivationJournal = rawPreparedJournal;

const rawActiveManifest = {
  ...activeManifest,
};

// @ts-expect-error Active manifests can only be constructed by their branch builder.
const invalidActiveManifest: ActiveEcdsaCapabilityManifest = rawActiveManifest;

buildActiveEcdsaCapabilityManifest({
  committedJournal,
  registeredPublicFacts,
  readyMaterial,
  committedAt,
  // @ts-expect-error Durable material activation has no recovery-use policy.
  recoveryPolicy: {
    kind: 'recoverable',
    remainingRecoveryUses: 1,
  },
});

void invalidReadyMaterial;
void invalidPreparedJournal;
void invalidActiveManifest;
