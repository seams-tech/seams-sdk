import { parseWalletAuthMethodId } from '@shared/utils/domainIds';
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
import type {
  RouterAbEcdsaDerivationNormalSigningStateV1,
  RouterAbEcdsaRegistrationActivationReceiptV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
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
import type { EcdsaRoleLocalPublicFacts } from '@/core/platform';
import type { EvmFamilySigningKeySlotId } from '@shared/signing-lanes';
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
  buildDurableEcdsaMaterialBinding,
  buildEcdsaActivationBinding,
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
  type DurableEcdsaMaterialBinding,
  type EcdsaActivationBinding,
  type PreparedEcdsaActivationJournal,
  type ValidatedEncryptedEcdsaReadyMaterial,
} from './ecdsaCapabilityManifest';

declare const capability: CapabilityInstanceRef;
declare const materialOwner: MpcMaterialOwnerRef;
declare const activationId: MpcMaterialActivationId;
declare const evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
declare const roleLocalPublicFacts: EcdsaRoleLocalPublicFacts;
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
declare const runtimePolicyScope: RuntimePolicyScope;
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
declare const routerAbEcdsaDerivationNormalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
declare const registeredPublicFacts: VerifiedEcdsaPublicFacts;
declare const replacementActiveManifest: ActiveEcdsaCapabilityManifest;

const walletAuthMethodId = parseWalletAuthMethodId('passkey:wallet.example.test:typecheck');
if (!walletAuthMethodId.ok) {
  throw new Error('type fixture requires a valid wallet auth-method identity');
}
const authority: WalletAuthAuthorityRef = {
  kind: 'wallet_auth_authority_ref',
    walletAuthMethodId: walletAuthMethodId.value,
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

const activationBinding = buildEcdsaActivationBinding({
  targetManifest,
  signer: preparedSigner,
  roleLocalBinding,
  bindingDigest,
  durableMaterialRef,
});

const candidate = buildPreparedEcdsaActivationCandidate({
  activationBinding,
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

const durableMaterial = buildDurableEcdsaMaterialBinding({
  activationBinding,
  serverActivation: committedJournal.serverActivation,
  routerAbEcdsaDerivationNormalSigning,
  roleLocalPublicFacts,
  ciphertextDigest,
  runtimePolicyScope,
});

const readyMaterial = buildValidatedEncryptedEcdsaReadyMaterial({
  binding: durableMaterial,
  sealingKeyId,
  iv12B64u,
  ciphertextB64u,
});

const activeManifest = buildActiveEcdsaCapabilityManifest({
  activationBinding,
  serverActivation: committedJournal.serverActivation,
  registeredPublicFacts,
  durableMaterial,
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
const replacementActivationBinding = buildEcdsaActivationBinding({
  targetManifest: replacementTarget,
  signer: preparedSigner,
  roleLocalBinding,
  bindingDigest,
  durableMaterialRef,
});

buildPreparedEcdsaActivationJournal({
  journalId,
  candidate: buildPreparedEcdsaActivationCandidate({
    activationBinding: replacementActivationBinding,
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

// @ts-expect-error Activation bindings require a durable material reference.
buildEcdsaActivationBinding({
  targetManifest,
  signer: preparedSigner,
  roleLocalBinding,
  bindingDigest,
});

// @ts-expect-error Activation bindings require an exact role-local binding digest.
buildEcdsaActivationBinding({
  targetManifest,
  signer: preparedSigner,
  roleLocalBinding,
  durableMaterialRef,
});

buildEcdsaActivationBinding({
  targetManifest,
  signer: preparedSigner,
  roleLocalBinding,
  bindingDigest,
  durableMaterialRef,
  // @ts-expect-error The Router mints material activation identity after preparation.
  activationId: 'browser-owned-activation-id',
});

// @ts-expect-error Prepared candidates require a nominal activation binding.
buildPreparedEcdsaActivationCandidate({ encryptedPending });

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

// @ts-expect-error Active manifests require a durable material binding.
buildActiveEcdsaCapabilityManifest({
  activationBinding,
  serverActivation: committedJournal.serverActivation,
  registeredPublicFacts,
  committedAt,
});

const rawReadyMaterial = {
  ...readyMaterial,
};

// @ts-expect-error Spreading validated material loses its opaque validation proof.
const invalidReadyMaterial: ValidatedEncryptedEcdsaReadyMaterial = rawReadyMaterial;

buildActiveEcdsaCapabilityManifest({
  activationBinding,
  serverActivation: committedJournal.serverActivation,
  registeredPublicFacts,
  durableMaterial,
  committedAt,
  // @ts-expect-error Active construction cannot accept ciphertext-bearing ready material.
  readyMaterial: rawReadyMaterial,
});

buildActiveEcdsaCapabilityManifest({
  activationBinding,
  serverActivation: committedJournal.serverActivation,
  registeredPublicFacts,
  durableMaterial,
  committedAt,
  // @ts-expect-error Active manifests cannot carry pending ciphertext.
  encryptedPending,
});

buildActiveEcdsaCapabilityManifest({
  activationBinding,
  serverActivation: committedJournal.serverActivation,
  registeredPublicFacts,
  durableMaterial,
  committedAt,
  // @ts-expect-error Active manifests cannot carry ready ciphertext.
  ciphertextB64u,
});

const rawActivationBinding = {
  ...activationBinding,
};

// @ts-expect-error Activation bindings can only be constructed by their builder.
const invalidActivationBinding: EcdsaActivationBinding = rawActivationBinding;

const rawDurableMaterial = {
  ...durableMaterial,
};

// @ts-expect-error Durable material bindings can only be constructed by their builder.
const invalidDurableMaterial: DurableEcdsaMaterialBinding = rawDurableMaterial;

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
  activationBinding,
  serverActivation: committedJournal.serverActivation,
  registeredPublicFacts,
  durableMaterial,
  committedAt,
  // @ts-expect-error Durable material activation has no recovery-use policy.
  recoveryPolicy: {
    kind: 'recoverable',
    remainingRecoveryUses: 1,
  },
});

void invalidReadyMaterial;
void invalidActivationBinding;
void invalidDurableMaterial;
void invalidPreparedJournal;
void invalidActiveManifest;
