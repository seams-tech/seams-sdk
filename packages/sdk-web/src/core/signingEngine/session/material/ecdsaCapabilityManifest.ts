import {
  buildMpcMaterialActivationRef,
  parseMpcKeyBindingRef,
  parseMpcLifecycleBindingRef,
  parseMpcSigningWorkerRef,
  type CapabilityInstanceRef,
  type DomainIdParseResult,
  type MpcMaterialActivationId,
  type MpcMaterialActivationRef,
  type MpcMaterialOwnerRef,
} from '@shared/utils/domainIds';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import {
  parseRouterAbEcdsaRegistrationActivationReceiptV1,
  type RouterAbEcdsaRegistrationActivationReceiptV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type {
  SigningRootId,
  SigningRootVersion,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import type { CorrelationId, DigestB64u, IsoTimestamp } from '@shared/utils/canonicalPrimitives';
import { isoTimestampFromUnixMs } from '@shared/utils/canonicalPrimitives';
import {
  parseEcdsaActivationDigest,
  parseEcdsaLifecycleId,
  type CanonicalEcdsaServerActivationRequest,
  type EcdsaActivationDigest,
  type EcdsaCapabilityManifestId,
  type EcdsaCapabilityManifestRevision,
  type EcdsaCiphertextB64u,
  type EcdsaCiphertextDigest,
  type EcdsaIv12B64u,
  type EcdsaLifecycleId,
  type EcdsaMaterialSealingKeyId,
  type EcdsaPendingCiphertextDigest,
  type EcdsaServerGeneration,
  type EvmFamilyEcdsaSignerId,
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

abstract class EcdsaCapabilityManifestProof {
  private retainProof(): true {
    return true;
  }

  constructor() {
    void this.retainProof();
  }
}

type EcdsaCapabilityScopeExclusions = {
  readonly exactTarget?: never;
};

class EcdsaCapabilityScopeProof extends EcdsaCapabilityManifestProof {
  readonly kind = 'evm_family';
  readonly targetMemberships: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];

  constructor(
    targetMemberships: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]],
  ) {
    super();
    this.targetMemberships = targetMemberships;
  }
}

export type EcdsaCapabilityScope = EcdsaCapabilityScopeProof & EcdsaCapabilityScopeExclusions;

class EcdsaManifestIdentityProof extends EcdsaCapabilityManifestProof {
  readonly manifestId: EcdsaCapabilityManifestId;
  readonly manifestRevision: EcdsaCapabilityManifestRevision;

  constructor(fields: {
    readonly manifestId: EcdsaCapabilityManifestId;
    readonly manifestRevision: EcdsaCapabilityManifestRevision;
  }) {
    super();
    this.manifestId = fields.manifestId;
    this.manifestRevision = fields.manifestRevision;
  }
}

export type EcdsaManifestIdentity = EcdsaManifestIdentityProof;

class NoCurrentEcdsaManifestExpectationProof extends EcdsaCapabilityManifestProof {
  readonly kind = 'no_current_manifest';
}

export type NoCurrentEcdsaManifestExpectation = NoCurrentEcdsaManifestExpectationProof & {
  readonly manifestId?: never;
  readonly manifestRevision?: never;
};

class ExactEcdsaManifestExpectationProof extends EcdsaCapabilityManifestProof {
  readonly kind = 'exact_manifest';
  readonly manifestId: EcdsaCapabilityManifestId;
  readonly manifestRevision: EcdsaCapabilityManifestRevision;

  constructor(identity: EcdsaManifestIdentity) {
    super();
    this.manifestId = identity.manifestId;
    this.manifestRevision = identity.manifestRevision;
  }
}

export type ExactEcdsaManifestExpectation = ExactEcdsaManifestExpectationProof;

export type EcdsaManifestRevisionExpectation =
  | NoCurrentEcdsaManifestExpectation
  | ExactEcdsaManifestExpectation;

class NoCurrentEcdsaServerGenerationExpectationProof extends EcdsaCapabilityManifestProof {
  readonly kind = 'no_current_generation';
}

export type NoCurrentEcdsaServerGenerationExpectation =
  NoCurrentEcdsaServerGenerationExpectationProof & {
    readonly serverGeneration?: never;
  };

class ExactEcdsaServerGenerationExpectationProof extends EcdsaCapabilityManifestProof {
  readonly kind = 'exact_generation';
  readonly serverGeneration: EcdsaServerGeneration;

  constructor(serverGeneration: EcdsaServerGeneration) {
    super();
    this.serverGeneration = serverGeneration;
  }
}

export type ExactEcdsaServerGenerationExpectation = ExactEcdsaServerGenerationExpectationProof;

export type EcdsaServerGenerationExpectation =
  | NoCurrentEcdsaServerGenerationExpectation
  | ExactEcdsaServerGenerationExpectation;

type EcdsaRoleLocalMaterialExclusions = {
  readonly walletId?: never;
  readonly chainTarget?: never;
  readonly thresholdSessionId?: never;
  readonly signingGrantId?: never;
  readonly quotaState?: never;
  readonly remainingUses?: never;
  readonly expiresAtMs?: never;
};

class EcdsaRoleLocalMaterialBindingProof extends EcdsaCapabilityManifestProof {
  readonly kind = 'ecdsa_role_local_material_binding';
  readonly keyHandle: EcdsaKeyHandle;
  readonly ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  readonly clientVerifyingPublicKey33B64u: EcdsaClientVerifyingPublicKey33B64u;
  readonly participantIds: readonly [ParticipantId, ...ParticipantId[]];
  readonly relayerKeyId: EcdsaRelayerKeyId;

  constructor(fields: {
    readonly keyHandle: EcdsaKeyHandle;
    readonly ecdsaThresholdKeyId: EcdsaThresholdKeyId;
    readonly clientVerifyingPublicKey33B64u: EcdsaClientVerifyingPublicKey33B64u;
    readonly participantIds: readonly [ParticipantId, ...ParticipantId[]];
    readonly relayerKeyId: EcdsaRelayerKeyId;
  }) {
    super();
    this.keyHandle = fields.keyHandle;
    this.ecdsaThresholdKeyId = fields.ecdsaThresholdKeyId;
    this.clientVerifyingPublicKey33B64u = fields.clientVerifyingPublicKey33B64u;
    this.participantIds = fields.participantIds;
    this.relayerKeyId = fields.relayerKeyId;
  }
}

export type EcdsaRoleLocalMaterialBinding = EcdsaRoleLocalMaterialBindingProof &
  EcdsaRoleLocalMaterialExclusions;

type PreparedEvmFamilySignerExclusions = {
  readonly registeredPublicFacts?: never;
  readonly materialActivation?: never;
  readonly durableMaterial?: never;
  readonly runtime?: never;
  readonly operationGrant?: never;
  readonly quotaState?: never;
  readonly nonceState?: never;
  readonly bearerSessionCredential?: never;
};

class PreparedEvmFamilySignerProof extends EcdsaCapabilityManifestProof {
  readonly kind = 'prepared_evm_family_signer';
  readonly capability: CapabilityInstanceRef;
  readonly signerId: EvmFamilyEcdsaSignerId;
  readonly walletId: WalletAuthAuthorityRef['walletId'];
  readonly authority: WalletAuthAuthorityRef;
  readonly scope: EcdsaCapabilityScope;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly signingRootId: SigningRootId;
  readonly signingRootVersion: SigningRootVersion;

  constructor(fields: {
    readonly capability: CapabilityInstanceRef;
    readonly signerId: EvmFamilyEcdsaSignerId;
    readonly authority: WalletAuthAuthorityRef;
    readonly scope: EcdsaCapabilityScope;
    readonly materialOwner: MpcMaterialOwnerRef;
    readonly signingRootId: SigningRootId;
    readonly signingRootVersion: SigningRootVersion;
  }) {
    super();
    this.capability = fields.capability;
    this.signerId = fields.signerId;
    this.walletId = fields.authority.walletId;
    this.authority = fields.authority;
    this.scope = fields.scope;
    this.materialOwner = fields.materialOwner;
    this.signingRootId = fields.signingRootId;
    this.signingRootVersion = fields.signingRootVersion;
  }
}

export type PreparedEvmFamilySigner = PreparedEvmFamilySignerProof &
  PreparedEvmFamilySignerExclusions;

class RegisteredEvmFamilySignerProof extends EcdsaCapabilityManifestProof {
  readonly kind = 'registered_evm_family_signer';
  readonly capability: CapabilityInstanceRef;
  readonly signerId: EvmFamilyEcdsaSignerId;
  readonly walletId: WalletAuthAuthorityRef['walletId'];
  readonly authority: WalletAuthAuthorityRef;
  readonly scope: EcdsaCapabilityScope;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly signingRootId: SigningRootId;
  readonly signingRootVersion: SigningRootVersion;
  readonly registeredPublicFacts: VerifiedEcdsaPublicFacts;

  constructor(fields: {
    readonly preparedSigner: PreparedEvmFamilySigner;
    readonly registeredPublicFacts: VerifiedEcdsaPublicFacts;
  }) {
    super();
    this.capability = fields.preparedSigner.capability;
    this.signerId = fields.preparedSigner.signerId;
    this.walletId = fields.preparedSigner.walletId;
    this.authority = fields.preparedSigner.authority;
    this.scope = fields.preparedSigner.scope;
    this.materialOwner = fields.preparedSigner.materialOwner;
    this.signingRootId = fields.preparedSigner.signingRootId;
    this.signingRootVersion = fields.preparedSigner.signingRootVersion;
    this.registeredPublicFacts = fields.registeredPublicFacts;
  }
}

export type RegisteredEvmFamilySigner = RegisteredEvmFamilySignerProof &
  Omit<PreparedEvmFamilySignerExclusions, 'registeredPublicFacts'>;

type EncryptedEcdsaPendingCandidateExclusions = {
  readonly plaintext?: never;
  readonly stateBlobB64u?: never;
  readonly readyMaterial?: never;
};

class EncryptedEcdsaPendingCandidateProof extends EcdsaCapabilityManifestProof {
  readonly kind = 'encrypted_ecdsa_pending_candidate';
  readonly sealingKeyId: EcdsaMaterialSealingKeyId;
  readonly iv12B64u: EcdsaIv12B64u;
  readonly ciphertextB64u: EcdsaCiphertextB64u;
  readonly ciphertextDigest: EcdsaPendingCiphertextDigest;

  constructor(fields: {
    readonly sealingKeyId: EcdsaMaterialSealingKeyId;
    readonly iv12B64u: EcdsaIv12B64u;
    readonly ciphertextB64u: EcdsaCiphertextB64u;
    readonly ciphertextDigest: EcdsaPendingCiphertextDigest;
  }) {
    super();
    this.sealingKeyId = fields.sealingKeyId;
    this.iv12B64u = fields.iv12B64u;
    this.ciphertextB64u = fields.ciphertextB64u;
    this.ciphertextDigest = fields.ciphertextDigest;
  }
}

export type EncryptedEcdsaPendingCandidate = EncryptedEcdsaPendingCandidateProof &
  EncryptedEcdsaPendingCandidateExclusions;

type PreparedEcdsaActivationCandidateExclusions = {
  readonly registeredPublicFacts?: never;
  readonly lifecycleId?: never;
  readonly activationDigest?: never;
  readonly activatedAt?: never;
  readonly finalCiphertextDigest?: never;
  readonly serverGeneration?: never;
  readonly serverActivationReceipt?: never;
};

class PreparedEcdsaActivationCandidateProof extends EcdsaCapabilityManifestProof {
  readonly kind = 'prepared_ecdsa_activation_candidate';
  readonly targetManifest: EcdsaManifestIdentity;
  readonly signer: PreparedEvmFamilySigner;
  readonly activationId: MpcMaterialActivationId;
  readonly roleLocalBinding: EcdsaRoleLocalMaterialBinding;
  readonly bindingDigest: EcdsaRoleLocalBindingDigest;
  readonly durableMaterialRef: EcdsaRoleLocalDurableMaterialRef;
  readonly encryptedPending: EncryptedEcdsaPendingCandidate;

  constructor(fields: {
    readonly targetManifest: EcdsaManifestIdentity;
    readonly signer: PreparedEvmFamilySigner;
    readonly activationId: MpcMaterialActivationId;
    readonly roleLocalBinding: EcdsaRoleLocalMaterialBinding;
    readonly bindingDigest: EcdsaRoleLocalBindingDigest;
    readonly durableMaterialRef: EcdsaRoleLocalDurableMaterialRef;
    readonly encryptedPending: EncryptedEcdsaPendingCandidate;
  }) {
    super();
    this.targetManifest = fields.targetManifest;
    this.signer = fields.signer;
    this.activationId = fields.activationId;
    this.roleLocalBinding = fields.roleLocalBinding;
    this.bindingDigest = fields.bindingDigest;
    this.durableMaterialRef = fields.durableMaterialRef;
    this.encryptedPending = fields.encryptedPending;
  }
}

export type PreparedEcdsaActivationCandidate = PreparedEcdsaActivationCandidateProof &
  PreparedEcdsaActivationCandidateExclusions;

class EcdsaServerActivationCommandProof extends EcdsaCapabilityManifestProof {
  readonly kind = 'ecdsa_server_activation_command';
  readonly correlationId: CorrelationId;
  readonly expectedGeneration: EcdsaServerGenerationExpectation;
  readonly requestDigest: DigestB64u;
  readonly canonicalRequest: CanonicalEcdsaServerActivationRequest;

  constructor(fields: {
    readonly correlationId: CorrelationId;
    readonly expectedGeneration: EcdsaServerGenerationExpectation;
    readonly requestDigest: DigestB64u;
    readonly canonicalRequest: CanonicalEcdsaServerActivationRequest;
  }) {
    super();
    this.correlationId = fields.correlationId;
    this.expectedGeneration = fields.expectedGeneration;
    this.requestDigest = fields.requestDigest;
    this.canonicalRequest = fields.canonicalRequest;
  }
}

export type EcdsaServerActivationCommand = EcdsaServerActivationCommandProof;

class EcdsaServerActivationReceiptProof extends EcdsaCapabilityManifestProof {
  readonly kind = 'ecdsa_server_activation_receipt';
  readonly lifecycleId: EcdsaLifecycleId;
  readonly activationDigest: EcdsaActivationDigest;
  readonly activatedAt: IsoTimestamp;
  readonly protocolReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;

  constructor(fields: {
    readonly lifecycleId: EcdsaLifecycleId;
    readonly activationDigest: EcdsaActivationDigest;
    readonly activatedAt: IsoTimestamp;
    readonly protocolReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
  }) {
    super();
    this.lifecycleId = fields.lifecycleId;
    this.activationDigest = fields.activationDigest;
    this.activatedAt = fields.activatedAt;
    this.protocolReceipt = fields.protocolReceipt;
  }
}

export type EcdsaServerActivationReceipt = EcdsaServerActivationReceiptProof;

class EcdsaServerActivationCommitProof extends EcdsaCapabilityManifestProof {
  readonly kind = 'ecdsa_server_activation_commit';
  readonly correlationId: CorrelationId;
  readonly activationRequestDigest: DigestB64u;
  readonly serverGeneration: EcdsaServerGeneration;
  readonly serverActivationReceipt: EcdsaServerActivationReceipt;

  constructor(fields: {
    readonly correlationId: CorrelationId;
    readonly activationRequestDigest: DigestB64u;
    readonly serverGeneration: EcdsaServerGeneration;
    readonly serverActivationReceipt: EcdsaServerActivationReceipt;
  }) {
    super();
    this.correlationId = fields.correlationId;
    this.activationRequestDigest = fields.activationRequestDigest;
    this.serverGeneration = fields.serverGeneration;
    this.serverActivationReceipt = fields.serverActivationReceipt;
  }
}

export type EcdsaServerActivationCommit = EcdsaServerActivationCommitProof;

type EcdsaActivationJournalCommonFields = {
  readonly journalId: CorrelationId;
  readonly expectedManifest: EcdsaManifestRevisionExpectation;
  readonly activationCommand: EcdsaServerActivationCommand;
  readonly candidate: PreparedEcdsaActivationCandidate;
  readonly createdAt: IsoTimestamp;
};

class PreparedEcdsaActivationJournalProof extends EcdsaCapabilityManifestProof {
  readonly kind = 'activation_prepared';
  readonly journalId: CorrelationId;
  readonly expectedManifest: EcdsaManifestRevisionExpectation;
  readonly activationCommand: EcdsaServerActivationCommand;
  readonly candidate: PreparedEcdsaActivationCandidate;
  readonly createdAt: IsoTimestamp;

  constructor(fields: EcdsaActivationJournalCommonFields) {
    super();
    this.journalId = fields.journalId;
    this.expectedManifest = fields.expectedManifest;
    this.activationCommand = fields.activationCommand;
    this.candidate = fields.candidate;
    this.createdAt = fields.createdAt;
  }
}

export type PreparedEcdsaActivationJournal = PreparedEcdsaActivationJournalProof & {
  readonly serverActivation?: never;
};

class ServerCommittedEcdsaActivationJournalProof extends EcdsaCapabilityManifestProof {
  readonly kind = 'server_activation_committed';
  readonly journalId: CorrelationId;
  readonly expectedManifest: EcdsaManifestRevisionExpectation;
  readonly activationCommand: EcdsaServerActivationCommand;
  readonly candidate: PreparedEcdsaActivationCandidate;
  readonly createdAt: IsoTimestamp;
  readonly serverActivation: EcdsaServerActivationCommit;

  constructor(
    fields: EcdsaActivationJournalCommonFields & {
      readonly serverActivation: EcdsaServerActivationCommit;
    },
  ) {
    super();
    this.journalId = fields.journalId;
    this.expectedManifest = fields.expectedManifest;
    this.activationCommand = fields.activationCommand;
    this.candidate = fields.candidate;
    this.createdAt = fields.createdAt;
    this.serverActivation = fields.serverActivation;
  }
}

export type ServerCommittedEcdsaActivationJournal = ServerCommittedEcdsaActivationJournalProof;

export type EcdsaCapabilityActivationCommitJournal =
  | PreparedEcdsaActivationJournal
  | ServerCommittedEcdsaActivationJournal;

export type DurableEcdsaMaterialBinding = {
  readonly kind: 'durable_ecdsa_material';
  readonly materialActivation: MpcMaterialActivationRef;
  readonly roleLocalBinding: EcdsaRoleLocalMaterialBinding;
  readonly durableMaterialRef: EcdsaRoleLocalDurableMaterialRef;
  readonly bindingDigest: EcdsaRoleLocalBindingDigest;
  readonly lifecycleId: EcdsaLifecycleId;
  readonly ciphertextDigest: EcdsaCiphertextDigest;
  readonly activationDigest: EcdsaActivationDigest;
  readonly activatedAt: IsoTimestamp;
  readonly runtime?: never;
};

type ValidatedEncryptedEcdsaReadyMaterialExclusions = {
  readonly plaintext?: never;
  readonly stateBlobB64u?: never;
  readonly pendingCandidate?: never;
};

class ValidatedEncryptedEcdsaReadyMaterialProof extends EcdsaCapabilityManifestProof {
  readonly kind = 'encrypted_ecdsa_ready_material';
  readonly binding: DurableEcdsaMaterialBinding;
  readonly sealingKeyId: EcdsaMaterialSealingKeyId;
  readonly iv12B64u: EcdsaIv12B64u;
  readonly ciphertextB64u: EcdsaCiphertextB64u;

  constructor(fields: {
    readonly binding: DurableEcdsaMaterialBinding;
    readonly sealingKeyId: EcdsaMaterialSealingKeyId;
    readonly iv12B64u: EcdsaIv12B64u;
    readonly ciphertextB64u: EcdsaCiphertextB64u;
  }) {
    super();
    this.binding = fields.binding;
    this.sealingKeyId = fields.sealingKeyId;
    this.iv12B64u = fields.iv12B64u;
    this.ciphertextB64u = fields.ciphertextB64u;
  }
}

export type ValidatedEncryptedEcdsaReadyMaterial = ValidatedEncryptedEcdsaReadyMaterialProof &
  ValidatedEncryptedEcdsaReadyMaterialExclusions;

export type ActiveEcdsaMaterialActivation = {
  readonly kind: 'active_ecdsa_material_activation';
  readonly materialActivation: MpcMaterialActivationRef;
  readonly serverActivation: EcdsaServerActivationCommit;
  readonly retention: 'retained';
  readonly operationGrant?: never;
  readonly quotaState?: never;
  readonly nonceState?: never;
  readonly bearerSessionCredential?: never;
};

type ActiveEcdsaCapabilityManifestExclusions = {
  readonly publicReauthAnchor?: never;
  readonly retirement?: never;
  readonly runtime?: never;
  readonly operationGrant?: never;
  readonly quotaState?: never;
  readonly nonceState?: never;
  readonly bearerSessionCredential?: never;
  readonly provenance?: never;
  readonly diagnostics?: never;
};

class ActiveEcdsaCapabilityManifestProof extends EcdsaCapabilityManifestProof {
  readonly kind = 'active_ecdsa_capability_manifest';
  readonly identity: EcdsaManifestIdentity;
  readonly signer: RegisteredEvmFamilySigner;
  readonly activation: ActiveEcdsaMaterialActivation;
  readonly durableMaterial: DurableEcdsaMaterialBinding;
  readonly committedAt: IsoTimestamp;

  constructor(fields: {
    readonly identity: EcdsaManifestIdentity;
    readonly signer: RegisteredEvmFamilySigner;
    readonly activation: ActiveEcdsaMaterialActivation;
    readonly durableMaterial: DurableEcdsaMaterialBinding;
    readonly committedAt: IsoTimestamp;
  }) {
    super();
    this.identity = fields.identity;
    this.signer = fields.signer;
    this.activation = fields.activation;
    this.durableMaterial = fields.durableMaterial;
    this.committedAt = fields.committedAt;
  }
}

export type ActiveEcdsaCapabilityManifest = ActiveEcdsaCapabilityManifestProof &
  ActiveEcdsaCapabilityManifestExclusions;

export type ReplacedEcdsaRetirement = {
  readonly kind: 'replaced';
  readonly replacementManifest: EcdsaManifestIdentity;
  readonly replacementActivation: EcdsaServerActivationCommit;
};

type ReplacedEcdsaCapabilityManifestExclusions = {
  readonly activation?: never;
  readonly durableMaterial?: never;
  readonly publicReauthAnchor?: never;
  readonly runtime?: never;
  readonly operationGrant?: never;
  readonly quotaState?: never;
  readonly nonceState?: never;
  readonly bearerSessionCredential?: never;
  readonly provenance?: never;
  readonly diagnostics?: never;
};

class ReplacedEcdsaCapabilityManifestProof extends EcdsaCapabilityManifestProof {
  readonly kind = 'replaced_ecdsa_capability_manifest';
  readonly identity: EcdsaManifestIdentity;
  readonly signer: RegisteredEvmFamilySigner;
  readonly retirement: ReplacedEcdsaRetirement;

  constructor(fields: {
    readonly identity: EcdsaManifestIdentity;
    readonly signer: RegisteredEvmFamilySigner;
    readonly retirement: ReplacedEcdsaRetirement;
  }) {
    super();
    this.identity = fields.identity;
    this.signer = fields.signer;
    this.retirement = fields.retirement;
  }
}

export type ReplacedEcdsaCapabilityManifest = ReplacedEcdsaCapabilityManifestProof &
  ReplacedEcdsaCapabilityManifestExclusions;

export type EcdsaCapabilityManifest =
  | ActiveEcdsaCapabilityManifest
  | ReplacedEcdsaCapabilityManifest;

export function buildEcdsaCapabilityScope(input: {
  readonly targetMemberships: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
  readonly kind?: never;
  readonly exactTarget?: never;
}): EcdsaCapabilityScope {
  assertUniqueEcdsaTargetMemberships(input.targetMemberships);
  return new EcdsaCapabilityScopeProof([...input.targetMemberships]);
}

export function buildEcdsaManifestIdentity(input: {
  readonly manifestId: EcdsaCapabilityManifestId;
  readonly manifestRevision: EcdsaCapabilityManifestRevision;
}): EcdsaManifestIdentity {
  return new EcdsaManifestIdentityProof(input);
}

export function buildNoCurrentEcdsaManifestExpectation(): NoCurrentEcdsaManifestExpectation {
  return new NoCurrentEcdsaManifestExpectationProof();
}

export function buildExactEcdsaManifestExpectation(
  identity: EcdsaManifestIdentity,
): ExactEcdsaManifestExpectation {
  return new ExactEcdsaManifestExpectationProof(identity);
}

export function buildNoCurrentEcdsaServerGenerationExpectation(): NoCurrentEcdsaServerGenerationExpectation {
  return new NoCurrentEcdsaServerGenerationExpectationProof();
}

export function buildExactEcdsaServerGenerationExpectation(
  serverGeneration: EcdsaServerGeneration,
): ExactEcdsaServerGenerationExpectation {
  return new ExactEcdsaServerGenerationExpectationProof(serverGeneration);
}

export function buildEcdsaRoleLocalMaterialBinding(
  input: {
    readonly keyHandle: EcdsaKeyHandle;
    readonly ecdsaThresholdKeyId: EcdsaThresholdKeyId;
    readonly clientVerifyingPublicKey33B64u: EcdsaClientVerifyingPublicKey33B64u;
    readonly participantIds: readonly [ParticipantId, ...ParticipantId[]];
    readonly relayerKeyId: EcdsaRelayerKeyId;
  } & EcdsaRoleLocalMaterialExclusions,
): EcdsaRoleLocalMaterialBinding {
  assertUniqueParticipantIds(input.participantIds);
  return new EcdsaRoleLocalMaterialBindingProof({
    keyHandle: input.keyHandle,
    ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
    clientVerifyingPublicKey33B64u: input.clientVerifyingPublicKey33B64u,
    participantIds: [...input.participantIds],
    relayerKeyId: input.relayerKeyId,
  });
}

export function buildPreparedEvmFamilySigner(
  input: {
    readonly capability: CapabilityInstanceRef;
    readonly signerId: EvmFamilyEcdsaSignerId;
    readonly authority: WalletAuthAuthorityRef;
    readonly scope: EcdsaCapabilityScope;
    readonly materialOwner: MpcMaterialOwnerRef;
    readonly signingRootId: SigningRootId;
    readonly signingRootVersion: SigningRootVersion;
    readonly walletId?: never;
    readonly kind?: never;
  } & PreparedEvmFamilySignerExclusions,
): PreparedEvmFamilySigner {
  return new PreparedEvmFamilySignerProof(input);
}

export function buildEncryptedEcdsaPendingCandidate(
  input: {
    readonly sealingKeyId: EcdsaMaterialSealingKeyId;
    readonly iv12B64u: EcdsaIv12B64u;
    readonly ciphertextB64u: EcdsaCiphertextB64u;
    readonly ciphertextDigest: EcdsaPendingCiphertextDigest;
    readonly kind?: never;
  } & EncryptedEcdsaPendingCandidateExclusions,
): EncryptedEcdsaPendingCandidate {
  return new EncryptedEcdsaPendingCandidateProof(input);
}

export function buildPreparedEcdsaActivationCandidate(
  input: {
    readonly targetManifest: EcdsaManifestIdentity;
    readonly signer: PreparedEvmFamilySigner;
    readonly activationId: MpcMaterialActivationId;
    readonly roleLocalBinding: EcdsaRoleLocalMaterialBinding;
    readonly bindingDigest: EcdsaRoleLocalBindingDigest;
    readonly durableMaterialRef: EcdsaRoleLocalDurableMaterialRef;
    readonly encryptedPending: EncryptedEcdsaPendingCandidate;
    readonly kind?: never;
  } & PreparedEcdsaActivationCandidateExclusions,
): PreparedEcdsaActivationCandidate {
  return new PreparedEcdsaActivationCandidateProof(input);
}

type BuildPreparedEcdsaActivationJournalCommon = {
  readonly journalId: CorrelationId;
  readonly candidate: PreparedEcdsaActivationCandidate;
  readonly requestDigest: DigestB64u;
  readonly canonicalRequest: CanonicalEcdsaServerActivationRequest;
  readonly createdAt: IsoTimestamp;
  readonly activationCommand?: never;
  readonly serverActivation?: never;
  readonly kind?: never;
};

export type BuildPreparedEcdsaActivationJournalInput = BuildPreparedEcdsaActivationJournalCommon &
  (
    | {
        readonly expectedManifest: NoCurrentEcdsaManifestExpectation;
        readonly expectedGeneration: NoCurrentEcdsaServerGenerationExpectation;
      }
    | {
        readonly expectedManifest: ExactEcdsaManifestExpectation;
        readonly expectedGeneration: ExactEcdsaServerGenerationExpectation;
      }
  );

export function buildPreparedEcdsaActivationJournal(
  input: BuildPreparedEcdsaActivationJournalInput,
): PreparedEcdsaActivationJournal {
  assertTargetManifestTransition(input.expectedManifest, input.candidate.targetManifest);
  assertExpectedStatePair(input.expectedManifest, input.expectedGeneration);
  const activationCommand = new EcdsaServerActivationCommandProof({
    correlationId: input.journalId,
    expectedGeneration: input.expectedGeneration,
    requestDigest: input.requestDigest,
    canonicalRequest: input.canonicalRequest,
  });
  return new PreparedEcdsaActivationJournalProof({
    journalId: input.journalId,
    expectedManifest: input.expectedManifest,
    activationCommand,
    candidate: input.candidate,
    createdAt: input.createdAt,
  });
}

export type ServerReturnedEcdsaActivationCommit = {
  readonly correlationId: CorrelationId;
  readonly activationRequestDigest: DigestB64u;
  readonly serverGeneration: EcdsaServerGeneration;
  readonly protocolReceipt: unknown;
};

export function buildServerCommittedEcdsaActivationJournal(input: {
  readonly preparedJournal: PreparedEcdsaActivationJournal;
  readonly serverCommit: ServerReturnedEcdsaActivationCommit;
  readonly journalId?: never;
  readonly activationRequestDigest?: never;
  readonly serverActivationReceipt?: never;
  readonly kind?: never;
}): ServerCommittedEcdsaActivationJournal {
  assertServerCommitMatchesPreparedCommand(input.serverCommit, input.preparedJournal);
  const protocolReceipt = parseRouterAbEcdsaRegistrationActivationReceiptV1(
    input.serverCommit.protocolReceipt,
  );
  assertProtocolReceiptMatchesCandidate(protocolReceipt, input.preparedJournal.candidate);
  const serverActivationReceipt = new EcdsaServerActivationReceiptProof({
    lifecycleId: lifecycleIdFromProtocolReceipt(protocolReceipt),
    activationDigest: activationDigestFromProtocolReceipt(protocolReceipt),
    activatedAt: isoTimestampFromUnixMs(protocolReceipt.ecdsa_activation.activated_at_ms),
    protocolReceipt,
  });
  const serverActivation = new EcdsaServerActivationCommitProof({
    correlationId: input.serverCommit.correlationId,
    activationRequestDigest: input.serverCommit.activationRequestDigest,
    serverGeneration: input.serverCommit.serverGeneration,
    serverActivationReceipt,
  });
  return new ServerCommittedEcdsaActivationJournalProof({
    journalId: input.preparedJournal.journalId,
    expectedManifest: input.preparedJournal.expectedManifest,
    activationCommand: input.preparedJournal.activationCommand,
    candidate: input.preparedJournal.candidate,
    createdAt: input.preparedJournal.createdAt,
    serverActivation,
  });
}

export function buildValidatedEncryptedEcdsaReadyMaterial(input: {
  readonly committedJournal: ServerCommittedEcdsaActivationJournal;
  readonly sealingKeyId: EcdsaMaterialSealingKeyId;
  readonly iv12B64u: EcdsaIv12B64u;
  readonly ciphertextB64u: EcdsaCiphertextB64u;
  readonly ciphertextDigest: EcdsaCiphertextDigest;
  readonly binding?: never;
  readonly plaintext?: never;
  readonly stateBlobB64u?: never;
  readonly kind?: never;
}): ValidatedEncryptedEcdsaReadyMaterial {
  const candidate = input.committedJournal.candidate;
  const receipt = input.committedJournal.serverActivation.serverActivationReceipt;
  const materialActivation = materialActivationFromCommit(candidate, receipt.protocolReceipt);
  const binding: DurableEcdsaMaterialBinding = {
    kind: 'durable_ecdsa_material',
    materialActivation,
    roleLocalBinding: candidate.roleLocalBinding,
    durableMaterialRef: candidate.durableMaterialRef,
    bindingDigest: candidate.bindingDigest,
    lifecycleId: receipt.lifecycleId,
    ciphertextDigest: input.ciphertextDigest,
    activationDigest: receipt.activationDigest,
    activatedAt: receipt.activatedAt,
  };
  return new ValidatedEncryptedEcdsaReadyMaterialProof({
    binding,
    sealingKeyId: input.sealingKeyId,
    iv12B64u: input.iv12B64u,
    ciphertextB64u: input.ciphertextB64u,
  });
}

export function buildActiveEcdsaCapabilityManifest(
  input: {
    readonly committedJournal: ServerCommittedEcdsaActivationJournal;
    readonly registeredPublicFacts: VerifiedEcdsaPublicFacts;
    readonly readyMaterial: ValidatedEncryptedEcdsaReadyMaterial;
    readonly committedAt: IsoTimestamp;
    readonly identity?: never;
    readonly signer?: never;
    readonly activation?: never;
    readonly durableMaterial?: never;
    readonly kind?: never;
  } & ActiveEcdsaCapabilityManifestExclusions,
): ActiveEcdsaCapabilityManifest {
  const candidate = input.committedJournal.candidate;
  assertRegisteredPublicFactsMatchBinding(input.registeredPublicFacts, candidate.roleLocalBinding);
  assertReadyMaterialMatchesJournal(input.readyMaterial, input.committedJournal);
  const signer = new RegisteredEvmFamilySignerProof({
    preparedSigner: candidate.signer,
    registeredPublicFacts: input.registeredPublicFacts,
  });
  const activation: ActiveEcdsaMaterialActivation = {
    kind: 'active_ecdsa_material_activation',
    materialActivation: input.readyMaterial.binding.materialActivation,
    serverActivation: input.committedJournal.serverActivation,
    retention: 'retained',
  };
  return new ActiveEcdsaCapabilityManifestProof({
    identity: candidate.targetManifest,
    signer,
    activation,
    durableMaterial: input.readyMaterial.binding,
    committedAt: input.committedAt,
  });
}

export function buildReplacedEcdsaCapabilityManifest(
  input: {
    readonly activeManifest: ActiveEcdsaCapabilityManifest;
    readonly replacementManifest: ActiveEcdsaCapabilityManifest;
    readonly identity?: never;
    readonly signer?: never;
    readonly retirement?: never;
    readonly kind?: never;
  } & ReplacedEcdsaCapabilityManifestExclusions,
): ReplacedEcdsaCapabilityManifest {
  assertValidEcdsaReplacement(input.activeManifest, input.replacementManifest);
  return new ReplacedEcdsaCapabilityManifestProof({
    identity: input.activeManifest.identity,
    signer: input.activeManifest.signer,
    retirement: {
      kind: 'replaced',
      replacementManifest: input.replacementManifest.identity,
      replacementActivation: input.replacementManifest.activation.serverActivation,
    },
  });
}

export function ecdsaCapabilityManifestIdentity(
  manifest: EcdsaCapabilityManifest,
): EcdsaManifestIdentity {
  switch (manifest.kind) {
    case 'active_ecdsa_capability_manifest':
    case 'replaced_ecdsa_capability_manifest':
      return manifest.identity;
    default:
      return assertNever(manifest);
  }
}

export function ecdsaActivationJournalId(
  journal: EcdsaCapabilityActivationCommitJournal,
): CorrelationId {
  switch (journal.kind) {
    case 'activation_prepared':
    case 'server_activation_committed':
      return journal.journalId;
    default:
      return assertNever(journal);
  }
}

function assertUniqueEcdsaTargetMemberships(
  targetMemberships: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]],
): void {
  const targetKeys = targetMemberships.map(ecdsaTargetMembershipKey);
  if (new Set(targetKeys).size !== targetKeys.length) {
    throw new Error('ECDSA capability target memberships must be unique');
  }
}

function ecdsaTargetMembershipKey(target: ThresholdEcdsaChainTarget): string {
  switch (target.kind) {
    case 'evm':
      return `evm:${target.namespace}:${target.chainId}:${target.networkSlug}`;
    case 'tempo':
      return `tempo:${target.chainId}:${target.networkSlug}`;
    default:
      return assertNever(target);
  }
}

function assertUniqueParticipantIds(
  participantIds: readonly [ParticipantId, ...ParticipantId[]],
): void {
  const normalizedIds = participantIds.map(Number);
  if (
    normalizedIds.some(
      (participantId) => !Number.isSafeInteger(participantId) || participantId < 1,
    ) ||
    new Set(normalizedIds).size !== normalizedIds.length
  ) {
    throw new Error('ECDSA participant ids must be unique positive integers');
  }
}

function assertTargetManifestTransition(
  expected: EcdsaManifestRevisionExpectation,
  target: EcdsaManifestIdentity,
): void {
  switch (expected.kind) {
    case 'no_current_manifest':
      if (Number(target.manifestRevision) !== 1) {
        throw new Error('Initial ECDSA manifest revision must be 1');
      }
      return;
    case 'exact_manifest':
      if (
        target.manifestId === expected.manifestId ||
        Number(target.manifestRevision) !== Number(expected.manifestRevision) + 1
      ) {
        throw new Error('Replacement ECDSA manifest must use a fresh id and next revision');
      }
      return;
    default:
      return assertNever(expected);
  }
}

function assertExpectedStatePair(
  expectedManifest: EcdsaManifestRevisionExpectation,
  expectedGeneration: EcdsaServerGenerationExpectation,
): void {
  switch (expectedManifest.kind) {
    case 'no_current_manifest':
      if (expectedGeneration.kind !== 'no_current_generation') {
        throw new Error('Initial ECDSA activation cannot expect a server generation');
      }
      return;
    case 'exact_manifest':
      if (expectedGeneration.kind !== 'exact_generation') {
        throw new Error('Replacement ECDSA activation requires an exact server generation');
      }
      return;
    default:
      return assertNever(expectedManifest);
  }
}

function assertServerCommitMatchesPreparedCommand(
  serverCommit: ServerReturnedEcdsaActivationCommit,
  journal: PreparedEcdsaActivationJournal,
): void {
  if (
    serverCommit.correlationId !== journal.activationCommand.correlationId ||
    serverCommit.activationRequestDigest !== journal.activationCommand.requestDigest
  ) {
    throw new Error('ECDSA server activation commit does not match the prepared command');
  }
}

function assertProtocolReceiptMatchesCandidate(
  receipt: RouterAbEcdsaRegistrationActivationReceiptV1,
  candidate: PreparedEcdsaActivationCandidate,
): void {
  const publicIdentity = receipt.ecdsa_activation.public_identity;
  if (
    publicIdentity.context_binding_b64u !== String(candidate.bindingDigest) ||
    publicIdentity.derivation_client_share_public_key33_b64u !==
      String(candidate.roleLocalBinding.clientVerifyingPublicKey33B64u)
  ) {
    throw new Error('ECDSA activation receipt does not match the prepared material binding');
  }
}

function lifecycleIdFromProtocolReceipt(
  receipt: RouterAbEcdsaRegistrationActivationReceiptV1,
): EcdsaLifecycleId {
  return parseEcdsaLifecycleId(receipt.lifecycle_id);
}

function activationDigestFromProtocolReceipt(
  receipt: RouterAbEcdsaRegistrationActivationReceiptV1,
): EcdsaActivationDigest {
  return parseEcdsaActivationDigest(receipt.ecdsa_activation.activation_digest_b64u);
}

function unwrapDomainId<T>(result: DomainIdParseResult<T>): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function materialActivationFromCommit(
  candidate: PreparedEcdsaActivationCandidate,
  receipt: RouterAbEcdsaRegistrationActivationReceiptV1,
): MpcMaterialActivationRef {
  return buildMpcMaterialActivationRef({
    activationId: candidate.activationId,
    capability: candidate.signer.capability,
    materialOwner: candidate.signer.materialOwner,
    keyBinding: unwrapDomainId(parseMpcKeyBindingRef(candidate.bindingDigest)),
    lifecycleBinding: unwrapDomainId(parseMpcLifecycleBindingRef(receipt.lifecycle_id)),
    signingWorker: unwrapDomainId(
      parseMpcSigningWorkerRef(receipt.ecdsa_activation.signing_worker.server_id),
    ),
  });
}

function assertRegisteredPublicFactsMatchBinding(
  publicFacts: VerifiedEcdsaPublicFacts,
  binding: EcdsaRoleLocalMaterialBinding,
): void {
  if (
    String(publicFacts.keyHandle) !== String(binding.keyHandle) ||
    !participantIdsMatch(publicFacts.participantIds, binding.participantIds)
  ) {
    throw new Error('Registered ECDSA public facts do not match role-local material');
  }
}

function participantIdsMatch(
  left: readonly ParticipantId[],
  right: readonly ParticipantId[],
): boolean {
  if (left.length !== right.length) return false;
  return left.every((participantId, index) => Number(participantId) === Number(right[index]));
}

function assertReadyMaterialMatchesJournal(
  material: ValidatedEncryptedEcdsaReadyMaterial,
  journal: ServerCommittedEcdsaActivationJournal,
): void {
  const binding = material.binding;
  const candidate = journal.candidate;
  const receipt = journal.serverActivation.serverActivationReceipt;
  if (
    binding.materialActivation.activationId !== candidate.activationId ||
    binding.materialActivation.capability !== candidate.signer.capability ||
    binding.materialActivation.materialOwner !== candidate.signer.materialOwner ||
    binding.roleLocalBinding !== candidate.roleLocalBinding ||
    binding.durableMaterialRef !== candidate.durableMaterialRef ||
    binding.bindingDigest !== candidate.bindingDigest ||
    binding.lifecycleId !== receipt.lifecycleId ||
    binding.activationDigest !== receipt.activationDigest ||
    binding.activatedAt !== receipt.activatedAt
  ) {
    throw new Error('Validated ECDSA ready material does not match the committed journal');
  }
}

function assertValidEcdsaReplacement(
  active: ActiveEcdsaCapabilityManifest,
  replacement: ActiveEcdsaCapabilityManifest,
): void {
  if (
    active.identity.manifestId === replacement.identity.manifestId ||
    Number(replacement.identity.manifestRevision) !==
      Number(active.identity.manifestRevision) + 1 ||
    active.signer.capability !== replacement.signer.capability ||
    active.signer.signerId !== replacement.signer.signerId ||
    active.signer.walletId !== replacement.signer.walletId ||
    active.signer.authority.authorityDigest !== replacement.signer.authority.authorityDigest ||
    active.signer.materialOwner !== replacement.signer.materialOwner ||
    active.durableMaterial.durableMaterialRef === replacement.durableMaterial.durableMaterialRef ||
    active.activation.serverActivation.serverGeneration ===
      replacement.activation.serverActivation.serverGeneration
  ) {
    throw new Error('ECDSA replacement manifest does not exactly replace the active manifest');
  }
}

function assertNever(value: never): never {
  throw new Error(`Unexpected ECDSA capability branch: ${String(value)}`);
}
