import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import {
  parseCorrelationId,
  parseDigestB64u,
  parseIsoTimestamp,
  type CorrelationId,
  type DigestB64u,
  type IsoTimestamp,
} from '@shared/utils/canonicalPrimitives';
import {
  mpcMaterialActivationRefsEqual,
  parseCapabilityInstanceRef,
  parseMpcMaterialActivationRef,
  parseMpcMaterialOwnerRef,
  parseWalletId,
  type CapabilityInstanceRef,
  type DomainIdParseResult,
  type MpcMaterialActivationRef,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletId,
} from '@shared/utils/domainIds';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  parseCanonicalEcdsaServerActivationRequest,
  parseEcdsaActivationDigest,
  parseEcdsaCapabilityManifestId,
  parseEcdsaCapabilityManifestRevision,
  parseEcdsaCiphertextB64u,
  parseEcdsaCiphertextDigest,
  parseEcdsaIv12B64u,
  parseEcdsaLifecycleId,
  parseEcdsaMaterialSealingKeyId,
  parseEcdsaPendingCiphertextDigest,
  parseEcdsaServerGeneration,
  parseEvmFamilyEcdsaSignerId,
  type EcdsaCapabilityManifestId,
  type EcdsaCapabilityManifestRevision,
  type EcdsaMaterialSealingKeyId,
} from '@shared/utils/ecdsaCapabilityActivation';
import { alphabetizeStringify, sha256Bytes, sha256BytesUtf8 } from '@shared/utils/digests';
import { secureRandomId } from '@shared/utils/secureRandomId';
import {
  normalizeRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import {
  parseRouterAbEcdsaDerivationPublicCapabilityV1,
  parseRouterAbEcdsaRegistrationActivationReceiptV1,
  requireRouterAbEcdsaDerivationNormalSigningStateV1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
  type RouterAbEcdsaDerivationPublicCapabilityV1,
  type RouterAbEcdsaRegistrationActivationReceiptV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  parseSdkEcdsaDerivationSigningRootId,
  parseSdkEcdsaDerivationSigningRootVersion,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import {
  parseWalletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { thresholdEcdsaChainTargetFromRequest } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { buildEcdsaRoleLocalPublicFacts, type EcdsaRoleLocalPublicFacts } from '@/core/platform';
import {
  buildVerifiedEcdsaPublicFacts,
  toEvmFamilyEcdsaKeyHandle,
  toParticipantId,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  parseEcdsaClientVerifyingPublicKey33B64u,
  parseEcdsaKeyHandle,
  parseEcdsaRelayerKeyId,
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaRoleLocalDurableMaterialRef,
  parseEcdsaRoleLocalPersistedMaterialRef,
  parseEcdsaThresholdKeyId,
  type EcdsaRoleLocalPersistedMaterialRef,
} from '@/core/signingEngine/session/keyMaterialBrands';
import {
  buildActiveEcdsaCapabilityManifest,
  buildDurableEcdsaMaterialBinding,
  buildEcdsaActivationBinding,
  buildEcdsaCapabilityScope,
  buildEcdsaManifestIdentity,
  buildEcdsaRoleLocalMaterialBinding,
  buildEcdsaServerActivationCommit,
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
  type BuildPreparedEcdsaActivationJournalInput,
  type DurableEcdsaMaterialBinding,
  type EcdsaActivationBinding,
  type EcdsaCapabilityActivationCommitJournal,
  type EncryptedEcdsaPendingCandidate,
  type ServerReturnedEcdsaActivationCommit,
  type EcdsaServerActivationCommit,
  type EcdsaManifestRevisionExpectation,
  type PreparedEcdsaActivationJournal,
  type ReplacedEcdsaCapabilityManifest,
  type ServerCommittedEcdsaActivationJournal,
  type ValidatedEncryptedEcdsaReadyMaterial,
} from '@/core/signingEngine/session/material/ecdsaCapabilityManifest';
import type { VerifiedEcdsaPublicFacts } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type { ThresholdEcdsaChainTarget } from '@/core/platform/types';
import type { WalletCustodyEvmFamilyPublicFacts } from '@shared/passkey-custody';
import { SEAMS_WALLET_INDEXES, SEAMS_WALLET_STORES } from '../schemaNames';
import { seamsWalletDB } from '../singletons';
import { SeamsWalletRepositories } from './repositories';
import type { SeamsWalletDBManager, SeamsWalletTransactionContext } from './manager';

// Bumped with the authority ref: these rows now record which wallet auth
// method issued the authority, so a row written before that is read as the
// wrong version and re-derived rather than failing an exact-key check.
const MANIFEST_RECORD_VERSION = 'ecdsa_capability_manifest_v3' as const;
const POINTER_RECORD_VERSION = 'ecdsa_current_capability_manifest_v2' as const;
const MATERIAL_RECORD_VERSION = 'ecdsa_role_local_material_v2' as const;
const JOURNAL_RECORD_VERSION = 'ecdsa_activation_commit_journal_v1' as const;
const SEALING_KEY_RECORD_VERSION = 'ecdsa_material_sealing_key_v1' as const;

const MANIFEST_STORE = SEAMS_WALLET_STORES.ecdsaCapabilityManifests;
const POINTER_STORE = SEAMS_WALLET_STORES.ecdsaCurrentCapabilityManifests;
const MATERIAL_STORE = SEAMS_WALLET_STORES.ecdsaRoleLocalMaterial;
const JOURNAL_STORE = SEAMS_WALLET_STORES.ecdsaActivationCommitJournals;
const SEALING_KEY_STORE = SEAMS_WALLET_STORES.ecdsaMaterialSealingKeys;
const AES_GCM_IV_BYTES = 12;
const MATERIAL_AAD_VERSION = 1;

export type EcdsaCapabilitySelector = {
  readonly capability: CapabilityInstanceRef;
  readonly authority: WalletAuthAuthorityRef;
};

export type ActiveEcdsaWalletCapabilitySubject = EcdsaCapabilitySelector & {
  readonly ecdsaThresholdKeyId: ReturnType<typeof parseEcdsaThresholdKeyId>;
};

export type ActiveEcdsaWalletCapabilitySubjectListResult =
  | {
      readonly kind: 'resolved';
      readonly subjects: readonly ActiveEcdsaWalletCapabilitySubject[];
    }
  | {
      readonly kind: 'invalid_current_state';
      readonly subjects?: never;
    }
  | {
      readonly kind: 'persistence_unavailable';
      readonly subjects?: never;
    };

export type EcdsaWalletActivationSelectorListResult =
  | {
      readonly kind: 'resolved';
      readonly selectors: readonly EcdsaCapabilitySelector[];
    }
  | {
      readonly kind: 'invalid_current_state';
      readonly selectors?: never;
    }
  | {
      readonly kind: 'persistence_unavailable';
      readonly selectors?: never;
    };

type LookupFailureExclusions = {
  readonly manifest?: never;
  readonly material?: never;
};

export type EcdsaCapabilityManifestLookup =
  | {
      readonly kind: 'active';
      readonly manifest: ActiveEcdsaCapabilityManifest;
      readonly material: ValidatedEncryptedEcdsaReadyMaterial;
    }
  | {
      readonly kind: 'retired';
      readonly manifest: ReplacedEcdsaCapabilityManifest;
      readonly material?: never;
    }
  | ({
      readonly kind: 'missing';
      readonly selector: EcdsaCapabilitySelector;
      readonly subject: 'capability' | 'material';
    } & LookupFailureExclusions)
  | ({
      readonly kind: 'exact_binding_mismatch';
      readonly selector: EcdsaCapabilitySelector;
      readonly failureDigest: DigestB64u;
    } & LookupFailureExclusions)
  | ({
      readonly kind: 'exact_record_conflict';
      readonly selector: EcdsaCapabilitySelector;
      readonly conflictDigest: DigestB64u;
    } & LookupFailureExclusions)
  | ({
      readonly kind: 'corrupt';
      readonly selector: EcdsaCapabilitySelector;
      readonly corruptionDigest: DigestB64u;
    } & LookupFailureExclusions)
  | ({
      readonly kind: 'persistence_unavailable';
      readonly selector: EcdsaCapabilitySelector;
      readonly retryCorrelation: CorrelationId;
    } & LookupFailureExclusions);

export type EcdsaActivationJournalWriteResult<
  TJournal extends EcdsaCapabilityActivationCommitJournal = EcdsaCapabilityActivationCommitJournal,
> =
  | {
      readonly kind: 'stored';
      readonly journal: TJournal;
    }
  | {
      readonly kind: 'exact_record_conflict';
      readonly conflictDigest: DigestB64u;
      readonly journal?: never;
    }
  | {
      readonly kind: 'corrupt';
      readonly corruptionDigest: DigestB64u;
      readonly journal?: never;
    }
  | {
      readonly kind: 'persistence_unavailable';
      readonly retryCorrelation: CorrelationId;
      readonly journal?: never;
    };

export type EcdsaActivationJournalReadResult =
  | {
      readonly kind: 'found';
      readonly journal: EcdsaCapabilityActivationCommitJournal;
    }
  | {
      readonly kind: 'missing' | 'corrupt' | 'persistence_unavailable';
      readonly journal?: never;
    };

export type EcdsaPreparedActivationCancellationResult =
  | { readonly kind: 'cancelled' }
  | { readonly kind: 'missing' }
  | { readonly kind: 'server_activation_committed' }
  | { readonly kind: 'exact_record_conflict' }
  | { readonly kind: 'corrupt' }
  | { readonly kind: 'persistence_unavailable' };

export type FinalizeEcdsaCapabilityActivationInput = {
  readonly committedJournal: ServerCommittedEcdsaActivationJournal;
  readonly readyMaterial: ValidatedEncryptedEcdsaReadyMaterial;
  readonly activeManifest: ActiveEcdsaCapabilityManifest;
};

type PreparedJournalInputWithoutCandidate<T> = T extends unknown ? Omit<T, 'candidate'> : never;

export type PrepareEcdsaCapabilityActivationInput =
  PreparedJournalInputWithoutCandidate<BuildPreparedEcdsaActivationJournalInput> & {
    readonly activationBinding: EcdsaActivationBinding;
    readonly pendingPayloadB64u: string;
  };

export type RecordEcdsaServerActivationInput = {
  readonly preparedJournal: PreparedEcdsaActivationJournal;
  readonly serverCommit: ServerReturnedEcdsaActivationCommit;
};

export type SealEcdsaCapabilityActivationInput = {
  readonly committedJournal: ServerCommittedEcdsaActivationJournal;
  readonly readyStateBlobB64u: string;
  readonly registeredPublicFacts: VerifiedEcdsaPublicFacts;
  readonly roleLocalPublicFacts: EcdsaRoleLocalPublicFacts;
  readonly routerAbEcdsaDerivationNormalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
  readonly runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
  readonly committedAt: IsoTimestamp;
};

export type ImportCommittedWalletCustodyEcdsaActivationInput = {
  readonly activationBinding: EcdsaActivationBinding;
  readonly serverCommit: ServerReturnedEcdsaActivationCommit;
  readonly readyStateBlobB64u: string;
  readonly registeredPublicFacts: VerifiedEcdsaPublicFacts;
  readonly roleLocalPublicFacts: EcdsaRoleLocalPublicFacts;
  readonly routerAbEcdsaDerivationNormalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
  readonly runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
  readonly committedAt: IsoTimestamp;
};

function activeManifestMatchesWalletCustodyImport(input: {
  readonly manifest: ActiveEcdsaCapabilityManifest;
  readonly activationBinding: EcdsaActivationBinding;
  readonly serverActivation: EcdsaServerActivationCommit;
  readonly registeredPublicFacts: VerifiedEcdsaPublicFacts;
  readonly roleLocalPublicFacts: EcdsaRoleLocalPublicFacts;
  readonly routerAbEcdsaDerivationNormalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
  readonly runtimePolicyScope: RuntimePolicyScope;
}): boolean {
  const manifest = input.manifest;
  const binding = input.activationBinding;
  return (
    canonicalValuesMatch(manifest.signer.authority, binding.signer.authority) &&
    canonicalValuesMatch(manifest.signer.scope, binding.signer.scope) &&
    manifest.signer.walletId === binding.signer.walletId &&
    manifest.signer.capability === binding.signer.capability &&
    manifest.signer.materialOwner === binding.signer.materialOwner &&
    manifest.signer.signingRootId === binding.signer.signingRootId &&
    manifest.signer.signingRootVersion === binding.signer.signingRootVersion &&
    canonicalValuesMatch(manifest.signer.registeredPublicFacts, input.registeredPublicFacts) &&
    canonicalValuesMatch(manifest.activation.serverActivation, input.serverActivation) &&
    mpcMaterialActivationRefsEqual(
      manifest.activation.materialActivation,
      routerAbMpcMaterialActivationRefFromWire(
        input.serverActivation.serverActivationReceipt.protocolReceipt.ecdsa_activation
          .material_activation,
      ),
    ) &&
    canonicalValuesMatch(manifest.durableMaterial.roleLocalBinding, binding.roleLocalBinding) &&
    manifest.durableMaterial.bindingDigest === binding.bindingDigest &&
    canonicalValuesMatch(
      manifest.durableMaterial.roleLocalPublicFacts,
      input.roleLocalPublicFacts,
    ) &&
    canonicalValuesMatch(
      manifest.durableMaterial.routerAbEcdsaDerivationNormalSigning,
      input.routerAbEcdsaDerivationNormalSigning,
    ) &&
    canonicalValuesMatch(
      manifest.durableMaterial.runtimePolicyScope,
      normalizeRuntimePolicyScope(input.runtimePolicyScope),
    )
  );
}

export type EcdsaPreparedActivationOpenResult =
  | {
      readonly kind: 'found';
      readonly journal: EcdsaCapabilityActivationCommitJournal;
      readonly pendingPayloadB64u: string;
    }
  | {
      readonly kind: 'missing' | 'corrupt' | 'persistence_unavailable';
      readonly journal?: never;
      readonly pendingPayloadB64u?: never;
    };

export type EcdsaActiveMaterialOpenResult =
  | {
      readonly kind: 'active';
      readonly manifest: ActiveEcdsaCapabilityManifest;
      readonly readyStateBlobB64u: string;
    }
  | Exclude<EcdsaCapabilityManifestLookup, { readonly kind: 'active' }>;

export type EcdsaActiveMaterialRefOpenResult =
  | {
      readonly kind: 'active';
      readonly manifest: ActiveEcdsaCapabilityManifest;
      readonly readyStateBlobB64u: string;
    }
  | {
      readonly kind: 'missing' | 'binding_mismatch' | 'corrupt' | 'persistence_unavailable';
      readonly manifest?: never;
      readonly readyStateBlobB64u?: never;
    };

type EcdsaCapabilityMaterialRefLookupFailure =
  | {
      readonly kind: 'missing';
      readonly subject: 'capability' | 'material';
      readonly capability: CapabilityInstanceRef;
    }
  | {
      readonly kind:
        | 'exact_binding_mismatch'
        | 'exact_record_conflict'
        | 'corrupt'
        | 'persistence_unavailable';
      readonly capability: CapabilityInstanceRef;
      readonly subject?: never;
    };

export type EcdsaCapabilityMaterialRefLookup =
  | Extract<EcdsaCapabilityManifestLookup, { readonly kind: 'active' | 'retired' }>
  | EcdsaCapabilityMaterialRefLookupFailure;

/**
 * R109C: one cryptographic activation can back several exact method-bound
 * access projections, one per wallet auth method installed on the same wallet
 * authority. A material activation therefore no longer names one manifest.
 * A caller that does not say which method it is acting as gets
 * `ambiguous_authority` and must ask again with the exact authority; picking a
 * sibling here would silently sign under a credential the caller never named.
 */
export type EcdsaCapabilityActivationLookup =
  | Extract<EcdsaCapabilityManifestLookup, { readonly kind: 'active' | 'retired' }>
  | EcdsaCapabilityMaterialRefLookupFailure
  | {
      readonly kind: 'ambiguous_authority';
      readonly capability: CapabilityInstanceRef;
      readonly authorities: readonly WalletAuthAuthorityRef[];
      readonly subject?: never;
    };

export type EcdsaCapabilityActivationFinalizationResult =
  | {
      readonly kind: 'committed';
      readonly manifest: ActiveEcdsaCapabilityManifest;
      readonly material: ValidatedEncryptedEcdsaReadyMaterial;
    }
  | ({
      readonly kind: 'exact_record_conflict';
      readonly selector: EcdsaCapabilitySelector;
      readonly conflictDigest: DigestB64u;
    } & LookupFailureExclusions)
  | ({
      readonly kind: 'corrupt';
      readonly selector: EcdsaCapabilitySelector;
      readonly corruptionDigest: DigestB64u;
    } & LookupFailureExclusions)
  | ({
      readonly kind: 'persistence_unavailable';
      readonly selector: EcdsaCapabilitySelector;
      readonly retryCorrelation: CorrelationId;
    } & LookupFailureExclusions);

type ParsedActiveManifestProof = {
  readonly activationBinding: EcdsaActivationBinding;
  readonly serverActivation: EcdsaServerActivationCommit;
  readonly durableMaterial: DurableEcdsaMaterialBinding;
  readonly activeManifest: ActiveEcdsaCapabilityManifest;
  readonly committedAt: IsoTimestamp;
};

type ParsedManifestRow =
  | {
      readonly state: 'active';
      readonly selector: EcdsaCapabilitySelector;
      readonly manifest: ActiveEcdsaCapabilityManifest;
      readonly activeProof: ParsedActiveManifestProof;
    }
  | {
      readonly state: 'replaced';
      readonly selector: EcdsaCapabilitySelector;
      readonly manifest: ReplacedEcdsaCapabilityManifest;
      readonly activeProof: ParsedActiveManifestProof;
      readonly replacementProof: ParsedActiveManifestProof;
    };

type ParsedPointerRow = {
  readonly selector: EcdsaCapabilitySelector;
  readonly manifestId: EcdsaCapabilityManifestId;
  readonly manifestRevision: EcdsaCapabilityManifestRevision;
};

type ParsedSealingKeyRow = {
  readonly keyId: EcdsaMaterialSealingKeyId;
  readonly key: CryptoKey;
};

type LookupTransactionObservation =
  | {
      readonly kind: 'active';
      readonly manifest: ActiveEcdsaCapabilityManifest;
      readonly material: ValidatedEncryptedEcdsaReadyMaterial;
    }
  | {
      readonly kind: 'retired';
      readonly manifest: ReplacedEcdsaCapabilityManifest;
    }
  | {
      readonly kind: 'missing';
      readonly subject: 'capability' | 'material';
      readonly detail: string;
    }
  | {
      readonly kind: 'exact_binding_mismatch' | 'exact_record_conflict' | 'corrupt';
      readonly detail: string;
    };

type FinalizationControlKind = 'exact_record_conflict' | 'corrupt';

class FinalizationControlError extends Error {
  readonly kind: FinalizationControlKind;

  constructor(kind: FinalizationControlKind, message: string) {
    super(message);
    this.name = 'FinalizationControlError';
    this.kind = kind;
  }
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireExactKeys(
  record: Record<string, unknown>,
  label: string,
  expectedKeys: readonly string[],
): void {
  const actual = Object.keys(record).sort();
  const expected = [...expectedKeys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((field, index) => field !== expected[index])
  ) {
    throw new Error(`${label} has unexpected fields`);
  }
}

function requireArray(value: unknown, label: string): readonly unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value;
}

function unwrapDomainId<T>(result: DomainIdParseResult<T>): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function normalizeSelector(selector: EcdsaCapabilitySelector): EcdsaCapabilitySelector {
  const authority = parseWalletAuthAuthorityRef(selector.authority);
  if (!authority) throw new Error('ECDSA capability selector authority is invalid');
  return {
    capability: unwrapDomainId(parseCapabilityInstanceRef(selector.capability)),
    authority,
  };
}

function selectorFromJournal(
  journal: EcdsaCapabilityActivationCommitJournal,
): EcdsaCapabilitySelector {
  return {
    capability: journal.candidate.activationBinding.signer.capability,
    authority: journal.candidate.activationBinding.signer.authority,
  };
}

function selectorFromManifest(manifest: ActiveEcdsaCapabilityManifest): EcdsaCapabilitySelector {
  return {
    capability: manifest.signer.capability,
    authority: manifest.signer.authority,
  };
}

function selectorKey(selector: EcdsaCapabilitySelector): readonly [string, string, string] {
  return [
    String(selector.capability),
    String(selector.authority.walletId),
    String(selector.authority.authorityDigest),
  ];
}

function walletAuthAuthorityRefsMatch(
  left: WalletAuthAuthorityRef,
  right: WalletAuthAuthorityRef,
): boolean {
  return (
    left.walletId === right.walletId &&
    left.authorityDigest === right.authorityDigest &&
    left.walletAuthMethodId === right.walletAuthMethodId
  );
}

function selectorsMatch(left: EcdsaCapabilitySelector, right: EcdsaCapabilitySelector): boolean {
  const leftKey = selectorKey(left);
  const rightKey = selectorKey(right);
  return leftKey[0] === rightKey[0] && leftKey[1] === rightKey[1] && leftKey[2] === rightKey[2];
}

function canonicalValuesMatch(left: unknown, right: unknown): boolean {
  return alphabetizeStringify(left) === alphabetizeStringify(right);
}

async function persistenceDigest(
  category: string,
  selector: EcdsaCapabilitySelector,
  detail: string,
): Promise<DigestB64u> {
  const canonical = alphabetizeStringify({
    category,
    capability_ref: selector.capability,
    wallet_id: selector.authority.walletId,
    authority_digest: selector.authority.authorityDigest,
    wallet_auth_method_id: selector.authority.walletAuthMethodId,
    detail,
  });
  return parseDigestB64u(base64UrlEncode(await sha256BytesUtf8(canonical)));
}

function retryCorrelation(): CorrelationId {
  return parseCorrelationId(
    secureRandomId('ecdsa-persistence-retry', 16, 'ECDSA persistence retry correlations'),
  );
}

function buildPreparedJournalFromEncryptedCandidate(input: {
  readonly preparation: PrepareEcdsaCapabilityActivationInput;
  readonly encryptedPending: EncryptedEcdsaPendingCandidate;
}): PreparedEcdsaActivationJournal {
  const candidate = buildPreparedEcdsaActivationCandidate({
    activationBinding: input.preparation.activationBinding,
    encryptedPending: input.encryptedPending,
  });
  switch (input.preparation.expectedManifest.kind) {
    case 'no_current_manifest':
      if (input.preparation.expectedGeneration.kind !== 'no_current_generation') {
        throw new Error('Initial ECDSA activation cannot expect a server generation');
      }
      return buildPreparedEcdsaActivationJournal({
        journalId: input.preparation.journalId,
        expectedManifest: input.preparation.expectedManifest,
        expectedGeneration: input.preparation.expectedGeneration,
        candidate,
        requestDigest: input.preparation.requestDigest,
        canonicalRequest: input.preparation.canonicalRequest,
        createdAt: input.preparation.createdAt,
      });
    case 'exact_manifest':
      if (input.preparation.expectedGeneration.kind !== 'exact_generation') {
        throw new Error('Replacement ECDSA activation requires an exact server generation');
      }
      return buildPreparedEcdsaActivationJournal({
        journalId: input.preparation.journalId,
        expectedManifest: input.preparation.expectedManifest,
        expectedGeneration: input.preparation.expectedGeneration,
        candidate,
        requestDigest: input.preparation.requestDigest,
        canonicalRequest: input.preparation.canonicalRequest,
        createdAt: input.preparation.createdAt,
      });
    default:
      return assertNever(input.preparation.expectedManifest);
  }
}

function decodeCanonicalStateBlob(value: string, label: string): Uint8Array {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`${label} must be non-empty unpadded base64url`);
  }
  const bytes = base64UrlDecode(value);
  if (bytes.length === 0 || base64UrlEncode(bytes) !== value) {
    bytes.fill(0);
    throw new Error(`${label} must be canonical base64url`);
  }
  return bytes;
}

function activationBindingAadProjection(binding: EcdsaActivationBinding) {
  return {
    target_manifest: binding.targetManifest,
    signer: {
      capability: binding.signer.capability,
      signer_id: binding.signer.signerId,
      wallet_id: binding.signer.walletId,
      authority: binding.signer.authority,
      scope: binding.signer.scope,
      material_owner: binding.signer.materialOwner,
      signing_root_id: binding.signer.signingRootId,
      signing_root_version: binding.signer.signingRootVersion,
    },
    role_local_binding: binding.roleLocalBinding,
    binding_digest: binding.bindingDigest,
    durable_material_ref: binding.durableMaterialRef,
  };
}

function activeManifestBindingAadProjection(manifest: ActiveEcdsaCapabilityManifest) {
  return {
    target_manifest: manifest.identity,
    signer: {
      capability: manifest.signer.capability,
      signer_id: manifest.signer.signerId,
      wallet_id: manifest.signer.walletId,
      authority: manifest.signer.authority,
      scope: manifest.signer.scope,
      material_owner: manifest.signer.materialOwner,
      signing_root_id: manifest.signer.signingRootId,
      signing_root_version: manifest.signer.signingRootVersion,
    },
    role_local_binding: manifest.durableMaterial.roleLocalBinding,
    binding_digest: manifest.durableMaterial.bindingDigest,
    durable_material_ref: manifest.durableMaterial.durableMaterialRef,
  };
}

function pendingAadProjection(
  input:
    | PrepareEcdsaCapabilityActivationInput
    | PreparedEcdsaActivationJournal
    | ServerCommittedEcdsaActivationJournal,
) {
  if ('activationBinding' in input) {
    return {
      version: MATERIAL_AAD_VERSION,
      stage: 'activation_prepared',
      journal_id: input.journalId,
      expected_manifest: input.expectedManifest,
      activation_command: {
        kind: 'ecdsa_server_activation_command',
        correlationId: input.journalId,
        expectedGeneration: input.expectedGeneration,
        requestDigest: input.requestDigest,
        canonicalRequest: input.canonicalRequest,
      },
      activation_binding: activationBindingAadProjection(input.activationBinding),
      created_at: input.createdAt,
    };
  }
  return {
    version: MATERIAL_AAD_VERSION,
    stage: 'activation_prepared',
    journal_id: input.journalId,
    expected_manifest: input.expectedManifest,
    activation_command: input.activationCommand,
    activation_binding: activationBindingAadProjection(input.candidate.activationBinding),
    created_at: input.createdAt,
  };
}

function readyAadProjection(
  input: ServerCommittedEcdsaActivationJournal | ActiveEcdsaCapabilityManifest,
) {
  const activationBinding =
    input.kind === 'server_activation_committed'
      ? activationBindingAadProjection(input.candidate.activationBinding)
      : activeManifestBindingAadProjection(input);
  const serverActivation =
    input.kind === 'server_activation_committed'
      ? input.serverActivation
      : input.activation.serverActivation;
  return {
    version: MATERIAL_AAD_VERSION,
    stage: 'activation_ready',
    activation_binding: activationBinding,
    server_activation: serverActivation,
  };
}

function importedReadyAadProjection(input: {
  readonly activationBinding: EcdsaActivationBinding;
  readonly serverActivation: EcdsaServerActivationCommit;
}) {
  return {
    version: MATERIAL_AAD_VERSION,
    stage: 'activation_ready',
    activation_binding: activationBindingAadProjection(input.activationBinding),
    server_activation: input.serverActivation,
  };
}

function additionalData(projection: unknown): Uint8Array {
  return new TextEncoder().encode(alphabetizeStringify(projection));
}

async function generateMaterialSealingKey(): Promise<CryptoKey> {
  return await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
}

async function encryptStateBlob(input: {
  readonly key: CryptoKey;
  readonly stateBlobB64u: string;
  readonly aadProjection: unknown;
}): Promise<{
  readonly iv12B64u: ReturnType<typeof parseEcdsaIv12B64u>;
  readonly ciphertextB64u: ReturnType<typeof parseEcdsaCiphertextB64u>;
  readonly digestB64u: string;
}> {
  const plaintext = decodeCanonicalStateBlob(input.stateBlobB64u, 'ECDSA state blob');
  const iv12 = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
  const aad = additionalData(input.aadProjection);
  try {
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv12, additionalData: aad },
        input.key,
        plaintext,
      ),
    );
    try {
      return {
        iv12B64u: parseEcdsaIv12B64u(base64UrlEncode(iv12)),
        ciphertextB64u: parseEcdsaCiphertextB64u(base64UrlEncode(ciphertext)),
        digestB64u: base64UrlEncode(await sha256Bytes(ciphertext)),
      };
    } finally {
      ciphertext.fill(0);
    }
  } finally {
    plaintext.fill(0);
    aad.fill(0);
  }
}

async function ciphertextDigestB64u(ciphertextB64u: string): Promise<string> {
  const ciphertext = base64UrlDecode(ciphertextB64u);
  try {
    return base64UrlEncode(await sha256Bytes(ciphertext));
  } finally {
    ciphertext.fill(0);
  }
}

async function decryptStateBlob(input: {
  readonly key: CryptoKey;
  readonly iv12B64u: string;
  readonly ciphertextB64u: string;
  readonly aadProjection: unknown;
}): Promise<string> {
  const iv12 = base64UrlDecode(input.iv12B64u);
  const ciphertext = base64UrlDecode(input.ciphertextB64u);
  const aad = additionalData(input.aadProjection);
  let plaintext: Uint8Array | null = null;
  try {
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv12, additionalData: aad },
        input.key,
        ciphertext,
      ),
    );
    if (plaintext.length === 0) {
      throw new Error('decrypted ECDSA state blob must not be empty');
    }
    return base64UrlEncode(plaintext);
  } finally {
    iv12.fill(0);
    ciphertext.fill(0);
    aad.fill(0);
    plaintext?.fill(0);
  }
}

function parseManifestIdentity(value: unknown) {
  const record = requireRecord(value, 'ECDSA manifest identity');
  requireExactKeys(record, 'ECDSA manifest identity', ['manifestId', 'manifestRevision']);
  return buildEcdsaManifestIdentity({
    manifestId: parseEcdsaCapabilityManifestId(record.manifestId),
    manifestRevision: parseEcdsaCapabilityManifestRevision(record.manifestRevision),
  });
}

function parseManifestExpectation(value: unknown): EcdsaManifestRevisionExpectation {
  const record = requireRecord(value, 'ECDSA manifest expectation');
  switch (record.kind) {
    case 'no_current_manifest':
      requireExactKeys(record, 'ECDSA no-current manifest expectation', ['kind']);
      return buildNoCurrentEcdsaManifestExpectation();
    case 'exact_manifest':
      requireExactKeys(record, 'ECDSA exact manifest expectation', [
        'kind',
        'manifestId',
        'manifestRevision',
      ]);
      return buildExactEcdsaManifestExpectation(
        buildEcdsaManifestIdentity({
          manifestId: parseEcdsaCapabilityManifestId(record.manifestId),
          manifestRevision: parseEcdsaCapabilityManifestRevision(record.manifestRevision),
        }),
      );
    default:
      throw new Error('ECDSA manifest expectation kind is invalid');
  }
}

function parseChainTarget(value: unknown) {
  const record = requireRecord(value, 'ECDSA capability target');
  switch (record.kind) {
    case 'evm':
      requireExactKeys(record, 'ECDSA EVM capability target', [
        'kind',
        'namespace',
        'chainId',
        'networkSlug',
      ]);
      return thresholdEcdsaChainTargetFromRequest({
        kind: record.kind,
        namespace: record.namespace,
        chainId: record.chainId,
        networkSlug: record.networkSlug,
      });
    case 'tempo':
      requireExactKeys(record, 'ECDSA Tempo capability target', ['kind', 'chainId', 'networkSlug']);
      return thresholdEcdsaChainTargetFromRequest({
        kind: record.kind,
        chainId: record.chainId,
        networkSlug: record.networkSlug,
      });
    default:
      throw new Error('ECDSA capability target kind is invalid');
  }
}

function parseCapabilityScope(value: unknown) {
  const record = requireRecord(value, 'ECDSA capability scope');
  requireExactKeys(record, 'ECDSA capability scope', ['kind', 'targetMemberships']);
  if (record.kind !== 'evm_family') throw new Error('ECDSA capability scope kind is invalid');
  const targetValues = requireArray(
    record.targetMemberships,
    'ECDSA capability target memberships',
  );
  const targets = [];
  for (const targetValue of targetValues) targets.push(parseChainTarget(targetValue));
  const [first, ...rest] = targets;
  if (!first) throw new Error('ECDSA capability scope requires at least one target');
  return buildEcdsaCapabilityScope({
    targetMemberships: [first, ...rest],
  });
}

function parseRoleLocalBinding(value: unknown) {
  const record = requireRecord(value, 'ECDSA role-local material binding');
  requireExactKeys(record, 'ECDSA role-local material binding', [
    'kind',
    'keyHandle',
    'ecdsaThresholdKeyId',
    'clientVerifyingPublicKey33B64u',
    'participantIds',
    'relayerKeyId',
  ]);
  if (record.kind !== 'ecdsa_role_local_material_binding') {
    throw new Error('ECDSA role-local material binding kind is invalid');
  }
  const participantValues = requireArray(record.participantIds, 'ECDSA role-local participant ids');
  const participantIds = [];
  for (const participantValue of participantValues) {
    participantIds.push(toParticipantId(participantValue));
  }
  const [firstParticipantId, ...remainingParticipantIds] = participantIds;
  if (!firstParticipantId) {
    throw new Error('ECDSA role-local material requires at least one participant');
  }
  return buildEcdsaRoleLocalMaterialBinding({
    keyHandle: parseEcdsaKeyHandle(record.keyHandle),
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(record.ecdsaThresholdKeyId),
    clientVerifyingPublicKey33B64u: parseEcdsaClientVerifyingPublicKey33B64u(
      record.clientVerifyingPublicKey33B64u,
    ),
    participantIds: [firstParticipantId, ...remainingParticipantIds],
    relayerKeyId: parseEcdsaRelayerKeyId(record.relayerKeyId),
  });
}

function parsePreparedSigner(value: unknown) {
  const record = requireRecord(value, 'prepared ECDSA signer');
  requireExactKeys(record, 'prepared ECDSA signer', [
    'kind',
    'capability',
    'signerId',
    'walletId',
    'authority',
    'scope',
    'materialOwner',
    'signingRootId',
    'signingRootVersion',
  ]);
  if (record.kind !== 'prepared_evm_family_signer') {
    throw new Error('prepared ECDSA signer kind is invalid');
  }
  const authority = parseWalletAuthAuthorityRef(record.authority);
  if (!authority) throw new Error('prepared ECDSA signer authority is invalid');
  if (String(record.walletId) !== String(authority.walletId)) {
    throw new Error('prepared ECDSA signer wallet does not match its authority');
  }
  return buildPreparedEvmFamilySigner({
    capability: unwrapDomainId(parseCapabilityInstanceRef(record.capability)),
    signerId: parseEvmFamilyEcdsaSignerId(record.signerId),
    authority,
    scope: parseCapabilityScope(record.scope),
    materialOwner: unwrapDomainId(parseMpcMaterialOwnerRef(record.materialOwner)),
    signingRootId: parseSdkEcdsaDerivationSigningRootId(record.signingRootId),
    signingRootVersion: parseSdkEcdsaDerivationSigningRootVersion(record.signingRootVersion),
  });
}

function parseEncryptedPendingCandidate(value: unknown) {
  const record = requireRecord(value, 'encrypted ECDSA pending candidate');
  requireExactKeys(record, 'encrypted ECDSA pending candidate', [
    'kind',
    'sealingKeyId',
    'iv12B64u',
    'ciphertextB64u',
    'ciphertextDigest',
  ]);
  if (record.kind !== 'encrypted_ecdsa_pending_candidate') {
    throw new Error('encrypted ECDSA pending candidate kind is invalid');
  }
  return buildEncryptedEcdsaPendingCandidate({
    sealingKeyId: parseEcdsaMaterialSealingKeyId(record.sealingKeyId),
    iv12B64u: parseEcdsaIv12B64u(record.iv12B64u),
    ciphertextB64u: parseEcdsaCiphertextB64u(record.ciphertextB64u),
    ciphertextDigest: parseEcdsaPendingCiphertextDigest(record.ciphertextDigest),
  });
}

function parseActivationBinding(value: unknown): EcdsaActivationBinding {
  const record = requireRecord(value, 'ECDSA activation binding');
  requireExactKeys(record, 'ECDSA activation binding', [
    'kind',
    'targetManifest',
    'signer',
    'roleLocalBinding',
    'bindingDigest',
    'durableMaterialRef',
  ]);
  if (record.kind !== 'ecdsa_activation_binding') {
    throw new Error('ECDSA activation binding kind is invalid');
  }
  return buildEcdsaActivationBinding({
    targetManifest: parseManifestIdentity(record.targetManifest),
    signer: parsePreparedSigner(record.signer),
    roleLocalBinding: parseRoleLocalBinding(record.roleLocalBinding),
    bindingDigest: parseEcdsaRoleLocalBindingDigest(record.bindingDigest),
    durableMaterialRef: parseEcdsaRoleLocalDurableMaterialRef(record.durableMaterialRef),
  });
}

function parsePreparedCandidate(value: unknown) {
  const record = requireRecord(value, 'prepared ECDSA activation candidate');
  requireExactKeys(record, 'prepared ECDSA activation candidate', [
    'kind',
    'activationBinding',
    'encryptedPending',
  ]);
  if (record.kind !== 'prepared_ecdsa_activation_candidate') {
    throw new Error('prepared ECDSA activation candidate kind is invalid');
  }
  return buildPreparedEcdsaActivationCandidate({
    activationBinding: parseActivationBinding(record.activationBinding),
    encryptedPending: parseEncryptedPendingCandidate(record.encryptedPending),
  });
}

function parseExpectedServerGeneration(value: unknown) {
  const record = requireRecord(value, 'ECDSA server generation expectation');
  switch (record.kind) {
    case 'no_current_generation':
      requireExactKeys(record, 'ECDSA no-current server generation expectation', ['kind']);
      return buildNoCurrentEcdsaServerGenerationExpectation();
    case 'exact_generation':
      requireExactKeys(record, 'ECDSA exact server generation expectation', [
        'kind',
        'serverGeneration',
      ]);
      return buildExactEcdsaServerGenerationExpectation(
        parseEcdsaServerGeneration(record.serverGeneration),
      );
    default:
      throw new Error('ECDSA server generation expectation kind is invalid');
  }
}

function parsePreparedJournal(value: unknown): PreparedEcdsaActivationJournal {
  const record = requireRecord(value, 'prepared ECDSA activation journal');
  requireExactKeys(record, 'prepared ECDSA activation journal', [
    'kind',
    'journalId',
    'expectedManifest',
    'activationCommand',
    'candidate',
    'createdAt',
  ]);
  if (record.kind !== 'activation_prepared') {
    throw new Error('prepared ECDSA activation journal kind is invalid');
  }
  const command = requireRecord(record.activationCommand, 'ECDSA activation command');
  requireExactKeys(command, 'ECDSA activation command', [
    'kind',
    'correlationId',
    'expectedGeneration',
    'requestDigest',
    'canonicalRequest',
  ]);
  if (command.kind !== 'ecdsa_server_activation_command') {
    throw new Error('ECDSA activation command kind is invalid');
  }
  const journalId = parseCorrelationId(record.journalId);
  if (parseCorrelationId(command.correlationId) !== journalId) {
    throw new Error('ECDSA activation command correlation does not match its journal');
  }
  const expectedManifest = parseManifestExpectation(record.expectedManifest);
  const expectedGeneration = parseExpectedServerGeneration(command.expectedGeneration);
  const common = {
    journalId,
    candidate: parsePreparedCandidate(record.candidate),
    requestDigest: parseDigestB64u(command.requestDigest),
    canonicalRequest: parseCanonicalEcdsaServerActivationRequest(command.canonicalRequest),
    createdAt: parseIsoTimestamp(record.createdAt),
  };
  switch (expectedManifest.kind) {
    case 'no_current_manifest':
      if (expectedGeneration.kind !== 'no_current_generation') {
        throw new Error('initial ECDSA journal has an exact server generation');
      }
      return buildPreparedEcdsaActivationJournal({
        ...common,
        expectedManifest,
        expectedGeneration,
      });
    case 'exact_manifest':
      if (expectedGeneration.kind !== 'exact_generation') {
        throw new Error('replacement ECDSA journal is missing its exact server generation');
      }
      return buildPreparedEcdsaActivationJournal({
        ...common,
        expectedManifest,
        expectedGeneration,
      });
  }
  return assertNever(expectedManifest);
}

function preparedJournalValueFromCommitted(
  record: Record<string, unknown>,
): Record<string, unknown> {
  return {
    kind: 'activation_prepared',
    journalId: record.journalId,
    expectedManifest: record.expectedManifest,
    activationCommand: record.activationCommand,
    candidate: record.candidate,
    createdAt: record.createdAt,
  };
}

function preparedJournalProjection(
  journal: EcdsaCapabilityActivationCommitJournal,
): PreparedEcdsaActivationJournal | Record<string, unknown> {
  if (journal.kind === 'activation_prepared') return journal;
  return {
    kind: 'activation_prepared',
    journalId: journal.journalId,
    expectedManifest: journal.expectedManifest,
    activationCommand: journal.activationCommand,
    candidate: journal.candidate,
    createdAt: journal.createdAt,
  };
}

function parseCommittedJournal(value: unknown): ServerCommittedEcdsaActivationJournal {
  const record = requireRecord(value, 'server-committed ECDSA activation journal');
  requireExactKeys(record, 'server-committed ECDSA activation journal', [
    'kind',
    'journalId',
    'expectedManifest',
    'activationCommand',
    'candidate',
    'createdAt',
    'serverActivation',
  ]);
  if (record.kind !== 'server_activation_committed') {
    throw new Error('server-committed ECDSA activation journal kind is invalid');
  }
  const preparedJournal = parsePreparedJournal(preparedJournalValueFromCommitted(record));
  const serverActivation = requireRecord(record.serverActivation, 'ECDSA server activation commit');
  requireExactKeys(serverActivation, 'ECDSA server activation commit', [
    'kind',
    'correlationId',
    'activationRequestDigest',
    'serverGeneration',
    'serverActivationReceipt',
  ]);
  if (serverActivation.kind !== 'ecdsa_server_activation_commit') {
    throw new Error('ECDSA server activation commit kind is invalid');
  }
  const receipt = requireRecord(
    serverActivation.serverActivationReceipt,
    'ECDSA server activation receipt',
  );
  requireExactKeys(receipt, 'ECDSA server activation receipt', [
    'kind',
    'lifecycleId',
    'activationDigest',
    'activatedAt',
    'protocolReceipt',
  ]);
  if (receipt.kind !== 'ecdsa_server_activation_receipt') {
    throw new Error('ECDSA server activation receipt kind is invalid');
  }
  const committed = buildServerCommittedEcdsaActivationJournal({
    preparedJournal,
    serverCommit: {
      correlationId: parseCorrelationId(serverActivation.correlationId),
      activationRequestDigest: parseDigestB64u(serverActivation.activationRequestDigest),
      serverGeneration: parseEcdsaServerGeneration(serverActivation.serverGeneration),
      protocolReceipt: receipt.protocolReceipt,
    },
  });
  if (!canonicalValuesMatch(committed.serverActivation, serverActivation)) {
    throw new Error('ECDSA server activation commit fields are inconsistent');
  }
  return committed;
}

function parseJournal(value: unknown): EcdsaCapabilityActivationCommitJournal {
  const record = requireRecord(value, 'ECDSA activation journal');
  switch (record.kind) {
    case 'activation_prepared':
      return parsePreparedJournal(record);
    case 'server_activation_committed':
      return parseCommittedJournal(record);
    default:
      throw new Error('ECDSA activation journal kind is invalid');
  }
}

function parseRegisteredPublicFacts(value: unknown) {
  const record = requireRecord(value, 'registered ECDSA public facts');
  requireExactKeys(record, 'registered ECDSA public facts', [
    'kind',
    'keyHandle',
    'publicKeyB64u',
    'participantIds',
    'thresholdOwnerAddress',
  ]);
  if (record.kind !== 'verified_ecdsa_public_facts') {
    throw new Error('registered ECDSA public facts kind is invalid');
  }
  return buildVerifiedEcdsaPublicFacts({
    keyHandle: toEvmFamilyEcdsaKeyHandle(record.keyHandle),
    publicKeyB64u: record.publicKeyB64u,
    participantIds: requireArray(record.participantIds, 'registered ECDSA participant ids'),
    thresholdOwnerAddress: record.thresholdOwnerAddress,
  });
}

function storedActiveProof(input: ParsedActiveManifestProof) {
  return {
    activation_binding: input.activationBinding,
    server_activation: input.serverActivation,
    registered_public_facts: input.activeManifest.signer.registeredPublicFacts,
    role_local_public_facts: input.durableMaterial.roleLocalPublicFacts,
    router_ab_ecdsa_derivation_normal_signing:
      input.durableMaterial.routerAbEcdsaDerivationNormalSigning,
    runtime_policy_scope: input.durableMaterial.runtimePolicyScope,
    ciphertext_digest: input.durableMaterial.ciphertextDigest,
    committed_at: input.activeManifest.committedAt,
  };
}

function parseActiveProof(value: unknown): ParsedActiveManifestProof {
  const record = requireRecord(value, 'active ECDSA manifest proof');
  requireExactKeys(record, 'active ECDSA manifest proof', [
    'activation_binding',
    'server_activation',
    'registered_public_facts',
    'role_local_public_facts',
    'router_ab_ecdsa_derivation_normal_signing',
    'runtime_policy_scope',
    'ciphertext_digest',
    'committed_at',
  ]);
  const activationBinding = parseActivationBinding(record.activation_binding);
  const serverActivationRecord = requireRecord(
    record.server_activation,
    'ECDSA server activation commit',
  );
  requireExactKeys(serverActivationRecord, 'ECDSA server activation commit', [
    'kind',
    'correlationId',
    'activationRequestDigest',
    'serverGeneration',
    'serverActivationReceipt',
  ]);
  if (serverActivationRecord.kind !== 'ecdsa_server_activation_commit') {
    throw new Error('ECDSA server activation commit kind is invalid');
  }
  const receipt = requireRecord(
    serverActivationRecord.serverActivationReceipt,
    'ECDSA server activation receipt',
  );
  requireExactKeys(receipt, 'ECDSA server activation receipt', [
    'kind',
    'lifecycleId',
    'activationDigest',
    'activatedAt',
    'protocolReceipt',
  ]);
  if (receipt.kind !== 'ecdsa_server_activation_receipt') {
    throw new Error('ECDSA server activation receipt kind is invalid');
  }
  const serverActivation = buildEcdsaServerActivationCommit({
    activationBinding,
    serverCommit: {
      correlationId: parseCorrelationId(serverActivationRecord.correlationId),
      activationRequestDigest: parseDigestB64u(serverActivationRecord.activationRequestDigest),
      serverGeneration: parseEcdsaServerGeneration(serverActivationRecord.serverGeneration),
      protocolReceipt: receipt.protocolReceipt,
    },
  });
  if (!canonicalValuesMatch(serverActivation, serverActivationRecord)) {
    throw new Error('ECDSA server activation commit fields are inconsistent');
  }
  const durableMaterial = buildDurableEcdsaMaterialBinding({
    activationBinding,
    serverActivation,
    routerAbEcdsaDerivationNormalSigning: requireRouterAbEcdsaDerivationNormalSigningStateV1(
      record.router_ab_ecdsa_derivation_normal_signing,
    ),
    roleLocalPublicFacts: buildEcdsaRoleLocalPublicFacts(record.role_local_public_facts),
    ciphertextDigest: parseEcdsaCiphertextDigest(record.ciphertext_digest),
    runtimePolicyScope: normalizeRuntimePolicyScope(record.runtime_policy_scope),
  });
  const committedAt = parseIsoTimestamp(record.committed_at);
  const activeManifest = buildActiveEcdsaCapabilityManifest({
    activationBinding,
    serverActivation,
    registeredPublicFacts: parseRegisteredPublicFacts(record.registered_public_facts),
    durableMaterial,
    committedAt,
  });
  return {
    activationBinding,
    serverActivation,
    durableMaterial,
    activeManifest,
    committedAt,
  };
}

function manifestRowCommon(proof: ParsedActiveManifestProof, manifestState: 'active' | 'replaced') {
  const selector = selectorFromManifest(proof.activeManifest);
  return {
    record_version: MANIFEST_RECORD_VERSION,
    manifest_id: proof.activeManifest.identity.manifestId,
    manifest_revision: proof.activeManifest.identity.manifestRevision,
    capability_ref: selector.capability,
    wallet_id: selector.authority.walletId,
    authority_digest: selector.authority.authorityDigest,
    wallet_auth_method_id: selector.authority.walletAuthMethodId,
    manifest_state: manifestState,
  };
}

function storedActiveManifestRow(proof: ParsedActiveManifestProof) {
  return {
    ...manifestRowCommon(proof, 'active'),
    active_proof: storedActiveProof(proof),
  };
}

function storedReplacedManifestRow(
  previous: ParsedActiveManifestProof,
  replacement: ParsedActiveManifestProof,
) {
  return {
    ...manifestRowCommon(previous, 'replaced'),
    active_proof: storedActiveProof(previous),
    replacement_proof: storedActiveProof(replacement),
  };
}

function parseManifestRow(value: unknown): ParsedManifestRow {
  const record = requireRecord(value, 'ECDSA capability manifest row');
  const commonKeys = [
    'record_version',
    'manifest_id',
    'manifest_revision',
    'capability_ref',
    'wallet_id',
    'authority_digest',
    'wallet_auth_method_id',
    'manifest_state',
    'active_proof',
  ];
  switch (record.manifest_state) {
    case 'active': {
      requireExactKeys(record, 'active ECDSA capability manifest row', commonKeys);
      const activeProof = parseActiveProof(record.active_proof);
      const selector = selectorFromManifest(activeProof.activeManifest);
      assertManifestRowCommon(record, activeProof.activeManifest, selector);
      return {
        state: 'active',
        selector,
        manifest: activeProof.activeManifest,
        activeProof,
      };
    }
    case 'replaced': {
      requireExactKeys(record, 'replaced ECDSA capability manifest row', [
        ...commonKeys,
        'replacement_proof',
      ]);
      const activeProof = parseActiveProof(record.active_proof);
      const replacementProof = parseActiveProof(record.replacement_proof);
      const manifest = buildReplacedEcdsaCapabilityManifest({
        activeManifest: activeProof.activeManifest,
        replacementManifest: replacementProof.activeManifest,
      });
      const selector = selectorFromManifest(activeProof.activeManifest);
      assertManifestRowCommon(record, activeProof.activeManifest, selector);
      return {
        state: 'replaced',
        selector,
        manifest,
        activeProof,
        replacementProof,
      };
    }
    default:
      throw new Error('ECDSA capability manifest row state is invalid');
  }
}

function assertManifestRowCommon(
  record: Record<string, unknown>,
  manifest: ActiveEcdsaCapabilityManifest,
  selector: EcdsaCapabilitySelector,
): void {
  if (
    record.record_version !== MANIFEST_RECORD_VERSION ||
    parseEcdsaCapabilityManifestId(record.manifest_id) !== manifest.identity.manifestId ||
    parseEcdsaCapabilityManifestRevision(record.manifest_revision) !==
      manifest.identity.manifestRevision ||
    String(record.capability_ref) !== String(selector.capability) ||
    String(record.wallet_id) !== String(selector.authority.walletId) ||
    String(record.authority_digest) !== String(selector.authority.authorityDigest)
  ) {
    throw new Error('ECDSA capability manifest row identity is inconsistent');
  }
}

function storedPointerRow(manifest: ActiveEcdsaCapabilityManifest) {
  const selector = selectorFromManifest(manifest);
  return {
    record_version: POINTER_RECORD_VERSION,
    capability_ref: selector.capability,
    wallet_id: selector.authority.walletId,
    authority_digest: selector.authority.authorityDigest,
    wallet_auth_method_id: selector.authority.walletAuthMethodId,
    manifest_id: manifest.identity.manifestId,
    manifest_revision: manifest.identity.manifestRevision,
  };
}

function parsePointerRow(value: unknown): ParsedPointerRow {
  const record = requireRecord(value, 'current ECDSA capability pointer');
  requireExactKeys(record, 'current ECDSA capability pointer', [
    'record_version',
    'capability_ref',
    'wallet_id',
    'authority_digest',
    'wallet_auth_method_id',
    'manifest_id',
    'manifest_revision',
  ]);
  if (record.record_version !== POINTER_RECORD_VERSION) {
    throw new Error('current ECDSA capability pointer version is invalid');
  }
  const authority = parseWalletAuthAuthorityRef({
    kind: 'wallet_auth_authority_ref',
    walletId: record.wallet_id,
    authorityDigest: record.authority_digest,
    walletAuthMethodId: record.wallet_auth_method_id,
  });
  if (!authority) throw new Error('current ECDSA capability pointer authority is invalid');
  return {
    selector: {
      capability: unwrapDomainId(parseCapabilityInstanceRef(record.capability_ref)),
      authority,
    },
    manifestId: parseEcdsaCapabilityManifestId(record.manifest_id),
    manifestRevision: parseEcdsaCapabilityManifestRevision(record.manifest_revision),
  };
}

function storedMaterialRow(
  material: ValidatedEncryptedEcdsaReadyMaterial,
  manifest: ActiveEcdsaCapabilityManifest,
) {
  const selector = selectorFromManifest(manifest);
  return {
    record_version: MATERIAL_RECORD_VERSION,
    durable_material_ref: material.binding.durableMaterialRef,
    binding_digest: material.binding.bindingDigest,
    capability_ref: selector.capability,
    wallet_id: selector.authority.walletId,
    authority_digest: selector.authority.authorityDigest,
    wallet_auth_method_id: selector.authority.walletAuthMethodId,
    sealing_key_id: material.sealingKeyId,
    iv: material.iv12B64u,
    ciphertext: material.ciphertextB64u,
  };
}

type ParsedMaterialLocator = {
  readonly durableMaterialRef: ReturnType<typeof parseEcdsaRoleLocalDurableMaterialRef>;
  readonly bindingDigest: ReturnType<typeof parseEcdsaRoleLocalBindingDigest>;
  readonly selector: EcdsaCapabilitySelector;
};

function parseMaterialLocator(value: unknown): ParsedMaterialLocator {
  const record = requireRecord(value, 'ECDSA role-local material row');
  requireExactKeys(record, 'ECDSA role-local material row', [
    'record_version',
    'durable_material_ref',
    'binding_digest',
    'capability_ref',
    'wallet_id',
    'authority_digest',
    'wallet_auth_method_id',
    'sealing_key_id',
    'iv',
    'ciphertext',
  ]);
  if (record.record_version !== MATERIAL_RECORD_VERSION) {
    throw new Error('ECDSA role-local material row version is invalid');
  }
  const authority = parseWalletAuthAuthorityRef({
    kind: 'wallet_auth_authority_ref',
    walletId: record.wallet_id,
    authorityDigest: record.authority_digest,
    walletAuthMethodId: record.wallet_auth_method_id,
  });
  if (!authority) throw new Error('ECDSA role-local material authority is invalid');
  return {
    durableMaterialRef: parseEcdsaRoleLocalDurableMaterialRef(record.durable_material_ref),
    bindingDigest: parseEcdsaRoleLocalBindingDigest(record.binding_digest),
    selector: {
      capability: unwrapDomainId(parseCapabilityInstanceRef(record.capability_ref)),
      authority,
    },
  };
}

function parseMaterialRow(
  value: unknown,
  activeProof: ParsedActiveManifestProof,
): ValidatedEncryptedEcdsaReadyMaterial {
  const record = requireRecord(value, 'ECDSA role-local material row');
  const locator = parseMaterialLocator(record);
  const material = buildValidatedEncryptedEcdsaReadyMaterial({
    binding: activeProof.durableMaterial,
    sealingKeyId: parseEcdsaMaterialSealingKeyId(record.sealing_key_id),
    iv12B64u: parseEcdsaIv12B64u(record.iv),
    ciphertextB64u: parseEcdsaCiphertextB64u(record.ciphertext),
  });
  if (
    locator.durableMaterialRef !== material.binding.durableMaterialRef ||
    locator.bindingDigest !== material.binding.bindingDigest ||
    !selectorsMatch(locator.selector, selectorFromManifest(activeProof.activeManifest))
  ) {
    throw new Error('ECDSA role-local material row binding is inconsistent');
  }
  return material;
}

function materialMatchesManifest(
  material: ValidatedEncryptedEcdsaReadyMaterial,
  manifest: ActiveEcdsaCapabilityManifest,
): boolean {
  return (
    material.binding.durableMaterialRef === manifest.durableMaterial.durableMaterialRef &&
    material.binding.bindingDigest === manifest.durableMaterial.bindingDigest &&
    material.binding.lifecycleId === manifest.durableMaterial.lifecycleId &&
    material.binding.ciphertextDigest === manifest.durableMaterial.ciphertextDigest &&
    material.binding.activationDigest === manifest.durableMaterial.activationDigest &&
    material.binding.activatedAt === manifest.durableMaterial.activatedAt &&
    canonicalValuesMatch(
      material.binding.materialActivation,
      manifest.durableMaterial.materialActivation,
    ) &&
    canonicalValuesMatch(
      material.binding.roleLocalBinding,
      manifest.durableMaterial.roleLocalBinding,
    )
  );
}

function storedJournalRow(journal: EcdsaCapabilityActivationCommitJournal) {
  const selector = selectorFromJournal(journal);
  return {
    record_version: JOURNAL_RECORD_VERSION,
    journal_id: journal.journalId,
    capability_ref: selector.capability,
    wallet_id: selector.authority.walletId,
    authority_digest: selector.authority.authorityDigest,
    wallet_auth_method_id: selector.authority.walletAuthMethodId,
    journal,
  };
}

function parseJournalRow(value: unknown) {
  const record = requireRecord(value, 'ECDSA activation commit journal row');
  requireExactKeys(record, 'ECDSA activation commit journal row', [
    'record_version',
    'journal_id',
    'capability_ref',
    'wallet_id',
    'authority_digest',
    'wallet_auth_method_id',
    'journal',
  ]);
  if (record.record_version !== JOURNAL_RECORD_VERSION) {
    throw new Error('ECDSA activation commit journal row version is invalid');
  }
  const journal = parseJournal(record.journal);
  const selector = selectorFromJournal(journal);
  if (
    parseCorrelationId(record.journal_id) !== journal.journalId ||
    String(record.capability_ref) !== String(selector.capability) ||
    String(record.wallet_id) !== String(selector.authority.walletId) ||
    String(record.authority_digest) !== String(selector.authority.authorityDigest)
  ) {
    throw new Error('ECDSA activation commit journal row identity is inconsistent');
  }
  return { journal, selector };
}

function isNonExtractableAesGcmKey(value: unknown): value is CryptoKey {
  if (typeof CryptoKey === 'undefined' || !(value instanceof CryptoKey)) return false;
  if (value.type !== 'secret' || value.extractable || value.algorithm.name !== 'AES-GCM') {
    return false;
  }
  return value.usages.includes('encrypt') && value.usages.includes('decrypt');
}

function storedSealingKeyRow(keyId: EcdsaMaterialSealingKeyId, key: CryptoKey) {
  return {
    record_version: SEALING_KEY_RECORD_VERSION,
    key_id: keyId,
    key,
  };
}

function parseSealingKeyRow(value: unknown): ParsedSealingKeyRow {
  const record = requireRecord(value, 'ECDSA material sealing key row');
  requireExactKeys(record, 'ECDSA material sealing key row', ['record_version', 'key_id', 'key']);
  if (record.record_version !== SEALING_KEY_RECORD_VERSION) {
    throw new Error('ECDSA material sealing key row version is invalid');
  }
  if (!isNonExtractableAesGcmKey(record.key)) {
    throw new Error('ECDSA material sealing key must be a non-extractable AES-GCM key');
  }
  return {
    keyId: parseEcdsaMaterialSealingKeyId(record.key_id),
    key: record.key,
  };
}

function assertActiveProofInput(
  input: FinalizeEcdsaCapabilityActivationInput,
): ParsedActiveManifestProof {
  const proof: ParsedActiveManifestProof = {
    activationBinding: input.committedJournal.candidate.activationBinding,
    serverActivation: input.committedJournal.serverActivation,
    durableMaterial: input.readyMaterial.binding,
    activeManifest: input.activeManifest,
    committedAt: input.activeManifest.committedAt,
  };
  const parsed = parseActiveProof(storedActiveProof(proof));
  if (
    !canonicalValuesMatch(parsed.activeManifest, input.activeManifest) ||
    !canonicalValuesMatch(parsed.durableMaterial, input.readyMaterial.binding)
  ) {
    throw new Error('ECDSA finalization input does not describe one exact active manifest');
  }
  return parsed;
}

function assertExpectedPointer(
  expected: EcdsaManifestRevisionExpectation,
  pointerRaw: unknown,
  selector: EcdsaCapabilitySelector,
): ParsedPointerRow | null {
  switch (expected.kind) {
    case 'no_current_manifest':
      if (pointerRaw !== undefined) {
        throw new FinalizationControlError(
          'exact_record_conflict',
          'initial ECDSA activation found an existing current pointer',
        );
      }
      return null;
    case 'exact_manifest': {
      if (pointerRaw === undefined) {
        throw new FinalizationControlError(
          'exact_record_conflict',
          'replacement ECDSA activation is missing its expected current pointer',
        );
      }
      let pointer: ParsedPointerRow;
      try {
        pointer = parsePointerRow(pointerRaw);
      } catch (error: unknown) {
        throw new FinalizationControlError('corrupt', errorMessage(error));
      }
      if (
        !selectorsMatch(pointer.selector, selector) ||
        pointer.manifestId !== expected.manifestId ||
        pointer.manifestRevision !== expected.manifestRevision
      ) {
        throw new FinalizationControlError(
          'exact_record_conflict',
          'replacement ECDSA activation pointer CAS did not match',
        );
      }
      return pointer;
    }
  }
  return assertNever(expected);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isConstraintError(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'ConstraintError';
}

function assertNever(value: never): never {
  throw new Error(`Unexpected ECDSA persistence branch: ${String(value)}`);
}

async function cancelPreparedActivationInTransaction(
  preparedJournal: PreparedEcdsaActivationJournal,
  context: SeamsWalletTransactionContext,
): Promise<
  Exclude<EcdsaPreparedActivationCancellationResult, { kind: 'persistence_unavailable' }>
> {
  const journalStore = context.store(JOURNAL_STORE);
  const raw = await journalStore.get(preparedJournal.journalId);
  if (raw === undefined) return { kind: 'missing' };

  let persisted: ReturnType<typeof parseJournalRow>;
  try {
    persisted = parseJournalRow(raw);
  } catch {
    return { kind: 'corrupt' };
  }
  if (persisted.journal.journalId !== preparedJournal.journalId) {
    return { kind: 'corrupt' };
  }
  switch (persisted.journal.kind) {
    case 'server_activation_committed':
      return { kind: 'server_activation_committed' };
    case 'activation_prepared':
      if (!canonicalValuesMatch(persisted.journal, preparedJournal)) {
        return { kind: 'exact_record_conflict' };
      }
      await context
        .store(SEALING_KEY_STORE)
        .delete(persisted.journal.candidate.encryptedPending.sealingKeyId);
      await journalStore.delete(persisted.journal.journalId);
      return { kind: 'cancelled' };
  }
  return assertNever(persisted.journal);
}

async function readCurrentPointerRowsForWallet(
  context: SeamsWalletTransactionContext,
  walletId: WalletId,
): Promise<readonly unknown[]> {
  return await context.store(POINTER_STORE).index(SEAMS_WALLET_INDEXES.walletId).getAll(walletId);
}

async function readActivationJournalRows(
  context: SeamsWalletTransactionContext,
): Promise<readonly unknown[]> {
  return await context.store(JOURNAL_STORE).getAll();
}

export class IndexedDbEcdsaCapabilityManifestStore {
  private readonly manager: SeamsWalletDBManager;

  constructor(manager: SeamsWalletDBManager = seamsWalletDB) {
    this.manager = manager;
  }

  async listActiveWalletCapabilitySubjects(
    walletIdInput: WalletId,
  ): Promise<ActiveEcdsaWalletCapabilitySubjectListResult> {
    const parsedWalletId = parseWalletId(walletIdInput);
    if (!parsedWalletId.ok) return { kind: 'invalid_current_state' };
    let rows: readonly unknown[];
    try {
      rows = await this.manager.runTransaction(
        [POINTER_STORE],
        'readonly',
        async (context) => await readCurrentPointerRowsForWallet(context, parsedWalletId.value),
      );
    } catch {
      return { kind: 'persistence_unavailable' };
    }

    const selectors: EcdsaCapabilitySelector[] = [];
    try {
      for (const row of rows) {
        const pointer = parsePointerRow(row);
        if (pointer.selector.authority.walletId === parsedWalletId.value) {
          selectors.push(pointer.selector);
        }
      }
    } catch {
      return { kind: 'invalid_current_state' };
    }

    const subjects: ActiveEcdsaWalletCapabilitySubject[] = [];
    for (const selector of selectors) {
      const lookup = await this.lookup(selector);
      if (lookup.kind === 'persistence_unavailable') {
        return { kind: 'persistence_unavailable' };
      }
      if (lookup.kind !== 'active') {
        return { kind: 'invalid_current_state' };
      }
      subjects.push({
        capability: lookup.manifest.signer.capability,
        authority: lookup.manifest.signer.authority,
        ecdsaThresholdKeyId: lookup.manifest.durableMaterial.roleLocalBinding.ecdsaThresholdKeyId,
      });
    }
    return { kind: 'resolved', subjects };
  }

  async listWalletActivationJournalSelectors(
    walletIdInput: WalletId,
  ): Promise<EcdsaWalletActivationSelectorListResult> {
    const parsedWalletId = parseWalletId(walletIdInput);
    if (!parsedWalletId.ok) return { kind: 'invalid_current_state' };
    let rows: readonly unknown[];
    try {
      rows = await this.manager.runTransaction(
        [JOURNAL_STORE],
        'readonly',
        readActivationJournalRows,
      );
    } catch {
      return { kind: 'persistence_unavailable' };
    }

    const selectors: EcdsaCapabilitySelector[] = [];
    try {
      for (const row of rows) {
        const journal = parseJournalRow(row).journal;
        const signer = journal.candidate.activationBinding.signer;
        if (signer.authority.walletId !== parsedWalletId.value) continue;
        selectors.push({
          capability: signer.capability,
          authority: signer.authority,
        });
      }
    } catch {
      return { kind: 'invalid_current_state' };
    }
    return { kind: 'resolved', selectors };
  }

  async prepareActivation(
    input: PrepareEcdsaCapabilityActivationInput,
  ): Promise<EcdsaActivationJournalWriteResult<PreparedEcdsaActivationJournal>> {
    const selector: EcdsaCapabilitySelector = {
      capability: input.activationBinding.signer.capability,
      authority: input.activationBinding.signer.authority,
    };
    try {
      const keyId = parseEcdsaMaterialSealingKeyId(
        secureRandomId('ecdsa-material-key', 32, 'ECDSA activation material sealing key'),
      );
      const key = await generateMaterialSealingKey();
      const encrypted = await encryptStateBlob({
        key,
        stateBlobB64u: input.pendingPayloadB64u,
        aadProjection: pendingAadProjection(input),
      });
      const journal = buildPreparedJournalFromEncryptedCandidate({
        preparation: input,
        encryptedPending: buildEncryptedEcdsaPendingCandidate({
          sealingKeyId: keyId,
          iv12B64u: encrypted.iv12B64u,
          ciphertextB64u: encrypted.ciphertextB64u,
          ciphertextDigest: parseEcdsaPendingCiphertextDigest(encrypted.digestB64u),
        }),
      });
      await this.manager.runTransaction(
        [SEALING_KEY_STORE, JOURNAL_STORE],
        'readwrite',
        async (context) => {
          await context.store(SEALING_KEY_STORE).add(storedSealingKeyRow(keyId, key));
          await context.store(JOURNAL_STORE).add(storedJournalRow(journal));
        },
      );
      return { kind: 'stored', journal };
    } catch (error: unknown) {
      if (isConstraintError(error)) {
        return {
          kind: 'exact_record_conflict',
          conflictDigest: await persistenceDigest(
            'journal_constraint_conflict',
            selector,
            errorMessage(error),
          ),
        };
      }
      if (error instanceof DOMException && error.name === 'OperationError') {
        return {
          kind: 'corrupt',
          corruptionDigest: await persistenceDigest(
            'journal_encryption_failed',
            selector,
            errorMessage(error),
          ),
        };
      }
      if (error instanceof Error && !(error instanceof DOMException)) {
        return {
          kind: 'corrupt',
          corruptionDigest: await persistenceDigest(
            'journal_preparation_invalid',
            selector,
            error.message,
          ),
        };
      }
      return {
        kind: 'persistence_unavailable',
        retryCorrelation: retryCorrelation(),
      };
    }
  }

  async recordServerActivation(
    input: RecordEcdsaServerActivationInput,
  ): Promise<EcdsaActivationJournalWriteResult<ServerCommittedEcdsaActivationJournal>> {
    let committedJournal: ServerCommittedEcdsaActivationJournal;
    try {
      committedJournal = buildServerCommittedEcdsaActivationJournal(input);
    } catch (error: unknown) {
      return {
        kind: 'corrupt',
        corruptionDigest: await persistenceDigest(
          'server_activation_commit_corrupt',
          selectorFromJournal(input.preparedJournal),
          errorMessage(error),
        ),
      };
    }
    return await this.putActivationJournal(committedJournal);
  }

  private async putActivationJournal(
    journalInput: ServerCommittedEcdsaActivationJournal,
  ): Promise<EcdsaActivationJournalWriteResult<ServerCommittedEcdsaActivationJournal>> {
    let journal: ServerCommittedEcdsaActivationJournal;
    try {
      journal = parseCommittedJournal(journalInput);
      if (
        (await ciphertextDigestB64u(journal.candidate.encryptedPending.ciphertextB64u)) !==
        journal.candidate.encryptedPending.ciphertextDigest
      ) {
        throw new Error('ECDSA pending material ciphertext digest is invalid');
      }
    } catch (error: unknown) {
      return {
        kind: 'corrupt',
        corruptionDigest: await persistenceDigest(
          'journal_input_corrupt',
          selectorFromJournal(journalInput),
          errorMessage(error),
        ),
      };
    }
    const selector = selectorFromJournal(journal);
    try {
      const sealingKey = await this.readMaterialSealingKey(
        journal.candidate.encryptedPending.sealingKeyId,
      );
      if (!sealingKey) {
        throw new FinalizationControlError(
          'corrupt',
          'ECDSA activation journal references a missing sealing key',
        );
      }
      await decryptStateBlob({
        key: sealingKey,
        iv12B64u: journal.candidate.encryptedPending.iv12B64u,
        ciphertextB64u: journal.candidate.encryptedPending.ciphertextB64u,
        aadProjection: pendingAadProjection(journal),
      });
      await this.manager.runTransaction(
        [SEALING_KEY_STORE, JOURNAL_STORE],
        'readwrite',
        async (context) => {
          const sealingKeyRaw = await context
            .store(SEALING_KEY_STORE)
            .get(journal.candidate.encryptedPending.sealingKeyId);
          if (sealingKeyRaw === undefined) {
            throw new FinalizationControlError(
              'corrupt',
              'ECDSA activation journal references a missing sealing key',
            );
          }
          try {
            parseSealingKeyRow(sealingKeyRaw);
          } catch (error: unknown) {
            throw new FinalizationControlError('corrupt', errorMessage(error));
          }
          const journalStore = context.store(JOURNAL_STORE);
          const existingRaw = await journalStore.get(journal.journalId);
          if (existingRaw === undefined) {
            throw new FinalizationControlError(
              'exact_record_conflict',
              'ECDSA committed activation is missing its prepared journal',
            );
          }
          let existing: ReturnType<typeof parseJournalRow>;
          try {
            existing = parseJournalRow(existingRaw);
          } catch (error: unknown) {
            throw new FinalizationControlError('corrupt', errorMessage(error));
          }
          if (
            !selectorsMatch(existing.selector, selector) ||
            (existing.journal.kind === 'activation_prepared' &&
              !canonicalValuesMatch(existing.journal, preparedJournalProjection(journal))) ||
            (existing.journal.kind === 'server_activation_committed' &&
              !canonicalValuesMatch(existing.journal, journal))
          ) {
            throw new FinalizationControlError(
              'exact_record_conflict',
              'ECDSA activation journal conflicts with its existing correlation',
            );
          }
          await journalStore.put(storedJournalRow(journal));
        },
      );
      return {
        kind: 'stored',
        journal,
      };
    } catch (error: unknown) {
      if (error instanceof FinalizationControlError) {
        const digest = await persistenceDigest(
          error.kind === 'corrupt' ? 'journal_corrupt' : 'journal_conflict',
          selector,
          error.message,
        );
        return error.kind === 'corrupt'
          ? { kind: 'corrupt', corruptionDigest: digest }
          : { kind: 'exact_record_conflict', conflictDigest: digest };
      }
      if (isConstraintError(error)) {
        return {
          kind: 'exact_record_conflict',
          conflictDigest: await persistenceDigest(
            'journal_constraint_conflict',
            selector,
            errorMessage(error),
          ),
        };
      }
      if (error instanceof DOMException && error.name === 'OperationError') {
        return {
          kind: 'corrupt',
          corruptionDigest: await persistenceDigest(
            'journal_ciphertext_corrupt',
            selector,
            errorMessage(error),
          ),
        };
      }
      return {
        kind: 'persistence_unavailable',
        retryCorrelation: retryCorrelation(),
      };
    }
  }

  async readActivationJournal(
    journalIdInput: CorrelationId,
  ): Promise<EcdsaActivationJournalReadResult> {
    const journalId = parseCorrelationId(journalIdInput);
    try {
      const raw = await this.manager.runTransaction(
        [JOURNAL_STORE],
        'readonly',
        async (context) => await context.store(JOURNAL_STORE).get(journalId),
      );
      if (raw === undefined) return { kind: 'missing' };
      try {
        const parsed = parseJournalRow(raw);
        return parsed.journal.journalId === journalId
          ? { kind: 'found', journal: parsed.journal }
          : { kind: 'corrupt' };
      } catch {
        return { kind: 'corrupt' };
      }
    } catch {
      return { kind: 'persistence_unavailable' };
    }
  }

  async discoverActivationJournal(
    selectorInput: EcdsaCapabilitySelector,
  ): Promise<EcdsaActivationJournalReadResult> {
    let selector: EcdsaCapabilitySelector;
    try {
      selector = normalizeSelector(selectorInput);
    } catch {
      return { kind: 'corrupt' };
    }
    try {
      const raw = await this.manager.runTransaction(
        [JOURNAL_STORE],
        'readonly',
        async (context) =>
          await context
            .store(JOURNAL_STORE)
            .index(SEAMS_WALLET_INDEXES.capabilityWalletAuthority)
            .get(selectorKey(selector)),
      );
      if (raw === undefined) return { kind: 'missing' };
      try {
        const parsed = parseJournalRow(raw);
        return selectorsMatch(parsed.selector, selector)
          ? { kind: 'found', journal: parsed.journal }
          : { kind: 'corrupt' };
      } catch {
        return { kind: 'corrupt' };
      }
    } catch {
      return { kind: 'persistence_unavailable' };
    }
  }

  async cancelPreparedActivation(
    preparedJournal: PreparedEcdsaActivationJournal,
  ): Promise<EcdsaPreparedActivationCancellationResult> {
    try {
      return await this.manager.runTransaction(
        [SEALING_KEY_STORE, JOURNAL_STORE],
        'readwrite',
        cancelPreparedActivationInTransaction.bind(undefined, preparedJournal),
      );
    } catch {
      return { kind: 'persistence_unavailable' };
    }
  }

  async openPreparedActivation(
    journalIdInput: CorrelationId,
  ): Promise<EcdsaPreparedActivationOpenResult> {
    const read = await this.readActivationJournal(journalIdInput);
    if (read.kind !== 'found') return read;
    const encryptedPending = read.journal.candidate.encryptedPending;
    try {
      if (
        (await ciphertextDigestB64u(encryptedPending.ciphertextB64u)) !==
        encryptedPending.ciphertextDigest
      ) {
        return { kind: 'corrupt' };
      }
      const sealingKey = await this.readMaterialSealingKey(encryptedPending.sealingKeyId);
      if (!sealingKey) return { kind: 'corrupt' };
      return {
        kind: 'found',
        journal: read.journal,
        pendingPayloadB64u: await decryptStateBlob({
          key: sealingKey,
          iv12B64u: encryptedPending.iv12B64u,
          ciphertextB64u: encryptedPending.ciphertextB64u,
          aadProjection: pendingAadProjection(read.journal),
        }),
      };
    } catch {
      return { kind: 'corrupt' };
    }
  }

  async lookup(selectorInput: EcdsaCapabilitySelector): Promise<EcdsaCapabilityManifestLookup> {
    const selector = normalizeSelector(selectorInput);
    let observation: LookupTransactionObservation;
    try {
      observation = await this.manager.runTransaction(
        [MANIFEST_STORE, POINTER_STORE, MATERIAL_STORE, SEALING_KEY_STORE],
        'readonly',
        async (context) => await lookupInTransaction(context, selector),
      );
    } catch {
      return {
        kind: 'persistence_unavailable',
        selector,
        retryCorrelation: retryCorrelation(),
      };
    }
    switch (observation.kind) {
      case 'active':
        return observation;
      case 'retired':
        return observation;
      case 'missing':
        return {
          kind: 'missing',
          selector,
          subject: observation.subject,
        };
      case 'exact_binding_mismatch':
        return {
          kind: 'exact_binding_mismatch',
          selector,
          failureDigest: await persistenceDigest(observation.kind, selector, observation.detail),
        };
      case 'exact_record_conflict':
        return {
          kind: 'exact_record_conflict',
          selector,
          conflictDigest: await persistenceDigest(observation.kind, selector, observation.detail),
        };
      case 'corrupt':
        return {
          kind: 'corrupt',
          selector,
          corruptionDigest: await persistenceDigest(observation.kind, selector, observation.detail),
        };
    }
    return assertNever(observation);
  }

  async lookupByMaterialActivation(input: {
    readonly walletId: WalletId;
    readonly materialActivation: MpcMaterialActivationRef;
    readonly authority?: WalletAuthAuthorityRef;
  }): Promise<EcdsaCapabilityActivationLookup> {
    const walletIdResult = parseWalletId(input.walletId);
    const materialActivationResult = parseMpcMaterialActivationRef(input.materialActivation);
    const capability = materialActivationResult.ok
      ? materialActivationResult.value.capability
      : input.materialActivation.capability;
    if (!walletIdResult.ok || !materialActivationResult.ok) {
      return { kind: 'corrupt', capability };
    }
    const walletId = walletIdResult.value;
    const materialActivation = materialActivationResult.value;
    let rows: readonly unknown[];
    try {
      rows = await this.manager.runTransaction(
        [POINTER_STORE],
        'readonly',
        async (context) => await readCurrentPointerRowsForWallet(context, walletId),
      );
    } catch {
      return { kind: 'persistence_unavailable', capability };
    }

    const selectors: EcdsaCapabilitySelector[] = [];
    try {
      for (const row of rows) {
        const pointer = parsePointerRow(row);
        if (pointer.selector.authority.walletId === walletId) {
          selectors.push(pointer.selector);
        }
      }
    } catch {
      return { kind: 'corrupt', capability };
    }
    if (selectors.length === 0) {
      return { kind: 'missing', subject: 'capability', capability };
    }
    const exact: Extract<EcdsaCapabilityManifestLookup, { readonly kind: 'active' }>[] = [];
    for (const selector of selectors) {
      const lookup = await this.lookup(selector);
      switch (lookup.kind) {
        case 'active':
          if (
            mpcMaterialActivationRefsEqual(
              lookup.manifest.activation.materialActivation,
              materialActivation,
            ) &&
            mpcMaterialActivationRefsEqual(
              lookup.manifest.durableMaterial.materialActivation,
              materialActivation,
            ) &&
            mpcMaterialActivationRefsEqual(
              lookup.material.binding.materialActivation,
              materialActivation,
            )
          ) {
            exact.push(lookup);
          }
          break;
        case 'retired':
          break;
        case 'missing':
          return { kind: 'missing', subject: lookup.subject, capability };
        case 'exact_binding_mismatch':
        case 'exact_record_conflict':
        case 'corrupt':
        case 'persistence_unavailable':
          return { kind: lookup.kind, capability };
      }
    }
    const requested = input.authority;
    if (requested) {
      const selected = exact.filter((candidate) =>
        walletAuthAuthorityRefsMatch(candidate.manifest.signer.authority, requested),
      );
      // Two projections cannot share one authority digest: the digest is the
      // store's own selector key. More than one here is corruption, not the
      // sibling case.
      if (selected.length > 1) return { kind: 'exact_record_conflict', capability };
      return selected[0] ?? { kind: 'exact_binding_mismatch', capability };
    }
    if (exact.length > 1) {
      return {
        kind: 'ambiguous_authority',
        capability,
        authorities: exact.map((candidate) => candidate.manifest.signer.authority),
      };
    }
    return exact[0] ?? { kind: 'exact_binding_mismatch', capability };
  }

  async openActiveMaterial(
    selectorInput: EcdsaCapabilitySelector,
  ): Promise<EcdsaActiveMaterialOpenResult> {
    const selector = normalizeSelector(selectorInput);
    const lookup = await this.lookup(selector);
    if (lookup.kind !== 'active') return lookup;
    return await this.openActiveMaterialLookup(lookup);
  }

  async lookupByMaterialRef(
    materialRefInput: EcdsaRoleLocalPersistedMaterialRef,
  ): Promise<EcdsaCapabilityMaterialRefLookup> {
    const materialRef = parseEcdsaRoleLocalPersistedMaterialRef(materialRefInput);
    const capability = materialRef.materialActivation.capability;
    let raw: unknown;
    try {
      raw = await this.manager.runTransaction(
        [MATERIAL_STORE],
        'readonly',
        async (context) => await context.store(MATERIAL_STORE).get(materialRef.durableMaterialRef),
      );
    } catch {
      return { kind: 'persistence_unavailable', capability };
    }
    if (raw === undefined) return await this.lookupMissingMaterialByRef(materialRef);
    let locator: ParsedMaterialLocator;
    try {
      locator = parseMaterialLocator(raw);
    } catch {
      return { kind: 'corrupt', capability };
    }
    if (
      locator.durableMaterialRef !== materialRef.durableMaterialRef ||
      locator.bindingDigest !== materialRef.bindingDigest
    ) {
      return { kind: 'exact_binding_mismatch', capability };
    }
    const lookup = await this.lookup(locator.selector);
    switch (lookup.kind) {
      case 'active':
        if (
          lookup.manifest.durableMaterial.durableMaterialRef !== materialRef.durableMaterialRef ||
          lookup.manifest.durableMaterial.bindingDigest !== materialRef.bindingDigest ||
          !mpcMaterialActivationRefsEqual(
            lookup.manifest.activation.materialActivation,
            materialRef.materialActivation,
          ) ||
          !mpcMaterialActivationRefsEqual(
            lookup.manifest.durableMaterial.materialActivation,
            materialRef.materialActivation,
          ) ||
          !mpcMaterialActivationRefsEqual(
            lookup.material.binding.materialActivation,
            materialRef.materialActivation,
          )
        ) {
          return { kind: 'exact_binding_mismatch', capability };
        }
        return lookup;
      case 'retired':
        return lookup;
      case 'missing':
        return {
          kind: 'missing',
          subject: lookup.subject,
          capability,
        };
      case 'exact_binding_mismatch':
      case 'exact_record_conflict':
      case 'corrupt':
      case 'persistence_unavailable':
        return { kind: lookup.kind, capability };
    }
    return assertNever(lookup);
  }

  private async lookupMissingMaterialByRef(
    materialRef: EcdsaRoleLocalPersistedMaterialRef,
  ): Promise<EcdsaCapabilityMaterialRefLookup> {
    const capability = materialRef.materialActivation.capability;
    let rows: unknown[];
    try {
      rows = await this.manager.runTransaction(
        [MANIFEST_STORE],
        'readonly',
        async (context) => await context.store(MANIFEST_STORE).getAll(),
      );
    } catch {
      return { kind: 'persistence_unavailable', capability };
    }
    const exact: ParsedManifestRow[] = [];
    let bindingMismatch = false;
    for (const raw of rows) {
      let parsed: ParsedManifestRow;
      try {
        parsed = parseManifestRow(raw);
      } catch {
        return { kind: 'corrupt', capability };
      }
      const durableMaterial = parsed.activeProof.durableMaterial;
      if (durableMaterial.durableMaterialRef !== materialRef.durableMaterialRef) continue;
      if (
        durableMaterial.bindingDigest !== materialRef.bindingDigest ||
        !mpcMaterialActivationRefsEqual(
          durableMaterial.materialActivation,
          materialRef.materialActivation,
        )
      ) {
        bindingMismatch = true;
        continue;
      }
      exact.push(parsed);
    }
    if (exact.length > 1) return { kind: 'exact_record_conflict', capability };
    const [matched] = exact;
    if (!matched) {
      return bindingMismatch
        ? { kind: 'exact_binding_mismatch', capability }
        : { kind: 'missing', subject: 'material', capability };
    }
    if (matched.state === 'replaced') {
      return { kind: 'retired', manifest: matched.manifest };
    }
    return { kind: 'missing', subject: 'material', capability };
  }

  async openActiveMaterialLookup(
    lookup: Extract<EcdsaCapabilityMaterialRefLookup, { readonly kind: 'active' }>,
  ): Promise<EcdsaActiveMaterialOpenResult> {
    const selector = selectorFromManifest(lookup.manifest);
    try {
      if (
        (await ciphertextDigestB64u(lookup.material.ciphertextB64u)) !==
        lookup.material.binding.ciphertextDigest
      ) {
        throw new Error('active ECDSA material ciphertext digest is invalid');
      }
      const sealingKey = await this.readMaterialSealingKey(lookup.material.sealingKeyId);
      if (!sealingKey) throw new Error('active ECDSA material sealing key is missing');
      return {
        kind: 'active',
        manifest: lookup.manifest,
        readyStateBlobB64u: await decryptStateBlob({
          key: sealingKey,
          iv12B64u: lookup.material.iv12B64u,
          ciphertextB64u: lookup.material.ciphertextB64u,
          aadProjection: readyAadProjection(lookup.manifest),
        }),
      };
    } catch (error: unknown) {
      return {
        kind: 'corrupt',
        selector,
        corruptionDigest: await persistenceDigest(
          'active_material_open_corrupt',
          selector,
          errorMessage(error),
        ),
      };
    }
  }

  async openActiveMaterialByRef(
    materialRefInput: EcdsaRoleLocalPersistedMaterialRef,
  ): Promise<EcdsaActiveMaterialRefOpenResult> {
    let lookup: EcdsaCapabilityMaterialRefLookup;
    try {
      lookup = await this.lookupByMaterialRef(materialRefInput);
    } catch {
      return { kind: 'corrupt' };
    }
    switch (lookup.kind) {
      case 'active': {
        const opened = await this.openActiveMaterialLookup(lookup);
        switch (opened.kind) {
          case 'active':
            return opened;
          case 'missing':
          case 'retired':
            return { kind: 'missing' };
          case 'exact_binding_mismatch':
            return { kind: 'binding_mismatch' };
          case 'exact_record_conflict':
          case 'corrupt':
            return { kind: 'corrupt' };
          case 'persistence_unavailable':
            return { kind: 'persistence_unavailable' };
        }
        return assertNever(opened);
      }
      case 'missing':
      case 'retired':
        return { kind: 'missing' };
      case 'exact_binding_mismatch':
        return { kind: 'binding_mismatch' };
      case 'exact_record_conflict':
      case 'corrupt':
        return { kind: 'corrupt' };
      case 'persistence_unavailable':
        return { kind: 'persistence_unavailable' };
    }
    return assertNever(lookup);
  }

  async sealAndFinalizeActivation(
    input: SealEcdsaCapabilityActivationInput,
  ): Promise<EcdsaCapabilityActivationFinalizationResult> {
    const selector = selectorFromJournal(input.committedJournal);
    try {
      const parsedJournal = parseCommittedJournal(input.committedJournal);
      const sealingKeyId = parsedJournal.candidate.encryptedPending.sealingKeyId;
      const sealingKey = await this.readMaterialSealingKey(sealingKeyId);
      if (!sealingKey) throw new Error('ECDSA activation material sealing key is missing');
      const encrypted = await encryptStateBlob({
        key: sealingKey,
        stateBlobB64u: input.readyStateBlobB64u,
        aadProjection: readyAadProjection(parsedJournal),
      });
      const durableMaterial = buildDurableEcdsaMaterialBinding({
        activationBinding: parsedJournal.candidate.activationBinding,
        serverActivation: parsedJournal.serverActivation,
        routerAbEcdsaDerivationNormalSigning: input.routerAbEcdsaDerivationNormalSigning,
        roleLocalPublicFacts: buildEcdsaRoleLocalPublicFacts(input.roleLocalPublicFacts),
        ciphertextDigest: parseEcdsaCiphertextDigest(encrypted.digestB64u),
        runtimePolicyScope: input.runtimePolicyScope,
      });
      const readyMaterial = buildValidatedEncryptedEcdsaReadyMaterial({
        binding: durableMaterial,
        sealingKeyId,
        iv12B64u: encrypted.iv12B64u,
        ciphertextB64u: encrypted.ciphertextB64u,
      });
      const activeManifest = buildActiveEcdsaCapabilityManifest({
        activationBinding: parsedJournal.candidate.activationBinding,
        serverActivation: parsedJournal.serverActivation,
        registeredPublicFacts: input.registeredPublicFacts,
        durableMaterial,
        committedAt: input.committedAt,
      });
      return await this.finalizeActivation({
        committedJournal: parsedJournal,
        readyMaterial,
        activeManifest,
      });
    } catch (error: unknown) {
      return {
        kind: 'corrupt',
        selector,
        corruptionDigest: await persistenceDigest(
          'activation_seal_corrupt',
          selector,
          errorMessage(error),
        ),
      };
    }
  }

  async importCommittedWalletCustodyActivation(
    input: ImportCommittedWalletCustodyEcdsaActivationInput,
  ): Promise<EcdsaCapabilityActivationFinalizationResult> {
    const serverActivation = buildEcdsaServerActivationCommit({
      activationBinding: input.activationBinding,
      serverCommit: input.serverCommit,
    });
    const selector = {
      capability: input.activationBinding.signer.capability,
      authority: input.activationBinding.signer.authority,
    };
    const existing = await this.lookup(selector);
    if (existing.kind === 'active') {
      if (
        activeManifestMatchesWalletCustodyImport({
          manifest: existing.manifest,
          activationBinding: input.activationBinding,
          serverActivation,
          registeredPublicFacts: input.registeredPublicFacts,
          roleLocalPublicFacts: input.roleLocalPublicFacts,
          routerAbEcdsaDerivationNormalSigning: input.routerAbEcdsaDerivationNormalSigning,
          runtimePolicyScope: input.runtimePolicyScope,
        })
      ) {
        return { kind: 'committed', manifest: existing.manifest, material: existing.material };
      }
      return {
        kind: 'exact_record_conflict',
        selector,
        conflictDigest: await persistenceDigest(
          'custody_import_conflict',
          selector,
          'ECDSA custody import conflicts with the active manifest',
        ),
      };
    }
    const sealingKeyId = parseEcdsaMaterialSealingKeyId(
      secureRandomId('ecdsa-material-sealing-key', 32, 'ECDSA material sealing key identities'),
    );
    try {
      const sealingKey = await generateMaterialSealingKey();
      const encrypted = await encryptStateBlob({
        key: sealingKey,
        stateBlobB64u: input.readyStateBlobB64u,
        aadProjection: importedReadyAadProjection({
          activationBinding: input.activationBinding,
          serverActivation,
        }),
      });
      const durableMaterial = buildDurableEcdsaMaterialBinding({
        activationBinding: input.activationBinding,
        serverActivation,
        routerAbEcdsaDerivationNormalSigning: input.routerAbEcdsaDerivationNormalSigning,
        roleLocalPublicFacts: input.roleLocalPublicFacts,
        ciphertextDigest: parseEcdsaCiphertextDigest(encrypted.digestB64u),
        runtimePolicyScope: input.runtimePolicyScope,
      });
      const readyMaterial = buildValidatedEncryptedEcdsaReadyMaterial({
        binding: durableMaterial,
        sealingKeyId,
        iv12B64u: encrypted.iv12B64u,
        ciphertextB64u: encrypted.ciphertextB64u,
      });
      const activeManifest = buildActiveEcdsaCapabilityManifest({
        activationBinding: input.activationBinding,
        serverActivation,
        registeredPublicFacts: input.registeredPublicFacts,
        durableMaterial,
        committedAt: input.committedAt,
      });
      const activeProof: ParsedActiveManifestProof = {
        activationBinding: input.activationBinding,
        serverActivation,
        durableMaterial,
        activeManifest,
        committedAt: input.committedAt,
      };
      await this.manager.runTransaction(
        [MANIFEST_STORE, POINTER_STORE, MATERIAL_STORE, SEALING_KEY_STORE],
        'readwrite',
        async (context) => {
          const pointerStore = context.store(POINTER_STORE);
          const existingPointer = await pointerStore.get(selectorKey(selector));
          const activeRows = await context
            .store(MANIFEST_STORE)
            .index(SEAMS_WALLET_INDEXES.capabilityWalletAuthorityState)
            .getAll([...selectorKey(selector), 'active']);
          if (existingPointer !== undefined || activeRows.length !== 0) {
            throw new FinalizationControlError(
              'exact_record_conflict',
              'ECDSA custody import found an existing active manifest',
            );
          }
          await context.store(SEALING_KEY_STORE).add(storedSealingKeyRow(sealingKeyId, sealingKey));
          await context.store(MATERIAL_STORE).add(storedMaterialRow(readyMaterial, activeManifest));
          await context.store(MANIFEST_STORE).add(storedActiveManifestRow(activeProof));
          await pointerStore.put(storedPointerRow(activeManifest));
        },
      );
      return { kind: 'committed', manifest: activeManifest, material: readyMaterial };
    } catch (error: unknown) {
      if (error instanceof FinalizationControlError || isConstraintError(error)) {
        const replay = await this.lookup(selector);
        if (
          replay.kind === 'active' &&
          activeManifestMatchesWalletCustodyImport({
            manifest: replay.manifest,
            activationBinding: input.activationBinding,
            serverActivation,
            registeredPublicFacts: input.registeredPublicFacts,
            roleLocalPublicFacts: input.roleLocalPublicFacts,
            routerAbEcdsaDerivationNormalSigning: input.routerAbEcdsaDerivationNormalSigning,
            runtimePolicyScope: input.runtimePolicyScope,
          })
        ) {
          return { kind: 'committed', manifest: replay.manifest, material: replay.material };
        }
        return {
          kind: 'exact_record_conflict',
          selector,
          conflictDigest: await persistenceDigest(
            'custody_import_conflict',
            selector,
            errorMessage(error),
          ),
        };
      }
      return {
        kind: 'corrupt',
        selector,
        corruptionDigest: await persistenceDigest(
          'custody_import_corrupt',
          selector,
          errorMessage(error),
        ),
      };
    }
  }

  private async readMaterialSealingKey(
    keyIdInput: EcdsaMaterialSealingKeyId,
  ): Promise<CryptoKey | null> {
    const keyId = parseEcdsaMaterialSealingKeyId(keyIdInput);
    const raw = await this.manager.runTransaction(
      [SEALING_KEY_STORE],
      'readonly',
      async (context) => await context.store(SEALING_KEY_STORE).get(keyId),
    );
    if (raw === undefined) return null;
    const parsed = parseSealingKeyRow(raw);
    if (parsed.keyId !== keyId) {
      throw new Error('ECDSA material sealing key row identity is inconsistent');
    }
    return parsed.key;
  }

  private async finalizeActivation(
    input: FinalizeEcdsaCapabilityActivationInput,
  ): Promise<EcdsaCapabilityActivationFinalizationResult> {
    let activeProof: ParsedActiveManifestProof;
    try {
      activeProof = assertActiveProofInput(input);
    } catch (error: unknown) {
      const selector = selectorFromJournal(input.committedJournal);
      return {
        kind: 'corrupt',
        selector,
        corruptionDigest: await persistenceDigest(
          'finalization_input_corrupt',
          selector,
          errorMessage(error),
        ),
      };
    }
    const selector = selectorFromManifest(activeProof.activeManifest);
    try {
      if (
        (await ciphertextDigestB64u(input.readyMaterial.ciphertextB64u)) !==
        input.readyMaterial.binding.ciphertextDigest
      ) {
        throw new FinalizationControlError(
          'corrupt',
          'ECDSA ready material ciphertext digest is invalid',
        );
      }
      const sealingKey = await this.readMaterialSealingKey(input.readyMaterial.sealingKeyId);
      if (!sealingKey) {
        throw new FinalizationControlError(
          'corrupt',
          'ECDSA ready material sealing key is missing',
        );
      }
      await decryptStateBlob({
        key: sealingKey,
        iv12B64u: input.readyMaterial.iv12B64u,
        ciphertextB64u: input.readyMaterial.ciphertextB64u,
        aadProjection: readyAadProjection(input.committedJournal),
      });
      await this.manager.runTransaction(
        [MANIFEST_STORE, POINTER_STORE, MATERIAL_STORE, JOURNAL_STORE, SEALING_KEY_STORE],
        'readwrite',
        async (context) => {
          await finalizeInTransaction(context, input, activeProof, selector);
        },
      );
      return {
        kind: 'committed',
        manifest: activeProof.activeManifest,
        material: input.readyMaterial,
      };
    } catch (error: unknown) {
      if (error instanceof FinalizationControlError) {
        const digest = await persistenceDigest(
          error.kind === 'corrupt' ? 'finalization_corrupt' : 'finalization_conflict',
          selector,
          error.message,
        );
        return error.kind === 'corrupt'
          ? {
              kind: 'corrupt',
              selector,
              corruptionDigest: digest,
            }
          : {
              kind: 'exact_record_conflict',
              selector,
              conflictDigest: digest,
            };
      }
      if (isConstraintError(error)) {
        return {
          kind: 'exact_record_conflict',
          selector,
          conflictDigest: await persistenceDigest(
            'finalization_constraint_conflict',
            selector,
            errorMessage(error),
          ),
        };
      }
      return {
        kind: 'persistence_unavailable',
        selector,
        retryCorrelation: retryCorrelation(),
      };
    }
  }
}

export type ImportWalletCustodyEcdsaContinuityInput = {
  readonly store: IndexedDbEcdsaCapabilityManifestStore;
  readonly authority: WalletAuthAuthorityRef;
  readonly chainTargets: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
  readonly walletId: string;
  readonly keyHandle: string;
  readonly ecdsaThresholdKeyId: string;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly relayerKeyId: string;
  readonly participantIds: readonly [number, number];
  readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  readonly activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly readyStateBlobB64u: string;
  readonly publicFacts: WalletCustodyEvmFamilyPublicFacts;
};

export async function importWalletCustodyEcdsaContinuity(
  input: ImportWalletCustodyEcdsaContinuityInput,
): Promise<EcdsaCapabilityActivationFinalizationResult> {
  const authority = parseWalletAuthAuthorityRef(input.authority);
  if (!authority || String(authority.walletId) !== String(input.walletId)) {
    throw new Error('ECDSA custody import authority is invalid');
  }
  const publicCapability = parseRouterAbEcdsaDerivationPublicCapabilityV1(input.publicCapability);
  const receipt = parseRouterAbEcdsaRegistrationActivationReceiptV1(input.activationReceipt);
  const materialActivation = routerAbMpcMaterialActivationRefFromWire(
    receipt.ecdsa_activation.material_activation,
  );
  if (
    !mpcMaterialActivationRefsEqual(
      materialActivation,
      routerAbMpcMaterialActivationRefFromWire(publicCapability.material_activation),
    )
  ) {
    throw new Error('ECDSA custody continuity changed the material activation');
  }
  const participantIds = [
    toParticipantId(input.participantIds[0]),
    toParticipantId(input.participantIds[1]),
  ] as const;
  const roleLocalBinding = buildEcdsaRoleLocalMaterialBinding({
    keyHandle: parseEcdsaKeyHandle(input.keyHandle),
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(input.ecdsaThresholdKeyId),
    clientVerifyingPublicKey33B64u: parseEcdsaClientVerifyingPublicKey33B64u(
      input.publicFacts.derivationClientSharePublicKey33B64u,
    ),
    participantIds,
    relayerKeyId: parseEcdsaRelayerKeyId(input.relayerKeyId),
  });
  const signer = buildPreparedEvmFamilySigner({
    capability: materialActivation.capability,
    signerId: parseEvmFamilyEcdsaSignerId(
      secureRandomId('ecdsa-signer', 32, 'ECDSA custody signer identities'),
    ),
    authority,
    scope: buildEcdsaCapabilityScope({ targetMemberships: input.chainTargets }),
    materialOwner: materialActivation.materialOwner,
    signingRootId: parseSdkEcdsaDerivationSigningRootId(input.signingRootId),
    signingRootVersion: parseSdkEcdsaDerivationSigningRootVersion(input.signingRootVersion),
  });
  const activationBinding = buildEcdsaActivationBinding({
    targetManifest: buildEcdsaManifestIdentity({
      manifestId: parseEcdsaCapabilityManifestId(
        secureRandomId('ecdsa-manifest', 32, 'ECDSA custody manifest identities'),
      ),
      manifestRevision: parseEcdsaCapabilityManifestRevision(1),
    }),
    signer,
    roleLocalBinding,
    bindingDigest: parseEcdsaRoleLocalBindingDigest(input.publicFacts.contextBinding32B64u),
    durableMaterialRef: parseEcdsaRoleLocalDurableMaterialRef(
      secureRandomId('ecdsa-role-local-material', 32, 'ECDSA custody material identities'),
    ),
  });
  const ethereumAddress = input.publicFacts.ethereumAddress;
  const registeredPublicFacts = buildVerifiedEcdsaPublicFacts({
    keyHandle: toEvmFamilyEcdsaKeyHandle(input.keyHandle),
    publicKeyB64u: input.publicFacts.groupPublicKey33B64u,
    participantIds,
    thresholdOwnerAddress: ethereumAddress,
  });
  const roleLocalPublicFacts = buildEcdsaRoleLocalPublicFacts({
    walletId: authority.walletId,
    chainTarget: input.chainTargets[0],
    keyHandle: roleLocalBinding.keyHandle,
    ecdsaThresholdKeyId: roleLocalBinding.ecdsaThresholdKeyId,
    signingRootId: signer.signingRootId,
    signingRootVersion: signer.signingRootVersion,
    applicationBindingDigestB64u: publicCapability.context.application_binding_digest_b64u,
    clientParticipantId: participantIds[0],
    relayerParticipantId: participantIds[1],
    participantIds,
    contextBinding32B64u: input.publicFacts.contextBinding32B64u,
    derivationClientSharePublicKey33B64u: input.publicFacts.derivationClientSharePublicKey33B64u,
    relayerPublicKey33B64u: input.publicFacts.relayerPublicKey33B64u,
    groupPublicKey33B64u: input.publicFacts.groupPublicKey33B64u,
    ethereumAddress,
    publicCapability,
  });
  const normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1 = {
    kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
    scope: {
      wallet_id: String(authority.walletId),
      ecdsa_threshold_key_id: String(roleLocalBinding.ecdsaThresholdKeyId),
      signing_root_id: String(signer.signingRootId),
      signing_root_version: String(signer.signingRootVersion),
      context: receipt.ecdsa_activation.context,
      public_identity: receipt.ecdsa_activation.public_identity,
      material_activation: receipt.ecdsa_activation.material_activation,
      signing_worker: receipt.ecdsa_activation.signing_worker,
      activation_epoch: receipt.ecdsa_activation.activation_epoch,
    },
  };
  return await input.store.importCommittedWalletCustodyActivation({
    activationBinding,
    serverCommit: {
      correlationId: receipt.activation_correlation_id,
      activationRequestDigest: parseDigestB64u(
        base64UrlEncode(Uint8Array.from(receipt.activation_request_digest.bytes)),
      ),
      serverGeneration: receipt.server_generation,
      protocolReceipt: receipt,
    },
    readyStateBlobB64u: input.readyStateBlobB64u,
    registeredPublicFacts,
    roleLocalPublicFacts,
    routerAbEcdsaDerivationNormalSigning: normalSigning,
    runtimePolicyScope: normalizeRuntimePolicyScope(input.runtimePolicyScope),
    committedAt: parseIsoTimestamp(
      new Date(receipt.ecdsa_activation.activated_at_ms).toISOString(),
    ),
  });
}

async function assertSharedWalletAuthorityMembership(input: {
  readonly walletId: WalletId;
  readonly walletAuthorityId: WalletAuthorityId;
  readonly walletAuthMethodIds: readonly WalletAuthMethodId[];
}): Promise<void> {
  const repositories = new SeamsWalletRepositories(seamsWalletDB);
  for (const walletAuthMethodId of input.walletAuthMethodIds) {
    const authMethod = await repositories.getWalletAuthMethodV2(String(walletAuthMethodId));
    if (
      !authMethod ||
      authMethod.status !== 'active' ||
      authMethod.walletId !== input.walletId ||
      authMethod.walletAuthorityId !== input.walletAuthorityId
    ) {
      throw new Error(
        `ECDSA custody continuity method ${String(walletAuthMethodId)} is not an active member of the wallet authority`,
      );
    }
  }
}

/**
 * R109C: give an added auth method its own encrypted access projection over the
 * activation the wallet already has. The activation is not re-created and the
 * source credential's authority is not widened; only a second method-bound
 * record over the same material appears.
 *
 * The membership check is the whole safety argument. Copying access to a method
 * on another wallet authority would hand that credential custody it was never
 * granted, so both methods are read back and required to be active members of
 * the exact same authority before anything is opened.
 */
export async function copyWalletCustodyEcdsaContinuityToAuthMethod(input: {
  readonly walletId: WalletId;
  readonly walletAuthorityId: WalletAuthorityId;
  readonly sourceWalletAuthMethodId: WalletAuthMethodId;
  readonly targetAuthority: WalletAuthAuthorityRef;
}): Promise<void> {
  if (
    input.targetAuthority.walletId !== input.walletId ||
    input.targetAuthority.walletAuthMethodId === input.sourceWalletAuthMethodId
  ) {
    throw new Error('ECDSA custody continuity target is invalid');
  }
  await assertSharedWalletAuthorityMembership({
    walletId: input.walletId,
    walletAuthorityId: input.walletAuthorityId,
    walletAuthMethodIds: [input.sourceWalletAuthMethodId, input.targetAuthority.walletAuthMethodId],
  });
  const store = new IndexedDbEcdsaCapabilityManifestStore();
  const listed = await store.listActiveWalletCapabilitySubjects(input.walletId);
  if (listed.kind !== 'resolved') {
    throw new Error(`ECDSA custody continuity inventory is ${listed.kind}`);
  }
  const sources = listed.subjects.filter(
    (subject) => subject.authority.walletAuthMethodId === input.sourceWalletAuthMethodId,
  );
  for (const source of sources) {
    const sourceLookup = await store.lookup(source);
    if (sourceLookup.kind !== 'active') {
      throw new Error(`ECDSA custody continuity source is ${sourceLookup.kind}`);
    }
    const targetSelector = {
      capability: source.capability,
      authority: input.targetAuthority,
    };
    const targetLookup = await store.lookup(targetSelector);
    if (targetLookup.kind === 'active') {
      // Repeating a finished copy is a no-op, but only when the projection
      // already there describes the same activation, threshold key, public
      // facts, and role-local binding. Anything else is a different capability
      // wearing the target's key.
      const targetMaterial = targetLookup.manifest.durableMaterial;
      const sourceMaterial = sourceLookup.manifest.durableMaterial;
      if (
        targetMaterial.materialActivation.activationId !==
          sourceMaterial.materialActivation.activationId ||
        targetMaterial.roleLocalBinding.ecdsaThresholdKeyId !==
          sourceMaterial.roleLocalBinding.ecdsaThresholdKeyId ||
        !canonicalValuesMatch(targetMaterial.roleLocalBinding, sourceMaterial.roleLocalBinding) ||
        !canonicalValuesMatch(
          targetMaterial.roleLocalPublicFacts,
          sourceMaterial.roleLocalPublicFacts,
        ) ||
        !canonicalValuesMatch(
          targetLookup.manifest.signer.registeredPublicFacts,
          sourceLookup.manifest.signer.registeredPublicFacts,
        )
      ) {
        throw new Error('ECDSA custody continuity target conflicts with source material');
      }
      continue;
    }
    if (targetLookup.kind !== 'missing') {
      throw new Error(`ECDSA custody continuity target is ${targetLookup.kind}`);
    }
    const opened = await store.openActiveMaterialLookup(sourceLookup);
    if (opened.kind !== 'active') {
      throw new Error(`ECDSA custody continuity material is ${opened.kind}`);
    }
    const manifest = opened.manifest;
    const publicFacts = manifest.durableMaterial.roleLocalPublicFacts;
    const imported = await importWalletCustodyEcdsaContinuity({
      store,
      authority: input.targetAuthority,
      chainTargets: manifest.signer.scope.targetMemberships,
      walletId: String(input.walletId),
      keyHandle: publicFacts.keyHandle,
      ecdsaThresholdKeyId: String(publicFacts.ecdsaThresholdKeyId),
      signingRootId: String(publicFacts.signingRootId),
      signingRootVersion: String(publicFacts.signingRootVersion),
      relayerKeyId: String(manifest.durableMaterial.roleLocalBinding.relayerKeyId),
      participantIds: publicFacts.participantIds,
      publicCapability: publicFacts.publicCapability,
      activationReceipt:
        manifest.activation.serverActivation.serverActivationReceipt.protocolReceipt,
      runtimePolicyScope: manifest.durableMaterial.runtimePolicyScope,
      readyStateBlobB64u: opened.readyStateBlobB64u,
      publicFacts: {
        contextBinding32B64u: publicFacts.contextBinding32B64u,
        derivationClientSharePublicKey33B64u: publicFacts.derivationClientSharePublicKey33B64u,
        clientVerifyingShare33B64u:
          publicFacts.publicCapability.public_identity.derivation_client_share_public_key33_b64u,
        relayerPublicKey33B64u: publicFacts.relayerPublicKey33B64u,
        groupPublicKey33B64u: publicFacts.groupPublicKey33B64u,
        ethereumAddress: publicFacts.ethereumAddress,
        clientShareRetryCounter:
          publicFacts.publicCapability.public_identity.client_share_retry_counter,
        relayerShareRetryCounter:
          publicFacts.publicCapability.public_identity.server_share_retry_counter,
      },
    });
    if (imported.kind !== 'committed') {
      throw new Error(`ECDSA custody continuity import is ${imported.kind}`);
    }
  }
}

async function lookupInTransaction(
  context: SeamsWalletTransactionContext,
  selector: EcdsaCapabilitySelector,
): Promise<LookupTransactionObservation> {
  const pointerRaw = await context.store(POINTER_STORE).get(selectorKey(selector));
  if (pointerRaw === undefined) {
    return await lookupWithoutPointer(context, selector);
  }
  let pointer: ParsedPointerRow;
  try {
    pointer = parsePointerRow(pointerRaw);
  } catch (error: unknown) {
    return { kind: 'corrupt', detail: errorMessage(error) };
  }
  if (!selectorsMatch(pointer.selector, selector)) {
    return {
      kind: 'exact_binding_mismatch',
      detail: 'current ECDSA pointer belongs to a different exact authority',
    };
  }
  const manifestRaw = await context.store(MANIFEST_STORE).get(pointer.manifestId);
  if (manifestRaw === undefined) {
    return {
      kind: 'exact_record_conflict',
      detail: 'current ECDSA pointer references a missing manifest',
    };
  }
  let parsedManifest: ParsedManifestRow;
  try {
    parsedManifest = parseManifestRow(manifestRaw);
  } catch (error: unknown) {
    return { kind: 'corrupt', detail: errorMessage(error) };
  }
  if (!selectorsMatch(parsedManifest.selector, selector)) {
    return {
      kind: 'exact_binding_mismatch',
      detail: 'current ECDSA manifest belongs to a different exact authority',
    };
  }
  if (
    parsedManifest.manifest.identity.manifestId !== pointer.manifestId ||
    parsedManifest.manifest.identity.manifestRevision !== pointer.manifestRevision
  ) {
    return {
      kind: 'exact_record_conflict',
      detail: 'current ECDSA pointer does not match its manifest identity',
    };
  }
  if (parsedManifest.state === 'replaced') {
    return {
      kind: 'retired',
      manifest: parsedManifest.manifest,
    };
  }
  const activeRows = await context
    .store(MANIFEST_STORE)
    .index(SEAMS_WALLET_INDEXES.capabilityWalletAuthorityState)
    .getAll([...selectorKey(selector), 'active']);
  if (activeRows.length !== 1) {
    return {
      kind: 'exact_record_conflict',
      detail: 'exact ECDSA authority has multiple current manifests',
    };
  }
  let indexedActive: ParsedManifestRow;
  try {
    indexedActive = parseManifestRow(activeRows[0]);
  } catch (error: unknown) {
    return { kind: 'corrupt', detail: errorMessage(error) };
  }
  if (
    indexedActive.state !== 'active' ||
    indexedActive.manifest.identity.manifestId !== pointer.manifestId
  ) {
    return {
      kind: 'exact_record_conflict',
      detail: 'exact ECDSA current index disagrees with its pointer',
    };
  }
  const materialRaw = await context
    .store(MATERIAL_STORE)
    .get(parsedManifest.manifest.durableMaterial.durableMaterialRef);
  if (materialRaw === undefined) {
    return {
      kind: 'missing',
      subject: 'material',
      detail: 'active ECDSA manifest is missing its ready material',
    };
  }
  let material: ValidatedEncryptedEcdsaReadyMaterial;
  try {
    material = parseMaterialRow(materialRaw, parsedManifest.activeProof);
  } catch (error: unknown) {
    return { kind: 'corrupt', detail: errorMessage(error) };
  }
  if (!materialMatchesManifest(material, parsedManifest.manifest)) {
    return {
      kind: 'exact_binding_mismatch',
      detail: 'active ECDSA material does not match its manifest',
    };
  }
  const sealingKeyRaw = await context.store(SEALING_KEY_STORE).get(material.sealingKeyId);
  if (sealingKeyRaw === undefined) {
    return {
      kind: 'missing',
      subject: 'material',
      detail: 'active ECDSA material is missing its sealing key',
    };
  }
  try {
    const sealingKey = parseSealingKeyRow(sealingKeyRaw);
    if (sealingKey.keyId !== material.sealingKeyId) {
      return {
        kind: 'exact_binding_mismatch',
        detail: 'active ECDSA material sealing key id does not match',
      };
    }
  } catch (error: unknown) {
    return { kind: 'corrupt', detail: errorMessage(error) };
  }
  if ((await ciphertextDigestB64u(material.ciphertextB64u)) !== material.binding.ciphertextDigest) {
    return {
      kind: 'corrupt',
      detail: 'active ECDSA material ciphertext digest is invalid',
    };
  }
  return {
    kind: 'active',
    manifest: parsedManifest.manifest,
    material,
  };
}

async function lookupWithoutPointer(
  context: SeamsWalletTransactionContext,
  selector: EcdsaCapabilitySelector,
): Promise<LookupTransactionObservation> {
  const rows = await context
    .store(MANIFEST_STORE)
    .index(SEAMS_WALLET_INDEXES.capabilityWallet)
    .getAll([String(selector.capability), String(selector.authority.walletId)]);
  if (rows.length === 0) {
    return {
      kind: 'missing',
      subject: 'capability',
      detail: 'no ECDSA capability manifest exists',
    };
  }
  let hasDifferentAuthority = false;
  let hasExactAuthority = false;
  for (const raw of rows) {
    let parsed: ParsedManifestRow;
    try {
      parsed = parseManifestRow(raw);
    } catch (error: unknown) {
      return { kind: 'corrupt', detail: errorMessage(error) };
    }
    if (selectorsMatch(parsed.selector, selector)) {
      hasExactAuthority = true;
    } else {
      hasDifferentAuthority = true;
    }
  }
  if (hasExactAuthority) {
    return {
      kind: 'exact_record_conflict',
      detail: 'exact ECDSA authority has manifest history without a current pointer',
    };
  }
  if (hasDifferentAuthority) {
    return {
      kind: 'exact_binding_mismatch',
      detail: 'ECDSA capability exists under a different exact authority',
    };
  }
  return {
    kind: 'missing',
    subject: 'capability',
    detail: 'no exact ECDSA capability manifest exists',
  };
}

async function finalizeInTransaction(
  context: SeamsWalletTransactionContext,
  input: FinalizeEcdsaCapabilityActivationInput,
  activeProof: ParsedActiveManifestProof,
  selector: EcdsaCapabilitySelector,
): Promise<void> {
  const journalStore = context.store(JOURNAL_STORE);
  const journalRaw = await journalStore.get(input.committedJournal.journalId);
  if (journalRaw === undefined) {
    throw new FinalizationControlError(
      'exact_record_conflict',
      'ECDSA finalization is missing its durable activation journal',
    );
  }
  let persistedJournal: ReturnType<typeof parseJournalRow>;
  try {
    persistedJournal = parseJournalRow(journalRaw);
  } catch (error: unknown) {
    throw new FinalizationControlError('corrupt', errorMessage(error));
  }
  if (
    persistedJournal.journal.kind !== 'server_activation_committed' ||
    !selectorsMatch(persistedJournal.selector, selector) ||
    !canonicalValuesMatch(persistedJournal.journal, input.committedJournal)
  ) {
    throw new FinalizationControlError(
      'exact_record_conflict',
      'ECDSA finalization journal does not match its committed activation',
    );
  }
  const sealingKeyRaw = await context
    .store(SEALING_KEY_STORE)
    .get(input.readyMaterial.sealingKeyId);
  if (sealingKeyRaw === undefined) {
    throw new FinalizationControlError(
      'corrupt',
      'ECDSA finalization is missing its material sealing key',
    );
  }
  try {
    parseSealingKeyRow(sealingKeyRaw);
  } catch (error: unknown) {
    throw new FinalizationControlError('corrupt', errorMessage(error));
  }

  const pointerStore = context.store(POINTER_STORE);
  const pointerRaw = await pointerStore.get(selectorKey(selector));
  const expected = input.committedJournal.expectedManifest;
  const currentPointer = assertExpectedPointer(expected, pointerRaw, selector);
  const activeRows = await context
    .store(MANIFEST_STORE)
    .index(SEAMS_WALLET_INDEXES.capabilityWalletAuthorityState)
    .getAll([...selectorKey(selector), 'active']);

  let previousProof: ParsedActiveManifestProof | null = null;
  let previousSealingKeyId: EcdsaMaterialSealingKeyId | null = null;
  if (currentPointer === null) {
    if (activeRows.length !== 0) {
      throw new FinalizationControlError(
        'exact_record_conflict',
        'initial ECDSA activation found an unpointed active manifest',
      );
    }
  } else {
    if (activeRows.length !== 1) {
      throw new FinalizationControlError(
        'exact_record_conflict',
        'replacement ECDSA activation found conflicting current manifests',
      );
    }
    let previousManifest: ParsedManifestRow;
    try {
      previousManifest = parseManifestRow(activeRows[0]);
    } catch (error: unknown) {
      throw new FinalizationControlError('corrupt', errorMessage(error));
    }
    if (
      previousManifest.state !== 'active' ||
      previousManifest.manifest.identity.manifestId !== currentPointer.manifestId
    ) {
      throw new FinalizationControlError(
        'exact_record_conflict',
        'replacement ECDSA activation current manifest does not match its pointer',
      );
    }
    if (
      input.committedJournal.activationCommand.expectedGeneration.kind !== 'exact_generation' ||
      previousManifest.activeProof.serverActivation.serverGeneration !==
        input.committedJournal.activationCommand.expectedGeneration.serverGeneration
    ) {
      throw new FinalizationControlError(
        'exact_record_conflict',
        'replacement ECDSA activation server generation CAS did not match',
      );
    }
    const previousMaterialRaw = await context
      .store(MATERIAL_STORE)
      .get(previousManifest.manifest.durableMaterial.durableMaterialRef);
    if (previousMaterialRaw === undefined) {
      throw new FinalizationControlError(
        'corrupt',
        'replacement ECDSA activation is missing prior material',
      );
    }
    try {
      const previousMaterial = parseMaterialRow(previousMaterialRaw, previousManifest.activeProof);
      if (!materialMatchesManifest(previousMaterial, previousManifest.manifest)) {
        throw new Error('prior ECDSA material does not match its active manifest');
      }
      if (previousMaterial.sealingKeyId === input.readyMaterial.sealingKeyId) {
        throw new Error('replacement ECDSA activation must use a fresh material sealing key');
      }
      previousSealingKeyId = previousMaterial.sealingKeyId;
    } catch (error: unknown) {
      throw new FinalizationControlError('corrupt', errorMessage(error));
    }
    previousProof = previousManifest.activeProof;
  }

  const manifestStore = context.store(MANIFEST_STORE);
  const materialStore = context.store(MATERIAL_STORE);
  if (previousProof) {
    if (!previousSealingKeyId) {
      throw new FinalizationControlError(
        'corrupt',
        'replacement ECDSA activation is missing its prior sealing key identity',
      );
    }
    await manifestStore.put(storedReplacedManifestRow(previousProof, activeProof));
    await materialStore.delete(previousProof.durableMaterial.durableMaterialRef);
    await context.store(SEALING_KEY_STORE).delete(previousSealingKeyId);
  }
  await materialStore.add(storedMaterialRow(input.readyMaterial, activeProof.activeManifest));
  await manifestStore.add(storedActiveManifestRow(activeProof));
  await pointerStore.put(storedPointerRow(activeProof.activeManifest));
  await journalStore.delete(input.committedJournal.journalId);
}
