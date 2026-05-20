import type {
  EvmFamilyKeyFingerprint,
  ReadyEcdsaSignerSession,
  VerifiedEcdsaPublicFacts,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import type { ReadyThresholdEcdsaExportMaterial } from './ecdsaExportMaterial';

declare const signerSession: ReadyEcdsaSignerSession;
declare const publicFacts: VerifiedEcdsaPublicFacts;
declare const record: ThresholdEcdsaSessionRecord;
declare const keyRef: unknown;
declare const evmFamilyKeyFingerprint: EvmFamilyKeyFingerprint;

const exportMaterial: ReadyThresholdEcdsaExportMaterial = {
  kind: 'ready_threshold_ecdsa_export_material',
  signerSession,
  publicFacts,
  record,
  cachedExportArtifact: null,
  evmFamilyKeyFingerprint,
};
void exportMaterial;

// @ts-expect-error ready export material requires signer-session material.
const exportMaterialMissingSignerSession: ReadyThresholdEcdsaExportMaterial = {
  kind: 'ready_threshold_ecdsa_export_material',
  publicFacts,
  record,
  cachedExportArtifact: null,
  evmFamilyKeyFingerprint,
};
void exportMaterialMissingSignerSession;

// @ts-expect-error ready export material requires verified public facts.
const exportMaterialMissingPublicFacts: ReadyThresholdEcdsaExportMaterial = {
  kind: 'ready_threshold_ecdsa_export_material',
  signerSession,
  record,
  cachedExportArtifact: null,
  evmFamilyKeyFingerprint,
};
void exportMaterialMissingPublicFacts;

const exportMaterialWithThresholdKeyId: ReadyThresholdEcdsaExportMaterial = {
  ...exportMaterial,
  // @ts-expect-error ready export material carries keyHandle through public facts.
  ecdsaThresholdKeyId: 'ehss-key-1',
};
void exportMaterialWithThresholdKeyId;

const exportMaterialWithBroadReadyMaterial: ReadyThresholdEcdsaExportMaterial = {
  ...exportMaterial,
  // @ts-expect-error export material rejects broad ready signing material.
  readyMaterial: {},
};
void exportMaterialWithBroadReadyMaterial;

const exportMaterialWithBroadKeyRef: ReadyThresholdEcdsaExportMaterial = {
  ...exportMaterial,
  // @ts-expect-error export material exposes signerSession instead of broad key refs.
  keyRef,
};
void exportMaterialWithBroadKeyRef;

export {};
