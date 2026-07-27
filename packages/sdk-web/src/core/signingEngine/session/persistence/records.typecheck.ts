import {
  commitCurrentThresholdEcdsaSession,
  commitCurrentThresholdEd25519Session,
  type EmailOtpEcdsaSessionRecord,
  type OperationUsableThresholdEcdsaSessionRecord,
  type OperationUsableThresholdEd25519SessionRecord,
  type ReadyPasskeyEcdsaSessionRecord,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
  type ThresholdEd25519SessionRecord,
} from './records';
import type {
  EcdsaRoleLocalPersistedMaterialRef,
  EcdsaRoleLocalWorkerHandle,
} from '../keyMaterialBrands';

declare const ecdsaDeps: ThresholdEcdsaSessionStoreDeps;
declare const genericEcdsaRecord: ThresholdEcdsaSessionRecord;
declare const currentEcdsaRecord: OperationUsableThresholdEcdsaSessionRecord;
declare const genericEd25519Record: ThresholdEd25519SessionRecord;
declare const currentEd25519Record: OperationUsableThresholdEd25519SessionRecord;
declare const roleLocalWorkerHandle: EcdsaRoleLocalWorkerHandle;
declare const roleLocalMaterialRef: EcdsaRoleLocalPersistedMaterialRef;
declare const passkeyRecord: ReadyPasskeyEcdsaSessionRecord;
declare const emailOtpRecord: EmailOtpEcdsaSessionRecord;
declare const workerOwnedEmailOtpRecord: Extract<
  EmailOtpEcdsaSessionRecord,
  { roleLocalMaterialRef: unknown }
>;
declare const inlineEmailOtpRecord: Extract<
  EmailOtpEcdsaSessionRecord,
  { ecdsaRoleLocalReadyRecord: unknown }
>;

const invalidDurableEcdsaRecordWithVolatileHandle: ThresholdEcdsaSessionRecord = {
  ...genericEcdsaRecord,
  // @ts-expect-error Durable ECDSA session records cannot contain runtime worker handles.
  roleLocalMaterialHandle: roleLocalWorkerHandle,
};
void invalidDurableEcdsaRecordWithVolatileHandle;

const invalidPasskeyRecordWithEmailOtpAuth: ReadyPasskeyEcdsaSessionRecord = {
  ...passkeyRecord,
  // @ts-expect-error Passkey records require passkey role-local auth.
  ecdsaRoleLocalAuthMethod: emailOtpRecord.ecdsaRoleLocalAuthMethod,
};
void invalidPasskeyRecordWithEmailOtpAuth;

const invalidPasskeyRecordWithoutDurableMaterial: ReadyPasskeyEcdsaSessionRecord = {
  ...passkeyRecord,
  // @ts-expect-error Passkey records require durable role-local material.
  roleLocalMaterialRef: undefined,
};
void invalidPasskeyRecordWithoutDurableMaterial;

const invalidInlineEmailOtpRecordWithDurableMaterial: typeof inlineEmailOtpRecord = {
  ...inlineEmailOtpRecord,
  // @ts-expect-error Inline Email OTP records cannot also reference worker-owned material.
  roleLocalMaterialRef: workerOwnedEmailOtpRecord.roleLocalMaterialRef,
};
void invalidInlineEmailOtpRecordWithDurableMaterial;

// @ts-expect-error Persisted role-local material requires exact activation identity.
const invalidRoleLocalMaterialRefWithoutActivation: EcdsaRoleLocalPersistedMaterialRef = {
  kind: 'ecdsa_role_local_persisted_material_ref_v1',
  durableMaterialRef: roleLocalMaterialRef.durableMaterialRef,
  bindingDigest: roleLocalMaterialRef.bindingDigest,
};
void invalidRoleLocalMaterialRefWithoutActivation;

const invalidWorkerOwnedEmailOtpRecordWithInlineState: typeof workerOwnedEmailOtpRecord = {
  ...workerOwnedEmailOtpRecord,
  // @ts-expect-error Worker-owned Email OTP records cannot also contain inline role-local state.
  ecdsaRoleLocalReadyRecord: inlineEmailOtpRecord.ecdsaRoleLocalReadyRecord,
};
void invalidWorkerOwnedEmailOtpRecordWithInlineState;

void commitCurrentThresholdEcdsaSession({
  deps: ecdsaDeps,
  record: currentEcdsaRecord,
  transition: 'step_up',
});

void commitCurrentThresholdEcdsaSession({
  deps: ecdsaDeps,
  // @ts-expect-error Current ECDSA commit requires an operation-usable boundary-built record.
  record: genericEcdsaRecord,
  transition: 'step_up',
});

void commitCurrentThresholdEd25519Session({
  record: currentEd25519Record,
  transition: 'step_up',
});

void commitCurrentThresholdEd25519Session({
  // @ts-expect-error Current Ed25519 commit requires an operation-usable boundary-built record.
  record: genericEd25519Record,
  transition: 'step_up',
});

export {};
