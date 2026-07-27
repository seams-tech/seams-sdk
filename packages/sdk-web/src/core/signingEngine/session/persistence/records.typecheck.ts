import {
  commitCurrentThresholdEcdsaSession,
  commitCurrentThresholdEd25519Session,
  type EmailOtpEcdsaSessionRecord,
  type OperationUsableThresholdEd25519SessionRecord,
  type ReadyPasskeyEcdsaSessionRecord,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
  type ThresholdEd25519SessionRecord,
} from './records';
import type {
  ThresholdEcdsaClientAdditiveShareHandle,
} from '../../interfaces/signing';
import type {
  EcdsaRoleLocalPersistedMaterialRef,
  EcdsaRoleLocalWorkerHandle,
} from '../keyMaterialBrands';
import type { EcdsaRoleLocalReadyRecord } from '@/core/platform/types';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';

declare const ecdsaDeps: ThresholdEcdsaSessionStoreDeps;
declare const genericEcdsaRecord: ThresholdEcdsaSessionRecord;
declare const genericEd25519Record: ThresholdEd25519SessionRecord;
declare const currentEd25519Record: OperationUsableThresholdEd25519SessionRecord;
declare const roleLocalWorkerHandle: EcdsaRoleLocalWorkerHandle;
declare const roleLocalMaterialRef: EcdsaRoleLocalPersistedMaterialRef;
declare const passkeyRecord: ReadyPasskeyEcdsaSessionRecord;
declare const emailOtpRecord: EmailOtpEcdsaSessionRecord;
declare const clientAdditiveShareHandle: ThresholdEcdsaClientAdditiveShareHandle;
declare const roleLocalReadyRecord: EcdsaRoleLocalReadyRecord;
declare const authority: WalletAuthAuthorityRef;
declare const materialActivation: MpcMaterialActivationRef;

const validExactIdentityRecord: ThresholdEcdsaSessionRecord = {
  ...genericEcdsaRecord,
  authority,
  materialActivation,
};
void validExactIdentityRecord;

const invalidEcdsaRecordWithoutAuthority: ThresholdEcdsaSessionRecord = {
  ...genericEcdsaRecord,
  // @ts-expect-error Canonical ECDSA session records require exact wallet authority.
  authority: undefined,
};
void invalidEcdsaRecordWithoutAuthority;

const invalidEcdsaRecordWithoutMaterialActivation: ThresholdEcdsaSessionRecord = {
  ...genericEcdsaRecord,
  // @ts-expect-error Canonical ECDSA session records require exact material activation.
  materialActivation: undefined,
};
void invalidEcdsaRecordWithoutMaterialActivation;

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

const invalidPasskeyRecordWithOwnedDurableMaterial: ReadyPasskeyEcdsaSessionRecord = {
  ...passkeyRecord,
  // @ts-expect-error Session records cannot own canonical durable role-local material.
  roleLocalMaterialRef,
};
void invalidPasskeyRecordWithOwnedDurableMaterial;

const invalidEmailOtpRecordWithInlineState: EmailOtpEcdsaSessionRecord = {
  ...emailOtpRecord,
  // @ts-expect-error Persisted Email OTP records cannot contain inline role-local state.
  ecdsaRoleLocalReadyRecord: roleLocalReadyRecord,
};
void invalidEmailOtpRecordWithInlineState;

// @ts-expect-error Persisted role-local material requires exact activation identity.
const invalidRoleLocalMaterialRefWithoutActivation: EcdsaRoleLocalPersistedMaterialRef = {
  kind: 'ecdsa_role_local_persisted_material_ref_v1',
  durableMaterialRef: roleLocalMaterialRef.durableMaterialRef,
  bindingDigest: roleLocalMaterialRef.bindingDigest,
};
void invalidRoleLocalMaterialRefWithoutActivation;

const invalidEmailOtpRecordWithWorkerSession: EmailOtpEcdsaSessionRecord = {
  ...emailOtpRecord,
  // @ts-expect-error Persisted Email OTP records cannot contain worker-session material.
  clientAdditiveShareHandle,
};
void invalidEmailOtpRecordWithWorkerSession;

void commitCurrentThresholdEcdsaSession({
  deps: ecdsaDeps,
  record: genericEcdsaRecord,
});

void commitCurrentThresholdEd25519Session({
  record: currentEd25519Record,
});

void commitCurrentThresholdEd25519Session({
  // @ts-expect-error Current Ed25519 commit requires an operation-usable boundary-built record.
  record: genericEd25519Record,
});

export {};
