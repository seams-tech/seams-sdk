import {
  commitCurrentThresholdEcdsaSession,
  commitCurrentThresholdEd25519Session,
  type OperationUsableThresholdEcdsaSessionRecord,
  type OperationUsableThresholdEd25519SessionRecord,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
  type ThresholdEd25519SessionRecord,
} from './records';

declare const ecdsaDeps: ThresholdEcdsaSessionStoreDeps;
declare const genericEcdsaRecord: ThresholdEcdsaSessionRecord;
declare const currentEcdsaRecord: OperationUsableThresholdEcdsaSessionRecord;
declare const genericEd25519Record: ThresholdEd25519SessionRecord;
declare const currentEd25519Record: OperationUsableThresholdEd25519SessionRecord;

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
