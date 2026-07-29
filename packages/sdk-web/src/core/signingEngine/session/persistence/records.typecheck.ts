import {
  commitCurrentThresholdEd25519Session,
  type OperationUsableThresholdEd25519SessionRecord,
  type ThresholdEd25519SessionRecord,
} from './records';

declare const genericEd25519Record: ThresholdEd25519SessionRecord;
declare const currentEd25519Record: OperationUsableThresholdEd25519SessionRecord;

void commitCurrentThresholdEd25519Session({
  record: currentEd25519Record,
});

void commitCurrentThresholdEd25519Session({
  // @ts-expect-error Current Ed25519 commit requires an operation-usable boundary-built record.
  record: genericEd25519Record,
});

export {};
