import type {
  ThresholdEcdsaCanonicalExportArtifact,
  ThresholdEcdsaSecp256k1KeyRef,
} from '../../interfaces/signing';
import { buildThresholdEcdsaSecp256k1KeyRefFromSessionRecord } from './evmFamilyEcdsaIdentity';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';

export function buildThresholdEcdsaSecp256k1KeyRefFromRecord(args: {
  record: ThresholdEcdsaSessionRecord;
  exportArtifact?: ThresholdEcdsaCanonicalExportArtifact;
}): ThresholdEcdsaSecp256k1KeyRef {
  return buildThresholdEcdsaSecp256k1KeyRefFromSessionRecord({
    record: args.record,
    ...(args.exportArtifact ? { exportArtifact: args.exportArtifact } : {}),
  });
}
