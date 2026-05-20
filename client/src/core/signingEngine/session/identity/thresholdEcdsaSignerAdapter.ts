import type {
  ThresholdEcdsaCanonicalExportArtifact,
  ThresholdEcdsaSecp256k1KeyRef,
} from '../../interfaces/signing';
import {
  resolveThresholdEcdsaKeyIdFromRecord,
  resolveThresholdSigningRootBindingFromRecord,
} from './evmFamilyEcdsaIdentity';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';

export function buildThresholdEcdsaSecp256k1KeyRefFromRecord(args: {
  record: ThresholdEcdsaSessionRecord;
  exportArtifact?: ThresholdEcdsaCanonicalExportArtifact;
}): ThresholdEcdsaSecp256k1KeyRef {
  const record = args.record;
  const signingRootBinding = resolveThresholdSigningRootBindingFromRecord({
    record,
  });
  return {
    type: 'threshold-ecdsa-secp256k1',
    userId: String(record.walletId),
    chainTarget: record.chainTarget,
    relayerUrl: record.relayerUrl,
    keyHandle: record.keyHandle,
    ecdsaThresholdKeyId: resolveThresholdEcdsaKeyIdFromRecord({ record }),
    signingRootId: signingRootBinding.signingRootId,
    ...(signingRootBinding.signingRootVersion
      ? { signingRootVersion: signingRootBinding.signingRootVersion }
      : {}),
    backendBinding: {
      relayerKeyId: record.relayerKeyId,
      clientVerifyingShareB64u: record.clientVerifyingShareB64u,
      ...(record.clientAdditiveShare32B64u
        ? { clientAdditiveShare32B64u: record.clientAdditiveShare32B64u }
        : {}),
      ...(record.clientAdditiveShareHandle
        ? { clientAdditiveShareHandle: record.clientAdditiveShareHandle }
        : {}),
      ...(record.ecdsaHssRoleLocalClientState
        ? { ecdsaHssRoleLocalClientState: record.ecdsaHssRoleLocalClientState }
        : {}),
    },
    ...(args.exportArtifact ? { ecdsaHssExportArtifact: args.exportArtifact } : {}),
    participantIds: record.participantIds,
    thresholdSessionKind: record.thresholdSessionKind,
    thresholdSessionId: record.thresholdSessionId,
    walletSigningSessionId: record.walletSigningSessionId,
    ...(record.thresholdSessionAuthToken
      ? { thresholdSessionAuthToken: record.thresholdSessionAuthToken }
      : {}),
    ...(record.thresholdEcdsaPublicKeyB64u
      ? { thresholdEcdsaPublicKeyB64u: record.thresholdEcdsaPublicKeyB64u }
      : {}),
    ...(record.ethereumAddress ? { ethereumAddress: record.ethereumAddress } : {}),
    ...(record.relayerVerifyingShareB64u
      ? { relayerVerifyingShareB64u: record.relayerVerifyingShareB64u }
      : {}),
  };
}
