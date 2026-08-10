import {
  parseLaneEnrollmentId,
  parseLaneOperationId,
  parseLaneShareEpoch,
  parseSigningLaneId,
  parseWalletId,
  parseWalletKeyId,
} from '../../../packages/shared-ts/src/utils/domainIds';
import type {
  LaneEnrollmentId,
  WalletKeyId,
} from '../../../packages/shared-ts/src/signing-lanes/ids';
import type { LaneEffectRecordV1 } from '../../../packages/sdk-server-ts/src/core/signingLanes/LaneEffectJournalStore';

function requiredId<T>(
  parser: (raw: unknown) => { ok: true; value: T } | { ok: false; error: { message: string } },
  raw: string,
): T {
  const result = parser(raw);
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

export function buildR102LaneEffectRecordFixture(): LaneEffectRecordV1 {
  return {
    kind: 'lane_effect_record_v1',
    effectId: 'effect-r102-fixture',
    enrollmentId: requiredId(parseLaneEnrollmentId, 'enrollment-r102-fixture'),
    operationId: requiredId(parseLaneOperationId, 'operation-r102-fixture'),
    walletId: requiredId(parseWalletId, 'wallet-r102-fixture'),
    walletKeyId: requiredId(parseWalletKeyId, 'wallet-key-r102-fixture'),
    laneId: requiredId(parseSigningLaneId, 'lane-r102-fixture'),
    laneShareEpoch: requiredId(parseLaneShareEpoch, 'epoch-r102-fixture'),
    effectKind: 'retire_server_material',
    requestDigestB64u: 'request-digest-r102-fixture',
    status: 'recorded',
    recordedAtMs: 1_000,
  };
}

export function buildR102LaneLockIdentitiesFixture(): {
  readonly walletKeyId: WalletKeyId;
  readonly enrollmentId: LaneEnrollmentId;
} {
  return {
    walletKeyId: requiredId(parseWalletKeyId, 'wallet-key-r102-lock'),
    enrollmentId: requiredId(parseLaneEnrollmentId, 'enrollment-r102-lock'),
  };
}
