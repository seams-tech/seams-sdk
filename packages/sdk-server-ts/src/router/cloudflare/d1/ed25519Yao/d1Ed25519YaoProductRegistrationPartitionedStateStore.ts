import {
  createCloudflareD1VersionedJsonRecordStore,
  type CloudflareD1VersionedJsonRecordStoreOptions,
} from '../versionedJson/d1VersionedJsonRecordStore';
import {
  createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
  encodeRouterAbEd25519YaoProductRegistrationPartitionRecordV1,
  parseRouterAbEd25519YaoProductRegistrationPartitionRecordV1,
  type RouterAbEd25519YaoProductRegistrationPartitionRecordStoreV1,
  type RouterAbEd25519YaoProductRegistrationPartitionRecordV1,
  type RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
} from '../../../domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistrationPartitionedStateStore';

export type RouterAbEd25519YaoProductRegistrationPartitionedStateD1OptionsV1 = Omit<
  CloudflareD1VersionedJsonRecordStoreOptions<RouterAbEd25519YaoProductRegistrationPartitionRecordV1>,
  'encode' | 'parse'
>;

export function createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreFromD1V1(
  options: RouterAbEd25519YaoProductRegistrationPartitionedStateD1OptionsV1,
): RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1 {
  const records = createCloudflareD1VersionedJsonRecordStore({
    ...options,
    encode: encodeRouterAbEd25519YaoProductRegistrationPartitionRecordV1,
    parse: parseRouterAbEd25519YaoProductRegistrationPartitionRecordV1,
  });
  const store: RouterAbEd25519YaoProductRegistrationPartitionRecordStoreV1 = {
    readMany: records.readMany.bind(records),
    putMany: records.putMany.bind(records),
  };
  return createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1(
    store,
    records.patchAtomically.bind(records),
  );
}
