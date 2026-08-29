import type {
  EcdsaCapabilityManifestId,
  EcdsaCapabilityManifestRevision,
} from '../utils/ecdsaCapabilityActivation';

export type {
  LaneShareEpoch,
  LaneEnrollmentId,
  LaneOperationId,
  LaneOperationIdempotencyKey,
  LinkedDeviceId,
  LinkedDeviceEnrollmentId,
  LinkDeviceSessionId,
  SigningLaneId,
  WalletKeyId,
  Ed25519YaoSuiteId,
  EcdsaRelayerKeyId,
} from '../utils/domainIds';
export type EcdsaManifestIdentity = {
  manifestId: EcdsaCapabilityManifestId;
  manifestRevision: EcdsaCapabilityManifestRevision;
};

// Shared-ts cannot depend on the wallet package's platform module. Keep the
// chain target structural so its ThresholdEcdsaChainTarget remains assignable.
export type ThresholdEcdsaChainTarget =
  | {
      kind: 'evm';
      namespace: 'eip155';
      chainId: number;
      networkSlug: string;
    }
  | {
      kind: 'tempo';
      chainId: number;
      networkSlug: string;
    };

export {
  parseLaneShareEpoch,
  parseLaneEnrollmentId,
  parseLaneOperationId,
  parseLaneOperationIdempotencyKey,
  parseLinkedDeviceId,
  parseLinkedDeviceEnrollmentId,
  parseLinkDeviceSessionId,
  parseSigningLaneId,
  parseWalletKeyId,
  parseEd25519YaoSuiteId,
  parseEcdsaRelayerKeyId,
} from '../utils/domainIds';
