import type {
  EcdsaCapabilityManifestId,
  EcdsaCapabilityManifestRevision,
} from '../utils/ecdsaCapabilityActivation';

export type {
  AgentPrincipalId,
  DelegatedIdempotencyKey,
  DelegatedIntentDigest,
  LaneShareEpoch,
  LaneEnrollmentId,
  LaneOperationId,
  LaneOperationIdempotencyKey,
  LinkedDeviceId,
  LinkedDeviceEnrollmentId,
  LinkDeviceSessionId,
  MandatePolicyId,
  SigningLaneId,
  WalletKeyId,
  Ed25519YaoSuiteId,
  EcdsaRelayerKeyId,
} from '../utils/domainIds';
export type EcdsaManifestIdentity = {
  manifestId: EcdsaCapabilityManifestId;
  manifestRevision: EcdsaCapabilityManifestRevision;
};

// Shared-ts cannot depend on sdk-web's platform module. Keep the chain target
// structural so sdk-web's ThresholdEcdsaChainTarget remains assignable.
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
  parseAgentPrincipalId,
  parseDelegatedIdempotencyKey,
  parseDelegatedIntentDigest,
  parseLaneShareEpoch,
  parseLaneEnrollmentId,
  parseLaneOperationId,
  parseLaneOperationIdempotencyKey,
  parseLinkedDeviceId,
  parseLinkedDeviceEnrollmentId,
  parseLinkDeviceSessionId,
  parseMandatePolicyId,
  parseSigningLaneId,
  parseWalletKeyId,
  parseEd25519YaoSuiteId,
  parseEcdsaRelayerKeyId,
} from '../utils/domainIds';
