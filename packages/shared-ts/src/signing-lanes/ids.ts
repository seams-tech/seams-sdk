import type { DomainId } from '../utils/domainIds';
import type {
  EcdsaCapabilityManifestId,
  EcdsaCapabilityManifestRevision,
} from '../utils/ecdsaCapabilityActivation';

export type {
  AgentPrincipalId,
  DelegatedIdempotencyKey,
  DelegatedIntentDigest,
  LaneShareEpoch,
  LinkedDeviceId,
  LinkDeviceSessionId,
  MandatePolicyId,
  RotationOperationId,
  SigningLaneId,
  WalletKeyId,
} from '../utils/domainIds';

// Lane protocol identities are deliberately distinct from the legacy
// delegated-operation and rotation ids. A protocol operation and its parent
// enrollment are immutable transcript identities.
export type LaneOperationId = DomainId<'LaneOperationId'>;
export type LaneEnrollmentId = DomainId<'LaneEnrollmentId'>;
export type LaneOperationIdempotencyKey = DomainId<'LaneOperationIdempotencyKey'>;
export type LinkedDeviceEnrollmentId = DomainId<'LinkedDeviceEnrollmentId'>;

// These protocol bindings are public identifiers, never private key material.
export type Ed25519YaoSuiteId = string & {
  readonly __ed25519YaoSuiteIdBrand: 'Ed25519YaoSuiteId';
};
export type EcdsaRelayerKeyId = string & {
  readonly __ecdsaRelayerKeyIdBrand: 'EcdsaRelayerKeyId';
};
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
  parseLinkedDeviceId,
  parseLinkDeviceSessionId,
  parseMandatePolicyId,
  parseRotationOperationId,
  parseSigningLaneId,
  parseWalletKeyId,
} from '../utils/domainIds';
