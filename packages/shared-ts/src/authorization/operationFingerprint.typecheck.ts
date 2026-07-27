import type { DigestB64u } from '../utils/canonicalPrimitives';
import {
  CAPABILITY_KINDS,
  EVM_ECDSA_MPC_OPERATION_KINDS,
  NEAR_ED25519_MPC_OPERATION_KINDS,
  VAULT_OPERATION_KINDS,
  buildEvmEcdsaMpcOperationRef,
  buildNearEd25519MpcOperationRef,
  buildVaultOperationRef,
  type CapabilityId,
  type CapabilityOperationId,
  type TenantId,
} from './capabilityKinds';
import {
  buildCapabilityOperationEnvelope,
  type CapabilityOperationEnvelope,
  type CapabilityOperationFingerprintDigest,
} from './operationFingerprint';

declare const tenantId: TenantId;
declare const capabilityId: CapabilityId;
declare const operationId: CapabilityOperationId;
declare const laneDigest: DigestB64u;
declare const intentDigest: DigestB64u;
declare const displayDigest: DigestB64u;
declare const fingerprintDigest: CapabilityOperationFingerprintDigest;

const vaultEnvelope = buildCapabilityOperationEnvelope({
  tenantId,
  capabilityId,
  operationId,
  operation: buildVaultOperationRef(VAULT_OPERATION_KINDS.proxyUse),
  digests: {
    laneDigest,
    intentDigest,
    displayDigest,
  },
});

const nearEnvelope = buildCapabilityOperationEnvelope({
  tenantId,
  capabilityId,
  operationId,
  operation: buildNearEd25519MpcOperationRef(NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction),
  digests: {
    laneDigest,
    intentDigest,
    displayDigest,
  },
});

const evmEnvelope = buildCapabilityOperationEnvelope({
  tenantId,
  capabilityId,
  operationId,
  operation: buildEvmEcdsaMpcOperationRef(EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction),
  digests: {
    laneDigest,
    intentDigest,
    displayDigest,
  },
});

void vaultEnvelope;
void nearEnvelope;
void evmEnvelope;
void fingerprintDigest;

buildCapabilityOperationEnvelope({
  // @ts-expect-error Capability-operation envelopes require branded tenant identity.
  tenantId: 'tenant-1',
  capabilityId,
  operationId,
  operation: buildVaultOperationRef(VAULT_OPERATION_KINDS.proxyUse),
  digests: { laneDigest, intentDigest, displayDigest },
});

buildCapabilityOperationEnvelope({
  tenantId,
  capabilityId,
  operationId,
  // @ts-expect-error A vault capability cannot carry a NEAR operation.
  operation: {
    capabilityKind: CAPABILITY_KINDS.vaultAccess,
    operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
  },
  digests: { laneDigest, intentDigest, displayDigest },
});

buildCapabilityOperationEnvelope({
  tenantId,
  capabilityId,
  operationId,
  operation: buildVaultOperationRef(VAULT_OPERATION_KINDS.proxyUse),
  digests: {
    // @ts-expect-error Raw strings must be parsed into canonical digests.
    laneDigest: 'raw-digest',
    intentDigest,
    displayDigest,
  },
});

buildCapabilityOperationEnvelope({
  tenantId,
  capabilityId,
  operationId,
  operation: buildVaultOperationRef(VAULT_OPERATION_KINDS.proxyUse),
  digests: { laneDigest, intentDigest, displayDigest },
  // @ts-expect-error Authorization and session identities are excluded from operation semantics.
  grantId: 'grant-1',
});

// @ts-expect-error The private proof prevents direct envelope construction.
const forgedEnvelope: CapabilityOperationEnvelope = {
  tenantId,
  capabilityId,
  operationId,
  operation: buildVaultOperationRef(VAULT_OPERATION_KINDS.proxyUse),
  digests: { laneDigest, intentDigest, displayDigest },
};
void forgedEnvelope;

// @ts-expect-error A general digest is not an authorization operation fingerprint.
const forgedFingerprint: CapabilityOperationFingerprintDigest = laneDigest;
void forgedFingerprint;
