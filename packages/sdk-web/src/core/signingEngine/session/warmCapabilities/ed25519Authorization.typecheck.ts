import type { RouterAbEd25519RuntimeValidatedMaterial } from '../../threshold/ed25519/workerMaterialHandle';
import { buildRouterAbEd25519SigningMaterialRef } from '../../threshold/ed25519/workerMaterialBinding';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { RouterAbEd25519NormalSigningState } from '../../threshold/ed25519/routerAbNormalSigningState';
import type { WarmEd25519SigningSessionAuthorization } from './ed25519Authorization';
import type {
  ThresholdEd25519WorkerMaterialBinding,
  ThresholdEd25519WorkerMaterialSessionBinding,
} from '@/core/types/signer-worker';

const runtimePolicyScope = {
  orgId: 'org-test',
  projectId: 'project-test',
  envId: 'dev',
  signingRootVersion: 'default',
} satisfies ThresholdRuntimePolicyScope;
void runtimePolicyScope;

const routerAbNormalSigning = {
  kind: 'router_ab_ed25519_normal_signing_v1',
  signingWorkerId: 'signing-worker-a',
} satisfies RouterAbEd25519NormalSigningState;
void routerAbNormalSigning;

const warmAuthorization = {
  kind: 'warm_ed25519_signing_session_authorized',
  curve: 'ed25519',
  authMethod: 'passkey',
  walletId: 'alice-wallet',
  nearAccountId: 'alice.testnet',
  nearEd25519SigningKeyId: 'alice-wallet',
  rpId: 'localhost',
  relayerUrl: 'https://router.test',
  relayerKeyId: 'near-key-1',
  participantIds: [1, 2, 3],
  thresholdSessionKind: 'jwt',
  thresholdSessionId: 'threshold-session-1',
  signingGrantId: 'signing-grant-1',
  walletSessionJwt: 'wallet-session-jwt',
  runtimePolicyScope,
  signingRootId: 'project-test:dev',
  signingRootVersion: 'default',
  routerAbNormalSigning,
  signingWorkerId: 'signing-worker-a',
  remainingUses: 3,
  availableUses: 3,
  expiresAtMs: 1_900_000_000_000,
  prfClaim: {
    kind: 'hot_prf_claim',
    sessionId: 'threshold-session-1',
    remainingUses: 3,
    availableUses: 3,
    expiresAtMs: 1_900_000_000_000,
  },
  materialState: 'material_pending',
} satisfies WarmEd25519SigningSessionAuthorization;
void warmAuthorization;

const warmAuthorizationWithMaterialHandle = {
  ...warmAuthorization,
  // @ts-expect-error Unlock authorization cannot carry Ed25519 material handles.
  ed25519WorkerMaterialHandle: 'ed25519-material-handle',
} satisfies WarmEd25519SigningSessionAuthorization;
void warmAuthorizationWithMaterialHandle;

const warmAuthorizationWithRawClientBase = {
  ...warmAuthorization,
  // @ts-expect-error Unlock authorization cannot carry raw Ed25519 client base material.
  xClientBaseB64u: 'raw-client-base',
} satisfies WarmEd25519SigningSessionAuthorization;
void warmAuthorizationWithRawClientBase;

const warmAuthorizationMissingSigningGrant = {
  ...warmAuthorization,
  // @ts-expect-error Unlock authorization requires the signing grant id.
  signingGrantId: undefined,
} satisfies WarmEd25519SigningSessionAuthorization;
void warmAuthorizationMissingSigningGrant;

const signingMaterialRef = buildRouterAbEd25519SigningMaterialRef({
  materialHandle: 'ed25519-material-handle',
  bindingDigest: 'binding-digest',
  clientVerifyingShareB64u: 'client-verifying-share',
});
void signingMaterialRef;

const materialBinding = {
  kind: 'ed25519_worker_material_binding_v1',
  curve: 'ed25519',
  protocol: 'router_ab_normal_signing',
  nearAccountId: 'alice.testnet',
  signerSlot: 1,
  signingRootId: 'project-test:dev',
  signingRootVersion: 'default',
  relayerKeyId: 'near-key-1',
  participantIds: [1, 2, 3],
  clientVerifyingShareB64u: signingMaterialRef.clientVerifierB64u,
  materialFormatVersion: 'ed25519_worker_material_v1',
  materialKeyId: 'material-key-id',
  createdAtMs: 1_700_000_000_000,
} satisfies ThresholdEd25519WorkerMaterialBinding;
void materialBinding;

const sessionBinding = {
  kind: 'ed25519_worker_material_session_binding_v1',
  materialBindingDigest: signingMaterialRef.bindingDigest,
  nearAccountId: 'alice.testnet',
  signerSlot: 1,
  thresholdSessionId: 'threshold-session-1',
  signingGrantId: 'signing-grant-1',
  signingRootId: 'project-test:dev',
  signingRootVersion: 'default',
  runtimePolicyScope,
  relayerKeyId: 'near-key-1',
  participantIds: [1, 2, 3],
  signingWorkerId: 'signing-worker-a',
  expiresAtMs: 1_900_000_000_000,
} satisfies ThresholdEd25519WorkerMaterialSessionBinding;
void sessionBinding;

const signingMaterialReady = {
  kind: 'router_ab_ed25519_runtime_validated_material_v1',
  materialRef: signingMaterialRef,
  materialBinding,
  sessionBinding,
} satisfies RouterAbEd25519RuntimeValidatedMaterial;
void signingMaterialReady;

const signingMaterialMissingRef = {
  ...signingMaterialReady,
  // @ts-expect-error Runtime-validated Ed25519 material requires a parsed material ref.
  materialRef: undefined,
} satisfies RouterAbEd25519RuntimeValidatedMaterial;
void signingMaterialMissingRef;

const signingMaterialMissingBinding = {
  ...signingMaterialReady,
  materialRef: {
    ...signingMaterialRef,
    // @ts-expect-error Runtime-validated Ed25519 material ref requires a binding digest.
    bindingDigest: undefined,
  },
} satisfies RouterAbEd25519RuntimeValidatedMaterial;
void signingMaterialMissingBinding;

const signingMaterialMissingVerifier = {
  ...signingMaterialReady,
  materialRef: {
    ...signingMaterialRef,
    // @ts-expect-error Runtime-validated Ed25519 material ref requires the public client verifier.
    clientVerifierB64u: undefined,
  },
} satisfies RouterAbEd25519RuntimeValidatedMaterial;
void signingMaterialMissingVerifier;

const signingMaterialWithRawClientBase = {
  ...signingMaterialReady,
  // @ts-expect-error Sign-ready Ed25519 material cannot carry raw client base material.
  xClientBaseB64u: 'raw-client-base',
} satisfies RouterAbEd25519RuntimeValidatedMaterial;
void signingMaterialWithRawClientBase;
