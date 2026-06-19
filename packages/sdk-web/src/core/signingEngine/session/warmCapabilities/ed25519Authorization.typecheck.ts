import type { RouterAbEd25519SigningMaterialReady } from '../../threshold/ed25519/hssClientBase';
import { buildRouterAbEd25519SigningMaterialRef } from '../../threshold/ed25519/hssMaterialBinding';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { RouterAbEd25519NormalSigningState } from '../../threshold/ed25519/routerAbNormalSigningState';
import type { WarmEd25519SigningSessionAuthorization } from './ed25519Authorization';

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
  nearAccountId: 'alice.testnet',
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
  ed25519HssMaterialHandle: 'ed25519-material-handle',
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
  // @ts-expect-error Unlock authorization requires the wallet signing session id.
  signingGrantId: undefined,
} satisfies WarmEd25519SigningSessionAuthorization;
void warmAuthorizationMissingSigningGrant;

const signingMaterialRef = buildRouterAbEd25519SigningMaterialRef({
  materialHandle: 'ed25519-material-handle',
  bindingDigest: 'binding-digest',
  clientVerifyingShareB64u: 'client-verifying-share',
});
void signingMaterialRef;

const signingMaterialReady = {
  kind: 'router_ab_ed25519_signing_material_ready_v1',
  materialHandle: signingMaterialRef.materialHandle,
  bindingDigest: signingMaterialRef.bindingDigest,
  thresholdSessionId: 'threshold-session-1',
  signingGrantId: 'signing-grant-1',
  signingRootId: 'project-test:dev',
  signingRootVersion: 'default',
  expiresAtMs: 1_900_000_000_000,
  nearAccountId: 'alice.testnet',
  relayerKeyId: 'near-key-1',
  participantIds: [1, 2, 3],
  signingWorkerId: 'signing-worker-a',
  clientVerifyingShareB64u: signingMaterialRef.clientVerifierB64u,
} satisfies RouterAbEd25519SigningMaterialReady;
void signingMaterialReady;

const signingMaterialMissingHandle = {
  ...signingMaterialReady,
  // @ts-expect-error Sign-ready Ed25519 material requires a worker material handle.
  materialHandle: undefined,
} satisfies RouterAbEd25519SigningMaterialReady;
void signingMaterialMissingHandle;

const signingMaterialMissingBinding = {
  ...signingMaterialReady,
  // @ts-expect-error Sign-ready Ed25519 material requires a binding digest.
  bindingDigest: undefined,
} satisfies RouterAbEd25519SigningMaterialReady;
void signingMaterialMissingBinding;

const signingMaterialMissingVerifier = {
  ...signingMaterialReady,
  // @ts-expect-error Sign-ready Ed25519 material requires the public client verifier.
  clientVerifyingShareB64u: undefined,
} satisfies RouterAbEd25519SigningMaterialReady;
void signingMaterialMissingVerifier;

const signingMaterialWithRawClientBase = {
  ...signingMaterialReady,
  // @ts-expect-error Sign-ready Ed25519 material cannot carry raw client base material.
  xClientBaseB64u: 'raw-client-base',
} satisfies RouterAbEd25519SigningMaterialReady;
void signingMaterialWithRawClientBase;
