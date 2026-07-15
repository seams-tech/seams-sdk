import type { RouterAbEcdsaHssNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaHss';
import type { ThresholdRuntimePolicyScope } from '../threshold/sessionPolicy';
import { buildRouterAbEcdsaHssSigningMaterialRef } from '../routerAb/ecdsaHss/signingMaterialRef';
import type {
  RouterAbEcdsaHssSigningWalletSession,
  RouterAbSigningWalletSessionAuth,
} from './routerAbSigningWalletSession';

const walletSessionAuth = {
  kind: 'wallet_session_jwt',
  walletSessionJwt: 'wallet-session-jwt',
  credential: {
    kind: 'jwt',
    walletSessionJwt: 'wallet-session-jwt',
  },
} satisfies RouterAbSigningWalletSessionAuth;

const runtimePolicyScope = {
  orgId: 'org-test',
  projectId: 'project-test',
  envId: 'dev',
  signingRootVersion: 'default',
} satisfies ThresholdRuntimePolicyScope;

const routerAbNormalSigning = {
  kind: 'router_ab_ecdsa_hss_normal_signing_v1',
  scope: {
    wallet_key_id: 'localhost',
    wallet_id: 'alice.testnet',
    ecdsa_threshold_key_id: 'ehss-shared-key',
    signing_root_id: 'project-test:dev',
    signing_root_version: 'default',
    context: {
      application_binding_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
    },
    public_identity: {
      context_binding_b64u: 'context-binding',
      client_public_key33_b64u: 'client-public-key',
      server_public_key33_b64u: 'server-public-key',
      threshold_public_key33_b64u: 'threshold-public-key',
      ethereum_address20_b64u: 'ethereum-address',
      client_share_retry_counter: 0,
      server_share_retry_counter: 0,
    },
    signing_worker: {
      server_id: 'signing-worker-a',
      key_epoch: 'epoch-1',
      recipient_encryption_key: 'x25519:recipient',
    },
    activation_epoch: 'activation-epoch-1',
  },
} satisfies RouterAbEcdsaHssNormalSigningStateV1;

const signingMaterial = buildRouterAbEcdsaHssSigningMaterialRef({
  routerAbState: routerAbNormalSigning,
});

const validSession = {
  curve: 'ecdsa',
  auth: walletSessionAuth,
  thresholdSessionId: 'threshold-session-1',
  signingGrantId: 'signing-grant-1',
  remainingUses: 1,
  expiresAtMs: 1_900_000_000_000,
  signingMaterial,
  runtimePolicyScope,
  routerAbEcdsaHssNormalSigning: routerAbNormalSigning,
} satisfies RouterAbEcdsaHssSigningWalletSession;

const missingRouterAbState = {
  ...validSession,
  // @ts-expect-error A signable ECDSA-HSS Wallet Session requires Router A/B state.
  routerAbEcdsaHssNormalSigning: undefined,
} satisfies RouterAbEcdsaHssSigningWalletSession;
void missingRouterAbState;

const missingRuntimePolicyScope = {
  ...validSession,
  // @ts-expect-error A signable ECDSA-HSS Wallet Session requires runtime policy scope.
  runtimePolicyScope: undefined,
} satisfies RouterAbEcdsaHssSigningWalletSession;
void missingRuntimePolicyScope;

const cookieAuth = {
  ...validSession,
  auth: {
    // @ts-expect-error A signable ECDSA-HSS Wallet Session requires bearer JWT auth.
    kind: 'browser_cookie',
  },
} satisfies RouterAbEcdsaHssSigningWalletSession;
void cookieAuth;

const rawClientShare = {
  ...validSession,
  // @ts-expect-error Raw client signing shares cannot enter Wallet Session state.
  clientSigningShare32: new Uint8Array(32),
} satisfies RouterAbEcdsaHssSigningWalletSession;
void rawClientShare;

const rawClientVerifier = {
  ...validSession,
  // @ts-expect-error Verifier material is carried by the parsed signing material.
  clientVerifyingShareB64u: 'raw-client-verifier',
} satisfies RouterAbEcdsaHssSigningWalletSession;
void rawClientVerifier;

const missingSigningMaterial = {
  ...validSession,
  // @ts-expect-error A signable ECDSA-HSS Wallet Session requires parsed signing material.
  signingMaterial: undefined,
} satisfies RouterAbEcdsaHssSigningWalletSession;
void missingSigningMaterial;
