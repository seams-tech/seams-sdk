import type { RouterAbEd25519NormalSigningReadyState } from './routerAbWalletSessionCredential';
import {
  buildNearTransactionSigningLane,
} from '../../../session/operationState/lanes';
import { SigningSessionIds } from '../../../session/operationState/types';
import type {
  ResolvedRouterAbEd25519WalletSessionState,
} from './routerAbEd25519WalletSessionState';
import { buildRouterAbEd25519SigningMaterialRef } from '../../../threshold/ed25519/hssMaterialBinding';

const validSigningMaterial = buildRouterAbEd25519SigningMaterialRef({
  materialHandle: 'ed25519-hss-material:threshold-session-1:binding',
  bindingDigest: 'binding',
  clientVerifyingShareB64u: 'client-verifying-share',
});

const validWalletSessionState = {
  walletSessionAuth: {
    kind: 'wallet_session_jwt',
    walletSessionJwt: 'wallet-session-jwt',
  },
  thresholdSessionId: 'threshold-session-1',
  walletSigningSessionId: 'wallet-signing-session-1',
  signingLane: buildNearTransactionSigningLane({
    accountId: 'alice.testnet',
    authMethod: 'passkey',
    walletSigningSessionId:
      SigningSessionIds.walletSigningSession('wallet-signing-session-1'),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session('threshold-session-1'),
    storageSource: 'login',
  }),
  remainingUses: 1,
  signingRootId: 'project-test:dev',
  signingRootVersion: 'default',
  signingMaterial: validSigningMaterial,
  runtimePolicyScope: {
    orgId: 'org-test',
    projectId: 'project-test',
    envId: 'dev',
    signingRootVersion: 'default',
  },
  routerAbNormalSigning: {
    kind: 'router_ab_ed25519_normal_signing_v1',
    signingWorkerId: 'signing-worker-a',
  },
  relayerUrl: 'https://router.example',
  persistSigningMaterial: () => true,
  signingWalletSession: {
    curve: 'ed25519',
    auth: {
      kind: 'wallet_session_jwt',
      walletSessionJwt: 'wallet-session-jwt',
      credential: {
        kind: 'jwt',
        walletSessionJwt: 'wallet-session-jwt',
      },
    },
    thresholdSessionId: 'threshold-session-1',
    walletSigningSessionId: 'wallet-signing-session-1',
    remainingUses: 1,
    expiresAtMs: 1_900_000_000_000,
    signingMaterial: validSigningMaterial,
    signingRootId: 'project-test:dev',
    signingRootVersion: 'default',
    runtimePolicyScope: {
      orgId: 'org-test',
      projectId: 'project-test',
      envId: 'dev',
      signingRootVersion: 'default',
    },
    routerAbNormalSigning: {
      kind: 'router_ab_ed25519_normal_signing_v1',
      signingWorkerId: 'signing-worker-a',
    },
  },
} satisfies ResolvedRouterAbEd25519WalletSessionState;
void validWalletSessionState;

const cookieWalletSessionState = {
  ...validWalletSessionState,
  walletSessionAuth: {
    kind: 'browser_cookie',
  },
  signingWalletSession: {
    ...validWalletSessionState.signingWalletSession,
    auth: {
      // @ts-expect-error strict Router A/B Ed25519 signing state requires bearer Wallet Session JWT auth.
      kind: 'browser_cookie',
    },
  },
} satisfies ResolvedRouterAbEd25519WalletSessionState;
void cookieWalletSessionState;

const missingSigningMaterial = {
  ...validWalletSessionState,
  signingWalletSession: {
    ...validWalletSessionState.signingWalletSession,
    // @ts-expect-error Signable Router A/B Ed25519 Wallet Session state requires a parsed material ref.
    signingMaterial: undefined,
  },
} satisfies ResolvedRouterAbEd25519WalletSessionState;
void missingSigningMaterial;

const obsoleteTopLevelRawMaterial = {
  ...validWalletSessionState,
  // @ts-expect-error Resolved Router A/B Ed25519 state keeps raw verifier fields behind the material-ref parser.
  clientVerifyingShareB64u: 'client-verifying-share',
} satisfies ResolvedRouterAbEd25519WalletSessionState;
void obsoleteTopLevelRawMaterial;

const validReadyState = {
  kind: 'router_ab_ed25519_normal_signing_ready_state_v1',
  thresholdSessionId: 'threshold-session-1',
  walletSigningSessionId: 'wallet-signing-session-1',
  nearAccountId: 'alice.testnet',
  relayerUrl: 'https://router.example',
  routerAbNormalSigning: {
    kind: 'router_ab_ed25519_normal_signing_v1',
    signingWorkerId: 'signing-worker-a',
  },
  signingWorkerId: 'signing-worker-a',
  signerPublicKey: 'ed25519:signer-public-key',
  signingRootId: 'project-test:dev',
  signingRootVersion: 'default',
  expiresAtMs: 1_900_000_000_000,
  signingMaterial: validSigningMaterial,
  runtimePolicyScope: {
    orgId: 'org-test',
    projectId: 'project-test',
    envId: 'dev',
    signingRootVersion: 'default',
  },
  credential: {
    kind: 'jwt',
    walletSessionJwt: 'wallet-session-jwt',
  },
} satisfies RouterAbEd25519NormalSigningReadyState;
void validReadyState;

// @ts-expect-error Router A/B ready state requires parsed normal-signing state.
const missingRouterAbNormalSigning: RouterAbEd25519NormalSigningReadyState = {
  kind: 'router_ab_ed25519_normal_signing_ready_state_v1',
  thresholdSessionId: 'threshold-session-1',
  walletSigningSessionId: 'wallet-signing-session-1',
  nearAccountId: 'alice.testnet',
  relayerUrl: 'https://router.example',
  signingWorkerId: 'signing-worker-a',
  signerPublicKey: 'ed25519:signer-public-key',
  signingRootId: validReadyState.signingRootId,
  signingRootVersion: validReadyState.signingRootVersion,
  expiresAtMs: validReadyState.expiresAtMs,
  signingMaterial: validReadyState.signingMaterial,
  runtimePolicyScope: validReadyState.runtimePolicyScope,
  credential: validReadyState.credential,
};
void missingRouterAbNormalSigning;

// @ts-expect-error Router A/B Ed25519 ready state requires a parsed material ref.
const missingReadyMaterial: RouterAbEd25519NormalSigningReadyState = {
  kind: 'router_ab_ed25519_normal_signing_ready_state_v1',
  thresholdSessionId: validReadyState.thresholdSessionId,
  walletSigningSessionId: validReadyState.walletSigningSessionId,
  nearAccountId: validReadyState.nearAccountId,
  relayerUrl: validReadyState.relayerUrl,
  routerAbNormalSigning: validReadyState.routerAbNormalSigning,
  signingWorkerId: validReadyState.signingWorkerId,
  signerPublicKey: validReadyState.signerPublicKey,
  signingRootId: validReadyState.signingRootId,
  signingRootVersion: validReadyState.signingRootVersion,
  expiresAtMs: validReadyState.expiresAtMs,
  runtimePolicyScope: validReadyState.runtimePolicyScope,
  credential: validReadyState.credential,
};
void missingReadyMaterial;

const obsoleteReadyRawMaterial: RouterAbEd25519NormalSigningReadyState = {
  ...validReadyState,
  // @ts-expect-error Router A/B Ed25519 ready state keeps raw verifier fields behind the material-ref parser.
  clientVerifyingShareB64u: 'client-verifying-share',
};
void obsoleteReadyRawMaterial;

const missingReadyMaterialBindingDigest = {
  ...validReadyState,
  signingMaterial: {
    ...validReadyState.signingMaterial,
    // @ts-expect-error Router A/B Ed25519 material ref requires a binding digest.
    bindingDigest: undefined,
  },
} satisfies RouterAbEd25519NormalSigningReadyState;
void missingReadyMaterialBindingDigest;

const missingReadyMaterialClientVerifier = {
  ...validReadyState,
  signingMaterial: {
    ...validReadyState.signingMaterial,
    // @ts-expect-error Router A/B Ed25519 material ref requires a material verifier.
    clientVerifierB64u: undefined,
  },
} satisfies RouterAbEd25519NormalSigningReadyState;
void missingReadyMaterialClientVerifier;

const missingReadyMaterialHandle = {
  ...validReadyState,
  signingMaterial: {
    ...validReadyState.signingMaterial,
    // @ts-expect-error Router A/B Ed25519 material ref requires a worker-owned HSS material handle.
    materialHandle: undefined,
  },
} satisfies RouterAbEd25519NormalSigningReadyState;
void missingReadyMaterialHandle;

const cookieReadyState: RouterAbEd25519NormalSigningReadyState = {
  ...validReadyState,
  credential: {
    // @ts-expect-error Router A/B Ed25519 ready state is bearer-only.
    kind: 'cookie',
    walletSessionJwt: 'wallet-session-jwt',
  },
};
void cookieReadyState;

const missingWalletSessionJwt: RouterAbEd25519NormalSigningReadyState = {
  ...validReadyState,
  // @ts-expect-error Router A/B Ed25519 ready state requires Wallet Session JWT auth.
  credential: {
    kind: 'jwt',
  },
};
void missingWalletSessionJwt;

const legacyAuthSpread: RouterAbEd25519NormalSigningReadyState = {
  ...validReadyState,
  // @ts-expect-error Router A/B Ed25519 ready state rejects legacy auth-token fields.
  thresholdSessionAuthToken: 'threshold-session-jwt',
};
void legacyAuthSpread;
