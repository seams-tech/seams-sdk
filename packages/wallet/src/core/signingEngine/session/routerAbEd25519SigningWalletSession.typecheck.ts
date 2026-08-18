import type { RouterAbEd25519NormalSigningState } from '../threshold/ed25519/routerAbNormalSigningState';
import type { ThresholdRuntimePolicyScope } from '../threshold/sessionPolicy';
import type {
  RouterAbEd25519SigningWalletSession,
  RouterAbSigningWalletSessionAuth,
} from './routerAbSigningWalletSession';
import type {
  ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import type {
  MpcWalletSigningQuotaId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';

declare const walletSessionId: WalletSessionId;
declare const authorizationId: WalletSessionAuthorizationId;
declare const quotaId: MpcWalletSigningQuotaId;
declare const thresholdSessionId: ThresholdEd25519SessionId;

const auth = {
  kind: 'wallet_session_opaque',
  walletSessionToken: 'wallet-session-token',
  credential: {
    kind: 'wallet_session_opaque',
    walletSessionToken: 'wallet-session-token',
  },
} satisfies RouterAbSigningWalletSessionAuth;

const runtimePolicyScope = {
  orgId: 'org-test',
  projectId: 'project-test',
  envId: 'dev',
  signingRootVersion: 'default',
} satisfies ThresholdRuntimePolicyScope;

const routerAbNormalSigning = {
  kind: 'router_ab_ed25519_normal_signing_v1',
  signingWorkerId: 'signing-worker-a',
} satisfies RouterAbEd25519NormalSigningState;

const validSession = {
  curve: 'ed25519',
  auth,
  walletSessionId,
  authorizationId,
  thresholdSessionId,
  quotaId,
  remainingUses: 2,
  expiresAtMs: 1_900_000_000_000,
  runtimePolicyScope,
  signingRootId: 'project-test:dev',
  signingRootVersion: 'default',
  routerAbNormalSigning,
} satisfies RouterAbEd25519SigningWalletSession;
void validSession;

// @ts-expect-error Public Ed25519 Wallet Session state requires a signing root.
const missingSigningRoot: RouterAbEd25519SigningWalletSession = {
  curve: 'ed25519',
  auth,
  walletSessionId,
  thresholdSessionId,
  quotaId,
  remainingUses: 2,
  expiresAtMs: 1_900_000_000_000,
  runtimePolicyScope,
  signingRootVersion: 'default',
  routerAbNormalSigning,
};
void missingSigningRoot;

const embeddedWorkerMaterial = {
  curve: 'ed25519',
  auth,
  walletSessionId,
  thresholdSessionId,
  quotaId,
  remainingUses: 2,
  expiresAtMs: 1_900_000_000_000,
  runtimePolicyScope,
  signingRootId: 'project-test:dev',
  signingRootVersion: 'default',
  routerAbNormalSigning,
  // @ts-expect-error Yao Client state cannot enter public Wallet Session state.
  signingMaterial: { materialHandle: 'legacy-worker-material' },
} satisfies RouterAbEd25519SigningWalletSession;
void embeddedWorkerMaterial;

const embeddedActiveClient = {
  curve: 'ed25519',
  auth,
  walletSessionId,
  thresholdSessionId,
  quotaId,
  remainingUses: 2,
  expiresAtMs: 1_900_000_000_000,
  runtimePolicyScope,
  signingRootId: 'project-test:dev',
  signingRootVersion: 'default',
  routerAbNormalSigning,
  // @ts-expect-error Active Yao Client state belongs in the in-memory capability registry.
  activeClient: {},
} satisfies RouterAbEd25519SigningWalletSession;
void embeddedActiveClient;
