import type { RouterAbEd25519NormalSigningState } from './routerAbNormalSigningState';

const validRouterAbNormalSigningState = {
  kind: 'router_ab_ed25519_normal_signing_v1',
  signingWorkerId: 'signing-worker-a',
} satisfies RouterAbEd25519NormalSigningState;
void validRouterAbNormalSigningState;

// @ts-expect-error Router A/B normal signing requires an explicit SigningWorker id.
const missingSigningWorkerId: RouterAbEd25519NormalSigningState = {
  kind: 'router_ab_ed25519_normal_signing_v1',
};
void missingSigningWorkerId;

const wrongNormalSigningStateKind: RouterAbEd25519NormalSigningState = {
  // @ts-expect-error Router A/B normal signing rejects unknown state variants.
  kind: 'router_ab_ed25519_normal_signing_invalid_variant',
  signingWorkerId: 'signing-worker-a',
};
void wrongNormalSigningStateKind;
