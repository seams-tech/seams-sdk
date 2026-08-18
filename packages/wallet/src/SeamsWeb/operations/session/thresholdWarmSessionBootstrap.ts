import type { SeamsConfigsReadonly } from '@/core/types/seams';
import {
  ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
  type RouterAbEd25519NormalSigningState,
} from '@shared/utils/signingSessionSeal';

function assertNeverNormalSigning(value: never): never {
  throw new Error(`Unexpected Router A/B normal-signing config branch: ${String(value)}`);
}

export function createRouterAbNormalSigningPolicy(
  configs: SeamsConfigsReadonly,
): RouterAbEd25519NormalSigningState {
  const normalSigning = configs.signing.routerAb.normalSigning;
  switch (normalSigning.mode) {
    case 'disabled':
      throw new Error(
        '[threshold-warm-session] Router A/B normal signing must be enabled for Ed25519 sessions',
      );
    case 'enabled':
      return {
        kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
        signingWorkerId: normalSigning.signingWorkerId,
      };
    default:
      return assertNeverNormalSigning(normalSigning);
  }
}
