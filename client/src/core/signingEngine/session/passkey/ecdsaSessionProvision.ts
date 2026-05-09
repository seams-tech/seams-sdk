import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { ThresholdSessionSealTransportAuthMaterial } from '../persistence/records';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  bootstrapEcdsaSessionValue,
  type BootstrapEcdsaSessionArgs,
  type ThresholdSessionActivationDeps,
} from './ecdsaBootstrap';
import { withThresholdEcdsaBootstrapQueue } from '../warmCapabilities/ecdsaBootstrapQueue';
import {
  ensureEcdsaPrfSealPersisted,
  type WarmSessionSealPersistPorts,
} from './runtime';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';

export type ProvisionThresholdEcdsaSessionDeps = {
  queueByAccount: Map<string, Promise<void>>;
  activationDeps: ThresholdSessionActivationDeps;
  touchConfirm: WarmSessionSealPersistPorts;
  resolveSealTransport: (args: {
    thresholdSessionId: string;
    chainTarget: ThresholdEcdsaChainTarget;
  }) => ThresholdSessionSealTransportAuthMaterial | null;
};

export async function provisionThresholdEcdsaSession(
  deps: ProvisionThresholdEcdsaSessionDeps,
  args: BootstrapEcdsaSessionArgs,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const nearAccountId = toAccountId(args.nearAccountId);
  return await withThresholdEcdsaBootstrapQueue(deps.queueByAccount, nearAccountId, async () => {
    const bootstrap = await bootstrapEcdsaSessionValue(deps.activationDeps, {
      ...args,
      nearAccountId,
    });
    const thresholdSessionId = String(bootstrap.thresholdEcdsaKeyRef.thresholdSessionId || '').trim();
    if (thresholdSessionId) {
      await ensureEcdsaPrfSealPersisted({
        touchConfirm: deps.touchConfirm,
        chainTarget: args.chainTarget,
        thresholdSessionId,
        required: Boolean(args.thresholdSessionAuth),
        errorContext: 'threshold-ecdsa bootstrap seal persistence',
        sealPersistInFlightBySessionId: new Map(),
        resolveSealTransport: deps.resolveSealTransport,
      });
    }
    return bootstrap;
  });
}
