import type { NormalizedLogger } from '../logger';
import type {
  RouterAbEcdsaDerivationPoolFillSessionStore,
} from '../ThresholdService/stores/EcdsaSigningStore';
import type { ThresholdEcdsaIntegratedKeyStore } from '../ThresholdService/stores/KeyStore';
import type { ThresholdEcdsaSessionStore } from '../ThresholdService/stores/SessionStore';
import {
  coerceThresholdNodeRole,
  parseThresholdCoordinatorPeers,
  parseThresholdEd25519ParticipantIds2p,
} from '../ThresholdService/config';
import { secureRandomIdFragment } from '../ThresholdService/secureRandomId';
import {
  RouterAbEcdsaDerivationPoolFillHandlers,
} from '../ThresholdService/routerAb/ecdsaDerivationPoolFillHandlers';
import type { RouterAbEcdsaDerivationPoolFillLiveSessionOwner } from '../ThresholdService/routerAb/ecdsaDerivationPoolFillLiveSession';
import type { RouterAbNormalSigningRuntime } from './RouterAbNormalSigningRuntime';

export type RouterAbEcdsaPresignRuntimeConfig = {
  readonly nodeRole: ReturnType<typeof coerceThresholdNodeRole>;
  readonly participantIds: {
    readonly clientParticipantId: number;
    readonly relayerParticipantId: number;
    readonly participantIds2p: number[];
  };
  readonly coordinatorInstanceId: string | null;
  readonly coordinatorPeers: ReturnType<typeof parseThresholdCoordinatorPeers>;
};

export function parseRouterAbEcdsaPresignRuntimeConfig(
  input: Record<string, unknown>,
): RouterAbEcdsaPresignRuntimeConfig {
  const coordinatorInstanceIdRaw = input.THRESHOLD_COORDINATOR_INSTANCE_ID;
  const coordinatorInstanceId =
    typeof coordinatorInstanceIdRaw === 'string' && coordinatorInstanceIdRaw.trim()
      ? coordinatorInstanceIdRaw.trim()
      : null;
  return {
    nodeRole: coerceThresholdNodeRole(input.THRESHOLD_NODE_ROLE),
    participantIds: parseThresholdEd25519ParticipantIds2p(input),
    coordinatorInstanceId,
    coordinatorPeers: parseThresholdCoordinatorPeers(input.THRESHOLD_COORDINATOR_PEERS),
  };
}

type RouterAbEcdsaPresignInitInput = Parameters<
  RouterAbEcdsaDerivationPoolFillHandlers['routerAbEcdsaDerivationPresignaturePoolFillInit']
>[0];

type RouterAbEcdsaPresignStepInput = Parameters<
  RouterAbEcdsaDerivationPoolFillHandlers['routerAbEcdsaDerivationPresignaturePoolFillStep']
>[0];

type RouterAbEcdsaPresignInitResult = Awaited<
  ReturnType<RouterAbEcdsaDerivationPoolFillHandlers['routerAbEcdsaDerivationPresignaturePoolFillInit']>
>;

type RouterAbEcdsaPresignStepResult = Awaited<
  ReturnType<RouterAbEcdsaDerivationPoolFillHandlers['routerAbEcdsaDerivationPresignaturePoolFillStep']>
>;

function createPresignSessionId(): string {
  return `ecdsa-presign-${secureRandomIdFragment()}`;
}

export class RouterAbEcdsaPresignRuntime {
  private readonly handlers: RouterAbEcdsaDerivationPoolFillHandlers;

  constructor(input: {
    readonly logger: NormalizedLogger;
    readonly config: RouterAbEcdsaPresignRuntimeConfig;
    readonly ecdsaSessionStore: ThresholdEcdsaSessionStore;
    readonly ecdsaPoolFillSessionStore: RouterAbEcdsaDerivationPoolFillSessionStore;
    readonly ecdsaKeyStore: ThresholdEcdsaIntegratedKeyStore;
    readonly normalSigningRuntime: RouterAbNormalSigningRuntime;
    readonly ensureReady: () => Promise<void>;
    readonly liveSessionOwner: RouterAbEcdsaDerivationPoolFillLiveSessionOwner | undefined;
  }) {
    const privateTransport = input.normalSigningRuntime.getSigningWorkerPrivateTransport();
    const poolFillTransport =
      privateTransport.kind === 'configured'
        ? {
            signingWorkerBaseUrl: privateTransport.signingWorkerBaseUrl,
            auth: privateTransport.auth,
          }
        : null;
    this.handlers = new RouterAbEcdsaDerivationPoolFillHandlers({
      logger: input.logger,
      nodeRole: input.config.nodeRole,
      participantIds2p: input.config.participantIds.participantIds2p,
      clientParticipantId: input.config.participantIds.clientParticipantId,
      relayerParticipantId: input.config.participantIds.relayerParticipantId,
      coordinatorInstanceId: input.config.coordinatorInstanceId,
      coordinatorPeers: input.config.coordinatorPeers ?? [],
      sessionStore: {
        readMpcSession: input.ecdsaSessionStore.readMpcSession.bind(input.ecdsaSessionStore),
        claimMpcSession: input.ecdsaSessionStore.claimMpcSession.bind(input.ecdsaSessionStore),
      },
      poolFillSessionStore: input.ecdsaPoolFillSessionStore,
      resolveRoleLocalKeyRecord: input.ecdsaKeyStore.getRoleLocalByKeyHandle.bind(
        input.ecdsaKeyStore,
      ),
      ensureReady: input.ensureReady,
      createPoolFillSessionId: createPresignSessionId,
      liveSessionOwner: input.liveSessionOwner,
      routerAbEcdsaDerivationPoolFill: poolFillTransport,
    });
  }

  healthz(): { readonly ok: true } {
    return { ok: true };
  }

  async initializePoolFill(
    input: RouterAbEcdsaPresignInitInput,
  ): Promise<RouterAbEcdsaPresignInitResult> {
    return await this.handlers.routerAbEcdsaDerivationPresignaturePoolFillInit(input);
  }

  async advancePoolFill(
    input: RouterAbEcdsaPresignStepInput,
  ): Promise<RouterAbEcdsaPresignStepResult> {
    return await this.handlers.routerAbEcdsaDerivationPresignaturePoolFillStep(input);
  }
}
