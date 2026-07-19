import type { NormalizedLogger } from '../logger';
import type { RouterAbEcdsaDerivationPoolFillSessionStore } from '../ThresholdService/stores/EcdsaSigningStore';
import {
  coerceThresholdNodeRole,
  parseThresholdEd25519ParticipantIds2p,
} from '../ThresholdService/config';
import { secureRandomIdFragment } from '../ThresholdService/secureRandomId';
import {
  RouterAbEcdsaDerivationPoolFillHandlers,
  type RouterAbEcdsaPresignSigningWorkerTransport,
} from '../ThresholdService/routerAb/ecdsaDerivationPoolFillHandlers';
import type { RouterAbConfiguredSigningWorkerPrivateTransport } from './RouterAbNormalSigningRuntime';

export type RouterAbEcdsaPresignRuntimeConfig = {
  readonly nodeRole: ReturnType<typeof coerceThresholdNodeRole>;
  readonly participantIds: {
    readonly clientParticipantId: number;
    readonly relayerParticipantId: number;
    readonly participantIds2p: number[];
  };
};

export function parseRouterAbEcdsaPresignRuntimeConfig(
  input: Record<string, unknown>,
): RouterAbEcdsaPresignRuntimeConfig {
  return {
    nodeRole: coerceThresholdNodeRole(input.THRESHOLD_NODE_ROLE),
    participantIds: parseThresholdEd25519ParticipantIds2p(input),
  };
}

type RouterAbEcdsaPresignInitInput = Parameters<
  RouterAbEcdsaDerivationPoolFillHandlers['routerAbEcdsaDerivationPresignaturePoolFillInit']
>[0];

type RouterAbEcdsaPresignStepInput = Parameters<
  RouterAbEcdsaDerivationPoolFillHandlers['routerAbEcdsaDerivationPresignaturePoolFillStep']
>[0];

type RouterAbEcdsaPresignInitResult = Awaited<
  ReturnType<
    RouterAbEcdsaDerivationPoolFillHandlers['routerAbEcdsaDerivationPresignaturePoolFillInit']
  >
>;

type RouterAbEcdsaPresignStepResult = Awaited<
  ReturnType<
    RouterAbEcdsaDerivationPoolFillHandlers['routerAbEcdsaDerivationPresignaturePoolFillStep']
  >
>;

function createPresignSessionId(): string {
  return `ecdsa-presign-${secureRandomIdFragment()}`;
}

function routerAbEcdsaPresignGlobalFetch(
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  return globalThis.fetch(input, init);
}

function resolveSigningWorkerTransport(
  input: RouterAbConfiguredSigningWorkerPrivateTransport,
): RouterAbEcdsaPresignSigningWorkerTransport {
  const fetchImpl =
    input.fetchImpl ??
    (typeof globalThis.fetch === 'function' ? routerAbEcdsaPresignGlobalFetch : null);
  if (!fetchImpl) {
    throw new Error(
      'InvalidLocalServiceConfig: fetch is required for Router A/B ECDSA SigningWorker presign transport',
    );
  }
  return {
    signingWorkerBaseUrl: input.signingWorkerBaseUrl,
    auth: input.auth,
    fetchImpl,
  };
}

export class RouterAbEcdsaPresignRuntime {
  private readonly handlers: RouterAbEcdsaDerivationPoolFillHandlers;

  constructor(input: {
    readonly logger: NormalizedLogger;
    readonly config: RouterAbEcdsaPresignRuntimeConfig;
    readonly ecdsaPoolFillSessionStore: RouterAbEcdsaDerivationPoolFillSessionStore;
    readonly signingWorkerTransport: RouterAbConfiguredSigningWorkerPrivateTransport;
    readonly ensureReady: () => Promise<void>;
  }) {
    this.handlers = new RouterAbEcdsaDerivationPoolFillHandlers({
      logger: input.logger,
      nodeRole: input.config.nodeRole,
      participantIds2p: input.config.participantIds.participantIds2p,
      clientParticipantId: input.config.participantIds.clientParticipantId,
      relayerParticipantId: input.config.participantIds.relayerParticipantId,
      poolFillSessionStore: input.ecdsaPoolFillSessionStore,
      ensureReady: input.ensureReady,
      createPoolFillSessionId: createPresignSessionId,
      signingWorkerTransport: resolveSigningWorkerTransport(input.signingWorkerTransport),
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
