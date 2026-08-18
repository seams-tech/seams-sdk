import {
  coerceThresholdNodeRole,
  parseThresholdEd25519ParticipantIds2p,
} from '../ThresholdService/config';
import { secureRandomIdFragment } from '../ThresholdService/secureRandomId';
import {
  RouterAbEcdsaDerivationPoolFillHandlers,
  type RouterAbEcdsaPresignSigningWorkerTransport,
} from '../ThresholdService/routerAb/ecdsaDerivationPoolFillHandlers';
import {
  startRouterAbLinkedDeviceEcdsaPresignSession,
  stepRouterAbLinkedDeviceEcdsaPresignSession,
  type RouterAbEcdsaPresignSessionHttpResult,
} from '../ThresholdService/routerAb/ecdsaDerivationPresignBridge';
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

function createPresignSessionId(expiresAtMs: number): string {
  return `ecdsa-presign-v2:${expiresAtMs}:${secureRandomIdFragment()}`;
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
  private readonly signingWorkerTransport: RouterAbEcdsaPresignSigningWorkerTransport;

  constructor(input: {
    readonly config: RouterAbEcdsaPresignRuntimeConfig;
    readonly signingWorkerTransport: RouterAbConfiguredSigningWorkerPrivateTransport;
    readonly ensureReady: () => Promise<void>;
  }) {
    this.signingWorkerTransport = resolveSigningWorkerTransport(input.signingWorkerTransport);
    this.handlers = new RouterAbEcdsaDerivationPoolFillHandlers({
      nodeRole: input.config.nodeRole,
      participantIds2p: input.config.participantIds.participantIds2p,
      ensureReady: input.ensureReady,
      createPoolFillSessionId: createPresignSessionId,
      signingWorkerTransport: this.signingWorkerTransport,
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

  async initializeLinkedDevicePresign(input: {
    readonly request: Record<string, unknown>;
    readonly materialSource: Record<string, unknown>;
    readonly presignSessionId: string;
    readonly expiresAtMs: number;
  }): Promise<RouterAbEcdsaPresignSessionHttpResult> {
    const transport = this.signingWorkerTransport;
    return await startRouterAbLinkedDeviceEcdsaPresignSession({
      signingWorkerBaseUrl: transport.signingWorkerBaseUrl,
      request: input.request,
      materialSource: input.materialSource,
      presignSessionId: input.presignSessionId,
      expiresAtMs: input.expiresAtMs,
      auth: transport.auth,
      fetchImpl: transport.fetchImpl,
    });
  }

  async advanceLinkedDevicePresign(input: {
    readonly request: Record<string, unknown>;
    readonly materialSource: Record<string, unknown>;
    readonly presignSessionId: string;
    readonly requestedStage: 'triples' | 'presign';
    readonly outgoingMessagesB64u: string[];
    readonly expiresAtMs: number;
  }): Promise<RouterAbEcdsaPresignSessionHttpResult> {
    const transport = this.signingWorkerTransport;
    return await stepRouterAbLinkedDeviceEcdsaPresignSession({
      signingWorkerBaseUrl: transport.signingWorkerBaseUrl,
      request: input.request,
      materialSource: input.materialSource,
      presignSessionId: input.presignSessionId,
      requestedStage: input.requestedStage,
      outgoingMessagesB64u: input.outgoingMessagesB64u,
      expiresAtMs: input.expiresAtMs,
      auth: transport.auth,
      fetchImpl: transport.fetchImpl,
    });
  }
}
