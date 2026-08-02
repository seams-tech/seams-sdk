import type { RouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { MpcMaterialActivationId } from '@shared/utils/domainIds';
import {
  MAX_WALLET_SESSION_REMAINING_USES,
  MAX_WALLET_SESSION_TTL_MS,
} from '@shared/threshold/sessionPolicy';
import {
  parseRouterAbNormalSigningServerPolicy,
  validateRouterAbNormalSigningServerPolicy,
  type ParseResult,
  type RouterAbNormalSigningServerPolicy,
} from '../ThresholdService/routerAbNormalSigningPolicy';
import type {
  Ed25519WalletSessionStore,
  EcdsaWalletSessionStore,
} from '../ThresholdService/stores/WalletSessionStore';

export type RouterAbSigningWorkerPrivateTransport =
  | {
      readonly kind: 'configured';
      readonly signingWorkerBaseUrl: string;
      readonly auth: {
        readonly kind: 'internal_service_auth_secret';
        readonly secret: string;
      };
      readonly fetchImpl?: typeof fetch;
    }
  | {
      readonly kind: 'unconfigured';
      readonly signingWorkerBaseUrl?: never;
      readonly auth?: never;
      readonly fetchImpl?: never;
    };

export type RouterAbConfiguredSigningWorkerPrivateTransport = Extract<
  RouterAbSigningWorkerPrivateTransport,
  { readonly kind: 'configured' }
>;

export function requireRouterAbConfiguredSigningWorkerPrivateTransport(
  transport: RouterAbSigningWorkerPrivateTransport,
): RouterAbConfiguredSigningWorkerPrivateTransport {
  if (transport.kind !== 'configured') {
    throw new Error(
      'InvalidLocalServiceConfig: ROUTER_AB_SIGNING_WORKER_URL and ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET are required for Router A/B ECDSA presign',
    );
  }
  return transport;
}

export type RouterAbNormalSigningRuntimeConfig = {
  readonly policy: RouterAbNormalSigningServerPolicy;
  readonly signingWorkerTransport: RouterAbSigningWorkerPrivateTransport;
};

export type RouterAbNormalSigningAuthorizationIdentity =
  | {
      readonly kind: 'reusable_wallet_session';
      readonly walletSessionId: string;
    }
  | {
      readonly kind: 'operation_step_up';
      readonly materialActivationId: MpcMaterialActivationId;
    };

export type RouterAbNormalSigningPrepareReplayReservationInput = {
  readonly curve: 'ed25519' | 'ecdsa';
  readonly authorizationIdentity: RouterAbNormalSigningAuthorizationIdentity;
  readonly requestId: string;
  readonly expiresAtMs: number;
};

export type RouterAbNormalSigningPrepareReplayReservationResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly status: number;
      readonly code: string;
      readonly message: string;
    };

export type RouterAbClampedSessionPolicy = {
  readonly ttlMs: number;
  readonly remainingUses: number;
};

function parseSigningWorkerTransport(
  config: Readonly<Record<string, unknown>>,
): RouterAbSigningWorkerPrivateTransport {
  const signingWorkerBaseUrl = toOptionalTrimmedString(config.ROUTER_AB_SIGNING_WORKER_URL);
  const secret = toOptionalTrimmedString(config.ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET);
  const fetchImpl =
    typeof config.routerAbSigningWorkerFetch === 'function'
      ? (config.routerAbSigningWorkerFetch as typeof fetch)
      : undefined;
  if (!signingWorkerBaseUrl && !secret) return { kind: 'unconfigured' };
  if (!signingWorkerBaseUrl) {
    throw new Error(
      'ROUTER_AB_SIGNING_WORKER_URL is required when Router A/B internal service auth is configured',
    );
  }
  if (!secret) {
    throw new Error(
      'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET is required when Router A/B SigningWorker URL is configured',
    );
  }
  return {
    kind: 'configured',
    signingWorkerBaseUrl,
    auth: { kind: 'internal_service_auth_secret', secret },
    ...(fetchImpl ? { fetchImpl } : {}),
  };
}

export function parseRouterAbNormalSigningRuntimeConfig(
  config: Readonly<Record<string, unknown>>,
): RouterAbNormalSigningRuntimeConfig {
  return {
    policy: parseRouterAbNormalSigningServerPolicy(config),
    signingWorkerTransport: parseSigningWorkerTransport(config),
  };
}

export class RouterAbNormalSigningRuntime {
  private readonly walletSessionStore: Ed25519WalletSessionStore;
  private readonly ecdsaWalletSessionStore: EcdsaWalletSessionStore;
  private readonly config: RouterAbNormalSigningRuntimeConfig;

  constructor(input: {
    readonly walletSessionStore: Ed25519WalletSessionStore;
    readonly ecdsaWalletSessionStore: EcdsaWalletSessionStore;
    readonly config: RouterAbNormalSigningRuntimeConfig;
  }) {
    this.walletSessionStore = input.walletSessionStore;
    this.ecdsaWalletSessionStore = input.ecdsaWalletSessionStore;
    this.config = input.config;
  }

  getSigningWorkerId(): string {
    return this.config.policy.signingWorkerId;
  }

  getSigningWorkerPrivateTransport(): RouterAbSigningWorkerPrivateTransport {
    return this.config.signingWorkerTransport;
  }

  validateSessionPolicy(
    requested: RouterAbEd25519NormalSigningState | undefined,
  ): ParseResult<null> {
    return validateRouterAbNormalSigningServerPolicy({
      requested,
      policy: this.config.policy,
    });
  }

  clampSessionPolicy(input: {
    readonly ttlMs: number;
    readonly remainingUses: number;
  }): RouterAbClampedSessionPolicy {
    const ttlMs = Math.max(0, Math.floor(Number(input.ttlMs) || 0));
    const remainingUses = Math.max(0, Math.floor(Number(input.remainingUses) || 0));
    return {
      ttlMs: Math.min(ttlMs, MAX_WALLET_SESSION_TTL_MS),
      remainingUses: Math.min(remainingUses, MAX_WALLET_SESSION_REMAINING_USES),
    };
  }

  async reservePrepareReplay(
    input: RouterAbNormalSigningPrepareReplayReservationInput,
  ): Promise<RouterAbNormalSigningPrepareReplayReservationResult> {
    const rawReplayIdentity =
      input.authorizationIdentity.kind === 'reusable_wallet_session'
        ? input.authorizationIdentity.walletSessionId
        : input.authorizationIdentity.materialActivationId;
    const replayIdentityValue = toOptionalTrimmedString(rawReplayIdentity);
    const requestId = toOptionalTrimmedString(input.requestId);
    const expiresAtMs = Number(input.expiresAtMs);
    if (!replayIdentityValue || !requestId || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
      return {
        ok: false,
        status: 400,
        code: 'invalid_body',
        message:
          'Router A/B normal-signing replay reservation requires authorization identity, request id, and expiry',
      };
    }
    const store =
      input.curve === 'ed25519' ? this.walletSessionStore : this.ecdsaWalletSessionStore;
    const replayIdentity = `${input.authorizationIdentity.kind}:${replayIdentityValue}`;
    const replayGuard = await store.reserveReplayGuard(
      ['router-ab-normal-signing', input.curve, 'prepare', replayIdentity].join(':'),
      requestId,
      expiresAtMs,
    );
    if (replayGuard.ok) return { ok: true };
    if (replayGuard.code === 'export_nonce_replay') {
      return {
        ok: false,
        status: 400,
        code: 'one_use_replay_rejected',
        message: 'Router A/B normal-signing prepare request id already used',
      };
    }
    if (replayGuard.code === 'export_authorization_expired') {
      return {
        ok: false,
        status: 400,
        code: 'expired_request',
        message: 'Router A/B normal-signing prepare request is expired',
      };
    }
    return {
      ok: false,
      status: 500,
      code: 'internal',
      message: replayGuard.message,
    };
  }

}
