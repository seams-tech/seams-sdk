import type { RouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { parseWalletId } from '@shared/utils/domainIds';
import { parseNearAccountId } from '@shared/utils/near';
import {
  parseNearEd25519SigningKeyId,
  type NearEd25519SigningKeyId,
} from '@shared/utils/registrationIntent';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  MAX_WALLET_SESSION_REMAINING_USES,
  MAX_WALLET_SESSION_TTL_MS,
} from '@shared/threshold/sessionPolicy';
import type { ThresholdEd25519AuthorityScope } from '../types';
import {
  parseRouterAbNormalSigningServerPolicy,
  validateRouterAbNormalSigningServerPolicy,
  type ParseResult,
  type RouterAbNormalSigningServerPolicy,
} from '../ThresholdService/routerAbNormalSigningPolicy';
import type {
  Ed25519WalletSessionStore,
  Ed25519WalletSessionRecord,
  EcdsaWalletSessionRecord,
  EcdsaWalletSessionStore,
  WalletSigningBudgetEcdsaBinding,
  WalletSigningBudgetEd25519Binding,
  WalletSigningBudgetSessionRecord,
  WalletSigningBudgetSessionStatus,
  WalletSigningBudgetSessionStore,
} from '../ThresholdService/stores/WalletSessionStore';
import { walletSigningBudgetSessionId } from '../ThresholdService/walletSigningBudget';
import {
  parseThresholdEd25519AuthorityScope,
  thresholdEd25519AuthorityScopesMatch,
} from '../ThresholdService/validation';
import {
  walletSessionFailureMessage,
  walletSessionFailureStatus,
  type WalletSessionFailureCode,
} from '../../router/walletSessionFailure';

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

export type RouterAbNormalSigningPrepareReplayReservationInput =
  | {
      readonly curve: 'ed25519';
      readonly thresholdSessionId: string;
      readonly requestId: string;
      readonly expiresAtMs: number;
    }
  | {
      readonly curve: 'ecdsa';
      readonly thresholdSessionId: string;
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

export type RouterAbNormalSigningBudgetReservationInput =
  | {
      readonly curve: 'ed25519';
      readonly thresholdSessionId: string;
      readonly signingGrantId: string;
      readonly signingWorkerId: string;
      readonly operationId: string;
      readonly requestDigest: string;
      readonly signatureUses: number;
      readonly expiresAtMs: number;
    }
  | {
      readonly curve: 'ecdsa';
      readonly thresholdSessionId: string;
      readonly signingGrantId: string;
      readonly signingWorkerId: string;
      readonly operationId: string;
      readonly requestDigest: string;
      readonly signatureUses: number;
      readonly expiresAtMs: number;
    };

export type RouterAbNormalSigningBudgetReservationResult =
  | {
      readonly ok: true;
      readonly reservationId: string;
      readonly remainingUses: number;
      readonly reservedUses: number;
      readonly availableUses: number;
    }
  | {
      readonly ok: false;
      readonly status: number;
      readonly code: string;
      readonly message: string;
    };

export type RouterAbNormalSigningBudgetFinalizeInput =
  | {
      readonly curve: 'ed25519';
      readonly thresholdSessionId: string;
      readonly signingGrantId: string;
      readonly reservationId: string;
      readonly signingWorkerId: string;
      readonly operationId: string;
      readonly requestDigest: string;
    }
  | {
      readonly curve: 'ecdsa';
      readonly thresholdSessionId: string;
      readonly signingGrantId: string;
      readonly reservationId: string;
      readonly signingWorkerId: string;
      readonly operationId: string;
      readonly requestDigest: string;
    };

export type RouterAbNormalSigningBudgetCommitResult =
  | { readonly ok: true; readonly remainingUses: number }
  | {
      readonly ok: false;
      readonly status: number;
      readonly code: string;
      readonly message: string;
    };

export type RouterAbNormalSigningBudgetReleaseInput =
  | {
      readonly curve: 'ed25519';
      readonly phase: 'prepare' | 'finalize';
      readonly thresholdSessionId: string;
      readonly signingGrantId: string;
      readonly reservationId: string;
    }
  | {
      readonly curve: 'ecdsa';
      readonly phase: 'prepare' | 'finalize';
      readonly thresholdSessionId: string;
      readonly signingGrantId: string;
      readonly reservationId: string;
    };

export type RouterAbNormalSigningBudgetReleaseResult =
  | {
      readonly ok: true;
      readonly released: boolean;
      readonly remainingUses: number;
      readonly reservedUses: number;
      readonly availableUses: number;
    }
  | {
      readonly ok: false;
      readonly status: number;
      readonly code: string;
      readonly message: string;
    };

export type RouterAbSigningGrantBudgetInput = {
  readonly signingGrantId: string;
  readonly thresholdSessionId: string;
  readonly userId: string;
  readonly participantIds: readonly number[];
  readonly ttlMs: number;
  readonly remainingUses: number;
  readonly operation: 'provision_curve_binding' | 'refresh_exhausted_binding';
} & (
  | {
      readonly curve: 'ed25519';
      readonly authorityScope: ThresholdEd25519AuthorityScope;
      readonly evmFamilySigningKeySlotId?: never;
    }
  | {
      readonly curve: 'ecdsa';
      readonly evmFamilySigningKeySlotId: string;
      readonly authorityScope?: never;
    }
);

export type RouterAbSigningGrantBudgetResult =
  | {
      readonly ok: true;
      readonly expiresAtMs: number;
      readonly participantIds: number[];
    }
  | { readonly ok: false; readonly code: string; readonly message: string };

export type RouterAbClampedSessionPolicy = {
  readonly ttlMs: number;
  readonly remainingUses: number;
};

export type RouterAbEd25519YaoNormalSigningSessionProvisionInput = {
  readonly kind: 'router_ab_ed25519_yao_normal_signing_session_v1';
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly authorityScope: ThresholdEd25519AuthorityScope;
  readonly thresholdSessionId: string;
  readonly signingGrantId: string;
  readonly signingWorkerId: string;
  readonly expiresAtMs: number;
  readonly participantIds: readonly [number, number];
  readonly remainingUses: number;
};

export type RouterAbEd25519YaoNormalSigningSessionProvisionResult =
  | {
      readonly ok: true;
      readonly thresholdSessionId: string;
      readonly signingGrantId: string;
      readonly expiresAtMs: number;
      readonly remainingUses: number;
    }
  | { readonly ok: false; readonly code: string; readonly message: string };

export type RouterAbEd25519YaoNormalSigningBudgetRefreshInput = {
  readonly kind: 'router_ab_ed25519_yao_normal_signing_budget_refresh_v1';
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly authorityScope: ThresholdEd25519AuthorityScope;
  readonly thresholdSessionId: string;
  readonly signingGrantId: string;
  readonly signingWorkerId: string;
  readonly participantIds: readonly [number, number];
  readonly ttlMs: number;
  readonly remainingUses: number;
};

export type RouterAbEd25519YaoNormalSigningBudgetRefreshResult =
  RouterAbEd25519YaoNormalSigningSessionProvisionResult;

export type RouterAbEcdsaNormalSigningSessionProvisionInput = {
  readonly kind: 'router_ab_ecdsa_normal_signing_session_v1';
  readonly walletId: string;
  readonly evmFamilySigningKeySlotId: string;
  readonly relayerKeyId: string;
  readonly thresholdSessionId: string;
  readonly signingGrantId: string;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly participantIds: readonly [number, number];
  readonly expiresAtMs: number;
  readonly remainingUses: number;
};

export type RouterAbEcdsaNormalSigningSessionProvisionResult =
  | {
      readonly ok: true;
      readonly thresholdSessionId: string;
      readonly signingGrantId: string;
      readonly expiresAtMs: number;
      readonly remainingUses: number;
      readonly participantIds: readonly [number, number];
    }
  | { readonly ok: false; readonly code: string; readonly message: string };

type BudgetCurve = 'ed25519' | 'ecdsa';

type ResolvedSigningGrantBudget =
  | {
      readonly ok: true;
      readonly budgetSessionId: string;
      readonly store: WalletSigningBudgetSessionStore;
    }
  | { readonly ok: false; readonly code: string; readonly message: string };

function assertNever(value: never): never {
  throw new Error(`Unexpected Router A/B normal-signing branch: ${String(value)}`);
}

function errorMessage(error: unknown): string {
  if (error && typeof error === 'object' && 'message' in error) {
    return String(error.message ?? '');
  }
  return String(error || '');
}

function participantIdsEqual(left: readonly number[], right: readonly number[]): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function normalizeExactEcdsaParticipantIds(
  raw: readonly [number, number],
): [number, number] | null {
  const first = Number(raw[0]);
  const second = Number(raw[1]);
  if (
    !Number.isSafeInteger(first) ||
    first <= 0 ||
    !Number.isSafeInteger(second) ||
    second <= 0 ||
    first === second
  ) {
    return null;
  }
  return [first, second];
}

function ecdsaWalletSessionsHaveSameAuthority(
  left: EcdsaWalletSessionRecord,
  right: EcdsaWalletSessionRecord,
): boolean {
  return (
    left.relayerKeyId === right.relayerKeyId &&
    left.walletId === right.walletId &&
    left.evmFamilySigningKeySlotId === right.evmFamilySigningKeySlotId &&
    participantIdsEqual(left.participantIds, right.participantIds)
  );
}

function ed25519WalletSessionsHaveSameAuthority(
  left: Ed25519WalletSessionRecord,
  right: Ed25519WalletSessionRecord,
): boolean {
  return (
    left.walletId === right.walletId &&
    left.userId === right.userId &&
    left.nearAccountId === right.nearAccountId &&
    left.nearEd25519SigningKeyId === right.nearEd25519SigningKeyId &&
    left.relayerKeyId === right.relayerKeyId &&
    thresholdEd25519AuthorityScopesMatch(left.authorityScope, right.authorityScope) &&
    participantIdsEqual(left.participantIds, right.participantIds)
  );
}

function signingGrantBudgetRecordHasCommonIdentity(
  record: WalletSigningBudgetSessionRecord,
  input: RouterAbSigningGrantBudgetInput,
): boolean {
  return record.walletId === input.userId;
}

function signingGrantBudgetEd25519Binding(
  record: WalletSigningBudgetSessionRecord,
): WalletSigningBudgetEd25519Binding | null {
  switch (record.bindings.kind) {
    case 'ed25519_only':
    case 'ed25519_and_ecdsa':
      return record.bindings.ed25519;
    case 'ecdsa_only':
      return null;
    default:
      return assertNever(record.bindings);
  }
}

function signingGrantBudgetEcdsaBindings(
  record: WalletSigningBudgetSessionRecord,
): readonly WalletSigningBudgetEcdsaBinding[] {
  switch (record.bindings.kind) {
    case 'ecdsa_only':
    case 'ed25519_and_ecdsa':
      return record.bindings.ecdsa;
    case 'ed25519_only':
      return [];
    default:
      return assertNever(record.bindings);
  }
}

function signingGrantBudgetRecordMatchesCurveBinding(
  record: WalletSigningBudgetSessionRecord,
  input: RouterAbSigningGrantBudgetInput,
): boolean {
  switch (input.curve) {
    case 'ed25519': {
      const binding = signingGrantBudgetEd25519Binding(record);
      return (
        binding !== null &&
        binding.thresholdSessionId === input.thresholdSessionId &&
        thresholdEd25519AuthorityScopesMatch(binding.authorityScope, input.authorityScope) &&
        participantIdsEqual(binding.participantIds, input.participantIds)
      );
    }
    case 'ecdsa': {
      for (const binding of signingGrantBudgetEcdsaBindings(record)) {
        if (
          binding.thresholdSessionId === input.thresholdSessionId &&
          binding.evmFamilySigningKeySlotId === input.evmFamilySigningKeySlotId &&
          participantIdsEqual(binding.participantIds, input.participantIds)
        ) {
          return true;
        }
      }
      return false;
    }
    default:
      return assertNever(input);
  }
}

function signingGrantBudgetCanAddCurveBinding(
  record: WalletSigningBudgetSessionRecord,
  input: RouterAbSigningGrantBudgetInput,
): boolean {
  switch (input.curve) {
    case 'ed25519':
      return signingGrantBudgetEd25519Binding(record) === null;
    case 'ecdsa':
      for (const binding of signingGrantBudgetEcdsaBindings(record)) {
        if (
          binding.evmFamilySigningKeySlotId !== input.evmFamilySigningKeySlotId ||
          !participantIdsEqual(binding.participantIds, input.participantIds)
        ) {
          return false;
        }
      }
      return true;
    default:
      return assertNever(input);
  }
}

function buildSigningGrantBudgetRecord(
  input: RouterAbSigningGrantBudgetInput,
  expiresAtMs: number,
): WalletSigningBudgetSessionRecord {
  switch (input.curve) {
    case 'ed25519':
      return {
        kind: 'wallet_signing_budget_session',
        expiresAtMs,
        walletId: input.userId,
        bindings: {
          kind: 'ed25519_only',
          ed25519: {
            thresholdSessionId: input.thresholdSessionId,
            authorityScope: input.authorityScope,
            participantIds: [...input.participantIds],
          },
        },
      };
    case 'ecdsa':
      return {
        kind: 'wallet_signing_budget_session',
        expiresAtMs,
        walletId: input.userId,
        bindings: {
          kind: 'ecdsa_only',
          ecdsa: [
            {
              thresholdSessionId: input.thresholdSessionId,
              evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
              participantIds: [...input.participantIds],
            },
          ],
        },
      };
    default:
      return assertNever(input);
  }
}

function normalizeSigningGrantBudgetInput(
  input: RouterAbSigningGrantBudgetInput,
  signingGrantId: string,
  thresholdSessionId: string,
): RouterAbSigningGrantBudgetInput {
  switch (input.curve) {
    case 'ed25519':
      return {
        curve: 'ed25519',
        signingGrantId,
        thresholdSessionId,
        userId: input.userId,
        participantIds: input.participantIds,
        ttlMs: input.ttlMs,
        remainingUses: input.remainingUses,
        operation: input.operation,
        authorityScope: input.authorityScope,
      };
    case 'ecdsa':
      return {
        curve: 'ecdsa',
        signingGrantId,
        thresholdSessionId,
        userId: input.userId,
        participantIds: input.participantIds,
        ttlMs: input.ttlMs,
        remainingUses: input.remainingUses,
        operation: input.operation,
        evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
      };
    default:
      return assertNever(input);
  }
}

function addSigningGrantBudgetCurveBinding(
  record: WalletSigningBudgetSessionRecord,
  input: RouterAbSigningGrantBudgetInput,
  expiresAtMs: number,
): WalletSigningBudgetSessionRecord {
  switch (input.curve) {
    case 'ed25519':
      if (record.bindings.kind !== 'ecdsa_only') {
        throw new Error('Ed25519 signing-grant binding already exists');
      }
      return {
        kind: 'wallet_signing_budget_session',
        expiresAtMs,
        walletId: record.walletId,
        bindings: {
          kind: 'ed25519_and_ecdsa',
          ed25519: {
            thresholdSessionId: input.thresholdSessionId,
            authorityScope: input.authorityScope,
            participantIds: [...input.participantIds],
          },
          ecdsa: record.bindings.ecdsa,
        },
      };
    case 'ecdsa': {
      const binding: WalletSigningBudgetEcdsaBinding = {
        thresholdSessionId: input.thresholdSessionId,
        evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
        participantIds: [...input.participantIds],
      };
      switch (record.bindings.kind) {
        case 'ed25519_only':
          return {
            kind: 'wallet_signing_budget_session',
            expiresAtMs,
            walletId: record.walletId,
            bindings: {
              kind: 'ed25519_and_ecdsa',
              ed25519: record.bindings.ed25519,
              ecdsa: [binding],
            },
          };
        case 'ecdsa_only':
          return {
            kind: 'wallet_signing_budget_session',
            expiresAtMs,
            walletId: record.walletId,
            bindings: {
              kind: 'ecdsa_only',
              ecdsa: [...record.bindings.ecdsa, binding],
            },
          };
        case 'ed25519_and_ecdsa':
          return {
            kind: 'wallet_signing_budget_session',
            expiresAtMs,
            walletId: record.walletId,
            bindings: {
              kind: 'ed25519_and_ecdsa',
              ed25519: record.bindings.ed25519,
              ecdsa: [...record.bindings.ecdsa, binding],
            },
          };
        default:
          return assertNever(record.bindings);
      }
    }
    default:
      return assertNever(input);
  }
}

function routerAbBudgetStoreFailure(input: { readonly code: string; readonly message: string }): {
  readonly ok: false;
  readonly status: number;
  readonly code: string;
  readonly message: string;
} {
  const code = toOptionalTrimmedString(input.code) || 'wallet_budget_internal';
  const message = toOptionalTrimmedString(input.message) || 'Wallet Session budget rejected';
  switch (code) {
    case 'wallet_session_missing':
    case 'wallet_session_signature_invalid':
    case 'wallet_session_claims_invalid':
    case 'wallet_session_expired':
    case 'wallet_session_scope_mismatch':
    case 'wallet_session_unavailable':
    case 'wallet_budget_exhausted':
      return {
        ok: false,
        status: walletSessionFailureStatus(code),
        code,
        message: walletSessionFailureMessage(code),
      };
    case 'wallet_budget_in_flight':
    case 'wallet_budget_reservation_mismatch':
      return { ok: false, status: 409, code, message };
    case 'wallet_budget_reservation_expired':
      return { ok: false, status: 410, code, message };
    case 'invalid_budget_request':
    case 'invalid_body':
      return { ok: false, status: 422, code: 'invalid_budget_request', message };
    default:
      return { ok: false, status: 500, code: 'wallet_budget_internal', message };
  }
}

function resolvedSigningGrantBudgetFailure(
  code: WalletSessionFailureCode,
): Extract<ResolvedSigningGrantBudget, { readonly ok: false }> {
  return { ok: false, code, message: walletSessionFailureMessage(code) };
}

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
  private readonly walletBudgetSessionStore: WalletSigningBudgetSessionStore;
  private readonly config: RouterAbNormalSigningRuntimeConfig;

  constructor(input: {
    readonly walletSessionStore: Ed25519WalletSessionStore;
    readonly ecdsaWalletSessionStore: EcdsaWalletSessionStore;
    readonly walletBudgetSessionStore: WalletSigningBudgetSessionStore;
    readonly config: RouterAbNormalSigningRuntimeConfig;
  }) {
    this.walletSessionStore = input.walletSessionStore;
    this.ecdsaWalletSessionStore = input.ecdsaWalletSessionStore;
    this.walletBudgetSessionStore = input.walletBudgetSessionStore;
    this.config = input.config;
  }

  getSigningWorkerId(): string {
    return this.config.policy.signingWorkerId;
  }

  getSigningWorkerPrivateTransport(): RouterAbSigningWorkerPrivateTransport {
    return this.config.signingWorkerTransport;
  }

  async getSigningGrantBudget(
    signingGrantId: string,
  ): Promise<WalletSigningBudgetSessionRecord | null> {
    const budgetSessionId = this.requireBudgetSessionId(signingGrantId);
    return await this.walletBudgetSessionStore.getSession(budgetSessionId);
  }

  async getSigningGrantBudgetStatus(
    signingGrantId: string,
  ): Promise<WalletSigningBudgetSessionStatus | null> {
    const budgetSessionId = this.requireBudgetSessionId(signingGrantId);
    const lookup = await this.walletBudgetSessionStore.getSessionStatus(budgetSessionId);
    return lookup.ok ? lookup.status : null;
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

  async provisionRouterAbEd25519YaoNormalSigningSession(
    input: RouterAbEd25519YaoNormalSigningSessionProvisionInput,
  ): Promise<RouterAbEd25519YaoNormalSigningSessionProvisionResult> {
    const walletId = parseWalletId(input.walletId);
    const nearAccountId = parseNearAccountId(input.nearAccountId);
    const authorityScope = parseThresholdEd25519AuthorityScope(input.authorityScope);
    const thresholdSessionId = toOptionalTrimmedString(input.thresholdSessionId);
    const signingGrantId = toOptionalTrimmedString(input.signingGrantId);
    const signingWorkerId = toOptionalTrimmedString(input.signingWorkerId);
    const expiresAtMs = Number(input.expiresAtMs);
    const remainingUses = Math.floor(Number(input.remainingUses));
    const participantIds = normalizeThresholdEd25519ParticipantIds(input.participantIds);
    let nearEd25519SigningKeyId: NearEd25519SigningKeyId;
    try {
      nearEd25519SigningKeyId = parseNearEd25519SigningKeyId(input.nearEd25519SigningKeyId);
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Ed25519 Yao signing-key identity is invalid',
      };
    }
    if (
      input.kind !== 'router_ab_ed25519_yao_normal_signing_session_v1' ||
      !walletId.ok ||
      !nearAccountId.ok ||
      !authorityScope ||
      !thresholdSessionId ||
      !signingGrantId ||
      !signingWorkerId ||
      signingWorkerId !== this.getSigningWorkerId() ||
      !participantIds ||
      participantIds.length !== 2 ||
      participantIds[0] === participantIds[1] ||
      !Number.isSafeInteger(remainingUses) ||
      remainingUses <= 0 ||
      !Number.isFinite(expiresAtMs) ||
      expiresAtMs <= Date.now()
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Ed25519 Yao normal-signing session is invalid',
      };
    }

    const expectedSession: Ed25519WalletSessionRecord = {
      expiresAtMs,
      relayerKeyId: signingWorkerId,
      userId: walletId.value,
      walletId: walletId.value,
      nearAccountId: nearAccountId.value,
      nearEd25519SigningKeyId,
      authorityScope,
      participantIds,
    };
    const existingSession = await this.walletSessionStore.getSession(thresholdSessionId);
    if (
      existingSession &&
      (existingSession.relayerKeyId !== expectedSession.relayerKeyId ||
        existingSession.userId !== expectedSession.userId ||
        existingSession.walletId !== expectedSession.walletId ||
        existingSession.nearAccountId !== expectedSession.nearAccountId ||
        existingSession.nearEd25519SigningKeyId !== expectedSession.nearEd25519SigningKeyId ||
        !thresholdEd25519AuthorityScopesMatch(
          existingSession.authorityScope,
          expectedSession.authorityScope,
        ) ||
        !participantIdsEqual(existingSession.participantIds, expectedSession.participantIds))
    ) {
      return {
        ok: false,
        code: 'conflict',
        message: 'thresholdSessionId already belongs to another signing authority',
      };
    }

    const existingBudget = await this.getSigningGrantBudget(signingGrantId);
    if (existingBudget && existingBudget.walletId !== walletId.value) {
      return {
        ok: false,
        code: 'conflict',
        message: 'signingGrantId already belongs to another signing authority',
      };
    }

    try {
      const ttlMs = Math.max(1, Math.floor(expiresAtMs - Date.now()));
      const walletBudget = await this.ensureSigningGrantBudget({
        signingGrantId,
        curve: 'ed25519',
        thresholdSessionId,
        userId: walletId.value,
        authorityScope,
        participantIds,
        ttlMs,
        remainingUses,
        operation: 'provision_curve_binding',
      });
      if (!walletBudget.ok) return walletBudget;
      await this.putEd25519WalletSessionRecord({
        sessionId: thresholdSessionId,
        record: expectedSession,
        ttlMs,
        remainingUses,
      });
      const budgetStatus = await this.getSigningGrantBudgetStatus(signingGrantId);
      if (!budgetStatus) {
        return {
          ok: false,
          code: 'internal',
          message: 'Ed25519 Yao signing budget was not persisted',
        };
      }
      return {
        ok: true,
        thresholdSessionId,
        signingGrantId,
        expiresAtMs: walletBudget.expiresAtMs,
        remainingUses: budgetStatus.remainingUses,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Ed25519 Yao normal-signing provisioning failed',
      };
    }
  }

  async provisionRouterAbEcdsaNormalSigningSession(
    input: RouterAbEcdsaNormalSigningSessionProvisionInput,
  ): Promise<RouterAbEcdsaNormalSigningSessionProvisionResult> {
    const walletId = parseWalletId(input.walletId);
    const evmFamilySigningKeySlotId = toOptionalTrimmedString(input.evmFamilySigningKeySlotId);
    const relayerKeyId = toOptionalTrimmedString(input.relayerKeyId);
    const thresholdSessionId = toOptionalTrimmedString(input.thresholdSessionId);
    const signingGrantId = toOptionalTrimmedString(input.signingGrantId);
    const signingRootId = toOptionalTrimmedString(input.signingRootId);
    const signingRootVersion = toOptionalTrimmedString(input.signingRootVersion);
    const expiresAtMs = Number(input.expiresAtMs);
    const remainingUses = Math.floor(Number(input.remainingUses));
    const participantIds = normalizeExactEcdsaParticipantIds(input.participantIds);
    if (
      input.kind !== 'router_ab_ecdsa_normal_signing_session_v1' ||
      !walletId.ok ||
      !evmFamilySigningKeySlotId ||
      !relayerKeyId ||
      !thresholdSessionId ||
      !signingGrantId ||
      !signingRootId ||
      !signingRootVersion ||
      !participantIds ||
      !Number.isSafeInteger(remainingUses) ||
      remainingUses <= 0 ||
      !Number.isFinite(expiresAtMs) ||
      expiresAtMs <= Date.now()
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Router A/B ECDSA normal-signing session is invalid',
      };
    }
    const requestedSession: EcdsaWalletSessionRecord = {
      expiresAtMs,
      relayerKeyId,
      walletId: walletId.value,
      evmFamilySigningKeySlotId,
      participantIds,
    };
    const existingSession = await this.ecdsaWalletSessionStore.getSession(thresholdSessionId);
    if (
      existingSession &&
      !ecdsaWalletSessionsHaveSameAuthority(existingSession, requestedSession)
    ) {
      return {
        ok: false,
        code: 'conflict',
        message: 'thresholdSessionId already belongs to another ECDSA signing authority',
      };
    }
    const ttlMs = Math.max(1, Math.floor(expiresAtMs - Date.now()));
    const budget = await this.ensureSigningGrantBudget({
      signingGrantId,
      curve: 'ecdsa',
      thresholdSessionId,
      userId: walletId.value,
      evmFamilySigningKeySlotId,
      participantIds,
      ttlMs,
      remainingUses,
      operation: 'provision_curve_binding',
    });
    if (!budget.ok) return budget;
    await this.ecdsaWalletSessionStore.putSession(thresholdSessionId, requestedSession, {
      ttlMs,
      remainingUses,
    });
    const status = await this.getSigningGrantBudgetStatus(signingGrantId);
    if (!status) {
      return {
        ok: false,
        code: 'internal',
        message: 'Router A/B ECDSA signing budget was not persisted',
      };
    }
    return {
      ok: true,
      thresholdSessionId,
      signingGrantId,
      expiresAtMs: budget.expiresAtMs,
      remainingUses: status.remainingUses,
      participantIds,
    };
  }

  async refreshRouterAbEd25519YaoNormalSigningBudget(
    input: RouterAbEd25519YaoNormalSigningBudgetRefreshInput,
  ): Promise<RouterAbEd25519YaoNormalSigningBudgetRefreshResult> {
    const walletId = parseWalletId(input.walletId);
    const nearAccountId = parseNearAccountId(input.nearAccountId);
    const authorityScope = parseThresholdEd25519AuthorityScope(input.authorityScope);
    const thresholdSessionId = toOptionalTrimmedString(input.thresholdSessionId);
    const signingGrantId = toOptionalTrimmedString(input.signingGrantId);
    const signingWorkerId = toOptionalTrimmedString(input.signingWorkerId);
    const participantIds = normalizeThresholdEd25519ParticipantIds(input.participantIds);
    const requested = this.clampSessionPolicy({
      ttlMs: Number(input.ttlMs),
      remainingUses: Number(input.remainingUses),
    });
    if (
      input.kind !== 'router_ab_ed25519_yao_normal_signing_budget_refresh_v1' ||
      !walletId.ok ||
      !nearAccountId.ok ||
      !authorityScope ||
      !thresholdSessionId ||
      !signingGrantId ||
      !signingWorkerId ||
      signingWorkerId !== this.getSigningWorkerId() ||
      !participantIds ||
      participantIds.length !== 2 ||
      participantIds[0] === participantIds[1] ||
      requested.ttlMs <= 0 ||
      requested.remainingUses <= 0
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Ed25519 Yao normal-signing budget refresh is invalid',
      };
    }

    const requestedExpiresAtMs = Date.now() + requested.ttlMs;
    const requestedSession: Ed25519WalletSessionRecord = {
      expiresAtMs: requestedExpiresAtMs,
      relayerKeyId: signingWorkerId,
      userId: walletId.value,
      walletId: walletId.value,
      nearAccountId: nearAccountId.value,
      nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
      authorityScope,
      participantIds,
    };
    const existingSession = await this.walletSessionStore.getSession(thresholdSessionId);
    if (
      existingSession &&
      !ed25519WalletSessionsHaveSameAuthority(existingSession, requestedSession)
    ) {
      return {
        ok: false,
        code: 'conflict',
        message: 'Ed25519 Yao Wallet Session belongs to another signing authority',
      };
    }

    const existingBudget = await this.getSigningGrantBudget(signingGrantId);
    if (existingBudget && existingBudget.walletId !== walletId.value) {
      return {
        ok: false,
        code: 'conflict',
        message: 'Ed25519 Yao signing grant belongs to another wallet',
      };
    }

    const refreshed = await this.ensureSigningGrantBudget({
      signingGrantId,
      curve: 'ed25519',
      thresholdSessionId,
      userId: walletId.value,
      authorityScope,
      participantIds,
      ttlMs: requested.ttlMs,
      remainingUses: requested.remainingUses,
      operation: 'refresh_exhausted_binding',
    });
    if (!refreshed.ok) return refreshed;
    const refreshedTtlMs = Math.max(1, refreshed.expiresAtMs - Date.now());
    await this.putEd25519WalletSessionRecord({
      sessionId: thresholdSessionId,
      record: {
        expiresAtMs: refreshed.expiresAtMs,
        relayerKeyId: requestedSession.relayerKeyId,
        userId: requestedSession.userId,
        walletId: requestedSession.walletId,
        nearAccountId: requestedSession.nearAccountId,
        nearEd25519SigningKeyId: requestedSession.nearEd25519SigningKeyId,
        authorityScope: requestedSession.authorityScope,
        participantIds: requestedSession.participantIds,
      },
      ttlMs: refreshedTtlMs,
      remainingUses: requested.remainingUses,
    });
    const status = await this.getSigningGrantBudgetStatus(signingGrantId);
    if (!status) {
      return {
        ok: false,
        code: 'internal',
        message: 'Ed25519 Yao refreshed budget was not persisted',
      };
    }
    return {
      ok: true,
      thresholdSessionId,
      signingGrantId,
      expiresAtMs: refreshed.expiresAtMs,
      remainingUses: status.remainingUses,
    };
  }

  async reservePrepareReplay(
    input: RouterAbNormalSigningPrepareReplayReservationInput,
  ): Promise<RouterAbNormalSigningPrepareReplayReservationResult> {
    const sessionId = toOptionalTrimmedString(input.thresholdSessionId);
    const requestId = toOptionalTrimmedString(input.requestId);
    const expiresAtMs = Number(input.expiresAtMs);
    if (!sessionId || !requestId || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
      return {
        ok: false,
        status: 400,
        code: 'invalid_body',
        message:
          'Router A/B normal-signing replay reservation requires session, request id, and expiry',
      };
    }
    const store =
      input.curve === 'ed25519' ? this.walletSessionStore : this.ecdsaWalletSessionStore;
    const replayGuard = await store.reserveReplayGuard(
      ['router-ab-normal-signing', input.curve, 'prepare', sessionId].join(':'),
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

  async reserveBudget(
    input: RouterAbNormalSigningBudgetReservationInput,
  ): Promise<RouterAbNormalSigningBudgetReservationResult> {
    const parsed = this.parseBudgetReservationInput(input);
    if (!parsed.ok) return parsed;
    const resolved = await this.resolveSigningGrantBudget({
      signingGrantId: parsed.signingGrantId,
      curve: parsed.curve,
      curveSessionId: parsed.thresholdSessionId,
    });
    if (!resolved.ok) return routerAbBudgetStoreFailure(resolved);
    const reserved = await resolved.store.reserveUseCountOnce({
      signingGrantId: resolved.budgetSessionId,
      curve: parsed.curve,
      thresholdSessionId: parsed.thresholdSessionId,
      signingWorkerId: parsed.signingWorkerId,
      operationId: parsed.operationId,
      requestDigest: parsed.requestDigest,
      signatureUses: parsed.signatureUses,
      expiresAtMs: parsed.expiresAtMs,
    });
    if (!reserved.ok) return routerAbBudgetStoreFailure(reserved);
    return {
      ok: true,
      reservationId: reserved.reservation.reservationId,
      remainingUses: reserved.remainingUses,
      reservedUses: reserved.reservedUses,
      availableUses: reserved.availableUses,
    };
  }

  async commitBudget(
    input: RouterAbNormalSigningBudgetFinalizeInput,
  ): Promise<RouterAbNormalSigningBudgetCommitResult> {
    const parsed = this.parseBudgetFinalizeInput(input, 'commit');
    if (!parsed.ok) return parsed;
    const resolved = await this.resolveSigningGrantBudget({
      signingGrantId: parsed.signingGrantId,
      curve: parsed.curve,
      curveSessionId: parsed.thresholdSessionId,
    });
    if (!resolved.ok) return routerAbBudgetStoreFailure(resolved);
    const committed = await resolved.store.commitReservedUseCountOnce({
      signingGrantId: resolved.budgetSessionId,
      reservationId: parsed.reservationId,
      signingWorkerId: parsed.signingWorkerId,
      operationId: parsed.operationId,
      requestDigest: parsed.requestDigest,
    });
    if (!committed.ok) return routerAbBudgetStoreFailure(committed);
    return {
      ok: true,
      remainingUses: Math.max(0, Math.floor(Number(committed.remainingUses) || 0)),
    };
  }

  async validateBudget(
    input: RouterAbNormalSigningBudgetFinalizeInput,
  ): Promise<RouterAbNormalSigningBudgetCommitResult> {
    const parsed = this.parseBudgetFinalizeInput(input, 'validation');
    if (!parsed.ok) return parsed;
    const resolved = await this.resolveSigningGrantBudget({
      signingGrantId: parsed.signingGrantId,
      curve: parsed.curve,
      curveSessionId: parsed.thresholdSessionId,
    });
    if (!resolved.ok) return routerAbBudgetStoreFailure(resolved);
    const validated = await resolved.store.validateReservedUseCount({
      signingGrantId: resolved.budgetSessionId,
      reservationId: parsed.reservationId,
      signingWorkerId: parsed.signingWorkerId,
      operationId: parsed.operationId,
      requestDigest: parsed.requestDigest,
    });
    if (!validated.ok) return routerAbBudgetStoreFailure(validated);
    return {
      ok: true,
      remainingUses: Math.max(0, Math.floor(Number(validated.remainingUses) || 0)),
    };
  }

  async releaseBudget(
    input: RouterAbNormalSigningBudgetReleaseInput,
  ): Promise<RouterAbNormalSigningBudgetReleaseResult> {
    const sessionId = toOptionalTrimmedString(input.thresholdSessionId);
    const signingGrantId = toOptionalTrimmedString(input.signingGrantId);
    const reservationId = toOptionalTrimmedString(input.reservationId);
    if (!sessionId || !signingGrantId || !reservationId) {
      return {
        ok: false,
        status: 422,
        code: 'invalid_budget_request',
        message: 'Router A/B budget release requires session and reservation',
      };
    }
    const resolved = await this.resolveSigningGrantBudget({
      signingGrantId,
      curve: input.curve === 'ed25519' ? 'ed25519' : 'ecdsa',
      curveSessionId: sessionId,
    });
    if (!resolved.ok) return routerAbBudgetStoreFailure(resolved);
    const released = await resolved.store.releaseReservedUseCount({
      signingGrantId: resolved.budgetSessionId,
      reservationId,
    });
    if (!released.ok) return routerAbBudgetStoreFailure(released);
    return released;
  }

  async releaseBudgetForIdentity(
    input: RouterAbNormalSigningBudgetFinalizeInput,
  ): Promise<RouterAbNormalSigningBudgetReleaseResult> {
    const parsed = this.parseBudgetFinalizeInput(input, 'identity release');
    if (!parsed.ok) return parsed;
    const resolved = await this.resolveSigningGrantBudget({
      signingGrantId: parsed.signingGrantId,
      curve: parsed.curve,
      curveSessionId: parsed.thresholdSessionId,
    });
    if (!resolved.ok) return routerAbBudgetStoreFailure(resolved);
    const released = await resolved.store.releaseReservedUseCountForIdentity({
      signingGrantId: resolved.budgetSessionId,
      reservationId: parsed.reservationId,
      signingWorkerId: parsed.signingWorkerId,
      operationId: parsed.operationId,
      requestDigest: parsed.requestDigest,
    });
    if (!released.ok) return routerAbBudgetStoreFailure(released);
    return released;
  }

  async ensureSigningGrantBudget(
    input: RouterAbSigningGrantBudgetInput,
  ): Promise<RouterAbSigningGrantBudgetResult> {
    const thresholdSessionId = toOptionalTrimmedString(input.thresholdSessionId);
    const signingGrantId = toOptionalTrimmedString(input.signingGrantId);
    const branchScopeId =
      input.curve === 'ecdsa'
        ? toOptionalTrimmedString(input.evmFamilySigningKeySlotId)
        : input.authorityScope.kind;
    const branchScopeLabel =
      input.curve === 'ecdsa' ? 'evmFamilySigningKeySlotId' : 'authorityScope';
    if (!thresholdSessionId) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'signing grant budget binding thresholdSessionId is required',
      };
    }
    if (!branchScopeId) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `signing grant budget ${branchScopeLabel} is required`,
      };
    }
    if (!signingGrantId) {
      return { ok: false, code: 'invalid_body', message: 'signingGrantId is required' };
    }
    const sessionId = walletSigningBudgetSessionId({ signingGrantId });
    const normalizedInput = normalizeSigningGrantBudgetInput(
      input,
      signingGrantId,
      thresholdSessionId,
    );
    const existingSession = await this.walletBudgetSessionStore.getSession(sessionId);
    if (!existingSession) {
      const expiresAtMs = Date.now() + input.ttlMs;
      await this.putWalletBudgetSessionRecord({
        sessionId,
        record: buildSigningGrantBudgetRecord(normalizedInput, expiresAtMs),
        ttlMs: input.ttlMs,
        remainingUses: input.remainingUses,
      });
      return { ok: true, expiresAtMs, participantIds: [...input.participantIds] };
    }
    if (!signingGrantBudgetRecordHasCommonIdentity(existingSession, normalizedInput)) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'signingGrantId already exists for a different signing authority',
      };
    }
    const matchesCurveBinding = signingGrantBudgetRecordMatchesCurveBinding(
      existingSession,
      normalizedInput,
    );
    const existingStatusLookup = await this.walletBudgetSessionStore.getSessionStatus(sessionId);
    const existingStatus = existingStatusLookup.ok ? existingStatusLookup.status : null;
    if (!matchesCurveBinding) {
      if (
        input.operation === 'refresh_exhausted_binding' ||
        !signingGrantBudgetCanAddCurveBinding(existingSession, normalizedInput) ||
        !existingStatus ||
        existingStatus.reservedUses > 0
      ) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'signingGrantId is not bound to this curve session',
        };
      }
      const expiresAtMs = Math.min(existingSession.expiresAtMs, Date.now() + input.ttlMs);
      const ttlMs = Math.max(1, expiresAtMs - Date.now());
      await this.putWalletBudgetSessionRecord({
        sessionId,
        record: addSigningGrantBudgetCurveBinding(existingSession, normalizedInput, expiresAtMs),
        ttlMs,
        remainingUses: existingStatus.committedRemainingUses,
      });
      return {
        ok: true,
        expiresAtMs,
        participantIds: [...input.participantIds],
      };
    }
    if (input.operation === 'provision_curve_binding') {
      return {
        ok: true,
        expiresAtMs: existingSession.expiresAtMs,
        participantIds: [...input.participantIds],
      };
    }
    const committedRemainingUses = Math.max(
      0,
      Math.floor(Number(existingStatus?.committedRemainingUses) || 0),
    );
    if (existingStatus && committedRemainingUses > 0) {
      return {
        ok: true,
        expiresAtMs: existingStatus.expiresAtMs,
        participantIds: [...input.participantIds],
      };
    }
    const expiresAtMs = Date.now() + input.ttlMs;
    await this.putWalletBudgetSessionRecord({
      sessionId,
      record: {
        kind: 'wallet_signing_budget_session',
        expiresAtMs,
        walletId: existingSession.walletId,
        bindings: existingSession.bindings,
      },
      ttlMs: input.ttlMs,
      remainingUses: input.remainingUses,
    });
    return { ok: true, expiresAtMs, participantIds: [...input.participantIds] };
  }

  private parseBudgetReservationInput(input: RouterAbNormalSigningBudgetReservationInput):
    | {
        readonly ok: true;
        readonly curve: BudgetCurve;
        readonly thresholdSessionId: string;
        readonly signingGrantId: string;
        readonly signingWorkerId: string;
        readonly operationId: string;
        readonly requestDigest: string;
        readonly signatureUses: number;
        readonly expiresAtMs: number;
      }
    | {
        readonly ok: false;
        readonly status: 422;
        readonly code: 'invalid_budget_request';
        readonly message: string;
      } {
    const thresholdSessionId = toOptionalTrimmedString(input.thresholdSessionId);
    const signingGrantId = toOptionalTrimmedString(input.signingGrantId);
    const signingWorkerId = toOptionalTrimmedString(input.signingWorkerId);
    const operationId = toOptionalTrimmedString(input.operationId);
    const requestDigest = toOptionalTrimmedString(input.requestDigest);
    const signatureUses = Math.floor(Number(input.signatureUses));
    const expiresAtMs = Number(input.expiresAtMs);
    if (
      !thresholdSessionId ||
      !signingGrantId ||
      !signingWorkerId ||
      !operationId ||
      !requestDigest ||
      !Number.isSafeInteger(signatureUses) ||
      signatureUses <= 0 ||
      !Number.isFinite(expiresAtMs)
    ) {
      return {
        ok: false,
        status: 422,
        code: 'invalid_budget_request',
        message: 'Router A/B budget reservation requires operation, digest, uses, and expiry',
      };
    }
    return {
      ok: true,
      curve: input.curve === 'ed25519' ? 'ed25519' : 'ecdsa',
      thresholdSessionId,
      signingGrantId,
      signingWorkerId,
      operationId,
      requestDigest,
      signatureUses,
      expiresAtMs,
    };
  }

  private parseBudgetFinalizeInput(
    input: RouterAbNormalSigningBudgetFinalizeInput,
    operation: 'commit' | 'validation' | 'identity release',
  ):
    | {
        readonly ok: true;
        readonly curve: BudgetCurve;
        readonly thresholdSessionId: string;
        readonly signingGrantId: string;
        readonly reservationId: string;
        readonly signingWorkerId: string;
        readonly operationId: string;
        readonly requestDigest: string;
      }
    | {
        readonly ok: false;
        readonly status: 422;
        readonly code: 'invalid_budget_request';
        readonly message: string;
      } {
    const thresholdSessionId = toOptionalTrimmedString(input.thresholdSessionId);
    const signingGrantId = toOptionalTrimmedString(input.signingGrantId);
    const reservationId = toOptionalTrimmedString(input.reservationId);
    const signingWorkerId = toOptionalTrimmedString(input.signingWorkerId);
    const operationId = toOptionalTrimmedString(input.operationId);
    const requestDigest = toOptionalTrimmedString(input.requestDigest);
    if (
      !thresholdSessionId ||
      !signingGrantId ||
      !reservationId ||
      !signingWorkerId ||
      !operationId ||
      !requestDigest
    ) {
      return {
        ok: false,
        status: 422,
        code: 'invalid_budget_request',
        message: `Router A/B budget ${operation} requires reservation, SigningWorker, operation, and digest`,
      };
    }
    return {
      ok: true,
      curve: input.curve === 'ed25519' ? 'ed25519' : 'ecdsa',
      thresholdSessionId,
      signingGrantId,
      reservationId,
      signingWorkerId,
      operationId,
      requestDigest,
    };
  }

  private async putWalletBudgetSessionRecord(input: {
    readonly sessionId: string;
    readonly record: WalletSigningBudgetSessionRecord;
    readonly ttlMs: number;
    readonly remainingUses: number;
  }): Promise<void> {
    await this.walletBudgetSessionStore.putSession(input.sessionId, input.record, {
      ttlMs: input.ttlMs,
      remainingUses: input.remainingUses,
    });
  }

  private async putEd25519WalletSessionRecord(input: {
    readonly sessionId: string;
    readonly record: Ed25519WalletSessionRecord;
    readonly ttlMs: number;
    readonly remainingUses: number;
  }): Promise<void> {
    await this.walletSessionStore.putSession(input.sessionId, input.record, {
      ttlMs: input.ttlMs,
      remainingUses: input.remainingUses,
    });
  }

  private requireBudgetSessionId(signingGrantId: string): string {
    const budgetSessionId = walletSigningBudgetSessionId({ signingGrantId });
    if (!budgetSessionId) {
      throw new Error('signingGrantId is required');
    }
    return budgetSessionId;
  }

  private async resolveSigningGrantBudget(input: {
    readonly signingGrantId: string;
    readonly curve: BudgetCurve;
    readonly curveSessionId: string;
  }): Promise<ResolvedSigningGrantBudget> {
    const budgetSessionId = walletSigningBudgetSessionId({
      signingGrantId: input.signingGrantId,
    });
    if (!budgetSessionId) {
      return { ok: false, code: 'invalid_budget_request', message: 'signingGrantId is required' };
    }
    let budgetLookup: Awaited<
      ReturnType<WalletSigningBudgetSessionStore['getSessionStatus']>
    >;
    try {
      budgetLookup = await this.walletBudgetSessionStore.getSessionStatus(budgetSessionId);
    } catch {
      return resolvedSigningGrantBudgetFailure('wallet_session_unavailable');
    }
    if (!budgetLookup.ok) return resolvedSigningGrantBudgetFailure(budgetLookup.code);
    const budgetStatus = budgetLookup.status;
    const budgetSession = budgetStatus.record;
    const checkedAtMs = Date.now();
    if (budgetStatus.expiresAtMs <= checkedAtMs) {
      return resolvedSigningGrantBudgetFailure('wallet_session_expired');
    }
    switch (input.curve) {
      case 'ed25519': {
        let curveLookup: Awaited<ReturnType<Ed25519WalletSessionStore['getSessionStatus']>>;
        try {
          curveLookup = await this.walletSessionStore.getSessionStatus(input.curveSessionId);
        } catch {
          return resolvedSigningGrantBudgetFailure('wallet_session_unavailable');
        }
        if (!curveLookup.ok) return resolvedSigningGrantBudgetFailure(curveLookup.code);
        if (curveLookup.status.expiresAtMs <= checkedAtMs) {
          return resolvedSigningGrantBudgetFailure('wallet_session_expired');
        }
        const curveSession = curveLookup.status.record;
        const binding = signingGrantBudgetEd25519Binding(budgetSession);
        if (
          !binding ||
          binding.thresholdSessionId !== input.curveSessionId ||
          budgetSession.walletId !== curveSession.userId ||
          !thresholdEd25519AuthorityScopesMatch(
            binding.authorityScope,
            curveSession.authorityScope,
          ) ||
          !participantIdsEqual(binding.participantIds, curveSession.participantIds)
        ) {
          return resolvedSigningGrantBudgetFailure('wallet_session_scope_mismatch');
        }
        break;
      }
      case 'ecdsa': {
        let curveLookup: Awaited<ReturnType<EcdsaWalletSessionStore['getSessionStatus']>>;
        try {
          curveLookup = await this.ecdsaWalletSessionStore.getSessionStatus(input.curveSessionId);
        } catch {
          return resolvedSigningGrantBudgetFailure('wallet_session_unavailable');
        }
        if (!curveLookup.ok) return resolvedSigningGrantBudgetFailure(curveLookup.code);
        if (curveLookup.status.expiresAtMs <= checkedAtMs) {
          return resolvedSigningGrantBudgetFailure('wallet_session_expired');
        }
        const curveSession = curveLookup.status.record;
        let binding: WalletSigningBudgetEcdsaBinding | null = null;
        for (const candidate of signingGrantBudgetEcdsaBindings(budgetSession)) {
          if (candidate.thresholdSessionId === input.curveSessionId) {
            binding = candidate;
            break;
          }
        }
        if (
          !binding ||
          budgetSession.walletId !== curveSession.walletId ||
          binding.evmFamilySigningKeySlotId !== curveSession.evmFamilySigningKeySlotId ||
          !participantIdsEqual(binding.participantIds, curveSession.participantIds)
        ) {
          return resolvedSigningGrantBudgetFailure('wallet_session_scope_mismatch');
        }
        break;
      }
      default:
        return assertNever(input.curve);
    }
    return { ok: true, budgetSessionId, store: this.walletBudgetSessionStore };
  }
}
