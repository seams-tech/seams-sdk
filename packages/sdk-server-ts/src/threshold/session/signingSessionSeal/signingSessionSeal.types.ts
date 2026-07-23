import type { NormalizedLogger } from '../../../core/logger';
import type { ThresholdEd25519AuthorityScope } from '../../../core/types';
import type { WalletSigningBudgetBindings } from '../../../core/ThresholdService/stores/WalletSessionStore';
import type { SessionParseResult } from '../../../core/sessionValidation';

export type SigningSessionSealRouteHeaders = Record<string, string | string[] | undefined>;

export type SigningSessionSealSessionClaims = Record<string, unknown>;

export interface SigningSessionSealSessionAdapter {
  parse(
    headers: SigningSessionSealRouteHeaders,
  ): Promise<SessionParseResult<SigningSessionSealSessionClaims>>;
}

export interface SigningSessionSealAuthContext {
  userId: string;
  claims: SigningSessionSealSessionClaims;
}

export interface SigningSessionSealAuthorizeInput {
  headers: SigningSessionSealRouteHeaders;
  session: SigningSessionSealSessionAdapter | null | undefined;
  thresholdSessionId?: string;
}

export type SigningSessionSealAuthorizeResult =
  | { ok: true; auth: SigningSessionSealAuthContext }
  | { ok: false; code?: string; message?: string; status?: number };

export interface SigningSessionSealApplyServerSealRequest {
  thresholdSessionId: string;
  ciphertext: string;
  keyVersion?: string;
  metadata?: Record<string, unknown>;
}

export interface SigningSessionSealRemoveServerSealRequest {
  thresholdSessionId: string;
  ciphertext: string;
  keyVersion?: string;
  metadata?: Record<string, unknown>;
}

export type SigningSessionSealRouteResult =
  | {
      ok: true;
      ciphertext: string;
      keyVersion?: string;
      expiresAtMs?: number;
      remainingUses?: number;
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

export interface SigningSessionSealIdempotencyGetInput {
  key: string;
  nowMs: number;
}

export interface SigningSessionSealIdempotencySetInput {
  key: string;
  result: SigningSessionSealRouteResult;
  expiresAtMs: number;
}

export interface SigningSessionSealIdempotencyStore {
  get(input: SigningSessionSealIdempotencyGetInput): Promise<SigningSessionSealRouteResult | null>;
  set(input: SigningSessionSealIdempotencySetInput): Promise<void>;
}

export interface SigningSessionSealServiceIdempotencyOptions {
  store: SigningSessionSealIdempotencyStore;
  ttlMs?: number;
}

export interface SigningSessionSealService {
  applyServerSeal(
    request: SigningSessionSealApplyServerSealRequest,
    auth: SigningSessionSealAuthContext,
  ): Promise<SigningSessionSealRouteResult>;

  removeServerSeal(
    request: SigningSessionSealRemoveServerSealRequest,
    auth: SigningSessionSealAuthContext,
  ): Promise<SigningSessionSealRouteResult>;
}

export interface SigningSessionSealRoutesOptions {
  basePath?: string;
  service: SigningSessionSealService;
  sessionPolicy?: SigningSessionSealThresholdSessionPolicy;
  capabilities?: SigningSessionSealStartupCapabilities;
  authorize?: (
    input: SigningSessionSealAuthorizeInput,
  ) => Promise<SigningSessionSealAuthorizeResult> | SigningSessionSealAuthorizeResult;
}

export interface SigningSessionSealStartupCapabilities {
  mode: 'sealed_refresh_v1';
  keyVersion?: string;
  shamirPrimeB64u: string;
}

export type SigningSessionSealOperation = 'apply-server-seal' | 'remove-server-seal';

export type SigningSessionSealCurve = 'ecdsa' | 'ed25519';

type SigningSessionSealThresholdSessionRecordBase = {
  curve: SigningSessionSealCurve;
  thresholdSessionId: string;
  userId: string;
  expiresAtMs: number;
  relayerKeyId: string;
  participantIds: readonly number[];
  signingRootId?: string;
  signingRootVersion?: string;
  remainingUses?: number;
};

export type SigningSessionSealEcdsaThresholdSessionRecord =
  SigningSessionSealThresholdSessionRecordBase & {
    curve: 'ecdsa';
    evmFamilySigningKeySlotId: string;
    authorityScope?: never;
  };

export type SigningSessionSealEd25519ThresholdSessionRecord =
  SigningSessionSealThresholdSessionRecordBase & {
    curve: 'ed25519';
    authorityScope: ThresholdEd25519AuthorityScope;
    evmFamilySigningKeySlotId?: never;
  };

export type SigningSessionSealThresholdSessionRecord =
  | SigningSessionSealEcdsaThresholdSessionRecord
  | SigningSessionSealEd25519ThresholdSessionRecord;

export type SigningSessionSealThresholdSessionStatus = SigningSessionSealThresholdSessionRecord & {
  kind: 'wallet_session';
  remainingUses: number;
};

export type SigningSessionSealWalletBudgetStatus = {
  kind: 'wallet_budget';
  signingGrantId: string;
  userId: string;
  expiresAtMs: number;
  relayerKeyId: string;
  bindings: WalletSigningBudgetBindings;
  committedRemainingUses: number;
  reservedUses: number;
  availableUses: number;
  remainingUses: number;
};

export type SigningSessionSealThresholdStatusLookup =
  | {
      curve: 'ecdsa';
      thresholdSessionId: string;
    }
  | {
      curve: 'ed25519';
      thresholdSessionId: string;
    };

export type SigningSessionSealWalletBudgetStatusLookup = {
  signingGrantId: string;
};

export type SigningSessionSealConsumeUseResult =
  | { ok: true; remainingUses?: number }
  | { ok: false; code: string; message: string };

export interface SigningSessionSealThresholdSessionPolicy {
  getThresholdSession(
    input: SigningSessionSealThresholdStatusLookup,
  ): Promise<SigningSessionSealThresholdSessionRecord | null>;
  getThresholdSessionStatuses(
    input: SigningSessionSealThresholdStatusLookup,
  ): Promise<SigningSessionSealThresholdSessionStatus[]>;
  getWalletBudgetStatus?(
    input: SigningSessionSealWalletBudgetStatusLookup,
  ): Promise<SigningSessionSealWalletBudgetStatus | null>;
  consumeUseCount?(
    input: SigningSessionSealThresholdStatusLookup,
  ): Promise<SigningSessionSealConsumeUseResult>;
}

export interface SigningSessionSealCipherOperationInput {
  operation: SigningSessionSealOperation;
  thresholdSessionId: string;
  ciphertext: string;
  keyVersion?: string;
  metadata?: Record<string, unknown>;
  auth: SigningSessionSealAuthContext;
}

export type SigningSessionSealCipherOperationResult =
  | { ok: true; ciphertext: string; keyVersion?: string }
  | { ok: false; code: string; message: string };

export interface SigningSessionSealCipherAdapter {
  run(
    input: SigningSessionSealCipherOperationInput,
  ): Promise<SigningSessionSealCipherOperationResult>;
}

export type SigningSessionSealConsumePolicy = 'never' | 'apply-only' | 'remove-only' | 'always';

export interface SigningSessionSealGuardInput {
  operation: SigningSessionSealOperation;
  thresholdSessionId: string;
  auth: SigningSessionSealAuthContext;
}

export type SigningSessionSealGuardResult =
  | { ok: true }
  | { ok: false; code: string; message: string };

export type SigningSessionSealGuard = (
  input: SigningSessionSealGuardInput,
) => Promise<SigningSessionSealGuardResult> | SigningSessionSealGuardResult;

export interface SigningSessionSealAuditEvent {
  operation: SigningSessionSealOperation;
  thresholdSessionId: string;
  userId: string;
  ok: boolean;
  code?: string;
  durationMs: number;
}

export type SigningSessionSealAuditSink = (
  event: SigningSessionSealAuditEvent,
) => Promise<void> | void;

export interface CreateSigningSessionSealServiceOptions {
  sessionPolicy: SigningSessionSealThresholdSessionPolicy;
  cipher: SigningSessionSealCipherAdapter;
  idempotency?: SigningSessionSealServiceIdempotencyOptions;
  consumePolicy?: SigningSessionSealConsumePolicy;
  guard?: SigningSessionSealGuard;
  audit?: SigningSessionSealAuditSink;
  logger?: NormalizedLogger;
  nowMs?: () => number;
}
