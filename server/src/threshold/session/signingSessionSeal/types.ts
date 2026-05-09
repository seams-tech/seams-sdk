import type { NormalizedLogger } from '../../../core/logger';

export type SigningSessionSealRouteHeaders = Record<string, string | string[] | undefined>;

export type SigningSessionSealSessionClaims = Record<string, unknown>;

export interface SigningSessionSealSessionAdapter {
  parse(
    headers: SigningSessionSealRouteHeaders,
  ): Promise<{ ok: true; claims: SigningSessionSealSessionClaims } | { ok: false }>;
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
  enabled?: boolean;
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

export interface SigningSessionSealThresholdSessionRecord {
  thresholdSessionId: string;
  userId: string;
  expiresAtMs: number;
  remainingUses?: number;
}

export interface SigningSessionSealThresholdSessionStatus
  extends SigningSessionSealThresholdSessionRecord {
  remainingUses: number;
  record: {
    expiresAtMs: number;
    relayerKeyId: string;
    userId: string;
    rpId: string;
    participantIds: number[];
  };
}

export type SigningSessionSealConsumeUseResult =
  | { ok: true; remainingUses?: number }
  | { ok: false; code: string; message: string };

export interface SigningSessionSealThresholdSessionPolicy {
  getSession(thresholdSessionId: string): Promise<SigningSessionSealThresholdSessionRecord | null>;
  getSessionStatus?(
    thresholdSessionId: string,
  ): Promise<SigningSessionSealThresholdSessionStatus | null>;
  getSessionStatuses(
    thresholdSessionId: string,
  ): Promise<SigningSessionSealThresholdSessionStatus[]>;
  consumeUseCount?(thresholdSessionId: string): Promise<SigningSessionSealConsumeUseResult>;
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
  run(input: SigningSessionSealCipherOperationInput): Promise<SigningSessionSealCipherOperationResult>;
}

export type SigningSessionSealConsumePolicy = 'never' | 'apply-only' | 'remove-only' | 'always';

export interface SigningSessionSealGuardInput {
  operation: SigningSessionSealOperation;
  thresholdSessionId: string;
  auth: SigningSessionSealAuthContext;
}

export type SigningSessionSealGuardResult = { ok: true } | { ok: false; code: string; message: string };

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

export type SigningSessionSealAuditSink = (event: SigningSessionSealAuditEvent) => Promise<void> | void;

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
