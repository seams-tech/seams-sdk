export type PrfSessionSealRouteHeaders = Record<string, string | string[] | undefined>;

export type PrfSessionSealSessionClaims = Record<string, unknown>;

export interface PrfSessionSealSessionAdapter {
  parse(
    headers: PrfSessionSealRouteHeaders,
  ): Promise<{ ok: true; claims: PrfSessionSealSessionClaims } | { ok: false }>;
}

export interface PrfSessionSealAuthContext {
  userId: string;
  claims: PrfSessionSealSessionClaims;
}

export interface PrfSessionSealAuthorizeInput {
  headers: PrfSessionSealRouteHeaders;
  session: PrfSessionSealSessionAdapter | null | undefined;
}

export type PrfSessionSealAuthorizeResult =
  | { ok: true; auth: PrfSessionSealAuthContext }
  | { ok: false; code?: string; message?: string; status?: number };

export interface PrfSessionSealApplyServerSealRequest {
  thresholdSessionId: string;
  ciphertext: string;
  keyVersion?: string;
  metadata?: Record<string, unknown>;
}

export interface PrfSessionSealRemoveServerSealRequest {
  thresholdSessionId: string;
  ciphertext: string;
  keyVersion?: string;
  metadata?: Record<string, unknown>;
}

export type PrfSessionSealRouteResult =
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

export interface PrfSessionSealService {
  applyServerSeal(
    request: PrfSessionSealApplyServerSealRequest,
    auth: PrfSessionSealAuthContext,
  ): Promise<PrfSessionSealRouteResult>;

  removeServerSeal(
    request: PrfSessionSealRemoveServerSealRequest,
    auth: PrfSessionSealAuthContext,
  ): Promise<PrfSessionSealRouteResult>;
}

export interface PrfSessionSealRoutesOptions {
  enabled?: boolean;
  basePath?: string;
  service: PrfSessionSealService;
  authorize?: (
    input: PrfSessionSealAuthorizeInput,
  ) => Promise<PrfSessionSealAuthorizeResult> | PrfSessionSealAuthorizeResult;
}

export type PrfSessionSealOperation = 'apply-server-seal' | 'remove-server-seal';

export interface PrfSessionSealThresholdSessionRecord {
  thresholdSessionId: string;
  userId: string;
  expiresAtMs: number;
  remainingUses?: number;
}

export type PrfSessionSealConsumeUseResult =
  | { ok: true; remainingUses?: number }
  | { ok: false; code: string; message: string };

export interface PrfSessionSealThresholdSessionPolicy {
  getSession(thresholdSessionId: string): Promise<PrfSessionSealThresholdSessionRecord | null>;
  consumeUseCount?(thresholdSessionId: string): Promise<PrfSessionSealConsumeUseResult>;
}

export interface PrfSessionSealCipherOperationInput {
  operation: PrfSessionSealOperation;
  thresholdSessionId: string;
  ciphertext: string;
  keyVersion?: string;
  metadata?: Record<string, unknown>;
  auth: PrfSessionSealAuthContext;
}

export type PrfSessionSealCipherOperationResult =
  | { ok: true; ciphertext: string; keyVersion?: string }
  | { ok: false; code: string; message: string };

export interface PrfSessionSealCipherAdapter {
  run(input: PrfSessionSealCipherOperationInput): Promise<PrfSessionSealCipherOperationResult>;
}

export type PrfSessionSealConsumePolicy = 'never' | 'apply-only' | 'remove-only' | 'always';

export interface PrfSessionSealGuardInput {
  operation: PrfSessionSealOperation;
  thresholdSessionId: string;
  auth: PrfSessionSealAuthContext;
}

export type PrfSessionSealGuardResult = { ok: true } | { ok: false; code: string; message: string };

export type PrfSessionSealGuard = (
  input: PrfSessionSealGuardInput,
) => Promise<PrfSessionSealGuardResult> | PrfSessionSealGuardResult;

export interface PrfSessionSealAuditEvent {
  operation: PrfSessionSealOperation;
  thresholdSessionId: string;
  userId: string;
  ok: boolean;
  code?: string;
  durationMs: number;
}

export type PrfSessionSealAuditSink = (event: PrfSessionSealAuditEvent) => Promise<void> | void;

export interface CreatePrfSessionSealServiceOptions {
  sessionPolicy: PrfSessionSealThresholdSessionPolicy;
  cipher: PrfSessionSealCipherAdapter;
  consumePolicy?: PrfSessionSealConsumePolicy;
  guard?: PrfSessionSealGuard;
  audit?: PrfSessionSealAuditSink;
  nowMs?: () => number;
}
