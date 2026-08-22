import type { SigningSessionSealProtocol } from '@shared/utils/signingSessionSeal';
import type { NormalizedLogger } from '../../../core/logger';
import type { ThresholdEd25519AuthorityScope } from '../../../core/types';
import type { EcdsaKeyHandle } from '../../../core/keyMaterialBrands';

export type SigningSessionSealRouteHeaders = Record<string, string | string[] | undefined>;

export interface SigningSessionSealAuthContext {
  userId: string;
  session: SigningSessionSealAuthorizationSessionRecord;
}

export interface SigningSessionSealCipherAuthContext {
  userId: string;
}

export interface SigningSessionSealAuthorizeInput {
  headers: SigningSessionSealRouteHeaders;
  thresholdSessionId: string;
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

type SigningSessionSealRouteSuccessBase = {
  ok: true;
  ciphertext: string;
  keyVersion?: string;
  expiresAtMs?: number;
};

export type SigningSessionSealRouteResult =
  SigningSessionSealRouteSuccessBase
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
  capabilities?: SigningSessionSealStartupCapabilities;
  authorize?: (
    input: SigningSessionSealAuthorizeInput,
  ) => Promise<SigningSessionSealAuthorizeResult> | SigningSessionSealAuthorizeResult;
}

export interface SigningSessionSealStartupCapabilities {
  mode: 'sealed_refresh_v1';
  protocol: SigningSessionSealProtocol;
  currentKeyVersion: string;
}

export type SigningSessionSealOperation = 'apply-server-seal' | 'remove-server-seal';

export type SigningSessionSealCurve = 'ecdsa' | 'ed25519';

type SigningSessionSealAuthorizationSessionRecordBase = {
  userId: string;
  expiresAtMs: number;
};

type SigningSessionSealOwnerThresholdSessionRecordBase =
  SigningSessionSealAuthorizationSessionRecordBase & {
    kind: 'owner_threshold_session';
    thresholdSessionId: string;
    relayerKeyId: string;
    participantIds: readonly number[];
    signingRootId?: string;
    signingRootVersion?: string;
    remainingUses?: never;
  };

export type SigningSessionSealEcdsaThresholdSessionRecord =
  SigningSessionSealOwnerThresholdSessionRecordBase & {
    curve: 'ecdsa';
    keyHandle: EcdsaKeyHandle;
    authorityScope?: never;
  };

export type SigningSessionSealEd25519ThresholdSessionRecord =
  SigningSessionSealOwnerThresholdSessionRecordBase & {
    curve: 'ed25519';
    authorityScope: ThresholdEd25519AuthorityScope;
    keyHandle?: never;
  };

export type SigningSessionSealThresholdSessionRecord =
  | SigningSessionSealEcdsaThresholdSessionRecord
  | SigningSessionSealEd25519ThresholdSessionRecord;

export type SigningSessionSealAuthorizationSessionRecord = SigningSessionSealThresholdSessionRecord;

export interface SigningSessionSealCipherOperationInput {
  operation: SigningSessionSealOperation;
  thresholdSessionId: string;
  ciphertext: string;
  keyVersion?: string;
  metadata?: Record<string, unknown>;
  auth: SigningSessionSealCipherAuthContext;
}

export type SigningSessionSealCipherOperationResult =
  | { ok: true; ciphertext: string; keyVersion?: string }
  | { ok: false; code: string; message: string };

export interface SigningSessionSealCipherAdapter {
  run(
    input: SigningSessionSealCipherOperationInput,
  ): Promise<SigningSessionSealCipherOperationResult>;
}

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
  cipher: SigningSessionSealCipherAdapter;
  idempotency?: SigningSessionSealServiceIdempotencyOptions;
  guard?: SigningSessionSealGuard;
  audit?: SigningSessionSealAuditSink;
  logger?: NormalizedLogger;
  nowMs?: () => number;
}
