import type { NormalizedLogger } from '../../logger';
import { alphabetizeStringify } from '@shared/utils/digests';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { parseEvmFamilySigningKeySlotIdOrNull } from '@shared/signing-lanes';
import { WALLET_SESSION_FAILURE_CODES } from '@shared/utils/walletSessionFailure';
import {
  parseRouterAbEcdsaDerivationNormalSigningScopeV1,
  type RouterAbEcdsaDerivationNormalSigningScopeV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type {
  ThresholdEcdsaSigningRootMetadata,
  RouterAbEcdsaDerivationPoolFillInitRequest,
  RouterAbEcdsaDerivationPoolFillInitResponse,
  RouterAbEcdsaDerivationPoolFillStepRequest,
  RouterAbEcdsaDerivationPoolFillStepResponse,
} from '../../types';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  signingRootScopeFromRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import type { ThresholdNodeRole } from '../config';
import type {
  RouterAbEcdsaDerivationPoolFillSessionRecord,
  RouterAbEcdsaDerivationPoolFillSessionDestination,
  RouterAbEcdsaDerivationPoolFillSessionStore,
} from '../stores/EcdsaSigningStore';
import {
  startRouterAbEcdsaPresignSession,
  stepRouterAbEcdsaPresignSession,
  type RouterAbEcdsaDerivationPresignaturePoolFillAuth,
} from './ecdsaDerivationPresignBridge';
import type { ThresholdEcdsaSessionClaims } from '../validation';
import {
  formatEcdsaDerivationKeyVersionForWire,
  formatEcdsaKeyHandleForWire,
  formatEcdsaRelayerKeyIdForWire,
  formatEcdsaThresholdKeyIdForWire,
  parseEcdsaDerivationKeyVersion,
  parseEcdsaKeyHandle,
  parseEcdsaRelayerKeyId,
  parseEcdsaThresholdKeyId,
  type EcdsaKeyHandle,
  type EcdsaRelayerKeyId,
  type EcdsaThresholdKeyId,
} from '../../keyMaterialBrands';

const THRESHOLD_ECDSA_DERIVATION_ROLE_LOCAL_WALLET_KEY_VERSION =
  parseEcdsaDerivationKeyVersion('v1');
const THRESHOLD_ECDSA_DERIVATION_ROLE_LOCAL_DERIVATION_VERSION = 1;

type ParseOk<T> = { ok: true; value: T };
type ParseErr = { ok: false; code: string; message: string };
type ParseResult<T> = ParseOk<T> | ParseErr;

type RouterAbEcdsaDerivationPoolFillInitClaims = Pick<
  ThresholdEcdsaSessionClaims,
  | 'walletId'
  | 'evmFamilySigningKeySlotId'
  | 'relayerKeyId'
  | 'keyHandle'
  | 'runtimePolicyScope'
  | 'participantIds'
  | 'thresholdExpiresAtMs'
  | 'routerAbEcdsaDerivationNormalSigning'
>;

type RouterAbEcdsaDerivationPoolFillStepClaims = Pick<
  ThresholdEcdsaSessionClaims,
  | 'walletId'
  | 'evmFamilySigningKeySlotId'
  | 'relayerKeyId'
  | 'participantIds'
  | 'thresholdExpiresAtMs'
  | 'routerAbEcdsaDerivationNormalSigning'
>;

function parseEvmFamilySigningKeySlotString(value: unknown): string | null {
  const parsed = parseEvmFamilySigningKeySlotIdOrNull(value);
  return parsed ? String(parsed) : null;
}
const ECDSA_PRESIGN_POOL_KEY_VERSION = 'v2';

function presignPoolKeyPart(value: unknown, fieldName: string): string {
  const normalized =
    typeof value === 'number' && Number.isFinite(value)
      ? String(value)
      : toOptionalTrimmedString(value);
  if (!normalized)
    throw new Error(`${fieldName} is required for Router A/B ECDSA derivation pool key`);
  return encodeURIComponent(normalized);
}

function ecdsaPresignPoolKey(input: {
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  keyHandle: EcdsaKeyHandle;
  relayerKeyId: EcdsaRelayerKeyId;
  thresholdEcdsaPublicKeyB64u: string;
  signingRootMetadata: ThresholdEcdsaSigningRootMetadata;
}): string {
  return [
    ECDSA_PRESIGN_POOL_KEY_VERSION,
    `keyHandle=${presignPoolKeyPart(formatEcdsaKeyHandleForWire(input.keyHandle), 'keyHandle')}`,
    `ecdsaThresholdKeyId=${presignPoolKeyPart(
      formatEcdsaThresholdKeyIdForWire(input.ecdsaThresholdKeyId),
      'ecdsaThresholdKeyId',
    )}`,
    `relayerKeyId=${presignPoolKeyPart(
      formatEcdsaRelayerKeyIdForWire(input.relayerKeyId),
      'relayerKeyId',
    )}`,
    `signingRootId=${presignPoolKeyPart(input.signingRootMetadata.signingRootId, 'signingRootId')}`,
    `signingRootVersion=${presignPoolKeyPart(
      input.signingRootMetadata.signingRootVersion || 'default',
      'signingRootVersion',
    )}`,
    `walletKeyVersion=${presignPoolKeyPart(
      input.signingRootMetadata.walletKeyVersion,
      'walletKeyVersion',
    )}`,
    `derivationVersion=${presignPoolKeyPart(
      input.signingRootMetadata.derivationVersion,
      'derivationVersion',
    )}`,
    `groupPublicKey=${presignPoolKeyPart(
      input.thresholdEcdsaPublicKeyB64u,
      'thresholdEcdsaPublicKeyB64u',
    )}`,
  ].join('|');
}

function signingRootMetadataFromRuntimePolicyScope(
  scope: unknown,
): Pick<ThresholdEcdsaSigningRootMetadata, 'signingRootId' | 'signingRootVersion'> | null {
  try {
    return signingRootScopeFromRuntimePolicyScope(scope as RuntimePolicyScope);
  } catch {
    return null;
  }
}

function errorMessage(error: unknown): string {
  return String(
    error && typeof error === 'object' && 'message' in error
      ? (error as { message?: unknown }).message
      : error || '',
  );
}

type ThresholdEcdsaRoleLocalKeyRecordSelector = {
  kind: 'key_handle';
  keyHandle: string;
  ecdsaThresholdKeyId?: never;
};

type RouterAbEcdsaDerivationSigningWorkerPoolFillDestination = Extract<
  RouterAbEcdsaDerivationPoolFillSessionDestination,
  { kind: 'router_ab_ecdsa_derivation_signing_worker_pool' }
>;

function requireExactPoolFillKeys(
  record: Record<string, unknown>,
  expectedKeys: readonly string[],
): ParseResult<null> {
  const expected = new Set(expectedKeys);
  for (const key of Object.keys(record)) {
    if (!expected.has(key)) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `poolFill.${key} is not a supported field`,
      };
    }
  }
  return { ok: true, value: null };
}

function parseRouterAbEcdsaDerivationPoolFillRequest(
  value: unknown,
): ParseResult<RouterAbEcdsaDerivationSigningWorkerPoolFillDestination> {
  if (value === undefined) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'poolFill is required for Router A/B ECDSA derivation presign refill',
    };
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { ok: false, code: 'invalid_body', message: 'poolFill must be an object' };
  }

  const record = value as Record<string, unknown>;
  const kind = toOptionalTrimmedString(record.kind);
  if (kind !== 'router_ab_ecdsa_derivation_signing_worker_pool') {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'poolFill.kind must be router_ab_ecdsa_derivation_signing_worker_pool',
    };
  }
  const exactKeys = requireExactPoolFillKeys(record, ['kind', 'scope', 'expiresAtMs']);
  if (!exactKeys.ok) return exactKeys;

  let scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  try {
    scope = parseRouterAbEcdsaDerivationNormalSigningScopeV1(record.scope);
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `poolFill.scope is invalid: ${errorMessage(error)}`,
    };
  }

  const expiresAtMs = record.expiresAtMs;
  if (typeof expiresAtMs !== 'number' || !Number.isFinite(expiresAtMs)) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'poolFill.expiresAtMs must be a finite number',
    };
  }
  const expiresAtMsInt = Math.floor(expiresAtMs);
  if (expiresAtMsInt !== expiresAtMs || expiresAtMsInt <= 0) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'poolFill.expiresAtMs must be a positive integer timestamp',
    };
  }

  return {
    ok: true,
    value: {
      kind,
      routerAbEcdsaDerivation: {
        scope,
        expiresAtMs: expiresAtMsInt,
      },
    },
  };
}

function parseRouterAbEcdsaDerivationPoolFillInitRequest(
  request: RouterAbEcdsaDerivationPoolFillInitRequest,
): ParseResult<{
  keySelector: ThresholdEcdsaRoleLocalKeyRecordSelector;
  count: number;
  poolFill: RouterAbEcdsaDerivationSigningWorkerPoolFillDestination;
}> {
  const keyHandle = toOptionalTrimmedString((request as { keyHandle?: unknown }).keyHandle);
  const ecdsaThresholdKeyId = toOptionalTrimmedString(request.ecdsaThresholdKeyId);
  if (ecdsaThresholdKeyId) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'keyHandle is required for Router A/B ECDSA derivation pool-fill init',
    };
  }
  if (!keyHandle) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'keyHandle is required for Router A/B ECDSA derivation pool-fill init',
    };
  }
  const countRaw = (request as { count?: unknown }).count;
  const count = Math.max(1, Math.floor(Number(countRaw ?? 1)));
  if (count !== 1) {
    return {
      ok: false,
      code: 'unsupported',
      message: 'Router A/B ECDSA derivation pool-fill init supports only count=1',
    };
  }
  const poolFill = parseRouterAbEcdsaDerivationPoolFillRequest(
    (request as { poolFill?: unknown }).poolFill,
  );
  if (!poolFill.ok) return poolFill;
  return {
    ok: true,
    value: {
      keySelector: { kind: 'key_handle', keyHandle },
      count,
      poolFill: poolFill.value,
    },
  };
}

function parseRouterAbEcdsaDerivationPoolFillStepRequest(
  request: RouterAbEcdsaDerivationPoolFillStepRequest,
): ParseResult<{
  presignSessionId: string;
  stage: 'triples' | 'presign';
  outgoingMessagesB64u: string[];
}> {
  const presignSessionId = toOptionalTrimmedString(request.presignSessionId);
  if (!presignSessionId)
    return { ok: false, code: 'invalid_body', message: 'presignSessionId is required' };
  const stageRaw = toOptionalTrimmedString((request as { stage?: unknown }).stage);
  if (stageRaw !== 'triples' && stageRaw !== 'presign') {
    return { ok: false, code: 'invalid_body', message: 'stage must be "triples" or "presign"' };
  }
  const msgsRaw = (request as { outgoingMessagesB64u?: unknown }).outgoingMessagesB64u;
  const outgoingMessagesB64u = Array.isArray(msgsRaw)
    ? msgsRaw.map((v) => toOptionalTrimmedString(v)).filter((v): v is string => Boolean(v))
    : [];
  return { ok: true, value: { presignSessionId, stage: stageRaw, outgoingMessagesB64u } };
}

function sameParticipantIds(a: number[], b: number[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export type RouterAbEcdsaPresignSigningWorkerTransport = {
  readonly signingWorkerBaseUrl: string;
  readonly auth: RouterAbEcdsaDerivationPresignaturePoolFillAuth;
  readonly fetchImpl: typeof fetch;
};

export class RouterAbEcdsaDerivationPoolFillHandlers {
  private readonly logger: NormalizedLogger;
  private readonly nodeRole: ThresholdNodeRole;
  private readonly participantIds2p: number[];
  private readonly clientParticipantId: number;
  private readonly relayerParticipantId: number;
  private readonly poolFillSessionStore: RouterAbEcdsaDerivationPoolFillSessionStore;
  private readonly ensureReady: () => Promise<void>;
  private readonly createPoolFillSessionId: () => string;
  private readonly signingWorkerTransport: RouterAbEcdsaPresignSigningWorkerTransport;

  constructor(input: {
    readonly logger: NormalizedLogger;
    readonly nodeRole: ThresholdNodeRole;
    readonly participantIds2p: number[];
    readonly clientParticipantId: number;
    readonly relayerParticipantId: number;
    readonly poolFillSessionStore: RouterAbEcdsaDerivationPoolFillSessionStore;
    readonly ensureReady: () => Promise<void>;
    readonly createPoolFillSessionId: () => string;
    readonly signingWorkerTransport: RouterAbEcdsaPresignSigningWorkerTransport;
  }) {
    this.logger = input.logger;
    this.nodeRole = input.nodeRole;
    this.participantIds2p = input.participantIds2p;
    this.clientParticipantId = input.clientParticipantId;
    this.relayerParticipantId = input.relayerParticipantId;
    this.poolFillSessionStore = input.poolFillSessionStore;
    this.ensureReady = input.ensureReady;
    this.createPoolFillSessionId = input.createPoolFillSessionId;
    this.signingWorkerTransport = input.signingWorkerTransport;
  }

  private async startStrictPresignSession(input: {
    claims: RouterAbEcdsaDerivationPoolFillInitClaims;
    keySelector: ThresholdEcdsaRoleLocalKeyRecordSelector;
    poolFill: RouterAbEcdsaDerivationSigningWorkerPoolFillDestination;
    walletId: string;
    evmFamilySigningKeySlotId: string;
    relayerKeyId: string;
    signingRoot: Pick<ThresholdEcdsaSigningRootMetadata, 'signingRootId' | 'signingRootVersion'>;
  }): Promise<RouterAbEcdsaDerivationPoolFillInitResponse> {
    const transport = this.signingWorkerTransport;
    const scope = input.poolFill.routerAbEcdsaDerivation.scope;
    const trustedScope = input.claims.routerAbEcdsaDerivationNormalSigning.scope;
    if (alphabetizeStringify(scope) !== alphabetizeStringify(trustedScope)) {
      return {
        ok: false,
        code: WALLET_SESSION_FAILURE_CODES.scopeMismatch,
        message: 'poolFill.scope does not match Wallet Session normal-signing scope',
      };
    }
    if (
      scope.wallet_id !== input.walletId ||
      scope.wallet_key_id !== input.evmFamilySigningKeySlotId ||
      scope.signing_root_id !== input.signingRoot.signingRootId ||
      scope.signing_root_version !== input.signingRoot.signingRootVersion ||
      input.keySelector.keyHandle !== input.claims.keyHandle
    ) {
      return {
        ok: false,
        code: WALLET_SESSION_FAILURE_CODES.scopeMismatch,
        message: 'poolFill scope does not match Wallet Session claims',
      };
    }
    const nowMs = Date.now();
    const expiresAtMs = Math.min(
      input.poolFill.routerAbEcdsaDerivation.expiresAtMs,
      input.claims.thresholdExpiresAtMs,
      nowMs + 5 * 60_000,
    );
    if (expiresAtMs <= nowMs) {
      return {
        ok: false,
        code: WALLET_SESSION_FAILURE_CODES.expired,
        message: 'Wallet Session expired',
      };
    }
    const signingRootMetadata: ThresholdEcdsaSigningRootMetadata = {
      ...input.signingRoot,
      walletKeyVersion: formatEcdsaDerivationKeyVersionForWire(
        THRESHOLD_ECDSA_DERIVATION_ROLE_LOCAL_WALLET_KEY_VERSION,
      ),
      derivationVersion: THRESHOLD_ECDSA_DERIVATION_ROLE_LOCAL_DERIVATION_VERSION,
    };
    const presignPoolKey = ecdsaPresignPoolKey({
      ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(scope.ecdsa_threshold_key_id),
      keyHandle: parseEcdsaKeyHandle(input.keySelector.keyHandle),
      relayerKeyId: parseEcdsaRelayerKeyId(input.relayerKeyId),
      thresholdEcdsaPublicKeyB64u: scope.public_identity.threshold_public_key33_b64u,
      signingRootMetadata,
    });
    const participantIds = normalizeThresholdEd25519ParticipantIds(input.claims.participantIds);
    if (!participantIds || !sameParticipantIds(participantIds, this.participantIds2p)) {
      return {
        ok: false,
        code: WALLET_SESSION_FAILURE_CODES.scopeMismatch,
        message: 'Wallet Session participantIds do not match the ECDSA signer set',
      };
    }
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const presignSessionId = this.createPoolFillSessionId();
      const started = await startRouterAbEcdsaPresignSession({
        signingWorkerBaseUrl: transport.signingWorkerBaseUrl,
        scope,
        presignSessionId,
        expiresAtMs,
        auth: transport.auth,
        fetchImpl: transport.fetchImpl,
      });
      if (!started.ok) {
        return { ok: false, code: started.code, message: started.message };
      }
      if (started.value.kind !== 'continue') {
        return {
          ok: false,
          code: 'internal',
          message: 'SigningWorker ECDSA presign init returned terminal progress',
        };
      }
      const createdAtMs = Date.now();
      const record: RouterAbEcdsaDerivationPoolFillSessionRecord = {
        expiresAtMs,
        walletId: input.walletId,
        evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
        relayerKeyId: input.relayerKeyId,
        presignPoolKey,
        poolFill: input.poolFill,
        participantIds,
        clientParticipantId: this.clientParticipantId,
        relayerParticipantId: this.relayerParticipantId,
        stage: started.value.stage,
        version: 1,
        createdAtMs,
        updatedAtMs: createdAtMs,
        ...signingRootMetadata,
      };
      const created = await this.poolFillSessionStore.createSession(
        presignSessionId,
        record,
        Math.max(1, expiresAtMs - Date.now()),
      );
      if (!created.ok) continue;
      return {
        ok: true,
        presignSessionId,
        stage: started.value.stage,
        outgoingMessagesB64u: started.value.outgoingMessagesB64u,
      };
    }
    return { ok: false, code: 'internal', message: 'Failed to allocate presignSessionId; retry' };
  }

  private async stepStrictPresignSession(input: {
    claims: RouterAbEcdsaDerivationPoolFillStepClaims;
    record: RouterAbEcdsaDerivationPoolFillSessionRecord;
    presignSessionId: string;
    requestedStage: 'triples' | 'presign';
    outgoingMessagesB64u: string[];
  }): Promise<RouterAbEcdsaDerivationPoolFillStepResponse> {
    const transport = this.signingWorkerTransport;
    const scope = input.record.poolFill.routerAbEcdsaDerivation.scope;
    if (
      alphabetizeStringify(scope) !==
      alphabetizeStringify(input.claims.routerAbEcdsaDerivationNormalSigning.scope)
    ) {
      await this.poolFillSessionStore.deleteSession(input.presignSessionId);
      return {
        ok: false,
        code: WALLET_SESSION_FAILURE_CODES.scopeMismatch,
        message: 'presignSessionId does not match Wallet Session normal-signing scope',
      };
    }
    const stepped = await stepRouterAbEcdsaPresignSession({
      signingWorkerBaseUrl: transport.signingWorkerBaseUrl,
      scope,
      presignSessionId: input.presignSessionId,
      requestedStage: input.requestedStage,
      outgoingMessagesB64u: input.outgoingMessagesB64u,
      expiresAtMs: input.record.expiresAtMs,
      auth: transport.auth,
      fetchImpl: transport.fetchImpl,
    });
    if (!stepped.ok) {
      await this.poolFillSessionStore.deleteSession(input.presignSessionId);
      return {
        ok: false,
        code: 'stale_session_state',
        message: `SigningWorker ECDSA presign session is unavailable; restart pool fill: ${stepped.message}`,
      };
    }
    if (stepped.value.presignSessionId !== input.presignSessionId) {
      await this.poolFillSessionStore.deleteSession(input.presignSessionId);
      return {
        ok: false,
        code: 'internal',
        message: 'SigningWorker ECDSA presign response session mismatch',
      };
    }
    if (stepped.value.kind === 'complete') {
      await this.poolFillSessionStore.deleteSession(input.presignSessionId);
      return {
        ok: true,
        stage: 'done',
        event: 'presign_done',
        outgoingMessagesB64u: [],
        presignatureId: stepped.value.serverPresignatureId,
        bigRB64u: stepped.value.serverBigR33B64u,
      };
    }
    const nextRecord: RouterAbEcdsaDerivationPoolFillSessionRecord = {
      ...input.record,
      stage: stepped.value.stage,
      version: input.record.version + 1,
      updatedAtMs: Date.now(),
    };
    const cas = await this.poolFillSessionStore.advanceSessionCas({
      id: input.presignSessionId,
      expectedVersion: input.record.version,
      nextRecord,
      ttlMs: Math.max(1, input.record.expiresAtMs - Date.now()),
    });
    if (!cas.ok) {
      return {
        ok: false,
        code: 'stale_session_state',
        message: 'ECDSA presign session updated concurrently; restart pool fill',
      };
    }
    return {
      ok: true,
      stage: stepped.value.stage,
      event: stepped.value.event,
      outgoingMessagesB64u: stepped.value.outgoingMessagesB64u,
    };
  }

  private emitPresignSecurityEvent(input: {
    event: string;
    presignSessionId: string;
    record?: RouterAbEcdsaDerivationPoolFillSessionRecord | null;
    code?: string;
    message?: string;
    requestOrigin?: string;
  }): void {
    const record = input.record || null;
    this.logger.warn('[threshold-ecdsa-security]', {
      event: input.event,
      presignSessionId: input.presignSessionId,
      walletId: record?.walletId || null,
      evmFamilySigningKeySlotId: record?.evmFamilySigningKeySlotId || null,
      relayerKeyId: record?.relayerKeyId || null,
      ecdsaThresholdKeyId: null,
      presignPoolKey: record?.presignPoolKey || null,
      requestOrigin: input.requestOrigin || null,
      code: input.code || null,
      message: input.message || null,
    });
  }

  async routerAbEcdsaDerivationPresignaturePoolFillInit(input: {
    claims: RouterAbEcdsaDerivationPoolFillInitClaims;
    request: RouterAbEcdsaDerivationPoolFillInitRequest;
  }): Promise<RouterAbEcdsaDerivationPoolFillInitResponse> {
    if (this.nodeRole !== 'coordinator') {
      return {
        ok: false,
        code: 'not_found',
        message:
          'Router A/B ECDSA derivation pool-fill endpoints are not enabled on this server (set THRESHOLD_NODE_ROLE=coordinator)',
      };
    }

    await this.ensureReady();

    const parsedRequest = parseRouterAbEcdsaDerivationPoolFillInitRequest(input.request);
    if (!parsedRequest.ok) return parsedRequest;
    const { keySelector, poolFill } = parsedRequest.value;

    const claims = input.claims;
    const walletId = toOptionalTrimmedString(claims?.walletId);
    if (!walletId)
      return {
        ok: false,
        code: WALLET_SESSION_FAILURE_CODES.claimsInvalid,
        message: 'Missing walletId in Wallet Session token',
      };
    const tokenRelayerKeyId = toOptionalTrimmedString(claims?.relayerKeyId);
    const tokenWalletKeyId = parseEvmFamilySigningKeySlotString(claims?.evmFamilySigningKeySlotId);
    if (!tokenRelayerKeyId || !tokenWalletKeyId) {
      return {
        ok: false,
        code: WALLET_SESSION_FAILURE_CODES.claimsInvalid,
        message: 'Invalid Wallet Session token claims',
      };
    }
    const tokenSigningRoot = signingRootMetadataFromRuntimePolicyScope(claims.runtimePolicyScope);
    if (!tokenSigningRoot) {
      return {
        ok: false,
        code: WALLET_SESSION_FAILURE_CODES.claimsInvalid,
        message: 'Wallet Session token is missing signing-root scope',
      };
    }
    return this.startStrictPresignSession({
      claims,
      keySelector,
      poolFill,
      walletId,
      evmFamilySigningKeySlotId: tokenWalletKeyId,
      relayerKeyId: tokenRelayerKeyId,
      signingRoot: tokenSigningRoot,
    });
  }

  async routerAbEcdsaDerivationPresignaturePoolFillStep(input: {
    readonly claims: RouterAbEcdsaDerivationPoolFillStepClaims;
    readonly request: RouterAbEcdsaDerivationPoolFillStepRequest;
  }): Promise<RouterAbEcdsaDerivationPoolFillStepResponse> {
    if (this.nodeRole !== 'coordinator') {
      return {
        ok: false,
        code: 'not_found',
        message:
          'Router A/B ECDSA derivation pool-fill endpoints are not enabled on this server (set THRESHOLD_NODE_ROLE=coordinator)',
      };
    }

    await this.ensureReady();

    const parsedRequest = parseRouterAbEcdsaDerivationPoolFillStepRequest(input.request);
    if (!parsedRequest.ok) return parsedRequest;
    const { presignSessionId, stage: requestedStage, outgoingMessagesB64u } = parsedRequest.value;
    const stepStartedAtMs = Date.now();
    const perf: {
      storeGetSessionMs?: number;
      resultCode?: string;
    } = {};
    try {
      const storeGetStartedAtMs = Date.now();
      const record = await this.poolFillSessionStore.getSession(presignSessionId);
      perf.storeGetSessionMs = Math.max(0, Date.now() - storeGetStartedAtMs);
      if (!record) {
        this.emitPresignSecurityEvent({
          event: 'presign_session_replay_or_missing',
          presignSessionId,
          code: 'unauthorized',
          message: 'presignSessionId expired or invalid',
        });
        perf.resultCode = 'unauthorized';
        return { ok: false, code: 'unauthorized', message: 'presignSessionId expired or invalid' };
      }
      if (Date.now() > record.expiresAtMs) {
        await this.poolFillSessionStore.deleteSession(presignSessionId);
        perf.resultCode = 'unauthorized';
        return { ok: false, code: 'unauthorized', message: 'presignSessionId expired' };
      }

      const claims = input.claims;
      const tokenUserId = toOptionalTrimmedString(claims.walletId);
      const tokenWalletKeyId = parseEvmFamilySigningKeySlotString(
        claims.evmFamilySigningKeySlotId,
      );
      const tokenParticipantIds = normalizeThresholdEd25519ParticipantIds(claims.participantIds);
      if (!tokenUserId || !tokenWalletKeyId || !tokenParticipantIds) {
        await this.poolFillSessionStore.deleteSession(presignSessionId);
        this.emitPresignSecurityEvent({
          event: 'presign_scope_mismatch',
          presignSessionId,
          record,
          code: WALLET_SESSION_FAILURE_CODES.claimsInvalid,
          message: 'Invalid Wallet Session token claims',
        });
        perf.resultCode = WALLET_SESSION_FAILURE_CODES.claimsInvalid;
        return {
          ok: false,
          code: WALLET_SESSION_FAILURE_CODES.claimsInvalid,
          message: 'Invalid Wallet Session token claims',
        };
      }
      if (
        tokenUserId !== record.walletId ||
        tokenWalletKeyId !== record.evmFamilySigningKeySlotId ||
        !sameParticipantIds(tokenParticipantIds, record.participantIds)
      ) {
        await this.poolFillSessionStore.deleteSession(presignSessionId);
        this.emitPresignSecurityEvent({
          event: 'presign_scope_mismatch',
          presignSessionId,
          record,
          code: WALLET_SESSION_FAILURE_CODES.scopeMismatch,
          message: 'presignSessionId does not match Wallet Session scope',
        });
        perf.resultCode = WALLET_SESSION_FAILURE_CODES.scopeMismatch;
        return {
          ok: false,
          code: WALLET_SESSION_FAILURE_CODES.scopeMismatch,
          message: 'presignSessionId does not match Wallet Session scope',
        };
      }
      if (toOptionalTrimmedString(claims.relayerKeyId) !== record.relayerKeyId) {
        await this.poolFillSessionStore.deleteSession(presignSessionId);
        this.emitPresignSecurityEvent({
          event: 'presign_scope_mismatch',
          presignSessionId,
          record,
          code: WALLET_SESSION_FAILURE_CODES.scopeMismatch,
          message: 'presignSessionId does not match Wallet Session scope',
        });
        perf.resultCode = WALLET_SESSION_FAILURE_CODES.scopeMismatch;
        return {
          ok: false,
          code: WALLET_SESSION_FAILURE_CODES.scopeMismatch,
          message: 'presignSessionId does not match Wallet Session scope',
        };
      }
      if (Date.now() > claims.thresholdExpiresAtMs) {
        await this.poolFillSessionStore.deleteSession(presignSessionId);
        perf.resultCode = WALLET_SESSION_FAILURE_CODES.expired;
        return {
          ok: false,
          code: WALLET_SESSION_FAILURE_CODES.expired,
          message: 'Wallet Session expired',
        };
      }
      const strictResponse = await this.stepStrictPresignSession({
        claims,
        record,
        presignSessionId,
        requestedStage,
        outgoingMessagesB64u,
      });
      perf.resultCode = strictResponse.ok
        ? 'ok'
        : toOptionalTrimmedString(strictResponse.code) || 'strict_presign_error';
      return strictResponse;
    } finally {
      this.logger.info('[router-ab-ecdsa-derivation-pool-fill] step perf', {
        presignSessionId,
        requestedStage,
        totalMs: Math.max(0, Date.now() - stepStartedAtMs),
        ...perf,
      });
    }
  }
}
