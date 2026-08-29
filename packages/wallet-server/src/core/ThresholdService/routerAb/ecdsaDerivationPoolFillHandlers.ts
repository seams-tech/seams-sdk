import { alphabetizeStringify } from '@shared/utils/digests';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { WALLET_SESSION_FAILURE_CODES } from '@shared/utils/walletSessionFailure';
import {
  parseRouterAbEcdsaDerivationNormalSigningScopeV1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
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
import type { RouterAbEcdsaDerivationPoolFillSessionDestination } from '../stores/EcdsaSigningStore';
import {
  startRouterAbEcdsaPresignSession,
  stepRouterAbEcdsaPresignSession,
  type RouterAbEcdsaDerivationPresignaturePoolFillAuth,
} from './ecdsaDerivationPresignBridge';
import { parseEcdsaKeyHandle, type EcdsaKeyHandle } from '../../keyMaterialBrands';

type ParseOk<T> = { ok: true; value: T };
type ParseErr = { ok: false; code: string; message: string };
type ParseResult<T> = ParseOk<T> | ParseErr;
const PRESIGN_SESSION_ID_PREFIX = 'ecdsa-presign-v2';

type RouterAbEcdsaDerivationPoolFillBinding = {
  readonly walletId: string;
  readonly relayerKeyId: string;
  readonly keyHandle: string;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly participantIds: readonly [number, number];
  readonly thresholdExpiresAtMs: number;
  readonly routerAbEcdsaDerivationNormalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
};
function presignSessionExpiresAtMs(presignSessionId: string): number | null {
  const [prefix, expiresAtRaw] = presignSessionId.split(':', 3);
  if (prefix !== PRESIGN_SESSION_ID_PREFIX) return null;
  const expiresAtMs = Number(expiresAtRaw);
  return Number.isSafeInteger(expiresAtMs) && expiresAtMs > 0 ? expiresAtMs : null;
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
  private readonly nodeRole: ThresholdNodeRole;
  private readonly participantIds2p: number[];
  private readonly ensureReady: () => Promise<void>;
  private readonly createPoolFillSessionId: (expiresAtMs: number) => string;
  private readonly signingWorkerTransport: RouterAbEcdsaPresignSigningWorkerTransport;

  constructor(input: {
    readonly nodeRole: ThresholdNodeRole;
    readonly participantIds2p: number[];
    readonly ensureReady: () => Promise<void>;
    readonly createPoolFillSessionId: (expiresAtMs: number) => string;
    readonly signingWorkerTransport: RouterAbEcdsaPresignSigningWorkerTransport;
  }) {
    this.nodeRole = input.nodeRole;
    this.participantIds2p = input.participantIds2p;
    this.ensureReady = input.ensureReady;
    this.createPoolFillSessionId = input.createPoolFillSessionId;
    this.signingWorkerTransport = input.signingWorkerTransport;
  }

  private async startStrictPresignSession(input: {
    binding: RouterAbEcdsaDerivationPoolFillBinding;
    keySelector: ThresholdEcdsaRoleLocalKeyRecordSelector;
    poolFill: RouterAbEcdsaDerivationSigningWorkerPoolFillDestination;
    walletId: string;
    keyHandle: EcdsaKeyHandle;
    relayerKeyId: string;
    signingRoot: Pick<ThresholdEcdsaSigningRootMetadata, 'signingRootId' | 'signingRootVersion'>;
  }): Promise<RouterAbEcdsaDerivationPoolFillInitResponse> {
    const transport = this.signingWorkerTransport;
    const scope = input.poolFill.routerAbEcdsaDerivation.scope;
    const trustedScope = input.binding.routerAbEcdsaDerivationNormalSigning.scope;
    if (alphabetizeStringify(scope) !== alphabetizeStringify(trustedScope)) {
      return {
        ok: false,
        code: WALLET_SESSION_FAILURE_CODES.scopeMismatch,
        message: 'poolFill.scope does not match Wallet Session normal-signing scope',
      };
    }
    if (
      scope.wallet_id !== input.walletId ||
      scope.signing_root_id !== input.signingRoot.signingRootId ||
      scope.signing_root_version !== input.signingRoot.signingRootVersion ||
      input.keySelector.keyHandle !== input.binding.keyHandle
    ) {
      return {
        ok: false,
        code: WALLET_SESSION_FAILURE_CODES.scopeMismatch,
        message: 'poolFill scope does not match Wallet Session binding',
      };
    }
    const nowMs = Date.now();
    const expiresAtMs = Math.min(
      input.poolFill.routerAbEcdsaDerivation.expiresAtMs,
      input.binding.thresholdExpiresAtMs,
      nowMs + 5 * 60_000,
    );
    if (expiresAtMs <= nowMs) {
      return {
        ok: false,
        code: WALLET_SESSION_FAILURE_CODES.expired,
        message: 'Wallet Session expired',
      };
    }
    const participantIds = normalizeThresholdEd25519ParticipantIds(input.binding.participantIds);
    if (!participantIds || !sameParticipantIds(participantIds, this.participantIds2p)) {
      return {
        ok: false,
        code: WALLET_SESSION_FAILURE_CODES.scopeMismatch,
        message: 'Wallet Session participantIds do not match the ECDSA signer set',
      };
    }
    const presignSessionId = this.createPoolFillSessionId(expiresAtMs);
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
    return {
      ok: true,
      presignSessionId,
      materialExpiresAtMs: expiresAtMs,
      stage: started.value.stage,
      outgoingMessagesB64u: started.value.outgoingMessagesB64u,
    };
  }

  private async stepStrictPresignSession(input: {
    binding: RouterAbEcdsaDerivationPoolFillBinding;
    presignSessionId: string;
    requestedStage: 'triples' | 'presign';
    outgoingMessagesB64u: string[];
  }): Promise<RouterAbEcdsaDerivationPoolFillStepResponse> {
    const transport = this.signingWorkerTransport;
    const scope = input.binding.routerAbEcdsaDerivationNormalSigning.scope;
    const stepped = await stepRouterAbEcdsaPresignSession({
      signingWorkerBaseUrl: transport.signingWorkerBaseUrl,
      scope,
      presignSessionId: input.presignSessionId,
      requestedStage: input.requestedStage,
      outgoingMessagesB64u: input.outgoingMessagesB64u,
      expiresAtMs: input.binding.thresholdExpiresAtMs,
      auth: transport.auth,
      fetchImpl: transport.fetchImpl,
    });
    if (!stepped.ok) {
      return {
        ok: false,
        code: 'stale_session_state',
        message: `SigningWorker ECDSA presign session is unavailable; restart pool fill: ${stepped.message}`,
      };
    }
    if (stepped.value.presignSessionId !== input.presignSessionId) {
      return {
        ok: false,
        code: 'internal',
        message: 'SigningWorker ECDSA presign response session mismatch',
      };
    }
    if (stepped.value.kind === 'complete') {
      return {
        ok: true,
        stage: 'done',
        event: 'presign_done',
        outgoingMessagesB64u: [],
        presignatureId: stepped.value.serverPresignatureId,
        bigRB64u: stepped.value.serverBigR33B64u,
      };
    }
    return {
      ok: true,
      stage: stepped.value.stage,
      event: stepped.value.event,
      outgoingMessagesB64u: stepped.value.outgoingMessagesB64u,
    };
  }

  async routerAbEcdsaDerivationPresignaturePoolFillInit(input: {
    binding: RouterAbEcdsaDerivationPoolFillBinding;
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

    const binding = input.binding;
    const walletId = toOptionalTrimmedString(binding?.walletId);
    if (!walletId)
      return {
        ok: false,
        code: WALLET_SESSION_FAILURE_CODES.invalid,
        message: 'Missing walletId in exact Wallet Session binding',
      };
    const tokenRelayerKeyId = toOptionalTrimmedString(binding?.relayerKeyId);
    let tokenKeyHandle: EcdsaKeyHandle;
    try {
      tokenKeyHandle = parseEcdsaKeyHandle(binding?.keyHandle);
    } catch {
      return {
        ok: false,
        code: WALLET_SESSION_FAILURE_CODES.invalid,
        message: 'Invalid exact Wallet Session binding',
      };
    }
    if (!tokenRelayerKeyId) {
      return {
        ok: false,
        code: WALLET_SESSION_FAILURE_CODES.invalid,
        message: 'Invalid exact Wallet Session binding',
      };
    }
    const tokenSigningRoot = signingRootMetadataFromRuntimePolicyScope(binding.runtimePolicyScope);
    if (!tokenSigningRoot) {
      return {
        ok: false,
        code: WALLET_SESSION_FAILURE_CODES.invalid,
        message: 'Exact Wallet Session binding is missing signing-root scope',
      };
    }
    return this.startStrictPresignSession({
      binding,
      keySelector,
      poolFill,
      walletId,
      keyHandle: tokenKeyHandle,
      relayerKeyId: tokenRelayerKeyId,
      signingRoot: tokenSigningRoot,
    });
  }

  async routerAbEcdsaDerivationPresignaturePoolFillStep(input: {
    readonly binding: RouterAbEcdsaDerivationPoolFillBinding;
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
    const binding = input.binding;
    const expiresAtMs = presignSessionExpiresAtMs(presignSessionId);
    const walletId = toOptionalTrimmedString(binding.walletId);
    try {
      parseEcdsaKeyHandle(binding.keyHandle);
    } catch {
      return {
        ok: false,
        code: WALLET_SESSION_FAILURE_CODES.invalid,
        message: 'Invalid exact Wallet Session binding',
      };
    }
    const relayerKeyId = toOptionalTrimmedString(binding.relayerKeyId);
    const participantIds = normalizeThresholdEd25519ParticipantIds(binding.participantIds);
    const scope = binding.routerAbEcdsaDerivationNormalSigning.scope;
    if (!walletId || !relayerKeyId || !participantIds || !expiresAtMs) {
      return {
        ok: false,
        code: WALLET_SESSION_FAILURE_CODES.invalid,
        message: 'Invalid exact Wallet Session binding',
      };
    }
    if (
      scope.wallet_id !== walletId ||
      !sameParticipantIds(participantIds, this.participantIds2p)
    ) {
      return {
        ok: false,
        code: WALLET_SESSION_FAILURE_CODES.scopeMismatch,
        message: 'Wallet Session normal-signing scope does not match presign binding',
      };
    }
    if (Date.now() > expiresAtMs || expiresAtMs > binding.thresholdExpiresAtMs) {
      return {
        ok: false,
        code: WALLET_SESSION_FAILURE_CODES.expired,
        message: 'Wallet Session expired',
      };
    }
    return await this.stepStrictPresignSession({
      binding: { ...binding, thresholdExpiresAtMs: expiresAtMs },
      presignSessionId,
      requestedStage,
      outgoingMessagesB64u,
    });
  }
}
