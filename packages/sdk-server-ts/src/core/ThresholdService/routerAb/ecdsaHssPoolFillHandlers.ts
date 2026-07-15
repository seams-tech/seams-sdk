import type { NormalizedLogger } from '../../logger';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { parseEvmFamilySigningKeySlotIdOrNull } from '@shared/signing-lanes';
import {
  ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_INIT_PATH,
  ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_STEP_PATH,
  parseRouterAbEcdsaHssNormalSigningScopeV1,
  type RouterAbEcdsaHssNormalSigningScopeV1,
} from '@shared/utils/routerAbEcdsaHss';
import type {
  EcdsaHssRoleLocalKeyRecord,
  ThresholdEcdsaSigningRootMetadata,
  RouterAbEcdsaHssPoolFillInitRequest,
  RouterAbEcdsaHssPoolFillInitResponse,
  RouterAbEcdsaHssPoolFillStepRequest,
  RouterAbEcdsaHssPoolFillStepResponse,
} from '../../types';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  signingRootScopeFromRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import type { ThresholdCoordinatorPeer, ThresholdNodeRole } from '../config';
import type {
  RouterAbEcdsaHssPoolFillSessionRecord,
  RouterAbEcdsaHssPoolFillSessionDestination,
  RouterAbEcdsaHssPoolFillSessionStore,
  RouterAbEcdsaHssServerPresignatureShareRecord,
  RouterAbEcdsaHssPresignaturePool,
} from '../stores/EcdsaSigningStore';
import {
  buildRouterAbEcdsaHssPresignaturePoolPutRequest,
  putRouterAbEcdsaHssPresignaturePoolFill,
  type RouterAbEcdsaHssPresignaturePoolFillAuth,
} from './ecdsaHssPresignBridge';
import type { ThresholdEcdsaSessionClaims } from '../validation';
import { ensureEthSignerWasm, validateSecp256k1PublicKey33 } from '../ethSignerWasm';
import {
  InMemoryRouterAbEcdsaHssPoolFillLiveSessionOwner,
  type RouterAbEcdsaHssPoolFillLiveSessionOwner,
  type RouterAbEcdsaHssPresignatureMaterial,
} from './ecdsaHssPoolFillLiveSession';
import {
  formatEcdsaHssKeyVersionForWire,
  formatEcdsaKeyHandleForWire,
  formatEcdsaRelayerKeyIdForWire,
  formatEcdsaThresholdKeyIdForWire,
  parseEcdsaClientVerifyingShareB64u,
  parseEcdsaHssKeyVersion,
  parseEcdsaKeyHandle,
  parseEcdsaRelayerKeyId,
  parseEcdsaThresholdKeyId,
  type EcdsaClientVerifyingShareB64u,
  type EcdsaKeyHandle,
  type EcdsaRelayerKeyId,
  type EcdsaThresholdKeyId,
} from '../../keyMaterialBrands';

const THRESHOLD_ECDSA_HSS_ROLE_LOCAL_WALLET_KEY_VERSION = parseEcdsaHssKeyVersion('v1');
const THRESHOLD_ECDSA_HSS_ROLE_LOCAL_DERIVATION_VERSION = 1;

type ThresholdEcdsaMpcSessionRecord = {
  expiresAtMs: number;
  ecdsaThresholdKeyId?: string;
  keyHandle?: string;
  relayerKeyId: string;
  purpose: string;
  intentDigestB64u: string;
  signingDigestB64u: string;
  walletId: string;
  evmFamilySigningKeySlotId: string;
  clientVerifyingShareB64u?: string;
  participantIds: number[];
} & Partial<ThresholdEcdsaSigningRootMetadata>;

type ThresholdEcdsaReadMpcSessionResult = {
  record: ThresholdEcdsaMpcSessionRecord;
  version: string;
};

type ThresholdEcdsaClaimMpcSessionResult =
  | { ok: true; record: ThresholdEcdsaMpcSessionRecord }
  | { ok: false; code: 'not_found' | 'expired' | 'version_mismatch' | 'invalid_record' };

type ParseOk<T> = { ok: true; value: T };
type ParseErr = { ok: false; code: string; message: string };
type ParseResult<T> = ParseOk<T> | ParseErr;

type RouterAbEcdsaHssPoolFillInitClaims = Pick<
  ThresholdEcdsaSessionClaims,
  | 'walletId'
  | 'evmFamilySigningKeySlotId'
  | 'relayerKeyId'
  | 'keyHandle'
  | 'runtimePolicyScope'
  | 'participantIds'
  | 'thresholdExpiresAtMs'
>;

type RouterAbEcdsaHssPoolFillStepClaims = Pick<
  ThresholdEcdsaSessionClaims,
  | 'walletId'
  | 'evmFamilySigningKeySlotId'
  | 'relayerKeyId'
  | 'participantIds'
  | 'thresholdExpiresAtMs'
>;

const ROUTER_AB_ECDSA_HSS_POOL_FILL_FORWARD_HOP_HEADER =
  'x-router-ab-ecdsa-hss-pool-fill-forward-hop';

function parseEvmFamilySigningKeySlotString(value: unknown): string | null {
  const parsed = parseEvmFamilySigningKeySlotIdOrNull(value);
  return parsed ? String(parsed) : null;
}
const ROUTER_AB_ECDSA_HSS_POOL_FILL_FORWARDED_BY_HEADER =
  'x-router-ab-ecdsa-hss-pool-fill-forwarded-by';
const ECDSA_PRESIGN_POOL_KEY_VERSION = 'v2';

function signingRootMetadataFromRoleLocalKey(
  record: EcdsaHssRoleLocalKeyRecord,
): ThresholdEcdsaSigningRootMetadata {
  return {
    signingRootId: record.signingRootId,
    signingRootVersion: record.signingRootVersion,
    walletKeyVersion: formatEcdsaHssKeyVersionForWire(
      THRESHOLD_ECDSA_HSS_ROLE_LOCAL_WALLET_KEY_VERSION,
    ),
    derivationVersion: THRESHOLD_ECDSA_HSS_ROLE_LOCAL_DERIVATION_VERSION,
  };
}

function presignPoolKeyPart(value: unknown, fieldName: string): string {
  const normalized =
    typeof value === 'number' && Number.isFinite(value)
      ? String(value)
      : toOptionalTrimmedString(value);
  if (!normalized) throw new Error(`${fieldName} is required for Router A/B ECDSA-HSS pool key`);
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

function isEthSignerWasmRuntimeError(messageRaw: string): boolean {
  const message = String(messageRaw || '').toLowerCase();
  return (
    message.includes('eth_signer wasm') ||
    message.includes('initialize eth_signer wasm') ||
    message.includes('not initialized')
  );
}

type ThresholdEcdsaRoleLocalKeyRecordSelector = {
  kind: 'key_handle';
  keyHandle: string;
  ecdsaThresholdKeyId?: never;
};

type ThresholdEcdsaRelayerSigningShare = {
  kind: 'cait_sith_mapped';
  share32B64u: string;
};

type ThresholdEcdsaSigningKeyMaterial = {
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  keyHandle: EcdsaKeyHandle;
  relayerKeyId: EcdsaRelayerKeyId;
  contextBinding32B64u: string;
  clientVerifyingShareB64u: EcdsaClientVerifyingShareB64u;
  relayerPublicKey33B64u: string;
  thresholdEcdsaPublicKeyB64u: string;
  signingRootMetadata: ThresholdEcdsaSigningRootMetadata;
  relayerSigningShare: ThresholdEcdsaRelayerSigningShare;
  presignPoolKey: string;
};

type RouterAbEcdsaHssSigningWorkerPoolFillDestination = Extract<
  RouterAbEcdsaHssPoolFillSessionDestination,
  { kind: 'router_ab_ecdsa_hss_signing_worker_pool' }
>;

function assertNever(value: never): never {
  throw new Error(`Unexpected threshold-ecdsa branch: ${String(value)}`);
}

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

function parseRouterAbEcdsaHssPoolFillRequest(
  value: unknown,
): ParseResult<RouterAbEcdsaHssSigningWorkerPoolFillDestination> {
  if (value === undefined) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'poolFill is required for Router A/B ECDSA-HSS presign refill',
    };
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { ok: false, code: 'invalid_body', message: 'poolFill must be an object' };
  }

  const record = value as Record<string, unknown>;
  const kind = toOptionalTrimmedString(record.kind);
  if (kind !== 'router_ab_ecdsa_hss_signing_worker_pool') {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'poolFill.kind must be router_ab_ecdsa_hss_signing_worker_pool',
    };
  }
  const exactKeys = requireExactPoolFillKeys(record, ['kind', 'scope', 'expiresAtMs']);
  if (!exactKeys.ok) return exactKeys;

  let scope: RouterAbEcdsaHssNormalSigningScopeV1;
  try {
    scope = parseRouterAbEcdsaHssNormalSigningScopeV1(record.scope);
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
      routerAbEcdsaHss: {
        scope,
        expiresAtMs: expiresAtMsInt,
      },
    },
  };
}

function parseRouterAbEcdsaHssPoolFillInitRequest(
  request: RouterAbEcdsaHssPoolFillInitRequest,
): ParseResult<{
  keySelector: ThresholdEcdsaRoleLocalKeyRecordSelector;
  count: number;
  poolFill: RouterAbEcdsaHssSigningWorkerPoolFillDestination;
}> {
  const keyHandle = toOptionalTrimmedString((request as { keyHandle?: unknown }).keyHandle);
  const ecdsaThresholdKeyId = toOptionalTrimmedString(request.ecdsaThresholdKeyId);
  if (ecdsaThresholdKeyId) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'keyHandle is required for Router A/B ECDSA-HSS pool-fill init',
    };
  }
  if (!keyHandle) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'keyHandle is required for Router A/B ECDSA-HSS pool-fill init',
    };
  }
  const countRaw = (request as { count?: unknown }).count;
  const count = Math.max(1, Math.floor(Number(countRaw ?? 1)));
  if (count !== 1) {
    return {
      ok: false,
      code: 'unsupported',
      message: 'Router A/B ECDSA-HSS pool-fill init supports only count=1',
    };
  }
  const poolFill = parseRouterAbEcdsaHssPoolFillRequest(
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

function validateRouterAbEcdsaHssPresignPoolFill(input: {
  poolFill: RouterAbEcdsaHssSigningWorkerPoolFillDestination;
  walletId: string;
  evmFamilySigningKeySlotId: string;
  keyMaterial: ThresholdEcdsaSigningKeyMaterial;
  sessionExpiresAtMs: number;
}): ParseResult<RouterAbEcdsaHssSigningWorkerPoolFillDestination> {
  const routerAb = input.poolFill.routerAbEcdsaHss;
  if (routerAb.expiresAtMs > input.sessionExpiresAtMs) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'poolFill.expiresAtMs must not exceed the Wallet Session expiry',
    };
  }

  const scope = routerAb.scope;
  const publicIdentity = scope.public_identity;
  const expected = input.keyMaterial;
  const signingRootVersion = expected.signingRootMetadata.signingRootVersion || 'default';
  const contextChecks: Array<[string, string, string]> = [
    ['poolFill.scope.wallet_key_id', scope.wallet_key_id, input.evmFamilySigningKeySlotId],
    ['poolFill.scope.wallet_id', scope.wallet_id, input.walletId],
    [
      'poolFill.scope.ecdsa_threshold_key_id',
      scope.ecdsa_threshold_key_id,
      expected.ecdsaThresholdKeyId,
    ],
    [
      'poolFill.scope.signing_root_id',
      scope.signing_root_id,
      expected.signingRootMetadata.signingRootId,
    ],
    ['poolFill.scope.signing_root_version', scope.signing_root_version, signingRootVersion],
  ];
  for (const [field, actual, expectedValue] of contextChecks) {
    if (actual !== expectedValue) {
      return {
        ok: false,
        code: 'unauthorized',
        message: `${field} does not match Router A/B ECDSA-HSS pool-fill scope`,
      };
    }
  }

  const identityChecks: Array<[string, string, string]> = [
    [
      'poolFill.scope.public_identity.context_binding_b64u',
      publicIdentity.context_binding_b64u,
      expected.contextBinding32B64u,
    ],
    [
      'poolFill.scope.public_identity.client_public_key33_b64u',
      publicIdentity.client_public_key33_b64u,
      expected.clientVerifyingShareB64u,
    ],
    [
      'poolFill.scope.public_identity.server_public_key33_b64u',
      publicIdentity.server_public_key33_b64u,
      expected.relayerPublicKey33B64u,
    ],
    [
      'poolFill.scope.public_identity.threshold_public_key33_b64u',
      publicIdentity.threshold_public_key33_b64u,
      expected.thresholdEcdsaPublicKeyB64u,
    ],
  ];
  for (const [field, actual, expectedValue] of identityChecks) {
    if (actual !== expectedValue) {
      return {
        ok: false,
        code: 'unauthorized',
        message: `${field} does not match threshold ECDSA key material`,
      };
    }
  }

  return { ok: true, value: input.poolFill };
}

function parseRouterAbEcdsaHssPoolFillStepRequest(
  request: RouterAbEcdsaHssPoolFillStepRequest,
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

type RouterAbEcdsaHssPoolFillStepTransport = {
  authorizationHeader?: string;
  cookieHeader?: string;
  forwardedHop?: number;
  forwardedByInstanceId?: string;
};

type RouterAbEcdsaHssPoolFillTarget =
  | {
      kind: 'disabled';
      signingWorkerBaseUrl?: never;
      auth?: never;
      fetchImpl?: never;
    }
  | {
      kind: 'strict_private_http';
      signingWorkerBaseUrl: string;
      auth: RouterAbEcdsaHssPresignaturePoolFillAuth;
      fetchImpl?: typeof fetch;
    };

function poolFillGlobalFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  return globalThis.fetch(input, init);
}

function resolvePoolFillFetchImpl(): typeof fetch | null {
  return typeof globalThis.fetch === 'function' ? poolFillGlobalFetch : null;
}

export class RouterAbEcdsaHssPoolFillHandlers {
  private readonly logger: NormalizedLogger;
  private readonly nodeRole: ThresholdNodeRole;
  private readonly participantIds2p: number[];
  private readonly clientParticipantId: number;
  private readonly relayerParticipantId: number;
  private readonly sessionStore: {
    readMpcSession(id: string): Promise<ThresholdEcdsaReadMpcSessionResult | null>;
    claimMpcSession(id: string, version: string): Promise<ThresholdEcdsaClaimMpcSessionResult>;
  };
  private readonly poolFillSessionStore: RouterAbEcdsaHssPoolFillSessionStore;
  private readonly presignaturePool: RouterAbEcdsaHssPresignaturePool;
  private readonly resolveRoleLocalKeyRecord: (
    args: ThresholdEcdsaRoleLocalKeyRecordSelector,
  ) => Promise<EcdsaHssRoleLocalKeyRecord | null>;
  private readonly ensureReady: () => Promise<void>;
  private readonly createPoolFillSessionId: () => string;
  private readonly coordinatorInstanceId: string | null;
  private readonly coordinatorPeerUrlByInstanceId: Map<string, string>;
  private readonly maxPresignForwardHops: number;
  private readonly routerAbEcdsaHssPoolFillTarget: RouterAbEcdsaHssPoolFillTarget;
  private readonly liveSessionOwner: RouterAbEcdsaHssPoolFillLiveSessionOwner;

  constructor(input: {
    logger: NormalizedLogger;
    nodeRole: ThresholdNodeRole;
    participantIds2p: number[];
    clientParticipantId: number;
    relayerParticipantId: number;
    coordinatorInstanceId?: string | null;
    coordinatorPeers?: ThresholdCoordinatorPeer[];
    sessionStore: {
      readMpcSession(id: string): Promise<ThresholdEcdsaReadMpcSessionResult | null>;
      claimMpcSession(id: string, version: string): Promise<ThresholdEcdsaClaimMpcSessionResult>;
    };
    poolFillSessionStore: RouterAbEcdsaHssPoolFillSessionStore;
    presignaturePool: RouterAbEcdsaHssPresignaturePool;
    resolveRoleLocalKeyRecord: (
      args: ThresholdEcdsaRoleLocalKeyRecordSelector,
    ) => Promise<EcdsaHssRoleLocalKeyRecord | null>;
    ensureReady: () => Promise<void>;
    createPoolFillSessionId: () => string;
    maxPresignForwardHops?: number;
    liveSessionOwner?: RouterAbEcdsaHssPoolFillLiveSessionOwner;
    routerAbEcdsaHssPoolFill?: {
      signingWorkerBaseUrl: string;
      auth: RouterAbEcdsaHssPresignaturePoolFillAuth;
      fetchImpl?: typeof fetch;
    } | null;
  }) {
    this.logger = input.logger;
    this.nodeRole = input.nodeRole;
    this.participantIds2p = input.participantIds2p;
    this.clientParticipantId = input.clientParticipantId;
    this.relayerParticipantId = input.relayerParticipantId;
    this.coordinatorInstanceId = toOptionalTrimmedString(input.coordinatorInstanceId);
    this.coordinatorPeerUrlByInstanceId = new Map<string, string>();
    for (const peer of input.coordinatorPeers || []) {
      const instanceId = toOptionalTrimmedString(peer?.instanceId);
      const relayerUrl = toOptionalTrimmedString(peer?.relayerUrl)?.replace(/\/+$/, '');
      if (!instanceId || !relayerUrl) continue;
      if (this.coordinatorInstanceId && instanceId === this.coordinatorInstanceId) continue;
      if (!this.coordinatorPeerUrlByInstanceId.has(instanceId)) {
        this.coordinatorPeerUrlByInstanceId.set(instanceId, relayerUrl);
      }
    }
    const maxPresignForwardHops = Math.floor(Number(input.maxPresignForwardHops ?? 1));
    this.maxPresignForwardHops =
      Number.isFinite(maxPresignForwardHops) && maxPresignForwardHops >= 0
        ? maxPresignForwardHops
        : 1;
    this.sessionStore = input.sessionStore;
    this.poolFillSessionStore = input.poolFillSessionStore;
    this.presignaturePool = input.presignaturePool;
    this.resolveRoleLocalKeyRecord = input.resolveRoleLocalKeyRecord;
    this.ensureReady = input.ensureReady;
    this.createPoolFillSessionId = input.createPoolFillSessionId;
    this.liveSessionOwner =
      input.liveSessionOwner || new InMemoryRouterAbEcdsaHssPoolFillLiveSessionOwner();
    const routerAbPoolFill = input.routerAbEcdsaHssPoolFill || null;
    if (routerAbPoolFill) {
      const signingWorkerBaseUrl = toOptionalTrimmedString(routerAbPoolFill.signingWorkerBaseUrl);
      this.routerAbEcdsaHssPoolFillTarget =
        signingWorkerBaseUrl && (routerAbPoolFill.fetchImpl || resolvePoolFillFetchImpl())
          ? {
              kind: 'strict_private_http',
              signingWorkerBaseUrl,
              auth: routerAbPoolFill.auth,
              ...(routerAbPoolFill.fetchImpl ? { fetchImpl: routerAbPoolFill.fetchImpl } : {}),
            }
          : { kind: 'disabled' };
    } else {
      this.routerAbEcdsaHssPoolFillTarget = { kind: 'disabled' };
    }
  }

  private async resolvePoolFillInitKeyMaterial(input: {
    keySelector: ThresholdEcdsaRoleLocalKeyRecordSelector;
    walletId: string;
    evmFamilySigningKeySlotId: string;
    participantIds: number[];
    tokenRelayerKeyId: string;
    tokenKeyHandle: string;
    tokenSigningRoot: Pick<
      ThresholdEcdsaSigningRootMetadata,
      'signingRootId' | 'signingRootVersion'
    >;
  }): Promise<ParseResult<ThresholdEcdsaSigningKeyMaterial>> {
    const roleLocalKey = await this.resolveRoleLocalKeyRecord(input.keySelector);
    if (!roleLocalKey) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'ECDSA key selector is not active on this server',
      };
    }
    const ecdsaThresholdKeyIdRaw = toOptionalTrimmedString(roleLocalKey.ecdsaThresholdKeyId);
    const keyHandleRaw = toOptionalTrimmedString(roleLocalKey.keyHandle);
    const tokenKeyHandle = toOptionalTrimmedString(input.tokenKeyHandle);
    if (
      !ecdsaThresholdKeyIdRaw ||
      !keyHandleRaw ||
      !tokenKeyHandle ||
      tokenKeyHandle !== keyHandleRaw
    ) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'keyHandle does not match Wallet Session scope',
      };
    }
    if (
      roleLocalKey.walletId !== input.walletId ||
      roleLocalKey.evmFamilySigningKeySlotId !== input.evmFamilySigningKeySlotId
    ) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'ecdsaThresholdKeyId does not match Wallet Session scope',
      };
    }
    if (!sameParticipantIds(this.participantIds2p, input.participantIds)) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'ecdsaThresholdKeyId participantIds do not match Wallet Session scope',
      };
    }
    const signingRootMetadata = signingRootMetadataFromRoleLocalKey(roleLocalKey);
    if (
      signingRootMetadata.signingRootId !== input.tokenSigningRoot.signingRootId ||
      signingRootMetadata.signingRootVersion !== input.tokenSigningRoot.signingRootVersion
    ) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'ecdsaThresholdKeyId signing root does not match Wallet Session scope',
      };
    }
    if (roleLocalKey.relayerKeyId !== input.tokenRelayerKeyId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'ecdsaThresholdKeyId does not match Wallet Session relayer scope',
      };
    }
    const ecdsaThresholdKeyId = parseEcdsaThresholdKeyId(ecdsaThresholdKeyIdRaw);
    const keyHandle = parseEcdsaKeyHandle(keyHandleRaw);
    const relayerKeyId = parseEcdsaRelayerKeyId(roleLocalKey.relayerKeyId);
    const clientVerifyingShareB64u = parseEcdsaClientVerifyingShareB64u(
      roleLocalKey.clientPublicKey33B64u,
    );
    return {
      ok: true,
      value: {
        ecdsaThresholdKeyId,
        keyHandle,
        relayerKeyId,
        contextBinding32B64u: roleLocalKey.contextBinding32B64u,
        clientVerifyingShareB64u,
        relayerPublicKey33B64u: roleLocalKey.relayerPublicKey33B64u,
        thresholdEcdsaPublicKeyB64u: roleLocalKey.groupPublicKey33B64u,
        signingRootMetadata,
        relayerSigningShare: {
          kind: 'cait_sith_mapped',
          share32B64u: roleLocalKey.relayerCaitSithInput.mappedPrivateShare32B64u,
        },
        presignPoolKey: ecdsaPresignPoolKey({
          ecdsaThresholdKeyId,
          keyHandle,
          relayerKeyId,
          thresholdEcdsaPublicKeyB64u: roleLocalKey.groupPublicKey33B64u,
          signingRootMetadata,
        }),
      },
    };
  }

  private async deleteLivePresignSession(presignSessionId: string): Promise<void> {
    await this.liveSessionOwner.deleteSession(presignSessionId);
  }

  private emitPresignSecurityEvent(input: {
    event: string;
    presignSessionId: string;
    record?: RouterAbEcdsaHssPoolFillSessionRecord | null;
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

  private async publishCompletedPresignature(input: {
    record: RouterAbEcdsaHssPoolFillSessionRecord;
    presignature: RouterAbEcdsaHssPresignatureMaterial;
  }): Promise<ParseResult<null>> {
    const shareRecord: RouterAbEcdsaHssServerPresignatureShareRecord = {
      relayerKeyId: input.record.presignPoolKey,
      presignatureId: input.presignature.presignatureId,
      bigRB64u: input.presignature.bigRB64u,
      kShareB64u: input.presignature.kShareB64u,
      sigmaShareB64u: input.presignature.sigmaShareB64u,
      createdAtMs: Date.now(),
    };

    switch (input.record.poolFill.kind) {
      case 'local_threshold_ecdsa_presignature_pool':
        await this.presignaturePool.put(shareRecord);
        return { ok: true, value: null };
      case 'router_ab_ecdsa_hss_signing_worker_pool': {
        const target = this.routerAbEcdsaHssPoolFillTarget;
        if (target.kind !== 'strict_private_http') {
          return {
            ok: false,
            code: 'internal',
            message: 'Router A/B ECDSA-HSS presignature pool-fill target is not configured',
          };
        }
        const fetchImpl = target.fetchImpl || resolvePoolFillFetchImpl();
        if (!fetchImpl) {
          return {
            ok: false,
            code: 'internal',
            message: 'Router A/B ECDSA-HSS presignature pool-fill target fetch is unavailable',
          };
        }
        const request = buildRouterAbEcdsaHssPresignaturePoolPutRequest({
          scope: input.record.poolFill.routerAbEcdsaHss.scope,
          presignature: {
            serverKeyId: shareRecord.relayerKeyId,
            presignatureId: shareRecord.presignatureId,
            bigRB64u: shareRecord.bigRB64u,
            kShareB64u: shareRecord.kShareB64u,
            sigmaShareB64u: shareRecord.sigmaShareB64u,
            createdAtMs: shareRecord.createdAtMs,
          },
          expiresAtMs: input.record.poolFill.routerAbEcdsaHss.expiresAtMs,
        });
        const result = await putRouterAbEcdsaHssPresignaturePoolFill({
          signingWorkerBaseUrl: target.signingWorkerBaseUrl,
          request,
          auth: target.auth,
          fetchImpl,
        });
        if (result.ok) return { ok: true, value: null };
        return {
          ok: false,
          code: result.code,
          message: result.message,
        };
      }
      default:
        return assertNever(input.record.poolFill);
    }
  }

  private isPresignSessionOwnedLocally(record: RouterAbEcdsaHssPoolFillSessionRecord): boolean {
    const ownerInstanceId = toOptionalTrimmedString(record.ownerInstanceId);
    if (!ownerInstanceId) return true;
    if (!this.coordinatorInstanceId) return false;
    return ownerInstanceId === this.coordinatorInstanceId;
  }

  private resolvePresignSessionOwnerPeerUrl(
    record: RouterAbEcdsaHssPoolFillSessionRecord,
  ): string | null {
    const ownerInstanceId = toOptionalTrimmedString(record.ownerInstanceId);
    if (!ownerInstanceId) return null;
    if (this.coordinatorInstanceId && ownerInstanceId === this.coordinatorInstanceId) return null;
    return this.coordinatorPeerUrlByInstanceId.get(ownerInstanceId) || null;
  }

  private async forwardPoolFillStepToOwner(input: {
    ownerInstanceId: string;
    ownerRelayerUrl: string;
    request: RouterAbEcdsaHssPoolFillStepRequest;
    authorizationHeader?: string;
    cookieHeader?: string;
    forwardedHop: number;
    presignSessionId: string;
  }): Promise<RouterAbEcdsaHssPoolFillStepResponse | null> {
    if (typeof fetch !== 'function') {
      this.logger.warn('[router-ab-ecdsa-hss-pool-fill] owner-forward skipped: fetch unavailable', {
        presignSessionId: input.presignSessionId,
        ownerInstanceId: input.ownerInstanceId,
      });
      return null;
    }

    const headers: Record<string, string> = {
      'content-type': 'application/json',
      [ROUTER_AB_ECDSA_HSS_POOL_FILL_FORWARD_HOP_HEADER]: String(input.forwardedHop + 1),
    };
    if (this.coordinatorInstanceId)
      headers[ROUTER_AB_ECDSA_HSS_POOL_FILL_FORWARDED_BY_HEADER] = this.coordinatorInstanceId;
    const authorizationHeader = toOptionalTrimmedString(input.authorizationHeader);
    if (authorizationHeader) headers.authorization = authorizationHeader;
    const cookieHeader = toOptionalTrimmedString(input.cookieHeader);
    if (cookieHeader) headers.cookie = cookieHeader;

    let response: Response;
    try {
      response = await fetch(
        `${input.ownerRelayerUrl}${ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_STEP_PATH}`,
        {
          method: 'POST',
          headers,
          body: JSON.stringify(input.request),
        },
      );
    } catch (error: unknown) {
      this.logger.warn('[router-ab-ecdsa-hss-pool-fill] owner-forward request failed', {
        presignSessionId: input.presignSessionId,
        ownerInstanceId: input.ownerInstanceId,
        ownerRelayerUrl: input.ownerRelayerUrl,
        error: errorMessage(error),
      });
      return null;
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch {
      this.logger.warn('[router-ab-ecdsa-hss-pool-fill] owner-forward response decode failed', {
        presignSessionId: input.presignSessionId,
        ownerInstanceId: input.ownerInstanceId,
        ownerRelayerUrl: input.ownerRelayerUrl,
        status: response.status,
      });
      return null;
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      this.logger.warn('[router-ab-ecdsa-hss-pool-fill] owner-forward response shape invalid', {
        presignSessionId: input.presignSessionId,
        ownerInstanceId: input.ownerInstanceId,
        ownerRelayerUrl: input.ownerRelayerUrl,
        status: response.status,
      });
      return null;
    }

    return body as RouterAbEcdsaHssPoolFillStepResponse;
  }

  async routerAbEcdsaHssPresignaturePoolFillInit(input: {
    claims: RouterAbEcdsaHssPoolFillInitClaims;
    request: RouterAbEcdsaHssPoolFillInitRequest;
  }): Promise<RouterAbEcdsaHssPoolFillInitResponse> {
    if (this.nodeRole !== 'coordinator') {
      return {
        ok: false,
        code: 'not_found',
        message:
          'Router A/B ECDSA-HSS pool-fill endpoints are not enabled on this server (set THRESHOLD_NODE_ROLE=coordinator)',
      };
    }

    await this.ensureReady();
    await ensureEthSignerWasm();

    const parsedRequest = parseRouterAbEcdsaHssPoolFillInitRequest(input.request);
    if (!parsedRequest.ok) return parsedRequest;
    const { keySelector, poolFill } = parsedRequest.value;

    const claims = input.claims;
    const walletId = toOptionalTrimmedString(claims?.walletId);
    if (!walletId)
      return {
        ok: false,
        code: 'unauthorized',
        message: 'Missing walletId in Wallet Session token',
      };
    const tokenRelayerKeyId = toOptionalTrimmedString(claims?.relayerKeyId);
    const tokenWalletKeyId = parseEvmFamilySigningKeySlotString(claims?.evmFamilySigningKeySlotId);
    if (!tokenRelayerKeyId || !tokenWalletKeyId) {
      return { ok: false, code: 'unauthorized', message: 'Invalid Wallet Session token claims' };
    }
    const tokenSigningRoot = signingRootMetadataFromRuntimePolicyScope(claims.runtimePolicyScope);
    if (!tokenSigningRoot) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'Wallet Session token is missing signing-root scope',
      };
    }
    const resolvedKeyMaterial = await this.resolvePoolFillInitKeyMaterial({
      keySelector,
      walletId,
      evmFamilySigningKeySlotId: tokenWalletKeyId,
      participantIds: claims.participantIds,
      tokenRelayerKeyId,
      tokenKeyHandle: claims.keyHandle,
      tokenSigningRoot,
    });
    if (!resolvedKeyMaterial.ok) return resolvedKeyMaterial;
    const {
      relayerKeyId,
      clientVerifyingShareB64u,
      thresholdEcdsaPublicKeyB64u,
      relayerSigningShare,
      signingRootMetadata,
      presignPoolKey,
    } = resolvedKeyMaterial.value;

    if (relayerKeyId !== tokenRelayerKeyId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'relayerKeyId does not match Wallet Session scope',
      };
    }
    if (Date.now() > claims.thresholdExpiresAtMs) {
      return { ok: false, code: 'unauthorized', message: 'Wallet Session expired' };
    }

    if (this.clientParticipantId !== 1 || this.relayerParticipantId !== 2) {
      return {
        ok: false,
        code: 'unsupported',
        message: 'Router A/B ECDSA-HSS pool-fill requires participantIds={client=1,relayer=2}',
      };
    }

    let clientVerifyingShareBytes: Uint8Array;
    try {
      clientVerifyingShareBytes = base64UrlDecode(clientVerifyingShareB64u);
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'clientVerifyingShareB64u must be valid base64url',
      };
    }
    if (clientVerifyingShareBytes.length !== 33) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'clientVerifyingShareB64u must decode to 33 bytes (compressed secp256k1 pubkey)',
      };
    }
    let validatedClientPublicKey33: Uint8Array;
    try {
      validatedClientPublicKey33 = await validateSecp256k1PublicKey33(clientVerifyingShareBytes);
    } catch (e: unknown) {
      const runtimeMessage = errorMessage(e);
      if (isEthSignerWasmRuntimeError(runtimeMessage)) {
        return {
          ok: false,
          code: 'internal',
          message: runtimeMessage || 'eth_signer WASM runtime error',
        };
      }
      return {
        ok: false,
        code: 'invalid_body',
        message: 'clientVerifyingShareB64u is not a valid secp256k1 public key',
      };
    }

    let relayerSigningShare32: Uint8Array;
    try {
      relayerSigningShare32 = base64UrlDecode(relayerSigningShare.share32B64u);
    } catch {
      return {
        ok: false,
        code: 'internal',
        message: 'Persisted relayer signing share is not valid base64url',
      };
    }
    if (relayerSigningShare32.length !== 32) {
      return {
        ok: false,
        code: 'internal',
        message: 'Persisted relayer signing share must decode to 32 bytes',
      };
    }
    let groupPublicKeyBytes: Uint8Array;
    try {
      groupPublicKeyBytes = await validateSecp256k1PublicKey33(
        base64UrlDecode(thresholdEcdsaPublicKeyB64u),
      );
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: `Persisted thresholdEcdsaPublicKeyB64u is invalid: ${String(e || 'error')}`,
      };
    }
    const relayerThresholdShare32 = relayerSigningShare32;

    const participantIds = normalizeThresholdEd25519ParticipantIds(claims.participantIds) || [
      ...this.participantIds2p,
    ];

    const nowMs = Date.now();
    const ttlMs = Math.max(0, Math.min(5 * 60_000, claims.thresholdExpiresAtMs - nowMs));
    if (ttlMs <= 0) {
      return { ok: false, code: 'unauthorized', message: 'Wallet Session expired' };
    }
    const expiresAtMs = nowMs + ttlMs;
    const sessionPoolFill = validateRouterAbEcdsaHssPresignPoolFill({
      poolFill,
      walletId,
      evmFamilySigningKeySlotId: tokenWalletKeyId,
      keyMaterial: resolvedKeyMaterial.value,
      sessionExpiresAtMs: expiresAtMs,
    });
    if (!sessionPoolFill.ok) return sessionPoolFill;

    if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
      return {
        ok: false,
        code: 'unsupported',
        message: 'crypto.getRandomValues is unavailable in this runtime',
      };
    }

    for (let attempt = 0; attempt < 4; attempt += 1) {
      const presignSessionId = this.createPoolFillSessionId();
      const createdAtMs = Date.now();
      const initialRecord: RouterAbEcdsaHssPoolFillSessionRecord = {
        expiresAtMs,
        walletId,
        evmFamilySigningKeySlotId: tokenWalletKeyId,
        relayerKeyId,
        presignPoolKey,
        poolFill: sessionPoolFill.value,
        ...(this.coordinatorInstanceId ? { ownerInstanceId: this.coordinatorInstanceId } : {}),
        participantIds,
        clientParticipantId: this.clientParticipantId,
        relayerParticipantId: this.relayerParticipantId,
        stage: 'triples',
        version: 1,
        createdAtMs,
        updatedAtMs: createdAtMs,
        ...signingRootMetadata,
      };
      const liveCreated = await this.liveSessionOwner.createSession({
        presignSessionId,
        record: initialRecord,
        participantIds,
        relayerParticipantId: this.relayerParticipantId,
        relayerThresholdShare32B64u: relayerSigningShare.share32B64u,
        groupPublicKey33B64u: thresholdEcdsaPublicKeyB64u,
      });
      if (!liveCreated.ok) return liveCreated;

      const created = await this.poolFillSessionStore.createSession(
        presignSessionId,
        liveCreated.value.record,
        Math.max(1, expiresAtMs - Date.now()),
      );
      if (!created.ok) {
        await this.deleteLivePresignSession(presignSessionId);
        continue;
      }

      return {
        ok: true,
        presignSessionId,
        stage: liveCreated.value.stage,
        outgoingMessagesB64u: liveCreated.value.outgoingMessagesB64u,
      };
    }

    return { ok: false, code: 'internal', message: 'Failed to allocate presignSessionId; retry' };
  }

  async routerAbEcdsaHssPresignaturePoolFillStep(input: {
    claims: RouterAbEcdsaHssPoolFillStepClaims;
    request: RouterAbEcdsaHssPoolFillStepRequest;
    transport?: RouterAbEcdsaHssPoolFillStepTransport;
  }): Promise<RouterAbEcdsaHssPoolFillStepResponse> {
    if (this.nodeRole !== 'coordinator') {
      return {
        ok: false,
        code: 'not_found',
        message:
          'Router A/B ECDSA-HSS pool-fill endpoints are not enabled on this server (set THRESHOLD_NODE_ROLE=coordinator)',
      };
    }

    await this.ensureReady();

    const parsedRequest = parseRouterAbEcdsaHssPoolFillStepRequest(input.request);
    if (!parsedRequest.ok) return parsedRequest;
    const transport = input.transport || {};
    const authorizationHeader = toOptionalTrimmedString(transport.authorizationHeader);
    const cookieHeader = toOptionalTrimmedString(transport.cookieHeader);
    const forwardedByInstanceId = toOptionalTrimmedString(transport.forwardedByInstanceId);
    const forwardedByTrustedPeer = Boolean(
      forwardedByInstanceId && this.coordinatorPeerUrlByInstanceId.has(forwardedByInstanceId),
    );
    const forwardedHopRaw = Math.floor(Number(transport.forwardedHop ?? 0));
    const forwardedHop =
      Number.isFinite(forwardedHopRaw) && forwardedHopRaw >= 0 ? forwardedHopRaw : 0;
    const trustedForwardedHop = forwardedHop > 0 && forwardedByTrustedPeer ? forwardedHop : 0;
    if (forwardedHop > 0 && trustedForwardedHop === 0) {
      this.logger.warn('[router-ab-ecdsa-hss-pool-fill] ignoring untrusted forwarded hop', {
        requestedForwardedHop: forwardedHop,
        forwardedByInstanceId: forwardedByInstanceId || null,
        localInstanceId: this.coordinatorInstanceId,
      });
    }
    const { presignSessionId, stage: requestedStage, outgoingMessagesB64u } = parsedRequest.value;
    const stepStartedAtMs = Date.now();
    const perf: {
      presign_live_cache_hit: 0 | 1;
      presign_live_cache_miss: 0 | 1;
      presign_stale_session_state: 0 | 1;
      presign_owner_forwarded: 0 | 1;
      forwardedHopRequested: number;
      forwardedHopTrusted: number;
      forwardedByInstanceId?: string;
      forwardedByTrustedPeer: 0 | 1;
      ownerInstanceId?: string;
      ownerForwardReason?: string;
      storeGetSessionMs?: number;
      liveResolveMs?: number;
      liveCacheStatus?: 'hit' | 'miss';
      liveCacheMissReason?: string;
      wasmStepMs?: number;
      storeCasMs?: number;
      casCode?: string;
      resultCode?: string;
    } = {
      presign_live_cache_hit: 0,
      presign_live_cache_miss: 0,
      presign_stale_session_state: 0,
      presign_owner_forwarded: 0,
      forwardedHopRequested: forwardedHop,
      forwardedHopTrusted: trustedForwardedHop,
      ...(forwardedByInstanceId ? { forwardedByInstanceId } : {}),
      forwardedByTrustedPeer: forwardedByTrustedPeer ? 1 : 0,
    };
    try {
      const storeGetStartedAtMs = Date.now();
      const record = await this.poolFillSessionStore.getSession(presignSessionId);
      perf.storeGetSessionMs = Math.max(0, Date.now() - storeGetStartedAtMs);
      if (!record) {
        await this.deleteLivePresignSession(presignSessionId);
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
        await this.deleteLivePresignSession(presignSessionId);
        perf.resultCode = 'unauthorized';
        return { ok: false, code: 'unauthorized', message: 'presignSessionId expired' };
      }
      const ownerInstanceId = toOptionalTrimmedString(record.ownerInstanceId);
      if (ownerInstanceId) perf.ownerInstanceId = ownerInstanceId;
      const ownedLocally = this.isPresignSessionOwnedLocally(record);
      const maybeDeleteOwnedSession = async (): Promise<void> => {
        if (!ownedLocally) return;
        await this.poolFillSessionStore.deleteSession(presignSessionId);
      };

      const claims = input.claims;
      const tokenUserId = toOptionalTrimmedString(claims?.walletId);
      const tokenWalletKeyId = parseEvmFamilySigningKeySlotString(
        claims?.evmFamilySigningKeySlotId,
      );
      const tokenParticipantIds = normalizeThresholdEd25519ParticipantIds(claims?.participantIds);
      if (!tokenUserId || !tokenWalletKeyId || !tokenParticipantIds) {
        await maybeDeleteOwnedSession();
        await this.deleteLivePresignSession(presignSessionId);
        this.emitPresignSecurityEvent({
          event: 'presign_scope_mismatch',
          presignSessionId,
          record,
          code: 'unauthorized',
          message: 'Invalid Wallet Session token claims',
        });
        perf.resultCode = 'unauthorized';
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Invalid Wallet Session token claims',
        };
      }
      if (
        tokenUserId !== record.walletId ||
        tokenWalletKeyId !== record.evmFamilySigningKeySlotId ||
        !sameParticipantIds(tokenParticipantIds, record.participantIds)
      ) {
        await maybeDeleteOwnedSession();
        await this.deleteLivePresignSession(presignSessionId);
        this.emitPresignSecurityEvent({
          event: 'presign_scope_mismatch',
          presignSessionId,
          record,
          code: 'unauthorized',
          message: 'presignSessionId does not match Wallet Session scope',
        });
        perf.resultCode = 'unauthorized';
        return {
          ok: false,
          code: 'unauthorized',
          message: 'presignSessionId does not match Wallet Session scope',
        };
      }
      if (toOptionalTrimmedString(claims?.relayerKeyId) !== record.relayerKeyId) {
        await maybeDeleteOwnedSession();
        await this.deleteLivePresignSession(presignSessionId);
        this.emitPresignSecurityEvent({
          event: 'presign_scope_mismatch',
          presignSessionId,
          record,
          code: 'unauthorized',
          message: 'presignSessionId does not match Wallet Session scope',
        });
        perf.resultCode = 'unauthorized';
        return {
          ok: false,
          code: 'unauthorized',
          message: 'presignSessionId does not match Wallet Session scope',
        };
      }
      if (Date.now() > claims.thresholdExpiresAtMs) {
        await maybeDeleteOwnedSession();
        await this.deleteLivePresignSession(presignSessionId);
        perf.resultCode = 'unauthorized';
        return { ok: false, code: 'unauthorized', message: 'Wallet Session expired' };
      }
      if (!ownedLocally && ownerInstanceId) {
        await this.deleteLivePresignSession(presignSessionId);
        if (trustedForwardedHop >= this.maxPresignForwardHops) {
          perf.presign_stale_session_state = 1;
          perf.ownerForwardReason = 'hop_limit_exceeded';
          perf.resultCode = 'stale_session_state';
          this.logger.warn('[router-ab-ecdsa-hss-pool-fill] owner-forward blocked by hop limit', {
            presignSessionId,
            ownerInstanceId,
            forwardedHop: trustedForwardedHop,
            maxPresignForwardHops: this.maxPresignForwardHops,
          });
          return {
            ok: false,
            code: 'stale_session_state',
            message: `Router A/B ECDSA-HSS pool-fill owner forwarding limit exceeded; retry ${ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_INIT_PATH}`,
          };
        }

        const ownerRelayerUrl = this.resolvePresignSessionOwnerPeerUrl(record);
        if (!ownerRelayerUrl) {
          perf.presign_stale_session_state = 1;
          perf.ownerForwardReason = 'owner_peer_unavailable';
          perf.resultCode = 'stale_session_state';
          this.logger.warn('[router-ab-ecdsa-hss-pool-fill] owner-forward peer missing', {
            presignSessionId,
            ownerInstanceId,
            localInstanceId: this.coordinatorInstanceId,
          });
          return {
            ok: false,
            code: 'stale_session_state',
            message: `Router A/B ECDSA-HSS pool-fill owner unavailable on this coordinator; retry ${ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_INIT_PATH}`,
          };
        }
        if (!authorizationHeader && !cookieHeader) {
          perf.presign_stale_session_state = 1;
          perf.ownerForwardReason = 'missing_session_auth';
          perf.resultCode = 'stale_session_state';
          this.logger.warn(
            '[router-ab-ecdsa-hss-pool-fill] owner-forward missing session auth headers',
            {
              presignSessionId,
              ownerInstanceId,
            },
          );
          return {
            ok: false,
            code: 'stale_session_state',
            message: `Router A/B ECDSA-HSS pool-fill owner forwarding missing session auth; retry ${ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_INIT_PATH}`,
          };
        }

        const forwardedResponse = await this.forwardPoolFillStepToOwner({
          ownerInstanceId,
          ownerRelayerUrl,
          request: input.request,
          authorizationHeader: authorizationHeader || undefined,
          cookieHeader: cookieHeader || undefined,
          forwardedHop: trustedForwardedHop,
          presignSessionId,
        });
        if (forwardedResponse) {
          perf.presign_owner_forwarded = 1;
          perf.ownerForwardReason = 'forwarded';
          perf.resultCode = forwardedResponse.ok
            ? 'ok'
            : toOptionalTrimmedString(forwardedResponse.code) || 'forwarded_error';
          this.logger.info('[router-ab-ecdsa-hss-pool-fill] owner-forward success', {
            presignSessionId,
            ownerInstanceId,
            ownerRelayerUrl,
            forwardedHop: trustedForwardedHop,
            ok: forwardedResponse.ok,
            code: forwardedResponse.ok ? undefined : forwardedResponse.code,
          });
          return forwardedResponse;
        }

        perf.presign_stale_session_state = 1;
        perf.ownerForwardReason = 'forward_failed';
        perf.resultCode = 'stale_session_state';
        return {
          ok: false,
          code: 'stale_session_state',
          message: `Router A/B ECDSA-HSS pool-fill owner forward failed; retry ${ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_INIT_PATH}`,
        };
      }

      const wasmStepStartedAtMs = Date.now();
      const prepared = await this.liveSessionOwner.stepSession({
        presignSessionId,
        record,
        requestedStage,
        outgoingMessagesB64u,
        thresholdExpiresAtMs: claims.thresholdExpiresAtMs,
      });
      perf.wasmStepMs = Math.max(0, Date.now() - wasmStepStartedAtMs);
      perf.liveResolveMs = perf.wasmStepMs;
      if (!prepared.ok) {
        await this.deleteLivePresignSession(presignSessionId);
        if (ownedLocally) {
          await this.poolFillSessionStore.deleteSession(presignSessionId);
        }
        this.emitPresignSecurityEvent({
          event:
            prepared.code === 'invalid_body'
              ? 'presign_protocol_rejected'
              : 'presign_terminal_failure',
          presignSessionId,
          record,
          code: prepared.code,
          message: prepared.message,
        });
        perf.resultCode = prepared.code;
        if (prepared.code === 'stale_session_state') {
          perf.presign_live_cache_miss = 1;
          perf.liveCacheStatus = 'miss';
          perf.liveCacheMissReason = prepared.message;
          perf.presign_stale_session_state = 1;
        }
        return prepared;
      }
      perf.presign_live_cache_hit = 1;
      perf.liveCacheStatus = 'hit';

      if (prepared.value.mode === 'immediate') {
        perf.resultCode = 'ok';
        return prepared.value.response;
      }

      if (prepared.value.mode === 'terminal') {
        const published = await this.publishCompletedPresignature({
          record,
          presignature: prepared.value.presignDone,
        });
        if (!published.ok) {
          await this.poolFillSessionStore.deleteSession(presignSessionId);
          await this.deleteLivePresignSession(presignSessionId);
          perf.resultCode = published.code;
          return published;
        }
        await this.poolFillSessionStore.deleteSession(presignSessionId);
        await this.deleteLivePresignSession(presignSessionId);
        perf.resultCode = 'ok';
        return {
          ok: true,
          stage: 'done',
          event: 'presign_done',
          outgoingMessagesB64u: [],
          presignatureId: prepared.value.presignDone.presignatureId,
          bigRB64u: prepared.value.presignDone.bigRB64u,
        };
      }

      const { polled, nextRecord, presignDone } = prepared.value;
      const ttlMs = nextRecord.expiresAtMs - Date.now();
      if (ttlMs <= 0) {
        await this.poolFillSessionStore.deleteSession(presignSessionId);
        await this.deleteLivePresignSession(presignSessionId);
        perf.resultCode = 'unauthorized';
        return { ok: false, code: 'unauthorized', message: 'Wallet Session expired' };
      }

      const storeCasStartedAtMs = Date.now();
      const cas = await this.poolFillSessionStore.advanceSessionCas({
        id: presignSessionId,
        expectedVersion: record.version,
        nextRecord,
        ttlMs,
      });
      perf.storeCasMs = Math.max(0, Date.now() - storeCasStartedAtMs);
      if (!cas.ok) {
        await this.deleteLivePresignSession(presignSessionId);
        this.logger.warn('[router-ab-ecdsa-hss-pool-fill] live-session CAS conflict', {
          presignSessionId,
          expectedVersion: record.version,
          nextVersion: nextRecord.version,
          code: cas.code,
        });
        perf.casCode = cas.code;
        if (cas.code === 'expired') {
          perf.resultCode = 'unauthorized';
          return { ok: false, code: 'unauthorized', message: 'presignSessionId expired' };
        }
        if (cas.code === 'not_found') {
          perf.resultCode = 'unauthorized';
          return {
            ok: false,
            code: 'unauthorized',
            message: 'presignSessionId expired or invalid',
          };
        }
        perf.presign_stale_session_state = 1;
        perf.resultCode = 'stale_session_state';
        return {
          ok: false,
          code: 'stale_session_state',
          message: 'Router A/B ECDSA-HSS pool-fill session updated concurrently; retry step',
        };
      }

      if (polled.event === 'presign_done') {
        if (!presignDone) {
          await this.poolFillSessionStore.deleteSession(presignSessionId);
          await this.deleteLivePresignSession(presignSessionId);
          perf.resultCode = 'internal';
          return {
            ok: false,
            code: 'internal',
            message: 'presign_done missing presignature material',
          };
        }
        const published = await this.publishCompletedPresignature({
          record: nextRecord,
          presignature: presignDone,
        });
        if (!published.ok) {
          await this.poolFillSessionStore.deleteSession(presignSessionId);
          await this.deleteLivePresignSession(presignSessionId);
          perf.resultCode = published.code;
          return published;
        }
        await this.poolFillSessionStore.deleteSession(presignSessionId);
        await this.deleteLivePresignSession(presignSessionId);
        perf.resultCode = 'ok';
        return {
          ok: true,
          stage: 'done',
          event: 'presign_done',
          outgoingMessagesB64u: polled.outgoingMessagesB64u,
          presignatureId: presignDone.presignatureId,
          bigRB64u: presignDone.bigRB64u,
        };
      }

      perf.resultCode = 'ok';
      return {
        ok: true,
        stage: polled.stage,
        event: polled.event === 'triples_done' ? 'triples_done' : 'none',
        outgoingMessagesB64u: polled.outgoingMessagesB64u,
      };
    } finally {
      this.logger.info('[router-ab-ecdsa-hss-pool-fill] step perf', {
        presignSessionId,
        requestedStage,
        totalMs: Math.max(0, Date.now() - stepStartedAtMs),
        ...perf,
      });
    }
  }
}
