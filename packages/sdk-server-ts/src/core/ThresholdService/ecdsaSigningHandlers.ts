import type { NormalizedLogger } from '../logger';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  EcdsaHssRoleLocalKeyRecord,
  ThresholdEcdsaSigningRootMetadata,
  ThresholdEcdsaPresignInitRequest,
  ThresholdEcdsaPresignInitResponse,
  ThresholdEcdsaPresignStepRequest,
  ThresholdEcdsaPresignStepResponse,
  ThresholdEcdsaSignFinalizeRequest,
  ThresholdEcdsaSignFinalizeResponse,
  ThresholdEcdsaSignInitRequest,
  ThresholdEcdsaSignInitResponse,
} from '../types';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  signingRootScopeFromRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import type { ThresholdCoordinatorPeer, ThresholdNodeRole } from './config';
import type {
  ThresholdEcdsaPresignSessionRecord,
  ThresholdEcdsaPresignSessionStore,
  ThresholdEcdsaPresignatureRelayerShareRecord,
  ThresholdEcdsaPresignaturePool,
  ThresholdEcdsaSigningSessionRecord,
  ThresholdEcdsaSigningSessionStore,
} from './stores/EcdsaSigningStore';
import type { ThresholdEcdsaSessionClaims } from './validation';
import {
  ensureEthSignerWasm,
  sha256BytesSync,
  validateSecp256k1PublicKey33,
} from './ethSignerWasm';
import {
  ThresholdEcdsaPresignSession,
  threshold_ecdsa_finalize_signature,
} from '../../../../../wasm/eth_signer/pkg/eth_signer.js';

const THRESHOLD_ECDSA_HSS_ROLE_LOCAL_WALLET_KEY_VERSION = 'v1';
const THRESHOLD_ECDSA_HSS_ROLE_LOCAL_DERIVATION_VERSION = 1;

type ThresholdEcdsaMpcSessionRecord = {
  expiresAtMs: number;
  ecdsaThresholdKeyId?: string;
  keyHandle?: string;
  relayerKeyId: string;
  purpose: string;
  intentDigestB64u: string;
  signingDigestB64u: string;
  walletSessionUserId: string;
  rpId: string;
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

const PRESIGN_FORWARD_HOP_HEADER = 'x-threshold-ecdsa-presign-forward-hop';
const PRESIGN_FORWARDED_BY_HEADER = 'x-threshold-ecdsa-presign-forwarded-by';
const ECDSA_PRESIGN_POOL_KEY_VERSION = 'v2';

function signingRootMetadataFromRoleLocalKey(
  record: EcdsaHssRoleLocalKeyRecord,
): ThresholdEcdsaSigningRootMetadata {
  return {
    signingRootId: record.signingRootId,
    signingRootVersion: record.signingRootVersion,
    walletKeyVersion: THRESHOLD_ECDSA_HSS_ROLE_LOCAL_WALLET_KEY_VERSION,
    derivationVersion: THRESHOLD_ECDSA_HSS_ROLE_LOCAL_DERIVATION_VERSION,
  };
}

function presignPoolKeyPart(value: unknown, fieldName: string): string {
  const normalized =
    typeof value === 'number' && Number.isFinite(value)
      ? String(value)
      : toOptionalTrimmedString(value);
  if (!normalized) throw new Error(`${fieldName} is required for threshold-ecdsa presign pool key`);
  return encodeURIComponent(normalized);
}

function ecdsaPresignPoolKey(input: {
  ecdsaThresholdKeyId: string;
  keyHandle: string;
  relayerKeyId: string;
  thresholdEcdsaPublicKeyB64u: string;
  signingRootMetadata: ThresholdEcdsaSigningRootMetadata;
}): string {
  return [
    ECDSA_PRESIGN_POOL_KEY_VERSION,
    `keyHandle=${presignPoolKeyPart(input.keyHandle, 'keyHandle')}`,
    `ecdsaThresholdKeyId=${presignPoolKeyPart(input.ecdsaThresholdKeyId, 'ecdsaThresholdKeyId')}`,
    `relayerKeyId=${presignPoolKeyPart(input.relayerKeyId, 'relayerKeyId')}`,
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

function parseThresholdEcdsaSignInitRequest(request: ThresholdEcdsaSignInitRequest): ParseResult<{
  mpcSessionId: string;
  relayerKeyId: string;
  signingDigestB64u: string;
  clientPresignatureId?: string;
}> {
  const mpcSessionId = toOptionalTrimmedString(request.mpcSessionId);
  if (!mpcSessionId)
    return { ok: false, code: 'invalid_body', message: 'mpcSessionId is required' };

  const relayerKeyId = toOptionalTrimmedString(request.relayerKeyId);
  if (!relayerKeyId)
    return { ok: false, code: 'invalid_body', message: 'relayerKeyId is required' };

  const signingDigestB64u = toOptionalTrimmedString(request.signingDigestB64u);
  if (!signingDigestB64u)
    return { ok: false, code: 'invalid_body', message: 'signingDigestB64u is required' };

  const clientRound1Raw = (request as { clientRound1?: unknown }).clientRound1;
  const clientRound1 =
    clientRound1Raw && typeof clientRound1Raw === 'object' && !Array.isArray(clientRound1Raw)
      ? (clientRound1Raw as { presignatureId?: unknown })
      : null;
  const clientPresignatureId = clientRound1
    ? toOptionalTrimmedString(clientRound1.presignatureId)
    : null;
  if (clientRound1 && clientRound1.presignatureId !== undefined && !clientPresignatureId) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'clientRound1.presignatureId must be a non-empty string when provided',
    };
  }

  return {
    ok: true,
    value: {
      mpcSessionId,
      relayerKeyId,
      signingDigestB64u,
      ...(clientPresignatureId ? { clientPresignatureId } : {}),
    },
  };
}

function parseThresholdEcdsaSignFinalizeRequest(
  request: ThresholdEcdsaSignFinalizeRequest,
): ParseResult<{
  signingSessionId: string;
  clientSignatureShareB64u: string;
}> {
  const signingSessionId = toOptionalTrimmedString(request.signingSessionId);
  if (!signingSessionId)
    return { ok: false, code: 'invalid_body', message: 'signingSessionId is required' };

  const clientRound2 = (request as unknown as { clientRound2?: unknown }).clientRound2;
  const clientSignatureShareB64u = toOptionalTrimmedString(
    (clientRound2 as { clientSignatureShareB64u?: unknown } | undefined)?.clientSignatureShareB64u,
  );
  if (!clientSignatureShareB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'clientRound2.clientSignatureShareB64u is required',
    };
  }

  return { ok: true, value: { signingSessionId, clientSignatureShareB64u } };
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
  ecdsaThresholdKeyId: string;
  keyHandle: string;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  thresholdEcdsaPublicKeyB64u: string;
  signingRootMetadata: ThresholdEcdsaSigningRootMetadata;
  relayerSigningShare: ThresholdEcdsaRelayerSigningShare;
  presignPoolKey: string;
};

function parseThresholdEcdsaPresignInitRequest(
  request: ThresholdEcdsaPresignInitRequest,
): ParseResult<{
  keySelector: ThresholdEcdsaRoleLocalKeyRecordSelector;
  count: number;
}> {
  const keyHandle = toOptionalTrimmedString((request as { keyHandle?: unknown }).keyHandle);
  const ecdsaThresholdKeyId = toOptionalTrimmedString(request.ecdsaThresholdKeyId);
  if (ecdsaThresholdKeyId) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'keyHandle is required for threshold-ecdsa presign/init',
    };
  }
  if (!keyHandle) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'keyHandle is required for threshold-ecdsa presign/init',
    };
  }
  const countRaw = (request as { count?: unknown }).count;
  const count = Math.max(1, Math.floor(Number(countRaw ?? 1)));
  if (count !== 1) {
    return { ok: false, code: 'unsupported', message: 'v1 presign endpoint supports only count=1' };
  }
  return {
    ok: true,
    value: {
      keySelector: { kind: 'key_handle', keyHandle },
      count,
    },
  };
}

function parseThresholdEcdsaPresignStepRequest(
  request: ThresholdEcdsaPresignStepRequest,
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

function computePresignatureIdFromBigRBytes(bigR33: Uint8Array): string {
  const digest = sha256BytesSync(bigR33);
  return `presig-${base64UrlEncode(digest)}`;
}

function sameParticipantIds(a: number[], b: number[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

type WasmPresignPoll = {
  stage: 'triples' | 'triples_done' | 'presign' | 'done';
  event: 'none' | 'triples_done' | 'presign_done';
  outgoingMessagesB64u: string[];
};

function normalizeWasmPresignStage(
  rawStage: string,
): 'triples' | 'triples_done' | 'presign' | 'done' {
  if (rawStage === 'triples_done') return 'triples_done';
  if (rawStage === 'presign') return 'presign';
  if (rawStage === 'done') return 'done';
  return 'triples';
}

function pollWasmPresignSession(session: ThresholdEcdsaPresignSession): WasmPresignPoll {
  const polled = session.poll() as { stage?: string; outgoing?: Uint8Array[]; event?: string };
  const outgoingMessages = Array.isArray(polled?.outgoing) ? polled.outgoing : [];
  return {
    stage: normalizeWasmPresignStage(String(polled?.stage || session.stage() || 'triples')),
    event:
      polled?.event === 'triples_done' || polled?.event === 'presign_done' ? polled.event : 'none',
    outgoingMessagesB64u: outgoingMessages.map((msg) => base64UrlEncode(msg)),
  };
}

function decodePresignIncomingMessages(outgoingMessagesB64u: string[]): ParseResult<Uint8Array[]> {
  const decoded: Uint8Array[] = [];
  for (const msgB64u of outgoingMessagesB64u) {
    try {
      decoded.push(base64UrlDecode(msgB64u));
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'outgoingMessagesB64u contains invalid base64url',
      };
    }
  }
  return { ok: true, value: decoded };
}

function takePresignatureFromSession(session: ThresholdEcdsaPresignSession): ParseResult<{
  presignatureId: string;
  bigRB64u: string;
  kShareB64u: string;
  sigmaShareB64u: string;
}> {
  const presig97 = session.take_presignature_97();
  if (presig97.length !== 97) {
    return {
      ok: false,
      code: 'internal',
      message: `Invalid presignature bytes (expected 97, got ${presig97.length})`,
    };
  }
  const bigR33 = presig97.slice(0, 33);
  const kShare32 = presig97.slice(33, 65);
  const sigmaShare32 = presig97.slice(65, 97);
  return {
    ok: true,
    value: {
      presignatureId: computePresignatureIdFromBigRBytes(bigR33),
      bigRB64u: base64UrlEncode(bigR33),
      kShareB64u: base64UrlEncode(kShare32),
      sigmaShareB64u: base64UrlEncode(sigmaShare32),
    },
  };
}

type LivePresignSessionCacheEntry = {
  session: ThresholdEcdsaPresignSession;
  record: ThresholdEcdsaPresignSessionRecord;
};

type ThresholdEcdsaPresignStepTransport = {
  authorizationHeader?: string;
  cookieHeader?: string;
  forwardedHop?: number;
  forwardedByInstanceId?: string;
};

function freePresignSession(session: ThresholdEcdsaPresignSession): void {
  try {
    session.free();
  } catch {
    // Best-effort cleanup only.
  }
}

export class ThresholdEcdsaSigningHandlers {
  private readonly logger: NormalizedLogger;
  private readonly nodeRole: ThresholdNodeRole;
  private readonly participantIds2p: number[];
  private readonly clientParticipantId: number;
  private readonly relayerParticipantId: number;
  private readonly sessionStore: {
    readMpcSession(id: string): Promise<ThresholdEcdsaReadMpcSessionResult | null>;
    claimMpcSession(id: string, version: string): Promise<ThresholdEcdsaClaimMpcSessionResult>;
  };
  private readonly signingSessionStore: ThresholdEcdsaSigningSessionStore;
  private readonly presignSessionStore: ThresholdEcdsaPresignSessionStore;
  private readonly presignaturePool: ThresholdEcdsaPresignaturePool;
  private readonly resolveRoleLocalKeyRecord: (
    args: ThresholdEcdsaRoleLocalKeyRecordSelector,
  ) => Promise<EcdsaHssRoleLocalKeyRecord | null>;
  private readonly ensureReady: () => Promise<void>;
  private readonly createSigningSessionId: () => string;
  private readonly createPresignSessionId: () => string;
  private readonly coordinatorInstanceId: string | null;
  private readonly coordinatorPeerUrlByInstanceId: Map<string, string>;
  private readonly maxPresignForwardHops: number;
  private readonly livePresignSessionById = new Map<string, LivePresignSessionCacheEntry>();
  private readonly presignSessionStepInFlight = new Set<string>();

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
    signingSessionStore: ThresholdEcdsaSigningSessionStore;
    presignSessionStore: ThresholdEcdsaPresignSessionStore;
    presignaturePool: ThresholdEcdsaPresignaturePool;
    resolveRoleLocalKeyRecord: (
      args: ThresholdEcdsaRoleLocalKeyRecordSelector,
    ) => Promise<EcdsaHssRoleLocalKeyRecord | null>;
    ensureReady: () => Promise<void>;
    createSigningSessionId: () => string;
    createPresignSessionId: () => string;
    maxPresignForwardHops?: number;
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
    this.signingSessionStore = input.signingSessionStore;
    this.presignSessionStore = input.presignSessionStore;
    this.presignaturePool = input.presignaturePool;
    this.resolveRoleLocalKeyRecord = input.resolveRoleLocalKeyRecord;
    this.ensureReady = input.ensureReady;
    this.createSigningSessionId = input.createSigningSessionId;
    this.createPresignSessionId = input.createPresignSessionId;
  }

  private async resolvePresignInitKeyMaterial(input: {
    keySelector: ThresholdEcdsaRoleLocalKeyRecordSelector;
    walletSessionUserId: string;
    rpId: string;
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
    const ecdsaThresholdKeyId = toOptionalTrimmedString(roleLocalKey.ecdsaThresholdKeyId);
    const keyHandle = toOptionalTrimmedString(roleLocalKey.keyHandle);
    const tokenKeyHandle = toOptionalTrimmedString(input.tokenKeyHandle);
    if (!ecdsaThresholdKeyId || !keyHandle || !tokenKeyHandle || tokenKeyHandle !== keyHandle) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'keyHandle does not match threshold session scope',
      };
    }
    if (roleLocalKey.walletId !== input.walletSessionUserId || roleLocalKey.rpId !== input.rpId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'ecdsaThresholdKeyId does not match threshold session scope',
      };
    }
    if (!sameParticipantIds(this.participantIds2p, input.participantIds)) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'ecdsaThresholdKeyId participantIds do not match threshold session scope',
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
        message: 'ecdsaThresholdKeyId signing root does not match threshold session scope',
      };
    }
    if (roleLocalKey.relayerKeyId !== input.tokenRelayerKeyId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'ecdsaThresholdKeyId does not match threshold session relayer scope',
      };
    }
    return {
      ok: true,
      value: {
        ecdsaThresholdKeyId,
        keyHandle,
        relayerKeyId: roleLocalKey.relayerKeyId,
        clientVerifyingShareB64u: roleLocalKey.clientPublicKey33B64u,
        thresholdEcdsaPublicKeyB64u: roleLocalKey.groupPublicKey33B64u,
        signingRootMetadata,
        relayerSigningShare: {
          kind: 'cait_sith_mapped',
          share32B64u: roleLocalKey.relayerCaitSithInput.mappedPrivateShare32B64u,
        },
        presignPoolKey: ecdsaPresignPoolKey({
          ecdsaThresholdKeyId,
          keyHandle,
          relayerKeyId: roleLocalKey.relayerKeyId,
          thresholdEcdsaPublicKeyB64u: roleLocalKey.groupPublicKey33B64u,
          signingRootMetadata,
        }),
      },
    };
  }

  private evictLivePresignSession(presignSessionId: string): void {
    const existing = this.livePresignSessionById.get(presignSessionId);
    if (!existing) return;
    this.livePresignSessionById.delete(presignSessionId);
    freePresignSession(existing.session);
  }

  private putLivePresignSession(
    presignSessionId: string,
    entry: LivePresignSessionCacheEntry,
  ): void {
    const existing = this.livePresignSessionById.get(presignSessionId);
    if (existing && existing.session !== entry.session) {
      freePresignSession(existing.session);
    }
    this.livePresignSessionById.set(presignSessionId, entry);
  }

  private emitPresignSecurityEvent(input: {
    event: string;
    presignSessionId: string;
    record?: ThresholdEcdsaPresignSessionRecord | null;
    code?: string;
    message?: string;
    requestOrigin?: string;
  }): void {
    const record = input.record || null;
    this.logger.warn('[threshold-ecdsa-security]', {
      event: input.event,
      presignSessionId: input.presignSessionId,
      walletSessionUserId: record?.walletSessionUserId || null,
      rpId: record?.rpId || null,
      relayerKeyId: record?.relayerKeyId || null,
      ecdsaThresholdKeyId: null,
      presignPoolKey: record?.presignPoolKey || null,
      requestOrigin: input.requestOrigin || null,
      code: input.code || null,
      message: input.message || null,
    });
  }

  private isPresignSessionOwnedLocally(record: ThresholdEcdsaPresignSessionRecord): boolean {
    const ownerInstanceId = toOptionalTrimmedString(record.ownerInstanceId);
    if (!ownerInstanceId) return true;
    if (!this.coordinatorInstanceId) return false;
    return ownerInstanceId === this.coordinatorInstanceId;
  }

  private resolvePresignSessionOwnerPeerUrl(
    record: ThresholdEcdsaPresignSessionRecord,
  ): string | null {
    const ownerInstanceId = toOptionalTrimmedString(record.ownerInstanceId);
    if (!ownerInstanceId) return null;
    if (this.coordinatorInstanceId && ownerInstanceId === this.coordinatorInstanceId) return null;
    return this.coordinatorPeerUrlByInstanceId.get(ownerInstanceId) || null;
  }

  private async forwardPresignStepToOwner(input: {
    ownerInstanceId: string;
    ownerRelayerUrl: string;
    request: ThresholdEcdsaPresignStepRequest;
    authorizationHeader?: string;
    cookieHeader?: string;
    forwardedHop: number;
    presignSessionId: string;
  }): Promise<ThresholdEcdsaPresignStepResponse | null> {
    if (typeof fetch !== 'function') {
      this.logger.warn('[threshold-ecdsa] owner-forward skipped: fetch unavailable', {
        presignSessionId: input.presignSessionId,
        ownerInstanceId: input.ownerInstanceId,
      });
      return null;
    }

    const headers: Record<string, string> = {
      'content-type': 'application/json',
      [PRESIGN_FORWARD_HOP_HEADER]: String(input.forwardedHop + 1),
    };
    if (this.coordinatorInstanceId)
      headers[PRESIGN_FORWARDED_BY_HEADER] = this.coordinatorInstanceId;
    const authorizationHeader = toOptionalTrimmedString(input.authorizationHeader);
    if (authorizationHeader) headers.authorization = authorizationHeader;
    const cookieHeader = toOptionalTrimmedString(input.cookieHeader);
    if (cookieHeader) headers.cookie = cookieHeader;

    let response: Response;
    try {
      response = await fetch(`${input.ownerRelayerUrl}/threshold-ecdsa/presign/step`, {
        method: 'POST',
        headers,
        body: JSON.stringify(input.request),
      });
    } catch (error: unknown) {
      this.logger.warn('[threshold-ecdsa] owner-forward request failed', {
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
      this.logger.warn('[threshold-ecdsa] owner-forward response decode failed', {
        presignSessionId: input.presignSessionId,
        ownerInstanceId: input.ownerInstanceId,
        ownerRelayerUrl: input.ownerRelayerUrl,
        status: response.status,
      });
      return null;
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      this.logger.warn('[threshold-ecdsa] owner-forward response shape invalid', {
        presignSessionId: input.presignSessionId,
        ownerInstanceId: input.ownerInstanceId,
        ownerRelayerUrl: input.ownerRelayerUrl,
        status: response.status,
      });
      return null;
    }

    return body as ThresholdEcdsaPresignStepResponse;
  }

  async ecdsaPresignInit(input: {
    claims: ThresholdEcdsaSessionClaims;
    request: ThresholdEcdsaPresignInitRequest;
  }): Promise<ThresholdEcdsaPresignInitResponse> {
    if (this.nodeRole !== 'coordinator') {
      return {
        ok: false,
        code: 'not_found',
        message:
          'threshold-ecdsa presign endpoints are not enabled on this server (set THRESHOLD_NODE_ROLE=coordinator)',
      };
    }

    await this.ensureReady();
    await ensureEthSignerWasm();

    const parsedRequest = parseThresholdEcdsaPresignInitRequest(input.request);
    if (!parsedRequest.ok) return parsedRequest;
    const { keySelector } = parsedRequest.value;

    const claims = input.claims;
    const walletSessionUserId = toOptionalTrimmedString(claims?.walletId);
    if (!walletSessionUserId)
      return {
        ok: false,
        code: 'unauthorized',
        message: 'Missing walletSessionUserId in threshold session token',
      };
    const tokenRelayerKeyId = toOptionalTrimmedString(claims?.relayerKeyId);
    const tokenRpId = toOptionalTrimmedString(claims?.rpId);
    if (!tokenRelayerKeyId || !tokenRpId) {
      return { ok: false, code: 'unauthorized', message: 'Invalid threshold session token claims' };
    }
    const tokenSigningRoot = signingRootMetadataFromRuntimePolicyScope(claims.runtimePolicyScope);
    if (!tokenSigningRoot) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'threshold session token is missing signing-root scope',
      };
    }
    const resolvedKeyMaterial = await this.resolvePresignInitKeyMaterial({
      keySelector,
      walletSessionUserId,
      rpId: tokenRpId,
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
        message: 'relayerKeyId does not match threshold session scope',
      };
    }
    if (Date.now() > claims.thresholdExpiresAtMs) {
      return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
    }

    if (this.clientParticipantId !== 1 || this.relayerParticipantId !== 2) {
      return {
        ok: false,
        code: 'unsupported',
        message: 'v1 presign endpoint requires participantIds={client=1,relayer=2}',
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
      return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
    }
    const expiresAtMs = nowMs + ttlMs;
    if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
      return {
        ok: false,
        code: 'unsupported',
        message: 'crypto.getRandomValues is unavailable in this runtime',
      };
    }

    for (let attempt = 0; attempt < 4; attempt += 1) {
      const presignSessionId = this.createPresignSessionId();
      const wasmSession = new ThresholdEcdsaPresignSession(
        new Uint32Array(participantIds),
        this.relayerParticipantId,
        2,
        relayerThresholdShare32,
        groupPublicKeyBytes,
      );
      const polled = pollWasmPresignSession(wasmSession);

      const createdAtMs = Date.now();
      const record: ThresholdEcdsaPresignSessionRecord = {
        expiresAtMs,
        walletSessionUserId,
        rpId: tokenRpId,
        relayerKeyId,
        presignPoolKey,
        ...(this.coordinatorInstanceId ? { ownerInstanceId: this.coordinatorInstanceId } : {}),
        participantIds,
        clientParticipantId: this.clientParticipantId,
        relayerParticipantId: this.relayerParticipantId,
        stage: polled.stage,
        version: 1,
        createdAtMs,
        updatedAtMs: createdAtMs,
        ...signingRootMetadata,
      };

      const created = await this.presignSessionStore.createSession(
        presignSessionId,
        record,
        Math.max(1, expiresAtMs - Date.now()),
      );
      if (!created.ok) {
        freePresignSession(wasmSession);
        continue;
      }

      this.putLivePresignSession(presignSessionId, {
        session: wasmSession,
        record,
      });

      return {
        ok: true,
        presignSessionId,
        stage: polled.stage,
        outgoingMessagesB64u: polled.outgoingMessagesB64u,
      };
    }

    return { ok: false, code: 'internal', message: 'Failed to allocate presignSessionId; retry' };
  }

  async ecdsaPresignStep(input: {
    claims: ThresholdEcdsaSessionClaims;
    request: ThresholdEcdsaPresignStepRequest;
    transport?: ThresholdEcdsaPresignStepTransport;
  }): Promise<ThresholdEcdsaPresignStepResponse> {
    if (this.nodeRole !== 'coordinator') {
      return {
        ok: false,
        code: 'not_found',
        message:
          'threshold-ecdsa presign endpoints are not enabled on this server (set THRESHOLD_NODE_ROLE=coordinator)',
      };
    }

    await this.ensureReady();
    await ensureEthSignerWasm();

    const parsedRequest = parseThresholdEcdsaPresignStepRequest(input.request);
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
      this.logger.warn('[threshold-ecdsa] ignoring untrusted forwarded hop', {
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
    if (this.presignSessionStepInFlight.has(presignSessionId)) {
      return {
        ok: false,
        code: 'stale_session_state',
        message: 'Presign session step already in progress; retry step',
      };
    }
    this.presignSessionStepInFlight.add(presignSessionId);
    try {
      const storeGetStartedAtMs = Date.now();
      const record = await this.presignSessionStore.getSession(presignSessionId);
      perf.storeGetSessionMs = Math.max(0, Date.now() - storeGetStartedAtMs);
      if (!record) {
        this.evictLivePresignSession(presignSessionId);
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
        await this.presignSessionStore.deleteSession(presignSessionId);
        this.evictLivePresignSession(presignSessionId);
        perf.resultCode = 'unauthorized';
        return { ok: false, code: 'unauthorized', message: 'presignSessionId expired' };
      }
      const ownerInstanceId = toOptionalTrimmedString(record.ownerInstanceId);
      if (ownerInstanceId) perf.ownerInstanceId = ownerInstanceId;
      const ownedLocally = this.isPresignSessionOwnedLocally(record);
      const maybeDeleteOwnedSession = async (): Promise<void> => {
        if (!ownedLocally) return;
        await this.presignSessionStore.deleteSession(presignSessionId);
      };

      const claims = input.claims;
      const tokenUserId = toOptionalTrimmedString(claims?.walletId);
      const tokenRpId = toOptionalTrimmedString(claims?.rpId);
      const tokenParticipantIds = normalizeThresholdEd25519ParticipantIds(claims?.participantIds);
      if (!tokenUserId || !tokenRpId || !tokenParticipantIds) {
        await maybeDeleteOwnedSession();
        this.evictLivePresignSession(presignSessionId);
        this.emitPresignSecurityEvent({
          event: 'presign_scope_mismatch',
          presignSessionId,
          record,
          code: 'unauthorized',
          message: 'Invalid threshold session token claims',
        });
        perf.resultCode = 'unauthorized';
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Invalid threshold session token claims',
        };
      }
      if (
        tokenUserId !== record.walletSessionUserId ||
        tokenRpId !== record.rpId ||
        !sameParticipantIds(tokenParticipantIds, record.participantIds)
      ) {
        await maybeDeleteOwnedSession();
        this.evictLivePresignSession(presignSessionId);
        this.emitPresignSecurityEvent({
          event: 'presign_scope_mismatch',
          presignSessionId,
          record,
          code: 'unauthorized',
          message: 'presignSessionId does not match threshold session scope',
        });
        perf.resultCode = 'unauthorized';
        return {
          ok: false,
          code: 'unauthorized',
          message: 'presignSessionId does not match threshold session scope',
        };
      }
      if (toOptionalTrimmedString(claims?.relayerKeyId) !== record.relayerKeyId) {
        await maybeDeleteOwnedSession();
        this.evictLivePresignSession(presignSessionId);
        this.emitPresignSecurityEvent({
          event: 'presign_scope_mismatch',
          presignSessionId,
          record,
          code: 'unauthorized',
          message: 'presignSessionId does not match threshold session scope',
        });
        perf.resultCode = 'unauthorized';
        return {
          ok: false,
          code: 'unauthorized',
          message: 'presignSessionId does not match threshold session scope',
        };
      }
      if (Date.now() > claims.thresholdExpiresAtMs) {
        await maybeDeleteOwnedSession();
        this.evictLivePresignSession(presignSessionId);
        perf.resultCode = 'unauthorized';
        return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
      }
      if (!ownedLocally && ownerInstanceId) {
        this.evictLivePresignSession(presignSessionId);
        if (trustedForwardedHop >= this.maxPresignForwardHops) {
          perf.presign_stale_session_state = 1;
          perf.ownerForwardReason = 'hop_limit_exceeded';
          perf.resultCode = 'stale_session_state';
          this.logger.warn('[threshold-ecdsa] owner-forward blocked by hop limit', {
            presignSessionId,
            ownerInstanceId,
            forwardedHop: trustedForwardedHop,
            maxPresignForwardHops: this.maxPresignForwardHops,
          });
          return {
            ok: false,
            code: 'stale_session_state',
            message: 'Presign owner forwarding limit exceeded; retry /threshold-ecdsa/presign/init',
          };
        }

        const ownerRelayerUrl = this.resolvePresignSessionOwnerPeerUrl(record);
        if (!ownerRelayerUrl) {
          perf.presign_stale_session_state = 1;
          perf.ownerForwardReason = 'owner_peer_unavailable';
          perf.resultCode = 'stale_session_state';
          this.logger.warn('[threshold-ecdsa] owner-forward peer missing', {
            presignSessionId,
            ownerInstanceId,
            localInstanceId: this.coordinatorInstanceId,
          });
          return {
            ok: false,
            code: 'stale_session_state',
            message:
              'Presign owner unavailable on this coordinator; retry /threshold-ecdsa/presign/init',
          };
        }
        if (!authorizationHeader && !cookieHeader) {
          perf.presign_stale_session_state = 1;
          perf.ownerForwardReason = 'missing_session_auth';
          perf.resultCode = 'stale_session_state';
          this.logger.warn('[threshold-ecdsa] owner-forward missing session auth headers', {
            presignSessionId,
            ownerInstanceId,
          });
          return {
            ok: false,
            code: 'stale_session_state',
            message:
              'Presign owner forwarding missing session auth; retry /threshold-ecdsa/presign/init',
          };
        }

        const forwardedResponse = await this.forwardPresignStepToOwner({
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
          this.logger.info('[threshold-ecdsa] owner-forward success', {
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
          message: 'Presign owner forward failed; retry /threshold-ecdsa/presign/init',
        };
      }

      const liveResolveStartedAtMs = Date.now();
      const cached = this.livePresignSessionById.get(presignSessionId);
      let liveEntry: LivePresignSessionCacheEntry | null = null;
      let liveCacheMissReason: string | null = null;
      if (!cached) {
        liveCacheMissReason = 'cache_miss';
      } else if (Date.now() > cached.record.expiresAtMs) {
        liveCacheMissReason = 'cache_expired';
      } else if (cached.record.version !== record.version) {
        liveCacheMissReason = 'cache_version_mismatch';
      } else if (cached.record.stage !== record.stage) {
        liveCacheMissReason = 'cache_stage_mismatch';
      } else {
        liveEntry = cached;
      }
      perf.liveResolveMs = Math.max(0, Date.now() - liveResolveStartedAtMs);
      if (!liveEntry) {
        perf.presign_live_cache_miss = 1;
        perf.liveCacheStatus = 'miss';
        perf.liveCacheMissReason = liveCacheMissReason || 'unknown';
        if (cached) this.evictLivePresignSession(presignSessionId);
        this.logger.warn('[threshold-ecdsa] presign live-session cache miss', {
          presignSessionId,
          recordVersion: record.version,
          recordStage: record.stage,
          reason: liveCacheMissReason || 'unknown',
        });
        if (ownedLocally) {
          await this.presignSessionStore.deleteSession(presignSessionId);
        }
        perf.presign_stale_session_state = 1;
        perf.resultCode = 'stale_session_state';
        return {
          ok: false,
          code: 'stale_session_state',
          message: 'Presign live session unavailable; retry /threshold-ecdsa/presign/init',
        };
      }
      perf.presign_live_cache_hit = 1;
      perf.liveCacheStatus = 'hit';

      type PreparedPresignStepValue =
        | {
            mode: 'terminal';
            presignDone: {
              presignatureId: string;
              bigRB64u: string;
              kShareB64u: string;
              sigmaShareB64u: string;
            };
          }
        | {
            mode: 'immediate';
            response: ThresholdEcdsaPresignStepResponse;
          }
        | {
            mode: 'advance';
            polled: WasmPresignPoll;
            nextRecord: ThresholdEcdsaPresignSessionRecord;
            presignDone: {
              presignatureId: string;
              bigRB64u: string;
              kShareB64u: string;
              sigmaShareB64u: string;
            } | null;
          };

      const wasmStepStartedAtMs = Date.now();
      const prepared: ParseResult<PreparedPresignStepValue> = (() => {
        const wasmSession = liveEntry.session;
        const currentStage = normalizeWasmPresignStage(wasmSession.stage());
        if (currentStage !== record.stage) {
          return {
            ok: false,
            code: 'internal',
            message: 'presign session stage mismatch',
          } as ParseErr;
        }

        if (currentStage === 'done') {
          const terminal = takePresignatureFromSession(wasmSession);
          if (!terminal.ok) return terminal;
          return {
            ok: true,
            value: {
              mode: 'terminal' as const,
              presignDone: terminal.value,
            },
          };
        }

        if (currentStage === 'triples_done' && requestedStage === 'triples') {
          return {
            ok: true,
            value: {
              mode: 'immediate' as const,
              response: {
                ok: true,
                stage: 'triples_done' as const,
                event: 'triples_done' as const,
                outgoingMessagesB64u: [],
              },
            },
          };
        }
        if (requestedStage === 'presign' && currentStage === 'triples_done') {
          try {
            wasmSession.start_presign();
          } catch {
            return {
              ok: false,
              code: 'invalid_body',
              message: 'server is not ready for presign',
            } as ParseErr;
          }
        } else if (requestedStage === 'presign' && currentStage === 'triples') {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'server is not ready for presign (triples still running)',
          } as ParseErr;
        } else if (requestedStage === 'triples' && currentStage !== 'triples') {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'stage regression is not allowed',
          } as ParseErr;
        }

        const decodedIncoming = decodePresignIncomingMessages(outgoingMessagesB64u);
        if (!decodedIncoming.ok) return decodedIncoming;

        for (const decoded of decodedIncoming.value) {
          try {
            wasmSession.message(record.clientParticipantId, decoded);
          } catch (e: unknown) {
            return {
              ok: false,
              code: 'invalid_body',
              message: `Protocol rejected message: ${String(e || 'error')}`,
            } as ParseErr;
          }
        }

        const polled = pollWasmPresignSession(wasmSession);
        const nextExpiresAtMs = Math.min(record.expiresAtMs, claims.thresholdExpiresAtMs);
        const nextRecord: ThresholdEcdsaPresignSessionRecord = {
          ...record,
          stage: polled.stage,
          version: record.version + 1,
          expiresAtMs: nextExpiresAtMs,
          updatedAtMs: Date.now(),
        };

        let presignDone: {
          presignatureId: string;
          bigRB64u: string;
          kShareB64u: string;
          sigmaShareB64u: string;
        } | null = null;
        if (polled.event === 'presign_done') {
          const done = takePresignatureFromSession(wasmSession);
          if (!done.ok) return done;
          presignDone = done.value;
        }

        return {
          ok: true,
          value: {
            mode: 'advance' as const,
            polled,
            nextRecord,
            presignDone,
          },
        };
      })();
      perf.wasmStepMs = Math.max(0, Date.now() - wasmStepStartedAtMs);
      if (!prepared.ok) {
        this.evictLivePresignSession(presignSessionId);
        if (ownedLocally) {
          await this.presignSessionStore.deleteSession(presignSessionId);
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
        return prepared;
      }

      if (prepared.value.mode === 'immediate') {
        liveEntry.record = record;
        perf.resultCode = 'ok';
        return prepared.value.response;
      }

      if (prepared.value.mode === 'terminal') {
        await this.presignaturePool.put({
          relayerKeyId: record.presignPoolKey,
          presignatureId: prepared.value.presignDone.presignatureId,
          bigRB64u: prepared.value.presignDone.bigRB64u,
          kShareB64u: prepared.value.presignDone.kShareB64u,
          sigmaShareB64u: prepared.value.presignDone.sigmaShareB64u,
          createdAtMs: Date.now(),
        });
        await this.presignSessionStore.deleteSession(presignSessionId);
        this.evictLivePresignSession(presignSessionId);
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
        await this.presignSessionStore.deleteSession(presignSessionId);
        this.evictLivePresignSession(presignSessionId);
        perf.resultCode = 'unauthorized';
        return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
      }

      const storeCasStartedAtMs = Date.now();
      const cas = await this.presignSessionStore.advanceSessionCas({
        id: presignSessionId,
        expectedVersion: record.version,
        nextRecord,
        ttlMs,
      });
      perf.storeCasMs = Math.max(0, Date.now() - storeCasStartedAtMs);
      if (!cas.ok) {
        this.evictLivePresignSession(presignSessionId);
        this.logger.warn('[threshold-ecdsa] presign live-session CAS conflict', {
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
          message: 'Presign session updated concurrently; retry step',
        };
      }

      liveEntry.record = cas.record;
      this.putLivePresignSession(presignSessionId, liveEntry);

      if (polled.event === 'presign_done') {
        if (!presignDone) {
          await this.presignSessionStore.deleteSession(presignSessionId);
          this.evictLivePresignSession(presignSessionId);
          perf.resultCode = 'internal';
          return {
            ok: false,
            code: 'internal',
            message: 'presign_done missing presignature material',
          };
        }
        await this.presignaturePool.put({
          relayerKeyId: record.presignPoolKey,
          presignatureId: presignDone.presignatureId,
          bigRB64u: presignDone.bigRB64u,
          kShareB64u: presignDone.kShareB64u,
          sigmaShareB64u: presignDone.sigmaShareB64u,
          createdAtMs: Date.now(),
        });
        await this.presignSessionStore.deleteSession(presignSessionId);
        this.evictLivePresignSession(presignSessionId);
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
      this.presignSessionStepInFlight.delete(presignSessionId);
      this.logger.info('[threshold-ecdsa] presign/step perf', {
        presignSessionId,
        requestedStage,
        totalMs: Math.max(0, Date.now() - stepStartedAtMs),
        ...perf,
      });
    }
  }

  async ecdsaSignInit(
    request: ThresholdEcdsaSignInitRequest,
  ): Promise<ThresholdEcdsaSignInitResponse> {
    if (this.nodeRole !== 'coordinator') {
      return {
        ok: false,
        code: 'not_found',
        message:
          'threshold-ecdsa signing endpoints are not enabled on this server (set THRESHOLD_NODE_ROLE=coordinator)',
      };
    }

    await this.ensureReady();
    const parsedRequest = parseThresholdEcdsaSignInitRequest(request);
    if (!parsedRequest.ok) return parsedRequest;
    const { mpcSessionId, relayerKeyId, signingDigestB64u, clientPresignatureId } =
      parsedRequest.value;

    const sessionRead = await this.sessionStore.readMpcSession(mpcSessionId);
    if (!sessionRead) {
      return { ok: false, code: 'unauthorized', message: 'mpcSessionId expired or invalid' };
    }
    const sess = sessionRead.record;
    if (Date.now() > sess.expiresAtMs) {
      return { ok: false, code: 'unauthorized', message: 'mpcSessionId expired' };
    }

    const participantIds = normalizeThresholdEd25519ParticipantIds(sess.participantIds) || [
      ...this.participantIds2p,
    ];

    if (relayerKeyId !== sess.relayerKeyId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'relayerKeyId does not match mpcSessionId scope',
      };
    }
    if (signingDigestB64u !== sess.signingDigestB64u) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'signingDigestB64u does not match mpcSessionId scope',
      };
    }

    if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
      return {
        ok: false,
        code: 'unsupported',
        message: 'crypto.getRandomValues is unavailable in this runtime',
      };
    }

    const ttlMs = Math.max(0, Math.min(60_000, sess.expiresAtMs - Date.now()));
    if (ttlMs <= 0) {
      return { ok: false, code: 'unauthorized', message: 'mpcSessionId expired' };
    }
    const clientVerifyingShareB64u = toOptionalTrimmedString(sess.clientVerifyingShareB64u);
    if (!clientVerifyingShareB64u) {
      return {
        ok: false,
        code: 'internal',
        message: 'mpcSessionId is missing clientVerifyingShareB64u',
      };
    }
    const keyHandle = toOptionalTrimmedString(sess.keyHandle);
    if (!keyHandle) {
      return {
        ok: false,
        code: 'internal',
        message: 'mpcSessionId is missing keyHandle',
      };
    }
    const tokenSigningRootId = toOptionalTrimmedString(sess.signingRootId);
    if (!tokenSigningRootId) {
      return {
        ok: false,
        code: 'internal',
        message: 'mpcSessionId is missing signing-root metadata',
      };
    }
    const tokenSigningRoot = {
      signingRootId: tokenSigningRootId,
      ...(toOptionalTrimmedString(sess.signingRootVersion)
        ? { signingRootVersion: toOptionalTrimmedString(sess.signingRootVersion) }
        : {}),
    };
    const keyMaterial = await this.resolvePresignInitKeyMaterial({
      keySelector: { kind: 'key_handle', keyHandle },
      walletSessionUserId: sess.walletSessionUserId,
      rpId: sess.rpId,
      participantIds,
      tokenRelayerKeyId: sess.relayerKeyId,
      tokenKeyHandle: keyHandle,
      tokenSigningRoot,
    });
    if (!keyMaterial.ok) return keyMaterial;
    const signingMaterial = keyMaterial.value;
    const thresholdEcdsaPublicKeyB64u = toOptionalTrimmedString(
      signingMaterial.thresholdEcdsaPublicKeyB64u,
    );
    if (!thresholdEcdsaPublicKeyB64u) {
      return {
        ok: false,
        code: 'internal',
        message: 'ecdsaThresholdKeyId is missing persisted thresholdEcdsaPublicKeyB64u',
      };
    }
    const ecdsaThresholdKeyId = toOptionalTrimmedString(sess.ecdsaThresholdKeyId);
    if (ecdsaThresholdKeyId && signingMaterial.ecdsaThresholdKeyId !== ecdsaThresholdKeyId) {
      return {
        ok: false,
        code: 'internal',
        message: 'keyHandle does not match mpcSessionId threshold key scope',
      };
    }
    const signingRootMetadata = signingMaterial.signingRootMetadata;
    if (
      sess.signingRootId !== signingRootMetadata.signingRootId ||
      sess.signingRootVersion !== signingRootMetadata.signingRootVersion ||
      sess.walletKeyVersion !== signingRootMetadata.walletKeyVersion ||
      sess.derivationVersion !== signingRootMetadata.derivationVersion
    ) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'mpcSessionId signing root does not match ECDSA key',
      };
    }

    const presignature = await this.reserveSignInitPresignature(
      signingMaterial.presignPoolKey,
      clientPresignatureId,
    );
    if (!presignature) {
      if (clientPresignatureId) {
        return {
          ok: false,
          code: 'pool_empty',
          message: 'requested presignature is unavailable; refill required',
        };
      }
      return {
        ok: false,
        code: 'pool_empty',
        message: 'presignature pool is empty; refill required',
      };
    }

    const claimed = await this.sessionStore.claimMpcSession(mpcSessionId, sessionRead.version);
    if (!claimed.ok) {
      await this.presignaturePool.discard(
        signingMaterial.presignPoolKey,
        presignature.presignatureId,
      );
      const message =
        claimed.code === 'version_mismatch'
          ? 'mpcSessionId was claimed concurrently'
          : claimed.code === 'expired'
            ? 'mpcSessionId expired'
            : 'mpcSessionId expired or invalid';
      return { ok: false, code: 'unauthorized', message };
    }

    const signingSessionId = this.createSigningSessionId();
    const entropyB64u = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
    const walletSessionUserId = sess.walletSessionUserId;

    const record: ThresholdEcdsaSigningSessionRecord = {
      expiresAtMs: sess.expiresAtMs,
      mpcSessionId,
      relayerKeyId,
      presignPoolKey: signingMaterial.presignPoolKey,
      ecdsaThresholdKeyId,
      thresholdEcdsaPublicKeyB64u,
      signingDigestB64u: sess.signingDigestB64u,
      walletSessionUserId,
      rpId: sess.rpId,
      clientVerifyingShareB64u,
      participantIds,
      presignatureId: presignature.presignatureId,
      entropyB64u,
      ...signingRootMetadata,
      ...(presignature.bigRB64u ? { bigRB64u: presignature.bigRB64u } : {}),
    };

    await this.signingSessionStore.putSigningSession(signingSessionId, record, ttlMs);

    return {
      ok: true,
      signingSessionId,
      relayerRound1: {
        presignatureId: presignature.presignatureId,
        entropyB64u,
        ...(presignature.bigRB64u ? { bigRB64u: presignature.bigRB64u } : {}),
      },
    };
  }

  private async reserveSignInitPresignature(
    relayerKeyId: string,
    requestedPresignatureId?: string,
  ): Promise<ThresholdEcdsaPresignatureRelayerShareRecord | null> {
    const requested = toOptionalTrimmedString(requestedPresignatureId);
    if (!requested) {
      return await this.presignaturePool.reserve(relayerKeyId);
    }
    return await this.presignaturePool.reserveById(relayerKeyId, requested);
  }

  async ecdsaSignFinalize(
    request: ThresholdEcdsaSignFinalizeRequest,
  ): Promise<ThresholdEcdsaSignFinalizeResponse> {
    if (this.nodeRole !== 'coordinator') {
      return {
        ok: false,
        code: 'not_found',
        message:
          'threshold-ecdsa signing endpoints are not enabled on this server (set THRESHOLD_NODE_ROLE=coordinator)',
      };
    }

    await this.ensureReady();
    await ensureEthSignerWasm();
    const parsedRequest = parseThresholdEcdsaSignFinalizeRequest(request);
    if (!parsedRequest.ok) return parsedRequest;
    const { signingSessionId, clientSignatureShareB64u } = parsedRequest.value;

    const sess = await this.signingSessionStore.takeSigningSession(signingSessionId);
    if (!sess) {
      return { ok: false, code: 'unauthorized', message: 'signingSessionId expired or invalid' };
    }
    if (Date.now() > sess.expiresAtMs) {
      await this.presignaturePool.discard(sess.presignPoolKey, sess.presignatureId);
      return { ok: false, code: 'unauthorized', message: 'signingSessionId expired' };
    }

    if (this.clientParticipantId !== 1 || this.relayerParticipantId !== 2) {
      await this.presignaturePool.discard(sess.presignPoolKey, sess.presignatureId);
      return {
        ok: false,
        code: 'unsupported',
        message: 'v1 signer requires participantIds={client=1,relayer=2}',
      };
    }

    let clientSignatureShare32: Uint8Array;
    try {
      clientSignatureShare32 = base64UrlDecode(clientSignatureShareB64u);
      if (clientSignatureShare32.length !== 32) {
        await this.presignaturePool.discard(sess.presignPoolKey, sess.presignatureId);
        return {
          ok: false,
          code: 'invalid_body',
          message: `clientSignatureShareB64u must be 32 bytes, got ${clientSignatureShare32.length}`,
        };
      }
    } catch (e: unknown) {
      await this.presignaturePool.discard(sess.presignPoolKey, sess.presignatureId);
      return {
        ok: false,
        code: 'invalid_body',
        message: `Invalid clientSignatureShareB64u: ${String(e || 'decode failed')}`,
      };
    }

    const presignature = await this.presignaturePool.consume(
      sess.presignPoolKey,
      sess.presignatureId,
    );
    if (!presignature) {
      return {
        ok: false,
        code: 'internal',
        message: 'Reserved presignature is missing or expired (cannot finalize signature)',
      };
    }

    let digest32: Uint8Array;
    let entropy32: Uint8Array;
    let presignBigR33: Uint8Array;
    let relayerKShare32: Uint8Array;
    let relayerSigmaShare32: Uint8Array;
    let clientVerifyingShare33: Uint8Array;
    try {
      digest32 = base64UrlDecode(sess.signingDigestB64u);
      entropy32 = base64UrlDecode(sess.entropyB64u);
      presignBigR33 = base64UrlDecode(presignature.bigRB64u);
      relayerKShare32 = base64UrlDecode(presignature.kShareB64u);
      relayerSigmaShare32 = base64UrlDecode(presignature.sigmaShareB64u);
      clientVerifyingShare33 = base64UrlDecode(sess.clientVerifyingShareB64u);
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: `Failed to decode signing inputs: ${String(e || 'decode failed')}`,
      };
    }

    if (digest32.length !== 32)
      return {
        ok: false,
        code: 'internal',
        message: `signingDigestB64u must decode to 32 bytes, got ${digest32.length}`,
      };
    if (entropy32.length !== 32)
      return {
        ok: false,
        code: 'internal',
        message: `entropyB64u must decode to 32 bytes, got ${entropy32.length}`,
      };
    if (presignBigR33.length !== 33)
      return {
        ok: false,
        code: 'internal',
        message: `presignature.bigRB64u must decode to 33 bytes, got ${presignBigR33.length}`,
      };
    if (relayerKShare32.length !== 32)
      return {
        ok: false,
        code: 'internal',
        message: `presignature.kShareB64u must decode to 32 bytes, got ${relayerKShare32.length}`,
      };
    if (relayerSigmaShare32.length !== 32)
      return {
        ok: false,
        code: 'internal',
        message: `presignature.sigmaShareB64u must decode to 32 bytes, got ${relayerSigmaShare32.length}`,
      };
    if (clientVerifyingShare33.length !== 33)
      return {
        ok: false,
        code: 'internal',
        message: `clientVerifyingShareB64u must decode to 33 bytes, got ${clientVerifyingShare33.length}`,
      };

    let groupPublicKey33: Uint8Array;
    try {
      await validateSecp256k1PublicKey33(clientVerifyingShare33);
      groupPublicKey33 = await validateSecp256k1PublicKey33(
        base64UrlDecode(sess.thresholdEcdsaPublicKeyB64u),
      );
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: `Failed to resolve group public key: ${String(e || 'error')}`,
      };
    }

    const participantIds = normalizeThresholdEd25519ParticipantIds(sess.participantIds) || [
      ...this.participantIds2p,
    ];

    try {
      const sig65 = threshold_ecdsa_finalize_signature(
        new Uint32Array(participantIds),
        this.relayerParticipantId,
        groupPublicKey33,
        presignBigR33,
        relayerKShare32,
        relayerSigmaShare32,
        digest32,
        entropy32,
        clientSignatureShare32,
      );
      if (sig65.length !== 65) {
        return {
          ok: false,
          code: 'internal',
          message: `Invalid signature output (expected 65 bytes, got ${sig65.length})`,
        };
      }
      const r32 = sig65.slice(0, 32);
      const s32 = sig65.slice(32, 64);
      const recId = sig65[64]!;
      if (!Number.isFinite(recId) || recId < 0 || recId > 3) {
        return {
          ok: false,
          code: 'internal',
          message: `Invalid recovery id (expected 0..3, got ${recId})`,
        };
      }

      return {
        ok: true,
        relayerRound2: {
          signature65B64u: base64UrlEncode(sig65),
          rB64u: base64UrlEncode(r32),
          sB64u: base64UrlEncode(s32),
          recId,
        },
      };
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'finalize failed',
      );
      return { ok: false, code: 'invalid_body', message: msg };
    }
  }
}
