import { base64UrlDecode } from '@shared/utils/encoders';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { NormalizedLogger } from '../logger';
import type {
  ThresholdEd25519AuthorityScope,
  ThresholdEd25519CosignFinalizeRequest,
  ThresholdEd25519CosignFinalizeResponse,
  ThresholdEd25519CosignInitRequest,
  ThresholdEd25519CosignInitResponse,
} from '../types';
import {
  threshold_ed25519_round2_sign_cosigner,
} from '../../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import type {
  ThresholdEd25519Commitments,
  ThresholdEd25519CommitmentsById,
  ThresholdEd25519SessionStore,
} from './stores/SessionStore';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import type { ThresholdNodeRole } from './config';
import type {
  ParsedThresholdEd25519MpcSession,
  ThresholdEd25519CosignerGrantV1,
} from './coordinatorGrant';
import { verifyThresholdEd25519CosignerGrantV1 } from './coordinatorGrant';
import {
  lagrangeCoefficientAtZeroForCosigner,
  multiplyEd25519ScalarB64uByScalarBytesLE32,
  normalizeCosignerIds,
} from './cosigners';
import { createThresholdEd25519RelayerPresignMaterial } from './ed25519PresignRound1';
import { expectThresholdEd25519Round2SignWasmOutput } from './ed25519PresignRound2';
import { thresholdEd25519AuthorityScopesMatch } from './validation';

type ParseOk<T> = { ok: true; value: T };
type ParseErr = { ok: false; code: string; message: string };
type ParseResult<T> = ParseOk<T> | ParseErr;

function authorityScopesMatch(
  left: ThresholdEd25519AuthorityScope,
  right: ThresholdEd25519AuthorityScope,
): boolean {
  return thresholdEd25519AuthorityScopesMatch(left, right);
}

function parseCommitments(input: unknown, label: string): ParseResult<ThresholdEd25519Commitments> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, code: 'invalid_body', message: `${label}{hiding,binding} are required` };
  }
  const rec = input as Record<string, unknown>;
  const hiding = toOptionalTrimmedString(rec.hiding);
  const binding = toOptionalTrimmedString(rec.binding);
  if (!hiding || !binding) {
    return { ok: false, code: 'invalid_body', message: `${label}{hiding,binding} are required` };
  }
  return { ok: true, value: { hiding, binding } };
}

function parseThresholdEd25519CosignInitRequest(
  request: ThresholdEd25519CosignInitRequest,
): ParseResult<{
  signingSessionId: string;
  cosignerShareB64u: string;
  clientCommitments: ThresholdEd25519Commitments;
}> {
  const signingSessionId = toOptionalTrimmedString(request.signingSessionId);
  if (!signingSessionId)
    return { ok: false, code: 'invalid_body', message: 'signingSessionId is required' };

  const cosignerShareB64u = toOptionalTrimmedString(request.cosignerShareB64u);
  if (!cosignerShareB64u)
    return { ok: false, code: 'invalid_body', message: 'cosignerShareB64u is required' };
  try {
    const decoded = base64UrlDecode(cosignerShareB64u);
    if (decoded.length !== 32) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `cosignerShareB64u must be 32 bytes, got ${decoded.length}`,
      };
    }
  } catch (e: unknown) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `Invalid cosignerShareB64u: ${String(e || 'decode failed')}`,
    };
  }

  const commitments = parseCommitments(
    (request as unknown as { clientCommitments?: unknown }).clientCommitments,
    'clientCommitments',
  );
  if (!commitments.ok) return commitments;

  return {
    ok: true,
    value: { signingSessionId, cosignerShareB64u, clientCommitments: commitments.value },
  };
}

function parseThresholdEd25519CosignFinalizeRequest(
  request: ThresholdEd25519CosignFinalizeRequest,
): ParseResult<{
  signingSessionId: string;
  cosignerIds: number[];
  groupPublicKey: string;
  relayerCommitments: ThresholdEd25519Commitments;
}> {
  const signingSessionId = toOptionalTrimmedString(request.signingSessionId);
  if (!signingSessionId)
    return { ok: false, code: 'invalid_body', message: 'signingSessionId is required' };

  const groupPublicKey = toOptionalTrimmedString(request.groupPublicKey);
  if (!groupPublicKey)
    return { ok: false, code: 'invalid_body', message: 'groupPublicKey is required' };

  const cosignerIds = normalizeCosignerIds(
    (request as unknown as { cosignerIds?: unknown }).cosignerIds,
  );
  if (!cosignerIds)
    return {
      ok: false,
      code: 'invalid_body',
      message: 'cosignerIds must be a non-empty list of u16 ids',
    };

  const relayerCommitments = parseCommitments(
    (request as unknown as { relayerCommitments?: unknown }).relayerCommitments,
    'relayerCommitments',
  );
  if (!relayerCommitments.ok) return relayerCommitments;

  return {
    ok: true,
    value: {
      signingSessionId,
      cosignerIds,
      groupPublicKey,
      relayerCommitments: relayerCommitments.value,
    },
  };
}

function requireParticipantIdsIncludeSignerSet(
  raw: unknown,
  signerSet2p: number[],
  label: string,
): ParseResult<number[]> {
  const expected = normalizeThresholdEd25519ParticipantIds(signerSet2p) || [...signerSet2p];
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw) || [...expected];

  for (const id of expected) {
    if (!participantIds.includes(id)) {
      return {
        ok: false,
        code: 'unauthorized',
        message: `${label} does not include the server signer set (expected participantIds to include [${expected.join(',')}])`,
      };
    }
  }

  return { ok: true, value: participantIds };
}

export class ThresholdEd25519SigningHandlers {
  private readonly logger: NormalizedLogger;
  private readonly nodeRole: ThresholdNodeRole;
  private readonly relayerCosignerId: number | null;
  private readonly coordinatorSharedSecretBytes: Uint8Array | null;
  private coordinatorHmacKeyPromise: Promise<CryptoKey> | null = null;
  private readonly clientParticipantId: number;
  private readonly relayerParticipantId: number;
  private readonly participantIds2p: number[];
  private readonly sessionStore: ThresholdEd25519SessionStore;
  private readonly ensureReady: () => Promise<void>;
  private readonly ensureSignerWasm: () => Promise<void>;

  constructor(input: {
    logger: NormalizedLogger;
    nodeRole: ThresholdNodeRole;
    relayerCosignerId: number | null;
    coordinatorSharedSecretBytes: Uint8Array | null;
    clientParticipantId: number;
    relayerParticipantId: number;
    participantIds2p: number[];
    sessionStore: ThresholdEd25519SessionStore;
    ensureReady: () => Promise<void>;
    ensureSignerWasm: () => Promise<void>;
  }) {
    this.logger = input.logger;
    this.nodeRole = input.nodeRole;
    this.relayerCosignerId = input.relayerCosignerId;
    this.coordinatorSharedSecretBytes = input.coordinatorSharedSecretBytes;
    this.clientParticipantId = input.clientParticipantId;
    this.relayerParticipantId = input.relayerParticipantId;
    this.participantIds2p = input.participantIds2p;
    this.sessionStore = input.sessionStore;
    this.ensureReady = input.ensureReady;
    this.ensureSignerWasm = input.ensureSignerWasm;
  }

  private logResult(
    route: string,
    startedAtMs: number,
    result: { ok: boolean; code?: string; message?: string },
    extra?: Record<string, unknown>,
  ): void {
    const elapsedMs = Math.max(0, Date.now() - startedAtMs);
    const msg = typeof result.message === 'string' ? result.message : undefined;
    const message = msg && msg.length > 300 ? `${msg.slice(0, 297)}...` : msg;
    const payload = {
      route,
      ok: result.ok,
      ...(result.code ? { code: result.code } : {}),
      ...(!result.ok && message ? { message } : {}),
      elapsedMs,
      ...(extra || {}),
    };
    if (result.ok) {
      this.logger.info('[threshold-ed25519] response', payload);
      return;
    }
    if (result.code === 'internal') {
      this.logger.error('[threshold-ed25519] response', payload);
      return;
    }
    this.logger.warn('[threshold-ed25519] response', payload);
  }

  private async verifyCosignerGrant(token: unknown): Promise<
    | {
        ok: true;
        grant: ThresholdEd25519CosignerGrantV1;
        mpcSession: ParsedThresholdEd25519MpcSession;
      }
    | { ok: false; code: string; message: string }
  > {
    const verified = await verifyThresholdEd25519CosignerGrantV1({
      secretBytes: this.coordinatorSharedSecretBytes,
      keyPromise: this.coordinatorHmacKeyPromise,
      token,
    });
    this.coordinatorHmacKeyPromise = verified.keyPromise;
    if (!verified.ok) return verified;
    return { ok: true, grant: verified.grant, mpcSession: verified.mpcSession };
  }

  async thresholdEd25519CosignInit(
    request: ThresholdEd25519CosignInitRequest,
  ): Promise<ThresholdEd25519CosignInitResponse> {
    const route = 'router_ab_ed25519_internal_cosign_init';
    const startedAtMs = Date.now();
    const cosignerId = this.relayerCosignerId;
    const logExtra = cosignerId ? { cosignerId } : undefined;

    const result = await (async (): Promise<ThresholdEd25519CosignInitResponse> => {
      if (!cosignerId || (this.nodeRole !== 'cosigner' && this.nodeRole !== 'coordinator')) {
        return {
          ok: false,
          code: 'not_found',
          message:
            'threshold-ed25519 cosigner endpoints are not enabled on this server (set THRESHOLD_NODE_ROLE=cosigner)',
        };
      }

      await this.ensureReady();
      const parsedRequest = parseThresholdEd25519CosignInitRequest(request);
      if (!parsedRequest.ok) return parsedRequest;
      const { signingSessionId, cosignerShareB64u, clientCommitments } = parsedRequest.value;

      this.logger.info('[threshold-ed25519] request', {
        route,
        signingSessionId,
        cosignerId,
        cosignerShareB64u_len: cosignerShareB64u.length,
      });

      const verified = await this.verifyCosignerGrant(request.coordinatorGrant);
      if (!verified.ok) {
        return { ok: false, code: verified.code, message: verified.message };
      }
      const { grant, mpcSession } = verified;

      if (grant.cosignerId !== cosignerId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'coordinatorGrant does not match this cosigner id',
        };
      }

      const participantIdsRes = requireParticipantIdsIncludeSignerSet(
        mpcSession.participantIds,
        this.participantIds2p,
        'coordinatorGrant',
      );
      if (!participantIdsRes.ok) return participantIdsRes;

      await this.ensureSignerWasm();
      const commit = createThresholdEd25519RelayerPresignMaterial(cosignerShareB64u);

      const ttlMs = 60_000;
      const expiresAtMs = Date.now() + ttlMs;
      const commitmentsById: ThresholdEd25519CommitmentsById = {
        [String(this.clientParticipantId)]: clientCommitments,
      };

      await this.sessionStore.putSigningSession(
        signingSessionId,
        {
          expiresAtMs,
          mpcSessionId: grant.mpcSessionId,
          relayerKeyId: mpcSession.relayerKeyId,
          signingDigestB64u: mpcSession.signingDigestB64u,
          userId: mpcSession.userId,
          authorityScope: mpcSession.authorityScope,
          commitmentsById,
          signingShare: {
            kind: 'embedded_cosigner_share',
            relayerSigningShareB64u: cosignerShareB64u,
          },
          relayerNoncesB64u: commit.relayerNoncesB64u,
          participantIds: [...this.participantIds2p],
        },
        ttlMs,
      );

      return { ok: true, relayerCommitments: commit.relayerCommitments };
    })().catch((e: unknown) => {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Internal error',
      );
      return { ok: false, code: 'internal', message: msg };
    });

    this.logResult(route, startedAtMs, result, logExtra);
    return result;
  }

  async thresholdEd25519CosignFinalize(
    request: ThresholdEd25519CosignFinalizeRequest,
  ): Promise<ThresholdEd25519CosignFinalizeResponse> {
    const route = 'router_ab_ed25519_internal_cosign_finalize';
    const startedAtMs = Date.now();
    const cosignerId = this.relayerCosignerId;
    const logExtra = cosignerId ? { cosignerId } : undefined;

    const result = await (async (): Promise<ThresholdEd25519CosignFinalizeResponse> => {
      if (!cosignerId || (this.nodeRole !== 'cosigner' && this.nodeRole !== 'coordinator')) {
        return {
          ok: false,
          code: 'not_found',
          message:
            'threshold-ed25519 cosigner endpoints are not enabled on this server (set THRESHOLD_NODE_ROLE=cosigner)',
        };
      }

      await this.ensureReady();
      const parsedRequest = parseThresholdEd25519CosignFinalizeRequest(request);
      if (!parsedRequest.ok) return parsedRequest;
      const { signingSessionId, cosignerIds, groupPublicKey, relayerCommitments } =
        parsedRequest.value;

      this.logger.info('[threshold-ed25519] request', {
        route,
        signingSessionId,
        cosignerId,
        cosignerIds,
      });

      const verified = await this.verifyCosignerGrant(request.coordinatorGrant);
      if (!verified.ok) {
        return { ok: false, code: verified.code, message: verified.message };
      }
      const { grant, mpcSession } = verified;

      if (grant.cosignerId !== cosignerId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'coordinatorGrant does not match this cosigner id',
        };
      }

      if (!cosignerIds.includes(cosignerId)) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'cosignerIds must include this cosigner id',
        };
      }

      const sess = await this.sessionStore.takeSigningSession(signingSessionId);
      if (!sess) {
        return { ok: false, code: 'unauthorized', message: 'signingSessionId expired or invalid' };
      }
      if (Date.now() > sess.expiresAtMs) {
        return { ok: false, code: 'unauthorized', message: 'signingSessionId expired' };
      }

      const restoreOnMismatch = async (): Promise<void> => {
        const ttlMs = Math.max(0, sess.expiresAtMs - Date.now());
        if (!ttlMs) return;
        await this.sessionStore.putSigningSession(signingSessionId, sess, ttlMs);
      };

      if (sess.mpcSessionId !== grant.mpcSessionId) {
        await restoreOnMismatch();
        return {
          ok: false,
          code: 'unauthorized',
          message: 'signingSessionId does not match coordinatorGrant scope',
        };
      }
      if (sess.relayerKeyId !== mpcSession.relayerKeyId) {
        await restoreOnMismatch();
        return {
          ok: false,
          code: 'unauthorized',
          message: 'signingSessionId does not match coordinatorGrant scope',
        };
      }
      if (sess.signingDigestB64u !== mpcSession.signingDigestB64u) {
        await restoreOnMismatch();
        return {
          ok: false,
          code: 'unauthorized',
          message: 'signingSessionId does not match coordinatorGrant scope',
        };
      }
      if (sess.userId !== mpcSession.userId) {
        await restoreOnMismatch();
        return {
          ok: false,
          code: 'unauthorized',
          message: 'signingSessionId does not match coordinatorGrant scope',
        };
      }
      if (!authorityScopesMatch(sess.authorityScope, mpcSession.authorityScope)) {
        await restoreOnMismatch();
        return {
          ok: false,
          code: 'unauthorized',
          message: 'signingSessionId does not match coordinatorGrant scope',
        };
      }
      let storedShareB64u: string;
      switch (sess.signingShare.kind) {
        case 'embedded_cosigner_share':
          storedShareB64u = sess.signingShare.relayerSigningShareB64u;
          break;
        case 'key_store':
          return {
            ok: false,
            code: 'internal',
            message: 'cosigner signing session missing share material',
          };
        default:
          return assertNeverSigningShareMaterial(sess.signingShare);
      }

      await this.ensureSignerWasm();
      const lambdaRes = lagrangeCoefficientAtZeroForCosigner({ cosignerId, cosignerIds });
      if (!lambdaRes.ok) {
        return { ok: false, code: lambdaRes.code, message: lambdaRes.message };
      }

      const effShare = multiplyEd25519ScalarB64uByScalarBytesLE32({
        scalarB64u: storedShareB64u,
        factorBytesLE32: lambdaRes.lambda,
      });
      if (!effShare.ok) {
        return { ok: false, code: effShare.code, message: effShare.message };
      }
      const clientCommitments = sess.commitmentsById?.[String(this.clientParticipantId)];
      if (!clientCommitments) {
        return {
          ok: false,
          code: 'internal',
          message: 'signingSessionId missing client commitments',
        };
      }
      const out = expectThresholdEd25519Round2SignWasmOutput(
        threshold_ed25519_round2_sign_cosigner({
          clientParticipantId: this.clientParticipantId,
          relayerParticipantId: this.relayerParticipantId,
          relayerSigningShareB64u: effShare.scalarB64u,
          relayerNoncesB64u: sess.relayerNoncesB64u,
          groupPublicKey,
          signingDigestB64u: sess.signingDigestB64u,
          clientCommitments,
          relayerCommitments,
        }),
      );

      return { ok: true, relayerSignatureShareB64u: out.relayerSignatureShareB64u };
    })().catch((e: unknown) => {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Internal error',
      );
      return { ok: false, code: 'internal', message: msg };
    });

    this.logResult(route, startedAtMs, result, logExtra);
    return result;
  }
}

function assertNeverSigningShareMaterial(value: never): never {
  throw new Error(`Unhandled threshold-ed25519 signing share source: ${String(value)}`);
}
