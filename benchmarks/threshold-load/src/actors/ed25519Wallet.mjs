import { readFileSync } from 'node:fs';
import bs58 from 'bs58';
import * as ed from '@noble/ed25519';
import {
  initSync as initWasmSignerSync,
  threshold_ed25519_build_near_tx_unsigned_borsh,
  threshold_ed25519_client_presign_create,
  threshold_ed25519_client_presign_sign,
  threshold_ed25519_compute_near_tx_signing_digests,
  threshold_ed25519_hss_verifying_share_from_signing_share,
  threshold_ed25519_keygen_from_client_verifying_share,
  threshold_ed25519_round1_commit,
  threshold_ed25519_round2_sign,
} from '../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import {
  thresholdEd25519FinalizeRequestIntegrityHash,
  thresholdEd25519NearTransactionOperationFingerprint,
} from '../../../../shared/src/threshold/ed25519OperationFingerprint.ts';

const THRESHOLD_ED25519_KEY_VERSION_V1 = 'threshold-ed25519-hss-v1';
const NEAR_NETWORK_ID = 'testnet';
const BENCHMARK_RUNTIME_POLICY_SCOPE = {
  orgId: 'benchmark-org',
  projectId: 'benchmark-project',
  envId: 'test',
  signingRootVersion: 'benchmark-root-v1',
};
let wasmReady = false;

function ensureSignerWasm() {
  if (wasmReady) return;
  const wasmBytes = readFileSync(
    new URL('../../../../wasm/near_signer/pkg/wasm_signer_worker_bg.wasm', import.meta.url),
  );
  initWasmSignerSync({ module: wasmBytes });
  wasmReady = true;
}

function base64UrlEncode(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

function randomBytes32() {
  return crypto.getRandomValues(new Uint8Array(32));
}

function scalarToLittleEndianBytes32(value) {
  const out = new Uint8Array(32);
  let remaining = value;
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
}

async function randomSigningShareB64u() {
  const extended = await ed.utils.getExtendedPublicKeyAsync(randomBytes32());
  return base64UrlEncode(scalarToLittleEndianBytes32(extended.scalar));
}

function deriveVerifyingShareB64u(signingShareB64u) {
  ensureSignerWasm();
  const result = threshold_ed25519_hss_verifying_share_from_signing_share({
    signingShareB64u,
  });
  const verifyingShareB64u = String(result?.verifyingShareB64u || '').trim();
  if (!verifyingShareB64u) {
    throw new Error('Failed to derive threshold-ed25519 verifying share');
  }
  return verifyingShareB64u;
}

function keygenFromClientVerifyingShare(input) {
  ensureSignerWasm();
  const result = threshold_ed25519_keygen_from_client_verifying_share({
    clientParticipantId: input.clientParticipantId,
    relayerParticipantId: input.relayerParticipantId,
    clientVerifyingShareB64u: input.clientVerifyingShareB64u,
  });
  const publicKey = String(result?.publicKey || '').trim();
  const relayerSigningShareB64u = String(result?.relayerSigningShareB64u || '').trim();
  const relayerVerifyingShareB64u = String(result?.relayerVerifyingShareB64u || '').trim();
  if (!publicKey || !relayerSigningShareB64u || !relayerVerifyingShareB64u) {
    throw new Error('Failed to derive threshold-ed25519 key material from client verifying share');
  }
  return { publicKey, relayerSigningShareB64u, relayerVerifyingShareB64u };
}

function testWebauthnAuthenticationPayload() {
  return {
    id: 'bench',
    rawId: 'bench',
    type: 'public-key',
    authenticatorAttachment: null,
    response: {
      clientDataJSON: 'bench',
      authenticatorData: 'bench',
      signature: 'bench',
      userHandle: null,
    },
    clientExtensionResults: null,
  };
}

function requireTrimmedString(value, message) {
  const out = String(value || '').trim();
  if (!out) throw new Error(message);
  return out;
}

function requireCommitments(value, message) {
  if (!value?.hiding || !value?.binding) throw new Error(message);
  return value;
}

export class Ed25519WalletActor {
  constructor(input) {
    this.walletIndex = input.walletIndex;
    this.baseUrl = input.baseUrl.replace(/\/+$/, '');
    this.nearAccountId = input.nearAccountId;
    this.receiverId = input.receiverId;
    this.rpId = input.rpId;
    this.clientParticipantId = Number(input.clientParticipantId || 1);
    this.relayerParticipantId = Number(input.relayerParticipantId || 2);
    this.sessionTtlMs = Number(input.sessionTtlMs || 300000);
    this.remainingUses = Number(input.remainingUses || 100);
    this.keyVersion = String(input.keyVersion || THRESHOLD_ED25519_KEY_VERSION_V1);
    this.sequence = 0;
    this.clientPresigns = [];
  }

  async bootstrap(input) {
    const startedAt = performance.now();
    this.xClientBaseB64u = await randomSigningShareB64u();
    this.clientVerifyingShareB64u = deriveVerifyingShareB64u(this.xClientBaseB64u);
    const keygen = keygenFromClientVerifyingShare({
      clientParticipantId: this.clientParticipantId,
      relayerParticipantId: this.relayerParticipantId,
      clientVerifyingShareB64u: this.clientVerifyingShareB64u,
    });
    this.xRelayerBaseB64u = keygen.relayerSigningShareB64u;
    this.relayerVerifyingShareB64u = keygen.relayerVerifyingShareB64u;
    this.publicKey = keygen.publicKey;
    this.relayerKeyId = this.publicKey;

    await input.putRelayerKeyMaterial({
      relayerKeyId: this.relayerKeyId,
      nearAccountId: this.nearAccountId,
      rpId: this.rpId,
      publicKey: this.publicKey,
      relayerSigningShareB64u: this.xRelayerBaseB64u,
      relayerVerifyingShareB64u: this.relayerVerifyingShareB64u,
      keyVersion: this.keyVersion,
      recoveryExportCapable: true,
    });
    input.markAccessKeyOnChain(this.nearAccountId, this.publicKey);

    const sessionId = `bench-threshold-session-${this.walletIndex}-${Date.now()}`;
    const sessionPolicy = {
      version: 'threshold_session_v1',
      nearAccountId: this.nearAccountId,
      rpId: this.rpId,
      relayerKeyId: this.relayerKeyId,
      sessionId,
      ttlMs: this.sessionTtlMs,
      remainingUses: this.remainingUses,
      runtimePolicyScope: BENCHMARK_RUNTIME_POLICY_SCOPE,
    };

    const sessionRes = await this.requestJson({
      route: '/threshold-ed25519/session',
      headers: { 'Content-Type': 'application/json' },
      body: {
        relayerKeyId: this.relayerKeyId,
        clientVerifyingShareB64u: this.clientVerifyingShareB64u,
        sessionPolicy,
        sessionKind: 'jwt',
        webauthn_authentication: testWebauthnAuthenticationPayload(),
      },
    });
    if (sessionRes.status !== 200 || !sessionRes.json?.ok) {
      throw new Error(`threshold session mint failed: ${sessionRes.text}`);
    }
    this.thresholdJwt = String(sessionRes.json?.jwt || '').trim();
    if (!this.thresholdJwt) {
      throw new Error('threshold session mint did not return a jwt');
    }

    return {
      bootstrapMs: Number((performance.now() - startedAt).toFixed(2)),
      sessionMintMs: sessionRes.durationMs,
      routeTimings: [{ route: '/threshold-ed25519/session', durationMs: sessionRes.durationMs }],
    };
  }

  async signOnce() {
    const startedAt = performance.now();
    const routeTimings = [];
    const signingPayload = this.buildNearTxSigningPayload();
    const digests = threshold_ed25519_compute_near_tx_signing_digests(signingPayload);
    if (!Array.isArray(digests) || !digests.length || !(digests[0] instanceof Uint8Array)) {
      throw new Error('Failed to compute threshold-ed25519 signing digest');
    }
    const signingDigestBytes = digests[0];
    const signingDigestB64u = base64UrlEncode(signingDigestBytes);

    const authorizeRes = await this.requestJson({
      route: '/threshold-ed25519/authorize',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.thresholdJwt}`,
      },
      body: {
        relayerKeyId: this.relayerKeyId,
        clientVerifyingShareB64u: this.clientVerifyingShareB64u,
        purpose: 'near_tx',
        signing_digest_32: Array.from(signingDigestBytes),
        signingPayload,
      },
    });
    routeTimings.push({
      route: '/threshold-ed25519/authorize',
      durationMs: authorizeRes.durationMs,
    });
    if (authorizeRes.status !== 200 || !authorizeRes.json?.ok) {
      throw new Error(`threshold authorize failed: ${authorizeRes.text}`);
    }
    const mpcSessionId = String(authorizeRes.json?.mpcSessionId || '').trim();
    if (!mpcSessionId) {
      throw new Error('threshold authorize did not return mpcSessionId');
    }

    const clientRound1 = threshold_ed25519_round1_commit(this.xClientBaseB64u);
    const clientNoncesB64u = String(clientRound1?.relayerNoncesB64u || '').trim();
    const clientCommitments = clientRound1?.relayerCommitments;
    if (!clientNoncesB64u || !clientCommitments?.hiding || !clientCommitments?.binding) {
      throw new Error('client round1 commit failed');
    }

    const signInitRes = await this.requestJson({
      route: '/threshold-ed25519/sign/init',
      headers: { 'Content-Type': 'application/json' },
      body: {
        mpcSessionId,
        relayerKeyId: this.relayerKeyId,
        nearAccountId: this.nearAccountId,
        signingDigestB64u,
        clientCommitments,
      },
    });
    routeTimings.push({
      route: '/threshold-ed25519/sign/init',
      durationMs: signInitRes.durationMs,
    });
    if (signInitRes.status !== 200 || !signInitRes.json?.ok) {
      throw new Error(`threshold sign/init failed: ${signInitRes.text}`);
    }
    const signingSessionId = String(signInitRes.json?.signingSessionId || '').trim();
    if (!signingSessionId) {
      throw new Error('threshold sign/init did not return signingSessionId');
    }

    const commitmentsById = signInitRes.json?.commitmentsById || {};
    const relayerCommitments = commitmentsById[String(this.relayerParticipantId)];
    if (!relayerCommitments?.hiding || !relayerCommitments?.binding) {
      throw new Error('threshold sign/init did not return relayer commitments');
    }

    const clientRound2 = threshold_ed25519_round2_sign({
      clientParticipantId: this.relayerParticipantId,
      relayerParticipantId: this.clientParticipantId,
      relayerSigningShareB64u: this.xClientBaseB64u,
      relayerNoncesB64u: clientNoncesB64u,
      groupPublicKey: this.publicKey,
      signingDigestB64u,
      clientCommitments: relayerCommitments,
      relayerCommitments: clientCommitments,
    });
    const clientSignatureShareB64u = String(clientRound2?.relayerSignatureShareB64u || '').trim();
    if (!clientSignatureShareB64u) {
      throw new Error('client round2 sign failed');
    }

    const finalizeRes = await this.requestJson({
      route: '/threshold-ed25519/sign/finalize',
      headers: { 'Content-Type': 'application/json' },
      body: {
        signingSessionId,
        clientSignatureShareB64u,
      },
    });
    routeTimings.push({
      route: '/threshold-ed25519/sign/finalize',
      durationMs: finalizeRes.durationMs,
    });
    if (finalizeRes.status !== 200 || !finalizeRes.json?.ok) {
      throw new Error(`threshold sign/finalize failed: ${finalizeRes.text}`);
    }
    const relayerSignatureShare =
      finalizeRes.json?.relayerSignatureSharesById?.[String(this.relayerParticipantId)];
    if (!relayerSignatureShare) {
      throw new Error('threshold sign/finalize did not return relayer signature share');
    }

    this.sequence += 1;
    return {
      endToEndMs: Number((performance.now() - startedAt).toFixed(2)),
      routeTimings,
    };
  }

  createClientPresignOffer() {
    ensureSignerWasm();
    const clientPresign = threshold_ed25519_client_presign_create({
      clientParticipantId: this.clientParticipantId,
      relayerParticipantId: this.relayerParticipantId,
      xClientBaseB64u: this.xClientBaseB64u,
      groupPublicKey: this.publicKey,
    });
    const clientPresignId = `bench-client-presign-${this.walletIndex}-${Date.now()}-${crypto.randomUUID()}`;
    return {
      clientPresignId,
      nonceHandle: requireTrimmedString(
        clientPresign?.clientNonceHandleB64u,
        'client presign create did not return a nonce handle',
      ),
      clientVerifyingShareB64u: requireTrimmedString(
        clientPresign?.clientVerifyingShareB64u,
        'client presign create did not return a verifying share',
      ),
      clientCommitments: requireCommitments(
        clientPresign?.clientCommitments,
        'client presign create did not return commitments',
      ),
    };
  }

  async refillPresigns(input = {}) {
    const startedAt = performance.now();
    const count = Math.max(1, Math.floor(Number(input.count || 1)));
    const offers = Array.from({ length: count }, () => this.createClientPresignOffer());
    const refillRes = await this.requestJson({
      route: '/threshold-ed25519/presign/refill',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.thresholdJwt}`,
      },
      body: {
        kind: 'threshold_ed25519_presign_refill_v1',
        relayerKeyId: this.relayerKeyId,
        nearAccountId: this.nearAccountId,
        nearNetworkId: NEAR_NETWORK_ID,
        expectedSignerPublicKey: this.publicKey,
        participantIds: [this.clientParticipantId, this.relayerParticipantId],
        clientPresigns: offers.map((offer) => ({
          clientPresignId: offer.clientPresignId,
          clientVerifyingShareB64u: offer.clientVerifyingShareB64u,
          clientCommitments: offer.clientCommitments,
        })),
        requestTag: input.requestTag || 'background_presign_pool_refill',
      },
    });
    if (refillRes.status !== 200 || !refillRes.json?.ok) {
      throw new Error(`threshold presign/refill failed: ${refillRes.text}`);
    }

    const offersById = new Map(offers.map((offer) => [offer.clientPresignId, offer]));
    const accepted = Array.isArray(refillRes.json.accepted) ? refillRes.json.accepted : [];
    for (const pair of accepted) {
      const offer = offersById.get(String(pair?.clientPresignId || ''));
      if (!offer) continue;
      this.clientPresigns.push({
        presignId: requireTrimmedString(
          pair?.presignId,
          'presign refill accepted an empty presign id',
        ),
        nonceHandle: offer.nonceHandle,
        clientCommitments: offer.clientCommitments,
        relayerCommitments: requireCommitments(
          pair?.relayerCommitments,
          'presign refill accepted without relayer commitments',
        ),
      });
    }

    return {
      endToEndMs: Number((performance.now() - startedAt).toFixed(2)),
      routeTimings: [
        {
          route: '/threshold-ed25519/presign/refill',
          durationMs: refillRes.durationMs,
        },
      ],
      accepted: accepted.length,
      rejected: Array.isArray(refillRes.json.rejectedClientPresignIds)
        ? refillRes.json.rejectedClientPresignIds.length
        : 0,
    };
  }

  buildUnsignedNearTx() {
    ensureSignerWasm();
    const signingPayload = this.buildNearTxSigningPayload();
    const unsigned = threshold_ed25519_build_near_tx_unsigned_borsh(signingPayload);
    const firstUnsigned = Array.isArray(unsigned) ? unsigned[0] : null;
    return {
      transactions: signingPayload.txSigningRequests,
      unsignedTransactionBorshB64u: requireTrimmedString(
        firstUnsigned?.unsignedTransactionBorshB64u,
        'failed to build unsigned NEAR transaction borsh',
      ),
      signingDigestB64u: requireTrimmedString(
        firstUnsigned?.signingDigestB64u,
        'failed to build unsigned NEAR transaction digest',
      ),
    };
  }

  async createFinalizeAndDispatchBody(input) {
    const clientSignature = threshold_ed25519_client_presign_sign({
      clientParticipantId: this.clientParticipantId,
      relayerParticipantId: this.relayerParticipantId,
      xClientBaseB64u: this.xClientBaseB64u,
      groupPublicKey: this.publicKey,
      signingDigestB64u: input.unsigned.signingDigestB64u,
      clientNonceHandleB64u: input.presign.nonceHandle,
      clientCommitments: input.presign.clientCommitments,
      relayerCommitments: input.presign.relayerCommitments,
    });
    const operationId =
      input.operationId ||
      `bench-ed25519-presign-${this.walletIndex}-${Date.now()}-${this.sequence + 1}`;
    const request = {
      kind: 'threshold_ed25519_finalize_and_dispatch_near_tx_v1',
      operation: {
        kind: 'threshold_ed25519_signing_operation_v1',
        operationId,
        operationFingerprint: 'pending',
        purpose: 'near_transaction',
      },
      presignId: input.presign.presignId,
      relayerKeyId: this.relayerKeyId,
      nearAccountId: this.nearAccountId,
      nearNetworkId: NEAR_NETWORK_ID,
      expectedSignerPublicKey: this.publicKey,
      transactions: input.unsigned.transactions,
      unsignedTransactionBorshB64u: input.unsigned.unsignedTransactionBorshB64u,
      signingDigestB64u: input.unsigned.signingDigestB64u,
      clientSignatureShareB64u: requireTrimmedString(
        clientSignature?.clientSignatureShareB64u,
        'client presign sign did not return a signature share',
      ),
      dispatch: { kind: 'near_rpc_configured_default_v1' },
    };
    request.operation.operationFingerprint =
      await thresholdEd25519NearTransactionOperationFingerprint({
        nearAccountId: this.nearAccountId,
        nearNetworkId: NEAR_NETWORK_ID,
        relayerKeyId: this.relayerKeyId,
        signerPublicKey: this.publicKey,
        transactions: input.unsigned.transactions,
        unsignedTransactionBorshB64u: input.unsigned.unsignedTransactionBorshB64u,
        signingDigestB64u: input.unsigned.signingDigestB64u,
      });
    request.requestIntegrityHash = await thresholdEd25519FinalizeRequestIntegrityHash(request);
    return request;
  }

  async finalizeAndDispatchPresignBody(body) {
    const finalizeRes = await this.requestJson({
      route: '/threshold-ed25519/sign/finalize-and-dispatch',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.thresholdJwt}`,
      },
      body,
    });
    return {
      routeTiming: {
        route: '/threshold-ed25519/sign/finalize-and-dispatch',
        durationMs: finalizeRes.durationMs,
      },
      response: finalizeRes,
    };
  }

  async signOnceWithPresignPoolHit() {
    const startedAt = performance.now();
    const presign = this.clientPresigns.shift();
    if (!presign) {
      throw new Error('threshold presign pool is empty');
    }
    const unsigned = this.buildUnsignedNearTx();
    const body = await this.createFinalizeAndDispatchBody({ presign, unsigned });
    const finalized = await this.finalizeAndDispatchPresignBody(body);
    if (finalized.response.status !== 200 || !finalized.response.json?.ok) {
      throw new Error(`threshold finalize-and-dispatch failed: ${finalized.response.text}`);
    }
    this.sequence += 1;
    return {
      endToEndMs: Number((performance.now() - startedAt).toFixed(2)),
      routeTimings: [finalized.routeTiming],
      poolHit: true,
    };
  }

  async exerciseDoubleConsumePressure() {
    const startedAt = performance.now();
    const refill = await this.refillPresigns({
      count: 1,
      requestTag: 'foreground_presign_pool_refill',
    });
    const presign = this.clientPresigns.shift();
    if (!presign) {
      throw new Error('threshold double-consume scenario did not receive a presign');
    }
    const unsigned = this.buildUnsignedNearTx();
    const body = await this.createFinalizeAndDispatchBody({
      presign,
      unsigned,
      operationId: `bench-ed25519-double-consume-${this.walletIndex}-${Date.now()}`,
    });
    const attempts = await Promise.all([
      this.finalizeAndDispatchPresignBody(body),
      this.finalizeAndDispatchPresignBody(body),
    ]);
    const okCount = attempts.filter(
      (entry) => entry.response.status === 200 && entry.response.json?.ok,
    ).length;
    const rejectedCodes = attempts
      .filter((entry) => !(entry.response.status === 200 && entry.response.json?.ok))
      .map((entry) => String(entry.response.json?.code || entry.response.status || 'unknown'));
    if (okCount !== 1 || rejectedCodes.length !== 1) {
      throw new Error(
        `threshold double-consume pressure expected one success and one rejection, got ok=${okCount} rejected=${rejectedCodes.join(',')}`,
      );
    }
    this.sequence += 1;
    return {
      endToEndMs: Number((performance.now() - startedAt).toFixed(2)),
      routeTimings: [refill.routeTimings[0], ...attempts.map((entry) => entry.routeTiming)],
      poolHit: true,
      doubleConsumeOk: okCount,
      doubleConsumeRejected: rejectedCodes.length,
      doubleConsumeRejectedCodes: rejectedCodes,
    };
  }

  buildNearTxSigningPayload() {
    const txBlockHashBytes = randomBytes32();
    return {
      kind: 'near_tx',
      txSigningRequests: [
        {
          nearAccountId: this.nearAccountId,
          receiverId: this.receiverId,
          actions: [{ action_type: 'Transfer', deposit: '1' }],
        },
      ],
      transactionContext: {
        nearPublicKeyStr: this.publicKey,
        nextNonce: String(this.sequence + 1),
        txBlockHeight: String(1 + this.sequence),
        txBlockHash: bs58.encode(txBlockHashBytes),
      },
    };
  }

  async requestJson(input) {
    const startedAt = performance.now();
    const response = await fetch(`${this.baseUrl}${input.route}`, {
      method: 'POST',
      headers: input.headers,
      body: JSON.stringify(input.body),
    });
    const text = await response.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    return {
      status: response.status,
      text,
      json,
      durationMs: Number((performance.now() - startedAt).toFixed(2)),
    };
  }
}
