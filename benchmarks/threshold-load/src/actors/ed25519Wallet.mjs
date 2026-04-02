import { readFileSync } from 'node:fs';
import bs58 from 'bs58';
import * as ed from '@noble/ed25519';
import {
  initSync as initWasmSignerSync,
  threshold_ed25519_compute_near_tx_signing_digests,
  threshold_ed25519_hss_public_key_from_base_shares,
  threshold_ed25519_hss_verifying_share_from_signing_share,
  threshold_ed25519_round1_commit,
  threshold_ed25519_round2_sign,
} from '../../../../wasm/near_signer/pkg/wasm_signer_worker.js';

const THRESHOLD_ED25519_KEY_VERSION_V1 = 'threshold-ed25519-hss-v1';
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

function nearPublicKeyFromBaseShares(xClientBaseB64u, xRelayerBaseB64u) {
  ensureSignerWasm();
  const result = threshold_ed25519_hss_public_key_from_base_shares({
    xClientBaseB64u,
    xRelayerBaseB64u,
  });
  const publicKeyB64u = String(result?.publicKeyB64u || '').trim();
  if (!publicKeyB64u) {
    throw new Error('Failed to derive threshold-ed25519 public key from base shares');
  }
  return `ed25519:${bs58.encode(Buffer.from(publicKeyB64u, 'base64url'))}`;
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
  }

  async bootstrap(input) {
    const startedAt = performance.now();
    this.xClientBaseB64u = await randomSigningShareB64u();
    this.clientVerifyingShareB64u = deriveVerifyingShareB64u(this.xClientBaseB64u);
    this.xRelayerBaseB64u = await randomSigningShareB64u();
    this.relayerVerifyingShareB64u = deriveVerifyingShareB64u(this.xRelayerBaseB64u);
    this.publicKey = nearPublicKeyFromBaseShares(this.xClientBaseB64u, this.xRelayerBaseB64u);
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
