import type { KeyRef, SignRequest, SignatureBytes, Signer } from '../../interfaces/signing';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  deriveThresholdSecp256k1ClientShareWasm,
} from '../wasm/ethSignerWasm';
import { authorizeEcdsaWithSession } from '../../threshold/workflows/authorizeEcdsa';
import {
  getCachedEcdsaAuthSession,
  getCachedEcdsaAuthSessionJwt,
  makeEcdsaAuthSessionCacheKey,
} from '../../threshold/session/ecdsaAuthSession';
import { signThresholdEcdsaDigestWithPool } from '../../orchestration/walletOrigin/thresholdEcdsaCoordinator';

type EcdsaSessionKind = 'jwt' | 'cookie';

export type ThresholdEcdsaPrfFirstDispenseFn = (args: {
  sessionId: string;
  uses?: number;
}) => Promise<
  | { ok: true; prfFirstB64u: string; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string }
>;

export class Secp256k1Engine implements Signer {
  readonly algorithm = 'secp256k1' as const;

  private readonly getRpId?: () => string | null;
  private readonly dispenseThresholdEcdsaPrfFirstForSession?: ThresholdEcdsaPrfFirstDispenseFn;
  private readonly workerCtx: WorkerOperationContext;

  constructor(opts: {
    getRpId?: () => string | null;
    dispenseThresholdEcdsaPrfFirstForSession?: ThresholdEcdsaPrfFirstDispenseFn;
    workerCtx: WorkerOperationContext;
  }) {
    this.getRpId = opts.getRpId;
    this.dispenseThresholdEcdsaPrfFirstForSession = opts.dispenseThresholdEcdsaPrfFirstForSession;
    this.workerCtx = opts.workerCtx;
  }

  async sign(req: SignRequest, keyRef: KeyRef): Promise<SignatureBytes> {
    if (req.kind !== 'digest' || req.algorithm !== 'secp256k1') {
      throw new Error('[Secp256k1Engine] unsupported sign request');
    }
    if (req.digest32.length !== 32) {
      throw new Error('[Secp256k1Engine] digest32 must be 32 bytes');
    }

    if (keyRef.type !== 'threshold-ecdsa-secp256k1') {
      throw new Error('[Secp256k1Engine] runtime signing requires threshold-ecdsa-secp256k1 keyRef');
    }

    const rpId = this.getRpId?.() || null;
    const cacheKeyCandidates: string[] = [];
    if (rpId) {
      cacheKeyCandidates.push(
        makeEcdsaAuthSessionCacheKey({
          userId: keyRef.userId,
          rpId,
          relayerUrl: keyRef.relayerUrl,
          relayerKeyId: keyRef.relayerKeyId,
          participantIds: keyRef.participantIds,
        }),
      );

      // Fallback for callers still holding pre-session keyRefs without participant ids.
      if (!Array.isArray(keyRef.participantIds) || keyRef.participantIds.length === 0) {
        cacheKeyCandidates.push(
          makeEcdsaAuthSessionCacheKey({
            userId: keyRef.userId,
            rpId,
            relayerUrl: keyRef.relayerUrl,
            relayerKeyId: keyRef.relayerKeyId,
            participantIds: [1, 2],
          }),
        );
      }
    }

    let resolvedCacheKey: string | null = null;
    let cachedThresholdSession: ReturnType<typeof getCachedEcdsaAuthSession> = null;
    for (const candidate of cacheKeyCandidates) {
      const cached = getCachedEcdsaAuthSession(candidate);
      if (cached) {
        resolvedCacheKey = candidate;
        cachedThresholdSession = cached;
        break;
      }
      if (!resolvedCacheKey) {
        // Keep the first candidate so JWT lookup can still succeed when only token survives.
        resolvedCacheKey = candidate;
      }
    }

    const sessionKind: EcdsaSessionKind = keyRef.thresholdSessionKind || 'jwt';
    const thresholdSessionJwt = sessionKind === 'jwt'
      ? (
          (resolvedCacheKey ? getCachedEcdsaAuthSessionJwt(resolvedCacheKey) : undefined)
          || keyRef.thresholdSessionJwt
        )
      : undefined;

    if (sessionKind === 'jwt' && !thresholdSessionJwt) {
      throw new Error('[multichain] No cached threshold-ecdsa session token; call connectEcdsaSession first');
    }

    const purpose = String(req.label || 'secp256k1');
    const authorized = await authorizeEcdsaWithSession({
      relayerUrl: keyRef.relayerUrl,
      relayerKeyId: keyRef.relayerKeyId,
      clientVerifyingShareB64u: keyRef.clientVerifyingShareB64u,
      purpose,
      signingDigest32: req.digest32,
      sessionKind,
      ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
    });
    if (!authorized.ok || !authorized.mpcSessionId) {
      throw new Error(authorized.message || authorized.code || '[multichain] threshold-ecdsa authorize failed');
    }
    keyRef.mpcSessionId = authorized.mpcSessionId;

    const thresholdSessionId = String(
      cachedThresholdSession?.policy?.sessionId
      || keyRef.thresholdSessionId
      || ''
    ).trim();
    if (!thresholdSessionId) {
      throw new Error('[multichain] Missing threshold-ecdsa sessionId; reconnect session via connectEcdsaSession');
    }
    if (!this.dispenseThresholdEcdsaPrfFirstForSession) {
      throw new Error('[multichain] Missing PRF.first dispenser for threshold-ecdsa signing');
    }

    const dispensed = await this.dispenseThresholdEcdsaPrfFirstForSession({
      sessionId: thresholdSessionId,
      uses: 1,
    });
    if (!dispensed.ok) {
      throw new Error(dispensed.message || dispensed.code || '[multichain] failed to load PRF.first for threshold-ecdsa signing');
    }

    const derived = await deriveThresholdSecp256k1ClientShareWasm({
      prfFirstB64u: dispensed.prfFirstB64u,
      userId: keyRef.userId,
      workerCtx: this.workerCtx,
    });
    if (derived.clientVerifyingShareB64u !== keyRef.clientVerifyingShareB64u) {
      throw new Error('[multichain] Derived client share does not match keyRef.clientVerifyingShareB64u');
    }

    const signed = await signThresholdEcdsaDigestWithPool({
      relayerUrl: keyRef.relayerUrl,
      relayerKeyId: keyRef.relayerKeyId,
      clientVerifyingShareB64u: keyRef.clientVerifyingShareB64u,
      mpcSessionId: authorized.mpcSessionId,
      signingDigest32: req.digest32,
      clientSigningShare32: derived.clientSigningShare32,
      participantIds: keyRef.participantIds || cachedThresholdSession?.policy?.participantIds,
      groupPublicKeyB64u: keyRef.groupPublicKeyB64u,
      relayerVerifyingShareB64u: keyRef.relayerVerifyingShareB64u,
      sessionKind,
      ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
      workerCtx: this.workerCtx,
    });
    if (!signed.ok) {
      throw new Error(signed.message || signed.code || '[multichain] threshold-ecdsa signing failed');
    }

    return signed.signature65;
  }
}
