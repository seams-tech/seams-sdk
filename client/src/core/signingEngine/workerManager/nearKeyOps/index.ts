import type { NearSigningKeyOps } from '@/core/signingEngine/interfaces/nearKeyOps';
import type { SignerWorkerManagerContext } from '..';
import {
  deriveThresholdEd25519ClientVerifyingShareWasm,
  extractCosePublicKeyWasm,
  generateEphemeralNearKeypairWasm,
  signTransactionWithKeyPairWasm,
} from '@/core/signingEngine/signers/wasm/nearSignerWasm';

export function createNearKeyOps(getContext: () => SignerWorkerManagerContext): NearSigningKeyOps {
  return {
    async deriveThresholdEd25519ClientVerifyingShare(args) {
      const nearAccountId = String(args.nearAccountId);
      try {
        const derived = await deriveThresholdEd25519ClientVerifyingShareWasm({
          sessionId: args.sessionId,
          nearAccountId,
          prfFirstB64u: args.prfFirstB64u,
          wrapKeySalt: args.wrapKeySalt,
          workerCtx: getContext(),
        });
        return {
          success: true,
          nearAccountId: derived.nearAccountId,
          clientVerifyingShareB64u: derived.clientVerifyingShareB64u,
        };
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          success: false,
          nearAccountId,
          clientVerifyingShareB64u: '',
          error: message,
        };
      }
    },
    async extractCosePublicKey(attestationObjectBase64url) {
      return extractCosePublicKeyWasm({
        workerCtx: getContext(),
        attestationObjectBase64url,
      });
    },
    async signTransactionWithKeyPair(args) {
      return signTransactionWithKeyPairWasm({
        workerCtx: getContext(),
        ...args,
      });
    },
    async generateEphemeralNearKeypair() {
      return generateEphemeralNearKeypairWasm({ workerCtx: getContext() });
    },
  };
}
