import type { NearSigningKeyOps } from '@/core/signingEngine/interfaces/nearKeyOps';
import type { SignerWorkerManagerContext } from '../SignerWorkerManager';
import {
  deriveThresholdEd25519ClientVerifyingShareWasm,
  extractCosePublicKeyWasm,
  generateEphemeralNearKeypairHandleWasm,
  signTransactionWithEphemeralNearKeypairHandleWasm,
} from '@/core/signingEngine/chains/near/nearSignerWasm';
import { deriveThresholdEd25519HssClientInputsWasm } from '@/core/signingEngine/threshold/crypto/hssClientSignerWasm';

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
    async deriveThresholdEd25519HssClientInputs(args) {
      const applicationBindingDigestB64u = String(args.applicationBindingDigestB64u || '').trim();
      try {
        const derived = await deriveThresholdEd25519HssClientInputsWasm({
          sessionId: args.sessionId,
          applicationBindingDigestB64u,
          participantIds: args.participantIds,
          prfFirstB64u: args.prfFirstB64u,
          workerCtx: getContext(),
        });
        return {
          success: true,
          applicationBindingDigestB64u: derived.applicationBindingDigestB64u,
          participantIds: derived.participantIds,
          contextBindingB64u: derived.contextBindingB64u,
          yClientB64u: derived.yClientB64u,
          tauClientB64u: derived.tauClientB64u,
        };
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          success: false,
          applicationBindingDigestB64u,
          participantIds: args.participantIds,
          contextBindingB64u: '',
          yClientB64u: '',
          tauClientB64u: '',
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
    async signTransactionWithEphemeralNearKeypairHandle(args) {
      return signTransactionWithEphemeralNearKeypairHandleWasm({
        workerCtx: getContext(),
        ...args,
      });
    },
    async generateEphemeralNearKeypairHandle(args) {
      return generateEphemeralNearKeypairHandleWasm({ workerCtx: getContext(), ...args });
    },
  };
}
