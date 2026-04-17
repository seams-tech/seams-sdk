import type { NearSigningKeyOps } from '@/core/signingEngine/interfaces/nearKeyOps';
import type { SignerWorkerManagerContext } from '..';
import {
  deriveThresholdEd25519ClientVerifyingShareWasm,
  extractCosePublicKeyWasm,
  generateEphemeralNearKeypairWasm,
  signTransactionWithKeyPairWasm,
} from '@/core/signingEngine/signers/wasm/nearSignerWasm';
import { deriveThresholdEd25519HssClientInputsWasm } from '@/core/signingEngine/signers/wasm/hssClientSignerWasm';

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
      const signingRootId = String(args.signingRootId || '').trim();
      const nearAccountId = String(args.nearAccountId);
      const keyPurpose = String(args.keyPurpose || '').trim();
      const keyVersion = String(args.keyVersion || '').trim();
      try {
        const derived = await deriveThresholdEd25519HssClientInputsWasm({
          sessionId: args.sessionId,
          signingRootId,
          nearAccountId,
          keyPurpose,
          keyVersion,
          participantIds: args.participantIds,
          derivationVersion: args.derivationVersion,
          prfFirstB64u: args.prfFirstB64u,
          workerCtx: getContext(),
        });
        return {
          success: true,
          signingRootId: derived.signingRootId,
          nearAccountId: derived.nearAccountId,
          keyPurpose: derived.keyPurpose,
          keyVersion: derived.keyVersion,
          participantIds: derived.participantIds,
          derivationVersion: derived.derivationVersion,
          contextBindingB64u: derived.contextBindingB64u,
          yClientB64u: derived.yClientB64u,
          tauClientB64u: derived.tauClientB64u,
        };
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          success: false,
          signingRootId,
          nearAccountId,
          keyPurpose,
          keyVersion,
          participantIds: args.participantIds,
          derivationVersion: args.derivationVersion,
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
