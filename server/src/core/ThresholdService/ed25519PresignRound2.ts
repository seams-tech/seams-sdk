import { threshold_ed25519_round2_sign } from '../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import type { ThresholdEd25519Commitments } from './stores/SessionStore';

export type ThresholdEd25519RelayerSignatureShare = {
  relayerSignatureShareB64u: string;
};

export function expectThresholdEd25519Round2SignWasmOutput(
  output: unknown,
): ThresholdEd25519RelayerSignatureShare {
  const parsed = output as ThresholdEd25519RelayerSignatureShare;
  if (!parsed?.relayerSignatureShareB64u) {
    throw new Error('threshold-ed25519 finalize missing relayerSignatureShareB64u');
  }
  return parsed;
}

export function createThresholdEd25519RelayerSignatureShare(input: {
  clientParticipantId: number;
  relayerParticipantId: number;
  relayerSigningShareB64u: string;
  relayerNoncesB64u: string;
  groupPublicKey: string;
  signingDigestB64u: string;
  clientCommitments: ThresholdEd25519Commitments;
  relayerCommitments: ThresholdEd25519Commitments;
}): ThresholdEd25519RelayerSignatureShare {
  return expectThresholdEd25519Round2SignWasmOutput(threshold_ed25519_round2_sign(input));
}
