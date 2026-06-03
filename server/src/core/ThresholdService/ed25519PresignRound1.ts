import { toOptionalTrimmedString } from '@shared/utils/validation';
import { threshold_ed25519_round1_commit } from '../../../../wasm/near_signer/pkg/wasm_signer_worker.js';

export type ThresholdEd25519RelayerPresignMaterial = {
  relayerNoncesB64u: string;
  relayerCommitments: { hiding: string; binding: string };
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

export function createThresholdEd25519RelayerPresignMaterial(
  relayerSigningShareB64u: string,
): ThresholdEd25519RelayerPresignMaterial {
  const output = threshold_ed25519_round1_commit(relayerSigningShareB64u);
  if (!isRecord(output)) {
    throw new Error('threshold-ed25519 presign refill produced invalid relayer presign');
  }
  const relayerNoncesB64u = toOptionalTrimmedString(output.relayerNoncesB64u);
  const relayerCommitments = output.relayerCommitments;
  if (!isRecord(relayerCommitments)) {
    throw new Error('threshold-ed25519 presign refill missing relayer commitments');
  }
  const hiding = toOptionalTrimmedString(relayerCommitments.hiding);
  const binding = toOptionalTrimmedString(relayerCommitments.binding);
  if (!relayerNoncesB64u || !hiding || !binding) {
    throw new Error('threshold-ed25519 presign refill produced incomplete relayer presign');
  }
  return { relayerNoncesB64u, relayerCommitments: { hiding, binding } };
}
