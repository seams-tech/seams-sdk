import type { EvmSigningRequest } from '@/core/signingEngine/chains/evm/evmSigning.types';
import type { TempoSigningRequest } from '@/core/signingEngine/chains/tempo/tempoSigning.types';
import type { SigningIntent } from '../../interfaces/signing';

export function requiredEvmFamilyRequestSignatureUses(
  request: EvmSigningRequest | TempoSigningRequest,
): number {
  switch (request.kind) {
    case 'eip1559':
    case 'tempoTransaction':
      return 1;
    default: {
      const unreachable: never = request;
      return unreachable;
    }
  }
}

export function requiredEvmFamilySignatureUses(
  intent: SigningIntent<unknown, object>,
): number {
  const thresholdSignatureUses = intent.signRequests.filter(
    (request) => request.kind === 'digest' && request.algorithm === 'secp256k1',
  ).length;
  return Math.max(1, thresholdSignatureUses);
}
