import type { SeamsConfigsInput, SeamsConfigsReadonly } from '@/core/types/seams';
import { formatSigningSessionSealKeyVersionForWire } from '@/core/signingEngine/session/keyMaterialBrands';

export function signingSessionSealInputFromReadonly(
  value: SeamsConfigsReadonly['signing']['sessionSeal'],
): SeamsConfigsInput['signingSessionSeal'] | undefined {
  const keyVersion = value.signingSessionSealKeyVersion
    ? formatSigningSessionSealKeyVersionForWire(value.signingSessionSealKeyVersion)
    : '';
  const shamirPrimeB64u = String(value.shamirPrimeB64u || '').trim();
  if (!keyVersion && !shamirPrimeB64u) return undefined;
  return {
    ...(keyVersion ? { keyVersion } : {}),
    ...(shamirPrimeB64u ? { shamirPrimeB64u } : {}),
  };
}
