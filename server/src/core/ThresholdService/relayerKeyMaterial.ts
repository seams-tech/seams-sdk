import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { ThresholdEd25519KeyStore } from './stores/KeyStore';

export async function resolveThresholdEd25519RelayerKeyMaterial(input: {
  relayerKeyId: string;
  keyStore: ThresholdEd25519KeyStore;
}): Promise<
  | {
      ok: true;
      publicKey: string;
      relayerSigningShareB64u: string;
      relayerVerifyingShareB64u: string;
    }
  | { ok: false; code: string; message: string }
> {
  const relayerKeyId = toOptionalTrimmedString(input.relayerKeyId);
  if (!relayerKeyId) {
    return { ok: false, code: 'invalid_body', message: 'relayerKeyId is required' };
  }

  const existing = await input.keyStore.get(relayerKeyId);
  if (!existing) {
    return {
      ok: false,
      code: 'missing_key',
      message: 'Unknown relayerKeyId; bootstrap Ed25519 key material must be persisted',
    };
  }

  return { ok: true, ...existing };
}
