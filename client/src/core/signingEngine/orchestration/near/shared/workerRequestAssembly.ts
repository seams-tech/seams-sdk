import type {
  LocalNearSkV3Material,
  ThresholdEd25519_2p_V1Material,
} from '@/core/indexedDB/passkeyNearKeysDB.types';
import type {
  SignerMode,
  ThresholdSignerConfig,
  WasmSignTransactionsWithActionsRequest,
} from '@/core/types/signer-worker';

type NearWorkerDecryptionPayload = WasmSignTransactionsWithActionsRequest['decryption'];

type NearThresholdSignerConfigInput = {
  relayerUrl: string;
  thresholdKeyMaterial: ThresholdEd25519_2p_V1Material;
  thresholdSessionKind?: 'jwt' | 'cookie';
  thresholdSessionJwt?: string;
};

export function emptyNearWorkerDecryptionPayload(): NearWorkerDecryptionPayload {
  return {
    encryptedPrivateKeyData: '',
    encryptedPrivateKeyChacha20NonceB64u: '',
  };
}

export function localNearWorkerDecryptionPayload(
  localKeyMaterial: LocalNearSkV3Material,
): NearWorkerDecryptionPayload {
  return {
    encryptedPrivateKeyData: localKeyMaterial.encryptedSk,
    encryptedPrivateKeyChacha20NonceB64u: localKeyMaterial.chacha20NonceB64u,
  };
}

export function buildNearThresholdSignerConfig(
  args: NearThresholdSignerConfigInput,
): ThresholdSignerConfig {
  const thresholdSessionKind = args.thresholdSessionKind === 'cookie' ? 'cookie' : 'jwt';
  const thresholdSessionJwt =
    thresholdSessionKind === 'jwt' ? String(args.thresholdSessionJwt || '').trim() || undefined : undefined;
  return {
    relayerUrl: args.relayerUrl,
    relayerKeyId: args.thresholdKeyMaterial.relayerKeyId,
    clientParticipantId: args.thresholdKeyMaterial.participants.find((p) => p.role === 'client')
      ?.id,
    relayerParticipantId: args.thresholdKeyMaterial.participants.find((p) => p.role === 'relayer')
      ?.id,
    participantIds: args.thresholdKeyMaterial.participants.map((p) => p.id),
    thresholdSessionKind,
    ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
  };
}

export function buildNearWorkerSigningEnvelope(args: {
  signerMode: SignerMode['mode'];
  prfFirstB64u?: string;
  wrapKeySalt: string;
  localKeyMaterial?: LocalNearSkV3Material | null;
  threshold?: NearThresholdSignerConfigInput | null;
}): Pick<
  WasmSignTransactionsWithActionsRequest,
  'signerMode' | 'prfFirstB64u' | 'wrapKeySalt' | 'decryption' | 'threshold'
> {
  if (args.localKeyMaterial && args.threshold) {
    throw new Error(
      'Near worker request assembly received both local and threshold signing material',
    );
  }

  const decryption = args.localKeyMaterial
    ? localNearWorkerDecryptionPayload(args.localKeyMaterial)
    : emptyNearWorkerDecryptionPayload();

  return {
    signerMode: args.signerMode,
    prfFirstB64u: args.prfFirstB64u,
    wrapKeySalt: args.wrapKeySalt,
    decryption,
    ...(args.threshold ? { threshold: buildNearThresholdSignerConfig(args.threshold) } : {}),
  };
}
