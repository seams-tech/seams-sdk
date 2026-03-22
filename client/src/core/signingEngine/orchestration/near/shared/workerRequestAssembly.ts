import type { ThresholdEd25519_2p_V1Material } from '@/core/indexedDB/passkeyNearKeysDB.types';
import type {
  ThresholdSignerConfig,
  WasmSignTransactionsWithActionsRequest,
} from '@/core/types/signer-worker';

type NearThresholdSignerConfigInput = {
  relayerUrl: string;
  thresholdKeyMaterial: ThresholdEd25519_2p_V1Material;
  thresholdSessionKind?: 'jwt' | 'cookie';
  thresholdSessionJwt?: string;
};

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
  prfFirstB64u?: string;
  wrapKeySalt: string;
  threshold: NearThresholdSignerConfigInput;
}): Pick<WasmSignTransactionsWithActionsRequest, 'prfFirstB64u' | 'wrapKeySalt' | 'threshold'> {
  return {
    prfFirstB64u: args.prfFirstB64u,
    wrapKeySalt: args.wrapKeySalt,
    threshold: buildNearThresholdSignerConfig(args.threshold),
  };
}
