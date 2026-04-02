import type { ThresholdEd25519_V1Material } from '@/core/indexedDB/passkeyNearKeysDB.types';
import type {
  ThresholdSignerConfig,
  WasmSignTransactionsWithActionsRequest,
} from '@/core/types/signer-worker';

type NearThresholdSignerConfigInput = {
  relayerUrl: string;
  thresholdKeyMaterial: ThresholdEd25519_V1Material;
  xClientBaseB64u?: string;
  thresholdSessionKind?: 'jwt' | 'cookie';
  thresholdSessionJwt?: string;
};

export function buildNearThresholdSignerConfig(
  args: NearThresholdSignerConfigInput,
): ThresholdSignerConfig {
  const thresholdSessionKind = args.thresholdSessionKind === 'cookie' ? 'cookie' : 'jwt';
  const thresholdSessionJwt =
    thresholdSessionKind === 'jwt'
      ? String(args.thresholdSessionJwt || '').trim() || undefined
      : undefined;
  const xClientBaseB64u = String(args.xClientBaseB64u || '').trim() || undefined;
  return {
    relayerUrl: args.relayerUrl,
    relayerKeyId: args.thresholdKeyMaterial.relayerKeyId,
    ...(xClientBaseB64u ? { xClientBaseB64u } : {}),
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
  threshold: NearThresholdSignerConfigInput;
}): Pick<WasmSignTransactionsWithActionsRequest, 'threshold'> {
  return {
    threshold: buildNearThresholdSignerConfig(args.threshold),
  };
}
