import {
  parseLaneShareEpoch,
  parseSigningLaneId,
  parseWalletKeyId,
  type SigningLaneKind,
  type SigningLaneReference,
} from '@shared/signing-lanes';
import { parseWalletId } from '@shared/utils/domainIds';

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function parseSigningLaneKind(value: unknown): SigningLaneKind {
  switch (value) {
    case 'owner_passkey':
    case 'owner_email_otp':
    case 'linked_device':
    case 'delegated_agent':
    case 'recovery':
    case 'break_glass':
      return value;
  }
  throw new Error('[SigningLaneReference] laneKind is invalid');
}

export function parseSigningLaneReference(raw: unknown): SigningLaneReference {
  if (!isRecord(raw)) {
    throw new Error('[SigningLaneReference] record is required');
  }
  const walletId = parseWalletId(raw.walletId);
  if (!walletId.ok) throw new Error(walletId.error.message);
  const walletKeyId = parseWalletKeyId(raw.walletKeyId);
  if (!walletKeyId.ok) throw new Error(walletKeyId.error.message);
  const laneId = parseSigningLaneId(raw.laneId);
  if (!laneId.ok) throw new Error(laneId.error.message);
  const laneShareEpoch = parseLaneShareEpoch(raw.laneShareEpoch);
  if (!laneShareEpoch.ok) throw new Error(laneShareEpoch.error.message);
  return {
    kind: 'signing_lane_reference_v1',
    walletId: walletId.value,
    walletKeyId: walletKeyId.value,
    laneId: laneId.value,
    laneKind: parseSigningLaneKind(raw.laneKind),
    laneShareEpoch: laneShareEpoch.value,
  };
}
