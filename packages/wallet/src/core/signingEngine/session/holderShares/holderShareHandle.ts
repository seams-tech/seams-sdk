import type { LaneShareEpoch, SigningLaneId, WalletKeyId } from '@shared/signing-lanes';
import type { WalletId } from '@shared/utils/domainIds';

declare const openHolderShareHandleBrand: unique symbol;

export type OpenHolderShareHandle = string & {
  readonly [openHolderShareHandleBrand]: 'OpenHolderShareHandle';
};

export type OpenHolderShareState = {
  state: 'holder_share_open';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  handle: OpenHolderShareHandle;
  openedAtMs: number;
  expiresAtMs: number;
};

export function parseOpenHolderShareHandle(raw: unknown): OpenHolderShareHandle {
  const value = String(raw || '').trim();
  if (!value) {
    throw new Error('[OpenHolderShareHandle] handle is required');
  }
  return value as OpenHolderShareHandle;
}
