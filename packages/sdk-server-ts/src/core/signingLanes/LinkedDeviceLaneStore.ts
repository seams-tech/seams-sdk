import type {
  LinkedDeviceId,
  LinkedDeviceSigningLaneRecord,
  LinkDeviceSessionId,
  SigningLaneId,
  WalletKeyId,
} from '@shared/signing-lanes';

export type LinkedDeviceLaneActivationReceipt = {
  kind: 'linked_device_lane_activation_receipt_v1';
  linkSessionId: LinkDeviceSessionId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  deviceId: LinkedDeviceId;
  holderShareDeliveryReceiptB64u: string;
  createdAtMs: number;
};

export interface LinkedDeviceLaneStore {
  getLinkedDeviceLane(args: {
    walletKeyId: WalletKeyId;
    laneId: SigningLaneId;
  }): Promise<LinkedDeviceSigningLaneRecord | null>;
  putActivationReceipt(receipt: LinkedDeviceLaneActivationReceipt): Promise<void>;
}
