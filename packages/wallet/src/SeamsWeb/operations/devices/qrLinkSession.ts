/**
 * QR is a single shared boundary. Keep this module as a local import seam for
 * browser callers; all parsing and branch selection lives in shared-ts.
 */
export {
  buildQrLinkedDeviceSessionPayloadV5,
  parseQrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking';
export type {
  LinkDevicePublicKeyB64u,
  QrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking';
