/**
 * QR is a single shared boundary. Keep this module as a local import seam for
 * browser callers; all parsing and branch selection lives in shared-ts.
 */
export {
  buildQrLinkedDevicePermissionRequest,
  buildQrLinkedDeviceSessionPayloadV4,
  parseQrLinkedDeviceSessionPayloadV4,
} from '@shared/device-linking';
export type {
  LinkDevicePublicKeyB64u,
  QrLinkedDevicePermissionRequest,
  QrLinkedDeviceSessionPayloadV4,
} from '@shared/device-linking';
