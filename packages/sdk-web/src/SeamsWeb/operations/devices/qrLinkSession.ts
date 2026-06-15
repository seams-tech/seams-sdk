import {
  parseLinkDeviceSessionId,
  type LinkDeviceSessionId,
} from '@shared/signing-lanes';

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requiredString(record: Record<string, unknown>, fieldName: string): string {
  const value = String(record[fieldName] || '').trim();
  if (!value) {
    throw new Error(`[QrLinkedDeviceSession] ${fieldName} is required`);
  }
  return value;
}

function requiredPositiveInteger(record: Record<string, unknown>, fieldName: string): number {
  const value = Math.floor(Number(record[fieldName]));
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`[QrLinkedDeviceSession] ${fieldName} must be a positive integer`);
  }
  return value;
}

export type QrLinkedDevicePermissionRequest =
  | {
      kind: 'owner_equivalent_signing';
      administrationScope: 'signing_only' | 'device_management' | 'full_owner_admin';
      mandatePolicyDigest?: never;
    }
  | {
      kind: 'scoped_signing';
      administrationScope: 'no_account_admin';
      mandatePolicyDigest: string;
    };

export type QrLinkedDeviceSessionPayloadV4 = {
  version: 'v4';
  purpose: 'linked_device_lane_creation';
  linkSessionId: LinkDeviceSessionId;
  linkPublicKeyB64u: string;
  devicePublicKeyB64u: string;
  requestedPermission: QrLinkedDevicePermissionRequest;
  issuedAtMs: number;
  expiresAtMs: number;
};

function parseRequestedPermission(raw: unknown): QrLinkedDevicePermissionRequest {
  if (!isRecord(raw)) {
    throw new Error('[QrLinkedDeviceSession] requestedPermission is required');
  }
  switch (raw.kind) {
    case 'owner_equivalent_signing': {
      const administrationScope = requiredString(raw, 'administrationScope');
      if (
        administrationScope !== 'signing_only' &&
        administrationScope !== 'device_management' &&
        administrationScope !== 'full_owner_admin'
      ) {
        throw new Error('[QrLinkedDeviceSession] administrationScope is invalid');
      }
      return {
        kind: 'owner_equivalent_signing',
        administrationScope,
      };
    }
    case 'scoped_signing':
      return {
        kind: 'scoped_signing',
        administrationScope: 'no_account_admin',
        mandatePolicyDigest: requiredString(raw, 'mandatePolicyDigest'),
      };
  }
  throw new Error('[QrLinkedDeviceSession] requestedPermission.kind is invalid');
}

export function parseQrLinkedDeviceSessionPayloadV4(
  raw: unknown,
): QrLinkedDeviceSessionPayloadV4 {
  if (!isRecord(raw)) {
    throw new Error('[QrLinkedDeviceSession] payload is required');
  }
  if (raw.version !== 'v4') {
    throw new Error('[QrLinkedDeviceSession] version must be v4');
  }
  if (raw.purpose !== 'linked_device_lane_creation') {
    throw new Error('[QrLinkedDeviceSession] purpose is invalid');
  }
  const linkSessionId = parseLinkDeviceSessionId(raw.linkSessionId);
  if (!linkSessionId.ok) {
    throw new Error(linkSessionId.error.message);
  }
  const issuedAtMs = requiredPositiveInteger(raw, 'issuedAtMs');
  const expiresAtMs = requiredPositiveInteger(raw, 'expiresAtMs');
  if (expiresAtMs <= issuedAtMs) {
    throw new Error('[QrLinkedDeviceSession] expiresAtMs must be after issuedAtMs');
  }
  return {
    version: 'v4',
    purpose: 'linked_device_lane_creation',
    linkSessionId: linkSessionId.value,
    linkPublicKeyB64u: requiredString(raw, 'linkPublicKeyB64u'),
    devicePublicKeyB64u: requiredString(raw, 'devicePublicKeyB64u'),
    requestedPermission: parseRequestedPermission(raw.requestedPermission),
    issuedAtMs,
    expiresAtMs,
  };
}
