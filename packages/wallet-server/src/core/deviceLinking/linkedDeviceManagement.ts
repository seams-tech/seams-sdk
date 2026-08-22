import type {
  LinkedDeviceListRequestV1,
  LinkedDeviceListResultV1,
  LinkedDeviceRevokeRequestV1,
  LinkedDeviceRevokeResultV1,
  LinkedDeviceSummaryV1,
  OwnerDeviceSummaryV1,
} from '@shared/device-linking/contracts';
import {
  buildDelegatedWalletAuthorityV1,
  hasDelegatedWalletPermissionV1,
  sameDelegatedWalletAuthorityV1,
  buildFullOwnerPermissionsV1,
  type DelegatedWalletAuthorityV1,
} from '@shared/authorization/delegatedAuthority';
import type {
  ActiveWalletAuthorityV1,
  WalletAuthorityV1,
} from '@shared/authorization/walletAuthority';
import type {
  IssuedWalletSessionAuthorizationV2,
  WalletSessionAuthorizationV2,
} from '../../authorization/domain';
import type { AuthorizationService } from '../../authorization/service';
import type { OrdinaryInactiveSignerMaterialDeactivationPortV1 } from '../signingMaterial/ordinaryInactiveSignerMaterialReservation';
import {
  parseWalletAuthorityId,
  parseLinkedDeviceId,
  type MpcMaterialActivationRef,
  type WalletAuthorityId,
  type WalletAuthMethodId,
  type WalletId,
} from '@shared/utils/domainIds';
import type {
  TenantId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { WalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import type { WebAuthnAuthenticatorDeviceInfo } from '@shared/utils/webauthnDeviceInfo';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import type { LinkedDeviceId, WalletKeyId } from '@shared/signing-lanes/ids';

export const MAX_LINKED_DEVICE_LIST_LIMIT_V1 = 50;

export type LinkedDeviceManagementListCursorV1 = {
  readonly kind: 'wallet_authority_v1';
  readonly updatedAtMs: number;
  readonly authorityId: WalletAuthorityId;
};

export class LinkedDeviceListCursorError extends Error {
  readonly kind = 'linked_device_list_cursor_error_v1';
}

/** Identity supplied by the bearer boundary; authority and method are reread from D1. */
export type LinkedDeviceManagementSourceV1 = {
  readonly walletId: WalletId;
  readonly walletSessionId: WalletSessionId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly expiresAtMs: number;
};

export type LinkedDeviceManagementSourceResolutionV1 = {
  readonly session: WalletSessionAuthorizationV2;
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
  readonly permission: DelegatedWalletAuthorityV1;
};

export type LinkedDeviceManagementAuthorityPageV1 = {
  readonly records: readonly ActiveWalletAuthorityV1[];
  readonly nextCursor: LinkedDeviceManagementListCursorV1 | null;
};

export type LinkedDeviceManagementAuthorityPortV1 = {
  listActiveForWalletV1(input: {
    readonly walletId: WalletId;
    readonly limit: number;
    readonly cursor: LinkedDeviceManagementListCursorV1 | null;
  }): Promise<LinkedDeviceManagementAuthorityPageV1>;
  readByIdV1(authorityId: WalletAuthorityId): Promise<WalletAuthorityV1 | null>;
  revokeWalletAuthMethodV1(input: {
    readonly walletId: WalletId;
    readonly authorityId: WalletAuthorityId;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly expectedAuthorityRevocationEpoch: number;
    readonly requestedAtMs: number;
  }): Promise<
    | {
        readonly kind: 'revoked_method';
        readonly authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'revoked' }>;
        readonly authority: WalletAuthorityV1;
      }
    | { readonly kind: 'would_remove_last_wallet_auth_method' }
    | { readonly kind: 'conflict' }
  >;
};

export type LinkedDeviceManagementAuthMethodPortV1 = {
  listForAuthorityV1(input: {
    readonly walletId: WalletId;
    readonly authorityId: WalletAuthorityId;
  }): Promise<readonly WalletAuthMethodRecordV2[]>;
  readByIdV1(input: { readonly walletAuthMethodId: WalletAuthMethodId }): Promise<WalletAuthMethodRecordV2 | null>;
};

export type LinkedDeviceManagementAuthenticatorPortV1 = Pick<
  AuthorizationService,
  'readWalletSessionAuthorizationV2ByIdentity'
>;

export type LinkedDeviceManagementSessionRevocationPortV1 = Pick<
  AuthorizationService,
  'revokeReusableWalletSessionsForAuthMethod'
>;

export type LinkedDeviceManagementCredentialMetadataPortV1 = {
  readPasskeyDeviceInfoV1(input: {
    readonly walletId: WalletId;
    readonly credentialIdB64u: string;
  }): Promise<WebAuthnAuthenticatorDeviceInfo | null>;
};

export type LinkedDeviceManagementServiceOptionsV1 = {
  readonly tenantId: TenantId;
  readonly authenticator: LinkedDeviceManagementAuthenticatorPortV1;
  readonly authority: LinkedDeviceManagementAuthorityPortV1;
  readonly authMethod: LinkedDeviceManagementAuthMethodPortV1;
  readonly sessions: LinkedDeviceManagementSessionRevocationPortV1;
  readonly credentials: LinkedDeviceManagementCredentialMetadataPortV1;
  readonly materialDeactivation?: OrdinaryInactiveSignerMaterialDeactivationPortV1;
};

export type LinkedDeviceManagementServiceResultV1 =
  | LinkedDeviceListResultV1
  | { readonly kind: 'unauthorized' };

export class LinkedDeviceManagementServiceV1 {
  constructor(private readonly options: LinkedDeviceManagementServiceOptionsV1) {}

  async listLinkedDevicesV1(
    request: LinkedDeviceListRequestV1,
    source: LinkedDeviceManagementSourceV1,
    requestedAtMs: number,
  ): Promise<LinkedDeviceManagementServiceResultV1> {
    const resolved = await this.resolveSourceV1(source, requestedAtMs);
    if (!resolved || !canListDevicesV1(resolved.permission)) return { kind: 'unauthorized' };
    validateListLimit(request.limit);
    if (request.walletId !== resolved.session.walletId) return { kind: 'unauthorized' };
    const page = await this.options.authority.listActiveForWalletV1({
      walletId: request.walletId,
      limit: request.limit,
      cursor: decodeLinkedDeviceListCursorV1(request.cursor),
    });
    const devices: LinkedDeviceSummaryV1[] = [];
    const ownerDevices: OwnerDeviceSummaryV1[] = [];
    for (const authority of page.records) {
      const methods = await this.options.authMethod.listForAuthorityV1({
        walletId: authority.walletId,
        authorityId: authority.authorityId,
      });
      const activeMethods = methods.filter(isActiveAuthMethod);
      if (authority.provenance.kind === 'device_link') {
        if (activeMethods.length === 0) continue;
        devices.push(await this.buildLinkedDeviceSummaryV1(authority, activeMethods[0]));
      } else if (request.cursor === null && activeMethods.length > 0) {
        ownerDevices.push(await this.buildOwnerDeviceSummaryV1(authority, activeMethods[0]));
      }
    }
    return {
      devices,
      ownerDevices,
      nextCursor: page.nextCursor ? encodeLinkedDeviceListCursorV1(page.nextCursor) : null,
    };
  }

  async revokeLinkedDeviceV1(
    request: LinkedDeviceRevokeRequestV1,
    source: LinkedDeviceManagementSourceV1,
  ): Promise<LinkedDeviceRevokeResultV1> {
    const resolved = await this.resolveSourceV1(source, request.requestedAtMs);
    if (!resolved || !hasFullOwnerPermissionsV1(resolved.authority)) {
      return { kind: 'unauthorized' };
    }
    if (request.walletId !== resolved.session.walletId) return { kind: 'unauthorized' };
    if (request.walletAuthMethodId === resolved.authMethod.walletAuthMethodId) {
      return { kind: 'conflict' };
    }
    const targetMethod = await this.options.authMethod.readByIdV1({
      walletAuthMethodId: request.walletAuthMethodId,
    });
    if (!targetMethod || targetMethod.walletId !== request.walletId) {
      return { kind: 'not_found' };
    }
    const targetAuthority = await this.options.authority.readByIdV1(targetMethod.walletAuthorityId);
    if (
      !targetAuthority ||
      targetAuthority.walletId !== request.walletId ||
      targetAuthority.provenance.kind !== 'device_link'
    ) {
      return { kind: 'not_found' };
    }
    if (targetMethod.status === 'revoked') {
      await this.options.sessions.revokeReusableWalletSessionsForAuthMethod({
        tenantId: this.options.tenantId,
        walletId: request.walletId,
        walletAuthMethodId: targetMethod.walletAuthMethodId,
        nowMs: request.requestedAtMs,
      });
      if (targetAuthority.state === 'revoked') {
        await this.deactivateSignerMaterialV1(targetAuthority, request.requestedAtMs);
      }
      return {
        kind: 'revoked',
        walletAuthMethodId: targetMethod.walletAuthMethodId,
        authorityId: targetAuthority.authorityId,
        revocationEpoch: targetAuthority.revocationEpoch,
      };
    }
    if (targetMethod.status !== 'active' || targetAuthority.state !== 'active') {
      return { kind: 'not_found' };
    }
    const result = await this.options.authority.revokeWalletAuthMethodV1({
      walletId: request.walletId,
      authorityId: targetAuthority.authorityId,
      walletAuthMethodId: targetMethod.walletAuthMethodId,
      expectedAuthorityRevocationEpoch: targetAuthority.revocationEpoch,
      requestedAtMs: request.requestedAtMs,
    });
    if (result.kind === 'would_remove_last_wallet_auth_method' || result.kind === 'conflict') {
      return { kind: 'conflict' };
    }
    await this.options.sessions.revokeReusableWalletSessionsForAuthMethod({
      tenantId: this.options.tenantId,
      walletId: request.walletId,
      walletAuthMethodId: targetMethod.walletAuthMethodId,
      nowMs: request.requestedAtMs,
    });
    if (result.authority.state === 'revoked') {
      await this.deactivateSignerMaterialV1(result.authority, request.requestedAtMs);
    }
    return {
      kind: 'revoked',
      walletAuthMethodId: result.authMethod.walletAuthMethodId,
      authorityId: result.authority.authorityId,
      revocationEpoch: result.authority.revocationEpoch,
    };
  }

  private async resolveSourceV1(
    source: LinkedDeviceManagementSourceV1,
    requestedAtMs: number,
  ): Promise<LinkedDeviceManagementSourceResolutionV1 | null> {
    if (source.expiresAtMs <= requestedAtMs) return null;
    const issued: IssuedWalletSessionAuthorizationV2 | null =
      await this.options.authenticator.readWalletSessionAuthorizationV2ByIdentity({
        tenantId: this.options.tenantId,
        walletId: source.walletId,
        walletSessionId: source.walletSessionId,
        authorizationId: source.authorizationId,
        nowMs: requestedAtMs,
      });
    if (!issued || issued.session.expiresAtMs <= requestedAtMs) return null;
    const session = issued.session;
    const authority = await this.options.authority.readByIdV1(session.authorityId);
    const authMethod = await this.options.authMethod.readByIdV1({
      walletAuthMethodId: session.walletAuthMethodId,
    });
    if (
      !authority ||
      authority.state !== 'active' ||
      authority.walletId !== session.walletId ||
      authority.authorityDigestB64u !== session.authorityDigestB64u ||
      authority.revocationEpoch !== session.authorityRevocationEpoch ||
      !authMethod ||
      authMethod.status !== 'active' ||
      authMethod.walletId !== session.walletId ||
      authMethod.walletAuthorityId !== authority.authorityId
    ) {
      return null;
    }
    const permission = buildDelegatedWalletAuthorityV1({ permissions: authority.permissions });
    return { session, authority, authMethod, permission };
  }

  private async deactivateSignerMaterialV1(
    authority: Extract<WalletAuthorityV1, { readonly state: 'revoked' }>,
    requestedAtMs: number,
  ): Promise<void> {
    const port = this.options.materialDeactivation;
    if (!port) return;
    for (const materialActivation of activationRefsFromAuthority(authority)) {
      await port.deactivateOrdinarySignerMaterialV1({
        keyFamily: materialActivation.keyFamily,
        materialActivation: materialActivation.materialActivation,
        requestedAtMs,
      });
    }
  }

  private async buildLinkedDeviceSummaryV1(
    authority: ActiveWalletAuthorityV1,
    authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>,
  ): Promise<LinkedDeviceSummaryV1> {
    if (authority.provenance.kind !== 'device_link') {
      throw new Error('linked authority provenance is invalid');
    }
    return {
      deviceId: parseLinkedDeviceIdValue(authority.principal.deviceId),
      enrollmentId: authority.provenance.enrollmentId,
      walletId: authority.walletId,
      credential: await credentialMetadataV1(
        this.options.credentials,
        authority.walletId,
        authMethod,
      ),
      permission: buildDelegatedWalletAuthorityV1({ permissions: authority.permissions }),
      keyManifestDigestB64u: authority.signerActivationSetDigestB64u,
      coveredWalletKeys: walletKeysFromAuthority(authority),
      state: 'active',
      createdAtMs: authority.createdAtMs,
      lastActivityAtMs: Math.max(authority.updatedAtMs, authMethod.updatedAtMs),
      revocationEpoch: authority.revocationEpoch,
    };
  }

  private async buildOwnerDeviceSummaryV1(
    authority: ActiveWalletAuthorityV1,
    authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>,
  ): Promise<OwnerDeviceSummaryV1> {
    return {
      walletId: authority.walletId,
      credential: await credentialMetadataV1(
        this.options.credentials,
        authority.walletId,
        authMethod,
      ),
      createdAtMs: authority.createdAtMs,
      lastActivityAtMs: Math.max(authority.updatedAtMs, authMethod.updatedAtMs),
    };
  }
}

function validateListLimit(limit: number): void {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_LINKED_DEVICE_LIST_LIMIT_V1) {
    throw new Error('linked-device list limit is invalid');
  }
}

function canListDevicesV1(permission: DelegatedWalletAuthorityV1): boolean {
  return (
    hasDelegatedWalletPermissionV1(permission, 'link_devices') ||
    hasDelegatedWalletPermissionV1(permission, 'revoke_devices')
  );
}

function hasFullOwnerPermissionsV1(authority: ActiveWalletAuthorityV1): boolean {
  return sameDelegatedWalletAuthorityV1(
    buildDelegatedWalletAuthorityV1({ permissions: authority.permissions }),
    buildDelegatedWalletAuthorityV1({ permissions: buildFullOwnerPermissionsV1() }),
  );
}

function isActiveAuthMethod(
  record: WalletAuthMethodRecordV2,
): record is Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }> {
  return record.status === 'active';
}

async function credentialMetadataV1(
  credentials: LinkedDeviceManagementCredentialMetadataPortV1,
  walletId: WalletId,
  authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>,
): Promise<LinkedDeviceSummaryV1['credential']> {
  if (authMethod.kind === 'email_otp') {
    return { kind: 'email_otp', walletAuthMethodId: authMethod.walletAuthMethodId };
  }
  const device = await credentials.readPasskeyDeviceInfoV1({
    walletId,
    credentialIdB64u: authMethod.credentialIdB64u,
  });
  if (!device) throw new Error('active passkey authenticator metadata is missing');
  return {
    kind: 'passkey',
    walletAuthMethodId: authMethod.walletAuthMethodId,
    credentialIdB64u: authMethod.credentialIdB64u,
    device,
  };
}

function walletKeysFromAuthority(authority: ActiveWalletAuthorityV1): readonly WalletKeyId[] {
  const signers = authority.signerActivations;
  if (signers.keyFamilies.length === 1 && signers.keyFamilies[0] === 'ed25519') {
    if (!signers.ed25519) throw new Error('Ed25519 signer activation is missing');
    return [signers.ed25519.signer.walletKeyId];
  }
  if (signers.keyFamilies.length === 1 && signers.keyFamilies[0] === 'ecdsa_secp256k1') {
    if (!signers.ecdsa) throw new Error('ECDSA signer activation is missing');
    return [signers.ecdsa.signer.walletKeyId];
  }
  if (!signers.ed25519 || !signers.ecdsa) {
    throw new Error('dual-family signer activation is incomplete');
  }
  return [signers.ed25519.signer.walletKeyId, signers.ecdsa.signer.walletKeyId];
}

function activationRefsFromAuthority(
  authority: Extract<WalletAuthorityV1, { readonly state: 'revoked' }>,
): readonly AuthorityMaterialActivationV1[] {
  const signers = authority.signerActivations;
  if (signers.keyFamilies.length === 1 && signers.keyFamilies[0] === 'ed25519') {
    if (!signers.ed25519) throw new Error('Ed25519 signer activation is missing');
    return [{ keyFamily: 'ed25519', materialActivation: signers.ed25519.materialActivation }];
  }
  if (signers.keyFamilies.length === 1 && signers.keyFamilies[0] === 'ecdsa_secp256k1') {
    if (!signers.ecdsa) throw new Error('ECDSA signer activation is missing');
    return [{ keyFamily: 'ecdsa_secp256k1', materialActivation: signers.ecdsa.materialActivation }];
  }
  if (!signers.ed25519 || !signers.ecdsa) {
    throw new Error('dual-family signer activation is incomplete');
  }
  return [
    { keyFamily: 'ed25519', materialActivation: signers.ed25519.materialActivation },
    { keyFamily: 'ecdsa_secp256k1', materialActivation: signers.ecdsa.materialActivation },
  ];
}

type AuthorityMaterialActivationV1 =
  | { readonly keyFamily: 'ed25519'; readonly materialActivation: MpcMaterialActivationRef }
  | {
      readonly keyFamily: 'ecdsa_secp256k1';
      readonly materialActivation: MpcMaterialActivationRef;
    };

function parseLinkedDeviceIdValue(raw: string): LinkedDeviceId {
  const parsed = parseLinkedDeviceId(raw);
  if (!parsed.ok) throw new Error('linked authority device id is invalid');
  return parsed.value;
}

export function encodeLinkedDeviceListCursorV1(cursor: LinkedDeviceManagementListCursorV1): string {
  if (!Number.isSafeInteger(cursor.updatedAtMs) || cursor.updatedAtMs < 0) {
    throw new LinkedDeviceListCursorError('linked-device list cursor timestamp is invalid');
  }
  if (cursor.kind !== 'wallet_authority_v1') {
    throw new LinkedDeviceListCursorError('linked-device list cursor kind is invalid');
  }
  const authorityId = parseWalletAuthorityId(String(cursor.authorityId));
  if (!authorityId.ok) {
    throw new LinkedDeviceListCursorError('linked-device list cursor authority id is invalid');
  }
  return base64UrlEncode(
    new TextEncoder().encode(
      JSON.stringify({
        kind: cursor.kind,
        updatedAtMs: cursor.updatedAtMs,
        authorityId: String(authorityId.value),
      }),
    ),
  );
}

export function decodeLinkedDeviceListCursorV1(
  raw: string | null,
): LinkedDeviceManagementListCursorV1 | null {
  if (raw === null) return null;
  try {
    const record: unknown = JSON.parse(new TextDecoder().decode(base64UrlDecode(raw)));
    if (!isCursorRecordV1(record) || record.kind !== 'wallet_authority_v1') {
      throw new Error('invalid cursor');
    }
    if (!Number.isSafeInteger(record.updatedAtMs) || Number(record.updatedAtMs) < 0) {
      throw new Error('invalid cursor timestamp');
    }
    const authorityId = parseWalletAuthorityId(record.authorityId);
    if (!authorityId.ok) throw new Error('invalid cursor authority id');
    const cursor = {
      kind: 'wallet_authority_v1',
      updatedAtMs: Number(record.updatedAtMs),
      authorityId: authorityId.value,
    } satisfies LinkedDeviceManagementListCursorV1;
    if (encodeLinkedDeviceListCursorV1(cursor) !== raw) throw new Error('non-canonical cursor');
    return cursor;
  } catch {
    throw new LinkedDeviceListCursorError('linked-device list cursor is invalid');
  }
}

function isCursorRecordV1(
  value: unknown,
): value is { readonly kind: unknown; readonly updatedAtMs: unknown; readonly authorityId: unknown } {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join(',') === 'authorityId,kind,updatedAtMs'
  );
}
