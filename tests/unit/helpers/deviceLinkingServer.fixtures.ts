import {
  buildLinkedDeviceApprovalV1,
  buildLinkedDeviceEnrollmentChildReceiptV1,
  buildLinkedDeviceEnrollmentReceiptV1,
  buildLinkedDeviceSessionClaimV1,
} from '../../../packages/shared-ts/src/device-linking/parsers';
import {
  computeLinkedDeviceApprovalDigestV1,
  computeLinkedDeviceSessionClaimDigestV1,
} from '../../../packages/shared-ts/src/device-linking/digests';
import {
  buildLinkedDeviceWalletSessionAuthorizationRef,
  parseTenantId,
} from '../../../packages/shared-ts/src/authorization/capabilityKinds';
import {
  DEFAULT_WALLET_SESSION_REMAINING_USES,
  DEFAULT_WALLET_SESSION_TTL_MS,
} from '../../../packages/shared-ts/src/threshold/sessionPolicy';
import {
  buildActiveWalletSessionQuota,
  buildLinkedDeviceWalletSessionAuthorization,
} from '../../../packages/sdk-server-ts/src/authorization/domain';
import {
  deriveLinkedDeviceWalletSessionIdentityV1,
  type IssuedLinkedDeviceWalletSession,
} from '../../../packages/sdk-server-ts/src/authorization/service';
import {
  parseLinkedDeviceSessionRecordV1,
  type LinkedDeviceSessionRecordV1,
} from '../../../packages/sdk-server-ts/src/core/deviceLinking/linkedDeviceSession';
import type { SessionAdapter } from '../../../packages/sdk-server-ts/src/router/framework/routerApi';
import { base64UrlEncode } from '../../../packages/shared-ts/src/utils/base64';
import type { R103DeviceLinkFixture } from './deviceLinkContracts.fixtures';

export async function buildR103ActiveLinkedDeviceSessionRecordV1(
  fixture: R103DeviceLinkFixture,
  keyFamily: 'ed25519' | 'ecdsa_secp256k1' = 'ed25519',
): Promise<Extract<LinkedDeviceSessionRecordV1, { readonly state: { readonly state: 'active' } }>> {
  const sourceBinding = fixture.approval.orderedKeyBindings[0];
  const sourceReceipt = fixture.receipt.orderedChildReceipts[0];
  const protocolVersion = fixture.approval.protocolVersions[0];
  if (!sourceBinding || !sourceReceipt || !protocolVersion) {
    throw new Error('R103 server fixture requires one approved child');
  }
  const approval = buildLinkedDeviceApprovalV1({
    linkSessionId: fixture.approval.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    linkPublicKeyB64u: fixture.approval.linkPublicKeyB64u,
    devicePublicKeyB64u: fixture.approval.devicePublicKeyB64u,
    permission: fixture.approval.permission,
    ownerAuthorization: fixture.approval.ownerAuthorization,
    policyDigestB64u: fixture.approval.policyDigestB64u,
    operationId: fixture.approval.operationId,
    idempotencyKey: fixture.approval.idempotencyKey,
    orderedKeyBindings: [
      {
        walletKeyId: sourceBinding.walletKeyId,
        keyFamily,
        sourceLaneId: sourceBinding.sourceLaneId,
        sourceLaneShareEpoch: sourceBinding.sourceLaneShareEpoch,
        sourceRevocationEpoch: sourceBinding.sourceRevocationEpoch,
        sourceHolderParticipantId: sourceBinding.sourceHolderParticipantId,
        sourceSigningWorkerParticipantId: sourceBinding.sourceSigningWorkerParticipantId,
        targetLaneId: sourceBinding.targetLaneId,
        targetLaneShareEpoch: sourceBinding.targetLaneShareEpoch,
      },
    ],
    protocolVersions: [{ keyFamily, version: protocolVersion.version }],
    approvedAtMs: fixture.approval.approvedAtMs,
    expiresAtMs: fixture.approval.expiresAtMs,
  });
  const childReceipt = buildLinkedDeviceEnrollmentChildReceiptV1({
    enrollmentId: sourceReceipt.enrollmentId,
    walletId: sourceReceipt.walletId,
    walletKeyId: sourceReceipt.walletKeyId,
    keyFamily,
    targetLaneId: sourceReceipt.targetLaneId,
    targetLaneShareEpoch: sourceReceipt.targetLaneShareEpoch,
    materialActivation: sourceReceipt.materialActivation,
    receiptDigestB64u: sourceReceipt.receiptDigestB64u,
    transcriptHashB64u: sourceReceipt.transcriptHashB64u,
    deliveredAtMs: sourceReceipt.deliveredAtMs,
  });
  const receipt = buildLinkedDeviceEnrollmentReceiptV1({
    enrollmentId: fixture.receipt.enrollmentId,
    walletId: fixture.receipt.walletId,
    deviceId: fixture.receipt.deviceId,
    manifestDigestB64u: fixture.receipt.manifestDigestB64u,
    aggregateReceiptDigestB64u: fixture.receipt.aggregateReceiptDigestB64u,
    orderedChildReceipts: [childReceipt],
    activatedAtMs: sourceReceipt.deliveredAtMs,
  });
  const claim = buildLinkedDeviceSessionClaimV1({
    linkSessionId: fixture.payload.linkSessionId,
    walletId: approval.walletId,
    enrollmentId: approval.enrollmentId,
    deviceId: approval.deviceId,
    devicePublicKeyB64u: fixture.payload.devicePublicKeyB64u,
    claimedAtMs: 1_500,
    claimExpiresAtMs: fixture.payload.expiresAtMs,
  });
  const record = parseLinkedDeviceSessionRecordV1({
    version: 'linked_device_session_v1',
    linkSessionId: fixture.payload.linkSessionId,
    qrPayload: fixture.payload,
    state: {
      state: 'active',
      linkSessionId: fixture.payload.linkSessionId,
      walletId: approval.walletId,
      enrollmentId: approval.enrollmentId,
      activatedAtMs: receipt.activatedAtMs,
    },
    revision: 4,
    claimTranscript: {
      digestB64u: await computeLinkedDeviceSessionClaimDigestV1(claim),
      value: claim,
    },
    approvalTranscript: {
      digestB64u: await computeLinkedDeviceApprovalDigestV1(approval),
      value: approval,
    },
    aggregateReceipt: receipt,
    createdAtMs: fixture.payload.issuedAtMs,
    updatedAtMs: receipt.activatedAtMs,
  });
  if (!isActiveSessionRecord(record)) {
    throw new Error('R103 active session fixture did not produce an active record');
  }
  return record;
}

function isActiveSessionRecord(
  record: LinkedDeviceSessionRecordV1,
): record is Extract<
  LinkedDeviceSessionRecordV1,
  { readonly state: { readonly state: 'active' } }
> {
  return record.state.state === 'active';
}

export async function buildR103IssuedLinkedDeviceWalletSessionV1(
  session: Extract<LinkedDeviceSessionRecordV1, { readonly state: { readonly state: 'active' } }>,
): Promise<IssuedLinkedDeviceWalletSession> {
  const tenantId = parseTenantId('tenant-r103-delivery');
  if (!tenantId.ok) throw new Error(tenantId.error.message);
  const binding = session.approvalTranscript.value.orderedKeyBindings[0];
  if (!binding) throw new Error('R103 active session fixture has no key binding');
  const input = {
    tenantId: tenantId.value,
    deviceId: session.approvalTranscript.value.deviceId,
    walletId: session.state.walletId,
    enrollmentId: session.state.enrollmentId,
    keyManifestDigestB64u: session.aggregateReceipt.manifestDigestB64u,
    permission: session.approvalTranscript.value.permission,
    revocationEpoch: binding.sourceRevocationEpoch,
    remainingUses: DEFAULT_WALLET_SESSION_REMAINING_USES,
    issuedAtMs: session.aggregateReceipt.activatedAtMs,
    expiresAtMs: session.aggregateReceipt.activatedAtMs + DEFAULT_WALLET_SESSION_TTL_MS,
  };
  const identity = await deriveLinkedDeviceWalletSessionIdentityV1(input);
  const authorization = buildLinkedDeviceWalletSessionAuthorization({
    tenantId: input.tenantId,
    authorizationGrantRef: buildLinkedDeviceWalletSessionAuthorizationRef(identity.authorizationId),
    walletId: input.walletId,
    enrollmentId: input.enrollmentId,
    deviceId: input.deviceId,
    walletSessionId: identity.walletSessionId,
    quotaId: identity.quotaId,
    keyManifestDigestB64u: input.keyManifestDigestB64u,
    permission: input.permission,
    revocationEpoch: input.revocationEpoch,
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
  });
  return {
    authorization,
    quota: buildActiveWalletSessionQuota({
      tenantId: authorization.tenantId,
      principalId: authorization.principalId,
      walletSessionId: authorization.walletSessionId,
      quotaId: authorization.quotaId,
      remainingUses: input.remainingUses,
      expiresAtMs: authorization.expiresAtMs,
    }),
  };
}

export class LinkedDeviceJwtSessionAdapterV1 implements SessionAdapter {
  async signJwt(sub: string, extra: Record<string, unknown> = {}): Promise<string> {
    const header = base64UrlEncode(
      new TextEncoder().encode(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })),
    );
    const payload = base64UrlEncode(
      new TextEncoder().encode(
        JSON.stringify({
          ...extra,
          sub,
          iss: 'seams-router-test',
          aud: 'seams-linked-wallet-session',
        }),
      ),
    );
    return `${header}.${payload}.signature`;
  }

  async verifyJwt(): Promise<never> {
    throw new Error('Session verification is outside the linked-device delivery fixture');
  }

  async parse(): Promise<never> {
    throw new Error('Session parsing is outside the linked-device delivery fixture');
  }

  buildSetCookie(): string {
    throw new Error('Cookie building is outside the linked-device delivery fixture');
  }

  buildClearCookie(): string {
    throw new Error('Cookie clearing is outside the linked-device delivery fixture');
  }

  async refresh(): Promise<never> {
    throw new Error('Session refresh is outside the linked-device delivery fixture');
  }
}
