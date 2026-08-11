import {
  DEFAULT_WALLET_SESSION_REMAINING_USES,
  DEFAULT_WALLET_SESSION_TTL_MS,
} from '@shared/threshold/sessionPolicy';
import { parseLaneEnrollmentId } from '@shared/signing-lanes/ids';
import { computeLaneEnrollmentManifestDigestV1 } from '@shared/signing-lanes/rotationDigests';
import type { LaneEnrollmentManifestV1 } from '@shared/signing-lanes/rotation';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import type { TenantId } from '@shared/authorization/capabilityKinds';
import type {
  AuthorizationService,
  IssueLinkedDeviceWalletSessionInput,
  IssuedLinkedDeviceWalletSession,
} from '../../../../authorization/service';
import { deriveLinkedDeviceWalletSessionIdentityV1 } from '../../../../authorization/service';
import type { LinkedDeviceSessionRecordV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import type { CloudflareD1LaneLifecycleStore } from '../signingLanes/d1LaneLifecycleStore';

export type ActiveLinkedDeviceSessionRecordV1 = Extract<
  LinkedDeviceSessionRecordV1,
  { readonly state: { readonly state: 'active' } }
>;

export type D1LinkedDeviceWalletSessionIssuerOptionsV1 = {
  readonly tenantId: TenantId;
  readonly authorizationService: Pick<
    AuthorizationService,
    | 'getLinkedDeviceWalletSessionStatus'
    | 'issueLinkedDeviceWalletSession'
    | 'readLinkedDeviceWalletSessionAuthorization'
  >;
  readonly laneLifecycle: Pick<
    CloudflareD1LaneLifecycleStore,
    'getEnrollment' | 'listEnrollmentProductEpochs'
  >;
};

export class D1LinkedDeviceWalletSessionIssuerV1 {
  constructor(private readonly options: D1LinkedDeviceWalletSessionIssuerOptionsV1) {}

  async issueForActiveSessionV1(input: {
    readonly session: ActiveLinkedDeviceSessionRecordV1;
    readonly requestedAtMs: number;
  }): Promise<void> {
    const issueInput = await this.buildIssueInputV1(input);
    const identity = await deriveLinkedDeviceWalletSessionIdentityV1(issueInput);
    const status = await this.options.authorizationService.getLinkedDeviceWalletSessionStatus({
      tenantId: issueInput.tenantId,
      deviceId: issueInput.deviceId,
      ...identity,
      nowMs: input.requestedAtMs,
    });
    switch (status.kind) {
      case 'missing':
        if (input.requestedAtMs >= issueInput.expiresAtMs) {
          throw new Error('linked-device Wallet Session activation is too old to authorize');
        }
        await this.options.authorizationService.issueLinkedDeviceWalletSession(issueInput);
        return;
      case 'active':
      case 'exhausted':
      case 'expired':
      case 'revoked':
        requireExistingAuthorizationMatches(status, issueInput);
        return;
      case 'invalid':
        throw new Error('linked-device Wallet Session persisted identity is invalid');
      default:
        return assertNeverLinkedDeviceWalletSessionStatus(status);
    }
  }

  async readActiveForSessionV1(input: {
    readonly session: ActiveLinkedDeviceSessionRecordV1;
    readonly requestedAtMs: number;
  }): Promise<IssuedLinkedDeviceWalletSession> {
    const issueInput = await this.buildIssueInputV1(input);
    const identity = await deriveLinkedDeviceWalletSessionIdentityV1(issueInput);
    const issued =
      await this.options.authorizationService.readLinkedDeviceWalletSessionAuthorization({
        tenantId: issueInput.tenantId,
        deviceId: issueInput.deviceId,
        ...identity,
        nowMs: input.requestedAtMs,
      });
    if (!issued) throw new Error('linked-device Wallet Session authorization is missing');
    requireIssuedAuthorizationMatches(issued, issueInput);
    return issued;
  }

  private async buildIssueInputV1(input: {
    readonly session: ActiveLinkedDeviceSessionRecordV1;
    readonly requestedAtMs: number;
  }): Promise<IssueLinkedDeviceWalletSessionInput> {
    const { session, requestedAtMs } = input;
    const approval = session.approvalTranscript.value;
    const receipt = session.aggregateReceipt;
    requireActiveSessionIdentity(session);
    if (!Number.isSafeInteger(requestedAtMs) || requestedAtMs < receipt.activatedAtMs) {
      throw new Error('linked-device Wallet Session request time is invalid');
    }

    const enrollmentId = parseLaneEnrollmentId(String(session.state.enrollmentId));
    if (!enrollmentId.ok) throw new Error(enrollmentId.error.message);
    const enrollment = await this.options.laneLifecycle.getEnrollment(enrollmentId.value);
    if (!enrollment || enrollment.value.lifecycle.state !== 'active') {
      throw new Error('linked-device Wallet Session requires an active lane enrollment');
    }
    const manifest = enrollment.value.manifest;
    const manifestDigestB64u = await computeLaneEnrollmentManifestDigestV1(manifest);
    if (
      String(manifest.enrollmentId) !== String(session.state.enrollmentId) ||
      String(manifest.walletId) !== String(session.state.walletId) ||
      manifestDigestB64u !== receipt.manifestDigestB64u ||
      manifest.authorization.kind !== 'linked_device_enrollment' ||
      String(manifest.authorization.linkedDeviceEnrollmentId) !==
        String(session.state.enrollmentId) ||
      String(manifest.authorization.authorizedOperationId) !== String(approval.operationId) ||
      manifest.authorization.linkedDevicePermissionDigestB64u !== approval.policyDigestB64u
    ) {
      throw new Error('linked-device Wallet Session enrollment binding is invalid');
    }

    const products = await this.options.laneLifecycle.listEnrollmentProductEpochs(
      enrollmentId.value,
    );
    const revocationEpoch = requireActiveProductCoverage(session, manifest, products);
    const issuedAtMs = receipt.activatedAtMs;
    const expiresAtMs = issuedAtMs + DEFAULT_WALLET_SESSION_TTL_MS;
    if (!Number.isSafeInteger(expiresAtMs)) {
      throw new Error('linked-device Wallet Session expiry is invalid');
    }
    return {
      tenantId: this.options.tenantId,
      deviceId: approval.deviceId,
      walletId: approval.walletId,
      enrollmentId: approval.enrollmentId,
      keyManifestDigestB64u: receipt.manifestDigestB64u,
      permission: approval.permission,
      revocationEpoch,
      remainingUses: DEFAULT_WALLET_SESSION_REMAINING_USES,
      issuedAtMs,
      expiresAtMs,
    };
  }
}

function requireIssuedAuthorizationMatches(
  issued: IssuedLinkedDeviceWalletSession,
  expected: IssueLinkedDeviceWalletSessionInput,
): void {
  const authorization = issued.authorization;
  if (
    authorization.tenantId !== expected.tenantId ||
    authorization.walletId !== expected.walletId ||
    authorization.enrollmentId !== expected.enrollmentId ||
    authorization.deviceId !== expected.deviceId ||
    authorization.keyManifestDigestB64u !== expected.keyManifestDigestB64u ||
    authorization.permission.kind !== expected.permission.kind ||
    authorization.permission.administrationScope !== expected.permission.administrationScope ||
    authorization.permission.localUserPresence !== expected.permission.localUserPresence ||
    authorization.revocationEpoch !== expected.revocationEpoch ||
    authorization.issuedAtMs !== expected.issuedAtMs ||
    authorization.expiresAtMs !== expected.expiresAtMs ||
    issued.quota.tenantId !== expected.tenantId ||
    issued.quota.principalId !== authorization.principalId ||
    issued.quota.walletSessionId !== authorization.walletSessionId ||
    issued.quota.quotaId !== authorization.quotaId ||
    issued.quota.expiresAtMs !== expected.expiresAtMs
  ) {
    throw new Error('linked-device Wallet Session active authorization differs');
  }
}

function requireExistingAuthorizationMatches(
  status: Exclude<
    Awaited<ReturnType<AuthorizationService['getLinkedDeviceWalletSessionStatus']>>,
    { readonly kind: 'missing' | 'invalid' }
  >,
  expected: IssueLinkedDeviceWalletSessionInput,
): void {
  if (
    status.walletId !== expected.walletId ||
    status.enrollmentId !== expected.enrollmentId ||
    status.deviceId !== expected.deviceId ||
    status.keyManifestDigestB64u !== expected.keyManifestDigestB64u ||
    status.revocationEpoch !== expected.revocationEpoch ||
    status.expiresAtMs !== expected.expiresAtMs
  ) {
    throw new Error('linked-device Wallet Session persisted authorization differs');
  }
}

function assertNeverLinkedDeviceWalletSessionStatus(value: never): never {
  throw new Error(`unknown linked-device Wallet Session status: ${String(value)}`);
}

function requireActiveSessionIdentity(session: ActiveLinkedDeviceSessionRecordV1): void {
  const approval = session.approvalTranscript.value;
  const claim = session.claimTranscript.value;
  const receipt = session.aggregateReceipt;
  if (
    approval.linkSessionId !== session.linkSessionId ||
    approval.linkSessionId !== session.state.linkSessionId ||
    approval.walletId !== session.state.walletId ||
    approval.enrollmentId !== session.state.enrollmentId ||
    approval.deviceId !== claim.deviceId ||
    receipt.walletId !== approval.walletId ||
    receipt.enrollmentId !== approval.enrollmentId ||
    receipt.deviceId !== approval.deviceId ||
    receipt.activatedAtMs !== session.state.activatedAtMs
  ) {
    throw new Error('linked-device Wallet Session active session binding is invalid');
  }
}

function requireActiveProductCoverage(
  session: ActiveLinkedDeviceSessionRecordV1,
  manifest: LaneEnrollmentManifestV1,
  products: Awaited<ReturnType<CloudflareD1LaneLifecycleStore['listEnrollmentProductEpochs']>>,
): number {
  const approval = session.approvalTranscript.value;
  const receipt = session.aggregateReceipt;
  if (
    manifest.orderedChildren.length !== approval.orderedKeyBindings.length ||
    products.length !== manifest.orderedChildren.length ||
    products.length !== receipt.orderedChildReceipts.length
  ) {
    throw new Error('linked-device Wallet Session product coverage is incomplete');
  }
  const productsByOperation = new Map<string, (typeof products)[number]>();
  for (const product of products) {
    const operationId = String(product.operationId);
    if (productsByOperation.has(operationId)) {
      throw new Error('linked-device Wallet Session products contain duplicate operations');
    }
    productsByOperation.set(operationId, product);
  }
  let revocationEpoch: number | null = null;
  for (let index = 0; index < manifest.orderedChildren.length; index += 1) {
    const manifestChild = manifest.orderedChildren[index];
    const binding = approval.orderedKeyBindings[index];
    const child = receipt.orderedChildReceipts[index];
    const product = manifestChild
      ? productsByOperation.get(String(manifestChild.operationId))
      : undefined;
    if (
      !manifestChild ||
      !product ||
      !binding ||
      !child ||
      product.state !== 'active' ||
      product.laneKind !== 'linked_device' ||
      product.walletId !== approval.walletId ||
      String(product.enrollmentId) !== String(approval.enrollmentId) ||
      product.walletKeyId !== binding.walletKeyId ||
      product.keyFamily !== binding.keyFamily ||
      product.laneId !== binding.targetLaneId ||
      product.laneShareEpoch !== binding.targetLaneShareEpoch ||
      product.walletKeyId !== manifestChild.walletKeyId ||
      product.keyFamily !== manifestChild.keyFamily ||
      product.laneId !== manifestChild.targetLaneId ||
      product.laneShareEpoch !== manifestChild.targetLaneShareEpoch ||
      product.targetMaterialActivationId !== manifestChild.targetMaterialActivationId ||
      product.walletKeyId !== child.walletKeyId ||
      product.keyFamily !== child.keyFamily ||
      product.laneId !== child.targetLaneId ||
      product.laneShareEpoch !== child.targetLaneShareEpoch ||
      product.aggregateManifestDigestB64u !== receipt.manifestDigestB64u ||
      product.aggregateActivationReceiptDigestB64u !== receipt.aggregateReceiptDigestB64u ||
      !mpcMaterialActivationRefsEqual(product.materialActivation, child.materialActivation)
    ) {
      throw new Error(`linked-device Wallet Session product ${index} is invalid`);
    }
    if (revocationEpoch === null) revocationEpoch = product.revocationEpoch;
    else if (revocationEpoch !== product.revocationEpoch) {
      throw new Error('linked-device Wallet Session products have different revocation epochs');
    }
  }
  if (revocationEpoch === null) {
    throw new Error('linked-device Wallet Session has no active products');
  }
  return revocationEpoch;
}
