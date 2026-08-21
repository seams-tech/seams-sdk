import {
  DEFAULT_WALLET_SESSION_TTL_MS,
  DEFAULT_WALLET_SESSION_REMAINING_USES,
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

export type CommittedLinkedDeviceSessionRecordV1 = Extract<
  LinkedDeviceSessionRecordV1,
  { readonly state: { readonly state: 'committed_completion_required' } }
>;

export type WalletSessionEligibleLinkedDeviceSessionRecordV1 =
  | CommittedLinkedDeviceSessionRecordV1
  | ActiveLinkedDeviceSessionRecordV1;

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

export type ActiveLinkedDeviceWalletSessionResolutionV1 =
  | {
      readonly kind: 'active';
      readonly authorization: IssuedLinkedDeviceWalletSession;
    }
  | { readonly kind: 'unavailable' };

export type LinkedDeviceWalletSessionRenewalTargetV1 = {
  readonly tenantId: TenantId;
  readonly deviceId: IssueLinkedDeviceWalletSessionInput['deviceId'];
  readonly enrollmentId: IssueLinkedDeviceWalletSessionInput['enrollmentId'];
  readonly authorizationId: Awaited<
    ReturnType<typeof deriveLinkedDeviceWalletSessionIdentityV1>
  >['authorizationId'];
  readonly walletSessionId: Awaited<
    ReturnType<typeof deriveLinkedDeviceWalletSessionIdentityV1>
  >['walletSessionId'];
  readonly quotaId: Awaited<
    ReturnType<typeof deriveLinkedDeviceWalletSessionIdentityV1>
  >['quotaId'];
  readonly revocationEpoch: number;
};

export class D1LinkedDeviceWalletSessionIssuerV1 {
  constructor(private readonly options: D1LinkedDeviceWalletSessionIssuerOptionsV1) {}

  async issueForEligibleSessionV1(input: {
    readonly session: WalletSessionEligibleLinkedDeviceSessionRecordV1;
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
        return;
      case 'invalid':
        throw new Error('linked-device Wallet Session persisted identity is invalid');
      default:
        return assertNeverLinkedDeviceWalletSessionStatus(status);
    }
  }

  async resolveRenewalTargetV1(input: {
    readonly session: ActiveLinkedDeviceSessionRecordV1;
    readonly requestedAtMs: number;
  }): Promise<
    | { readonly kind: 'available'; readonly target: LinkedDeviceWalletSessionRenewalTargetV1 }
    | { readonly kind: 'unavailable' }
  > {
    const issueInput = await this.buildIssueInputV1(input);
    const identity = await deriveLinkedDeviceWalletSessionIdentityV1(issueInput);
    const status = await this.options.authorizationService.getLinkedDeviceWalletSessionStatus({
      tenantId: issueInput.tenantId,
      deviceId: issueInput.deviceId,
      ...identity,
      nowMs: input.requestedAtMs,
    });
    switch (status.kind) {
      case 'active':
      case 'exhausted':
      case 'expired':
        return {
          kind: 'available',
          target: {
            tenantId: issueInput.tenantId,
            deviceId: issueInput.deviceId,
            enrollmentId: issueInput.enrollmentId,
            ...identity,
            revocationEpoch: status.revocationEpoch,
          },
        };
      case 'missing':
      case 'invalid':
      case 'revoked':
        return { kind: 'unavailable' };
      default:
        return assertNeverLinkedDeviceWalletSessionStatus(status);
    }
  }

  async readActiveForSessionV1(input: {
    readonly session: ActiveLinkedDeviceSessionRecordV1;
    readonly requestedAtMs: number;
  }): Promise<IssuedLinkedDeviceWalletSession> {
    const resolution = await this.resolveActiveForSessionV1(input);
    if (resolution.kind === 'active') return resolution.authorization;
    throw new Error('linked-device Wallet Session authorization is missing');
  }

  async resolveActiveForSessionV1(input: {
    readonly session: WalletSessionEligibleLinkedDeviceSessionRecordV1;
    readonly requestedAtMs: number;
  }): Promise<ActiveLinkedDeviceWalletSessionResolutionV1> {
    const issueInput = await this.buildIssueInputV1(input);
    const identity = await deriveLinkedDeviceWalletSessionIdentityV1(issueInput);
    const issued =
      await this.options.authorizationService.readLinkedDeviceWalletSessionAuthorization({
        tenantId: issueInput.tenantId,
        deviceId: issueInput.deviceId,
        ...identity,
        nowMs: input.requestedAtMs,
      });
    if (!issued) return { kind: 'unavailable' };
    return { kind: 'active', authorization: issued };
  }

  private async buildIssueInputV1(input: {
    readonly session: WalletSessionEligibleLinkedDeviceSessionRecordV1;
    readonly requestedAtMs: number;
  }): Promise<IssueLinkedDeviceWalletSessionInput> {
    const { session, requestedAtMs } = input;
    const approval = session.approvalTranscript.value;
    requireWalletSessionEligibleIdentity(session);
    if (!Number.isSafeInteger(requestedAtMs) || requestedAtMs < session.updatedAtMs) {
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
      manifestDigestB64u !== walletSessionManifestDigestV1(session) ||
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
    const revocationEpoch = requireWalletSessionProductCoverage(session, manifest, products);
    const issuedAtMs = requestedAtMs;
    const expiresAtMs = issuedAtMs + DEFAULT_WALLET_SESSION_TTL_MS;
    if (!Number.isSafeInteger(expiresAtMs)) {
      throw new Error('linked-device Wallet Session expiry is invalid');
    }
    return {
      tenantId: this.options.tenantId,
      deviceId: approval.deviceId,
      walletId: approval.walletId,
      enrollmentId: approval.enrollmentId,
      keyManifestDigestB64u: walletSessionManifestDigestV1(session),
      permission: approval.permission,
      revocationEpoch,
      remainingUses: DEFAULT_WALLET_SESSION_REMAINING_USES,
      issuedAtMs,
      expiresAtMs,
    };
  }
}

function assertNeverLinkedDeviceWalletSessionStatus(value: never): never {
  throw new Error(`unknown linked-device Wallet Session status: ${String(value)}`);
}

function requireWalletSessionEligibleIdentity(
  session: WalletSessionEligibleLinkedDeviceSessionRecordV1,
): void {
  const approval = session.approvalTranscript.value;
  const claim = session.claimTranscript.value;
  if (
    approval.linkSessionId !== session.linkSessionId ||
    approval.linkSessionId !== session.state.linkSessionId ||
    approval.walletId !== session.state.walletId ||
    approval.enrollmentId !== session.state.enrollmentId ||
    approval.deviceId !== claim.deviceId
  ) {
    throw new Error('linked-device Wallet Session eligible session binding is invalid');
  }
  if (!isActiveWalletSessionEligibleRecordV1(session)) return;
  const receipt = session.aggregateReceipt;
  if (
    receipt.walletId !== approval.walletId ||
    receipt.enrollmentId !== approval.enrollmentId ||
    receipt.deviceId !== approval.deviceId
  ) {
    throw new Error('linked-device active Wallet Session receipt identity is invalid');
  }
  if (receipt.activatedAtMs !== session.state.activatedAtMs) {
    throw new Error('linked-device active Wallet Session timestamp binding is invalid');
  }
}

function isActiveWalletSessionEligibleRecordV1(
  session: WalletSessionEligibleLinkedDeviceSessionRecordV1,
): session is ActiveLinkedDeviceSessionRecordV1 {
  switch (session.state.state) {
    case 'active':
      return true;
    case 'committed_completion_required':
      return false;
    }
  return session.state satisfies never;
}

function walletSessionManifestDigestV1(
  session: WalletSessionEligibleLinkedDeviceSessionRecordV1,
) {
  if (isActiveWalletSessionEligibleRecordV1(session)) {
    return session.aggregateReceipt.manifestDigestB64u;
  }
  return session.state.keyManifestDigestB64u;
}

function requireWalletSessionProductCoverage(
  session: WalletSessionEligibleLinkedDeviceSessionRecordV1,
  manifest: LaneEnrollmentManifestV1,
  products: Awaited<ReturnType<CloudflareD1LaneLifecycleStore['listEnrollmentProductEpochs']>>,
): number {
  const approval = session.approvalTranscript.value;
  if (
    manifest.orderedChildren.length !== approval.orderedKeyBindings.length ||
    products.length !== manifest.orderedChildren.length
  ) {
    throw new Error('linked-device Wallet Session product coverage is incomplete');
  }
  const receipt = isActiveWalletSessionEligibleRecordV1(session)
    ? session.aggregateReceipt
    : null;
  if (receipt && products.length !== receipt.orderedChildReceipts.length) {
    throw new Error('linked-device active Wallet Session receipt coverage is incomplete');
  }
  const productsByOperation = new Map<string, (typeof products)[number]>();
  for (const product of products) {
    const operationId = String(product.operationId);
    if (productsByOperation.has(operationId)) {
      throw new Error('linked-device Wallet Session products contain duplicate operations');
    }
    productsByOperation.set(operationId, product);
  }
  // The grant carries an enrollment fence. Child lanes retain their own
  // revocation epochs, so the fence is the max active child epoch rather than
  // an equality requirement across independently refreshed lanes.
  let revocationEpoch = 0;
  let activeProductCount = 0;
  for (let index = 0; index < manifest.orderedChildren.length; index += 1) {
    const manifestChild = manifest.orderedChildren[index];
    const binding = approval.orderedKeyBindings[index];
    const child = receipt?.orderedChildReceipts[index];
    const product = manifestChild
      ? productsByOperation.get(String(manifestChild.operationId))
      : undefined;
    if (
      !manifestChild ||
      !product ||
      !binding ||
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
      product.aggregateManifestDigestB64u !== walletSessionManifestDigestV1(session) ||
      (child !== undefined &&
        (product.walletKeyId !== child.walletKeyId ||
          product.keyFamily !== child.keyFamily ||
          product.laneId !== child.targetLaneId ||
          product.laneShareEpoch !== child.targetLaneShareEpoch ||
          product.aggregateActivationReceiptDigestB64u !== receipt?.aggregateReceiptDigestB64u ||
          !mpcMaterialActivationRefsEqual(product.materialActivation, child.materialActivation)))
    ) {
      throw new Error(`linked-device Wallet Session product ${index} is invalid`);
    }
    activeProductCount += 1;
    revocationEpoch = Math.max(revocationEpoch, product.revocationEpoch);
  }
  if (activeProductCount === 0) {
    throw new Error('linked-device Wallet Session has no active products');
  }
  return revocationEpoch;
}
