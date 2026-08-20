import type { FinalizeWalletAddAuthMethodCommand } from '../../../framework/authServicePort';
import type { WalletAddAuthMethodFinalizeResponse } from '../../../../core/registrationContracts';
import type {
  LinkedOwnerEmailOtpBaseFactorReaderV1,
  LinkedOwnerEnrollmentCeremonyReaderV1,
} from '../../../../core/deviceLinking/linkedOwnerEnrollmentProvenance';
import { parseLinkDeviceSessionId, type LinkDeviceSessionId } from '@shared/signing-lanes/ids';
import { readJson } from '../../../../router/framework/http';
import { LinkedDeviceRequestProofVerifierV1 } from '../../../../core/deviceLinking/requestProof';
import { type LinkedDeviceOwnerAuthorizationPortV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import type { D1DatabaseLike, D1PreparedStatementLike } from '../../../../storage/tenantRoute';
import type { WalletId } from '@shared/utils/domainIds';
import {
  parseLinkedDeviceLocalAccountProjectionV1,
  type LinkedDeviceLocalAccountProjectionV1,
} from '@shared/device-linking';
import { D1LinkedDeviceRequestProofNonceStoreV1 } from './d1LinkedDeviceRequestProofNonceStore';
import { D1LinkedDeviceCustodyTransferStoreV1 } from './d1LinkedDeviceCustodyTransferStore';
import { type D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';
import { CloudflareD1LaneLifecycleStore } from '../signingLanes/d1LaneLifecycleStore';
import { createD1LinkedDeviceSessionServiceV1 } from './d1LinkedDeviceSessionService';
import { D1LinkedDeviceProvisioningVerifierV1 } from './d1LinkedDeviceProvisioningVerifier';
import {
  createD1LinkedDeviceCompletionAdaptersV1,
  D1LinkedDeviceCommittedDeliveryRetryV1,
} from './d1LinkedDeviceCompletionAdapters';
import {
  D1LinkedDeviceWalletSessionIssuerV1,
  type ActiveLinkedDeviceSessionRecordV1,
} from './d1LinkedDeviceWalletSessionIssuer';
import type { AuthorizationService } from '../../../../authorization/service';
import type { TenantId } from '@shared/authorization/capabilityKinds';
import { D1WalletStore } from '../../../../core/d1WalletStore';
import { alphabetizeStringify } from '@shared/utils/digests';
import type {
  DeviceLinkingAuthenticatedRequestV1,
  DeviceLinkingAuthDeniedV1,
  DeviceLinkingDeviceAuthenticatedRequestV1,
  DeviceLinkingOwnerRequestInputV1,
  DeviceLinkingOperatorRecoveryProviderV1,
  DeviceLinkingOwnerSourceHandoffProviderV1,
  DeviceLinkingRouteServiceV1,
} from '../../../../router/transport/fetch/routes/deviceLinking';
import type { LinkedDeviceLocalPresenceVerifierPortV1 } from '../../../auth/linkedDeviceLocalPresenceVerifier';
import { verifyLinkedDeviceLocalPresenceForOperation } from '../../../domains/signingOperations/linkedDeviceNormalSigning';
import { buildLinkedDeviceWalletSessionRenewalCapabilityV1 } from '../../../domains/signingOperations/walletExecutionAdmission';
import {
  computeLinkedDeviceWalletSessionRenewalIntentDigestV1,
  linkedDeviceWalletSessionRenewalAuthorizedOperationIdV1,
} from '@shared/device-linking/digests';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { parseNearAccountId } from '@shared/utils/near';

export type D1LinkedDeviceRouteServiceOptionsV1 = {
  readonly database: D1DatabaseLike;
  readonly scope: D1LinkedDeviceSessionScopeV1;
  readonly tenantId: TenantId;
  readonly expectedOrigin: string;
  /** The canonical add-auth-method service; the linked finalize reuses it. */
  readonly walletAuthMethods: {
    /**
     * The second argument is how the linked finalize stays atomic: the session
     * CAS travels in the same batch as the credential it belongs to.
     */
    finalizeWalletAddAuthMethod(
      command: FinalizeWalletAddAuthMethodCommand,
      atomicCompanionStatements: readonly D1PreparedStatementLike[],
    ): Promise<WalletAddAuthMethodFinalizeResponse>;
  };
  readonly authorizationService: Pick<
    AuthorizationService,
    | 'getLinkedDeviceWalletSessionStatus'
    | 'issueLinkedDeviceWalletSession'
    | 'readLinkedDeviceWalletSessionAuthorization'
    | 'renewLinkedDeviceWalletSession'
  >;
  readonly linkedDeviceLocalPresence: LinkedDeviceLocalPresenceVerifierPortV1;
  readonly ownerAuthorization: LinkedDeviceOwnerAuthorizationPortV1;
  /** Reads back the add-auth-method ceremony an approval names, for provenance. */
  readonly ownerEnrollmentCeremonies: LinkedOwnerEnrollmentCeremonyReaderV1;
  /** Approval-time base Email OTP factor provenance; unwired = fail-closed. */
  readonly emailOtpBaseFactors?: LinkedOwnerEmailOtpBaseFactorReaderV1;
  /** The Email OTP challenge/verify/release surface; unwired = routes answer 501. */
  readonly emailOtpTargetFactor?: DeviceLinkingRouteServiceV1['emailOtpTargetFactor'];
  readonly authenticateOwnerRequestV1: (
    input: DeviceLinkingOwnerRequestInputV1,
  ) => Promise<DeviceLinkingAuthenticatedRequestV1 | DeviceLinkingAuthDeniedV1>;
  readonly targetCredential: DeviceLinkingRouteServiceV1['targetCredential'];
  readonly operatorRecovery?: DeviceLinkingOperatorRecoveryProviderV1;
  readonly provisioning: DeviceLinkingRouteServiceV1['provisioning'];
  readonly sourceHandoff: ConstructorParameters<typeof D1LinkedDeviceCommittedDeliveryRetryV1>[0];
  readonly nowV1?: () => number;
};

export function createD1LinkedDeviceRouteServiceV1(
  options: D1LinkedDeviceRouteServiceOptionsV1,
): DeviceLinkingRouteServiceV1 {
  const nowV1 = options.nowV1 ?? Date.now;
  const proofNonceStore = new D1LinkedDeviceRequestProofNonceStoreV1({
    database: options.database,
    scope: options.scope,
  });
  const proofVerifier = new LinkedDeviceRequestProofVerifierV1({ nonceStore: proofNonceStore });
  const laneLifecycle = new CloudflareD1LaneLifecycleStore({
    database: options.database,
    scope: options.scope,
    now: nowV1,
  });
  const { sessionService, sessionStore } = createD1LinkedDeviceSessionServiceV1({
    database: options.database,
    scope: options.scope,
    ownerAuthorization: options.ownerAuthorization,
    ownerEnrollmentCeremonies: options.ownerEnrollmentCeremonies,
    ...(options.emailOtpBaseFactors === undefined
      ? {}
      : { emailOtpBaseFactors: options.emailOtpBaseFactors }),
    laneLifecycle,
    nowV1,
  });
  const provisioningVerifier = new D1LinkedDeviceProvisioningVerifierV1({
    lifecycleStore: laneLifecycle,
  });
  const walletSessionIssuer = new D1LinkedDeviceWalletSessionIssuerV1({
    tenantId: options.tenantId,
    authorizationService: options.authorizationService,
    laneLifecycle,
  });
  const walletStore = new D1WalletStore({
    database: options.database,
    namespace: options.scope.namespace,
    orgId: options.scope.orgId,
    projectId: options.scope.projectId,
    envId: options.scope.envId,
  });
  const completion = createD1LinkedDeviceCompletionAdaptersV1({
    sessionService,
    sourceHandoff: options.sourceHandoff,
  });
  const acknowledgeReceiptV1 = acknowledgeReceiptAndIssueWalletSessionV1.bind(
    undefined,
    completion.acknowledgement.acknowledgeReceiptV1.bind(completion.acknowledgement),
    walletSessionIssuer,
  );
  const readWalletSessionAuthorizationV1: DeviceLinkingRouteServiceV1['readWalletSessionAuthorizationV1'] =
    async (input) => await walletSessionIssuer.resolveActiveForSessionV1(input);
  const renewWalletSessionAuthorizationV1: DeviceLinkingRouteServiceV1['renewWalletSessionAuthorizationV1'] =
    async (input) => {
      const target = await walletSessionIssuer.resolveRenewalTargetV1({
        session: input.session,
        requestedAtMs: input.requestedAtMs,
      });
      if (target.kind === 'unavailable') return target;
      const authorizedOperationId = linkedDeviceWalletSessionRenewalAuthorizedOperationIdV1();
      const intentDigestB64u = await computeLinkedDeviceWalletSessionRenewalIntentDigestV1({
        authorizationId: target.target.authorizationId,
        walletSessionId: target.target.walletSessionId,
        quotaId: target.target.quotaId,
        deviceId: target.target.deviceId,
        enrollmentId: target.target.enrollmentId,
      });
      const presence = await verifyLinkedDeviceLocalPresenceForOperation({
        assertion: input.localPresenceAssertion,
        verifier: options.linkedDeviceLocalPresence,
        authorizedOperationId,
        deviceId: target.target.deviceId,
        enrollmentId: target.target.enrollmentId,
        intentDigestB64u,
        nowMs: () => input.requestedAtMs,
      });
      if (presence.kind === 'refused') {
        return { kind: 'local_presence_refused', reason: presence.reason };
      }
      const renewal = buildLinkedDeviceWalletSessionRenewalCapabilityV1({
        evidence: presence.evidence,
        tenantId: target.target.tenantId,
        deviceId: target.target.deviceId,
        enrollmentId: target.target.enrollmentId,
        authorizationId: target.target.authorizationId,
        walletSessionId: target.target.walletSessionId,
        quotaId: target.target.quotaId,
        revocationEpoch: target.target.revocationEpoch,
        authorizedOperationId,
        intentDigestB64u,
      });
      const authorization = await options.authorizationService.renewLinkedDeviceWalletSession({
        renewedAtMs: renewal.verifiedAtMs,
        renewal,
      });
      return { kind: 'active', authorization };
    };
  const routeSessionService: DeviceLinkingRouteServiceV1['sessionService'] = {
    createUnclaimedSessionV1: sessionService.createUnclaimedSessionV1.bind(sessionService),
    claimSessionV1: sessionService.claimSessionV1.bind(sessionService),
    recordOwnerApprovalV1: sessionService.recordOwnerApprovalV1.bind(sessionService),
    recordTargetCredentialV1: sessionService.recordTargetCredentialV1.bind(sessionService),
    recordEmailOtpChallengeStateV1:
      sessionService.recordEmailOtpChallengeStateV1.bind(sessionService),
    bindRecoveryContinuationV1: sessionService.bindRecoveryContinuationV1.bind(sessionService),
    cancelSessionV1: sessionService.cancelSessionV1.bind(sessionService),
    // A string input is the pre-proof, read-only QR lookup. Authenticated reads
    // use the core service so expiry projection receives the request clock.
    getSessionV1: async (input) =>
      typeof input === 'string'
        ? await sessionStore.getSessionV1(input)
        : await sessionService.getSessionV1(input),
    listSessionsForWalletV1: sessionService.listSessionsForWalletV1.bind(sessionService),
  };
  return {
    sessionService: routeSessionService,
    nowV1,
    ...(options.emailOtpTargetFactor === undefined
      ? {}
      : { emailOtpTargetFactor: options.emailOtpTargetFactor }),
    // Refactor 103 Phase 8: Device 1 seals the wallet custody seed to the
    // recipient Device 2 publishes, through this store. Left unwired, the
    // routes answer 501 and linking dies after the owner has already asserted.
    custodyTransfer: new D1LinkedDeviceCustodyTransferStoreV1({
      database: options.database,
      scope: options.scope,
    }),
    // Same finalizer the owner add-auth-method route calls. The tenant is this
    // service's own, so the route never names one.
    finalizeLinkedOwnerEnrollmentV1: async (input) => {
      // Reserve the awaiting session revision in the same transaction as the
      // owner credential. The target-credential route alone starts provisioning.
      const plan = await sessionService.prepareLinkedOwnerEnrollmentCompletionV1({
        linkSessionId: input.linkSessionId,
        expectedRevision: input.expectedRevision,
        nowMs: input.nowMs,
      });
      if (plan.outcome !== 'prepared') {
        return { outcome: 'completion_refused', completion: plan };
      }
      const response = await options.walletAuthMethods.finalizeWalletAddAuthMethod(
        {
          addAuthMethodCeremonyId: input.addAuthMethodCeremonyId,
          webauthnRegistration: input.webauthnRegistration,
          custodyEnvelope: input.custodyEnvelope,
          subject: {
            kind: 'wallet_auth_method_management',
            walletId: input.admission.walletId,
          },
          authorization: {
            kind: 'linked_device',
            tenantId: options.tenantId,
            admission: input.admission,
            expectedOrigin: options.expectedOrigin,
          },
        },
        sessionStore.buildTargetCredentialCasStatementsV1(plan),
      );
      if (!response.ok) return { outcome: 'finalized', response };
      // Read after the finalize committed, so it reflects the wallet Device 2 is
      // now an owner of rather than a snapshot taken before it joined.
      return {
        outcome: 'finalized',
        response,
        localAccount: await buildLinkedDeviceLocalAccountProjectionV1(
          walletStore,
          input.admission.walletId,
        ),
      };
    },
    verifyPublicSessionProofV1: async (input) => {
      const result = await proofVerifier.verifyPublicCreateV1({
        proof: input.proof,
        devicePublicKeyB64u: input.payload.devicePublicKeyB64u,
        devicePublicKeyDigestB64u: input.devicePublicKeyDigestB64u,
        linkSessionId: input.payload.linkSessionId,
        method: input.method,
        canonicalPath: input.canonicalPath,
        bodyDigestB64u: input.bodyDigestB64u,
        nowMs: input.requestedAtMs,
      });
      return result.kind === 'authorized' ? result : mapProofDenied(result);
    },
    authenticateOwnerRequestV1: options.authenticateOwnerRequestV1,
    authenticateDeviceRequestV1: async (input) => {
      const linkSessionId = parseSessionId(input.linkSessionId);
      const result = await proofVerifier.verifyV1({
        proof: input.proof,
        expectedDevicePublicKeyB64u: input.expectedDevicePublicKeyB64u,
        expectedDevicePublicKeyDigestB64u: input.expectedDevicePublicKeyDigestB64u,
        expectedLinkSessionId: linkSessionId,
        expectedMethod: input.method,
        expectedCanonicalPath: input.pathname,
        expectedBodyDigestB64u: input.bodyDigestB64u,
        nowMs: input.requestedAtMs,
      });
      if (result.kind === 'denied') return mapProofDenied(result);
      const body = input.method === 'GET' ? null : await readJson(input.request);
      return {
        kind: 'authorized',
        body,
        proof: input.proof,
      } satisfies DeviceLinkingDeviceAuthenticatedRequestV1;
    },
    targetCredential: options.targetCredential,
    acknowledgeReceiptV1,
    readWalletSessionAuthorizationV1,
    renewWalletSessionAuthorizationV1,
    resolveNearAccountIdForEd25519WalletKeyV1: resolveNearAccountIdForEd25519WalletKeyV1.bind(
      undefined,
      walletStore,
    ),
    resolveEd25519OwnerActivationV1: resolveEd25519OwnerActivationV1.bind(undefined, walletStore),
    retryCommittedDeliveryV1: completion.retry.retryCommittedDeliveryV1.bind(completion.retry),
    operatorRecovery: options.operatorRecovery,
    provisioning: options.provisioning,
    provisioningVerifier,
    sourceHandoff: options.sourceHandoff,
  };
}

async function resolveNearAccountIdForEd25519WalletKeyV1(
  walletStore: D1WalletStore,
  input: Parameters<DeviceLinkingRouteServiceV1['resolveNearAccountIdForEd25519WalletKeyV1']>[0],
): Promise<string> {
  return (await requireCanonicalEd25519SignerV1(walletStore, input.walletId)).nearAccountId;
}

async function resolveEd25519OwnerActivationV1(
  walletStore: D1WalletStore,
  input: Parameters<DeviceLinkingRouteServiceV1['resolveEd25519OwnerActivationV1']>[0],
): ReturnType<DeviceLinkingRouteServiceV1['resolveEd25519OwnerActivationV1']> {
  const signer = await requireCanonicalEd25519SignerV1(walletStore, input.walletId);
  const expectedWalletKeyId = `wallet-key:ed25519:${signer.walletId}:${signer.nearEd25519SigningKeyId}`;
  if (String(input.walletKeyId) !== expectedWalletKeyId) {
    throw new Error('linked-device Ed25519 owner activation names another wallet key');
  }
  const capability = signer.activeYaoCapability;
  const nearAccountId = parseNearAccountId(signer.nearAccountId);
  if (!nearAccountId.ok) {
    throw new Error('linked-device Ed25519 owner activation has an invalid NEAR account');
  }
  return {
    kind: 'present',
    nearAccountId: nearAccountId.value,
    nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
    signerSlot: signer.signerSlot,
    signingWorkerId: signer.signingWorkerId,
    thresholdSessionId: signer.thresholdSessionId,
    signingRootId: signer.signingRootId,
    signingRootVersion: signer.signingRootVersion,
    walletSessionToken: input.walletSessionToken,
    runtimePolicyScope: signer.runtimePolicyScope,
    routerAbNormalSigning: {
      kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
      signingWorkerId: signer.signingWorkerId,
    },
    recoveryBasis: {
      materialActivation: routerAbMpcMaterialActivationRefFromWire(
        capability.activationResult.public_receipt.material_activation,
      ),
      activeCapabilityBinding: capability.activeCapabilityBinding,
      registeredPublicKey: capability.activationResult.public_receipt.registered_public_key,
      applicationBinding: capability.admissionRequest.application_binding,
      participantIds: signer.participantIds,
      lifecycle: {
        lifecycleId: capability.admissionRequest.scope.lifecycle_id,
        rootShareEpoch: capability.admissionRequest.scope.root_share_epoch,
        accountId: capability.admissionRequest.scope.account_id,
        thresholdSessionId: signer.thresholdSessionId,
        signerSetId: capability.admissionRequest.scope.signer_set_id,
        signingWorkerId: signer.signingWorkerId,
      },
    },
  };
}

/**
 * The wallet's one canonical Ed25519 signer.
 *
 * Exactly one, cross-checked against its own active Yao capability: this signer
 * is the source of the identity Device 2 persists locally, and a wallet with two
 * of them or with a capability naming a different account has no single answer
 * to give.
 */
async function requireCanonicalEd25519SignerV1(walletStore: D1WalletStore, walletId: WalletId) {
  const signers = await walletStore.listEd25519SignersForWallet({ walletId });
  if (signers.length !== 1) {
    throw new Error('authoritative linked-device NEAR account identity is unavailable');
  }
  const signer = signers[0]!;
  if (signer.activeYaoCapability.nearAccountId !== signer.nearAccountId) {
    throw new Error('authoritative linked-device NEAR account identity changed');
  }
  return signer;
}

/**
 * The local account identity a finalized linked device needs.
 *
 * `signerSlot` is the canonical signer's own slot, which is what
 * `keyCreationSignerSlot` is derived from everywhere else in the server. It is
 * not allocated per device or per auth method — Device 2 adds a factor to one
 * existing wallet key rather than creating a key — and it deliberately does not
 * come from the temporary R102 target child, which the lane cutover removes.
 */
async function buildLinkedDeviceLocalAccountProjectionV1(
  walletStore: D1WalletStore,
  walletId: WalletId,
): Promise<LinkedDeviceLocalAccountProjectionV1> {
  const signer = await requireCanonicalEd25519SignerV1(walletStore, walletId);
  return parseLinkedDeviceLocalAccountProjectionV1({
    kind: 'linked_device_local_account_projection_v1',
    walletId: String(walletId),
    nearAccountId: signer.nearAccountId,
    signerSlot: signer.signerSlot,
  });
}

async function acknowledgeReceiptAndIssueWalletSessionV1(
  acknowledgeReceiptV1: DeviceLinkingRouteServiceV1['acknowledgeReceiptV1'],
  walletSessionIssuer: D1LinkedDeviceWalletSessionIssuerV1,
  input: Parameters<DeviceLinkingRouteServiceV1['acknowledgeReceiptV1']>[0],
): ReturnType<DeviceLinkingRouteServiceV1['acknowledgeReceiptV1']> {
  const result = await acknowledgeReceiptV1(input);
  if (
    (result.outcome !== 'applied' && result.outcome !== 'replayed') ||
    !isActiveLinkedDeviceSessionRecord(result.record)
  ) {
    return result;
  }
  if (
    result.record.linkSessionId !== input.acknowledgement.linkSessionId ||
    alphabetizeStringify(result.record.aggregateReceipt) !==
      alphabetizeStringify(input.acknowledgement.receipt)
  ) {
    throw new Error('linked-device receipt acknowledgement returned a different active session');
  }
  await walletSessionIssuer.issueForActiveSessionV1({
    session: result.record,
    requestedAtMs: input.requestedAtMs,
  });
  return result;
}

function isActiveLinkedDeviceSessionRecord(
  record: DeviceLinkingRouteMutationResultV1Record,
): record is ActiveLinkedDeviceSessionRecordV1 {
  return record.state.state === 'active';
}

type DeviceLinkingRouteMutationResultV1Record = Extract<
  Awaited<ReturnType<DeviceLinkingRouteServiceV1['acknowledgeReceiptV1']>>,
  { readonly outcome: 'applied' | 'replayed' }
>['record'];

function parseSessionId(raw: string): LinkDeviceSessionId {
  const result = parseLinkDeviceSessionId(raw);
  if (!result.ok) throw new Error(`link session id is invalid: ${result.error.message}`);
  return result.value;
}

function mapProofDenied(
  result: Extract<
    Awaited<ReturnType<LinkedDeviceRequestProofVerifierV1['verifyV1']>>,
    { readonly kind: 'denied' }
  >,
): DeviceLinkingAuthDeniedV1 {
  return {
    kind: 'denied',
    code: result.code,
    message: result.message,
  };
}
