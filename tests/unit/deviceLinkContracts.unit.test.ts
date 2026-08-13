import { expect, test } from '@playwright/test';
import {
  buildActiveLinkedDeviceSessionState,
  buildCancelledUnclaimedLinkedDeviceSessionState,
  buildCommittedCompletionRequiredLinkedDeviceSessionState,
  computeLinkedDeviceApprovalDigestV1,
  computeLinkedDeviceSessionClaimDigestV1,
  buildLinkedDeviceHolderDeliveryAcknowledgementV1,
  buildLinkedDeviceProvisioningCommandV1,
  buildLinkedDeviceTargetCredentialRegistrationV1,
  buildLinkedDeviceTargetPreparationV1,
  assertLinkedDeviceTargetCredentialRegistrationMatchesPreparationV1,
  computeLinkedDeviceTargetPreparationDigestV1,
  parseLinkedDeviceApprovalV1,
  parseLinkedDeviceHolderDeliveryAcknowledgementV1,
  parseLinkedDeviceEnrollmentReceiptV1,
  parseLinkedDeviceEnrollmentTranscriptV1,
  parseLinkedDeviceProvisioningCommandV1,
  parseLinkedDeviceProvisioningDeliveriesV1,
  parseLinkedDeviceProvisioningDeliveriesSubmissionV1,
  parseLinkedDeviceSessionState,
  parseLinkedDeviceSessionTransportRequestV1,
  parseLinkedDeviceTargetCredentialRegistrationV1,
  parseLinkedDeviceTargetPreparationV1,
  parseLinkedDeviceTargetReadyR102InputV1,
  parseLinkedDeviceWalletSessionDeliveryV1,
  parseLinkedDeviceOwnerAuthorizationRequestV1,
  parseLinkedDeviceOwnerSourceLaneV1,
  parseQrLinkedDeviceSessionPayloadV4,
} from '../../packages/shared-ts/src/device-linking';
import type { HttpTransport } from '../../packages/sdk-web/src/core/platform/http';
import { createWalletHostOwnerAuthoritiesV1 } from '../../packages/sdk-web/src/SeamsWeb/operations/devices/walletHostOwnerAuthority';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import { buildOwnerWalletExecutionEvidenceFixture } from './helpers/walletExecutionLane.fixtures';
import { availableLaneEd25519Authorization } from './helpers/availableSigningLanes.fixtures';
import {
  buildR102HolderDeliveryReceipt,
  buildR102LaneJob,
  buildR102ManifestChild,
  buildR102ProtocolCommitReceipt,
} from './helpers/r102LaneGateway.fixtures';
import { parseRotatableSigningLaneJobV1 } from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import { buildLaneEnrollmentManifestV1 } from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import {
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '../../packages/shared-ts/src/utils/domainIds';
import { buildR103LinkedWalletSessionDeliveryFixture } from './helpers/deviceLinkContracts.fixtures';

function manifestForJob(job: ReturnType<typeof buildR102LaneJob>) {
  return buildLaneEnrollmentManifestV1({
    enrollmentId: job.enrollmentId,
    walletId: job.walletId,
    authorization: job.authorization,
    orderedChildren: [buildR102ManifestChild(job)],
    createdAtMs: 1_000,
    expiresAtMs: job.expiresAtMs,
  });
}

test.describe('R103 shared linked-device contracts', () => {
  test('wallet-host owner authorization sends only authenticated public source projections', async () => {
    const deviceLink = buildR103DeviceLinkFixture();
    const owner = await buildOwnerWalletExecutionEvidenceFixture();
    const sourceHint = parseLinkedDeviceOwnerSourceLaneV1({
      kind: 'linked_device_owner_source_lane_v1',
      keyFamily: 'ecdsa_secp256k1',
      walletKey: owner.walletKey,
      lane: owner.lane,
      materialActivation: owner.materialActivation,
      verifiedActivationReceiptDigestB64u: owner.verifiedActivationReceiptDigestB64u,
      ecdsaSourceManifest: {
        manifestId: 'ecdsa-manifest-fixture',
        manifestRevision: 1,
      },
    });
    const projection = availableLaneEd25519Authorization({
      walletId: String(owner.walletId),
      identitySeed: 'owner-authorization',
      authMethod: 'passkey',
    });
    let captured: Parameters<HttpTransport['request']>[0] | null = null;
    const http: HttpTransport = {
      kind: 'http_transport',
      request: async (input) => {
        captured = input;
        return {
          ok: true,
          value: { status: 400, body: { message: 'stop after capture' } },
        };
      },
    };
    const authorities = createWalletHostOwnerAuthoritiesV1({
      http,
      relayerUrl: 'https://relay.example.test',
      walletSessions: {
        read: async () => ({ kind: 'missing' as const }),
        readActiveForWallet: async () => ({ kind: 'found' as const, projection }),
      },
      readWalletAuthenticationState: () => ({
        kind: 'authenticated',
        walletId: projection.walletId,
        authMethod: projection.authMethod,
      }),
      readOwnerSourceLaneHintsV1: async () => [sourceHint],
    });

    await expect(
      authorities.ownerAuthorization.authenticateOwnerForLinkingV1({
        payload: deviceLink.payload,
        requestedAtMs: 2_000,
      }),
    ).rejects.toThrow('Owner authorization failed');
    expect(captured?.headers?.authorization).toBe(
      'Bearer fixture-wallet-session-jwt:owner-authorization',
    );
    expect(captured?.url).toBe(
      'https://relay.example.test/wallet/device-linking/v1/owner-authorization',
    );
    const body = parseLinkedDeviceOwnerAuthorizationRequestV1(captured?.body);
    expect(body.orderedOwnerSourceLaneHints).toEqual([sourceHint]);
    expect(JSON.stringify(captured?.body)).not.toContain('walletSessionJwt');
    expect(JSON.stringify(captured?.body)).not.toContain('privateKey');
  });

  test('round-trips QR, approval, transcript, and receipt projections through strict parsers', async () => {
    const fixture = buildR103DeviceLinkFixture();

    expect(parseQrLinkedDeviceSessionPayloadV4(fixture.payload)).toEqual(fixture.payload);
    expect(parseLinkedDeviceApprovalV1(fixture.approval)).toEqual(fixture.approval);
    expect(parseLinkedDeviceEnrollmentTranscriptV1(fixture.transcript)).toEqual(fixture.transcript);
    expect(parseLinkedDeviceEnrollmentReceiptV1(fixture.receipt)).toEqual(fixture.receipt);

    const claimDigest = await computeLinkedDeviceSessionClaimDigestV1({
      kind: 'linked_device_session_claim_v1',
      linkSessionId: fixture.payload.linkSessionId,
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      deviceId: fixture.approval.deviceId,
      devicePublicKeyB64u: fixture.payload.devicePublicKeyB64u,
      claimedAtMs: 1_500,
      claimExpiresAtMs: 9_000,
    });
    const approvalDigest = await computeLinkedDeviceApprovalDigestV1(fixture.approval);
    expect(claimDigest).toBe('FgZvqK0Fekq89xChB3UoQBKz0nlTcbBvkxXAa6v6_EA');
    expect(approvalDigest).toBe('ibcErM2M3FJ-1VBJ2YH35qnTwaOAnUjqKKT8CLc4kjc');
  });

  test('rejects dormant QR permissions, unknown fields, non-canonical keys, and invalid expiry', () => {
    const fixture = buildR103DeviceLinkFixture();

    expect(() =>
      parseQrLinkedDeviceSessionPayloadV4({
        ...fixture.payload,
        requestedPermission: {
          kind: 'scoped_signing',
          administrationScope: 'no_account_admin',
          mandatePolicyDigest: 'retired',
        },
      }),
    ).toThrow();
    expect(() =>
      parseQrLinkedDeviceSessionPayloadV4({ ...fixture.payload, walletId: 'wallet:leak' }),
    ).toThrow(/walletId/);
    expect(() =>
      parseQrLinkedDeviceSessionPayloadV4({
        ...fixture.payload,
        linkPublicKeyB64u: `${fixture.payload.linkPublicKeyB64u}=`,
      }),
    ).toThrow(/base64url/);
    expect(() =>
      parseQrLinkedDeviceSessionPayloadV4({
        ...fixture.payload,
        expiresAtMs: fixture.payload.issuedAtMs,
      }),
    ).toThrow(/expiresAtMs/);
  });

  test('keeps wallet identity out of unclaimed states and splits cancellation branches', () => {
    const fixture = buildR103DeviceLinkFixture();
    const active = buildActiveLinkedDeviceSessionState({
      linkSessionId: fixture.payload.linkSessionId,
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      activatedAtMs: 10_000,
    });
    const cancelled = buildCancelledUnclaimedLinkedDeviceSessionState({
      linkSessionId: fixture.payload.linkSessionId,
      cancelledAtMs: 3_000,
    });
    expect(parseLinkedDeviceSessionState(active)).toEqual(active);
    expect(parseLinkedDeviceSessionState(cancelled)).toEqual(cancelled);
    const committed = buildCommittedCompletionRequiredLinkedDeviceSessionState({
      linkSessionId: fixture.payload.linkSessionId,
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      keyManifestDigestB64u: fixture.receipt.manifestDigestB64u,
      transcriptSetDigestB64u: fixture.receipt.aggregateReceiptDigestB64u,
    });
    expect(parseLinkedDeviceSessionState(committed)).toEqual(committed);
    expect(() =>
      parseLinkedDeviceSessionState({ ...cancelled, walletId: fixture.approval.walletId }),
    ).toThrow(/walletId/);

    expect(
      parseLinkedDeviceSessionTransportRequestV1({
        kind: 'linked_device_session_cancel_unclaimed_request_v1',
        linkSessionId: fixture.payload.linkSessionId,
        reason: 'user_cancelled',
        requestedAtMs: 3_000,
      }),
    ).toMatchObject({ kind: 'linked_device_session_cancel_unclaimed_request_v1' });
    expect(() =>
      parseLinkedDeviceSessionTransportRequestV1({
        kind: 'linked_device_session_cancel_unclaimed_request_v1',
        linkSessionId: fixture.payload.linkSessionId,
        reason: 'user_cancelled',
        requestedAtMs: 3_000,
        deviceId: fixture.approval.deviceId,
      }),
    ).toThrow(/deviceId/);
  });

  test('round-trips role-bound provisioning and holder receipt DTOs', () => {
    const fixture = buildR103DeviceLinkFixture();
    const command = buildLinkedDeviceProvisioningCommandV1({
      linkSessionId: fixture.payload.linkSessionId,
      enrollmentId: fixture.approval.enrollmentId,
      deviceId: fixture.approval.deviceId,
    });
    expect(parseLinkedDeviceProvisioningCommandV1(command)).toEqual(command);

    const sourceJob = buildR102LaneJob('linked-device');
    const job = parseRotatableSigningLaneJobV1({
      ...sourceJob,
      enrollmentId: String(fixture.approval.enrollmentId),
      walletId: String(fixture.approval.walletId),
      authorization: {
        kind: 'linked_device_enrollment',
        authorizedOperationId: String(sourceJob.authorization.authorizedOperationId),
        linkedDeviceEnrollmentId: String(fixture.approval.enrollmentId),
        linkedDevicePermissionDigestB64u: fixture.approval.policyDigestB64u,
      },
    });
    const protocolCommitReceipt = buildR102ProtocolCommitReceipt(job);
    const deliveries = {
      kind: 'linked_device_provisioning_deliveries_v1' as const,
      linkSessionId: fixture.payload.linkSessionId,
      enrollmentId: fixture.approval.enrollmentId,
      deviceId: fixture.approval.deviceId,
      manifest: manifestForJob(job),
      orderedChildren: [
        {
          kind: 'linked_device_provisioning_child_v1' as const,
          job,
          protocolCommitReceipt,
          holderPackage: {
            kind: 'ed25519_yao_lane_holder_package_set_v1' as const,
            deriverAEncryptedPackageJson: '{}',
            deriverBEncryptedPackageJson: '{}',
          },
          expectedVersion: 0,
        },
      ],
    };
    expect(parseLinkedDeviceProvisioningDeliveriesV1(deliveries)).toEqual(deliveries);

    const holderReceipt = buildR102HolderDeliveryReceipt(job);
    const acknowledgement = buildLinkedDeviceHolderDeliveryAcknowledgementV1({
      linkSessionId: fixture.payload.linkSessionId,
      enrollmentId: fixture.approval.enrollmentId,
      deviceId: fixture.approval.deviceId,
      orderedHolderDeliveryReceipts: [holderReceipt],
      acknowledgedAtMs: 4_000,
    });
    expect(parseLinkedDeviceHolderDeliveryAcknowledgementV1(acknowledgement)).toEqual(
      acknowledgement,
    );
  });

  test('binds each delivered Wallet Session JWT to the linked device and approved key', () => {
    const fixture = buildR103DeviceLinkFixture();
    const delivery = buildR103LinkedWalletSessionDeliveryFixture(fixture);

    expect(parseLinkedDeviceWalletSessionDeliveryV1(delivery)).toEqual(delivery);
    expect(() =>
      parseLinkedDeviceWalletSessionDeliveryV1({ ...delivery, unexpected: true }),
    ).toThrow(/not part/);
    expect(() =>
      parseLinkedDeviceWalletSessionDeliveryV1({
        ...delivery,
        orderedTokens: [delivery.orderedTokens[0], delivery.orderedTokens[0]],
      }),
    ).toThrow(/duplicate wallet key/);
    expect(() =>
      parseLinkedDeviceWalletSessionDeliveryV1({
        ...delivery,
        orderedTokens: [{ ...delivery.orderedTokens[0], keyFamily: 'ecdsa_secp256k1' }],
      }),
    ).toThrow(/identity does not match/);
  });

  test('rejects provisioning identity substitution and unknown DTO fields', () => {
    const fixture = buildR103DeviceLinkFixture();
    const command = buildLinkedDeviceProvisioningCommandV1({
      linkSessionId: fixture.payload.linkSessionId,
      enrollmentId: fixture.approval.enrollmentId,
      deviceId: fixture.approval.deviceId,
    });
    expect(() => parseLinkedDeviceProvisioningCommandV1({ ...command, extra: true })).toThrow(
      /not part/,
    );

    const sourceJob = buildR102LaneJob('substitution');
    const job = parseRotatableSigningLaneJobV1({
      ...sourceJob,
      enrollmentId: String(fixture.approval.enrollmentId),
      walletId: String(fixture.approval.walletId),
      authorization: {
        kind: 'linked_device_enrollment',
        authorizedOperationId: String(sourceJob.authorization.authorizedOperationId),
        linkedDeviceEnrollmentId: String(fixture.approval.enrollmentId),
        linkedDevicePermissionDigestB64u: fixture.approval.policyDigestB64u,
      },
    });
    const commit = buildR102ProtocolCommitReceipt(job);
    expect(() =>
      parseLinkedDeviceProvisioningDeliveriesV1({
        kind: 'linked_device_provisioning_deliveries_v1',
        linkSessionId: fixture.payload.linkSessionId,
        enrollmentId: fixture.approval.enrollmentId,
        deviceId: fixture.approval.deviceId,
        manifest: manifestForJob(job),
        orderedChildren: [
          {
            kind: 'linked_device_provisioning_child_v1',
            job,
            protocolCommitReceipt: {
              ...commit,
              sourceRevocationEpoch: commit.sourceRevocationEpoch + 1,
            },
            holderPackage: {
              kind: 'ed25519_yao_lane_holder_package_set_v1',
              deriverAEncryptedPackageJson: '{}',
              deriverBEncryptedPackageJson: '{}',
            },
            expectedVersion: 0,
          },
        ],
      }),
    ).toThrow(/does not match its job/);
  });

  test('binds target-ready jobs and prepared deliveries to one exact manifest', () => {
    const fixture = buildR103DeviceLinkFixture();
    const sourceJob = buildR102LaneJob('target-ready');
    const job = parseRotatableSigningLaneJobV1({
      ...sourceJob,
      enrollmentId: String(fixture.approval.enrollmentId),
      walletId: String(fixture.approval.walletId),
      authorization: {
        kind: 'linked_device_enrollment',
        authorizedOperationId: String(sourceJob.authorization.authorizedOperationId),
        linkedDeviceEnrollmentId: String(fixture.approval.enrollmentId),
        linkedDevicePermissionDigestB64u: fixture.approval.policyDigestB64u,
      },
    });
    const manifest = buildLaneEnrollmentManifestV1({
      enrollmentId: job.enrollmentId,
      walletId: job.walletId,
      authorization: job.authorization,
      orderedChildren: [
        {
          operationId: job.operationId,
          walletKeyId: job.walletKeyId,
          keyFamily: job.keyFamily,
          sourceLaneId: job.source.laneId,
          sourceLaneShareEpoch: job.source.laneShareEpoch,
          sourceRevocationEpoch: job.source.revocationEpoch,
          sourceMaterialActivation: job.source.materialActivation,
          targetLaneId: job.target.laneId,
          targetLaneShareEpoch: job.target.laneShareEpoch,
          targetMaterialActivationId: job.targetMaterialActivationId,
          holderParticipantBindingDigestB64u: job.targetHolder.participantBindingDigestB64u,
          signingWorkerParticipantBindingDigestB64u:
            job.targetSigningWorker.participantBindingDigestB64u,
        },
      ],
      createdAtMs: 1_000,
      expiresAtMs: 9_000,
    });
    const targetReady = {
      kind: 'linked_device_target_ready_r102_input_v1' as const,
      linkSessionId: fixture.approval.linkSessionId,
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      deviceId: fixture.approval.deviceId,
      manifest,
      children: [job] as const,
    };
    expect(parseLinkedDeviceTargetReadyR102InputV1(targetReady)).toEqual(targetReady);
    const deliveries = parseLinkedDeviceProvisioningDeliveriesV1({
      kind: 'linked_device_provisioning_deliveries_v1',
      linkSessionId: targetReady.linkSessionId,
      enrollmentId: targetReady.enrollmentId,
      deviceId: targetReady.deviceId,
      manifest,
      orderedChildren: [
        {
          kind: 'linked_device_provisioning_child_v1',
          job,
          protocolCommitReceipt: buildR102ProtocolCommitReceipt(job),
          holderPackage: {
            kind: 'ed25519_yao_lane_holder_package_set_v1',
            deriverAEncryptedPackageJson: '{}',
            deriverBEncryptedPackageJson: '{}',
          },
          expectedVersion: 0,
        },
      ],
    });
    const submission = {
      kind: 'linked_device_provisioning_deliveries_submission_v1' as const,
      linkSessionId: targetReady.linkSessionId,
      walletId: targetReady.walletId,
      enrollmentId: targetReady.enrollmentId,
      deviceId: targetReady.deviceId,
      manifestDigestB64u: fixture.approval.policyDigestB64u,
      deliveries,
    };
    expect(parseLinkedDeviceProvisioningDeliveriesSubmissionV1(submission)).toEqual(submission);
    expect(() =>
      parseLinkedDeviceTargetReadyR102InputV1({
        ...targetReady,
        children: [{ ...job, walletKeyId: 'wallet-key:substituted' }],
      }),
    ).toThrow(/differs from its manifest child/);
  });

  test('binds verified target attestation and public holder records to one preparation', async () => {
    const fixture = buildR103DeviceLinkFixture();
    const job = buildR102LaneJob('target-preparation');
    const rpId = parseWebAuthnRpId('wallet.example.test');
    const credentialId = parseWebAuthnCredentialIdB64u('AQID');
    if (!rpId.ok) throw new Error(rpId.error.message);
    if (!credentialId.ok) throw new Error(credentialId.error.message);
    const preparation = buildLinkedDeviceTargetPreparationV1({
      linkSessionId: fixture.approval.linkSessionId,
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      deviceId: fixture.approval.deviceId,
      rpId: rpId.value,
      userHandleB64u: 'AQID',
      challengeB64u: fixture.approval.policyDigestB64u,
      orderedChildren: [
        {
          kind: 'linked_device_target_preparation_child_v1',
          operationId: job.operationId,
          walletKeyId: job.walletKeyId,
          keyFamily: job.keyFamily,
          targetLaneId: job.target.laneId,
          targetLaneShareEpoch: job.target.laneShareEpoch,
          targetMaterialActivationId: job.targetMaterialActivationId,
          targetHolderParticipantId: job.targetHolder.participantId,
        },
      ],
      issuedAtMs: 1_000,
      expiresAtMs: 2_000,
    });
    expect(parseLinkedDeviceTargetPreparationV1(preparation)).toEqual(preparation);
    const targetPreparationDigestB64u =
      await computeLinkedDeviceTargetPreparationDigestV1(preparation);
    const registration = buildLinkedDeviceTargetCredentialRegistrationV1({
      linkSessionId: fixture.approval.linkSessionId,
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      deviceId: fixture.approval.deviceId,
      targetPreparationDigestB64u,
      webauthnRegistration: {
        kind: 'linked_device_webauthn_registration_v1',
        credentialIdB64u: credentialId.value,
        authenticatorAttachment: 'platform',
        clientDataJsonB64u: 'AQID',
        attestationObjectB64u: 'BAUG',
        transports: ['internal'],
      },
      orderedHolderRegistrations: [
        {
          kind: 'linked_device_target_holder_registration_v1',
          operationId: job.operationId,
          walletKeyId: job.walletKeyId,
          keyFamily: job.keyFamily,
          targetLaneId: job.target.laneId,
          targetLaneShareEpoch: job.target.laneShareEpoch,
          targetMaterialActivationId: job.targetMaterialActivationId,
          holderParticipant: {
            kind: 'lane_holder_participant_v1',
            participantId: job.targetHolder.participantId,
            custodyBindingId: job.targetHolder.custodyBindingId,
            custodyBindingDigestB64u: job.targetHolder.custodyBindingDigestB64u,
            hpkePublicKeyB64u: job.targetHolder.hpkePublicKeyB64u,
            hpkePublicKeyDigestB64u: job.targetHolder.hpkePublicKeyDigestB64u,
            participantBindingDigestB64u: job.targetHolder.participantBindingDigestB64u,
          },
        },
      ],
      registeredAtMs: 1_500,
    });
    expect(parseLinkedDeviceTargetCredentialRegistrationV1(registration)).toEqual(registration);
    await expect(
      assertLinkedDeviceTargetCredentialRegistrationMatchesPreparationV1({
        preparation,
        registration,
      }),
    ).resolves.toBeUndefined();
    const substitutedRegistration = parseLinkedDeviceTargetCredentialRegistrationV1({
      ...registration,
      orderedHolderRegistrations: [
        {
          ...registration.orderedHolderRegistrations[0],
          operationId: 'operation:substituted',
        },
      ],
    });
    await expect(
      assertLinkedDeviceTargetCredentialRegistrationMatchesPreparationV1({
        preparation,
        registration: substitutedRegistration,
      }),
    ).rejects.toThrow(/R102 child/);
    expect(() =>
      parseLinkedDeviceTargetCredentialRegistrationV1({
        ...registration,
        webauthnRegistration: {
          ...registration.webauthnRegistration,
          clientExtensionResults: { prf: { results: { first: 'secret' } } },
        },
      }),
    ).toThrow(/clientExtensionResults/);
  });
});
