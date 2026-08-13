import { expect, test } from '@playwright/test';
import { base64UrlDecode, base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { parseLinkedDeviceTargetPreparationV1 } from '../../packages/shared-ts/src/device-linking';
import { installDeviceLinkingKeyWorkerV1 } from '../../packages/sdk-web/src/core/signingEngine/workerManager/workers/device-linking-key.worker';
import { createDeviceLinkingTargetCredentialPortV1 } from '../../packages/sdk-web/src/SeamsWeb/operations/devices/deviceLinkingTargetCredential';
import { toRpId } from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type { AuthenticatorPort } from '../../packages/sdk-web/src/core/platform';
import type { DeviceLinkingKeyMaterialPortV1 } from '../../packages/sdk-web/src/SeamsWeb/operations/devices/deviceLinkingPorts';
import { parseRotatableSigningLaneJobV1 } from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import { parseLaneHolderParticipantRecordV1 } from '../../packages/shared-ts/src/signing-lanes/participants';
import {
  buildR102EcdsaLaneJob,
  buildR102LaneJob,
  buildR102ProtocolCommitReceipt,
  buildR102ServerActivationReceipt,
  buildR103SealedHolderRecord,
} from './helpers/r102LaneGateway.fixtures';
import { EcdsaClientWorkerControlKind } from '../../packages/sdk-web/src/core/signingEngine/workerManager/ecdsaClientWorkerChannels';

class FakeWorkerScope {
  readonly responses: unknown[] = [];
  private listener: ((event: MessageEvent) => void) | null = null;

  postMessage(message: unknown): void {
    this.responses.push(message);
  }

  addEventListener(_type: 'message', listener: (event: MessageEvent) => void): void {
    this.listener = listener;
  }

  removeEventListener(_type: 'message', listener: (event: MessageEvent) => void): void {
    if (this.listener === listener) this.listener = null;
  }

  send(message: unknown): void {
    this.listener?.({ data: message } as MessageEvent);
  }
}

function digest(seed: number): string {
  return base64UrlEncode(Uint8Array.from({ length: 32 }, (_, index) => seed + index));
}

function challenge(): string {
  return base64UrlEncode(new Uint8Array(32).fill(7));
}

function targetPreparation() {
  return parseLinkedDeviceTargetPreparationV1({
    kind: 'linked_device_target_preparation_v1',
    linkSessionId: 'link-session-1',
    walletId: 'wallet-1',
    enrollmentId: 'linked-enrollment-1',
    deviceId: 'linked-device-1',
    rpId: 'wallet.example.test',
    userHandleB64u: base64UrlEncode(new Uint8Array(32).fill(4)),
    challengeB64u: digest(5),
    orderedChildren: [
      {
        kind: 'linked_device_target_preparation_child_v1',
        operationId: 'lane-operation-1',
        walletKeyId: 'wallet-key-1',
        keyFamily: 'ed25519',
        targetLaneId: 'linked-lane-1',
        targetLaneShareEpoch: '1',
        targetMaterialActivationId: 'material-activation-1',
        targetHolderParticipantId: 'holder-participant-1',
      },
    ],
    issuedAtMs: 1_000,
    expiresAtMs: 2_000,
  });
}

async function waitForResponse(scope: FakeWorkerScope): Promise<Record<string, unknown>> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const response = scope.responses.at(0);
    if (response && typeof response === 'object') return response as Record<string, unknown>;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error('worker response timed out');
}

test.describe('device-linking key worker', () => {
  test('keeps key material in the worker and signs the canonical request bytes', async () => {
    const scope = new FakeWorkerScope();
    let recipientsDestroyed = 0;
    let signingMaterialDestroyed = 0;
    let signingMaterialFreed = 0;
    let signingShareFreed = 0;
    const signingMaterialOpenCalls: unknown[] = [];
    let sealedCiphertextDigestB64u = digest(91);
    const installed = installDeviceLinkingKeyWorkerV1(scope, {
      createRecipient() {
        return {
          hpke_public_key_b64u: () => digest(21),
          hpke_public_key_digest_b64u: () => digest(31),
          open_and_seal: () => ({
            sealedHolderMaterialB64u: base64UrlEncode(new Uint8Array([1])),
            sealedHolderRecordDigestB64u: digest(81),
            verifiedHolderCiphertextDigestSetB64u: sealedCiphertextDigestB64u,
          }),
          destroy: () => {
            recipientsDestroyed += 1;
          },
          free: () => undefined,
        };
      },
      createCustodySeal() {
        return { free: () => undefined };
      },
      openSigningMaterial(input) {
        signingMaterialOpenCalls.push({
          ...input,
          factorSecret: input.factorSecret.slice(),
        });
        const persistedReceipt = JSON.parse(input.receiptJson) as Record<string, unknown>;
        return {
          key_family: () => 'ed25519',
          create_ed25519_signing_share: () => ({
            client_commitments_json: () =>
              JSON.stringify({ hiding: 'client-hiding', binding: 'client-binding' }),
            client_verifying_share: () =>
              base64UrlDecode(String(persistedReceipt.targetHolderPublicCommitmentB64u)),
            client_signature_share_b64u: () => digest(121),
            free: () => {
              signingShareFreed += 1;
            },
          }),
          create_ecdsa_presign_session: () => {
            throw new Error('ECDSA material is outside this Ed25519 test');
          },
          destroy: () => {
            signingMaterialDestroyed += 1;
          },
          free: () => {
            signingMaterialFreed += 1;
          },
        };
      },
    });
    scope.send({ id: 'create', request: { kind: 'device_linking_key_material_create_v1' } });
    const created = await waitForResponse(scope);
    expect(created.ok).toBe(true);
    const result = created.result as Record<string, unknown>;
    expect(Object.keys(result).sort()).toEqual([
      'devicePublicKeyB64u',
      'handleId',
      'linkPublicKeyB64u',
    ]);
    expect(typeof result.handleId).toBe('string');
    expect(typeof result.linkPublicKeyB64u).toBe('string');
    expect(typeof result.devicePublicKeyB64u).toBe('string');

    scope.responses.length = 0;
    const preparation = targetPreparation();
    const transferredFactorSecret = new Uint8Array(32).fill(11).buffer;
    scope.send({
      id: 'prepare-holders',
      request: {
        kind: 'device_linking_target_holders_prepare_v1',
        handleId: result.handleId,
        preparation,
        credentialIdB64u: base64UrlEncode(new Uint8Array(32).fill(8)),
        factorSecret: transferredFactorSecret,
      },
    });
    const holders = await waitForResponse(scope);
    expect(holders.error).toBeUndefined();
    expect(holders).toMatchObject({ ok: true });
    expect(new Uint8Array(transferredFactorSecret)).toEqual(new Uint8Array(32));
    const holderResult = holders.result as Record<string, unknown>;
    const ordered = holderResult.orderedHolderRegistrations as Record<string, unknown>[];
    expect(ordered).toHaveLength(1);
    expect(ordered[0]).toMatchObject({
      kind: 'linked_device_target_holder_registration_v1',
      operationId: preparation.orderedChildren[0].operationId,
      walletKeyId: preparation.orderedChildren[0].walletKeyId,
      keyFamily: preparation.orderedChildren[0].keyFamily,
      targetLaneId: preparation.orderedChildren[0].targetLaneId,
      targetLaneShareEpoch: preparation.orderedChildren[0].targetLaneShareEpoch,
      targetMaterialActivationId: preparation.orderedChildren[0].targetMaterialActivationId,
    });
    expect(ordered[0]).not.toHaveProperty('factorSecret');
    expect(JSON.stringify(holderResult)).not.toContain('prf');

    const sourceJob = buildR102LaneJob('device-linking-worker-seal');
    const holderParticipant = parseLaneHolderParticipantRecordV1(ordered[0].holderParticipant);
    const job = parseRotatableSigningLaneJobV1({
      ...sourceJob,
      operationId: preparation.orderedChildren[0].operationId,
      enrollmentId: String(preparation.enrollmentId),
      walletId: String(preparation.walletId),
      walletKeyId: preparation.orderedChildren[0].walletKeyId,
      target: {
        operation: 'create_lane',
        laneId: preparation.orderedChildren[0].targetLaneId,
        laneKind: 'linked_device',
        laneShareEpoch: preparation.orderedChildren[0].targetLaneShareEpoch,
        expectedTargetState: 'absent',
      },
      targetMaterialActivationId: preparation.orderedChildren[0].targetMaterialActivationId,
      targetHolder: {
        participantId: holderParticipant.participantId,
        participantBindingDigestB64u: holderParticipant.participantBindingDigestB64u,
        custodyBindingId: holderParticipant.custodyBindingId,
        custodyBindingDigestB64u: holderParticipant.custodyBindingDigestB64u,
        hpkePublicKeyB64u: holderParticipant.hpkePublicKeyB64u,
        hpkePublicKeyDigestB64u: holderParticipant.hpkePublicKeyDigestB64u,
      },
      authorization: {
        kind: 'linked_device_enrollment',
        authorizedOperationId: String(sourceJob.authorization.authorizedOperationId),
        linkedDeviceEnrollmentId: String(preparation.enrollmentId),
        linkedDevicePermissionDigestB64u: digest(101),
      },
    });
    const protocolCommitReceipt = buildR102ProtocolCommitReceipt(job);
    sealedCiphertextDigestB64u = protocolCommitReceipt.targetHolderCiphertextDigestSetB64u;
    scope.responses.length = 0;
    const openRequest = {
      kind: 'device_linking_target_holder_open_seal_v1',
      handleId: result.handleId,
      delivery: {
        kind: 'linked_device_provisioning_child_v1',
        job,
        protocolCommitReceipt,
        holderPackage: {
          kind: 'ed25519_yao_lane_holder_package_set_v1',
          deriverAEncryptedPackageJson: '{}',
          deriverBEncryptedPackageJson: '{}',
        },
        expectedVersion: 0,
      },
    };
    scope.send({ id: 'open-holder', request: openRequest });
    const sealed = await waitForResponse(scope);
    expect(sealed.error).toBeUndefined();
    expect(sealed.result).toMatchObject({
      verifiedHolderCiphertextDigestSetB64u:
        protocolCommitReceipt.targetHolderCiphertextDigestSetB64u,
    });
    scope.responses.length = 0;
    scope.send({ id: 'open-holder-replay', request: openRequest });
    const replayedSealed = await waitForResponse(scope);
    expect(replayedSealed.error).toBeUndefined();
    expect(replayedSealed.result).toEqual(sealed.result);

    const holderRecord = {
      kind: 'lane_sealed_holder_record_v1',
      operationId: job.operationId,
      enrollmentId: job.enrollmentId,
      walletId: job.walletId,
      walletKeyId: job.walletKeyId,
      laneId: job.target.laneId,
      laneShareEpoch: job.target.laneShareEpoch,
      targetMaterialActivationId: job.targetMaterialActivationId,
      holderParticipantBindingDigestB64u: job.targetHolder.participantBindingDigestB64u,
      custodyBindingId: job.targetHolder.custodyBindingId,
      holderRecipientKeyDigestB64u: protocolCommitReceipt.holderRecipientKeyDigestB64u,
      holderCiphertextDigestSetB64u: protocolCommitReceipt.targetHolderCiphertextDigestSetB64u,
      sealedHolderRecordDigestB64u: digest(81),
      transcriptHashB64u: protocolCommitReceipt.transcriptHashB64u,
      sealedHolderMaterialB64u: base64UrlEncode(new Uint8Array([1])),
      acknowledgedAtMs: 4_000,
      storedAtMs: 4_000,
    };
    const materialActivation = buildR102ServerActivationReceipt(job).targetMaterialActivation;
    scope.responses.length = 0;
    const rejectedFactor = new Uint8Array(32).fill(27).buffer;
    scope.send({
      id: 'open-signing-material-wrong-record',
      request: {
        kind: 'device_linking_holder_signing_material_open_v1',
        factorSecret: rejectedFactor,
        job,
        protocolCommitReceipt,
        materialActivation,
        holderRecord: { ...holderRecord, walletKeyId: 'wallet-key-substituted' },
      },
    });
    const rejectedSigningMaterial = await waitForResponse(scope);
    expect(rejectedSigningMaterial.ok).toBe(false);
    expect(rejectedSigningMaterial.error).toContain('persisted R102 child');
    expect(new Uint8Array(rejectedFactor)).toEqual(new Uint8Array(32));
    expect(signingMaterialOpenCalls).toHaveLength(0);

    scope.responses.length = 0;
    const signingFactor = new Uint8Array(32).fill(29).buffer;
    scope.send({
      id: 'open-signing-material',
      request: {
        kind: 'device_linking_holder_signing_material_open_v1',
        factorSecret: signingFactor,
        job,
        protocolCommitReceipt,
        materialActivation,
        holderRecord,
      },
    });
    const openedSigningMaterial = await waitForResponse(scope);
    expect(openedSigningMaterial).toMatchObject({
      ok: true,
      result: { keyFamily: 'ed25519' },
    });
    expect(Object.keys(openedSigningMaterial.result as Record<string, unknown>).sort()).toEqual([
      'handleId',
      'keyFamily',
    ]);
    expect(JSON.stringify(openedSigningMaterial)).not.toContain('factorSecret');
    expect(JSON.stringify(openedSigningMaterial)).not.toContain('share');
    expect(new Uint8Array(signingFactor)).toEqual(new Uint8Array(32));
    expect(signingMaterialOpenCalls).toHaveLength(1);

    scope.responses.length = 0;
    scope.send({
      id: 'create-ed25519-holder-share',
      request: {
        kind: 'device_linking_holder_ed25519_sign_v1',
        handleId: (openedSigningMaterial.result as Record<string, unknown>).handleId,
        admittedDigestB64u: digest(111),
        signingWorkerCommitments: {
          hiding: 'server-hiding',
          binding: 'server-binding',
        },
        signingWorkerVerifyingShareB64u: protocolCommitReceipt.targetServerPublicCommitmentB64u,
      },
    });
    const holderShare = await waitForResponse(scope);
    expect(holderShare).toMatchObject({
      ok: true,
      result: {
        clientCommitments: { hiding: 'client-hiding', binding: 'client-binding' },
        clientVerifyingShareB64u: protocolCommitReceipt.targetHolderPublicCommitmentB64u,
        clientSignatureShareB64u: digest(121),
      },
    });
    expect(signingShareFreed).toBe(1);

    scope.responses.length = 0;
    scope.send({
      id: 'discard-signing-material',
      request: {
        kind: 'device_linking_holder_signing_material_discard_v1',
        handleId: (openedSigningMaterial.result as Record<string, unknown>).handleId,
      },
    });
    const discardedSigningMaterial = await waitForResponse(scope);
    expect(discardedSigningMaterial.ok).toBe(true);
    expect(signingMaterialDestroyed).toBe(1);
    expect(signingMaterialFreed).toBe(1);

    scope.responses.length = 0;
    scope.send({
      id: 'sign',
      request: {
        kind: 'device_linking_request_sign_v1',
        handleId: result.handleId,
        linkSessionId: 'link-session-1',
        method: 'POST',
        canonicalPath: '/wallet/device-linking/v1/sessions/link-session-1/credential',
        bodyDigestB64u: digest(3),
        devicePublicKeyDigestB64u: digest(9),
        challengeB64u: challenge(),
        issuedAtMs: 1_000,
        expiresAtMs: 2_000,
      },
    });
    const signed = await waitForResponse(scope);
    expect(signed.ok).toBe(true);
    const signature = (signed.result as Record<string, unknown>).signatureB64u;
    expect(typeof signature).toBe('string');
    expect(base64UrlEncode(new Uint8Array(64))).not.toBe(signature);

    scope.responses.length = 0;
    scope.send({
      id: 'discard',
      request: { kind: 'device_linking_key_material_discard_v1', handleId: result.handleId },
    });
    await waitForResponse(scope);
    scope.responses.length = 0;
    scope.send({
      id: 'sign-after-discard',
      request: {
        kind: 'device_linking_request_sign_v1',
        handleId: result.handleId,
        linkSessionId: 'link-session-1',
        method: 'GET',
        canonicalPath: '/wallet/device-linking/v1/sessions/link-session-1',
        bodyDigestB64u: digest(3),
        devicePublicKeyDigestB64u: digest(9),
        challengeB64u: challenge(),
        issuedAtMs: 1_000,
        expiresAtMs: 2_000,
      },
    });
    const discarded = await waitForResponse(scope);
    expect(discarded.ok).toBe(false);
    expect(discarded.error).toContain('unknown or discarded');
    expect(recipientsDestroyed).toBe(1);
    await installed.close();
  });

  test('runs linked-holder ECDSA presign behind an opaque worker capability', async () => {
    const scope = new FakeWorkerScope();
    let presignSessionCreates = 0;
    let presignSessionFrees = 0;
    const installed = installDeviceLinkingKeyWorkerV1(scope, {
      createRecipient() {
        throw new Error('recipient creation is outside this ECDSA reopen test');
      },
      createCustodySeal() {
        throw new Error('custody creation is outside this ECDSA reopen test');
      },
      openSigningMaterial() {
        return {
          key_family: () => 'ecdsa_secp256k1',
          create_ed25519_signing_share: () => {
            throw new Error('Ed25519 signing is outside this ECDSA test');
          },
          create_ecdsa_presign_session: () => {
            presignSessionCreates += 1;
            return {
              stage: () => 'triples',
              poll: () => ({
                stage: 'triples',
                event: 'none',
                outgoing: [new Uint8Array([7, 8, 9])],
              }),
              message: () => undefined,
              start_presign: () => undefined,
              presignature_big_r_33: () => {
                throw new Error('presign is not complete');
              },
              compute_signature_share: () => {
                throw new Error('presign is not complete');
              },
              free: () => {
                presignSessionFrees += 1;
              },
            };
          },
          destroy: () => undefined,
          free: () => undefined,
        };
      },
    });
    const job = buildR102EcdsaLaneJob('device-linking-holder-presign');
    if (job.keyFamily !== 'ecdsa_secp256k1') throw new Error('ECDSA fixture changed branch');
    const protocolCommitReceipt = buildR102ProtocolCommitReceipt(job);
    const materialActivation = buildR102ServerActivationReceipt(job).targetMaterialActivation;
    const holderRecord = buildR103SealedHolderRecord(job, protocolCommitReceipt);
    const factorSecret = new Uint8Array(32).fill(29).buffer;
    scope.send({
      id: 'open-ecdsa-signing-material',
      request: {
        kind: 'device_linking_holder_signing_material_open_v1',
        factorSecret,
        job,
        protocolCommitReceipt,
        materialActivation,
        holderRecord,
      },
    });
    const opened = await waitForResponse(scope);
    expect(opened).toMatchObject({
      ok: true,
      result: { keyFamily: 'ecdsa_secp256k1' },
    });
    expect(new Uint8Array(factorSecret)).toEqual(new Uint8Array(32));
    const holderHandleId = String((opened.result as Record<string, unknown>).handleId);

    const channel = new MessageChannel();
    scope.send({
      kind: EcdsaClientWorkerControlKind.AttachLinkedHolderToPresign,
      port: channel.port1,
    });
    const response = new Promise<Record<string, unknown>>((resolve) => {
      channel.port2.onmessage = (event) => resolve(event.data as Record<string, unknown>);
      channel.port2.start();
    });
    const groupPublicKey33 = base64UrlDecode(job.thresholdPublicKey33B64u);
    channel.port2.postMessage(
      {
        kind: 'opaque_ecdsa_presign_session_init_v1',
        requestId: 'linked-presign-1',
        sessionId: 'linked-presign-session-1',
        authority: {
          kind: 'linked_holder_signing_material',
          holderHandleId,
        },
        poolIdentity: {
          poolKey: 'linked-holder-pool',
          materialActivationId: materialActivation.activationId,
          capability: materialActivation.capability,
          keyBinding: materialActivation.keyBinding,
          walletId: job.walletId,
          signingScopeB64u: digest(42),
          pairRole: 'client',
          keyEpoch: 'linked-holder-key-epoch-1',
          activationEpoch: 'linked-holder-activation-epoch-1',
          protocolId: 'seams/router-ab-ecdsa-presign/fixed-2of2/v1',
        },
        groupPublicKey33: groupPublicKey33.buffer,
        materialExpiresAtMs: Date.now() + 60_000,
      },
      [groupPublicKey33.buffer],
    );
    const progress = await response;
    expect(progress).toMatchObject({
      kind: 'opaque_ecdsa_presign_authority_result_v1',
      requestId: 'linked-presign-1',
      ok: true,
      result: {
        kind: 'progress',
        progress: { stage: 'triples', event: 'none' },
      },
    });
    expect(presignSessionCreates).toBe(1);
    expect(scope.responses).toHaveLength(1);
    channel.port2.close();
    await installed.close();
    expect(presignSessionFrees).toBe(1);
  });

  test('zeroizes rejected PRF input and awaits in-flight cleanup before closing', async () => {
    const malformedScope = new FakeWorkerScope();
    const malformedInstalled = installDeviceLinkingKeyWorkerV1(malformedScope, {
      createRecipient() {
        throw new Error('recipient creation must not run for malformed input');
      },
      createCustodySeal() {
        throw new Error('custody creation must not run for malformed input');
      },
      openSigningMaterial() {
        throw new Error('signing material must not open for malformed input');
      },
    });
    const rejectedFactorSecret = new Uint8Array(32).fill(17).buffer;
    malformedScope.send({
      id: 'malformed-prepare',
      request: {
        kind: 'device_linking_target_holders_prepare_v1',
        handleId: '',
        preparation: targetPreparation(),
        credentialIdB64u: base64UrlEncode(new Uint8Array(32).fill(8)),
        factorSecret: rejectedFactorSecret,
      },
    });
    const rejected = await waitForResponse(malformedScope);
    expect(rejected.ok).toBe(false);
    expect(new Uint8Array(rejectedFactorSecret)).toEqual(new Uint8Array(32));
    await malformedInstalled.close();

    const scope = new FakeWorkerScope();
    let releaseRecipient: (() => void) | undefined;
    let recipientsDestroyed = 0;
    const installed = installDeviceLinkingKeyWorkerV1(scope, {
      async createRecipient() {
        await new Promise<void>((resolve) => {
          releaseRecipient = resolve;
        });
        return {
          hpke_public_key_b64u: () => digest(21),
          hpke_public_key_digest_b64u: () => digest(31),
          open_and_seal: () => {
            throw new Error('holder sealing is outside this cleanup test');
          },
          destroy: () => {
            recipientsDestroyed += 1;
          },
          free: () => undefined,
        };
      },
      createCustodySeal() {
        throw new Error('custody creation is outside this cleanup test');
      },
      openSigningMaterial() {
        throw new Error('signing material is outside this cleanup test');
      },
    });
    scope.send({ id: 'create', request: { kind: 'device_linking_key_material_create_v1' } });
    const created = await waitForResponse(scope);
    const handleId = (created.result as Record<string, unknown>).handleId;
    scope.responses.length = 0;
    const inFlightFactorSecret = new Uint8Array(32).fill(23).buffer;
    scope.send({
      id: 'prepare-holders',
      request: {
        kind: 'device_linking_target_holders_prepare_v1',
        handleId,
        preparation: targetPreparation(),
        credentialIdB64u: base64UrlEncode(new Uint8Array(32).fill(8)),
        factorSecret: inFlightFactorSecret,
      },
    });
    for (let attempt = 0; attempt < 100 && !releaseRecipient; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    expect(releaseRecipient).toBeDefined();
    const closing = installed.close();
    releaseRecipient?.();
    await closing;

    expect(new Uint8Array(inFlightFactorSecret)).toEqual(new Uint8Array(32));
    expect(recipientsDestroyed).toBe(1);
    expect(scope.responses).toEqual([]);
  });

  test('transfers PRF output to the worker and returns an attestation-only projection', async () => {
    const preparation = targetPreparation();
    const credentialIdB64u = base64UrlEncode(new Uint8Array(32).fill(8));
    const prfFirstB64u = base64UrlEncode(new Uint8Array(32).fill(11));
    const authenticator: AuthenticatorPort = {
      kind: 'authenticator',
      async run() {
        return {
          ok: true,
          operation: 'create_passkey',
          requirePrfFirst: true,
          credential: {
            id: credentialIdB64u,
            rawId: credentialIdB64u,
            type: 'public-key',
            authenticatorAttachment: 'platform',
            response: {
              clientDataJSON: base64UrlEncode(new Uint8Array([1])),
              attestationObject: base64UrlEncode(new Uint8Array([2])),
              transports: ['internal'],
            },
            clientExtensionResults: {
              prf: { results: { first: prfFirstB64u, second: undefined } },
            },
          },
          credentialIdB64u,
          rawIdB64u: credentialIdB64u,
          rpId: toRpId(preparation.rpId),
          prf: { kind: 'required', prfFirstB64u },
        };
      },
    };
    let transferredFactorSecret: Uint8Array | null = null;
    const keyMaterial: DeviceLinkingKeyMaterialPortV1 = {
      async createBootstrapKeyMaterialV1() {
        throw new Error('bootstrap is outside this test');
      },
      async prepareTargetHolderRegistrationsV1(input) {
        transferredFactorSecret = new Uint8Array(input.factorSecret).slice();
        return {
          orderedHolderRegistrations: [
            {
              kind: 'linked_device_target_holder_registration_v1',
              operationId: preparation.orderedChildren[0].operationId,
              walletKeyId: preparation.orderedChildren[0].walletKeyId,
              keyFamily: preparation.orderedChildren[0].keyFamily,
              targetLaneId: preparation.orderedChildren[0].targetLaneId,
              targetLaneShareEpoch: preparation.orderedChildren[0].targetLaneShareEpoch,
              targetMaterialActivationId: preparation.orderedChildren[0].targetMaterialActivationId,
              holderParticipant: {
                kind: 'lane_holder_participant_v1',
                participantId: preparation.orderedChildren[0].targetHolderParticipantId,
                custodyBindingId: 'lane-custody-1',
                custodyBindingDigestB64u: digest(41),
                hpkePublicKeyB64u: digest(51),
                hpkePublicKeyDigestB64u: digest(61),
                participantBindingDigestB64u: digest(71),
              },
            },
          ],
        };
      },
      async openAndSealTargetHolderDeliveryV1() {
        throw new Error('holder delivery is outside this attestation test');
      },
      async discardKeyMaterialV1() {},
      async signDeviceSessionRequestV1() {
        throw new Error('signing is outside this test');
      },
    };
    const port = createDeviceLinkingTargetCredentialPortV1({ authenticator, keyMaterial });
    const result = await port.createTargetCredentialV1({
      preparation,
      keyMaterial: { kind: 'device_linking_key_material_handle_v1', handleId: 'handle-1' },
    });
    expect(transferredFactorSecret).toEqual(new Uint8Array(32).fill(11));
    expect(result.webauthnRegistration).not.toHaveProperty('clientExtensionResults');
    expect(JSON.stringify(result)).not.toContain('prfFirstB64u');
    expect(result.orderedHolderRegistrations).toHaveLength(1);
  });
});
